//! The SPIFFE (X.509-SVID) listener: callers are identified by the certificate they present over mutual TLS, never by anything
//! they send.

use std::net::SocketAddr;
use std::sync::Arc;

use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    Decision, HttpRequestEvaluation, HttpRequestTarget, Process, RequestContext,
    SupervisorMiddlewarePhase,
};
use openshell_risk_guard::detector::InteractionRiskDetector;
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::middleware_service::RiskGuardMiddlewareService;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::sidecar;
use openshell_risk_guard::spiffe::{
    PEER_SPIFFE_HEADER, SpiffeId, SvidAuthVerifier, SvidPolicy, serve_svid_listener,
    spiffe_id_from_certificate,
};
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::{AuthVerifier, RiskStore};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Code, Request};

const AUDIENCE: &str = "urn:openshell:extension:risk-guard";
const TRUST_DOMAIN: &str = "example.org";

/// A stand-in for a SPIRE server: one signing CA, from which SVIDs are issued.
struct Authority {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Authority {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    fn bundle(&self) -> String {
        self.cert.pem()
    }

    /// An X.509-SVID for `uris`, as SPIRE issues it: a leaf with the IDs as URI SANs.
    fn svid(&self, uris: &[&str]) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI(Ia5String::try_from((*uri).to_string()).unwrap()))
            .collect();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        (cert, key)
    }
}

#[test]
fn only_a_genuine_x509_svid_yields_a_spiffe_id() {
    let authority = Authority::new();

    let (good, _) = authority.svid(&["spiffe://example.org/ns/prod/sa/bot"]);
    assert_eq!(
        spiffe_id_from_certificate(good.der()).unwrap().uri(),
        "spiffe://example.org/ns/prod/sa/bot"
    );

    let (none, _) = authority.svid(&[]);
    assert!(
        spiffe_id_from_certificate(none.der()).is_err(),
        "no URI SAN"
    );

    let (two, _) = authority.svid(&["spiffe://example.org/a", "spiffe://example.org/b"]);
    assert!(
        spiffe_id_from_certificate(two.der()).is_err(),
        "two IDs are ambiguous"
    );

    let (web, _) = authority.svid(&["https://example.org/a"]);
    assert!(
        spiffe_id_from_certificate(web.der()).is_err(),
        "not a SPIFFE URI"
    );

    let (bad, _) = authority.svid(&["spiffe://Example.org/a"]);
    assert!(
        spiffe_id_from_certificate(bad.der()).is_err(),
        "malformed SPIFFE ID"
    );

    // A certificate authority is not an SVID, even when it carries a SPIFFE URI.
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::URI(
        Ia5String::try_from("spiffe://example.org/ca".to_string()).unwrap(),
    )];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = params.self_signed(&key).unwrap();
    assert!(
        spiffe_id_from_certificate(ca.der()).is_err(),
        "a CA is not a leaf"
    );
}

struct Running {
    addr: SocketAddr,
    server_ca: String,
    store: Arc<SqliteRiskStore>,
    stop: Arc<tokio::sync::Notify>,
    _dir: tempfile::TempDir,
}

async fn start(authority: &Authority, trust_domains: &[&str]) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let secrets = dir.path().join("secrets");
    sidecar::generate_local_secrets(&secrets, &["127.0.0.1".into(), "localhost".into()]).unwrap();
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, authority.bundle()).unwrap();

    let store = Arc::new(SqliteRiskStore::open_in_memory().unwrap());
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version = "v1".into();
    store.store_baseline(&baseline).unwrap();

    let policy = SvidPolicy::new(trust_domains).unwrap();
    let verifier: Arc<dyn AuthVerifier> = Arc::new(SvidAuthVerifier::new(
        policy.clone(),
        Arc::clone(&store) as Arc<dyn RiskStore>,
        "svid-gateway",
        baseline.task_profile.clone(),
    ));
    let service = RiskGuardMiddlewareService::new(
        verifier,
        Arc::new(CanonicalNormalizer::new_default(&[9u8; 32])),
        Arc::new(InteractionRiskDetector::new_default()),
        Arc::clone(&store) as Arc<dyn RiskStore>,
        AUDIENCE,
    );

    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let server_tls = sidecar::listener_tls(
        addr,
        Some(&secrets.join("tls.crt")),
        Some(&secrets.join("tls.key")),
        false,
    )
    .unwrap()
    .unwrap();
    let stop = Arc::new(tokio::sync::Notify::new());
    let stopper = Arc::clone(&stop);
    tokio::spawn(async move {
        let _ = serve_svid_listener(addr, server_tls, bundle, policy, service, move || {
            let stopper = Arc::clone(&stopper);
            async move { stopper.notified().await }
        })
        .await;
    });
    // The listener binds asynchronously.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Running {
        addr,
        server_ca: std::fs::read_to_string(secrets.join("ca.crt")).unwrap(),
        store,
        stop,
        _dir: dir,
    }
}

async fn connect(
    running: &Running,
    identity: Option<(&rcgen::Certificate, &KeyPair)>,
) -> Result<Channel, tonic::transport::Error> {
    let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&running.server_ca));
    if let Some((cert, key)) = identity {
        tls = tls.identity(Identity::from_pem(cert.pem(), key.serialize_pem()));
    }
    Endpoint::from_shared(format!("https://{}", running.addr))?
        .tls_config(tls)?
        .connect()
        .await
}

fn evaluation(sandbox: &str, method: &str, path: &str, id: &str) -> Request<HttpRequestEvaluation> {
    Request::new(HttpRequestEvaluation {
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: id.into(),
            sandbox_id: sandbox.into(),
            originating_process: Some(Process {
                binary: "/usr/bin/curl".into(),
                pid: 4242,
                ancestors: vec![],
            }),
            sandbox: sandbox.into(),
            workspace: "spiffe".into(),
        }),
        config: None,
        target: Some(HttpRequestTarget {
            scheme: "https".into(),
            host: "api.github.local".into(),
            port: 18443,
            method: method.into(),
            path: path.into(),
            query: String::new(),
        }),
        headers: vec![],
        body: vec![],
        middleware_name: "risk-guard".into(),
    })
}

#[tokio::test]
async fn a_caller_is_known_by_its_certificate_and_only_speaks_for_its_own_sandbox() {
    let authority = Authority::new();
    let running = start(&authority, &[TRUST_DOMAIN]).await;
    let me = SpiffeId::parse("spiffe://example.org/ns/prod/sa/release-bot").unwrap();
    let other = SpiffeId::parse("spiffe://example.org/ns/prod/sa/someone-else").unwrap();
    let (cert, key) = authority.svid(&[&me.uri()]);
    let mut client =
        SupervisorMiddlewareClient::new(connect(&running, Some((&cert, &key))).await.unwrap());

    let allowed = client
        .evaluate_http_request(evaluation(
            &me.sandbox_id(),
            "GET",
            "/repos/org/docs-site/issues",
            "r1",
        ))
        .await
        .expect("an SVID caller is evaluated for its own sandbox")
        .into_inner();
    assert_eq!(allowed.decision, Decision::Allow as i32);

    // The first call enrolled the sandbox and bound a workload derived from the SPIFFE ID.
    assert!(
        running
            .store
            .get_active_epoch(&me.sandbox_id())
            .unwrap()
            .is_some()
    );

    // It cannot evaluate for someone else's sandbox ...
    let cross = client
        .evaluate_http_request(evaluation(
            &other.sandbox_id(),
            "GET",
            "/repos/org/docs-site/issues",
            "r2",
        ))
        .await
        .unwrap_err();
    assert_eq!(cross.code(), Code::PermissionDenied);

    // ... and claiming another identity in a header changes nothing: the listener overwrites it with the certificate's.
    let mut forged = evaluation(
        &other.sandbox_id(),
        "GET",
        "/repos/org/docs-site/issues",
        "r3",
    );
    forged.metadata_mut().insert(
        PEER_SPIFFE_HEADER,
        MetadataValue::try_from(other.uri()).unwrap(),
    );
    let forged = client.evaluate_http_request(forged).await.unwrap_err();
    assert_eq!(
        forged.code(),
        Code::PermissionDenied,
        "a forged identity header must not be believed"
    );
    assert!(
        running
            .store
            .get_active_epoch(&other.sandbox_id())
            .unwrap()
            .is_none(),
        "the forged identity must not have been enrolled"
    );
    running.stop.notify_one();
}

#[tokio::test]
async fn certificates_that_do_not_chain_to_the_bundle_or_name_another_trust_domain_are_refused() {
    let authority = Authority::new();
    let running = start(&authority, &[TRUST_DOMAIN]).await;
    let id = SpiffeId::parse("spiffe://example.org/ns/prod/sa/bot").unwrap();

    // No client certificate: the handshake or the first call fails.
    let anonymous = match connect(&running, None).await {
        Err(_) => None,
        Ok(channel) => SupervisorMiddlewareClient::new(channel)
            .evaluate_http_request(evaluation(
                &id.sandbox_id(),
                "GET",
                "/repos/org/docs-site/issues",
                "a",
            ))
            .await
            .err(),
    };
    assert!(
        anonymous.is_some(),
        "a caller with no certificate must not be served"
    );

    // A certificate from a different authority (not in the bundle).
    let stranger = Authority::new();
    let (cert, key) = stranger.svid(&[&id.uri()]);
    let untrusted = match connect(&running, Some((&cert, &key))).await {
        Err(_) => None,
        Ok(channel) => SupervisorMiddlewareClient::new(channel)
            .evaluate_http_request(evaluation(
                &id.sandbox_id(),
                "GET",
                "/repos/org/docs-site/issues",
                "b",
            ))
            .await
            .err(),
    };
    assert!(
        untrusted.is_some(),
        "a certificate outside the trust bundle must not be served"
    );

    // Signed by the right authority, but for a trust domain the operator did not allow.
    let foreign = SpiffeId::parse("spiffe://evil.org/ns/prod/sa/bot").unwrap();
    let (cert, key) = authority.svid(&[&foreign.uri()]);
    let mut client =
        SupervisorMiddlewareClient::new(connect(&running, Some((&cert, &key))).await.unwrap());
    let refused = client
        .evaluate_http_request(evaluation(
            &foreign.sandbox_id(),
            "GET",
            "/repos/org/docs-site/issues",
            "c",
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied);
    assert!(
        running
            .store
            .get_active_epoch(&foreign.sandbox_id())
            .unwrap()
            .is_none()
    );
    running.stop.notify_one();
}

#[tokio::test]
async fn an_svid_workload_is_scored_like_any_other_and_a_destructive_call_is_denied() {
    let authority = Authority::new();
    let running = start(&authority, &[TRUST_DOMAIN]).await;
    let me = SpiffeId::parse("spiffe://example.org/ns/prod/sa/attacker").unwrap();
    let (cert, key) = authority.svid(&[&me.uri()]);
    let mut client =
        SupervisorMiddlewareClient::new(connect(&running, Some((&cert, &key))).await.unwrap());
    let denied = client
        .evaluate_http_request(evaluation(
            &me.sandbox_id(),
            "DELETE",
            "/repos/org/payments-prod",
            "d1",
        ))
        .await
        .expect("a deny is a decision, not an error")
        .into_inner();
    assert_eq!(denied.decision, Decision::Deny as i32);
    running.stop.notify_one();
}

#[tokio::test]
async fn the_probe_command_reports_a_decision_for_the_workload_that_owns_the_svid() {
    let authority = Authority::new();
    let running = start(&authority, &[TRUST_DOMAIN]).await;
    let me = SpiffeId::parse("spiffe://example.org/ns/prod/sa/probe").unwrap();
    let (cert, key) = authority.svid(&[&me.uri()]);
    let (svid_pem, key_pem) = (cert.pem(), key.serialize_pem());
    let probe = |method: &'static str, path: &'static str| {
        let endpoint = format!("https://{}", running.addr);
        let ca = running.server_ca.clone();
        let (svid_pem, key_pem) = (svid_pem.clone(), key_pem.clone());
        async move {
            openshell_risk_guard::spiffe::probe(&openshell_risk_guard::spiffe::ProbeRequest {
                endpoint: &endpoint,
                server_ca_pem: &ca,
                server_name: Some("localhost"),
                svid_pem: &svid_pem,
                svid_key_pem: &key_pem,
                method,
                host: "api.github.local",
                port: 18443,
                path,
            })
            .await
            .unwrap()
        }
    };
    let allowed = probe("GET", "/repos/org/docs-site/issues").await;
    assert_eq!(allowed["decision"], "allow");
    assert_eq!(allowed["spiffe_id"], me.uri());
    assert_eq!(allowed["sandbox_id"], me.sandbox_id());
    let denied = probe("DELETE", "/repos/org/payments-prod").await;
    assert_eq!(denied["decision"], "deny");
    running.stop.notify_one();
}
