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
use openshell_risk_guard::ext_authz::{
    Address, AttributeContext, AttributeRequest, CheckRequest, CheckResponse, ExtAuthzService,
    HttpRequest, Peer, SocketAddress,
};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::middleware_service::RiskGuardMiddlewareService;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::pod_resolver::{PodResolver, StaticPodResolver};
use openshell_risk_guard::sidecar;
use openshell_risk_guard::spiffe::{
    PEER_SPIFFE_HEADER, SpiffeId, SvidAuthVerifier, SvidEnroller, SvidPolicy, serve_svid_listener,
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
    start_with_proxies(authority, trust_domains, &[]).await
}

async fn start_with_proxies(
    authority: &Authority,
    trust_domains: &[&str],
    proxies: &[&str],
) -> Running {
    start_full(authority, trust_domains, proxies, None).await
}

async fn start_full(
    authority: &Authority,
    trust_domains: &[&str],
    proxies: &[&str],
    tunnels: Option<Arc<dyn PodResolver>>,
) -> Running {
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
    let enroller = Arc::new(SvidEnroller::new(
        Arc::clone(&store) as Arc<dyn RiskStore>,
        "svid-gateway",
        baseline.task_profile.clone(),
    ));
    let verifier: Arc<dyn AuthVerifier> = Arc::new(SvidAuthVerifier::with_enroller(
        policy.clone(),
        Arc::clone(&enroller),
    ));
    let ext_authz = if proxies.is_empty() {
        None
    } else {
        let service = ExtAuthzService::new(
            Arc::clone(&store) as Arc<dyn RiskStore>,
            Arc::new(CanonicalNormalizer::new_default(&[9u8; 32])),
            Arc::new(InteractionRiskDetector::new_default()),
            enroller,
            policy.clone(),
            proxies,
        )
        .unwrap();
        Some(match tunnels {
            Some(resolver) => service.with_tunnel_resolver(resolver),
            None => service,
        })
    };
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
        let _ = serve_svid_listener(
            addr,
            server_tls,
            bundle,
            policy,
            service,
            ext_authz,
            move || {
                let stopper = Arc::clone(&stopper);
                async move { stopper.notified().await }
            },
        )
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

async fn check(
    channel: Channel,
    workload: &str,
    method: &str,
    path: &str,
) -> Result<CheckResponse, tonic::Status> {
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    grpc.unary(
        Request::new(CheckRequest {
            attributes: Some(AttributeContext {
                source: Some(Peer {
                    address: None,
                    service: String::new(),
                    principal: workload.to_string(),
                }),
                request: Some(AttributeRequest {
                    http: Some(HttpRequest {
                        id: uuid_like(method, path),
                        method: method.into(),
                        path: path.into(),
                        host: "api.github.local:443".into(),
                        scheme: "https".into(),
                    }),
                }),
            }),
        }),
        tonic::codegen::http::uri::PathAndQuery::from_static(
            "/envoy.service.auth.v3.Authorization/Check",
        ),
        tonic_prost::ProstCodec::<CheckRequest, CheckResponse>::default(),
    )
    .await
    .map(tonic::Response::into_inner)
}

fn uuid_like(method: &str, path: &str) -> String {
    format!("check-{method}-{}", path.replace('/', "_"))
}

#[tokio::test]
async fn a_trusted_proxy_gets_allow_and_deny_decisions_for_the_workload_it_verified() {
    let authority = Authority::new();
    let proxy_id = "spiffe://example.org/ns/edge/sa/egress-proxy";
    let running = start_with_proxies(&authority, &[TRUST_DOMAIN], &[proxy_id]).await;
    let (cert, key) = authority.svid(&[proxy_id]);
    let channel = connect(&running, Some((&cert, &key))).await.unwrap();
    let workload = "spiffe://example.org/ns/prod/sa/release-bot";

    let allowed = check(
        channel.clone(),
        workload,
        "GET",
        "/repos/org/docs-site/issues",
    )
    .await
    .unwrap();
    assert!(
        allowed.ok_response.is_some() && allowed.denied_response.is_none(),
        "{allowed:?}"
    );

    let denied = check(
        channel.clone(),
        workload,
        "DELETE",
        "/repos/org/payments-prod?force=1",
    )
    .await
    .unwrap();
    assert_eq!(denied.denied_response.unwrap().status.unwrap().code, 403);
    assert_eq!(denied.status.unwrap().code, 7);

    // The workload was enrolled under its own identity, not the proxy's.
    let id = SpiffeId::parse(workload).unwrap();
    assert!(
        running
            .store
            .get_active_epoch(&id.sandbox_id())
            .unwrap()
            .is_some()
    );
    let proxy = SpiffeId::parse(proxy_id).unwrap();
    assert!(
        running
            .store
            .get_active_epoch(&proxy.sandbox_id())
            .unwrap()
            .is_none()
    );

    // No verified identity for the downstream caller, or one from another trust domain: nothing to score, so no forward.
    for principal in ["", "CN=someone", "spiffe://evil.org/ns/prod/sa/bot"] {
        let refused = check(
            channel.clone(),
            principal,
            "GET",
            "/repos/org/docs-site/issues",
        )
        .await
        .unwrap();
        assert!(
            refused.denied_response.is_some(),
            "{principal:?} must not be forwarded"
        );
    }
    running.stop.notify_one();
}

#[tokio::test]
async fn only_a_listed_proxy_may_ask_and_a_workload_cannot_vouch_for_itself() {
    let authority = Authority::new();
    let proxy_id = "spiffe://example.org/ns/edge/sa/egress-proxy";
    let running = start_with_proxies(&authority, &[TRUST_DOMAIN], &[proxy_id]).await;

    // A workload with a perfectly good SVID is still not a proxy: it cannot claim to be someone else's gateway.
    let (cert, key) = authority.svid(&["spiffe://example.org/ns/prod/sa/release-bot"]);
    let channel = connect(&running, Some((&cert, &key))).await.unwrap();
    let error = check(
        channel,
        "spiffe://example.org/ns/prod/sa/release-bot",
        "GET",
        "/repos/org/docs-site/issues",
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    running.stop.notify_one();
}

async fn tunnel_check(channel: Channel, source_ip: &str) -> CheckResponse {
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    grpc.unary(
        Request::new(CheckRequest {
            attributes: Some(AttributeContext {
                source: Some(Peer {
                    address: Some(Address {
                        socket_address: Some(SocketAddress {
                            address: source_ip.to_string(),
                        }),
                    }),
                    service: String::new(),
                    principal: String::new(),
                }),
                request: Some(AttributeRequest {
                    http: Some(HttpRequest {
                        id: String::new(),
                        method: "CONNECT".into(),
                        path: String::new(),
                        host: "93.184.216.34:443".into(),
                        scheme: String::new(),
                    }),
                }),
            }),
        }),
        tonic::codegen::http::uri::PathAndQuery::from_static(
            "/envoy.service.auth.v3.Authorization/Check",
        ),
        tonic_prost::ProstCodec::<CheckRequest, CheckResponse>::default(),
    )
    .await
    .unwrap()
    .into_inner()
}

#[tokio::test]
async fn a_sandbox_tunnel_is_carried_unless_the_sandbox_is_unknown_or_its_workload_is_locked() {
    use openshell_risk_guard::detector::compute_baseline_hash;
    use openshell_risk_guard::types::{EnforcementMode, EpochRecord, RawRequestInput};

    let authority = Authority::new();
    let proxy_id = "spiffe://example.org/ns/edge/sa/sandbox-egress";
    let resolver: Arc<dyn PodResolver> = Arc::new(StaticPodResolver(
        [
            ("10.0.0.1".parse().unwrap(), "sbx-open".to_string()),
            ("10.0.0.2".parse().unwrap(), "sbx-locked".to_string()),
            (
                "10.0.0.3".parse().unwrap(),
                "sbx-never-registered".to_string(),
            ),
        ]
        .into(),
    ));
    let running = start_full(&authority, &[TRUST_DOMAIN], &[proxy_id], Some(resolver)).await;

    let baseline = build_standard_corpus().default_baseline;
    for sandbox in ["sbx-open", "sbx-locked"] {
        running
            .store
            .upsert_epoch(&EpochRecord {
                epoch_id: format!("ep-{sandbox}"),
                gateway_id: "svid-gateway".into(),
                sandbox_id: sandbox.into(),
                task_profile: baseline.task_profile.clone(),
                baseline_hash: compute_baseline_hash(&baseline),
                mode: EnforcementMode::Enforce,
                active: true,
                next_sequence: 1,
                created_at_ms: 0,
                credentialed_endpoints: Default::default(),
                active_policy_hash: None,
            })
            .unwrap();
    }

    // Lock one sandbox's workload the way the supervisor path does: by repeating a destructive call until the ratchet latches.
    let normalizer = CanonicalNormalizer::new_default(&[9u8; 32]);
    let detector = InteractionRiskDetector::new_default();
    for n in 0..20_i64 {
        let request = normalizer
            .normalize(&RawRequestInput {
                request_id: format!("lock-{n}"),
                sandbox_id: "sbx-locked".into(),
                sandbox_name: "sbx-locked".into(),
                workspace: "default".into(),
                scheme: "https".into(),
                host: "api.github.local".into(),
                port: 443,
                method: "DELETE".into(),
                path: "/repos/org/payments-prod".into(),
                binary_path: None,
                pid: None,
                ancestors: vec![],
                timestamp_ms: 1_800_000_000_000 + n * 1_000,
            })
            .unwrap();
        let _ = running
            .store
            .evaluate_authenticated(&request, &detector, "svid-gateway", false);
        if running.store.sandbox_lock_state("sbx-locked").unwrap() == Some(true) {
            break;
        }
    }
    assert_eq!(
        running.store.sandbox_lock_state("sbx-locked").unwrap(),
        Some(true),
        "the test needs a locked workload"
    );
    assert_eq!(
        running.store.sandbox_lock_state("sbx-open").unwrap(),
        Some(false)
    );

    let (cert, key) = authority.svid(&[proxy_id]);
    let channel = connect(&running, Some((&cert, &key))).await.unwrap();
    let carried = tunnel_check(channel.clone(), "10.0.0.1").await;
    assert!(
        carried.ok_response.is_some(),
        "an unlocked sandbox's tunnel is carried: {carried:?}"
    );
    for (source, why) in [
        ("10.0.0.2", "a locked workload"),
        ("10.0.0.3", "a sandbox Risk Guard has no record of"),
        ("10.9.9.9", "an address that is no sandbox"),
        ("not-an-address", "a malformed address"),
    ] {
        let refused = tunnel_check(channel.clone(), source).await;
        assert!(
            refused.denied_response.is_some(),
            "{why} must not get a tunnel: {refused:?}"
        );
    }
    running.stop.notify_one();
}

#[tokio::test]
async fn tunnel_checks_are_refused_when_they_are_not_enabled() {
    let authority = Authority::new();
    let proxy_id = "spiffe://example.org/ns/edge/sa/sandbox-egress";
    let running = start_with_proxies(&authority, &[TRUST_DOMAIN], &[proxy_id]).await;
    let (cert, key) = authority.svid(&[proxy_id]);
    let channel = connect(&running, Some((&cert, &key))).await.unwrap();
    let refused = tunnel_check(channel, "10.0.0.1").await;
    assert!(refused.denied_response.is_some());
    running.stop.notify_one();
}
