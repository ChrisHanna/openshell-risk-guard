//! The gateway/supervisor -> Risk Guard channel exactly as OpenShell uses it:
//! TLS that clients verify against the registered CA, plus a gateway-signed EdDSA
//! JWT on every call.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    Decision, HttpRequestEvaluation, HttpRequestTarget, Process, RequestContext,
    SupervisorMiddlewarePhase,
};
use openshell_risk_guard::auth::{
    EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims, JwtTestIssuer,
};
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::middleware_service::RiskGuardMiddlewareService;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::sidecar::{
    self, HealthCheckRequest, HealthCheckResponse, HealthServer, SERVING,
};
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::{AuthVerifier, EnforcementMode, EpochRecord, RiskStore};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Server};
use tonic::{Code, Request};

const GATEWAY: &str = "transport-gateway";
const AUDIENCE: &str = "urn:openshell:extension:risk-guard";
const SANDBOX: &str = "sandbox-tls";

struct Running {
    addr: SocketAddr,
    issuer: JwtTestIssuer,
    ca_pem: String,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start(secrets: &Path) -> Running {
    sidecar::generate_local_secrets(secrets, &["127.0.0.1".into(), "localhost".into()]).unwrap();
    let store = Arc::new(SqliteRiskStore::open_in_memory().unwrap());
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version = "v1".into();
    store.store_baseline(&baseline).unwrap();
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: "epoch-tls".into(),
            gateway_id: GATEWAY.into(),
            sandbox_id: SANDBOX.into(),
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

    let issuer = JwtTestIssuer::new(GATEWAY);
    let auth: Arc<dyn AuthVerifier> = Arc::new(issuer.verifier(AUDIENCE).unwrap());
    let middleware = RiskGuardMiddlewareService::new(
        auth,
        Arc::new(CanonicalNormalizer::new_default(&[9u8; 32])),
        Arc::new(InteractionRiskDetector::new_default()),
        Arc::clone(&store) as Arc<dyn RiskStore>,
        AUDIENCE,
    )
    .with_required_agent_identity(false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tls = sidecar::listener_tls(
        addr,
        Some(&secrets.join("tls.crt")),
        Some(&secrets.join("tls.key")),
        false,
    )
    .unwrap()
    .expect("TLS identity");
    let (shutdown, stop) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(HealthServer::new(store))
            .add_service(middleware.into_server())
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stop.await;
                },
            ),
    );
    Running {
        addr,
        issuer,
        ca_pem: std::fs::read_to_string(secrets.join("ca.crt")).unwrap(),
        _shutdown: shutdown,
    }
}

async fn tls_channel(addr: SocketAddr, ca_pem: &str) -> Result<Channel, tonic::transport::Error> {
    Endpoint::from_shared(format!("https://{addr}"))?
        .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem)))?
        .connect()
        .await
}

fn evaluation(token: Option<&str>, request_id: &str) -> Request<HttpRequestEvaluation> {
    let mut request = Request::new(HttpRequestEvaluation {
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: request_id.into(),
            sandbox_id: SANDBOX.into(),
            originating_process: Some(Process {
                binary: "/usr/bin/curl".into(),
                pid: 4242,
                ancestors: vec![],
            }),
            sandbox: SANDBOX.into(),
            workspace: "/workspace".into(),
        }),
        config: None,
        target: Some(HttpRequestTarget {
            scheme: "https".into(),
            host: "api.github.local".into(),
            port: 18443,
            method: "GET".into(),
            path: "/repos/org/docs-site/issues".into(),
            query: String::new(),
        }),
        headers: vec![],
        body: vec![],
        middleware_name: "risk-guard".into(),
    });
    if let Some(token) = token {
        *request.metadata_mut() = JwtTestIssuer::bearer_metadata(token).unwrap();
    }
    request
}

#[tokio::test]
async fn tls_plus_gateway_jwt_is_required_on_every_supervisor_call() {
    let dir = tempfile::tempdir().unwrap();
    let running = start(&dir.path().join("secrets")).await;
    let channel = tls_channel(running.addr, &running.ca_pem)
        .await
        .expect("TLS handshake");
    let mut client = SupervisorMiddlewareClient::new(channel.clone());

    let token = running
        .issuer
        .mint_supervisor_token(AUDIENCE, SANDBOX, 300)
        .unwrap();
    let allowed = client
        .evaluate_http_request(evaluation(Some(&token), "tls-authenticated"))
        .await
        .expect("authenticated call over TLS")
        .into_inner();
    assert_eq!(allowed.decision, Decision::Allow as i32);

    let anonymous = client
        .evaluate_http_request(evaluation(None, "tls-anonymous"))
        .await
        .unwrap_err();
    assert_eq!(anonymous.code(), Code::Unauthenticated);

    let other_sandbox = running
        .issuer
        .mint_supervisor_token(AUDIENCE, "other-sandbox", 300)
        .unwrap();
    let cross = client
        .evaluate_http_request(evaluation(Some(&other_sandbox), "tls-cross-sandbox"))
        .await
        .unwrap_err();
    assert_eq!(
        cross.code(),
        Code::PermissionDenied,
        "a sandbox cannot speak for another"
    );

    let gateway_token = running.issuer.mint_gateway_token(AUDIENCE, 300).unwrap();
    let wrong_kind = client
        .evaluate_http_request(evaluation(Some(&gateway_token), "tls-wrong-caller"))
        .await
        .unwrap_err();
    assert_eq!(
        wrong_kind.code(),
        Code::PermissionDenied,
        "caller kind is enforced per RPC"
    );

    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    let health: tonic::Response<HealthCheckResponse> = grpc
        .unary(
            tonic::Request::new(HealthCheckRequest {
                service: String::new(),
            }),
            http::uri::PathAndQuery::from_static("/grpc.health.v1.Health/Check"),
            tonic_prost::ProstCodec::default(),
        )
        .await
        .expect("health over TLS");
    assert_eq!(health.into_inner().status, SERVING);
}

#[tokio::test]
async fn clients_refuse_an_untrusted_certificate_and_plaintext_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let running = start(&dir.path().join("secrets")).await;

    let impostor = dir.path().join("impostor");
    sidecar::generate_local_secrets(&impostor, &["127.0.0.1".into()]).unwrap();
    let other_ca = std::fs::read_to_string(impostor.join("ca.crt")).unwrap();
    assert!(
        tls_channel(running.addr, &other_ca).await.is_err(),
        "a client trusting a different CA must not connect"
    );

    let token = running
        .issuer
        .mint_supervisor_token(AUDIENCE, SANDBOX, 300)
        .unwrap();
    let plaintext = match Endpoint::from_shared(format!("http://{}", running.addr))
        .unwrap()
        .connect()
        .await
    {
        Err(_) => true,
        Ok(channel) => SupervisorMiddlewareClient::new(channel)
            .evaluate_http_request(evaluation(Some(&token), "plaintext"))
            .await
            .is_err(),
    };
    assert!(plaintext, "the TLS listener must not answer plaintext gRPC");
}

#[tokio::test]
async fn the_health_probe_serves_over_tls_and_refuses_an_untrusted_ca() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let endpoint = format!("https://{}", server.addr);
    let timeout = Duration::from_secs(5);

    sidecar::probe_health(
        &endpoint,
        Some(&dir.path().join("ca.crt")),
        Some("localhost"),
        timeout,
    )
    .await
    .expect("a trusted CA must see SERVING");

    let impostor = tempfile::tempdir().unwrap();
    sidecar::generate_local_secrets(impostor.path(), &["127.0.0.1".into()]).unwrap();
    assert!(
        sidecar::probe_health(
            &endpoint,
            Some(&impostor.path().join("ca.crt")),
            Some("localhost"),
            timeout
        )
        .await
        .is_err(),
        "an untrusted CA must fail the probe"
    );
    assert!(
        sidecar::probe_health(
            "https://127.0.0.1:1",
            Some(&dir.path().join("ca.crt")),
            Some("localhost"),
            Duration::from_secs(1)
        )
        .await
        .is_err(),
        "nothing listening must fail the probe"
    );
}

#[test]
fn local_secrets_are_private_and_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("secrets");
    sidecar::generate_local_secrets(&out, &["127.0.0.1".into()]).unwrap();
    for name in ["ca.crt", "tls.crt", "tls.key", "hmac.key"] {
        assert!(out.join(name).metadata().unwrap().len() > 0, "{name}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            out.join("tls.key").metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(out.metadata().unwrap().permissions().mode() & 0o777, 0o700);
    }
    let key = std::fs::read(out.join("tls.key")).unwrap();
    assert!(sidecar::generate_local_secrets(&out, &["127.0.0.1".into()]).is_err());
    assert_eq!(
        std::fs::read(out.join("tls.key")).unwrap(),
        key,
        "existing key untouched"
    );
    assert!(sidecar::resource_hmac_key(Some(&out.join("hmac.key")), false).is_ok());
}

/// Failure containment: a token that is expired, meant for another service, or signed by someone else is refused with `Unauthenticated`,
/// whatever else is correct about the call. (The contract: the supervisor then fails closed, because the extension is configured that way.)
#[tokio::test]
async fn expired_misdirected_and_foreign_tokens_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let running = start(&dir.path().join("secrets")).await;
    let channel = tls_channel(running.addr, &running.ca_pem)
        .await
        .expect("TLS handshake");
    let mut client = SupervisorMiddlewareClient::new(channel);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = |audience: &str, issued: i64, expires: i64| ExtensionJwtClaims {
        iss: running.issuer.issuer(),
        aud: audience.to_string(),
        sub: format!("spiffe://openshell/sandbox/{SANDBOX}"),
        iat: issued,
        exp: expires,
        jti: format!("jti-{issued}-{expires}-{audience}"),
        caller_kind: ExtensionCallerKind::Supervisor,
        sandbox_id: Some(SANDBOX.to_string()),
    };
    let sign = |issuer: &JwtTestIssuer, claims: &ExtensionJwtClaims| {
        issuer
            .mint_with_claims(Some(EXTENSION_JWT_TYP), claims)
            .unwrap()
    };

    let control = sign(&running.issuer, &claims(AUDIENCE, now, now + 300));
    let expired = sign(&running.issuer, &claims(AUDIENCE, now - 600, now - 300));
    let misdirected = sign(&running.issuer, &claims("urn:someone:else", now, now + 300));
    let foreign = sign(
        &JwtTestIssuer::new(GATEWAY),
        &claims(AUDIENCE, now, now + 300),
    );

    let ok = client
        .evaluate_http_request(evaluation(Some(&control), "tok-control"))
        .await;
    assert!(ok.is_ok(), "the control token must be accepted: {ok:?}");
    for (name, token) in [
        ("expired", expired),
        ("wrong audience", misdirected),
        ("foreign signature", foreign),
    ] {
        let error = client
            .evaluate_http_request(evaluation(Some(&token), &format!("tok-{name}")))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unauthenticated, "{name}: {error:?}");
    }
}
