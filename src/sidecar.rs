// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Sidecar runtime concerns: listener transport security, mounted secrets, and
//! the standard `grpc.health.v1` probe used by Kubernetes and Compose.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::task::{Context, Poll};

use tonic::codegen::{Body, BoxFuture, StdError, http};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig};

use crate::error::{Result, RiskGuardError};
use crate::store::SqliteRiskStore;

/// Test-only resource key, accepted solely with `--allow-insecure-local-test`.
pub const INSECURE_TEST_HMAC_KEY: &[u8] = b"openshell-risk-guard-hmac-key";

/// Minimum length of an operator-provisioned resource HMAC key.
pub const MIN_HMAC_KEY_BYTES: usize = 32;

const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

fn read_secret(path: &Path, what: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        RiskGuardError::InvalidArgument(format!("{what} '{}': {error}", path.display()))
    })?;
    if !metadata.is_file() || metadata.len() > MAX_SECRET_FILE_BYTES {
        return Err(RiskGuardError::InvalidArgument(format!(
            "{what} '{}' must be a regular file of at most {MAX_SECRET_FILE_BYTES} bytes",
            path.display()
        )));
    }
    std::fs::read(path).map_err(|error| {
        RiskGuardError::InvalidArgument(format!("{what} '{}': {error}", path.display()))
    })
}

/// Resolve the listener's TLS identity.
///
/// Plaintext is accepted only on loopback, where the gateway and supervisors share
/// the host, or with the explicit insecure local-test flag. Any listener that
/// sandbox supervisors reach over a network must present a certificate; the
/// gateway's EdDSA JWT remains the caller authentication on top of TLS.
pub fn listener_tls(
    listen: SocketAddr,
    cert: Option<&Path>,
    key: Option<&Path>,
    allow_insecure_local_test: bool,
) -> Result<Option<ServerTlsConfig>> {
    match (cert, key) {
        (Some(cert), Some(key)) => {
            let cert = read_secret(cert, "TLS certificate")?;
            let key = read_secret(key, "TLS private key")?;
            Ok(Some(ServerTlsConfig::new().identity(Identity::from_pem(cert, key))))
        }
        (None, None) if listen.ip().is_loopback() || allow_insecure_local_test => Ok(None),
        (None, None) => Err(RiskGuardError::InvalidArgument(format!(
            "plaintext gRPC is only allowed on loopback; {listen} needs --tls-cert and --tls-key"
        ))),
        _ => Err(RiskGuardError::InvalidArgument(
            "--tls-cert and --tls-key must be supplied together".into(),
        )),
    }
}

/// Load the resource HMAC key from a mounted secret file.
///
/// Without a file, only the explicit insecure local-test mode may fall back to the
/// public test key; real deployments refuse to start.
pub fn resource_hmac_key(path: Option<&Path>, allow_insecure_local_test: bool) -> Result<Vec<u8>> {
    let Some(path) = path else {
        if allow_insecure_local_test {
            tracing::warn!("using the public test resource HMAC key (--allow-insecure-local-test)");
            return Ok(INSECURE_TEST_HMAC_KEY.to_vec());
        }
        return Err(RiskGuardError::InvalidArgument(
            "--hmac-key-file is required unless --allow-insecure-local-test is explicitly enabled"
                .into(),
        ));
    };
    let raw = read_secret(path, "resource HMAC key file")?;
    let key = raw.trim_ascii().to_vec();
    if key.len() < MIN_HMAC_KEY_BYTES {
        return Err(RiskGuardError::InvalidArgument(format!(
            "resource HMAC key file must contain at least {MIN_HMAC_KEY_BYTES} bytes"
        )));
    }
    Ok(key)
}

fn write_new_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        RiskGuardError::InvalidArgument(format!(
            "refusing to create '{}': {error} (existing secrets are never overwritten)",
            path.display()
        ))
    })?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| RiskGuardError::Internal(format!("writing '{}': {error}", path.display())))
}

/// Generate a local-test CA, a server certificate for `sans`, its key, and a resource
/// HMAC key into a new private directory. Production deployments use their own PKI and
/// secret store; this exists so local rehearsals exercise the same TLS + JWT path.
pub fn generate_local_secrets(out_dir: &Path, sans: &[String]) -> Result<serde_json::Value> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

    if sans.is_empty() {
        return Err(RiskGuardError::InvalidArgument("at least one --san is required".into()));
    }
    std::fs::create_dir_all(out_dir).map_err(|error| {
        RiskGuardError::InvalidArgument(format!("creating '{}': {error}", out_dir.display()))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| RiskGuardError::Internal(format!("securing '{}': {error}", out_dir.display())),
        )?;
    }
    let tls_error = |error: rcgen::Error| RiskGuardError::Internal(format!("certificate generation: {error}"));
    let year = 1970
        + i32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() / 31_556_952),
        )
        .unwrap_or(0);

    let ca_key = KeyPair::generate().map_err(tls_error)?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(tls_error)?;
    ca_params.distinguished_name.push(DnType::CommonName, "openshell-risk-guard local test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(year + 2, 1, 1);
    let ca_cert = ca_params.self_signed(&ca_key).map_err(tls_error)?;

    let server_key = KeyPair::generate().map_err(tls_error)?;
    let mut server_params = CertificateParams::new(sans.to_vec()).map_err(tls_error)?;
    server_params.distinguished_name.push(DnType::CommonName, "openshell-risk-guard");
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    server_params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
    server_params.not_after = rcgen::date_time_ymd(year + 1, 12, 31);
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .map_err(tls_error)?;

    let hmac_key = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let files = [
        ("ca.crt", ca_cert.pem()),
        ("tls.crt", server_cert.pem()),
        ("tls.key", server_key.serialize_pem()),
        ("hmac.key", hmac_key),
    ];
    for (name, contents) in &files {
        write_new_private(&out_dir.join(name), contents.as_bytes())?;
    }
    Ok(serde_json::json!({
        "status": "generated",
        "out_dir": out_dir,
        "files": files.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        "subject_alt_names": sans,
        "note": "local test PKI; register ca.crt as tls_ca_cert_path and never reuse it in production",
    }))
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HealthCheckRequest {
    #[prost(string, tag = "1")]
    pub service: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HealthCheckResponse {
    #[prost(int32, tag = "1")]
    pub status: i32,
}

/// `grpc.health.v1.HealthCheckResponse.ServingStatus` values.
pub const SERVING: i32 = 1;
pub const NOT_SERVING: i32 = 2;

/// Ask a running sidecar whether it is serving, over TLS when the endpoint is `https://`.
///
/// Kubernetes' built-in gRPC probe cannot speak TLS, so a TLS-only listener needs an exec probe. This is that
/// probe: it connects, calls `grpc.health.v1.Health/Check` and succeeds only on SERVING. `ca_pem` is the CA that
/// signed the sidecar's certificate and `server_name` the DNS name on it (the endpoint may be a loopback address).
pub async fn probe_health(
    endpoint: &str,
    ca_pem: Option<&Path>,
    server_name: Option<&str>,
    timeout: std::time::Duration,
) -> Result<()> {
    let mut builder = Endpoint::from_shared(endpoint.to_string())
        .map_err(|err| RiskGuardError::InvalidArgument(format!("invalid endpoint '{endpoint}': {err}")))?
        .connect_timeout(timeout)
        .timeout(timeout);
    if endpoint.starts_with("https://") {
        let mut tls = ClientTlsConfig::new();
        if let Some(path) = ca_pem {
            let pem = std::fs::read(path)
                .map_err(|err| RiskGuardError::InvalidArgument(format!("cannot read CA {}: {err}", path.display())))?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }
        if let Some(name) = server_name {
            tls = tls.domain_name(name.to_string());
        }
        builder = builder
            .tls_config(tls)
            .map_err(|err| RiskGuardError::InvalidArgument(format!("invalid TLS settings: {err}")))?;
    }
    let channel = builder
        .connect()
        .await
        .map_err(|err| RiskGuardError::Internal(format!("cannot connect to {endpoint}: {err}")))?;
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|err| RiskGuardError::Internal(format!("channel not ready: {err}")))?;
    let response = grpc
        .unary(
            tonic::Request::new(HealthCheckRequest { service: String::new() }),
            http::uri::PathAndQuery::from_static("/grpc.health.v1.Health/Check"),
            tonic_prost::ProstCodec::<HealthCheckRequest, HealthCheckResponse>::default(),
        )
        .await
        .map_err(|status| RiskGuardError::Internal(format!("health check failed: {status}")))?
        .into_inner();
    if response.status == SERVING {
        Ok(())
    } else {
        Err(RiskGuardError::Internal("the sidecar reports NOT_SERVING".into()))
    }
}

/// Minimal `grpc.health.v1.Health/Check`. The sidecar reports SERVING only while
/// its decision store answers; a broken store is NOT_SERVING, matching fail-closed
/// evaluation. `Watch` is not implemented and returns UNIMPLEMENTED.
#[derive(Clone)]
pub struct HealthServer {
    store: Arc<SqliteRiskStore>,
}

impl HealthServer {
    #[must_use]
    pub fn new(store: Arc<SqliteRiskStore>) -> Self {
        Self { store }
    }

    async fn check(store: Arc<SqliteRiskStore>, request: HealthCheckRequest) -> std::result::Result<HealthCheckResponse, tonic::Status> {
        let known = ["", "openshell.middleware.v1.SupervisorMiddleware",
            "openshell.gateway_interceptor.v1.GatewayInterceptor"];
        if !known.contains(&request.service.as_str()) {
            return Err(tonic::Status::not_found("unknown service"));
        }
        let healthy = tokio::task::spawn_blocking(move || store.verify_pragmas().is_ok())
            .await
            .unwrap_or(false);
        Ok(HealthCheckResponse { status: if healthy { SERVING } else { NOT_SERVING } })
    }
}

impl tonic::server::NamedService for HealthServer {
    const NAME: &'static str = "grpc.health.v1.Health";
}

struct CheckSvc(Arc<SqliteRiskStore>);

impl tonic::server::UnaryService<HealthCheckRequest> for CheckSvc {
    type Response = HealthCheckResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<HealthCheckRequest>) -> Self::Future {
        let store = Arc::clone(&self.0);
        Box::pin(async move {
            HealthServer::check(store, request.into_inner()).await.map(tonic::Response::new)
        })
    }
}

impl<B> tonic::codegen::Service<http::Request<B>> for HealthServer
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        if req.uri().path() == "/grpc.health.v1.Health/Check" {
            let store = Arc::clone(&self.store);
            return Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Ok(grpc.unary(CheckSvc(store), req).await)
            });
        }
        Box::pin(async move {
            let mut response = http::Response::new(tonic::body::Body::default());
            let headers = response.headers_mut();
            headers.insert(tonic::Status::GRPC_STATUS, (tonic::Code::Unimplemented as i32).into());
            headers.insert(http::header::CONTENT_TYPE, tonic::metadata::GRPC_CONTENT_TYPE);
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_is_loopback_only_unless_explicitly_insecure() {
        let loopback: SocketAddr = "127.0.0.1:50061".parse().unwrap();
        let shared: SocketAddr = "0.0.0.0:50061".parse().unwrap();
        assert!(listener_tls(loopback, None, None, false).unwrap().is_none());
        assert!(listener_tls(shared, None, None, false).is_err());
        assert!(listener_tls(shared, None, None, true).unwrap().is_none());
        assert!(listener_tls(loopback, Some(Path::new("/cert.pem")), None, false).is_err());
    }

    #[test]
    fn resource_key_requires_a_mounted_secret_of_sufficient_length() {
        assert!(resource_hmac_key(None, false).is_err());
        assert_eq!(resource_hmac_key(None, true).unwrap(), INSECURE_TEST_HMAC_KEY);
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short");
        std::fs::write(&short, "too-short\n").unwrap();
        assert!(resource_hmac_key(Some(&short), false).is_err());
        let good = dir.path().join("good");
        std::fs::write(&good, format!("{}\n", "k".repeat(MIN_HMAC_KEY_BYTES))).unwrap();
        assert_eq!(resource_hmac_key(Some(&good), false).unwrap().len(), MIN_HMAC_KEY_BYTES);
    }

    #[tokio::test]
    async fn health_reports_serving_for_a_working_store_and_rejects_unknown_services() {
        let store = Arc::new(SqliteRiskStore::open_in_memory().unwrap());
        let ok = HealthServer::check(Arc::clone(&store), HealthCheckRequest { service: String::new() })
            .await
            .unwrap();
        assert_eq!(ok.status, SERVING);
        let unknown = HealthServer::check(store, HealthCheckRequest { service: "other".into() }).await;
        assert_eq!(unknown.unwrap_err().code(), tonic::Code::NotFound);
    }
}
