#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Extension, Path as AgentPath, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::error::{Result, RiskGuardError};
use crate::adaptive_controls::{AdaptiveOperation, AdaptiveUpdateResult};
use crate::guardrails::{GuardrailsSaveResult, GuardrailsUpdate};
use crate::store::SqliteRiskStore;

#[derive(Clone)]
pub(crate) struct OperatorControls {
    verifier: Option<[u8; 32]>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClearRestrictionRequest {
    scope: String,
    reason: String,
    #[serde(default)]
    context_id: Option<String>,
}

impl OperatorControls {
    pub(crate) fn disabled() -> Self {
        Self { verifier: None }
    }

    fn from_token(token: &str) -> Self {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(token.as_bytes()).expect("HMAC accepts this key length");
        mac.update(b"risk-guard-operator-v1");
        Self {
            verifier: Some(mac.finalize().into_bytes().into()),
        }
    }

    pub(crate) fn from_private_file(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            Self::from_unix_private_file(path)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(RiskGuardError::InvalidArgument(
                "operator editing requires Unix file-privacy validation; use WSL on Windows".into(),
            ))
        }
    }

    #[cfg(unix)]
    fn from_unix_private_file(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(RiskGuardError::InvalidArgument(
                "operator token file must be an absolute private runtime path".into(),
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            RiskGuardError::InvalidArgument("operator token file needs a parent directory".into())
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let metadata = std::fs::metadata(parent).map_err(|error| {
                RiskGuardError::InvalidArgument(format!("operator token directory: {error}"))
            })?;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(RiskGuardError::InvalidArgument(
                    "operator token directory must not be writable by other users".into(),
                ));
            }
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(mut file) => write_new_token(&mut file)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(RiskGuardError::InvalidArgument(format!(
                        "cannot create operator token file: {error}"
                    )));
                }
            }
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            RiskGuardError::InvalidArgument(format!("operator token metadata: {error}"))
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 128 {
            return Err(RiskGuardError::InvalidArgument(
                "operator token must be a small regular file, not a symlink".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(RiskGuardError::InvalidArgument(
                    "operator token file must be readable by its owner only (chmod 600)".into(),
                ));
            }
        }
        let mut raw = String::new();
        File::open(path)
            .and_then(|file| file.take(129).read_to_string(&mut raw))
            .map_err(|error| {
                RiskGuardError::InvalidArgument(format!("operator token read failed: {error}"))
            })?;
        let token = raw.trim();
        if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(RiskGuardError::InvalidArgument(
                "operator token file must contain exactly 64 hexadecimal characters".into(),
            ));
        }
        Ok(Self::from_token(token))
    }

    fn authorize(&self, headers: &HeaderMap) -> std::result::Result<(), Response> {
        let Some(expected) = &self.verifier else {
            return Err((StatusCode::NOT_FOUND, Json(json!({
                "error": "operator controls are disabled; start dashboard with --operator-token-file"
            }))).into_response());
        };
        let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
        let origin = headers
            .get(header::ORIGIN)
            .and_then(|h| h.to_str().ok())
            .and_then(|value| value.parse::<Uri>().ok());
        let same_origin = origin.as_ref().is_some_and(|origin| {
            origin.scheme_str() == Some("http")
                && origin.path() == "/"
                && origin.query().is_none()
                && origin
                    .authority()
                    .zip(host)
                    .is_some_and(|(authority, host)| authority.as_str().eq_ignore_ascii_case(host))
        });
        let fetch_site_ok = headers
            .get("sec-fetch-site")
            .is_none_or(|site| site == "same-origin" || site == "none");
        if !same_origin || !fetch_site_ok {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "operator writes require the dashboard's exact same origin"
                })),
            )
                .into_response());
        }
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        let valid = provided.is_some_and(|token| {
            if token.len() != 64 {
                return false;
            }
            let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
                .expect("HMAC accepts this key length");
            mac.update(b"risk-guard-operator-v1");
            mac.verify_slice(expected).is_ok()
        });
        if !valid {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "unlock editing with the private local operator token"
                })),
            )
                .into_response());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn write_new_token(file: &mut File) -> Result<()> {
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    file.write_all(token.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            RiskGuardError::Internal(format!("operator token creation failed: {error}"))
        })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

fn error_response(error: RiskGuardError) -> Response {
    let status = match &error {
        RiskGuardError::InvalidArgument(_) => StatusCode::BAD_REQUEST,
        RiskGuardError::Policy(_) => StatusCode::UNPROCESSABLE_ENTITY,
        RiskGuardError::PermissionDenied(_) => StatusCode::FORBIDDEN,
        RiskGuardError::Unauthenticated(_) => StatusCode::UNAUTHORIZED,
        _ => {
            tracing::error!(%error, "operator guardrail operation failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "guardrail operation failed; inspect service logs"
                })),
            )
                .into_response();
        }
    };
    (status, Json(json!({"error": error.to_string()}))).into_response()
}

pub(crate) fn routes() -> Router<Arc<SqliteRiskStore>> {
    Router::new()
        .route("/api/operator/status", get(
            |Extension(controls): Extension<OperatorControls>| async move {
                Json(json!({"enabled": controls.verifier.is_some()}))
            },
        ))
        .route("/api/operator/verify", post(
            |Extension(controls): Extension<OperatorControls>, headers: HeaderMap| async move {
                match controls.authorize(&headers) {
                    Ok(()) => Json(json!({"authorized": true})).into_response(),
                    Err(response) => response,
                }
            },
        ))
        .route("/api/agents/{agent_id}/guardrails", get(
            |State(store): State<Arc<SqliteRiskStore>>, AgentPath(agent): AgentPath<String>| async move {
                match tokio::task::spawn_blocking(move || store.agent_guardrails(&agent, now_ms())).await {
                    Ok(Ok(Some(view))) => Json(view).into_response(),
                    Ok(Ok(None)) => (StatusCode::NOT_FOUND, Json(json!({"error":"workload not found"}))).into_response(),
                    Ok(Err(error)) => error_response(error),
                    Err(error) => error_response(RiskGuardError::Internal(error.to_string())),
                }
            },
        ).put(
            |State(store): State<Arc<SqliteRiskStore>>,
             Extension(controls): Extension<OperatorControls>,
             AgentPath(agent): AgentPath<String>,
             headers: HeaderMap,
             payload: std::result::Result<Json<GuardrailsUpdate>, axum::extract::rejection::JsonRejection>| async move {
                if let Err(response) = controls.authorize(&headers) { return response; }
                let update = match payload {
                    Ok(Json(update)) => update,
                    Err(error) => return (error.status(), Json(json!({"error": error.body_text()}))).into_response(),
                };
                match tokio::task::spawn_blocking(move || {
                    store.save_agent_guardrails(&agent, &update, "local-operator", now_ms())
                }).await {
                    Ok(Ok(GuardrailsSaveResult::Saved(view))) => Json(view).into_response(),
                    Ok(Ok(GuardrailsSaveResult::Conflict { current_revision })) => (
                        StatusCode::CONFLICT,
                        Json(json!({"error":"saved settings changed; reload before saving","current_revision":current_revision})),
                    ).into_response(),
                    Ok(Err(error)) => error_response(error),
                    Err(error) => error_response(RiskGuardError::Internal(error.to_string())),
                }
            },
        ))
        .route("/api/agents/{agent_id}/guardrails/policy", get(
            |State(store): State<Arc<SqliteRiskStore>>, AgentPath(agent): AgentPath<String>| async move {
                match tokio::task::spawn_blocking(move || store.export_agent_guardrails_policy(&agent)).await {
                    Ok(Ok(Some(yaml))) => (
                        [(header::CONTENT_TYPE, "application/yaml; charset=utf-8"),
                         (header::CONTENT_DISPOSITION, "attachment; filename=\"agent-guardrails.yaml\"")],
                        yaml,
                    ).into_response(),
                    Ok(Ok(None)) => (StatusCode::NOT_FOUND, Json(json!({"error":"no saved guardrails"}))).into_response(),
                    Ok(Err(error)) => error_response(error),
                    Err(error) => error_response(RiskGuardError::Internal(error.to_string())),
                }
            },
        ))
        .route("/api/agents/{agent_id}/adaptive", get(
            |State(store): State<Arc<SqliteRiskStore>>, AgentPath(agent): AgentPath<String>| async move {
                match tokio::task::spawn_blocking(move || store.agent_adaptive(&agent, now_ms())).await {
                    Ok(Ok(Some(view))) => Json(view).into_response(),
                    Ok(Ok(None)) => (StatusCode::NOT_FOUND, Json(json!({"error":"workload not found"}))).into_response(),
                    Ok(Err(error)) => error_response(error),
                    Err(error) => error_response(RiskGuardError::Internal(error.to_string())),
                }
            },
        ).post(
            |State(store): State<Arc<SqliteRiskStore>>,
             Extension(controls): Extension<OperatorControls>,
             AgentPath(agent): AgentPath<String>,
             headers: HeaderMap,
             payload: std::result::Result<Json<AdaptiveOperation>, axum::extract::rejection::JsonRejection>| async move {
                if let Err(response) = controls.authorize(&headers) { return response; }
                let operation = match payload {
                    Ok(Json(operation)) => operation,
                    Err(error) => return (error.status(), Json(json!({"error":error.body_text()}))).into_response(),
                };
                match tokio::task::spawn_blocking(move || {
                    store.apply_adaptive_operation(&agent, &operation, "local-operator", now_ms())
                }).await {
                    Ok(Ok(AdaptiveUpdateResult::Applied(view))) => Json(view).into_response(),
                    Ok(Ok(AdaptiveUpdateResult::Conflict(message))) =>
                        (StatusCode::CONFLICT, Json(json!({"error":message}))).into_response(),
                    Ok(Err(error)) => error_response(error),
                    Err(error) => error_response(RiskGuardError::Internal(error.to_string())),
                }
            },
        ))
        .route("/api/agents/{agent_id}/restrictions", get(
            |State(store): State<Arc<SqliteRiskStore>>, AgentPath(agent): AgentPath<String>| async move {
                match tokio::task::spawn_blocking(move || {
                    store.list_restrictions(
                        crate::store::RestrictionTarget::Agent {
                            agent_id: &agent,
                            context_id: None,
                        },
                        now_ms(),
                    )
                }).await {
                    Ok(Ok(view)) => Json(view).into_response(),
                    Ok(Err(error)) => error_response(error),
                    Err(error) => error_response(RiskGuardError::Internal(error.to_string())),
                }
            },
        ))
        .route("/api/agents/{agent_id}/restrictions/clear", post(
            |State(store): State<Arc<SqliteRiskStore>>,
             Extension(controls): Extension<OperatorControls>,
             AgentPath(agent): AgentPath<String>,
             headers: HeaderMap,
             payload: std::result::Result<Json<ClearRestrictionRequest>, axum::extract::rejection::JsonRejection>| async move {
                if let Err(response) = controls.authorize(&headers) { return response; }
                let req = match payload {
                    Ok(Json(req)) => req,
                    Err(error) => return (error.status(), Json(json!({"error": error.body_text()}))).into_response(),
                };
                match tokio::task::spawn_blocking(move || {
                    store.clear_restriction(
                        crate::store::RestrictionTarget::Agent {
                            agent_id: &agent,
                            context_id: req.context_id.as_deref(),
                        },
                        &req.scope,
                        "local-operator",
                        &req.reason,
                        now_ms(),
                    )
                }).await {
                    Ok(Ok(view)) => Json(view).into_response(),
                    Ok(Err(error)) => error_response(error),
                    Err(error) => error_response(RiskGuardError::Internal(error.to_string())),
                }
            },
        ))
        .layer(DefaultBodyLimit::max(65_536))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::build_standard_corpus;
    use crate::guardrails::AgentGuardrails;
    use crate::types::{EnforcementMode, RiskStore};

    fn store() -> Arc<SqliteRiskStore> {
        let store = Arc::new(SqliteRiskStore::open_in_memory().unwrap());
        let mut baseline = build_standard_corpus().default_baseline;
        baseline.normalizer_version = crate::normalizer::DEFAULT_NORMALIZER_VERSION.into();
        store.store_baseline(&baseline).unwrap();
        store.register_agent("agent", "Test agent").unwrap();
        store
    }

    async fn start(
        controls: OperatorControls,
        store: Arc<SqliteRiskStore>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = crate::operator_dashboard::router_with_controls(store, controls);
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{address}"), server)
    }

    async fn request(
        server: &str,
        method: &str,
        path: &str,
        origin: Option<&str>,
        token: Option<&str>,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let address = server.strip_prefix("http://").unwrap();
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut headers = format!(
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len(),
        );
        if let Some(origin) = origin {
            headers.push_str(&format!("Origin: {origin}\r\n"));
        }
        if let Some(token) = token {
            headers.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        headers.push_str("\r\n");
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(body.as_bytes()).await.unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
        let code = headers
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        (
            StatusCode::from_u16(code).unwrap(),
            serde_json::from_str(body).unwrap(),
        )
    }

    #[tokio::test]
    async fn authenticated_same_origin_writes_validate_and_detect_conflicts() {
        let store = store();
        let token = "f".repeat(64);
        let (origin, server) =
            start(OperatorControls::from_token(&token), Arc::clone(&store)).await;
        let endpoint = "/api/agents/agent/guardrails";
        let mut settings = AgentGuardrails::from_baseline(
            &build_standard_corpus().default_baseline,
            EnforcementMode::Observe,
            None,
        );
        let update = GuardrailsUpdate {
            expected_revision: 0,
            settings: settings.clone(),
        };
        let body = serde_json::to_string(&update).unwrap();
        let (_, status) = request(&origin, "GET", "/api/operator/status", None, None, "").await;
        assert_eq!(status, json!({"enabled":true}));
        assert_eq!(
            request(&origin, "PUT", endpoint, Some(&origin), None, &body)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                &origin,
                "PUT",
                endpoint,
                Some("http://other.invalid"),
                Some(&token),
                &body
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request(
                &origin,
                "PUT",
                endpoint,
                Some(&origin),
                Some(&"0".repeat(64)),
                &body
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (verified, _) = request(
            &origin,
            "POST",
            "/api/operator/verify",
            Some(&origin),
            Some(&token),
            "",
        )
        .await;
        assert_eq!(verified, StatusCode::OK);
        let (saved, view) =
            request(&origin, "PUT", endpoint, Some(&origin), Some(&token), &body).await;
        assert_eq!(saved, StatusCode::OK);
        assert_eq!(view["revision"], 1);
        assert_eq!(view["settings"]["mode"], "observe");
        assert_eq!(view["history"][0]["updated_by"], "local-operator");
        assert!(!view.to_string().contains(&token));
        let (conflict, value) =
            request(&origin, "PUT", endpoint, Some(&origin), Some(&token), &body).await;
        assert_eq!(conflict, StatusCode::CONFLICT);
        assert_eq!(value["current_revision"], 1);

        settings.observe_threshold = settings.enforce_threshold;
        let body = serde_json::to_string(&GuardrailsUpdate {
            expected_revision: 1,
            settings,
        })
        .unwrap();
        let (invalid, _) =
            request(&origin, "PUT", endpoint, Some(&origin), Some(&token), &body).await;
        assert_eq!(invalid, StatusCode::BAD_REQUEST);
        let (oversized, _) = request(
            &origin,
            "PUT",
            endpoint,
            Some(&origin),
            Some(&token),
            &"x".repeat(70_000),
        )
        .await;
        assert_eq!(oversized, StatusCode::PAYLOAD_TOO_LARGE);
        let (_, readback) = request(&origin, "GET", endpoint, None, None, "").await;
        assert_eq!(readback["revision"], 1);
        assert_eq!(readback["settings"]["mode"], "observe");
        server.abort();
    }

    #[tokio::test]
    async fn default_dashboard_does_not_enable_mutations() {
        let (origin, server) = start(OperatorControls::disabled(), store()).await;
        let update = GuardrailsUpdate {
            expected_revision: 0,
            settings: AgentGuardrails::from_baseline(
                &build_standard_corpus().default_baseline,
                EnforcementMode::Enforce,
                None,
            ),
        };
        let body = serde_json::to_string(&update).unwrap();
        let (result, _) = request(
            &origin,
            "PUT",
            "/api/agents/agent/guardrails",
            Some(&origin),
            None,
            &body,
        )
        .await;
        assert_eq!(result, StatusCode::NOT_FOUND);
        let (_, status) = request(&origin, "GET", "/api/operator/status", None, None, "").await;
        assert_eq!(status["enabled"], false);
        server.abort();
    }

    #[tokio::test]
    async fn clear_restriction_api_requires_operator_auth_and_records_clearance_audit() {
        use crate::detector::{InteractionRiskDetector, compute_baseline_hash};
        use crate::normalizer::CanonicalNormalizer;
        use crate::types::{
            DecisionOutcome, EpochRecord, NativeObservationSource, RawRequestInput,
        };

        let store = store();
        let mut profile = build_standard_corpus().default_baseline;
        profile.normalizer_version = crate::normalizer::DEFAULT_NORMALIZER_VERSION.into();
        profile.forbid_unfamiliar_high_impact = true;
        store.store_baseline(&profile).unwrap();
        store
            .create_agent_run(
                "agent",
                "run-1",
                "r1",
                &profile.task_profile,
                EnforcementMode::Enforce,
            )
            .unwrap();
        store
            .upsert_epoch(&EpochRecord {
                epoch_id: "epoch-1".into(),
                gateway_id: "gateway".into(),
                sandbox_id: "sandbox-1".into(),
                task_profile: profile.task_profile.clone(),
                baseline_hash: compute_baseline_hash(&profile),
                mode: EnforcementMode::Enforce,
                active: true,
                next_sequence: 1,
                created_at_ms: 0,
                credentialed_endpoints: Default::default(),
                active_policy_hash: None,
            })
            .unwrap();
        store.bind_agent_run("run-1", "sandbox-1", "gateway").unwrap();

        let normalized = CanonicalNormalizer::new_default(b"operator-controls-test-key")
            .normalize(&RawRequestInput {
                request_id: "req-1".into(),
                sandbox_id: "sandbox-1".into(),
                sandbox_name: "sandbox-1".into(),
                workspace: "default".into(),
                scheme: "https".into(),
                host: "api.github.local".into(),
                port: 18443,
                method: "DELETE".into(),
                path: "/repos/org/payments-prod".into(),
                binary_path: Some("/usr/bin/curl".into()),
                pid: None,
                ancestors: vec![],
                timestamp_ms: 1_000_000,
            })
            .unwrap();
        let eval = store
            .evaluate_native_authenticated(
                &normalized,
                &InteractionRiskDetector::new_default(),
                "gateway",
                true,
                NativeObservationSource::LocalTestSupervisor,
            )
            .unwrap();
        assert_eq!(eval.outcome, DecisionOutcome::Deny);

        let token = "a".repeat(64);
        let (origin, server) =
            start(OperatorControls::from_token(&token), Arc::clone(&store)).await;

        let (list_status, listed) = request(
            &origin,
            "GET",
            "/api/agents/agent/restrictions",
            None,
            None,
            "",
        )
        .await;
        assert_eq!(list_status, StatusCode::OK);
        let restrictions = listed["restrictions"].as_array().unwrap();
        assert_eq!(restrictions.len(), 1);
        let scope = restrictions[0]["scope"].as_str().unwrap().to_string();
        let context_id = restrictions[0]["owner_id"].as_str().unwrap().to_string();

        let clear_body = json!({
            "scope": scope,
            "reason": "verified maintenance window",
            "context_id": context_id,
        })
        .to_string();

        assert_eq!(
            request(
                &origin,
                "POST",
                "/api/agents/agent/restrictions/clear",
                Some(&origin),
                None,
                &clear_body,
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );

        let (clear_status, cleared) = request(
            &origin,
            "POST",
            "/api/agents/agent/restrictions/clear",
            Some(&origin),
            Some(&token),
            &clear_body,
        )
        .await;
        assert_eq!(clear_status, StatusCode::OK);
        assert_eq!(cleared["status"], "cleared");
        assert_eq!(cleared["cleared_by"], "local-operator");
        assert_eq!(cleared["trigger_request_id"], "req-1");

        let (_, after) = request(
            &origin,
            "GET",
            "/api/agents/agent/restrictions",
            None,
            None,
            "",
        )
        .await;
        assert!(after["restrictions"].as_array().unwrap().is_empty());

        let metrics = store.prometheus_metrics(2_000_000).unwrap();
        assert!(metrics.contains("openshell_risk_guard_restriction_clearances_total 1"));

        server.abort();
    }

    #[cfg(unix)]
    #[test]
    fn private_operator_token_is_persistent_and_not_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator-token");
        let first = OperatorControls::from_private_file(&path).unwrap();
        let second = OperatorControls::from_private_file(&path).unwrap();
        assert_eq!(first.verifier, second.verifier);
        assert_eq!(std::fs::read_to_string(&path).unwrap().len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                0
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(OperatorControls::from_private_file(&path).is_err());
        }
    }
}
