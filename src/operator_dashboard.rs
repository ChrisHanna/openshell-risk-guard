//! Operator evidence view with explicitly enabled local guardrail controls.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::error::{Result, RiskGuardError};
use crate::operator_controls::OperatorControls;
use crate::store::SqliteRiskStore;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

async fn local_only(request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());
    let valid_host = host
        .and_then(|h| h.parse::<axum::http::uri::Authority>().ok())
        .is_some_and(|h| matches!(h.host(), "localhost" | "127.0.0.1" | "[::1]"));
    if !valid_host {
        return (
            StatusCode::FORBIDDEN,
            "operator dashboard requires a loopback Host",
        )
            .into_response();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response.headers_mut().insert(
        header::HeaderName::from_static("x-frame-options"),
        "DENY".parse().unwrap(),
    );
    response
}

fn response(result: Result<Option<Value>>, missing: &str) -> Response {
    match result {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": missing})),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "operator evidence query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "evidence query failed; inspect service logs"})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
fn router(store: Arc<SqliteRiskStore>) -> Router {
    router_with_controls(store, OperatorControls::disabled())
}

pub(crate) fn router_with_controls(
    store: Arc<SqliteRiskStore>,
    controls: OperatorControls,
) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("operator_ui.html")) }),
        )
        .route(
            "/metrics",
            get(|State(store): State<Arc<SqliteRiskStore>>| async move {
                match tokio::task::spawn_blocking(move || store.prometheus_metrics(now_ms())).await
                {
                    Ok(Ok(body)) => (
                        [(
                            header::CONTENT_TYPE,
                            "text/plain; version=0.0.4; charset=utf-8",
                        )],
                        body,
                    )
                        .into_response(),
                    Ok(Err(error)) => {
                        tracing::error!(%error, "prometheus metrics query failed");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "metrics query failed\n",
                        )
                            .into_response()
                    }
                    Err(error) => {
                        tracing::error!(%error, "prometheus metrics worker failed");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "metrics worker failed\n",
                        )
                            .into_response()
                    }
                }
            }),
        )
        .route(
            "/api/state",
            get(|State(store): State<Arc<SqliteRiskStore>>| async move {
                let result = tokio::task::spawn_blocking(move || {
                    store.operator_inventory(now_ms()).map(Some)
                })
                .await
                .map_err(|e| RiskGuardError::Internal(format!("evidence worker failed: {e}")))
                .and_then(|result| result);
                response(result, "evidence not found")
            }),
        )
        .route(
            "/api/agents/{agent_id}",
            get(
                |State(store): State<Arc<SqliteRiskStore>>, Path(id): Path<String>| async move {
                    let result = tokio::task::spawn_blocking(move || {
                        store.operator_agent_detail(&id, now_ms())
                    })
                    .await
                    .map_err(|e| {
                        RiskGuardError::Internal(format!("evidence worker failed: {e}"))
                    })
                    .and_then(|result| result);
                    response(result, "workload not found")
                },
            ),
        )
        .route(
            "/api/sandboxes/{sandbox_id}",
            get(
                |State(store): State<Arc<SqliteRiskStore>>, Path(id): Path<String>| async move {
                    let result =
                        tokio::task::spawn_blocking(move || store.operator_detail(&id, now_ms()))
                            .await
                            .map_err(|e| {
                                RiskGuardError::Internal(format!("evidence worker failed: {e}"))
                            })
                            .and_then(|result| result);
                    response(result, "governed sandbox not found")
                },
            ),
        )
        .merge(crate::operator_controls::routes())
        .with_state(store)
        .layer(Extension(controls))
        .layer(middleware::from_fn(local_only))
}

pub async fn serve(listen: SocketAddr, db: PathBuf) -> Result<()> {
    serve_with_operator_token(listen, db, None).await
}

pub async fn serve_with_operator_token(
    listen: SocketAddr,
    db: PathBuf,
    operator_token_file: Option<PathBuf>,
) -> Result<()> {
    if !listen.ip().is_loopback() {
        return Err(RiskGuardError::InvalidArgument(
            "operator dashboard is unauthenticated and must bind to loopback; use an authenticated local tunnel for remote access".to_string(),
        ));
    }
    if !db.is_file() {
        return Err(RiskGuardError::InvalidArgument(
            "dashboard requires an existing Risk Guard database; it never seeds demo data"
                .to_string(),
        ));
    }
    let store = Arc::new(SqliteRiskStore::open(db)?);
    let controls = match operator_token_file {
        Some(path) => {
            let controls = OperatorControls::from_private_file(&path)?;
            tracing::info!(token_file = %path.display(), "local operator guardrail controls enabled; token is never logged");
            controls
        }
        None => OperatorControls::disabled(),
    };
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| RiskGuardError::Internal(format!("dashboard bind failed: {e}")))?;
    tracing::info!(%listen, "starting operator dashboard");
    axum::serve(listener, router_with_controls(store, controls))
        .await
        .map_err(|e| RiskGuardError::Internal(format!("dashboard server failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_console_has_complete_offline_workspace() {
        let page = include_str!("operator_ui.html");
        for id in [
            "fleet-view",
            "agents-view",
            "agent-tab-map",
            "agent-tab-detections",
            "agent-tab-recommendations",
            "agent-tab-runs",
            "agent-tab-settings",
            "audit-modal",
        ] {
            assert!(page.contains(&format!("id=\"{id}\"")), "missing view: {id}");
        }
        assert!(page.contains("aria-label=\"Agent workspace\""));
        assert!(page.contains("Agent evidence"));
        assert!(page.contains("Context-scoped restrictions"));
        for remote_asset in ["src=\"https://", "href=\"https://", "@import", "@font-face"] {
            assert!(!page.contains(remote_asset), "remote asset: {remote_asset}");
        }
    }

    #[tokio::test]
    async fn read_api_has_no_demo_actions_and_rejects_nonlocal_hosts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn request(address: SocketAddr, method: &str, path: &str, host: &str) -> String {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream.write_all(format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            ).as_bytes()).await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        }
        let store = Arc::new(SqliteRiskStore::open_in_memory().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server =
            tokio::spawn(async move { axum::serve(listener, router(store)).await.unwrap() });
        let host = address.to_string();
        let result = request(address, "GET", "/api/state", &host).await;
        assert!(result.starts_with("HTTP/1.1 200"));
        assert!(result.contains("cache-control: no-store"));
        let body: Value = serde_json::from_str(result.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["sandboxes"], json!([]));
        assert_eq!(body["agents"], json!([]));
        assert_eq!(body["total_agents"], json!(0));
        let missing = request(address, "GET", "/api/agents/unknown", &host).await;
        assert!(missing.starts_with("HTTP/1.1 404"));
        assert!(missing.contains("workload not found"));
        let page = request(address, "GET", "/", &host).await;
        assert!(page.starts_with("HTTP/1.1 200"));
        assert!(page.contains("Agent evidence"));
        assert!(page.contains("Context-scoped restrictions"));
        let metrics = request(address, "GET", "/metrics", &host).await;
        assert!(metrics.starts_with("HTTP/1.1 200"));
        assert!(metrics.contains("text/plain; version=0.0.4"));
        assert!(metrics.contains("openshell_risk_guard_store_healthy 1"));
        assert!(
            !metrics.contains("Store_healthy"),
            "metric names are lower snake case; no differently capitalized duplicate"
        );
        assert!(metrics.contains("openshell_risk_guard_agents_total 0"));
        assert!(metrics.contains("openshell_risk_guard_decisions_total{outcome=\"deny\"} 0"));
        assert!(
            metrics.contains("openshell_risk_guard_active_restrictions_total{tier=\"strict_epoch\"} 0")
        );
        assert!(
            request(address, "POST", "/api/agents/unknown", &host)
                .await
                .starts_with("HTTP/1.1 405")
        );
        assert!(
            request(address, "GET", "/api/sandboxes/unknown", &host)
                .await
                .starts_with("HTTP/1.1 404")
        );
        for path in ["/api/reset", "/api/run-all", "/api/simulate", "/api/step"] {
            assert!(
                request(address, "POST", path, &host)
                    .await
                    .starts_with("HTTP/1.1 404")
            );
        }
        assert!(
            request(address, "GET", "/api/state", "attacker.example")
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            request(address, "GET", "/api/agents/unknown", "attacker.example")
                .await
                .starts_with("HTTP/1.1 403")
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn refuses_public_bind_and_missing_database() {
        assert!(
            serve("0.0.0.0:0".parse().unwrap(), PathBuf::from("missing.db"))
                .await
                .is_err()
        );
        assert!(
            serve("127.0.0.1:0".parse().unwrap(), PathBuf::from("missing.db"))
                .await
                .is_err()
        );
    }
}
