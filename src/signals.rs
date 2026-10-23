// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The listener through which a SIEM (or any detection system) can ask Risk Guard to tighten. The rules are in `store/signals.rs`; this
//! file is the door: its own port, its own token (never the operator's), a small body, and no way to loosen anything.
//!
//! `POST /v1/signals` sends one signal, `GET /v1/signals` lists the recent ones, `GET /healthz` answers without a token.
//! The token travels as `Authorization: Bearer <64 hex characters>`. Over plain HTTP that is a demonstration; a deployment that matters
//! puts mTLS (a SPIFFE identity for the sender) in front of it. See docs/siem-signals.md.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::error::{Result, RiskGuardError};
use crate::store::{SignalPolicy, SignalRequest, SqliteRiskStore};

const LABEL: &[u8] = b"risk-guard-signals-v1";

#[derive(Clone)]
pub struct SignalsState {
    store: Arc<SqliteRiskStore>,
    digest: [u8; 32],
    policy: SignalPolicy,
    ocsf: Option<Arc<crate::ocsf::OcsfEmitter>>,
}

fn digest_of(token: &str) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(token.as_bytes()).expect("HMAC accepts this key length");
    mac.update(LABEL);
    mac.finalize().into_bytes().into()
}

impl SignalsState {
    pub fn new(store: Arc<SqliteRiskStore>, token: &str, policy: SignalPolicy) -> Result<Self> {
        if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(RiskGuardError::InvalidArgument(
                "the signals token must be exactly 64 hexadecimal characters".into(),
            ));
        }
        Ok(Self {
            store,
            digest: digest_of(token),
            policy,
            ocsf: None,
        })
    }

    /// Send each signal and its outcome to the SIEM as an OCSF event (see `crate::ocsf`).
    #[must_use]
    pub fn with_ocsf(mut self, emitter: Arc<crate::ocsf::OcsfEmitter>) -> Self {
        self.ocsf = Some(emitter);
        self
    }

    /// Read the token from the environment variable `RISK_GUARD_SIGNALS_TOKEN` (how a Kubernetes Secret reaches the pod: a mounted Secret is a
    /// symlink, which the private-file check refuses). Never accepted as a command-line argument, which other users on a host could see.
    pub fn from_env(store: Arc<SqliteRiskStore>, policy: SignalPolicy) -> Result<Self> {
        let token = std::env::var("RISK_GUARD_SIGNALS_TOKEN").map_err(|_| {
            RiskGuardError::InvalidArgument(
                "the signals listener needs --signals-token-file or the RISK_GUARD_SIGNALS_TOKEN environment variable".into(),
            )
        })?;
        Self::new(store, token.trim(), policy)
    }

    /// Read the token from a provisioned private file (never created here: the sender needs the same secret).
    #[cfg(unix)]
    pub fn from_token_file(
        store: Arc<SqliteRiskStore>,
        path: &Path,
        policy: SignalPolicy,
    ) -> Result<Self> {
        let token = crate::operator_controls::read_private_token(path, false)?;
        Self::new(store, &token, policy)
    }

    #[cfg(not(unix))]
    pub fn from_token_file(
        _store: Arc<SqliteRiskStore>,
        _path: &Path,
        _policy: SignalPolicy,
    ) -> Result<Self> {
        Err(RiskGuardError::InvalidArgument(
            "the signals token file needs Unix file-privacy validation; use WSL on Windows".into(),
        ))
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return false;
        };
        if token.len() != 64 {
            return false;
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(token.as_bytes()).expect("HMAC accepts this key length");
        mac.update(LABEL);
        mac.verify_slice(&self.digest).is_ok()
    }
}

fn now_ms() -> i64 {
    crate::store::now_wall_ms()
}

fn reply(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

async fn post_signal(
    State(state): State<SignalsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.authorized(&headers) {
        tracing::warn!("signal refused: missing or wrong token");
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"error": "a valid signals token is required"}),
        );
    }
    let request: SignalRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(%error, "signal rejected: the body is not a valid signal");
            return reply(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("invalid signal: {error}")}),
            );
        }
    };
    let store = Arc::clone(&state.store);
    let policy = state.policy.clone();
    let for_event = request.clone();
    let result =
        tokio::task::spawn_blocking(move || store.apply_signal(&request, &policy, now_ms())).await;
    match result {
        Ok(Ok(outcome)) => {
            let status = match outcome.outcome.as_str() {
                "rate_limited" | "too_many_active" => StatusCode::TOO_MANY_REQUESTS,
                "unknown_target" => StatusCode::NOT_FOUND,
                _ => StatusCode::OK,
            };
            tracing::info!(outcome = %outcome.outcome, duplicate = outcome.duplicate, "signal handled");
            if let Some(ocsf) = &state.ocsf
                && !outcome.duplicate
            {
                ocsf.emit(crate::ocsf::Occurrence::Signal {
                    signal_id: for_event.signal_id,
                    source: for_event.source,
                    alert_id: for_event.alert_id,
                    agent_id: outcome.agent_id.clone().or(for_event.agent_id),
                    sandbox_id: for_event.sandbox_id,
                    outcome: outcome.outcome.clone(),
                    ttl_seconds: for_event.ttl_seconds,
                    reason: for_event.reason,
                    at_ms: now_ms(),
                });
            }
            reply(status, serde_json::to_value(&outcome).unwrap_or_default())
        }
        Ok(Err(RiskGuardError::InvalidArgument(message))) => {
            tracing::warn!(%message, "signal rejected");
            reply(StatusCode::BAD_REQUEST, json!({"error": message}))
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "handling a signal failed");
            reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "signal could not be recorded; nothing was changed"}),
            )
        }
        Err(_) => reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "signal handling stopped; nothing was changed"}),
        ),
    }
}

#[derive(serde::Deserialize)]
struct ListParams {
    limit: Option<u32>,
}

async fn list_signals(
    State(state): State<SignalsState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    if !state.authorized(&headers) {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"error": "a valid signals token is required"}),
        );
    }
    let store = Arc::clone(&state.store);
    let limit = params.limit.unwrap_or(50);
    match tokio::task::spawn_blocking(move || store.list_signals(limit)).await {
        Ok(Ok(view)) => reply(StatusCode::OK, view),
        _ => reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "could not read signals"}),
        ),
    }
}

pub fn router(state: SignalsState) -> Router {
    Router::new()
        .route("/v1/signals", get(list_signals).post(post_signal))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .with_state(state)
}

/// Serve until the process stops. Off loopback the caller must have said plain HTTP is acceptable (it is for a NetworkPolicy-fenced demo).
pub async fn serve(listen: SocketAddr, state: SignalsState, allow_plaintext: bool) -> Result<()> {
    if !listen.ip().is_loopback() && !allow_plaintext {
        return Err(RiskGuardError::InvalidArgument(format!(
            "the signals listener is plain HTTP; {listen} is not loopback, so pass --signals-allow-plaintext after fencing it with a network policy"
        )));
    }
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| RiskGuardError::Internal(format!("signals listener: {error}")))?;
    tracing::info!(%listen, dry_run = state.policy.dry_run, "signals listener started");
    axum::serve(listener, router(state))
        .await
        .map_err(|error| RiskGuardError::Internal(format!("signals listener stopped: {error}")))
}
