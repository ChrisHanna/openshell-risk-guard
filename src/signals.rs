// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The listener through which a SIEM (or any detection system) can ask Risk Guard to tighten. The rules are in `store/signals.rs`; this
//! file is the door: its own port, its own token (never the operator's), a small body, and no way to loosen anything.
//!
//! `POST /v1/signals` sends one signal, `GET /v1/signals` lists the recent ones, `GET /healthz` answers without a token.
//! `POST /features` takes a batch of SIEM risk features (see `store/siem_features.rs` and docs/design-siem-features.md) under the same authentication.
//! Two ways to prove who is sending:
//!
//! * **mTLS with a SPIFFE identity** (`serve_mtls`): the sender presents an X.509-SVID, the listener checks it against the SPIRE trust bundle and an allow-list of exact SPIFFE IDs,
//!   and records the verified ID as the signal's source. No shared secret exists. This is the deployment that matters.
//! * **A bearer token** over plain HTTP (`serve`): `Authorization: Bearer <64 hex characters>`. A demonstration and local testing; anyone who can see the traffic can replay it.
//!
//! See docs/siem-signals.md.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Extension, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::error::{Result, RiskGuardError};
use crate::spiffe::{SvidPolicy, spiffe_id_from_certificate};
use crate::store::{SignalPolicy, SignalRequest, SqliteRiskStore};
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

/// What the TLS layer knows about the connection a request arrived on.
type Peer = TlsConnectInfo<TcpConnectInfo>;

#[derive(Clone)]
enum Auth {
    /// The HMAC of the shared token.
    Bearer([u8; 32]),
    /// The sender's verified SPIFFE ID must be in `allowed_signals` (for `/v1/signals`) or `allowed_features` (for `/features`), in an accepted trust domain.
    Spiffe {
        policy: Arc<SvidPolicy>,
        allowed_signals: Arc<BTreeSet<String>>,
        allowed_features: Arc<BTreeSet<String>>,
    },
}

const LABEL: &[u8] = b"risk-guard-signals-v1";

#[derive(Clone)]
pub struct SignalsState {
    store: Arc<SqliteRiskStore>,
    auth: Auth,
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
            auth: Auth::Bearer(digest_of(token)),
            policy,
            ocsf: None,
        })
    }

    /// Accept only senders that prove one of `allowed` (exact SPIFFE IDs) over mutual TLS. Nothing in a header is trusted.
    pub fn new_spiffe<I, S>(
        store: Arc<SqliteRiskStore>,
        trust_domains: &[String],
        allowed: I,
        policy: SignalPolicy,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut ids = BTreeSet::new();
        for id in allowed {
            ids.insert(crate::spiffe::SpiffeId::parse(id.as_ref().trim())?.uri());
        }
        if ids.is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "name at least one SPIFFE ID that may send signals (--signals-allow-spiffe)".into(),
            ));
        }
        let shared = Arc::new(ids);
        Ok(Self {
            store,
            auth: Auth::Spiffe {
                policy: Arc::new(SvidPolicy::new(trust_domains)?),
                allowed_signals: Arc::clone(&shared),
                allowed_features: shared,
            },
            policy,
            ocsf: None,
        })
    }

    /// Restrict `/features` to a separate set of SPIFFE IDs (e.g. `spiffe://<domain>/ns/siem/sa/feature-publisher`) so the feature publisher
    /// cannot call `/v1/signals` to quarantine workloads.
    pub fn with_features_spiffe<I, S>(mut self, allowed_features: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut ids = BTreeSet::new();
        for id in allowed_features {
            ids.insert(crate::spiffe::SpiffeId::parse(id.as_ref().trim())?.uri());
        }
        if ids.is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "name at least one SPIFFE ID that may post features (--features-allow-spiffe)"
                    .into(),
            ));
        }
        if let Auth::Spiffe {
            allowed_features: slot,
            ..
        } = &mut self.auth
        {
            *slot = Arc::new(ids);
        }
        Ok(self)
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

    // The error is a ready-made HTTP response; it is returned at once, never stored, so its size does not matter.
    #[allow(clippy::result_large_err)]
    /// Who is sending: `Ok(Some(spiffe id))` for a verified SPIFFE sender, `Ok(None)` for a valid bearer token, an error response otherwise.
    fn authorize(
        &self,
        headers: &HeaderMap,
        peer: Option<&Peer>,
        for_features: bool,
    ) -> std::result::Result<Option<String>, Response> {
        match &self.auth {
            Auth::Bearer(digest) => {
                let valid = headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .is_some_and(|token| {
                        if token.len() != 64 {
                            return false;
                        }
                        let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
                            .expect("HMAC accepts this key length");
                        mac.update(LABEL);
                        mac.verify_slice(digest).is_ok()
                    });
                if valid {
                    Ok(None)
                } else {
                    tracing::warn!("signal refused: missing or wrong token");
                    Err(reply(
                        StatusCode::UNAUTHORIZED,
                        json!({"error": "a valid signals token is required"}),
                    ))
                }
            }
            Auth::Spiffe {
                policy,
                allowed_signals,
                allowed_features,
            } => {
                let id = peer
                    .and_then(|peer| peer.peer_certs())
                    .and_then(|certs| {
                        certs
                            .first()
                            .map(|leaf| spiffe_id_from_certificate(leaf.as_ref()))
                    })
                    .transpose()
                    .ok()
                    .flatten();
                let Some(id) = id else {
                    tracing::warn!("signal refused: no verified SPIFFE identity");
                    return Err(reply(
                        StatusCode::UNAUTHORIZED,
                        json!({"error": "a client certificate (X.509-SVID) is required"}),
                    ));
                };
                let allowed = if for_features {
                    allowed_features
                } else {
                    allowed_signals
                };
                if policy.authorize(&id).is_err() || !allowed.contains(&id.uri()) {
                    tracing::warn!(sender = %id.uri(), for_features, "signal refused: this identity may not call this endpoint");
                    return Err(reply(
                        StatusCode::FORBIDDEN,
                        json!({"error": "this identity may not send signals"}),
                    ));
                }
                Ok(Some(id.uri()))
            }
        }
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
    peer: Option<Extension<Peer>>,
    body: axum::body::Bytes,
) -> Response {
    let sender = match state.authorize(&headers, peer.as_ref().map(|Extension(peer)| peer), false) {
        Ok(sender) => sender,
        Err(response) => return response,
    };
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
    // Over mTLS the source is who the certificate says, not what the body claims: a sender cannot sign as someone else.
    let mut request = request;
    if let Some(sender) = sender {
        request.source = sender;
    }
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

/// `POST /features`: a batch of risk features from the SIEM. The source is who the certificate says (or `bearer-token` on the plain-HTTP demo listener),
/// never anything in the body, which has no field for it and refuses unknown ones.
async fn post_features(
    State(state): State<SignalsState>,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
    body: axum::body::Bytes,
) -> Response {
    let source = match state.authorize(&headers, peer.as_ref().map(|Extension(peer)| peer), true) {
        Ok(sender) => sender.unwrap_or_else(|| "bearer-token".to_string()),
        Err(response) => return response,
    };
    let bytes = body.len();
    let batch: crate::store::FeatureBatch = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(error) => {
            tracing::warn!(%error, %source, "features rejected: the body is not a valid batch");
            let store = Arc::clone(&state.store);
            let audited = source.clone();
            let _ = tokio::task::spawn_blocking(move || {
                store.record_rejected_feature_body(&audited, bytes, "malformed_body", now_ms())
            })
            .await;
            return reply(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("invalid feature batch: {error}")}),
            );
        }
    };
    let store = Arc::clone(&state.store);
    let result = tokio::task::spawn_blocking(move || {
        store.ingest_siem_features(&source, bytes, &batch, now_ms())
    })
    .await;
    match result {
        Ok(Ok(outcome)) => {
            let status = match outcome.status {
                crate::store::IngestStatus::Accepted => StatusCode::OK,
                crate::store::IngestStatus::Invalid => StatusCode::BAD_REQUEST,
                crate::store::IngestStatus::Stale => StatusCode::UNPROCESSABLE_ENTITY,
                crate::store::IngestStatus::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            };
            tracing::info!(
                status = outcome.status.as_str(),
                accepted = outcome.accepted,
                rejected = outcome.rejected,
                "features handled"
            );
            reply(status, serde_json::to_value(&outcome).unwrap_or_default())
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "handling a feature batch failed");
            reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "features could not be recorded; nothing was changed"}),
            )
        }
        Err(_) => reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "feature handling stopped; nothing was changed"}),
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
    peer: Option<Extension<Peer>>,
    Query(params): Query<ListParams>,
) -> Response {
    if let Err(response) = state.authorize(&headers, peer.as_ref().map(|Extension(peer)| peer), false)
    {
        return response;
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
    // A signal is small; a feature batch may be up to 64 KiB. Each router carries its own limit and they are merged, so neither limit leaks onto the other.
    let signals = Router::new()
        .route("/v1/signals", get(list_signals).post(post_signal))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(8 * 1024));
    let features = Router::new()
        .route("/features", post(post_features))
        .layer(DefaultBodyLimit::max(crate::store::FEATURE_BATCH_MAX_BYTES));
    signals.merge(features).with_state(state)
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

/// Serve over mutual TLS until `shutdown` resolves. The server certificate is Risk Guard's own; the sender must present an X.509-SVID that chains to `bundle` (SPIRE's trust bundle,
/// re-read every 30 s because SPIRE rotates its signing keys, with the listener restarted on a change) and whose SPIFFE ID the state allows.
pub async fn serve_mtls<F>(
    listen: SocketAddr,
    state: SignalsState,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    bundle: PathBuf,
    shutdown: impl Fn() -> F,
) -> Result<()>
where
    F: std::future::Future<Output = ()>,
{
    const BUNDLE_POLL: std::time::Duration = std::time::Duration::from_secs(30);
    loop {
        let pem = loop {
            match std::fs::read(&bundle) {
                Ok(pem) if !pem.trim_ascii().is_empty() => break pem,
                _ => {
                    tracing::warn!(bundle = %bundle.display(), "signals: waiting for the SPIFFE trust bundle");
                    tokio::select! {
                        () = tokio::time::sleep(std::time::Duration::from_secs(15)) => {}
                        () = shutdown() => return Ok(()),
                    }
                }
            }
        };
        let tls = tonic::transport::ServerTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(
                &server_cert_pem,
                &server_key_pem,
            ))
            .client_ca_root(tonic::transport::Certificate::from_pem(&pem))
            .client_auth_optional(false);
        let watched = bundle.clone();
        let current = pem.clone();
        let changed = async move {
            loop {
                tokio::time::sleep(BUNDLE_POLL).await;
                if std::fs::read(&watched).ok().as_deref() != Some(current.as_slice()) {
                    return;
                }
            }
        };
        let stopped_for_good = std::sync::atomic::AtomicBool::new(false);
        let wait = async {
            tokio::select! {
                () = changed => tracing::info!("signals: the trust bundle changed; reloading the listener"),
                () = shutdown() => stopped_for_good.store(true, std::sync::atomic::Ordering::SeqCst),
            }
        };
        tracing::info!(%listen, dry_run = state.policy.dry_run, "signals listener started (mutual TLS, SPIFFE identity)");
        let routes = tonic::service::Routes::from(router(state.clone()));
        tonic::transport::Server::builder()
            .accept_http1(true)
            .tls_config(tls)
            .map_err(|error| {
                RiskGuardError::InvalidArgument(format!("invalid signals TLS: {error}"))
            })?
            .add_routes(routes)
            .serve_with_shutdown(listen, wait)
            .await
            .map_err(|error| {
                RiskGuardError::Internal(format!("signals listener error: {error}"))
            })?;
        if stopped_for_good.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
    }
}
