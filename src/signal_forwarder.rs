// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The SIEM's side of the signals path: a small service with its own SPIFFE identity.
//!
//! OpenSearch's alert webhook can send a bearer token but cannot present a client certificate. This service sits next to it, inside the SIEM's trust zone, takes the webhook, checks
//! it is a plain `quarantine` signal, and forwards it to Risk Guard over **mutual TLS with its own X.509-SVID**. Risk Guard therefore never holds a shared secret: it accepts one exact
//! SPIFFE ID, and what that identity may do is limited by the signals rules (tighten only, expiring, rate limited, audited).
//!
//! The hop from OpenSearch to this service is the weak one (a token, and a network policy that lets only OpenSearch reach it). It is not hidden: it is inside the SIEM, where the
//! alert rules also live, and what it can ask for is the same narrow thing.
//!
//! The SVID is read from files on every request, so rotation (SPIRE reissues it about hourly, written by `spiffe-helper`) is picked up with no restart.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::error::{Result, RiskGuardError};

const LABEL: &[u8] = b"risk-guard-signal-forwarder-v1";

#[derive(Clone)]
pub struct ForwarderConfig {
    /// Where Risk Guard's signals listener is, e.g. `https://risk-guard.openshell.svc:50063/v1/signals`.
    pub target: String,
    /// The SVID (certificate chain, then key) that `spiffe-helper` keeps current.
    pub svid_cert: PathBuf,
    pub svid_key: PathBuf,
    /// The CA that signed Risk Guard's server certificate.
    pub server_ca: PathBuf,
}

#[derive(Clone)]
struct State_ {
    config: Arc<ForwarderConfig>,
    digest: [u8; 32],
}

/// An error with the reasons beneath it ("builder error" alone says nothing).
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}

fn digest_of(token: &str) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(token.as_bytes()).expect("HMAC accepts this key length");
    mac.update(LABEL);
    mac.finalize().into_bytes().into()
}

fn reply(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

fn authorized(headers: &HeaderMap, digest: &[u8; 32]) -> bool {
    headers
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
        })
}

type ClientCacheKey = (PathBuf, PathBuf, PathBuf);
type ClientCacheEntry = ([u8; 32], reqwest::Client);

fn client_cache() -> &'static std::sync::Mutex<std::collections::HashMap<ClientCacheKey, ClientCacheEntry>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<ClientCacheKey, ClientCacheEntry>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// A client that presents the current SVID. Reuses the cached TLS client and connection pool while the SVID and CA bytes are unchanged,
/// and rebuilds at once when `spiffe-helper` rotates the certificate on disk.
pub(crate) fn mtls_client(config: &ForwarderConfig) -> Result<reqwest::Client> {
    use sha2::Digest;

    let read = |path: &PathBuf, what: &str| {
        std::fs::read(path).map_err(|error| {
            RiskGuardError::Internal(format!(
                "cannot read the {what} ({}): {error}",
                path.display()
            ))
        })
    };
    let mut identity = read(&config.svid_cert, "SVID certificate")?;
    // The certificate file may not end in a newline; without one the key's header would join the certificate's footer and neither would parse.
    if !identity.ends_with(&[10]) {
        identity.push(10); // a newline
    }
    identity.extend_from_slice(&read(&config.svid_key, "SVID key")?);
    let ca_pem = read(&config.server_ca, "server CA")?;

    let mut hasher = Sha256::new();
    hasher.update(&identity);
    hasher.update(b"\0");
    hasher.update(&ca_pem);
    let fingerprint: [u8; 32] = hasher.finalize().into();
    let cache_key = (
        config.svid_cert.clone(),
        config.svid_key.clone(),
        config.server_ca.clone(),
    );

    if let Ok(cache) = client_cache().lock()
        && let Some((cached_fp, cached_client)) = cache.get(&cache_key)
        && *cached_fp == fingerprint
    {
        return Ok(cached_client.clone());
    }

    let ca = reqwest::Certificate::from_pem(&ca_pem)
        .map_err(|error| RiskGuardError::Internal(format!("server CA: {}", chain(&error))))?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(
            reqwest::Identity::from_pem(&identity)
                .map_err(|error| RiskGuardError::Internal(format!("SVID: {}", chain(&error))))?,
        )
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|error| RiskGuardError::Internal(format!("client: {}", chain(&error))))?;

    if let Ok(mut cache) = client_cache().lock() {
        if cache.len() >= 64 {
            cache.clear();
        }
        cache.insert(cache_key, (fingerprint, client.clone()));
    }
    Ok(client)
}

async fn webhook(State(state): State<State_>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&headers, &state.digest) {
        tracing::warn!("forwarder: refused a request without the right token");
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"error": "a valid token is required"}),
        );
    }
    // Only a plain quarantine signal is forwarded; anything else never leaves this service.
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            return reply(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("not JSON: {error}")}),
            );
        }
    };
    if value["action"] != "quarantine" {
        tracing::warn!("forwarder: refused a signal that is not a quarantine");
        return reply(
            StatusCode::BAD_REQUEST,
            json!({"error": "only the action \"quarantine\" is forwarded"}),
        );
    }
    let cfg = Arc::clone(&state.config);
    let client = match tokio::task::spawn_blocking(move || mtls_client(&cfg)).await {
        Ok(Ok(client)) => client,
        Ok(Err(error)) => {
            tracing::error!(%error, "forwarder: no usable identity");
            return reply(
                StatusCode::BAD_GATEWAY,
                json!({"error": "the forwarder has no usable SVID yet"}),
            );
        }
        Err(error) => {
            tracing::error!(%error, "forwarder: SVID loader task failed");
            return reply(
                StatusCode::BAD_GATEWAY,
                json!({"error": "the forwarder has no usable SVID yet"}),
            );
        }
    };
    match client
        .post(&state.config.target)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) => {
            let status =
                StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let text = response.text().await.unwrap_or_default();
            tracing::info!(status = %status, "forwarder: Risk Guard answered");
            (status, [(header::CONTENT_TYPE, "application/json")], text).into_response()
        }
        Err(error) => {
            tracing::error!(%error, "forwarder: could not reach Risk Guard");
            reply(
                StatusCode::BAD_GATEWAY,
                json!({"error": "Risk Guard could not be reached"}),
            )
        }
    }
}

pub fn router(config: ForwarderConfig, token: &str) -> Result<Router> {
    if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(RiskGuardError::InvalidArgument(
            "the forwarder token (RISK_GUARD_FORWARDER_TOKEN) must be exactly 64 hexadecimal characters".into(),
        ));
    }
    let state = State_ {
        config: Arc::new(config),
        digest: digest_of(token),
    };
    Ok(Router::new()
        .route("/webhook", post(webhook))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .with_state(state))
}

pub async fn serve(listen: SocketAddr, config: ForwarderConfig, token: &str) -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let app = router(config, token)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| RiskGuardError::Internal(format!("forwarder listener: {error}")))?;
    tracing::info!(%listen, "signal forwarder started");
    axum::serve(listener, app)
        .await
        .map_err(|error| RiskGuardError::Internal(format!("forwarder stopped: {error}")))
}
