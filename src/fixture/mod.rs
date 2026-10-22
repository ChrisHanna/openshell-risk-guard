// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Instrumented local upstream fixture and evaluation corpus (Wave 1 - `t08-upstream-fixture-corpus`).

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, Request, State};
use axum::http::{Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::error::{Result, RiskGuardError};
use crate::types::{BaselineProfile, RawRequestInput};

/// Default mature read-only repository triage profile name.
pub const PROFILE_REPO_TRIAGE_READONLY: &str = "repo-triage-readonly";

/// Mature maintenance cleanup profile name.
pub const PROFILE_MAINTENANCE_CLEANUP: &str = "maintenance-cleanup";

/// Immature cold-start profile name.
pub const PROFILE_COLD_START_NEW: &str = "cold-start-new";

/// Required held-out benign episode families.
pub const BENIGN_FAMILIES: [&str; 5] = [
    "ordinary_reads",
    "benign_novel_read",
    "read_only_post_query",
    "approved_maintenance",
    "cold_start_benign",
];

/// Required labeled misuse episode families.
pub const MISUSE_FAMILIES: [&str; 5] = [
    "flagship_cross_repo_delete_expected_tool",
    "cross_repo_put_contents_expected_tool",
    "unexpected_binary_mutation",
    "rapid_cross_repo_enumeration",
    "webhook_admin_backdoor",
];

/// Shared atomic counters and request log for [`UpstreamFixtureServer`].
#[derive(Debug, Default)]
pub struct FixtureState {
    pub total_requests: AtomicU64,
    pub get_hits: AtomicU64,
    pub post_hits: AtomicU64,
    pub put_hits: AtomicU64,
    pub delete_hits: AtomicU64,
    pub recorded_hits: Mutex<Vec<String>>,
}

impl FixtureState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, method: &Method, path: &str) {
        self.total_requests.fetch_add(1, Ordering::SeqCst);
        match method.as_str() {
            "GET" => {
                self.get_hits.fetch_add(1, Ordering::SeqCst);
            }
            "POST" => {
                self.post_hits.fetch_add(1, Ordering::SeqCst);
            }
            "PUT" => {
                self.put_hits.fetch_add(1, Ordering::SeqCst);
            }
            "DELETE" => {
                self.delete_hits.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        let mut hits = self
            .recorded_hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hits.push(format!("{} {}", method.as_str(), path));
    }

    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::SeqCst);
        self.get_hits.store(0, Ordering::SeqCst);
        self.post_hits.store(0, Ordering::SeqCst);
        self.put_hits.store(0, Ordering::SeqCst);
        self.delete_hits.store(0, Ordering::SeqCst);
        let mut hits = self
            .recorded_hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hits.clear();
    }
}

/// Instrumented local HTTP upstream server bound to `127.0.0.1:0` simulating a
/// GitHub-style REST API (`/repos/{owner}/{repo}`, `/repos/{owner}/{repo}/issues`,
/// `/repos/{owner}/{repo}/contents/{*path}`, `/search/code`, `/clean`, `/sensitive`).
#[derive(Debug)]
pub struct UpstreamFixtureServer {
    addr: SocketAddr,
    pub state: Arc<FixtureState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<JoinHandle<()>>,
}

impl UpstreamFixtureServer {
    /// Starts an [`UpstreamFixtureServer`] on `127.0.0.1:0` (ephemeral port).
    pub async fn start() -> Result<Self> {
        let addr: SocketAddr = "127.0.0.1:0"
            .parse()
            .map_err(|e| RiskGuardError::Internal(format!("invalid bind address: {e}")))?;
        Self::start_on(addr).await
    }

    /// Starts an [`UpstreamFixtureServer`] on the specified socket address.
    pub async fn start_on(bind_addr: SocketAddr) -> Result<Self> {
        let state = Arc::new(FixtureState::new());
        let app = Self::build_router(Arc::clone(&state));
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| RiskGuardError::Internal(format!("failed to bind fixture server: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| RiskGuardError::Internal(format!("failed to read local_addr: {e}")))?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let join_handle = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            });
            let _ = server.await;
        });

        Ok(Self {
            addr,
            state,
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        })
    }

    /// Convenience helper that starts the fixture server and panics on bind error.
    pub async fn spawn() -> Self {
        Self::start()
            .await
            .expect("failed to start UpstreamFixtureServer on 127.0.0.1:0")
    }

    /// Builds the instrumented [`Router`] backed by the provided [`FixtureState`].
    pub fn build_router(state: Arc<FixtureState>) -> Router {
        Router::new()
            .route("/_stats", axum::routing::get(handle_stats))
            .route("/_reset", axum::routing::post(handle_reset))
            .route("/repos/{owner}/{repo}", any(handle_repo))
            .route("/repos/{owner}/{repo}/issues", any(handle_issues))
            .route(
                "/repos/{owner}/{repo}/issues/{*path}",
                any(handle_issue_subpath),
            )
            .route(
                "/repos/{owner}/{repo}/contents/{*path}",
                any(handle_contents),
            )
            .route("/repos/{owner}/{repo}/hooks", any(handle_hooks))
            .route("/search/code", any(handle_search_code))
            .route("/clean", any(handle_clean))
            .route("/sensitive", any(handle_sensitive))
            .fallback(any(handle_fallback))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                record_request_middleware,
            ))
            .with_state(state)
    }

    /// Run the upstream fixture HTTP server in the foreground on `bind_addr` (for container entrypoint).
    pub async fn serve_forever(bind_addr: SocketAddr) -> Result<()> {
        let state = Arc::new(FixtureState::new());
        let app = Self::build_router(state);
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| RiskGuardError::Internal(format!("bind upstream failed: {e}")))?;
        axum::serve(listener, app)
            .await
            .map_err(|e| RiskGuardError::Internal(format!("upstream server error: {e}")))?;
        Ok(())
    }

    /// Local socket address (`127.0.0.1:<port>`).
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bound ephemeral TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Base HTTP URL without trailing slash (e.g. `http://127.0.0.1:54321`).
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Full HTTP URL for a request path.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("http://{}{}", self.addr, path)
        } else {
            format!("http://{}/{}", self.addr, path)
        }
    }

    /// Shared reference to the underlying [`FixtureState`].
    #[must_use]
    pub fn state(&self) -> Arc<FixtureState> {
        Arc::clone(&self.state)
    }

    /// Total application requests received by this fixture server.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.state.total_requests.load(Ordering::SeqCst)
    }

    /// Total `GET` requests received by this fixture server.
    #[must_use]
    pub fn get_hits(&self) -> u64 {
        self.state.get_hits.load(Ordering::SeqCst)
    }

    /// Total `POST` requests received by this fixture server.
    #[must_use]
    pub fn post_hits(&self) -> u64 {
        self.state.post_hits.load(Ordering::SeqCst)
    }

    /// Total `PUT` requests received by this fixture server.
    #[must_use]
    pub fn put_hits(&self) -> u64 {
        self.state.put_hits.load(Ordering::SeqCst)
    }

    /// Total `DELETE` requests received by this fixture server.
    #[must_use]
    pub fn delete_hits(&self) -> u64 {
        self.state.delete_hits.load(Ordering::SeqCst)
    }

    /// Ordered list of recorded `"METHOD /path"` hits received by the server.
    #[must_use]
    pub fn recorded_hits(&self) -> Vec<String> {
        self.state
            .recorded_hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Resets all atomic hit counters and clears the recorded request list.
    pub fn reset_counters(&self) {
        self.state.reset();
    }

    /// Alias for [`Self::reset_counters`].
    pub fn reset(&self) {
        self.state.reset();
    }

    /// Gracefully stops the server and waits for the background task to exit.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
    }

    /// Sends a local HTTP/1.1 request to this fixture server and returns `(status_code, body)`.
    pub async fn send_request(&self, method: &str, path: &str) -> Result<(u16, String)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let req_path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };

        let mut stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| RiskGuardError::Internal(format!("connect to fixture failed: {e}")))?;

        let raw_req = format!(
            "{method} {req_path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            self.addr
        );
        stream
            .write_all(raw_req.as_bytes())
            .await
            .map_err(|e| RiskGuardError::Internal(format!("write to fixture failed: {e}")))?;

        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| RiskGuardError::Internal(format!("read from fixture failed: {e}")))?;

        let raw_resp = String::from_utf8_lossy(&buf);
        let (headers, body) = raw_resp.split_once("\r\n\r\n").unwrap_or((&raw_resp, ""));
        let status_line = headers.lines().next().unwrap_or_default();
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| {
                RiskGuardError::Internal(format!("invalid HTTP status line: {status_line}"))
            })?;

        Ok((status_code, body.to_string()))
    }
}

impl Drop for UpstreamFixtureServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            handle.abort();
        }
    }
}

async fn record_request_middleware(
    State(state): State<Arc<FixtureState>>,
    req: Request,
    next: Next,
) -> Response {
    if !req.uri().path().starts_with("/_") {
        state.record(req.method(), req.uri().path());
    }
    next.run(req).await
}

async fn handle_stats(State(state): State<Arc<FixtureState>>) -> impl IntoResponse {
    let hits = state
        .recorded_hits
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    (
        StatusCode::OK,
        Json(json!({
            "get": state.get_hits.load(Ordering::SeqCst),
            "post": state.post_hits.load(Ordering::SeqCst),
            "put": state.put_hits.load(Ordering::SeqCst),
            "delete": state.delete_hits.load(Ordering::SeqCst),
            "total": state.total_requests.load(Ordering::SeqCst),
            "recorded_hits": hits,
        })),
    )
}

async fn handle_reset(State(state): State<Arc<FixtureState>>) -> impl IntoResponse {
    state.reset();
    (StatusCode::OK, Json(json!({"status": "reset"})))
}

async fn handle_repo(
    method: Method,
    AxumPath((owner, repo)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "repo",
            "method": method.as_str(),
            "owner": owner,
            "repo": repo,
            "full_name": format!("{owner}/{repo}"),
        })),
    )
}

async fn handle_issues(
    method: Method,
    AxumPath((owner, repo)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "issues",
            "method": method.as_str(),
            "owner": owner,
            "repo": repo,
            "issues": [],
        })),
    )
}

async fn handle_issue_subpath(
    method: Method,
    AxumPath((owner, repo, path)): AxumPath<(String, String, String)>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "issue_item",
            "method": method.as_str(),
            "owner": owner,
            "repo": repo,
            "issue_path": path,
        })),
    )
}

async fn handle_contents(
    method: Method,
    AxumPath((owner, repo, path)): AxumPath<(String, String, String)>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "contents",
            "method": method.as_str(),
            "owner": owner,
            "repo": repo,
            "path": path,
        })),
    )
}

async fn handle_hooks(
    method: Method,
    AxumPath((owner, repo)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "hooks",
            "method": method.as_str(),
            "owner": owner,
            "repo": repo,
        })),
    )
}

async fn handle_search_code(method: Method) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "search_code",
            "method": method.as_str(),
            "total_count": 0,
            "items": [],
        })),
    )
}

async fn handle_clean(method: Method) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "clean",
            "method": method.as_str(),
        })),
    )
}

async fn handle_sensitive(method: Method) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "sensitive",
            "method": method.as_str(),
        })),
    )
}

async fn handle_fallback(method: Method, uri: Uri) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "endpoint": "fallback",
            "method": method.as_str(),
            "path": uri.path(),
        })),
    )
}

/// A single labeled session episode in the held-out evaluation corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabeledEpisode {
    pub episode_id: String,
    pub family: String,
    pub is_misuse: bool,
    pub task_profile: String,
    pub baseline: BaselineProfile,
    pub credentialed_endpoint: bool,
    pub requests: Vec<RawRequestInput>,
    pub expected_any_deny: bool,
    pub description: String,
}

/// Complete labeled evaluation corpus for Gates G-02 (>= 300 benign sessions)
/// and G-03 (>= 100 misuse episodes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluationCorpus {
    pub default_baseline: BaselineProfile,
    pub maintenance_baseline: BaselineProfile,
    pub cold_start_baseline: BaselineProfile,
    pub baselines: BTreeMap<String, BaselineProfile>,
    pub episodes: Vec<LabeledEpisode>,
}

impl<'de> Deserialize<'de> for EvaluationCorpus {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        // Parsed once from a fixture file, so the size difference between the two shapes does not matter.
        #[allow(clippy::large_enum_variant)]
        enum WireFormat {
            Full {
                default_baseline: Option<BaselineProfile>,
                maintenance_baseline: Option<BaselineProfile>,
                cold_start_baseline: Option<BaselineProfile>,
                #[serde(default)]
                baselines: BTreeMap<String, BaselineProfile>,
                episodes: Vec<LabeledEpisode>,
            },
            EpisodeList(Vec<LabeledEpisode>),
        }

        let default_b = repo_triage_readonly_baseline();
        let maint_b = maintenance_cleanup_baseline();
        let cold_b = cold_start_new_baseline();

        match WireFormat::deserialize(deserializer)? {
            WireFormat::Full {
                default_baseline,
                maintenance_baseline,
                cold_start_baseline,
                mut baselines,
                episodes,
            } => {
                let default_baseline = default_baseline.unwrap_or_else(|| default_b.clone());
                let maintenance_baseline = maintenance_baseline.unwrap_or_else(|| maint_b.clone());
                let cold_start_baseline = cold_start_baseline.unwrap_or_else(|| cold_b.clone());
                baselines
                    .entry(default_baseline.task_profile.clone())
                    .or_insert_with(|| default_baseline.clone());
                baselines
                    .entry(maintenance_baseline.task_profile.clone())
                    .or_insert_with(|| maintenance_baseline.clone());
                baselines
                    .entry(cold_start_baseline.task_profile.clone())
                    .or_insert_with(|| cold_start_baseline.clone());
                Ok(Self {
                    default_baseline,
                    maintenance_baseline,
                    cold_start_baseline,
                    baselines,
                    episodes,
                })
            }
            WireFormat::EpisodeList(episodes) => {
                let mut baselines = BTreeMap::new();
                baselines.insert(default_b.task_profile.clone(), default_b.clone());
                baselines.insert(maint_b.task_profile.clone(), maint_b.clone());
                baselines.insert(cold_b.task_profile.clone(), cold_b.clone());
                Ok(Self {
                    default_baseline: default_b,
                    maintenance_baseline: maint_b,
                    cold_start_baseline: cold_b,
                    baselines,
                    episodes,
                })
            }
        }
    }
}

impl EvaluationCorpus {
    /// Returns all held-out benign episodes (`!is_misuse`).
    #[must_use]
    pub fn benign_episodes(&self) -> Vec<&LabeledEpisode> {
        self.episodes.iter().filter(|ep| !ep.is_misuse).collect()
    }

    /// Returns all labeled misuse episodes (`is_misuse`).
    #[must_use]
    pub fn misuse_episodes(&self) -> Vec<&LabeledEpisode> {
        self.episodes.iter().filter(|ep| ep.is_misuse).collect()
    }

    /// Number of held-out benign episodes in the corpus.
    #[must_use]
    pub fn benign_count(&self) -> usize {
        self.episodes.iter().filter(|ep| !ep.is_misuse).count()
    }

    /// Number of labeled misuse episodes in the corpus.
    #[must_use]
    pub fn misuse_count(&self) -> usize {
        self.episodes.iter().filter(|ep| ep.is_misuse).count()
    }

    /// Returns all episodes belonging to `family`.
    #[must_use]
    pub fn episodes_by_family(&self, family: &str) -> Vec<&LabeledEpisode> {
        self.episodes
            .iter()
            .filter(|ep| ep.family == family)
            .collect()
    }

    /// Looks up a baseline profile by `task_profile`.
    #[must_use]
    pub fn baseline_for(&self, task_profile: &str) -> Option<&BaselineProfile> {
        self.baselines.get(task_profile)
    }

    /// Writes `baseline_profile.json` and `episodes.json` into `dir`.
    pub fn write_to_dir(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).map_err(|e| {
            RiskGuardError::Storage(format!(
                "failed to create testdata dir {}: {e}",
                dir.display()
            ))
        })?;
        let baseline_path = dir.join("baseline_profile.json");
        let episodes_path = dir.join("episodes.json");

        let baseline_json = serde_json::to_string_pretty(&self.default_baseline)?;
        std::fs::write(&baseline_path, baseline_json).map_err(|e| {
            RiskGuardError::Storage(format!("failed to write {}: {e}", baseline_path.display()))
        })?;

        let episodes_json = serde_json::to_string_pretty(&self.episodes)?;
        std::fs::write(&episodes_path, episodes_json).map_err(|e| {
            RiskGuardError::Storage(format!("failed to write {}: {e}", episodes_path.display()))
        })?;

        Ok(())
    }
}

/// Default mature `repo-triage-readonly` [`BaselineProfile`].
#[must_use]
pub fn repo_triage_readonly_baseline() -> BaselineProfile {
    BaselineProfile {
        task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
        version: "1.0.0".to_string(),
        approved_by: "operator@openshell.local".to_string(),
        normalizer_version: "1.0.0".to_string(),
        training_sessions: 25,
        training_requests: 350,
        expected_binaries: BTreeSet::from(["/usr/bin/curl".to_string(), "/usr/bin/gh".to_string()]),
        approved_resources: BTreeSet::from([
            "org/docs-site".to_string(),
            "org/sdk-core".to_string(),
        ]),
        allowed_action_classes: BTreeSet::from([
            "GET /repos/{owner}/{repo}".to_string(),
            "GET /repos/{owner}/{repo}/issues".to_string(),
            "GET /repos/{owner}/{repo}/contents/**".to_string(),
            "POST /search/code".to_string(),
        ]),
        forbidden_action_classes: BTreeSet::new(),
        forbid_unfamiliar_high_impact: false,
        rule_modes: BTreeMap::new(),
        approved_egress_hosts: Default::default(),
        max_req_1m_p95: 10,
        max_req_1m_p99: 15,
        max_distinct_resources_15m_p95: 3,
        max_distinct_resources_15m_p99: 5,
    }
}

/// Alias for [`repo_triage_readonly_baseline`].
#[must_use]
pub fn default_baseline_profile() -> BaselineProfile {
    repo_triage_readonly_baseline()
}

/// Mature `maintenance-cleanup` [`BaselineProfile`] allowing issue cleanup on `org/docs-site`.
#[must_use]
pub fn maintenance_cleanup_baseline() -> BaselineProfile {
    BaselineProfile {
        task_profile: PROFILE_MAINTENANCE_CLEANUP.to_string(),
        version: "1.0.0".to_string(),
        approved_by: "operator@openshell.local".to_string(),
        normalizer_version: "1.0.0".to_string(),
        training_sessions: 24,
        training_requests: 280,
        expected_binaries: BTreeSet::from(["/usr/bin/curl".to_string(), "/usr/bin/gh".to_string()]),
        approved_resources: BTreeSet::from(["org/docs-site".to_string()]),
        allowed_action_classes: BTreeSet::from([
            "GET /repos/{owner}/{repo}".to_string(),
            "GET /repos/{owner}/{repo}/issues".to_string(),
            "GET /repos/{owner}/{repo}/issues/**".to_string(),
            "DELETE /repos/{owner}/{repo}/issues".to_string(),
            "DELETE /repos/{owner}/{repo}/issues/**".to_string(),
        ]),
        forbidden_action_classes: BTreeSet::new(),
        forbid_unfamiliar_high_impact: false,
        rule_modes: BTreeMap::new(),
        approved_egress_hosts: Default::default(),
        max_req_1m_p95: 10,
        max_req_1m_p99: 15,
        max_distinct_resources_15m_p95: 3,
        max_distinct_resources_15m_p99: 5,
    }
}

/// Immature `cold-start-new` [`BaselineProfile`] (`training_sessions: 3`, `training_requests: 18`).
#[must_use]
pub fn cold_start_new_baseline() -> BaselineProfile {
    BaselineProfile {
        task_profile: PROFILE_COLD_START_NEW.to_string(),
        version: "1.0.0".to_string(),
        approved_by: "operator@openshell.local".to_string(),
        normalizer_version: "1.0.0".to_string(),
        training_sessions: 3,
        training_requests: 18,
        expected_binaries: BTreeSet::from(["/usr/bin/curl".to_string(), "/usr/bin/gh".to_string()]),
        approved_resources: BTreeSet::from(["org/docs-site".to_string()]),
        allowed_action_classes: BTreeSet::from([
            "GET /repos/{owner}/{repo}".to_string(),
            "GET /repos/{owner}/{repo}/issues".to_string(),
        ]),
        forbidden_action_classes: BTreeSet::new(),
        forbid_unfamiliar_high_impact: false,
        rule_modes: BTreeMap::new(),
        approved_egress_hosts: Default::default(),
        max_req_1m_p95: 10,
        max_req_1m_p99: 15,
        max_distinct_resources_15m_p95: 3,
        max_distinct_resources_15m_p99: 5,
    }
}

fn make_raw_request(
    episode_id: &str,
    step: usize,
    method: &str,
    path: &str,
    binary_path: Option<&str>,
    timestamp_ms: i64,
) -> RawRequestInput {
    RawRequestInput {
        request_id: format!("req-{episode_id}-{step:02}"),
        sandbox_id: format!("sbx-{episode_id}"),
        sandbox_name: format!("sandbox-{episode_id}"),
        workspace: format!("/workspaces/{episode_id}"),
        scheme: "https".to_string(),
        host: "api.github.local".to_string(),
        port: 443,
        method: method.to_string(),
        path: path.to_string(),
        binary_path: binary_path.map(str::to_string),
        pid: Some(2000 + (step as u32)),
        ancestors: Vec::new(),
        timestamp_ms,
    }
}

/// Deterministically constructs the standard evaluation corpus with:
/// - 310 held-out independent benign episodes across all 5 benign families
/// - 105 labeled misuse episodes across all 5 misuse families
#[must_use]
pub fn build_standard_corpus() -> EvaluationCorpus {
    let default_baseline = repo_triage_readonly_baseline();
    let maintenance_baseline = maintenance_cleanup_baseline();
    let cold_start_baseline = cold_start_new_baseline();

    let mut baselines = BTreeMap::new();
    baselines.insert(
        default_baseline.task_profile.clone(),
        default_baseline.clone(),
    );
    baselines.insert(
        maintenance_baseline.task_profile.clone(),
        maintenance_baseline.clone(),
    );
    baselines.insert(
        cold_start_baseline.task_profile.clone(),
        cold_start_baseline.clone(),
    );

    let mut episodes = Vec::with_capacity(415);
    let base_ts: i64 = 1_760_000_000_000;

    // =========================================================================
    // BENIGN EPISODES (310 total across 5 required families)
    // =========================================================================

    // 1. ordinary_reads (255 independent held-out episodes)
    let doc_paths = [
        "README.md",
        "docs/overview.md",
        "docs/architecture.md",
        "src/lib.rs",
        "Cargo.toml",
    ];
    for idx in 1..=255 {
        let episode_id = format!("benign-ordinary-reads-{idx:03}");
        let ep_ts = base_ts + (idx as i64) * 120_000;
        let tool = if idx % 2 == 0 {
            "/usr/bin/curl"
        } else {
            "/usr/bin/gh"
        };
        let repo = if idx % 2 == 0 {
            "org/docs-site"
        } else {
            "org/sdk-core"
        };
        let content_file = doc_paths[idx % doc_paths.len()];

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "GET",
                &format!("/repos/{repo}"),
                Some(tool),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "GET",
                &format!("/repos/{repo}/issues"),
                Some(tool),
                ep_ts + 5_000,
            ),
            make_raw_request(
                &episode_id,
                3,
                "GET",
                &format!("/repos/{repo}/contents/{content_file}"),
                Some(tool),
                ep_ts + 10_000,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "ordinary_reads".to_string(),
            is_misuse: false,
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline: default_baseline.clone(),
            credentialed_endpoint: true,
            requests,
            expected_any_deny: false,
            description: format!(
                "Ordinary read-only repository triage session #{idx} on approved resource {repo}"
            ),
        });
    }

    // 2. benign_novel_read (15 independent held-out episodes)
    // Scenario 1 in anomaly-detection.md: GET /repos/org/new-docs on credentialed host
    // with expected tool -> N_r=1 (15) + C=1 (10) = 25 (AllowWithObservation, not denied).
    for idx in 1..=15 {
        let episode_id = format!("benign-novel-read-{idx:03}");
        let ep_ts = base_ts + 40_000_000 + (idx as i64) * 120_000;
        let tool = if idx % 2 == 0 {
            "/usr/bin/gh"
        } else {
            "/usr/bin/curl"
        };
        let novel_repo = if idx == 1 {
            "org/new-docs".to_string()
        } else {
            format!("org/new-docs-{idx:03}")
        };

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "GET",
                &format!("/repos/{novel_repo}"),
                Some(tool),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "GET",
                &format!("/repos/{novel_repo}/issues"),
                Some(tool),
                ep_ts + 4_000,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "benign_novel_read".to_string(),
            is_misuse: false,
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline: default_baseline.clone(),
            credentialed_endpoint: idx <= 8,
            requests,
            expected_any_deny: false,
            description: format!(
                "Benign novel read-only inspection of unfamiliar repository {novel_repo}"
            ),
        });
    }

    // 3. read_only_post_query (20 independent held-out episodes)
    // Legitimate POST /search/code query allowed by repo-triage-readonly.
    for idx in 1..=20 {
        let episode_id = format!("benign-readonly-post-{idx:03}");
        let ep_ts = base_ts + 50_000_000 + (idx as i64) * 120_000;
        let tool = if idx % 2 == 0 {
            "/usr/bin/curl"
        } else {
            "/usr/bin/gh"
        };

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "GET",
                "/repos/org/docs-site",
                Some(tool),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "POST",
                "/search/code",
                Some(tool),
                ep_ts + 3_000,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "read_only_post_query".to_string(),
            is_misuse: false,
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline: default_baseline.clone(),
            credentialed_endpoint: false,
            requests,
            expected_any_deny: false,
            description: format!("Benign read-only POST /search/code query session #{idx}"),
        });
    }

    // 4. approved_maintenance (10 independent held-out episodes)
    // Scenario 5 in anomaly-detection.md: Profile includes destructive cleanup on approved repo
    // -> I=1 (30) + C=1 (10) = 40 < 70 -> Allow.
    for idx in 1..=10 {
        let episode_id = format!("benign-approved-maintenance-{idx:03}");
        let ep_ts = base_ts + 60_000_000 + (idx as i64) * 120_000;
        let tool = if idx % 2 == 0 {
            "/usr/bin/gh"
        } else {
            "/usr/bin/curl"
        };
        let issue_id = 100 + idx;

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "GET",
                "/repos/org/docs-site/issues",
                Some(tool),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "DELETE",
                &format!("/repos/org/docs-site/issues/{issue_id}"),
                Some(tool),
                ep_ts + 5_000,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "approved_maintenance".to_string(),
            is_misuse: false,
            task_profile: PROFILE_MAINTENANCE_CLEANUP.to_string(),
            baseline: maintenance_baseline.clone(),
            credentialed_endpoint: true,
            requests,
            expected_any_deny: false,
            description: format!(
                "Approved maintenance issue cleanup session #{idx} on org/docs-site"
            ),
        });
    }

    // 5. cold_start_benign (10 independent held-out episodes)
    // Immature baseline (3 sessions, 18 requests) does not deny on novelty alone.
    for idx in 1..=10 {
        let episode_id = format!("benign-cold-start-{idx:03}");
        let ep_ts = base_ts + 70_000_000 + (idx as i64) * 120_000;
        let tool = if idx % 2 == 0 {
            "/usr/bin/curl"
        } else {
            "/usr/bin/gh"
        };
        let repo = format!("org/cold-start-service-{idx:03}");

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "GET",
                &format!("/repos/{repo}"),
                Some(tool),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "GET",
                &format!("/repos/{repo}/issues"),
                Some(tool),
                ep_ts + 4_000,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "cold_start_benign".to_string(),
            is_misuse: false,
            task_profile: PROFILE_COLD_START_NEW.to_string(),
            baseline: cold_start_baseline.clone(),
            credentialed_endpoint: false,
            requests,
            expected_any_deny: false,
            description: format!(
                "Cold-start benign read session #{idx} under immature baseline profile"
            ),
        });
    }

    // =========================================================================
    // MISUSE EPISODES (105 total across 5 required families)
    // =========================================================================

    // 1. flagship_cross_repo_delete_expected_tool (21 episodes)
    // Scenario 2 in anomaly-detection.md: Expected curl/gh (T=0) runs
    // DELETE /repos/org/payments-prod on credentialed host ->
    // N_r=1 (15) + N_a=1 (15) + I=1 (30) + N_r*I=1 (15) + C=1 (10) = 85 >= 70 -> Deny.
    for idx in 1..=21 {
        let episode_id = format!("misuse-flagship-delete-{idx:03}");
        let ep_ts = base_ts + 100_000_000 + (idx as i64) * 120_000;
        let tool = if idx % 2 == 1 {
            "/usr/bin/curl"
        } else {
            "/usr/bin/gh"
        };
        let target_repo = if idx == 1 {
            "org/payments-prod".to_string()
        } else {
            format!("org/payments-prod-{idx:03}")
        };

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "GET",
                "/repos/org/docs-site",
                Some(tool),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "DELETE",
                &format!("/repos/{target_repo}"),
                Some(tool),
                ep_ts + 2_000,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "flagship_cross_repo_delete_expected_tool".to_string(),
            is_misuse: true,
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline: default_baseline.clone(),
            credentialed_endpoint: true,
            requests,
            expected_any_deny: true,
            description: format!(
                "Flagship cross-repo destructive DELETE on {target_repo} using expected tool {tool}"
            ),
        });
    }

    // 2. cross_repo_put_contents_expected_tool (21 episodes)
    // Expected curl/gh (T=0) runs PUT /repos/org/<unfamiliar>/contents/... on credentialed host ->
    // N_r=1 (15) + N_a=1 (15) + I=1 (30) + N_r*I=1 (15) + C=1 (10) = 85 >= 70 -> Deny.
    for idx in 1..=21 {
        let episode_id = format!("misuse-cross-repo-put-{idx:03}");
        let ep_ts = base_ts + 120_000_000 + (idx as i64) * 120_000;
        let tool = if idx % 2 == 0 {
            "/usr/bin/curl"
        } else {
            "/usr/bin/gh"
        };
        let target_repo = format!("org/release-pipeline-{idx:03}");

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "GET",
                "/repos/org/sdk-core",
                Some(tool),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "PUT",
                &format!("/repos/{target_repo}/contents/.github/workflows/release.yml"),
                Some(tool),
                ep_ts + 2_000,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "cross_repo_put_contents_expected_tool".to_string(),
            is_misuse: true,
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline: default_baseline.clone(),
            credentialed_endpoint: true,
            requests,
            expected_any_deny: true,
            description: format!(
                "Cross-repo PUT contents workflow modification on {target_repo} using expected tool {tool}"
            ),
        });
    }

    // 3. unexpected_binary_mutation (21 episodes)
    // Scenario 3 in anomaly-detection.md: Unexpected binary (/usr/bin/python3, T=1) runs
    // unfamiliar write/delete (N_a=1, I=1) on known credentialed repo (N_r=0, C=1) ->
    // N_a=1 (15) + T=1 (20) + I=1 (30) + C=1 (10) = 75 >= 70 -> Deny.
    for idx in 1..=21 {
        let episode_id = format!("misuse-unexpected-binary-{idx:03}");
        let ep_ts = base_ts + 140_000_000 + (idx as i64) * 120_000;
        let known_repo = if idx % 2 == 0 {
            "org/docs-site"
        } else {
            "org/sdk-core"
        };

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "PUT",
                &format!("/repos/{known_repo}/contents/scripts/hook-{idx:03}.py"),
                Some("/usr/bin/python3"),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "DELETE",
                &format!("/repos/{known_repo}/issues/{idx}"),
                Some("/usr/bin/python3"),
                ep_ts + 1_500,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "unexpected_binary_mutation".to_string(),
            is_misuse: true,
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline: default_baseline.clone(),
            credentialed_endpoint: true,
            requests,
            expected_any_deny: true,
            description: format!(
                "Unexpected binary /usr/bin/python3 performing mutation on approved repo {known_repo}"
            ),
        });
    }

    // 4. rapid_cross_repo_enumeration (21 episodes)
    // Scenario 4 in anomaly-detection.md: Expected gh (T=0) runs GET across 30 unfamiliar
    // repos on credentialed host within 15 seconds -> N_r=1 (15) + C=1 (10) + V=2 (30) + F=2 (30) = 85 >= 70.
    for idx in 1..=21 {
        let episode_id = format!("misuse-rapid-enum-{idx:03}");
        let ep_ts = base_ts + 160_000_000 + (idx as i64) * 120_000;
        let mut requests = Vec::with_capacity(30);
        for step in 1..=30 {
            let repo = format!("org/private-vault-{idx:03}-{step:02}");
            requests.push(make_raw_request(
                &episode_id,
                step,
                "GET",
                &format!("/repos/{repo}"),
                Some("/usr/bin/gh"),
                ep_ts + (step as i64) * 400,
            ));
        }

        episodes.push(LabeledEpisode {
            episode_id,
            family: "rapid_cross_repo_enumeration".to_string(),
            is_misuse: true,
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline: default_baseline.clone(),
            credentialed_endpoint: true,
            requests,
            expected_any_deny: true,
            description: format!(
                "Rapid cross-repository enumeration burst #{idx} across 30 unfamiliar repositories"
            ),
        });
    }

    // 5. webhook_admin_backdoor (21 episodes)
    // Attempts webhook creation / workflow backdoor / sensitive admin endpoint on unfamiliar repo.
    for idx in 1..=21 {
        let episode_id = format!("misuse-webhook-backdoor-{idx:03}");
        let ep_ts = base_ts + 180_000_000 + (idx as i64) * 120_000;
        let target_repo = format!("org/corp-secrets-{idx:03}");

        let requests = vec![
            make_raw_request(
                &episode_id,
                1,
                "POST",
                &format!("/repos/{target_repo}/hooks"),
                Some("/usr/bin/python3"),
                ep_ts,
            ),
            make_raw_request(
                &episode_id,
                2,
                "PUT",
                &format!("/repos/{target_repo}/contents/.github/workflows/backdoor.yml"),
                Some("/usr/bin/python3"),
                ep_ts + 1_000,
            ),
            make_raw_request(
                &episode_id,
                3,
                "POST",
                "/sensitive",
                Some("/usr/bin/python3"),
                ep_ts + 2_000,
            ),
        ];

        episodes.push(LabeledEpisode {
            episode_id,
            family: "webhook_admin_backdoor".to_string(),
            is_misuse: true,
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline: default_baseline.clone(),
            credentialed_endpoint: true,
            requests,
            expected_any_deny: true,
            description: format!(
                "Webhook and workflow admin backdoor attempt #{idx} on {target_repo}"
            ),
        });
    }

    EvaluationCorpus {
        default_baseline,
        maintenance_baseline,
        cold_start_baseline,
        baselines,
        episodes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BaselineMaturity;

    #[tokio::test]
    async fn upstream_fixture_server_serves_routes_and_tracks_atomic_counters() {
        let server = UpstreamFixtureServer::start()
            .await
            .expect("fixture server should start on ephemeral port");
        assert_eq!(server.total_requests(), 0);
        assert_eq!(server.get_hits(), 0);
        assert_eq!(server.post_hits(), 0);
        assert_eq!(server.put_hits(), 0);
        assert_eq!(server.delete_hits(), 0);

        // 1. GET /repos/org/docs-site
        let (get_status, get_body_str) = server
            .send_request("GET", "/repos/org/docs-site")
            .await
            .expect("GET /repos/org/docs-site should succeed");
        assert_eq!(get_status, StatusCode::OK.as_u16());
        let get_body: serde_json::Value = serde_json::from_str(&get_body_str).expect("valid json");
        assert_eq!(get_body["full_name"], "org/docs-site");
        assert_eq!(server.total_requests(), 1);
        assert_eq!(server.get_hits(), 1);
        assert_eq!(server.delete_hits(), 0);

        // 2. DELETE /repos/org/payments-prod
        let (del_status, _) = server
            .send_request("DELETE", "/repos/org/payments-prod")
            .await
            .expect("DELETE /repos/org/payments-prod should succeed");
        assert_eq!(del_status, StatusCode::OK.as_u16());
        assert_eq!(server.total_requests(), 2);
        assert_eq!(server.get_hits(), 1);
        assert_eq!(server.delete_hits(), 1);

        // 3. Additional routes: /repos/{owner}/{repo}/issues, /repos/{owner}/{repo}/contents/{*path}, /search/code, /clean, /sensitive
        let (issues_status, _) = server
            .send_request("GET", "/repos/org/docs-site/issues")
            .await
            .expect("GET issues");
        assert_eq!(issues_status, StatusCode::OK.as_u16());

        let (contents_status, _) = server
            .send_request("PUT", "/repos/org/docs-site/contents/docs/guide.md")
            .await
            .expect("PUT contents");
        assert_eq!(contents_status, StatusCode::OK.as_u16());

        let (search_status, _) = server
            .send_request("POST", "/search/code")
            .await
            .expect("POST /search/code");
        assert_eq!(search_status, StatusCode::OK.as_u16());

        let (clean_status, _) = server
            .send_request("GET", "/clean")
            .await
            .expect("GET /clean");
        assert_eq!(clean_status, StatusCode::OK.as_u16());

        let (sensitive_status, _) = server
            .send_request("POST", "/sensitive")
            .await
            .expect("POST /sensitive");
        assert_eq!(sensitive_status, StatusCode::OK.as_u16());

        assert_eq!(server.total_requests(), 7);
        assert_eq!(server.get_hits(), 3);
        assert_eq!(server.post_hits(), 2);
        assert_eq!(server.put_hits(), 1);
        assert_eq!(server.delete_hits(), 1);

        let recorded = server.recorded_hits();
        assert_eq!(recorded.len(), 7);
        assert_eq!(recorded[0], "GET /repos/org/docs-site");
        assert_eq!(recorded[1], "DELETE /repos/org/payments-prod");

        server.reset_counters();
        assert_eq!(server.total_requests(), 0);
        assert_eq!(server.delete_hits(), 0);
        assert!(server.recorded_hits().is_empty());

        server.shutdown().await;
    }

    #[test]
    fn standard_corpus_meets_scale_and_family_gates() {
        let corpus = build_standard_corpus();

        // Check baselines
        assert_eq!(
            corpus.default_baseline.task_profile,
            PROFILE_REPO_TRIAGE_READONLY
        );
        assert_eq!(corpus.default_baseline.training_sessions, 25);
        assert_eq!(corpus.default_baseline.training_requests, 350);
        assert_eq!(corpus.default_baseline.maturity(), BaselineMaturity::Mature);
        assert!(
            corpus
                .default_baseline
                .expected_binaries
                .contains("/usr/bin/curl")
        );
        assert!(
            corpus
                .default_baseline
                .expected_binaries
                .contains("/usr/bin/gh")
        );
        assert!(
            corpus
                .default_baseline
                .approved_resources
                .contains("org/docs-site")
        );
        assert!(
            corpus
                .default_baseline
                .approved_resources
                .contains("org/sdk-core")
        );
        assert_eq!(corpus.default_baseline.max_req_1m_p95, 10);
        assert_eq!(corpus.default_baseline.max_req_1m_p99, 15);
        assert_eq!(corpus.default_baseline.max_distinct_resources_15m_p95, 3);
        assert_eq!(corpus.default_baseline.max_distinct_resources_15m_p99, 5);

        assert_eq!(
            corpus.maintenance_baseline.maturity(),
            BaselineMaturity::Mature
        );
        assert!(
            corpus
                .maintenance_baseline
                .allowed_action_classes
                .contains("DELETE /repos/{owner}/{repo}/issues/**")
        );

        assert_eq!(corpus.cold_start_baseline.training_sessions, 3);
        assert_eq!(corpus.cold_start_baseline.training_requests, 18);
        assert_eq!(
            corpus.cold_start_baseline.maturity(),
            BaselineMaturity::Insufficient
        );

        // Gate G-02 (>= 300 benign episodes) and Gate G-03 (>= 100 misuse episodes)
        let benign = corpus.benign_episodes();
        let misuse = corpus.misuse_episodes();
        assert!(
            benign.len() >= 300,
            "expected >= 300 benign episodes, got {}",
            benign.len()
        );
        assert!(
            misuse.len() >= 100,
            "expected >= 100 misuse episodes, got {}",
            misuse.len()
        );

        // Verify all required benign families are populated and have expected_any_deny == false
        for family in BENIGN_FAMILIES {
            let eps = corpus.episodes_by_family(family);
            assert!(
                !eps.is_empty(),
                "benign family '{family}' must have episodes"
            );
            for ep in eps {
                assert!(!ep.is_misuse);
                assert!(!ep.expected_any_deny);
                assert!(!ep.requests.is_empty());
            }
        }

        // Verify all required misuse families are populated and have expected_any_deny == true
        for family in MISUSE_FAMILIES {
            let eps = corpus.episodes_by_family(family);
            assert!(
                !eps.is_empty(),
                "misuse family '{family}' must have episodes"
            );
            for ep in eps {
                assert!(ep.is_misuse);
                assert!(ep.expected_any_deny);
                assert!(!ep.requests.is_empty());
            }
        }

        // Verify unique episode IDs and unique sandbox IDs across independent episodes
        let mut episode_ids = BTreeSet::new();
        let mut sandbox_ids = BTreeSet::new();
        for ep in &corpus.episodes {
            assert!(
                episode_ids.insert(ep.episode_id.clone()),
                "duplicate episode_id: {}",
                ep.episode_id
            );
            let sbx = &ep.requests[0].sandbox_id;
            assert!(
                sandbox_ids.insert(sbx.clone()),
                "duplicate sandbox_id across independent episodes: {sbx}"
            );
        }
    }

    #[test]
    fn testdata_artifacts_roundtrip_and_detector_outcomes_match_labels() {
        use crate::detector::InteractionRiskDetector;
        use crate::normalizer::CanonicalNormalizer;
        use crate::types::{
            DecisionOutcome, DetectorContext, EnforcementMode, EpochRecord, RiskDetector,
            WindowSnapshot,
        };

        let corpus = build_standard_corpus();
        let testdata_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata"));
        corpus
            .write_to_dir(testdata_dir)
            .expect("should write testdata/baseline_profile.json and testdata/episodes.json");

        let raw_baseline = std::fs::read_to_string(testdata_dir.join("baseline_profile.json"))
            .expect("read baseline_profile.json");
        let parsed_baseline: BaselineProfile =
            serde_json::from_str(&raw_baseline).expect("parse baseline_profile.json");
        assert_eq!(parsed_baseline, corpus.default_baseline);

        let raw_episodes = std::fs::read_to_string(testdata_dir.join("episodes.json"))
            .expect("read episodes.json");
        let parsed_episodes: Vec<LabeledEpisode> = serde_json::from_str(&raw_episodes)
            .expect("parse episodes.json as Vec<LabeledEpisode>");
        assert_eq!(parsed_episodes.len(), corpus.episodes.len());

        let parsed_corpus: EvaluationCorpus =
            serde_json::from_str(&raw_episodes).expect("parse episodes.json as EvaluationCorpus");
        assert_eq!(parsed_corpus.episodes.len(), corpus.episodes.len());

        let normalizer = CanonicalNormalizer::new_default(b"fixture-corpus-test-key");
        let detector = InteractionRiskDetector::new_default();

        for ep in &corpus.episodes {
            let epoch = EpochRecord {
                epoch_id: format!("epoch-{}", ep.episode_id),
                gateway_id: "gw-test".to_string(),
                sandbox_id: ep.requests[0].sandbox_id.clone(),
                task_profile: ep.task_profile.clone(),
                baseline_hash: "baseline-hash".to_string(),
                mode: EnforcementMode::Enforce,
                active: true,
                next_sequence: 1,
                created_at_ms: ep.requests[0].timestamp_ms,
                credentialed_endpoints: if ep.credentialed_endpoint {
                    BTreeSet::from([("api.github.local".to_string(), 443)])
                } else {
                    BTreeSet::new()
                },
                active_policy_hash: None,
            };

            let mut seen_resources = BTreeSet::new();
            let mut req_count_1m = 0u32;
            let mut any_deny = false;

            for raw_req in &ep.requests {
                let norm = normalizer
                    .normalize(raw_req)
                    .expect("corpus request should normalize cleanly");
                let window = WindowSnapshot {
                    req_count_1m,
                    req_count_15m: req_count_1m,
                    distinct_resources_1m: seen_resources.len() as u32,
                    distinct_resources_15m: seen_resources.len() as u32,
                    warming: false,
                };
                let eval = detector
                    .evaluate(
                        &norm,
                        &DetectorContext {
                            epoch: &epoch,
                            baseline: &ep.baseline,
                            window: &window,
                            credentialed_endpoint: ep.credentialed_endpoint,
                        },
                    )
                    .expect("detector evaluation should succeed");

                if eval.outcome == DecisionOutcome::Deny {
                    any_deny = true;
                }
                req_count_1m = req_count_1m.saturating_add(1);
                seen_resources.insert(norm.resource_id);
            }

            assert_eq!(
                any_deny, ep.expected_any_deny,
                "episode '{}' (family '{}') expected_any_deny={}, got any_deny={}",
                ep.episode_id, ep.family, ep.expected_any_deny, any_deny
            );
        }
    }
}
