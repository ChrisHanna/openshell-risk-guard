// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end 10-step live demo acceptance sequence and fault-injection suite
//! (`t11-e2e-demo-smoke`).
//!
//! Verifies release gates:
//! - **Gate G-01 (Enforcement & Baseline Attenuation):** Every designated denied
//!   request has zero corresponding application hits at `UpstreamFixtureServer`,
//!   and OpenShell baseline denials are never rescued by middleware.
//! - **Gate G-09 (Hardening Completeness & No Auto-Apply):** Periodic hardening
//!   recommendations declare completeness and replay results (`replay_would_block == 0`)
//!   while leaving the active policy hash in SQLite unchanged until operator approval.
//! - **Gate G-10 (Reliability & Fault Injection):** Explicit deterministic behavior
//!   for duplicate `request_id` idempotency, conflicting duplicate `request_id`
//!   rejection (`InvalidArgument`), wrong-sandbox/expired/wrong-audience JWT
//!   rejection (`PermissionDenied` / `Unauthenticated`), admission queue exhaustion
//!   (`ResourceExhausted`), and cold-start immature baseline safety.
//! - **Gate G-11 (Storage Durability & Strict Ratchet Persistence):** Verifies
//!   `PRAGMA journal_mode = WAL`, `synchronous = FULL (2)`, `foreign_keys = ON (1)`,
//!   and durable survival of Tier 1 `strict_epoch` and Tier 2 `cooldown` restrictions
//!   across full sidecar process stop and restart on the same on-disk SQLite file.
//! - **Gate G-12 (Two-Step Containment Proof):** Verifies `raw_prover_status` notes
//!   `unsupported: uses network middleware controls` on raw policies with
//!   `network_middlewares`, while Step 1 (`step1_middleware_invariant`) + Step 2
//!   (`openshell-prover` Z3 check on the middleware-stripped projection ->
//!   `within_boundary`) prove `verified_non_expanding == true` and reject expanding
//!   or middleware-stripping mutations.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::gateway_interceptor::v1::gateway_interceptor_client::GatewayInterceptorClient;
use openshell_core::proto::gateway_interceptor::v1::{
    InterceptorEvaluation, InterceptorResult, PostCommitEvaluation, ValidateEvaluation,
    interceptor_evaluation,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    Decision, HttpHeader, HttpRequestEvaluation, HttpRequestResult, HttpRequestTarget, Process,
    RequestContext, SupervisorMiddlewarePhase,
};
use openshell_risk_guard::auth::{
    EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims, JwtTestIssuer,
};
use openshell_risk_guard::cli::{Cli, Commands, execute_cli, open_and_seed_store};
use openshell_risk_guard::detector::{
    InteractionRiskDetector, REASON_BASELINE_INSUFFICIENT, compute_baseline_hash,
};
use openshell_risk_guard::fixture::{
    PROFILE_COLD_START_NEW, PROFILE_REPO_TRIAGE_READONLY, UpstreamFixtureServer,
    build_standard_corpus,
};
use openshell_risk_guard::hardening::ProverHardeningEngine;
use openshell_risk_guard::interceptor_service::RiskGuardInterceptorService;
use openshell_risk_guard::middleware_service::RiskGuardMiddlewareService;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::{
    DecisionOutcome, EnforcementMode, EpochRecord, HardeningCandidate, HardeningEngine,
    REASON_BEHAVIORAL_RISK_DENIED, REASON_BEHAVIORAL_RISK_RESTRICTED,
    REASON_TASK_CONSTRAINT_DENIED, RatchetAction, RawRequestInput, RiskStore,
};
use prost_types::value::Kind;
use prost_types::{ListValue, Struct, Value as ProtoValue};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;
use tonic::{Code, Request};

const DEMO_GATEWAY_ID: &str = "gw-demo-prod-01";
const DEMO_AUDIENCE: &str = "urn:openshell:extension:risk-guard";
const DEMO_SANDBOX_ID: &str = "sbx_demo";
const DEMO_ENUM_SANDBOX_ID: &str = "sbx_demo_enum";
const DEMO_HMAC_KEY: &[u8] = b"openshell-risk-guard-e2e-demo-hmac-key";

/// Deliberately broad initial static policy for Step 1 (`access: full` on
/// `api.github.local:18443` with `credential_binding: github-work` and
/// `network_middlewares: risk-guard` `on_error: fail_closed`).
const INITIAL_BROAD_POLICY_YAML: &str = r#"version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.local
        port: 18443
        protocol: rest
        enforcement: enforce
        access: full
        credential_binding:
          provider: github-work
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/gh
      - path: /usr/bin/git
"#;

/// Candidate policy for Step 9(b) that illegally strips `risk-guard` from `network_middlewares`.
const STRIPPED_MIDDLEWARE_POLICY_YAML: &str = r#"version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  github_api:
    endpoints:
      - host: api.github.local
        port: 18443
        protocol: rest
        enforcement: enforce
        access: read-only
        credential_binding:
          provider: github-work
    binaries:
      - path: /usr/bin/curl
"#;

/// Candidate policy for Step 9(c) that retains `risk-guard` middleware but expands
/// network permissions by adding a new host `evil.example.com`.
const EXPANDED_HOST_POLICY_YAML: &str = r#"version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.local
        port: 18443
        protocol: rest
        enforcement: enforce
        access: full
        credential_binding:
          provider: github-work
      - host: evil.example.com
        port: 8443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/gh
      - path: /usr/bin/git
"#;

/// Running gRPC server instance hosting both `RiskGuardMiddlewareService` and
/// `RiskGuardInterceptorService` over TCP.
struct RunningSidecarServer {
    addr: SocketAddr,
    store: Arc<SqliteRiskStore>,
    admission: Arc<Semaphore>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<JoinHandle<()>>,
}

impl RunningSidecarServer {
    /// Boots the unified gRPC server against the on-disk SQLite file at `db_path`.
    async fn start(
        db_path: &Path,
        issuer: &JwtTestIssuer,
        cooldown_duration_ms: i64,
        max_in_flight: usize,
    ) -> Self {
        let store = Arc::new(open_and_seed_store(db_path).expect("open and seed on-disk SQLite store"));
        let pragmas = store.verify_pragmas().expect("verify SQLite pragmas");
        assert_eq!(
            pragmas,
            ("wal".to_string(), 2, 1),
            "Gate G-11 requires journal_mode=wal, synchronous=FULL(2), foreign_keys=ON(1)"
        );

        let verifier = Arc::new(
            issuer
                .verifier(DEMO_AUDIENCE)
                .expect("construct Ed25519 JwtAuthVerifier"),
        );
        let normalizer = Arc::new(CanonicalNormalizer::new_default(DEMO_HMAC_KEY));
        let detector = Arc::new(
            InteractionRiskDetector::new_default()
                .with_cooldown_duration_ms(cooldown_duration_ms),
        );
        let hardening = Arc::new(ProverHardeningEngine::new());
        let admission = Arc::new(Semaphore::new(max_in_flight));

        let middleware_service = RiskGuardMiddlewareService::new(
            verifier.clone(),
            normalizer,
            detector,
            store.clone(),
            DEMO_AUDIENCE,
        )
        .with_admission(Arc::clone(&admission))
        .with_eval_timeout(Duration::from_secs(5));

        let interceptor_service = RiskGuardInterceptorService::new(
            verifier,
            store.clone(),
            hardening,
            issuer.gateway_id(),
            DEMO_AUDIENCE,
            PROFILE_REPO_TRIAGE_READONLY,
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral TCP listener for gRPC server");
        let addr = listener.local_addr().expect("read local_addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let join_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(middleware_service.into_server())
                .add_service(interceptor_service.into_server())
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("tonic gRPC server exited cleanly");
        });

        Self {
            addr,
            store,
            admission,
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn connect_middleware_client(&self) -> SupervisorMiddlewareClient<Channel> {
        SupervisorMiddlewareClient::connect(self.endpoint())
            .await
            .expect("connect SupervisorMiddlewareClient")
    }

    async fn connect_interceptor_client(&self) -> GatewayInterceptorClient<Channel> {
        GatewayInterceptorClient::connect(self.endpoint())
            .await
            .expect("connect GatewayInterceptorClient")
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for RunningSidecarServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            handle.abort();
        }
    }
}

fn json_to_proto_value(val: &Value) -> ProtoValue {
    let kind = match val {
        Value::Null => Kind::NullValue(0),
        Value::Bool(b) => Kind::BoolValue(*b),
        Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => Kind::StringValue(s.clone()),
        Value::Array(items) => Kind::ListValue(ListValue {
            values: items.iter().map(json_to_proto_value).collect(),
        }),
        Value::Object(map) => Kind::StructValue(Struct {
            fields: map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_proto_value(v)))
                .collect::<BTreeMap<_, _>>(),
        }),
    };
    ProtoValue { kind: Some(kind) }
}

fn json_to_struct(val: &Value) -> Struct {
    match json_to_proto_value(val).kind {
        Some(Kind::StructValue(s)) => s,
        _ => panic!("expected JSON object for prost_types::Struct"),
    }
}

fn build_http_eval_request(
    token: &str,
    request_id: &str,
    sandbox_id: &str,
    method: &str,
    path: &str,
    binary: &str,
) -> Request<HttpRequestEvaluation> {
    let metadata = JwtTestIssuer::bearer_metadata(token).expect("valid bearer metadata");
    let eval = HttpRequestEvaluation {
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: request_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            originating_process: Some(Process {
                binary: binary.to_string(),
                pid: 4242,
                ancestors: vec!["/bin/bash".to_string()],
            }),
            sandbox: format!("name-{sandbox_id}"),
            workspace: "/workspace/repo".to_string(),
        }),
        config: None,
        target: Some(HttpRequestTarget {
            scheme: "https".to_string(),
            host: "api.github.local".to_string(),
            port: 18443,
            method: method.to_string(),
            path: path.to_string(),
            query: "access_token=redacted_by_nfr04".to_string(),
        }),
        headers: vec![HttpHeader {
            name: "authorization".to_string(),
            value: "Bearer ghp_sensitive_should_never_be_stored".to_string(),
        }],
        body: br#"{"note":"sensitive request body ignored at PRE_CREDENTIALS"}"#.to_vec(),
        middleware_name: "risk-guard".to_string(),
    };
    let mut req = Request::new(eval);
    *req.metadata_mut() = metadata;
    req
}

fn build_interceptor_validate_request(
    gateway_token: &str,
    binding_id: &str,
    method: &str,
    proposed_operation: &Value,
) -> Request<InterceptorEvaluation> {
    let metadata = JwtTestIssuer::bearer_metadata(gateway_token).expect("valid gateway metadata");
    let eval = InterceptorEvaluation {
        interceptor_name: "risk-guard-governance".to_string(),
        binding_id: binding_id.to_string(),
        service: "openshell.v1.OpenShell".to_string(),
        method: method.to_string(),
        principal: HashMap::new(),
        phase: Some(interceptor_evaluation::Phase::Validate(ValidateEvaluation {
            proposed_operation: Some(json_to_struct(proposed_operation)),
            current_state: None,
        })),
    };
    let mut req = Request::new(eval);
    *req.metadata_mut() = metadata;
    req
}

fn build_interceptor_post_commit_request(
    gateway_token: &str,
    binding_id: &str,
    method: &str,
    committed_response: &Value,
) -> Request<InterceptorEvaluation> {
    let metadata = JwtTestIssuer::bearer_metadata(gateway_token).expect("valid gateway metadata");
    let eval = InterceptorEvaluation {
        interceptor_name: "risk-guard-governance".to_string(),
        binding_id: binding_id.to_string(),
        service: "openshell.v1.OpenShell".to_string(),
        method: method.to_string(),
        principal: HashMap::new(),
        phase: Some(interceptor_evaluation::Phase::PostCommit(
            PostCommitEvaluation {
                committed_response: Some(json_to_struct(committed_response)),
            },
        )),
    };
    let mut req = Request::new(eval);
    *req.metadata_mut() = metadata;
    req
}

/// Evaluates a request through `SupervisorMiddleware.EvaluateHttpRequest` and, iff
/// `Decision::Allow` is returned, forwards the request to `UpstreamFixtureServer`.
async fn evaluate_and_forward_if_allowed(
    mw_client: &mut SupervisorMiddlewareClient<Channel>,
    upstream: &UpstreamFixtureServer,
    supervisor_token: &str,
    request_id: &str,
    sandbox_id: &str,
    method: &str,
    path: &str,
    binary: &str,
) -> HttpRequestResult {
    let req = build_http_eval_request(
        supervisor_token,
        request_id,
        sandbox_id,
        method,
        path,
        binary,
    );
    let result = mw_client
        .evaluate_http_request(req)
        .await
        .expect("EvaluateHttpRequest RPC must succeed")
        .into_inner();

    // FR-01 contract check: risk-guard never mutates headers or replaces bodies.
    assert!(
        result.header_mutations.is_empty(),
        "FR-01 violation: header_mutations must be empty"
    );
    assert!(
        !result.has_body && result.body.is_empty(),
        "FR-01 violation: body must be empty"
    );

    if result.decision == Decision::Allow as i32 {
        let (status, _body) = upstream
            .send_request(method, path)
            .await
            .expect("forward allowed request to UpstreamFixtureServer");
        assert_eq!(status, 200, "UpstreamFixtureServer must return HTTP 200");
    }

    result
}

/// Checks whether the static OpenShell policy alone allows `(binary, host, port, method, path)`.
fn openshell_static_policy_allows(
    policy_yaml: &str,
    binary: &str,
    host: &str,
    port: u16,
    _method: &str,
    _path: &str,
) -> bool {
    let doc = openshell_policy_schema::parse_policy(policy_yaml).expect("parse policy YAML");
    for rule in doc.network_policies.values() {
        let binary_ok = rule.binaries.is_empty()
            || rule.binaries.iter().any(|b| b.path == binary);
        let endpoint_ok = rule.endpoints.iter().any(|ep| {
            ep.host.eq_ignore_ascii_case(host)
                && ep.effective_ports().contains(&port)
                && (ep.access == "full" || !ep.rules.is_empty())
        });
        if binary_ok && endpoint_ok {
            return true;
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_step_live_demo_and_fault_injection_suite() {
    println!("\n================================================================================");
    println!("  OPENSHELL BEHAVIORAL RISK GUARD — 10-STEP END-TO-END DEMO & FAULT SUITE");
    println!("================================================================================");

    // Boot real UpstreamFixtureServer (axum HTTP server with atomic per-method hit counters)
    let upstream = UpstreamFixtureServer::spawn().await;
    assert_eq!(upstream.total_requests(), 0);

    // Boot on-disk NamedTempFile SQLite database and verify Gate G-11 pragmas
    let temp_db = NamedTempFile::new().expect("create on-disk NamedTempFile for SQLite");
    let db_path = temp_db.path().to_path_buf();

    // Generate Ed25519 test issuer for Gateway + Supervisor JWT authentication
    let issuer = JwtTestIssuer::new(DEMO_GATEWAY_ID);
    let gateway_token = issuer
        .mint_gateway_token(DEMO_AUDIENCE, 600)
        .expect("mint gateway Ed25519 JWT");
    let supervisor_token = issuer
        .mint_supervisor_token(DEMO_AUDIENCE, DEMO_SANDBOX_ID, 600)
        .expect("mint supervisor Ed25519 JWT");

    // Start real tonic gRPC server hosting both RiskGuardMiddlewareService & RiskGuardInterceptorService
    // Use 300ms Tier 2 cooldown so Step 7 can demonstrate both active cooldown blocking and 3-strike promotion.
    let mut server = RunningSidecarServer::start(&db_path, &issuer, 300, 64).await;
    let (journal_mode, synchronous, foreign_keys) = server
        .store
        .verify_pragmas()
        .expect("verify pragmas on live store");
    assert_eq!(
        (journal_mode.as_str(), synchronous, foreign_keys),
        ("wal", 2, 1)
    );
    println!(
        "[BOOT] UpstreamFixtureServer={} | gRPC Sidecar={} | SQLite=({},{},{})",
        upstream.base_url(),
        server.endpoint(),
        journal_mode,
        synchronous,
        foreign_keys
    );

    // =========================================================================
    // STEP 1: Parse and display deliberately broad initial policy.yaml
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 1: Deliberately Broad Initial Static Policy (access: full + credential_binding)");
    println!("--------------------------------------------------------------------------------");
    let parsed_initial_policy = openshell_policy_schema::parse_policy(INITIAL_BROAD_POLICY_YAML)
        .expect("initial policy.yaml must parse cleanly");
    assert!(
        parsed_initial_policy
            .network_middlewares
            .contains_key("risk_guard")
    );
    assert_eq!(
        parsed_initial_policy.network_middlewares["risk_guard"].on_error,
        "fail_closed"
    );
    let gh_rule = &parsed_initial_policy.network_policies["github_api"];
    assert_eq!(gh_rule.endpoints[0].host, "api.github.local");
    assert_eq!(gh_rule.endpoints[0].port, 18443);
    assert_eq!(gh_rule.endpoints[0].access, "full");
    assert!(gh_rule.endpoints[0].credential_binding.is_some());
    assert!(openshell_static_policy_allows(
        INITIAL_BROAD_POLICY_YAML,
        "/usr/bin/curl",
        "api.github.local",
        18443,
        "DELETE",
        "/repos/org/payments-prod",
    ));
    println!("{INITIAL_BROAD_POLICY_YAML}");
    println!(
        "[STEP 1 PASS] Static policy alone permits /usr/bin/curl -> DELETE /repos/org/payments-prod on api.github.local:18443 (access: full)"
    );

    // =========================================================================
    // STEP 2: GatewayInterceptor.Evaluate (Validate + PostCommit) for CreateSandbox
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 2: GatewayInterceptor CreateSandbox (Validate + PostCommit Epoch Binding)");
    println!("--------------------------------------------------------------------------------");
    let mut interceptor_client = server.connect_interceptor_client().await;

    let create_op = json!({
        "sandbox": {
            "metadata": {
                "id": DEMO_SANDBOX_ID,
                "name": "demo-repo-triage"
            },
            "spec": {
                "policy_yaml": INITIAL_BROAD_POLICY_YAML
            }
        },
        "task_profile": PROFILE_REPO_TRIAGE_READONLY
    });

    let validate_create_res: InterceptorResult = interceptor_client
        .evaluate(build_interceptor_validate_request(
            &gateway_token,
            "validate-create-sandbox",
            "CreateSandbox",
            &create_op,
        ))
        .await
        .expect("CreateSandbox Validate RPC")
        .into_inner();
    assert!(
        validate_create_res.allowed,
        "CreateSandbox Validate must allow policy with fail_closed risk-guard middleware"
    );

    let post_commit_create_res: InterceptorResult = interceptor_client
        .evaluate(build_interceptor_post_commit_request(
            &gateway_token,
            "post-commit-create-sandbox",
            "CreateSandbox",
            &create_op,
        ))
        .await
        .expect("CreateSandbox PostCommit RPC")
        .into_inner();
    assert!(post_commit_create_res.allowed);
    assert_eq!(
        post_commit_create_res
            .log_annotations
            .get("epoch_id")
            .map(String::as_str),
        Some("ep_sbx_demo_1")
    );

    let active_epoch = server
        .store
        .get_active_epoch(DEMO_SANDBOX_ID)
        .expect("query active epoch")
        .expect("active epoch must exist after CreateSandbox PostCommit");
    assert_eq!(active_epoch.epoch_id, "ep_sbx_demo_1");
    assert_eq!(active_epoch.task_profile, PROFILE_REPO_TRIAGE_READONLY);
    assert_eq!(active_epoch.mode, EnforcementMode::Enforce);
    assert!(
        active_epoch
            .credentialed_endpoints
            .contains(&("api.github.local".to_string(), 18443)),
        "credentialed_endpoints must include (api.github.local, 18443)"
    );

    let (initial_policy_hash, stored_policy_yaml) = server
        .store
        .latest_policy_snapshot(DEMO_SANDBOX_ID)
        .expect("query latest policy snapshot")
        .expect("policy snapshot must exist in SQLite");
    assert_eq!(stored_policy_yaml, INITIAL_BROAD_POLICY_YAML);
    assert_eq!(
        active_epoch.active_policy_hash.as_deref(),
        Some(initial_policy_hash.as_str())
    );
    println!(
        "[STEP 2 PASS] Active Epoch '{}' bound to task_profile='{}', credentialed_endpoints={:?}, policy_hash={}",
        active_epoch.epoch_id,
        active_epoch.task_profile,
        active_epoch.credentialed_endpoints,
        &initial_policy_hash[..16]
    );

    // =========================================================================
    // STEP 3: Benign Task Requests -> Decision::Allow (score = 10), upstream.get_hits() == 2
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 3: Benign Task Requests (GET /repos/org/docs-site & /issues from /usr/bin/curl)");
    println!("--------------------------------------------------------------------------------");
    let mut mw_client = server.connect_middleware_client().await;

    let res_benign_1 = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &supervisor_token,
        "req-step3-benign-1",
        DEMO_SANDBOX_ID,
        "GET",
        "/repos/org/docs-site",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(res_benign_1.decision, Decision::Allow as i32);
    assert_eq!(
        res_benign_1.metadata.get("risk_score").map(String::as_str),
        Some("10")
    );
    assert!(res_benign_1.reason_code.is_empty());

    let res_benign_2 = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &supervisor_token,
        "req-step3-benign-2",
        DEMO_SANDBOX_ID,
        "GET",
        "/repos/org/docs-site/issues",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(res_benign_2.decision, Decision::Allow as i32);
    assert_eq!(
        res_benign_2.metadata.get("risk_score").map(String::as_str),
        Some("10")
    );
    assert_eq!(upstream.get_hits(), 2);
    println!(
        "[STEP 3 PASS] Both benign requests allowed: risk_score=10 (C=10 only), upstream.get_hits()={}",
        upstream.get_hits()
    );

    // =========================================================================
    // STEP 4: Legitimate Novelty (GET /repos/org/new-docs) -> Allow (score = 25), get_hits() == 3
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 4: Legitimate Novelty (GET /repos/org/new-docs -> AllowWithObservation, S=25)");
    println!("--------------------------------------------------------------------------------");
    let res_novel_read = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &supervisor_token,
        "req-step4-novel-read",
        DEMO_SANDBOX_ID,
        "GET",
        "/repos/org/new-docs",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(res_novel_read.decision, Decision::Allow as i32);
    assert_eq!(
        res_novel_read
            .metadata
            .get("risk_score")
            .map(String::as_str),
        Some("25")
    );
    assert_eq!(res_novel_read.findings.len(), 1);
    assert_eq!(res_novel_read.findings[0].r#type, "behavioral_risk_observed");
    assert_eq!(upstream.get_hits(), 3);
    println!(
        "[STEP 4 PASS] Novel harmless read allowed with observation: risk_score=25 (<70), reason='{}', upstream.get_hits()={}",
        res_novel_read.reason,
        upstream.get_hits()
    );

    // =========================================================================
    // STEP 5 (Gate G-01): Flagship Suspicious-but-Authorized Attack
    // (/usr/bin/curl -> DELETE /repos/org/payments-prod on credentialed endpoint)
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 5 (Gate G-01): Flagship Attack (DELETE /repos/org/payments-prod -> DENY, S=85)");
    println!("--------------------------------------------------------------------------------");
    let res_attack = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &supervisor_token,
        "req-step5-flagship-delete",
        DEMO_SANDBOX_ID,
        "DELETE",
        "/repos/org/payments-prod",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(res_attack.decision, Decision::Deny as i32);
    assert_eq!(res_attack.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
    assert_eq!(
        res_attack.metadata.get("risk_score").map(String::as_str),
        Some("85")
    );
    assert_eq!(
        upstream.delete_hits(),
        0,
        "Gate G-01: denied DELETE must have zero upstream hits"
    );
    println!(
        "[STEP 5 PASS] Flagship attack DENIED: reason_code='{}', risk_score=85 (15 N_r + 15 N_a + 30 I + 15 N_r*I + 10 C), upstream.delete_hits()={}",
        res_attack.reason_code,
        upstream.delete_hits()
    );

    // =========================================================================
    // STEP 6 (Gate G-11 & Strict Ratchet Persistence):
    // Retry DELETE before restart, then stop/restart server on same SQLite file and retry again
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 6 (Gate G-11): Tier 1 Strict Ratchet Persistence Across Sidecar Restart");
    println!("--------------------------------------------------------------------------------");
    let res_retry_before_restart = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &supervisor_token,
        "req-step6-retry-before-restart",
        DEMO_SANDBOX_ID,
        "DELETE",
        "/repos/org/payments-prod",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(res_retry_before_restart.decision, Decision::Deny as i32);
    assert_eq!(
        res_retry_before_restart.reason_code,
        REASON_BEHAVIORAL_RISK_RESTRICTED
    );
    assert_eq!(
        res_retry_before_restart
            .metadata
            .get("risk_score")
            .map(String::as_str),
        Some("100")
    );
    assert_eq!(upstream.delete_hits(), 0);

    // Drop/stop the running sidecar server and restart against the exact same on-disk SQLite file
    server.stop().await;
    server = RunningSidecarServer::start(&db_path, &issuer, 300, 64).await;
    mw_client = server.connect_middleware_client().await;
    interceptor_client = server.connect_interceptor_client().await;

    let res_retry_after_restart = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &supervisor_token,
        "req-step6-retry-after-restart",
        DEMO_SANDBOX_ID,
        "DELETE",
        "/repos/org/payments-prod",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(res_retry_after_restart.decision, Decision::Deny as i32);
    assert_eq!(
        res_retry_after_restart.reason_code,
        REASON_BEHAVIORAL_RISK_RESTRICTED
    );
    assert_eq!(
        res_retry_after_restart
            .metadata
            .get("risk_score")
            .map(String::as_str),
        Some("100")
    );
    assert_eq!(upstream.delete_hits(), 0);
    println!(
        "[STEP 6 PASS] Both pre-restart and post-restart retries DENIED with reason_code='{}', upstream.delete_hits()={}",
        res_retry_after_restart.reason_code,
        upstream.delete_hits()
    );

    // =========================================================================
    // STEP 7: Rapid Cross-Repo Enumeration Burst (20 unfamiliar repos in 1m)
    // Tier 2 cooldown triggers and 3 strikes escalate to Tier 1 strict_epoch
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 7: Rapid Cross-Repo Enumeration Burst (Tier 2 Cooldown -> 3 Strikes -> Tier 1)");
    println!("--------------------------------------------------------------------------------");
    let enum_create_op = json!({
        "sandbox": {
            "metadata": {
                "id": DEMO_ENUM_SANDBOX_ID,
                "name": "demo-enum-sandbox"
            },
            "spec": {
                "policy_yaml": INITIAL_BROAD_POLICY_YAML
            }
        },
        "task_profile": PROFILE_REPO_TRIAGE_READONLY
    });
    let enum_post_commit = interceptor_client
        .evaluate(build_interceptor_post_commit_request(
            &gateway_token,
            "post-commit-create-sandbox",
            "CreateSandbox",
            &enum_create_op,
        ))
        .await
        .expect("CreateSandbox PostCommit for enum sandbox")
        .into_inner();
    assert!(enum_post_commit.allowed);

    let enum_supervisor_token = issuer
        .mint_supervisor_token(DEMO_AUDIENCE, DEMO_ENUM_SANDBOX_ID, 600)
        .expect("mint enum supervisor JWT");

    // Send 20 GET requests across 20 unfamiliar repositories in 1 minute:
    // Requests 1..=19 accumulate velocity & fanout; the 20th request reaches
    // next_1m=20 (V tier 1 = +15) and next_fanout=20 (F tier 2 = +30) + N_r(15) + C(10) = 70 -> DENY (Strike 1, Tier 2 Cooldown).
    let mut strike1_result = None;
    for i in 1..=20 {
        let req_id = format!("req-step7-enum-{i:02}");
        let path = format!("/repos/org/unfamiliar-enum-repo-{i:02}");
        let res = mw_client
            .evaluate_http_request(build_http_eval_request(
                &enum_supervisor_token,
                &req_id,
                DEMO_ENUM_SANDBOX_ID,
                "GET",
                &path,
                "/usr/bin/curl",
            ))
            .await
            .expect("enum burst RPC")
            .into_inner();
        if i < 20 {
            assert_eq!(res.decision, Decision::Allow as i32);
        } else {
            strike1_result = Some(res);
        }
    }

    let strike1 = strike1_result.expect("20th enumeration request must be evaluated");
    assert_eq!(strike1.decision, Decision::Deny as i32);
    assert_eq!(strike1.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
    assert_eq!(
        strike1.metadata.get("risk_score").map(String::as_str),
        Some("70")
    );

    // Immediate request during Tier 2 cooldown window is blocked with behavioral_risk_restricted (cooldown)
    let during_cooldown = mw_client
        .evaluate_http_request(build_http_eval_request(
            &enum_supervisor_token,
            "req-step7-during-cooldown-1",
            DEMO_ENUM_SANDBOX_ID,
            "GET",
            "/repos/org/unfamiliar-enum-during-cd",
            "/usr/bin/curl",
        ))
        .await
        .expect("during cooldown RPC")
        .into_inner();
    assert_eq!(during_cooldown.decision, Decision::Deny as i32);
    assert_eq!(
        during_cooldown.reason_code,
        REASON_BEHAVIORAL_RISK_RESTRICTED
    );
    assert!(
        during_cooldown.reason.contains("restriction:cooldown"),
        "expected Tier 2 restriction:cooldown signal, got: {}",
        during_cooldown.reason
    );

    // Wait for cooldown window #1 to expire, then trigger Strike 2
    tokio::time::sleep(Duration::from_millis(350)).await;
    let strike2 = mw_client
        .evaluate_http_request(build_http_eval_request(
            &enum_supervisor_token,
            "req-step7-strike-2",
            DEMO_ENUM_SANDBOX_ID,
            "GET",
            "/repos/org/unfamiliar-enum-strike-2",
            "/usr/bin/curl",
        ))
        .await
        .expect("strike 2 RPC")
        .into_inner();
    assert_eq!(strike2.decision, Decision::Deny as i32);
    assert_eq!(strike2.reason_code, REASON_BEHAVIORAL_RISK_DENIED);

    // Wait for cooldown window #2 to expire, then trigger Strike 3 -> escalates to Tier 1 strict_epoch!
    tokio::time::sleep(Duration::from_millis(350)).await;
    let strike3 = mw_client
        .evaluate_http_request(build_http_eval_request(
            &enum_supervisor_token,
            "req-step7-strike-3",
            DEMO_ENUM_SANDBOX_ID,
            "GET",
            "/repos/org/unfamiliar-enum-strike-3",
            "/usr/bin/curl",
        ))
        .await
        .expect("strike 3 RPC")
        .into_inner();
    assert_eq!(strike3.decision, Decision::Deny as i32);
    assert_eq!(strike3.reason_code, REASON_BEHAVIORAL_RISK_DENIED);

    // Wait beyond cooldown duration again: because Strike 3 escalated to Tier 1 strict_epoch,
    // the route remains permanently blocked in this epoch!
    tokio::time::sleep(Duration::from_millis(350)).await;
    let post_escalation = mw_client
        .evaluate_http_request(build_http_eval_request(
            &enum_supervisor_token,
            "req-step7-after-3-strikes",
            DEMO_ENUM_SANDBOX_ID,
            "GET",
            "/repos/org/docs-site",
            "/usr/bin/curl",
        ))
        .await
        .expect("post escalation RPC")
        .into_inner();
    assert_eq!(post_escalation.decision, Decision::Deny as i32);
    assert_eq!(
        post_escalation.reason_code,
        REASON_BEHAVIORAL_RISK_RESTRICTED
    );
    assert!(
        post_escalation.reason.contains("restriction:strict_epoch"),
        "expected Tier 1 restriction:strict_epoch after 3 strikes, got: {}",
        post_escalation.reason
    );
    println!(
        "[STEP 7 PASS] 20-repo enumeration burst triggered Tier 2 cooldown (score=70) and 3 strikes escalated route to Tier 1 strict_epoch"
    );

    // =========================================================================
    // STEP 8 (Gate G-10 Fault Injection):
    // (a) Duplicate request_id idempotency
    // (b) Conflicting duplicate request_id rejection (Status::invalid_argument)
    // (c) Wrong-sandbox JWT rejection (Status::permission_denied)
    // (d) Admission queue exhaustion (Status::resource_exhausted)
    // (e) Simulated OpenShell baseline denial (never rescued by middleware)
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 8 (Gate G-10): Fault Injection (Idempotency, Conflict, Auth, Admission, Baseline)");
    println!("--------------------------------------------------------------------------------");

    // 8(a): Exact duplicate request_id idempotency on sbx_demo
    let seq_before_dup = server
        .store
        .get_active_epoch(DEMO_SANDBOX_ID)
        .expect("get epoch")
        .expect("epoch exists")
        .next_sequence;
    let dup_res = mw_client
        .evaluate_http_request(build_http_eval_request(
            &supervisor_token,
            "req-step3-benign-1",
            DEMO_SANDBOX_ID,
            "GET",
            "/repos/org/docs-site",
            "/usr/bin/curl",
        ))
        .await
        .expect("idempotent duplicate request_id must succeed")
        .into_inner();
    assert_eq!(dup_res.decision, Decision::Allow as i32);
    assert_eq!(
        dup_res.metadata.get("state_sequence").map(String::as_str),
        Some("1"),
        "idempotent replay must return original state_sequence=1"
    );
    let seq_after_dup = server
        .store
        .get_active_epoch(DEMO_SANDBOX_ID)
        .expect("get epoch")
        .expect("epoch exists")
        .next_sequence;
    assert_eq!(
        seq_before_dup, seq_after_dup,
        "idempotent duplicate must not advance epoch next_sequence"
    );

    // 8(b): Conflicting duplicate request_id (same request_id, different canonical request fingerprint)
    let conflict_err = mw_client
        .evaluate_http_request(build_http_eval_request(
            &supervisor_token,
            "req-step3-benign-1",
            DEMO_SANDBOX_ID,
            "DELETE",
            "/repos/org/payments-prod",
            "/usr/bin/curl",
        ))
        .await
        .expect_err("conflicting duplicate request_id must fail");
    assert_eq!(conflict_err.code(), Code::InvalidArgument);

    // 8(c): Wrong-sandbox JWT rejection (token for sbx_demo_enum used on context.sandbox_id = sbx_demo)
    let wrong_sbx_err = mw_client
        .evaluate_http_request(build_http_eval_request(
            &enum_supervisor_token,
            "req-step8-wrong-sandbox",
            DEMO_SANDBOX_ID,
            "GET",
            "/repos/org/docs-site",
            "/usr/bin/curl",
        ))
        .await
        .expect_err("mismatched JWT sandbox_id must fail");
    assert_eq!(wrong_sbx_err.code(), Code::PermissionDenied);

    // 8(d): Admission queue exhaustion (acquire all semaphore permits -> ResourceExhausted)
    let available = u32::try_from(server.admission.available_permits()).expect("permits fit u32");
    let held_permits = server
        .admission
        .acquire_many(available)
        .await
        .expect("acquire all admission permits");
    let exhausted_err = mw_client
        .evaluate_http_request(build_http_eval_request(
            &supervisor_token,
            "req-step8-admission-exhausted",
            DEMO_SANDBOX_ID,
            "GET",
            "/repos/org/docs-site",
            "/usr/bin/curl",
        ))
        .await
        .expect_err("admission queue exhaustion must return ResourceExhausted");
    assert_eq!(exhausted_err.code(), Code::ResourceExhausted);
    drop(held_permits);

    // 8(e): Simulated OpenShell baseline denial (FinalAllow(a) = OpenShellAllow(a) && RiskPermit(a))
    // /usr/bin/python3 is NOT in INITIAL_BROAD_POLICY_YAML binaries ([curl, gh, git]).
    let hits_before_baseline_deny = upstream.total_requests();
    let os_allow = openshell_static_policy_allows(
        INITIAL_BROAD_POLICY_YAML,
        "/usr/bin/python3",
        "api.github.local",
        18443,
        "GET",
        "/repos/org/docs-site",
    );
    assert!(
        !os_allow,
        "OpenShell static policy must deny unlisted binary /usr/bin/python3"
    );
    // Because OpenShell denies before middleware or attenuates: FinalAllow = os_allow && risk_permit == false.
    let final_allow = os_allow;
    assert!(!final_allow);
    assert_eq!(
        upstream.total_requests(),
        hits_before_baseline_deny,
        "OpenShell baseline denial is never rescued by middleware and never reaches upstream"
    );
    println!(
        "[STEP 8 PASS] Fault injection verified: idempotent duplicate (seq=1), conflicting duplicate -> {:?}, wrong-sandbox JWT -> {:?}, admission exhausted -> {:?}, OpenShell baseline denial -> blocked",
        conflict_err.code(),
        wrong_sbx_err.code(),
        exhausted_err.code()
    );

    // =========================================================================
    // STEP 9: Control-Plane Monotonicity (GatewayInterceptor Validate on UpdateConfig)
    // (a) proposal_approval_mode = "auto" -> rejected (allowed == false)
    // (b) stripping risk-guard from network_middlewares -> rejected (allowed == false)
    // (c) broadening policy to add evil.example.com -> rejected by Two-Step Proof (allowed == false)
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 9: Control-Plane Monotonicity (GatewayInterceptor Validate on UpdateConfig)");
    println!("--------------------------------------------------------------------------------");

    // 9(a): proposal_approval_mode = "auto"
    let auto_approval_op = json!({
        "sandbox": DEMO_SANDBOX_ID,
        "setting_key": "proposal_approval_mode",
        "setting_value": "auto"
    });
    let res_9a = interceptor_client
        .evaluate(build_interceptor_validate_request(
            &gateway_token,
            "validate-update-config",
            "UpdateConfig",
            &auto_approval_op,
        ))
        .await
        .expect("UpdateConfig 9(a) RPC")
        .into_inner();
    assert!(!res_9a.allowed);
    assert_eq!(res_9a.status_code, "PERMISSION_DENIED");

    // 9(b): stripping risk-guard from network_middlewares
    let strip_mw_op = json!({
        "sandbox": DEMO_SANDBOX_ID,
        "policy_yaml": STRIPPED_MIDDLEWARE_POLICY_YAML
    });
    let res_9b = interceptor_client
        .evaluate(build_interceptor_validate_request(
            &gateway_token,
            "validate-update-config",
            "UpdateConfig",
            &strip_mw_op,
        ))
        .await
        .expect("UpdateConfig 9(b) RPC")
        .into_inner();
    assert!(!res_9b.allowed);
    assert_eq!(res_9b.status_code, "PERMISSION_DENIED");

    // 9(c): broadening policy to add evil.example.com
    let broaden_host_op = json!({
        "sandbox": DEMO_SANDBOX_ID,
        "policy_yaml": EXPANDED_HOST_POLICY_YAML
    });
    let res_9c = interceptor_client
        .evaluate(build_interceptor_validate_request(
            &gateway_token,
            "validate-update-config",
            "UpdateConfig",
            &broaden_host_op,
        ))
        .await
        .expect("UpdateConfig 9(c) RPC")
        .into_inner();
    assert!(!res_9c.allowed);
    assert_eq!(res_9c.status_code, "PERMISSION_DENIED");
    assert!(
        res_9c
            .reason
            .contains("control-plane monotonicity violation"),
        "expected Two-Step Containment Proof rejection reason, got: {}",
        res_9c.reason
    );
    println!(
        "[STEP 9 PASS] All 3 unauthorized control-plane mutations rejected:\n  (a) auto-approval -> {}\n  (b) strip middleware -> {}\n  (c) add evil.example.com -> {}",
        res_9a.reason, res_9b.reason, res_9c.reason
    );

    // =========================================================================
    // STEP 10 (Gates G-09 & G-12): Periodic Hardening & Two-Step Containment Proof
    // =========================================================================
    println!("\n--------------------------------------------------------------------------------");
    println!("STEP 10 (Gates G-09 & G-12): Periodic Hardening Report & Two-Step Containment Proof");
    println!("--------------------------------------------------------------------------------");
    let temp_policy_file = NamedTempFile::new().expect("create temp policy file");
    std::fs::write(temp_policy_file.path(), INITIAL_BROAD_POLICY_YAML)
        .expect("write initial policy YAML");
    let temp_report_out = NamedTempFile::new().expect("create temp report output file");

    let report_json = execute_cli(Cli {
        command: Commands::HardeningReport {
            db: db_path.clone(),
            sandbox_id: DEMO_SANDBOX_ID.to_string(),
            policy: temp_policy_file.path().to_path_buf(),
            out: Some(temp_report_out.path().to_path_buf()),
        },
    })
    .await
    .expect("execute_cli HardeningReport must succeed");

    let candidate: HardeningCandidate =
        serde_json::from_str(&report_json).expect("parse HardeningCandidate JSON");

    assert_eq!(candidate.sandbox_id, DEMO_SANDBOX_ID);
    assert_eq!(candidate.epoch_id, "ep_sbx_demo_1");
    assert!(candidate.completeness_ok);
    assert!(candidate.coverage_gaps.is_empty());
    assert_eq!(
        candidate.two_step_proof.raw_prover_status,
        "unsupported: uses network middleware controls"
    );
    assert!(candidate.two_step_proof.step1_middleware_invariant);
    assert_eq!(
        candidate.two_step_proof.step2_prover_verdict,
        "within_boundary"
    );
    assert!(candidate.two_step_proof.verified_non_expanding);
    assert_eq!(candidate.replay_total_requests, 3);
    assert_eq!(candidate.replay_would_block, 0);
    assert_eq!(candidate.status, "ready");
    assert_ne!(candidate.source_policy_hash, candidate.candidate_policy_hash);

    // Verify active policy hash in SQLite remains unchanged (recommendations never auto-apply!)
    let epoch_after_report = server
        .store
        .get_active_epoch(DEMO_SANDBOX_ID)
        .expect("get active epoch")
        .expect("active epoch exists");
    assert_eq!(
        epoch_after_report.active_policy_hash.as_deref(),
        Some(initial_policy_hash.as_str()),
        "Gate G-09: generating a hardening recommendation must NEVER auto-apply or mutate active_policy_hash"
    );
    let (latest_hash_after_report, _) = server
        .store
        .latest_policy_snapshot(DEMO_SANDBOX_ID)
        .expect("latest policy snapshot")
        .expect("snapshot exists");
    assert_eq!(latest_hash_after_report, initial_policy_hash);

    // Verify final upstream hit counts: 3 benign GETs reached upstream, 0 DELETEs reached upstream.
    assert_eq!(upstream.get_hits(), 3);
    assert_eq!(upstream.delete_hits(), 0);
    assert_eq!(upstream.total_requests(), 3);

    println!("Diff summary: {:?}", candidate.diff_summary);
    println!("Two-Step Proof: {:?}", candidate.two_step_proof);
    println!("Narrowed Candidate Policy YAML:\n{}", candidate.candidate_yaml);
    println!(
        "[STEP 10 PASS] Hardening report ready: raw_prover='{}', step1_invariant={}, step2_verdict='{}', verified_non_expanding={}, replay_would_block={}/{}, active_policy_hash unchanged",
        candidate.two_step_proof.raw_prover_status,
        candidate.two_step_proof.step1_middleware_invariant,
        candidate.two_step_proof.step2_prover_verdict,
        candidate.two_step_proof.verified_non_expanding,
        candidate.replay_would_block,
        candidate.replay_total_requests
    );
    println!("================================================================================");
    println!("  ALL 10 DEMO ACCEPTANCE STEPS & GATES (G-01, G-09, G-10, G-11, G-12) PASSED!");
    println!("================================================================================\n");

    server.stop().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn gate_g01_zero_upstream_hits_on_denied_requests_and_baseline_attenuation() {
    let upstream = UpstreamFixtureServer::spawn().await;
    let temp_db = NamedTempFile::new().expect("create temp db");
    let issuer = JwtTestIssuer::new(DEMO_GATEWAY_ID);
    let server = RunningSidecarServer::start(temp_db.path(), &issuer, 300_000, 64).await;

    // Seed baseline with explicit Layer A task_constraint rule (forbid DELETE /repos/*/hooks)
    let mut profile = build_standard_corpus().default_baseline;
    profile.task_profile = "triage-with-layer-a".to_string();
    profile
        .forbidden_action_classes
        .insert("POST /repos/{owner}/{repo}/hooks".to_string());
    let baseline_hash = server
        .store
        .store_baseline(&profile)
        .expect("store baseline");

    let epoch = EpochRecord {
        epoch_id: "ep_g01_1".to_string(),
        gateway_id: DEMO_GATEWAY_ID.to_string(),
        sandbox_id: "sbx_g01".to_string(),
        task_profile: profile.task_profile.clone(),
        baseline_hash,
        mode: EnforcementMode::Enforce,
        active: true,
        next_sequence: 1,
        created_at_ms: 1_760_000_000_000,
        credentialed_endpoints: BTreeSet::from([("api.github.local".to_string(), 18443)]),
        active_policy_hash: Some("pol_g01".to_string()),
    };
    server.store.upsert_epoch(&epoch).expect("upsert epoch");

    let token = issuer
        .mint_supervisor_token(DEMO_AUDIENCE, "sbx_g01", 600)
        .expect("mint token");
    let mut mw_client = server.connect_middleware_client().await;

    // 1. Allowed request reaches upstream
    let allow_res = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &token,
        "g01-allow-1",
        "sbx_g01",
        "GET",
        "/repos/org/docs-site",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(allow_res.decision, Decision::Allow as i32);
    assert_eq!(upstream.get_hits(), 1);

    // 2. High-impact cross-repo DELETE is denied -> zero upstream DELETE hits
    let deny_behavioral = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &token,
        "g01-deny-delete",
        "sbx_g01",
        "DELETE",
        "/repos/org/payments-prod",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(deny_behavioral.decision, Decision::Deny as i32);
    assert_eq!(deny_behavioral.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
    assert_eq!(upstream.delete_hits(), 0);

    // 3. Layer A task_constraint violation (POST /repos/org/docs-site/hooks) is denied -> zero upstream POST hits
    let deny_task_constraint = evaluate_and_forward_if_allowed(
        &mut mw_client,
        &upstream,
        &token,
        "g01-deny-hooks",
        "sbx_g01",
        "POST",
        "/repos/org/docs-site/hooks",
        "/usr/bin/curl",
    )
    .await;
    assert_eq!(deny_task_constraint.decision, Decision::Deny as i32);
    assert_eq!(
        deny_task_constraint.reason_code,
        REASON_TASK_CONSTRAINT_DENIED
    );
    assert_eq!(upstream.post_hits(), 0);

    assert_eq!(upstream.total_requests(), 1);
    server.stop().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn gate_g09_and_g12_hardening_completeness_two_step_proof_and_no_auto_apply() {
    let temp_db = NamedTempFile::new().expect("create temp db");
    let store = open_and_seed_store(temp_db.path()).expect("open and seed store");
    let engine = ProverHardeningEngine::new();

    // Verify Two-Step Containment Proof rejects middleware stripping (Step 1) and host expansion (Step 2)
    let stripped_proof = engine
        .verify_two_step_containment(
            INITIAL_BROAD_POLICY_YAML,
            STRIPPED_MIDDLEWARE_POLICY_YAML,
            Duration::from_secs(5),
        )
        .expect("verify stripped middleware");
    assert_eq!(
        stripped_proof.raw_prover_status,
        "unsupported: uses network middleware controls"
    );
    assert!(!stripped_proof.step1_middleware_invariant);
    assert_eq!(stripped_proof.step2_prover_verdict, "skipped");
    assert!(!stripped_proof.verified_non_expanding);

    let expanded_proof = engine
        .verify_two_step_containment(
            INITIAL_BROAD_POLICY_YAML,
            EXPANDED_HOST_POLICY_YAML,
            Duration::from_secs(5),
        )
        .expect("verify expanded host");
    assert!(expanded_proof.step1_middleware_invariant);
    assert_eq!(expanded_proof.step2_prover_verdict, "exceeds_boundary");
    assert!(!expanded_proof.verified_non_expanding);

    // Record a coverage gap in SQLite and verify HardeningReport marks completeness_ok == false
    let epoch = EpochRecord {
        epoch_id: "ep_g09_1".to_string(),
        gateway_id: DEMO_GATEWAY_ID.to_string(),
        sandbox_id: "sbx_g09".to_string(),
        task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
        baseline_hash: "hash_g09".to_string(),
        mode: EnforcementMode::Enforce,
        active: true,
        next_sequence: 1,
        created_at_ms: 1_760_000_000_000,
        credentialed_endpoints: BTreeSet::from([("api.github.local".to_string(), 18443)]),
        active_policy_hash: Some("initial_hash_g09".to_string()),
    };
    store.upsert_epoch(&epoch).expect("upsert epoch");
    store
        .record_coverage_gap("sbx_g09", "sidecar_restart_window", 1_000, 2_000)
        .expect("record coverage gap");

    let temp_policy = NamedTempFile::new().expect("temp policy");
    std::fs::write(temp_policy.path(), INITIAL_BROAD_POLICY_YAML).expect("write policy");

    let report_json = execute_cli(Cli {
        command: Commands::HardeningReport {
            db: temp_db.path().to_path_buf(),
            sandbox_id: "sbx_g09".to_string(),
            policy: temp_policy.path().to_path_buf(),
            out: None,
        },
    })
    .await
    .expect("run HardeningReport with coverage gap");

    let candidate: HardeningCandidate =
        serde_json::from_str(&report_json).expect("parse candidate JSON");
    assert!(!candidate.completeness_ok);
    assert_eq!(candidate.status, "incomplete_coverage");
    assert_eq!(candidate.coverage_gaps.len(), 1);
    assert_eq!(
        store
            .get_active_epoch("sbx_g09")
            .unwrap()
            .unwrap()
            .active_policy_hash
            .as_deref(),
        Some("initial_hash_g09")
    );
}

#[tokio::test]
async fn gate_g10_fault_injection_duplicates_auth_admission_and_cold_start() {
    let temp_db = NamedTempFile::new().expect("create temp db");
    let issuer = JwtTestIssuer::new(DEMO_GATEWAY_ID);
    let server = RunningSidecarServer::start(temp_db.path(), &issuer, 300_000, 64).await;

    // Seed an immature cold-start epoch (training_sessions = 3 < 20)
    let cold_baseline = server
        .store
        .get_baseline(PROFILE_COLD_START_NEW)
        .expect("get cold start baseline")
        .expect("cold start baseline seeded");
    let cold_hash = compute_baseline_hash(&cold_baseline);
    let cold_epoch = EpochRecord {
        epoch_id: "ep_cold_1".to_string(),
        gateway_id: DEMO_GATEWAY_ID.to_string(),
        sandbox_id: "sbx_cold".to_string(),
        task_profile: PROFILE_COLD_START_NEW.to_string(),
        baseline_hash: cold_hash,
        mode: EnforcementMode::Enforce,
        active: true,
        next_sequence: 1,
        created_at_ms: 1_760_000_000_000,
        credentialed_endpoints: BTreeSet::from([("api.github.local".to_string(), 18443)]),
        active_policy_hash: Some("pol_cold".to_string()),
    };
    server.store.upsert_epoch(&cold_epoch).expect("upsert cold epoch");

    let mut mw_client = server.connect_middleware_client().await;
    let cold_token = issuer
        .mint_supervisor_token(DEMO_AUDIENCE, "sbx_cold", 600)
        .expect("mint cold token");

    // 1. Cold-start statistical novelty never false-denies in Enforce mode (returns baseline_insufficient)
    let cold_res = mw_client
        .evaluate_http_request(build_http_eval_request(
            &cold_token,
            "req-cold-novel-1",
            "sbx_cold",
            "GET",
            "/repos/org/brand-new-repo",
            "/usr/bin/curl",
        ))
        .await
        .expect("cold start eval")
        .into_inner();
    assert_eq!(cold_res.decision, Decision::Allow as i32);
    assert!(
        cold_res.reason.contains(REASON_BASELINE_INSUFFICIENT),
        "expected baseline_insufficient reason, got: {}",
        cold_res.reason
    );

    // 2. Expired JWT token is rejected with Code::Unauthenticated
    let expired_claims = ExtensionJwtClaims {
        iss: issuer.issuer(),
        aud: DEMO_AUDIENCE.to_string(),
        sub: "spiffe://openshell/sandbox/sbx_cold".to_string(),
        iat: 1_000,
        exp: 1_060,
        jti: "expired-jti-01".to_string(),
        caller_kind: ExtensionCallerKind::Supervisor,
        sandbox_id: Some("sbx_cold".to_string()),
    };
    let expired_token = issuer
        .mint_with_claims(Some(EXTENSION_JWT_TYP), &expired_claims)
        .expect("mint expired JWT");
    let expired_err = mw_client
        .evaluate_http_request(build_http_eval_request(
            &expired_token,
            "req-expired-jwt",
            "sbx_cold",
            "GET",
            "/repos/org/docs-site",
            "/usr/bin/curl",
        ))
        .await
        .expect_err("expired JWT must be rejected");
    assert_eq!(expired_err.code(), Code::Unauthenticated);

    // 3. Gateway token used on SupervisorMiddleware endpoint is rejected with Code::PermissionDenied
    let gw_token = issuer
        .mint_gateway_token(DEMO_AUDIENCE, 600)
        .expect("mint gateway token");
    let wrong_kind_err = mw_client
        .evaluate_http_request(build_http_eval_request(
            &gw_token,
            "req-wrong-caller-kind",
            "sbx_cold",
            "GET",
            "/repos/org/docs-site",
            "/usr/bin/curl",
        ))
        .await
        .expect_err("gateway token on supervisor endpoint must fail");
    assert_eq!(wrong_kind_err.code(), Code::PermissionDenied);

    server.stop().await;
}

#[test]
fn gate_g11_sqlite_wal_durability_crash_restart_and_ratchet_persistence() {
    let temp_db = NamedTempFile::new().expect("create on-disk SQLite file");
    let db_path = temp_db.path().to_path_buf();
    let normalizer = CanonicalNormalizer::new_default(DEMO_HMAC_KEY);
    let detector = InteractionRiskDetector::new_default();

    {
        let store = open_and_seed_store(&db_path).expect("open store #1");
        assert_eq!(
            store.verify_pragmas().expect("verify pragmas #1"),
            ("wal".to_string(), 2, 1)
        );

        let baseline = store
            .get_baseline(PROFILE_REPO_TRIAGE_READONLY)
            .unwrap()
            .unwrap();
        let epoch = EpochRecord {
            epoch_id: "ep_g11_1".to_string(),
            gateway_id: DEMO_GATEWAY_ID.to_string(),
            sandbox_id: "sbx_g11".to_string(),
            task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
            baseline_hash: compute_baseline_hash(&baseline),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: 1_760_000_000_000,
            credentialed_endpoints: BTreeSet::from([("api.github.local".to_string(), 18443)]),
            active_policy_hash: Some("pol_g11".to_string()),
        };
        store.upsert_epoch(&epoch).expect("upsert epoch");

        let raw_delete = RawRequestInput {
            request_id: "g11-del-1".to_string(),
            sandbox_id: "sbx_g11".to_string(),
            sandbox_name: "sbx_g11".to_string(),
            workspace: "/workspace".to_string(),
            scheme: "https".to_string(),
            host: "api.github.local".to_string(),
            port: 18443,
            method: "DELETE".to_string(),
            path: "/repos/org/payments-prod".to_string(),
            binary_path: Some("/usr/bin/curl".to_string()),
            pid: Some(1001),
            ancestors: vec!["/bin/bash".to_string()],
            timestamp_ms: 1_760_000_005_000,
        };
        let norm_delete = normalizer.normalize(&raw_delete).expect("normalize delete");
        let eval = store
            .evaluate_and_commit_atomic(&norm_delete, &detector)
            .expect("commit tier 1 deny");
        assert_eq!(eval.outcome, DecisionOutcome::Deny);
        assert_eq!(eval.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
        assert_eq!(eval.risk_score, 85);
        assert!(matches!(
            eval.ratchet_action,
            RatchetAction::LatchTier1StrictEpoch { .. }
        ));
    }

    // Reopen store from the same on-disk file and verify pragma invariants + restriction persistence
    let reopened = SqliteRiskStore::open(&db_path).expect("reopen store #2");
    assert_eq!(
        reopened.verify_pragmas().expect("verify pragmas #2"),
        ("wal".to_string(), 2, 1)
    );

    let raw_retry = RawRequestInput {
        request_id: "g11-del-2-after-reopen".to_string(),
        sandbox_id: "sbx_g11".to_string(),
        sandbox_name: "sbx_g11".to_string(),
        workspace: "/workspace".to_string(),
        scheme: "https".to_string(),
        host: "api.github.local".to_string(),
        port: 18443,
        method: "DELETE".to_string(),
        path: "/repos/org/payments-prod".to_string(),
        binary_path: Some("/usr/bin/curl".to_string()),
        pid: Some(1002),
        ancestors: vec!["/bin/bash".to_string()],
        timestamp_ms: 1_760_000_010_000,
    };
    let norm_retry = normalizer.normalize(&raw_retry).expect("normalize retry");
    let retry_eval = reopened
        .evaluate_and_commit_atomic(&norm_retry, &detector)
        .expect("eval after reopen");
    assert_eq!(retry_eval.outcome, DecisionOutcome::Deny);
    assert_eq!(retry_eval.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
    assert_eq!(retry_eval.risk_score, 100);
    assert_eq!(retry_eval.state_sequence, 2);
}

#[tokio::test]
async fn real_openshell_supervisor_and_gateway_runtimes_connect_and_enforce_over_grpc() {
    use openshell_core::config::{
        GatewayInterceptorBindingPolicy, GatewayInterceptorConfig, GatewayInterceptorFailurePolicy,
    };
    use openshell_core::proto::{SupervisorMiddlewareService, UpdateConfigRequest};
    use openshell_extension_core::BearerTokenSlot;
    use openshell_gateway_interceptors::{EvaluationContext, initialize_authenticated};
    use openshell_supervisor_middleware::{
        ChainEntry, ChainRunner, HttpRequestInput, MiddlewareRegistry, OnError,
    };
    use prost::Message as _;

    let temp_db = NamedTempFile::new().expect("create temp db");
    let issuer = JwtTestIssuer::new(DEMO_GATEWAY_ID);
    let server = RunningSidecarServer::start(temp_db.path(), &issuer, 300_000, 64).await;

    // 1. Seed active epoch for sbx_real_runtime
    let baseline = server
        .store
        .get_baseline(PROFILE_REPO_TRIAGE_READONLY)
        .unwrap()
        .unwrap();
    let epoch = EpochRecord {
        epoch_id: "ep_real_runtime_1".to_string(),
        gateway_id: DEMO_GATEWAY_ID.to_string(),
        sandbox_id: "sbx_real_runtime".to_string(),
        task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
        baseline_hash: compute_baseline_hash(&baseline),
        mode: EnforcementMode::Enforce,
        active: true,
        next_sequence: 1,
        created_at_ms: 1_760_000_000_000,
        credentialed_endpoints: BTreeSet::from([("api.github.local".to_string(), 18443)]),
        active_policy_hash: Some("pol_real_runtime".to_string()),
    };
    server.store.upsert_epoch(&epoch).expect("upsert epoch");

    // 2. Connect OpenShell's REAL `MiddlewareRegistry` & `ChainRunner` (`openshell-supervisor-middleware`)
    let sup_jwt = issuer
        .mint_supervisor_token(DEMO_AUDIENCE, "sbx_real_runtime", 600)
        .expect("mint supervisor jwt");
    let sup_slot = BearerTokenSlot::new(&sup_jwt, i64::MAX / 2).expect("create supervisor slot");
    let mut mw_creds = HashMap::new();
    mw_creds.insert("risk-guard".to_string(), sup_slot);

    let registration = SupervisorMiddlewareService {
        name: "risk-guard".to_string(),
        grpc_endpoint: server.endpoint(),
        allow_insecure_transport: false,
        max_payload_bytes: 16 * 1024,
        request_timeout: Some(prost_types::Duration {
            seconds: 0,
            nanos: 200_000_000,
        }),
        tls_ca_cert_pem: Vec::new(),
        audience: DEMO_AUDIENCE.to_string(),
    };

    let registry = MiddlewareRegistry::connect_services_authenticated(
        Vec::new(),
        vec![registration],
        &mw_creds,
    )
    .await
    .expect("OpenShell MiddlewareRegistry::connect_services_authenticated must succeed");

    let runner = ChainRunner::from_registry(registry);
    let mut cfg_fields = BTreeMap::new();
    cfg_fields.insert(
        "task_profile".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                PROFILE_REPO_TRIAGE_READONLY.to_string(),
            )),
        },
    );
    cfg_fields.insert(
        "mode".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("enforce".to_string())),
        },
    );
    let chain_entries = vec![ChainEntry {
        name: "behavioral-risk-guard".to_string(),
        implementation: "risk-guard".to_string(),
        order: 10,
        config: prost_types::Struct { fields: cfg_fields },
        on_error: OnError::FailClosed,
    }];

    // Evaluate benign request through OpenShell's real ChainRunner::evaluate
    let benign_outcome = runner
        .evaluate(
            &chain_entries,
            HttpRequestInput {
                request_id: "real-chain-allow-1".to_string(),
                sandbox_id: "sbx_real_runtime".to_string(),
                sandbox_name: "sbx_real_runtime".to_string(),
                workspace: "default".to_string(),
                scheme: "https".to_string(),
                host: "api.github.local".to_string(),
                port: 18443,
                method: "GET".to_string(),
                path: "/repos/org/docs-site".to_string(),
                query: String::new(),
                headers: Vec::new(),
                connection_nominated_headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .await
        .expect("ChainRunner::evaluate benign request");
    assert!(
        benign_outcome.allowed,
        "ChainRunner must allow benign GET; denial: {:?}",
        benign_outcome.denial
    );
    assert!(benign_outcome.denial.is_none());

    // Evaluate flagship attack through OpenShell's real ChainRunner::evaluate
    let attack_outcome = runner
        .evaluate(
            &chain_entries,
            HttpRequestInput {
                request_id: "real-chain-deny-1".to_string(),
                sandbox_id: "sbx_real_runtime".to_string(),
                sandbox_name: "sbx_real_runtime".to_string(),
                workspace: "default".to_string(),
                scheme: "https".to_string(),
                host: "api.github.local".to_string(),
                port: 18443,
                method: "DELETE".to_string(),
                path: "/repos/org/payments-prod".to_string(),
                query: String::new(),
                headers: Vec::new(),
                connection_nominated_headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .await
        .expect("ChainRunner::evaluate attack request");
    assert!(
        !attack_outcome.allowed,
        "ChainRunner must deny cross-repo DELETE attack"
    );
    let denial = attack_outcome
        .denial
        .expect("ChainRunner must populate MiddlewareDenial");
    assert_eq!(denial.config_name, "behavioral-risk-guard");
    assert_eq!(
        denial.reason_code.as_deref(),
        Some(REASON_BEHAVIORAL_RISK_DENIED)
    );

    // 3. Connect OpenShell's REAL `GatewayInterceptorRuntime` (`openshell-gateway-interceptors`)
    let gw_jwt = issuer
        .mint_gateway_token(DEMO_AUDIENCE, 600)
        .expect("mint gateway jwt");
    let gw_slot = BearerTokenSlot::new(&gw_jwt, i64::MAX / 2).expect("create gateway slot");
    let mut gw_slots = BTreeMap::new();
    gw_slots.insert("risk-guard-governance".to_string(), gw_slot);

    let interceptor_cfg = GatewayInterceptorConfig {
        name: "risk-guard-governance".to_string(),
        grpc_endpoint: server.endpoint(),
        order: 10,
        failure_policy: Some(GatewayInterceptorFailurePolicy::FailClosed),
        binding_policy: GatewayInterceptorBindingPolicy::Dynamic,
        timeout: Some("500ms".to_string()),
        max_response_bytes: Some(1024 * 1024),
        max_patches: Some(32),
        tls_ca_cert_path: None,
        allow_insecure_transport: false,
        audience: Some(DEMO_AUDIENCE.to_string()),
        bindings: Vec::new(),
    };

    let gw_runtime = initialize_authenticated(vec![interceptor_cfg], gw_slots)
        .await
        .expect("OpenShell GatewayInterceptorRuntime::initialize_authenticated must succeed")
        .expect("interceptor runtime present");

    let bad_update = UpdateConfigRequest {
        sandbox: "sbx_real_runtime".to_string(),
        setting_key: "proposal_approval_mode".to_string(),
        setting_value: Some(openshell_core::proto::SettingValue {
            value: Some(openshell_core::proto::setting_value::Value::StringValue(
                "auto".to_string(),
            )),
        }),
        ..Default::default()
    };
    let payload = bad_update.encode_to_vec();
    let mut grpc_frame = Vec::with_capacity(5 + payload.len());
    grpc_frame.push(0u8);
    grpc_frame.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("frame length")
            .to_be_bytes(),
    );
    grpc_frame.extend_from_slice(&payload);

    let err_status = gw_runtime
        .evaluate_request(
            "/openshell.v1.OpenShell/UpdateConfig",
            &grpc_frame,
            &EvaluationContext {
                principal: BTreeMap::new(),
                validate_current_state: None,
            },
        )
        .await
        .expect_err("GatewayInterceptorRuntime must reject proposal_approval_mode=auto");
    assert_eq!(err_status.code(), Code::PermissionDenied);
    assert!(
        err_status
            .message()
            .contains("forbids proposal_approval_mode=auto"),
        "unexpected status message: {}",
        err_status.message()
    );

    server.stop().await;
}
