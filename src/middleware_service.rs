// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! `SupervisorMiddleware` gRPC service (Wave 2 - `t06-middleware-grpc`).

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, validate_gateway_metadata,
};
use openshell_core::middleware::WebSocketResponseStream;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, Finding, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
    MiddlewareDescribeRequest, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse,
    WebSocketSessionEvent,
};
use prost_types::Struct;
use prost_types::value::Kind;
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

use crate::error::RiskGuardError;
use crate::types::{
    AuthVerifier, DecisionOutcome, EnforcementMode, REASON_RISK_STATE_UNAVAILABLE, RawRequestInput,
    RequestNormalizer, RiskDetector, RiskEvaluation, RiskStore,
};

/// Canonical manifest and extension name for the behavioral risk guard middleware.
pub const MIDDLEWARE_MANIFEST_NAME: &str = "openshell/behavioral-risk-guard";

/// Default maximum concurrent in-flight HTTP request evaluations.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// Default per-evaluation store + detector timeout in milliseconds.
pub const DEFAULT_EVAL_TIMEOUT_MS: u64 = 100;

/// Maximum payload bytes advertised by `openshell/behavioral-risk-guard`: the 4 MiB platform maximum. Risk Guard never
/// uses bodies, but OpenShell delivers them and treats an oversized payload as a middleware failure (which blocks under
/// `on_error: fail_closed`), so a smaller limit would deny legitimate large requests just for their size.
pub const MAX_PAYLOAD_BYTES: u64 = 4 * 1024 * 1024;

/// Largest gRPC message the server accepts: the payload limit plus envelope, as OpenShell advises (at least 4.5 MiB).
pub const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024 + 512 * 1024;

/// Per-request RPC timeout advertised in `MiddlewareBinding` (500 ms). OpenShell uses the smaller of this and the
/// timeout in the gateway registration, so deployments register the same 500 ms. The service itself answers within
/// `DEFAULT_EVAL_TIMEOUT_MS` and fails closed past it, so the gateway never has to time out first.
pub const REQUEST_TIMEOUT_NANOS: i32 = 500_000_000;

/// Validated per-stage policy configuration for `openshell/behavioral-risk-guard`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareStageConfig {
    pub task_profile: String,
    pub mode: EnforcementMode,
}

impl MiddlewareStageConfig {
    /// Parse and validate the protobuf `Struct` passed in `ValidateConfigRequest`.
    pub fn parse(config: Option<&Struct>) -> std::result::Result<Self, String> {
        let config = config.ok_or_else(|| "config is required".to_string())?;

        if let Some(unknown_field) = config
            .fields
            .keys()
            .find(|key| !matches!(key.as_str(), "task_profile" | "mode"))
        {
            return Err(format!("unsupported config field '{unknown_field}'"));
        }

        let task_profile_val = config
            .fields
            .get("task_profile")
            .ok_or_else(|| "config.task_profile is required".to_string())?;
        let Some(Kind::StringValue(raw_profile)) = task_profile_val.kind.as_ref() else {
            return Err("config.task_profile must be a string".to_string());
        };
        let task_profile = raw_profile.trim();
        if task_profile.is_empty() {
            return Err("config.task_profile must not be empty".to_string());
        }

        let mode = match config.fields.get("mode") {
            None => EnforcementMode::Enforce,
            Some(val) => {
                let Some(Kind::StringValue(raw_mode)) = val.kind.as_ref() else {
                    return Err("config.mode must be a string".to_string());
                };
                match raw_mode.as_str() {
                    "enforce" => EnforcementMode::Enforce,
                    "observe" => EnforcementMode::Observe,
                    _ => {
                        return Err("config.mode must be 'observe' or 'enforce'".to_string());
                    }
                }
            }
        };

        Ok(Self {
            task_profile: task_profile.to_string(),
            mode,
        })
    }
}

/// `SupervisorMiddleware` gRPC implementation for `openshell-risk-guard`.
#[derive(Clone)]
pub struct RiskGuardMiddlewareService {
    pub auth: Arc<dyn AuthVerifier>,
    pub normalizer: Arc<dyn RequestNormalizer>,
    pub detector: Arc<dyn RiskDetector>,
    pub store: Arc<dyn RiskStore>,
    pub admission: Arc<Semaphore>,
    pub expected_audience: String,
    pub eval_timeout: Duration,
    pub require_agent_identity: bool,
    /// Where each request's server-side decision time is recorded. `None` records nothing (tests).
    pub latency: Option<Arc<crate::latency::LatencyRecorder>>,
    /// Where refusals are sent as OCSF events. `None` sends nothing.
    pub ocsf: Option<Arc<crate::ocsf::OcsfEmitter>>,
}

impl fmt::Debug for RiskGuardMiddlewareService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RiskGuardMiddlewareService")
            .field("expected_audience", &self.expected_audience)
            .field("eval_timeout", &self.eval_timeout)
            .field("available_permits", &self.admission.available_permits())
            .finish_non_exhaustive()
    }
}

impl RiskGuardMiddlewareService {
    /// Construct a new `RiskGuardMiddlewareService` with default admission limit (`64`)
    /// and evaluation timeout (`100ms`).
    #[must_use]
    pub fn new(
        auth: Arc<dyn AuthVerifier>,
        normalizer: Arc<dyn RequestNormalizer>,
        detector: Arc<dyn RiskDetector>,
        store: Arc<dyn RiskStore>,
        expected_audience: impl Into<String>,
    ) -> Self {
        Self {
            auth,
            normalizer,
            detector,
            store,
            admission: Arc::new(Semaphore::new(DEFAULT_MAX_IN_FLIGHT)),
            expected_audience: expected_audience.into(),
            eval_timeout: Duration::from_millis(DEFAULT_EVAL_TIMEOUT_MS),
            require_agent_identity: false,
            latency: None,
            ocsf: None,
        }
    }

    /// Send each refusal to the SIEM as an OCSF event (see `crate::ocsf`).
    #[must_use]
    pub fn with_ocsf(mut self, emitter: Arc<crate::ocsf::OcsfEmitter>) -> Self {
        self.ocsf = Some(emitter);
        self
    }

    /// Record each request's server-side decision time (success, error and timeout alike) into `recorder`.
    #[must_use]
    pub fn with_latency_recorder(mut self, recorder: Arc<crate::latency::LatencyRecorder>) -> Self {
        self.latency = Some(recorder);
        self
    }

    #[must_use]
    pub const fn with_required_agent_identity(mut self, required: bool) -> Self {
        self.require_agent_identity = required;
        self
    }

    /// Override the maximum concurrent in-flight evaluations.
    #[must_use]
    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.admission = Arc::new(Semaphore::new(max_in_flight));
        self
    }

    /// Override the admission semaphore directly.
    #[must_use]
    pub fn with_admission(mut self, admission: Arc<Semaphore>) -> Self {
        self.admission = admission;
        self
    }

    /// Override the per-evaluation timeout.
    #[must_use]
    pub const fn with_eval_timeout(mut self, eval_timeout: Duration) -> Self {
        self.eval_timeout = eval_timeout;
        self
    }

    /// Wrap this service in a tonic `SupervisorMiddlewareServer`.
    #[must_use]
    pub fn into_server(self) -> SupervisorMiddlewareServer<Self> {
        SupervisorMiddlewareServer::new(self).max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
    }

    fn build_manifest(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: MIDDLEWARE_MANIFEST_NAME.to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                request_timeout: Some(prost_types::Duration {
                    seconds: 0,
                    nanos: REQUEST_TIMEOUT_NANOS,
                }),
            }],
            expected_audience: self.expected_audience.clone(),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                MIDDLEWARE_MANIFEST_NAME,
                openshell_core::VERSION,
                [],
            )),
        }
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn map_risk_guard_error(err: RiskGuardError) -> Status {
    match err {
        RiskGuardError::Unauthenticated(msg) => Status::unauthenticated(msg),
        RiskGuardError::PermissionDenied(msg) => Status::permission_denied(msg),
        RiskGuardError::InvalidArgument(msg) => Status::invalid_argument(msg),
        RiskGuardError::ConflictingDuplicateRequestId {
            epoch_id,
            request_id,
        } => Status::invalid_argument(format!(
            "conflicting duplicate request_id '{request_id}' in epoch '{epoch_id}'"
        )),
        RiskGuardError::AdmissionExhausted(msg) => Status::resource_exhausted(msg),
        RiskGuardError::Storage(_) => Status::unavailable(REASON_RISK_STATE_UNAVAILABLE),
        RiskGuardError::Policy(msg) => Status::failed_precondition(msg),
        RiskGuardError::Internal(msg) => Status::internal(msg),
    }
}

fn build_http_request_result(eval: &RiskEvaluation) -> HttpRequestResult {
    let decision = match eval.outcome {
        DecisionOutcome::Allow | DecisionOutcome::AllowWithObservation => Decision::Allow as i32,
        DecisionOutcome::Deny => Decision::Deny as i32,
    };

    let contributing_signals: Vec<&str> = eval
        .signals
        .iter()
        .filter(|s| {
            s.contribution > 0
                || s.feature == "task_constraint"
                || s.feature.starts_with("restriction:")
        })
        .map(|s| s.feature.as_str())
        .collect();
    let signals_summary = if contributing_signals.is_empty() {
        "none".to_string()
    } else {
        contributing_signals.join(",")
    };
    let reason = format!(
        "reason_code={} risk_score={}/{} signals=[{}]",
        eval.reason_code, eval.risk_score, eval.threshold, signals_summary
    );

    let reason_code = if eval.outcome == DecisionOutcome::Deny {
        eval.reason_code.clone()
    } else {
        String::new()
    };

    let findings = if eval.outcome != DecisionOutcome::Allow {
        vec![Finding {
            r#type: eval.reason_code.clone(),
            label: format!(
                "behavioral risk score {} (threshold {})",
                eval.risk_score, eval.threshold
            ),
            count: 1,
            confidence: "high".to_string(),
            severity: if eval.outcome == DecisionOutcome::Deny {
                "high".to_string()
            } else {
                "medium".to_string()
            },
        }]
    } else {
        Vec::new()
    };

    let metadata = HashMap::from([
        ("epoch_id".to_string(), eval.epoch_id.clone()),
        ("risk_score".to_string(), eval.risk_score.to_string()),
        ("threshold".to_string(), eval.threshold.to_string()),
        ("mode".to_string(), eval.mode.as_str().to_string()),
        (
            "state_sequence".to_string(),
            eval.state_sequence.to_string(),
        ),
        (
            "detector_version".to_string(),
            eval.detector_version.clone(),
        ),
        ("baseline_hash".to_string(), eval.baseline_hash.clone()),
    ]);

    HttpRequestResult {
        decision,
        reason,
        body: Vec::new(),
        has_body: false,
        header_mutations: Vec::new(),
        findings,
        metadata,
        reason_code,
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for RiskGuardMiddlewareService {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> std::result::Result<Response<MiddlewareManifest>, Status> {
        let manifest = self.build_manifest();
        validate_gateway_metadata(
            ExtensionFamily::SupervisorMiddleware,
            MIDDLEWARE_MANIFEST_NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;

        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> std::result::Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let response = match MiddlewareStageConfig::parse(request.config.as_ref()) {
            Ok(_) => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Err(reason) => ValidateConfigResponse {
                valid: false,
                reason,
            },
        };
        Ok(Response::new(response))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> std::result::Result<Response<HttpRequestResult>, Status> {
        let _permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("risk-guard admission queue exhausted"))?;

        let eval_req = request.get_ref();
        if eval_req.phase != SupervisorMiddlewarePhase::PreCredentials as i32 {
            return Err(Status::invalid_argument(
                "risk-guard only supports PRE_CREDENTIALS phase",
            ));
        }

        let ctx = eval_req
            .context
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("request context is required"))?;

        if ctx.sandbox_id.trim().is_empty() {
            return Err(Status::invalid_argument(
                "context.sandbox_id must not be empty",
            ));
        }
        if ctx.request_id.trim().is_empty() {
            return Err(Status::invalid_argument(
                "context.request_id must not be empty",
            ));
        }

        let caller = self
            .auth
            .verify_supervisor_call(request.metadata(), &ctx.sandbox_id)
            .map_err(map_risk_guard_error)?;
        let crate::types::AuthenticatedCaller::Supervisor {
            gateway_id, jti, ..
        } = caller
        else {
            return Err(Status::permission_denied("supervisor identity required"));
        };
        let source = if jti == "insecure-local-test" {
            crate::types::NativeObservationSource::LocalTestSupervisor
        } else {
            crate::types::NativeObservationSource::VerifiedSupervisor
        };

        let target = eval_req
            .target
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("request target is required"))?;

        let port = u16::try_from(target.port).map_err(|_| {
            Status::invalid_argument(format!("invalid target port: {}", target.port))
        })?;

        let (binary_path, pid, ancestors) = match ctx.originating_process.as_ref() {
            Some(proc_info) => {
                let binary_path = if proc_info.binary.trim().is_empty() {
                    None
                } else {
                    Some(proc_info.binary.clone())
                };
                let pid = if proc_info.pid == 0 {
                    None
                } else {
                    Some(proc_info.pid)
                };
                (binary_path, pid, proc_info.ancestors.clone())
            }
            None => (None, None, Vec::new()),
        };

        // Kept for the SIEM event: the method, host and path only (the privacy boundary below still holds: no body, headers or query).
        let (log_method, log_host, log_path) = (
            target.method.clone(),
            target.host.clone(),
            target.path.split('?').next().unwrap_or("/").to_string(),
        );
        // NFR-04 privacy boundary: ignore request.body, request.headers, and target.query.
        let raw_input = RawRequestInput {
            request_id: ctx.request_id.clone(),
            sandbox_id: ctx.sandbox_id.clone(),
            sandbox_name: ctx.sandbox.clone(),
            workspace: ctx.workspace.clone(),
            scheme: target.scheme.clone(),
            host: target.host.clone(),
            port,
            method: target.method.clone(),
            path: target.path.clone(),
            binary_path,
            pid,
            ancestors,
            timestamp_ms: now_unix_ms(),
        };

        // From here to the end of the function, on every path, the time is recorded: a slow failure must be counted too.
        let _timer = crate::latency::LatencyTimer::start(self.latency.as_deref());
        let normalized = self
            .normalizer
            .normalize(&raw_input)
            .map_err(map_risk_guard_error)?;

        let (route_host, route_method, route_template) = (
            normalized.host.clone(),
            normalized.method.clone(),
            normalized.route_template.clone(),
        );
        let store = Arc::clone(&self.store);
        let detector = Arc::clone(&self.detector);
        let require_agent = self.require_agent_identity;
        let eval_result = tokio::time::timeout(
            self.eval_timeout,
            tokio::task::spawn_blocking(move || {
                store.evaluate_native_authenticated(
                    &normalized,
                    detector.as_ref(),
                    &gateway_id,
                    require_agent,
                    source,
                )
            }),
        )
        .await;

        let eval = match eval_result {
            Ok(Ok(Ok(eval))) => eval,
            Ok(Ok(Err(err))) => return Err(map_risk_guard_error(err)),
            Ok(Err(_join_err)) => {
                return Err(Status::unavailable(REASON_RISK_STATE_UNAVAILABLE));
            }
            Err(_elapsed) => {
                return Err(Status::unavailable(REASON_RISK_STATE_UNAVAILABLE));
            }
        };

        if let Some(ocsf) = &self.ocsf
            && !matches!(
                eval.reason_code.as_str(),
                crate::types::REASON_BEHAVIORAL_RISK_RESTRICTED
                    | crate::types::REASON_WORKLOAD_QUARANTINED
            )
        {
            ocsf.record_decision(
                &eval.sandbox_id,
                eval.outcome == DecisionOutcome::Deny,
                eval.risk_score,
                &route_host,
                &route_method,
                &route_template,
            );
        }
        if let Some(ocsf) = &self.ocsf
            && eval.outcome == DecisionOutcome::Deny
        {
            ocsf.emit(crate::ocsf::Occurrence::Decision {
                sandbox_id: eval.sandbox_id.clone(),
                request_id: eval.request_id.clone(),
                outcome: "Deny".into(),
                reason_code: eval.reason_code.clone(),
                risk_score: eval.risk_score,
                threshold: eval.threshold,
                mode: eval.mode.as_str().to_string(),
                method: log_method,
                host: log_host,
                port,
                path: log_path,
                signals: eval
                    .signals
                    .iter()
                    .filter(|signal| signal.contribution > 0)
                    .map(|signal| (signal.feature.clone(), signal.contribution))
                    .collect(),
                at_ms: eval.decision_timestamp_ms,
            });
        }
        Ok(Response::new(build_http_request_result(&eval)))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> std::result::Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented(
            "WebSocket session inspection is not enabled on risk-guard v1",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use openshell_core::extension_protocol::gateway_metadata;
    use openshell_core::proto::{HttpHeader, HttpRequestTarget, Process, RequestContext};
    use prost_types::Value;
    use tonic::Code;

    use super::*;
    use crate::auth::JwtTestIssuer;
    use crate::detector::InteractionRiskDetector;
    use crate::normalizer::CanonicalNormalizer;
    use crate::store::SqliteRiskStore;
    use crate::types::{
        BaselineProfile, EpochRecord, REASON_BEHAVIORAL_RISK_DENIED,
        REASON_BEHAVIORAL_RISK_RESTRICTED,
    };

    const TEST_GATEWAY_ID: &str = "gw-test-01";
    const TEST_AUDIENCE: &str = "urn:openshell:extension:middleware:risk-guard";
    const TEST_SANDBOX_ID: &str = "sandbox-triage-01";
    const TEST_EPOCH_ID: &str = "epoch-triage-01";
    const TEST_TASK_PROFILE: &str = "repo-triage-readonly";

    fn sample_mature_baseline() -> BaselineProfile {
        BaselineProfile {
            task_profile: TEST_TASK_PROFILE.to_string(),
            version: "1.0.0".to_string(),
            approved_by: "operator@openshell.local".to_string(),
            normalizer_version: "v1".to_string(),
            training_sessions: 25,
            training_requests: 350,
            expected_binaries: BTreeSet::from([
                "/usr/bin/curl".to_string(),
                "/usr/bin/gh".to_string(),
            ]),
            approved_resources: BTreeSet::from([
                "org/docs-site".to_string(),
                "org/sdk-core".to_string(),
            ]),
            allowed_action_classes: BTreeSet::from([
                "GET /repos/{owner}/{repo}".to_string(),
                "GET /repos/{owner}/{repo}/contents/**".to_string(),
                "GET /repos/{owner}/{repo}/issues".to_string(),
                "POST /search/code".to_string(),
            ]),
            forbidden_action_classes: BTreeSet::new(),
            forbid_unfamiliar_high_impact: false,
            rule_modes: std::collections::BTreeMap::new(),
            approved_egress_hosts: Default::default(),
            siem_context_max_points: None,
            max_req_1m_p95: 10,
            max_req_1m_p99: 15,
            max_distinct_resources_15m_p95: 3,
            max_distinct_resources_15m_p99: 5,
        }
    }

    fn setup_service() -> (
        RiskGuardMiddlewareService,
        JwtTestIssuer,
        Arc<SqliteRiskStore>,
    ) {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = Arc::new(
            issuer
                .verifier(TEST_AUDIENCE)
                .expect("verifier construction must succeed"),
        );
        let normalizer = Arc::new(CanonicalNormalizer::new_default(b"test-hmac-secret-key"));
        let detector = Arc::new(InteractionRiskDetector::new_default());
        let store = Arc::new(SqliteRiskStore::open_in_memory().expect("in-memory store"));

        let baseline = sample_mature_baseline();
        let baseline_hash = store
            .store_baseline(&baseline)
            .expect("store baseline profile");

        let epoch = EpochRecord {
            epoch_id: TEST_EPOCH_ID.to_string(),
            gateway_id: TEST_GATEWAY_ID.to_string(),
            sandbox_id: TEST_SANDBOX_ID.to_string(),
            task_profile: TEST_TASK_PROFILE.to_string(),
            baseline_hash,
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: 1_700_000_000_000,
            credentialed_endpoints: BTreeSet::from([("api.github.com".to_string(), 443)]),
            active_policy_hash: Some("pol-hash-01".to_string()),
        };
        store.upsert_epoch(&epoch).expect("upsert active epoch");

        let service = RiskGuardMiddlewareService::new(
            verifier,
            normalizer,
            detector,
            store.clone(),
            TEST_AUDIENCE,
        );
        (service, issuer, store)
    }

    fn make_config_struct(fields: impl IntoIterator<Item = (&'static str, Kind)>) -> Struct {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(k.to_string(), Value { kind: Some(v) });
        }
        Struct { fields: map }
    }

    fn build_signed_eval_request(
        issuer: &JwtTestIssuer,
        token_sandbox_id: &str,
        context_sandbox_id: &str,
        request_id: &str,
        method: &str,
        path: &str,
    ) -> Request<HttpRequestEvaluation> {
        let token = issuer
            .mint_supervisor_token(TEST_AUDIENCE, token_sandbox_id, 300)
            .expect("mint supervisor token");
        let metadata = JwtTestIssuer::bearer_metadata(&token).expect("bearer metadata");

        let evaluation = HttpRequestEvaluation {
            phase: SupervisorMiddlewarePhase::PreCredentials as i32,
            context: Some(RequestContext {
                request_id: request_id.to_string(),
                sandbox_id: context_sandbox_id.to_string(),
                originating_process: Some(Process {
                    binary: "/usr/bin/gh".to_string(),
                    pid: 4242,
                    ancestors: vec!["/bin/bash".to_string()],
                }),
                sandbox: "triage-worker".to_string(),
                workspace: "default".to_string(),
            }),
            config: None,
            target: Some(HttpRequestTarget {
                scheme: "https".to_string(),
                host: "api.github.com".to_string(),
                port: 443,
                method: method.to_string(),
                path: path.to_string(),
                query: "secret_token=should_be_ignored".to_string(),
            }),
            headers: vec![HttpHeader {
                name: "x-sensitive".to_string(),
                value: "never-log-me".to_string(),
            }],
            body: b"sensitive-request-body".to_vec(),
            middleware_name: "risk-guard".to_string(),
        };

        let mut req = Request::new(evaluation);
        *req.metadata_mut() = metadata;
        req
    }

    #[tokio::test]
    async fn describe_negotiates_valid_gateway_metadata_and_advertises_pre_credentials() {
        let (service, _, _) = setup_service();

        let response = service
            .describe(Request::new(MiddlewareDescribeRequest {
                gateway: Some(gateway_metadata(ExtensionFamily::SupervisorMiddleware)),
            }))
            .await
            .expect("describe with valid gateway metadata should succeed")
            .into_inner();

        assert_eq!(response.name, MIDDLEWARE_MANIFEST_NAME);
        assert_eq!(response.expected_audience, TEST_AUDIENCE);
        assert_eq!(response.bindings.len(), 1);
        let binding = &response.bindings[0];
        assert_eq!(
            binding.operation,
            SupervisorMiddlewareOperation::HttpRequest as i32
        );
        assert_eq!(
            binding.phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(binding.max_payload_bytes, MAX_PAYLOAD_BYTES);
        assert_eq!(
            binding.request_timeout,
            Some(prost_types::Duration {
                seconds: 0,
                nanos: REQUEST_TIMEOUT_NANOS,
            })
        );

        let missing_gw = service
            .describe(Request::new(MiddlewareDescribeRequest { gateway: None }))
            .await
            .expect_err("describe without gateway metadata should fail");
        assert_eq!(missing_gw.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn validate_config_accepts_valid_and_rejects_unknown_keys_or_invalid_mode() {
        let (service, _, _) = setup_service();

        // Valid with explicit mode = "observe"
        let valid_observe = service
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(make_config_struct([
                    (
                        "task_profile",
                        Kind::StringValue(TEST_TASK_PROFILE.to_string()),
                    ),
                    ("mode", Kind::StringValue("observe".to_string())),
                ])),
                middleware_name: "risk-guard".to_string(),
            }))
            .await
            .expect("validate_config RPC should succeed")
            .into_inner();
        assert!(valid_observe.valid);
        assert!(valid_observe.reason.is_empty());

        // Valid with default mode ("enforce")
        let valid_default = service
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(make_config_struct([(
                    "task_profile",
                    Kind::StringValue(TEST_TASK_PROFILE.to_string()),
                )])),
                middleware_name: "risk-guard".to_string(),
            }))
            .await
            .expect("validate_config RPC should succeed")
            .into_inner();
        assert!(valid_default.valid);
        assert!(valid_default.reason.is_empty());

        // Reject unknown config field
        let unknown_key = service
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(make_config_struct([
                    (
                        "task_profile",
                        Kind::StringValue(TEST_TASK_PROFILE.to_string()),
                    ),
                    ("unknown_flag", Kind::BoolValue(true)),
                ])),
                middleware_name: "risk-guard".to_string(),
            }))
            .await
            .expect("validate_config RPC should succeed")
            .into_inner();
        assert!(!unknown_key.valid);
        assert!(unknown_key.reason.contains("unknown_flag"));

        // Reject invalid mode
        let invalid_mode = service
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(make_config_struct([
                    (
                        "task_profile",
                        Kind::StringValue(TEST_TASK_PROFILE.to_string()),
                    ),
                    ("mode", Kind::StringValue("permissive".to_string())),
                ])),
                middleware_name: "risk-guard".to_string(),
            }))
            .await
            .expect("validate_config RPC should succeed")
            .into_inner();
        assert!(!invalid_mode.valid);
        assert!(invalid_mode.reason.contains("config.mode"));

        // Reject empty task_profile
        let empty_profile = service
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(make_config_struct([(
                    "task_profile",
                    Kind::StringValue("   ".to_string()),
                )])),
                middleware_name: "risk-guard".to_string(),
            }))
            .await
            .expect("validate_config RPC should succeed")
            .into_inner();
        assert!(!empty_profile.valid);
    }

    #[tokio::test]
    async fn trusted_agent_binding_is_required_and_workload_claims_do_not_supply_it() {
        let (service, issuer, store) = setup_service();
        let service = service.with_required_agent_identity(true);
        let mut unbound = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "unbound",
            "GET",
            "/repos/org/docs-site/issues",
        );
        unbound.get_mut().config = Some(make_config_struct([(
            "agent_id",
            Kind::StringValue("self-declared-trusted-agent".into()),
        )]));
        assert_eq!(
            service
                .evaluate_http_request(unbound)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        store
            .register_agent("operator-agent", "Approved reviewer")
            .unwrap();
        store
            .create_agent_run(
                "operator-agent",
                "operator-run",
                "revision-1",
                TEST_TASK_PROFILE,
                EnforcementMode::Enforce,
            )
            .unwrap();
        store
            .bind_agent_run("operator-run", TEST_SANDBOX_ID, TEST_GATEWAY_ID)
            .unwrap();
        let request = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "bound",
            "GET",
            "/repos/org/docs-site/issues",
        );
        assert_eq!(
            service
                .evaluate_http_request(request)
                .await
                .unwrap()
                .into_inner()
                .decision,
            Decision::Allow as i32
        );
        let detail = store
            .operator_agent_detail("operator-agent", i64::MAX - 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            detail["decisions"][0]["identity"]["agent_id"],
            "operator-agent"
        );
        assert_eq!(detail["decisions"][0]["identity"]["run_id"], "operator-run");
    }

    #[tokio::test]
    async fn a_quarantined_workload_is_refused_at_the_middleware_gate_and_allowed_again_on_release()
    {
        let (service, issuer, store) = setup_service();
        store
            .register_agent("quarantine-agent", "Approved reviewer")
            .unwrap();
        store
            .create_agent_run(
                "quarantine-agent",
                "quarantine-run",
                "revision-1",
                TEST_TASK_PROFILE,
                EnforcementMode::Enforce,
            )
            .unwrap();
        store
            .bind_agent_run("quarantine-run", TEST_SANDBOX_ID, TEST_GATEWAY_ID)
            .unwrap();
        let ask = |id: &str| {
            build_signed_eval_request(
                &issuer,
                TEST_SANDBOX_ID,
                TEST_SANDBOX_ID,
                id,
                "GET",
                "/repos/org/docs-site/issues",
            )
        };
        let before = service
            .evaluate_http_request(ask("before"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(before.decision, Decision::Allow as i32);

        store
            .quarantine_workload("quarantine-agent", "siem", "test", now_unix_ms())
            .unwrap();
        let during = service
            .evaluate_http_request(ask("during"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(during.decision, Decision::Deny as i32);
        assert_eq!(
            during.reason_code,
            crate::types::REASON_WORKLOAD_QUARANTINED
        );

        assert!(
            store
                .release_workload("quarantine-agent", "siem", "test", now_unix_ms())
                .unwrap()
        );
        let after = service
            .evaluate_http_request(ask("after"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(after.decision, Decision::Allow as i32);
    }

    #[tokio::test]
    async fn evaluate_http_request_allows_benign_denies_cross_repo_delete_and_latches_restriction()
    {
        let (service, issuer, _) = setup_service();

        // 1. Benign GET /repos/org/docs-site/issues -> ALLOW, no mutations, has_body == false
        let benign_req = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-benign-01",
            "GET",
            "/repos/org/docs-site/issues",
        );
        let benign_res = service
            .evaluate_http_request(benign_req)
            .await
            .expect("benign evaluation should succeed")
            .into_inner();
        assert_eq!(benign_res.decision, Decision::Allow as i32);
        assert!(!benign_res.has_body);
        assert!(benign_res.body.is_empty());
        assert!(benign_res.header_mutations.is_empty());
        assert!(benign_res.reason_code.is_empty());
        assert!(benign_res.findings.is_empty());
        assert_eq!(
            benign_res.metadata.get("epoch_id").map(String::as_str),
            Some(TEST_EPOCH_ID)
        );
        assert_eq!(
            benign_res.metadata.get("mode").map(String::as_str),
            Some("enforce")
        );

        // 2. Flagship cross-repo destructive DELETE /repos/org/payments-prod -> DENY ("behavioral_risk_denied")
        let attack_req = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-attack-01",
            "DELETE",
            "/repos/org/payments-prod",
        );
        let attack_res = service
            .evaluate_http_request(attack_req)
            .await
            .expect("attack evaluation should return a deny decision")
            .into_inner();
        assert_eq!(attack_res.decision, Decision::Deny as i32);
        assert_eq!(attack_res.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
        assert!(!attack_res.has_body);
        assert!(attack_res.body.is_empty());
        assert!(attack_res.header_mutations.is_empty());
        assert_eq!(attack_res.findings.len(), 1);
        assert_eq!(attack_res.findings[0].r#type, REASON_BEHAVIORAL_RISK_DENIED);
        assert_eq!(attack_res.findings[0].severity, "high");

        // 3. Subsequent retry of DELETE /repos/org/payments-prod -> DENY ("behavioral_risk_restricted")
        let retry_req = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-attack-retry-02",
            "DELETE",
            "/repos/org/payments-prod",
        );
        let retry_res = service
            .evaluate_http_request(retry_req)
            .await
            .expect("retry evaluation should return a restricted deny decision")
            .into_inner();
        assert_eq!(retry_res.decision, Decision::Deny as i32);
        assert_eq!(retry_res.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
        assert!(!retry_res.has_body);
        assert!(retry_res.header_mutations.is_empty());
        assert_eq!(retry_res.findings.len(), 1);
        assert_eq!(
            retry_res.findings[0].r#type,
            REASON_BEHAVIORAL_RISK_RESTRICTED
        );
    }

    #[tokio::test]
    async fn evaluate_http_request_rejects_missing_jwt_mismatched_sandbox_and_conflicting_duplicate_id()
     {
        let (service, issuer, _) = setup_service();

        // 1. Missing JWT -> Status::unauthenticated
        let mut unauth_req = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-unauth-01",
            "GET",
            "/repos/org/docs-site",
        );
        unauth_req.metadata_mut().clear();
        let unauth_err = service
            .evaluate_http_request(unauth_req)
            .await
            .expect_err("missing JWT must be rejected");
        assert_eq!(unauth_err.code(), Code::Unauthenticated);

        // 2. Mismatched sandbox_id in JWT vs RequestContext -> Status::permission_denied
        let mismatch_req = build_signed_eval_request(
            &issuer,
            "sandbox-other-99",
            TEST_SANDBOX_ID,
            "req-mismatch-01",
            "GET",
            "/repos/org/docs-site",
        );
        let mismatch_err = service
            .evaluate_http_request(mismatch_req)
            .await
            .expect_err("mismatched sandbox_id must be rejected");
        assert_eq!(mismatch_err.code(), Code::PermissionDenied);

        // 3. Conflicting duplicate request_id -> Status::invalid_argument
        let first_req = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-dup-01",
            "GET",
            "/repos/org/docs-site",
        );
        service
            .evaluate_http_request(first_req)
            .await
            .expect("first request with req-dup-01 should succeed");

        let conflicting_req = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-dup-01",
            "GET",
            "/repos/org/sdk-core/issues",
        );
        let conflict_err = service
            .evaluate_http_request(conflicting_req)
            .await
            .expect_err("conflicting duplicate request_id must be rejected");
        assert_eq!(conflict_err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn evaluate_http_request_enforces_admission_capacity_limit() {
        let (service, issuer, _) = setup_service();
        let semaphore = Arc::new(Semaphore::new(1));
        let service = service.with_admission(Arc::clone(&semaphore));

        // Exhaust the single permit
        let _held_permit = semaphore
            .try_acquire_owned()
            .expect("acquire sole semaphore permit");

        let req = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-exhausted-01",
            "GET",
            "/repos/org/docs-site",
        );
        let err = service
            .evaluate_http_request(req)
            .await
            .expect_err("request when admission semaphore is exhausted must fail");
        assert_eq!(err.code(), Code::ResourceExhausted);
        assert!(err.message().contains("admission queue exhausted"));
    }

    #[tokio::test]
    async fn evaluate_http_request_validates_phase_context_and_idempotency() {
        let (service, issuer, _) = setup_service();

        // Wrong phase -> InvalidArgument
        let mut wrong_phase_req = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-phase-01",
            "GET",
            "/repos/org/docs-site",
        );
        wrong_phase_req.get_mut().phase = SupervisorMiddlewarePhase::PreReturn as i32;
        let phase_err = service
            .evaluate_http_request(wrong_phase_req)
            .await
            .expect_err("non-PRE_CREDENTIALS phase must be rejected");
        assert_eq!(phase_err.code(), Code::InvalidArgument);

        // Idempotent retry with identical request_id and payload -> returns identical cached result
        let req1 = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-idem-01",
            "GET",
            "/repos/org/docs-site/issues",
        );
        let res1 = service
            .evaluate_http_request(req1)
            .await
            .expect("initial request should succeed")
            .into_inner();
        let req2 = build_signed_eval_request(
            &issuer,
            TEST_SANDBOX_ID,
            TEST_SANDBOX_ID,
            "req-idem-01",
            "GET",
            "/repos/org/docs-site/issues",
        );
        let res2 = service
            .evaluate_http_request(req2)
            .await
            .expect("idempotent duplicate request should succeed")
            .into_inner();
        assert_eq!(res1.decision, res2.decision);
        assert_eq!(
            res1.metadata.get("state_sequence"),
            res2.metadata.get("state_sequence")
        );
    }
}
