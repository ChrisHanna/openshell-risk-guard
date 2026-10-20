// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Shared frozen domain types and trait contracts for `openshell-risk-guard`.
//!
//! Wave 0 freezes these types so Wave 1–3 agents can implement their modules in
//! parallel without cross-module edits.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tonic::metadata::MetadataMap;

use crate::error::Result;

/// Stable machine-readable reason code for inline behavioral risk denials.
pub const REASON_BEHAVIORAL_RISK_DENIED: &str = "behavioral_risk_denied";

/// Stable machine-readable reason code when a prior Tier 1 or Tier 2 restriction
/// blocks a subsequent request on the same scope.
pub const REASON_BEHAVIORAL_RISK_RESTRICTED: &str = "behavioral_risk_restricted";

/// Stable machine-readable reason code for Layer A task-constraint denials.
pub const REASON_TASK_CONSTRAINT_DENIED: &str = "task_constraint_denied";

/// Stable machine-readable reason code when risk state is unavailable in fail-closed mode.
pub const REASON_RISK_STATE_UNAVAILABLE: &str = "risk_state_unavailable";

/// Operating mode for an epoch or middleware evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Observe,
    Enforce,
}

impl EnforcementMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Enforce => "enforce",
        }
    }
}

/// Verified caller identity extracted from an `openshell-ext+jwt` bearer token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatedCaller {
    Gateway {
        gateway_id: String,
        jti: String,
        exp: i64,
    },
    Supervisor {
        gateway_id: String,
        sandbox_id: String,
        jti: String,
        exp: i64,
    },
}

/// Provenance assigned by the authenticated supervisor RPC, never workload JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeObservationSource {
    VerifiedSupervisor,
    LocalTestSupervisor,
}

impl NativeObservationSource {
    pub const fn learning_scope(self) -> crate::adaptive_controls::LearningScope {
        match self {
            Self::VerifiedSupervisor => crate::adaptive_controls::LearningScope::Verified,
            Self::LocalTestSupervisor => crate::adaptive_controls::LearningScope::LocalDemo,
        }
    }
}

/// Raw request metadata extracted from `HttpRequestEvaluation` before normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRequestInput {
    pub request_id: String,
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub workspace: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub binary_path: Option<String>,
    pub pid: Option<u32>,
    pub ancestors: Vec<String>,
    pub timestamp_ms: i64,
}

/// Canonicalized request representation produced by the normalizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedRequest {
    pub request_id: String,
    pub sandbox_id: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    /// Matched route template (e.g. `/repos/{owner}/{repo}`) or `unknown`.
    pub route_template: String,
    /// Logical resource identifier (e.g. `org/docs-site`) for trusted comparisons.
    pub resource_id: String,
    /// Keyed HMAC-SHA256 digest of resource_id for fixed-length window bucketing (raw resource_id is still retained in local SQLite forensic evidence).
    pub resource_key: String,
    /// Normalized action class combining method + route_template (e.g. `DELETE /repos/{owner}/{repo}`).
    pub action_class: String,
    /// Normalized restriction scope (`scheme://host:port method route_template resource_id`).
    pub restriction_scope: String,
    /// Semantic impact indicator `I in {0, 1}` from curated API semantic rules.
    pub high_impact: bool,
    /// Semantic category label (e.g. `read_only`, `write_mutation`, `destructive_admin`, `unknown`).
    pub semantic_category: String,
    /// Originating binary path when process identity is available.
    pub binary_path: Option<String>,
    /// Process ancestor paths when available.
    pub ancestors: Vec<String>,
    /// Deterministic SHA-256 fingerprint of the canonical request for idempotency checks.
    pub fingerprint: String,
    pub timestamp_ms: i64,
}

/// Pre-event temporal window statistics for an epoch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSnapshot {
    pub req_count_1m: u32,
    pub req_count_15m: u32,
    pub distinct_resources_1m: u32,
    pub distinct_resources_15m: u32,
    /// True after a restart or clock jump when temporal buckets are still warming up.
    pub warming: bool,
}

/// Maturity state of a baseline profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineMaturity {
    Mature,
    Insufficient,
}

/// Operator-approved task baseline profile artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub task_profile: String,
    pub version: String,
    pub approved_by: String,
    pub normalizer_version: String,
    pub training_sessions: u32,
    pub training_requests: u32,
    /// Expected originating binaries (e.g. `["/usr/bin/curl", "/usr/bin/gh"]`).
    pub expected_binaries: BTreeSet<String>,
    /// Approved resource identifiers (e.g. `["org/docs-site", "org/sdk-core"]`).
    pub approved_resources: BTreeSet<String>,
    /// Observed allowed action classes (e.g. `["GET /repos/{owner}/{repo}", "GET /repos/{owner}/{repo}/issues"]`).
    pub allowed_action_classes: BTreeSet<String>,
    /// Explicit Layer A forbidden action classes or prefixes that always trigger `task_constraint`.
    #[serde(default)]
    pub forbidden_action_classes: BTreeSet<String>,
    /// Whether high-impact operations on unfamiliar resources are strictly forbidden by task constraint.
    #[serde(default)]
    pub forbid_unfamiliar_high_impact: bool,
    /// 95th-percentile 1-minute request rate envelope.
    pub max_req_1m_p95: u32,
    /// 99th-percentile 1-minute request rate envelope.
    pub max_req_1m_p99: u32,
    /// 95th-percentile 15-minute distinct-resource envelope.
    pub max_distinct_resources_15m_p95: u32,
    /// 99th-percentile 15-minute distinct-resource envelope.
    pub max_distinct_resources_15m_p99: u32,
}

impl BaselineProfile {
    #[must_use]
    pub fn maturity(&self) -> BaselineMaturity {
        if self.training_sessions >= 20 && self.training_requests >= 200 {
            BaselineMaturity::Mature
        } else {
            BaselineMaturity::Insufficient
        }
    }
}

/// Explainable contribution of one signal to the overall risk score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalContribution {
    pub feature: String,
    pub observed_summary: String,
    pub baseline_summary: String,
    pub contribution: u32,
    pub support: String,
}

/// Decision outcome before or after enforcement mode mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Allow,
    AllowWithObservation,
    Deny,
}

/// Two-Tier Monotonic Ratchet transition triggered by an enforced denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RatchetAction {
    None,
    LatchTier1StrictEpoch {
        scope: String,
    },
    TriggerTier2Cooldown {
        scope: String,
        cooldown_duration_ms: i64,
    },
}

/// Complete risk evaluation result returned by the detector and persisted in SQLite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskEvaluation {
    pub request_id: String,
    pub sandbox_id: String,
    pub epoch_id: String,
    pub mode: EnforcementMode,
    pub outcome: DecisionOutcome,
    pub reason_code: String,
    pub risk_score: u32,
    pub threshold: u32,
    pub ratchet_action: RatchetAction,
    pub signals: Vec<SignalContribution>,
    pub missing_context: Vec<String>,
    pub baseline_maturity: BaselineMaturity,
    pub baseline_hash: String,
    pub detector_version: String,
    pub state_sequence: u64,
    pub decision_timestamp_ms: i64,
}

/// Stored epoch metadata binding a sandbox to a task profile and active mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecord {
    pub epoch_id: String,
    pub gateway_id: String,
    pub sandbox_id: String,
    pub task_profile: String,
    pub baseline_hash: String,
    pub mode: EnforcementMode,
    pub active: bool,
    pub next_sequence: u64,
    pub created_at_ms: i64,
    /// Credential-bearing `(host, port)` pairs extracted from the active policy snapshot.
    pub credentialed_endpoints: BTreeSet<(String, u16)>,
    pub active_policy_hash: Option<String>,
}

/// Result of the Two-Step Containment Proof (`network_middlewares` invariance + `openshell-prover`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoStepProofResult {
    /// Raw prover status on the unprojected policy (`unsupported_middleware` when middleware is present).
    pub raw_prover_status: String,
    /// Whether Step 1 (`network_middlewares` structural invariance + `fail_closed` + selector coverage) passed.
    pub step1_middleware_invariant: bool,
    pub step1_detail: String,
    /// Verdict of Step 2 (`openshell-prover` Z3 check on the middleware-stripped projection):
    /// `within_boundary`, `exceeds_boundary`, `unsupported`, `inconclusive`, or `skipped`.
    pub step2_prover_verdict: String,
    pub step2_counterexample_or_reason: Option<String>,
    pub coverage_domains: Vec<String>,
    /// True iff both Step 1 and Step 2 succeeded (`step1_middleware_invariant && step2_prover_verdict == "within_boundary"`).
    pub verified_non_expanding: bool,
}

/// Periodic policy-hardening recommendation artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningCandidate {
    pub recommendation_id: String,
    pub sandbox_id: String,
    pub epoch_id: String,
    pub interval_start_ms: i64,
    pub interval_end_ms: i64,
    pub observed_requests: usize,
    pub completeness_ok: bool,
    pub coverage_gaps: Vec<String>,
    pub source_policy_hash: String,
    pub candidate_policy_hash: String,
    pub candidate_yaml: String,
    pub diff_summary: Vec<String>,
    pub two_step_proof: TwoStepProofResult,
    pub replay_total_requests: usize,
    pub replay_would_block: usize,
    pub status: String,
}

/// Trait for verifying inbound `openshell-ext+jwt` bearer tokens.
pub trait AuthVerifier: Send + Sync {
    fn verify_supervisor_call(
        &self,
        metadata: &MetadataMap,
        expected_sandbox_id: &str,
    ) -> Result<AuthenticatedCaller>;

    fn verify_gateway_call(&self, metadata: &MetadataMap) -> Result<AuthenticatedCaller>;
}

/// Trait for canonicalizing HTTP request targets and classifying API semantics.
pub trait RequestNormalizer: Send + Sync {
    fn normalize(&self, input: &RawRequestInput) -> Result<NormalizedRequest>;
    fn normalizer_version(&self) -> &str;
}

/// Context passed into the pure detector evaluation.
#[derive(Debug, Clone)]
pub struct DetectorContext<'a> {
    pub epoch: &'a EpochRecord,
    pub baseline: &'a BaselineProfile,
    pub window: &'a WindowSnapshot,
    pub credentialed_endpoint: bool,
}

/// Trait for pure, deterministic behavioral risk scoring.
pub trait RiskDetector: Send + Sync {
    fn evaluate(
        &self,
        req: &NormalizedRequest,
        ctx: &DetectorContext<'_>,
    ) -> Result<RiskEvaluation>;

    fn detector_version(&self) -> &str;

    fn configuration_id(&self) -> String {
        self.detector_version().to_string()
    }
}

/// Trait for the transactional SQLite state and audit store.
/// One attempt to attach a sandbox to a workload, kept as evidence of who did it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingAudit {
    pub sandbox_id: String,
    pub workspace: String,
    pub principal_kind: String,
    pub principal_subject: String,
    pub agent_id: Option<String>,
    /// `principal` when the workload was derived from the authenticated caller, `label`
    /// when an allowlisted operator named it.
    pub source: &'static str,
    pub bound: bool,
    pub reason: Option<String>,
}

pub trait RiskStore: Send + Sync {
    fn upsert_epoch(&self, epoch: &EpochRecord) -> Result<()>;
    fn get_active_epoch(&self, sandbox_id: &str) -> Result<Option<EpochRecord>>;
    fn get_effective_active_epoch(&self, sandbox_id: &str) -> Result<Option<EpochRecord>> {
        self.get_active_epoch(sandbox_id)
    }
    fn terminate_epoch(&self, epoch_id: &str) -> Result<()>;
    fn store_baseline(&self, profile: &BaselineProfile) -> Result<String>;
    fn get_baseline(&self, task_profile: &str) -> Result<Option<BaselineProfile>>;
    fn record_policy_snapshot(
        &self,
        sandbox_id: &str,
        policy_hash: &str,
        policy_yaml: &str,
        credentialed_endpoints: &BTreeSet<(String, u16)>,
        source: &str,
        timestamp_ms: i64,
    ) -> Result<()>;
    fn latest_policy_snapshot(&self, sandbox_id: &str) -> Result<Option<(String, String)>>;
    fn record_coverage_gap(
        &self,
        sandbox_id: &str,
        reason: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<()>;
    fn evaluate_and_commit_atomic(
        &self,
        req: &NormalizedRequest,
        detector: &dyn RiskDetector,
    ) -> Result<RiskEvaluation>;
    fn evaluate_authenticated(
        &self,
        req: &NormalizedRequest,
        detector: &dyn RiskDetector,
        gateway_id: &str,
        require_agent: bool,
    ) -> Result<RiskEvaluation>;
    fn evaluate_native_authenticated(
        &self,
        req: &NormalizedRequest,
        detector: &dyn RiskDetector,
        gateway_id: &str,
        require_agent: bool,
        _source: NativeObservationSource,
    ) -> Result<RiskEvaluation> {
        self.evaluate_authenticated(req, detector, gateway_id, require_agent)
    }
    fn list_decisions(&self, sandbox_id: &str, limit: usize) -> Result<Vec<RiskEvaluation>>;
    fn list_normalized_requests(
        &self,
        sandbox_id: &str,
    ) -> Result<Vec<(NormalizedRequest, DecisionOutcome)>>;
    fn save_recommendation(&self, candidate: &HardeningCandidate) -> Result<()>;
    fn auto_bind_sandbox_epoch(
        &self,
        _sandbox_id: &str,
        _gateway_id: &str,
        _agent_id: &str,
        _agent_revision: &str,
        _run_id: &str,
        _auto_register: bool,
        _display_name: Option<&str>,
    ) -> Result<()> {
        Ok(())
    }
    /// Append one workload-binding attempt (accepted or refused) to the audit trail.
    fn record_binding_audit(&self, _entry: &BindingAudit) -> Result<()> {
        Ok(())
    }
    fn close_sandbox_lifecycle(&self, _sandbox_id: &str) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Trait for policy-hardening synthesis and Two-Step Containment Proof verification.
pub trait HardeningEngine: Send + Sync {
    fn extract_credentialed_endpoints(&self, policy_yaml: &str) -> Result<BTreeSet<(String, u16)>>;

    fn verify_two_step_containment(
        &self,
        boundary_yaml: &str,
        candidate_yaml: &str,
        timeout: Duration,
    ) -> Result<TwoStepProofResult>;

    fn generate_recommendation(
        &self,
        sandbox_id: &str,
        epoch_id: &str,
        current_policy_yaml: &str,
        history: &[(NormalizedRequest, DecisionOutcome)],
        held_out_benign: &[NormalizedRequest],
        interval_start_ms: i64,
        interval_end_ms: i64,
        coverage_gaps: Vec<String>,
    ) -> Result<HardeningCandidate>;
}

pub type MetadataBag = BTreeMap<String, String>;
