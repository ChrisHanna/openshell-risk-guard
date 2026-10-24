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

/// Stable machine-readable reason code when an operator (or a SIEM signal) has quarantined the workload: every request is refused, whatever it is.
pub const REASON_WORKLOAD_QUARANTINED: &str = "workload_quarantined";

/// Stable machine-readable reason code for Layer A task-constraint denials.
pub const REASON_TASK_CONSTRAINT_DENIED: &str = "task_constraint_denied";

/// Stable machine-readable reason code when risk state is unavailable in fail-closed mode.
pub const REASON_RISK_STATE_UNAVAILABLE: &str = "risk_state_unavailable";

/// Rule that denies any action listed in `forbidden_action_classes`. An explicit deny list: it always enforces.
pub const RULE_FORBIDDEN_ACTION: &str = "forbidden_action";
/// Rule that denies a high-impact action on a resource the task does not approve.
pub const RULE_UNFAMILIAR_HIGH_IMPACT: &str = "unfamiliar_high_impact";
/// Rule for an action class the task's allowed-action list does not contain.
pub const RULE_UNAPPROVED_ACTION: &str = "unapproved_action";
/// Rule for a resource the task's approved-resource list does not contain.
pub const RULE_UNAPPROVED_RESOURCE: &str = "unapproved_resource";
/// Rule for a tunnel to a destination the task's approved-egress list does not contain. Enforced at the network path, not in scoring; set it
/// in the profile's `rule_modes` (it is not one of the console's configurable rules). Default: shadow.
pub const RULE_EGRESS_DESTINATION: &str = "egress_destination";
/// The tunnel gate's cross-check that a sandbox which has been reporting requests has not gone quiet while still opening tunnels, which is what
/// a supervisor that stopped calling Risk Guard (crashed, misconfigured, or compromised) looks like from the network path. Like the egress rule it
/// is set in the profile's `rule_modes`, and defaults to shadow: it is recorded, not enforced, until an operator promotes it.
pub const RULE_SUPERVISOR_SILENT: &str = "supervisor_silent";
/// Risk features from the SIEM (OpenShell policy denials, refusal ratios, fleet counts) that may add a bounded number of points to a score. Set in
/// the profile's `rule_modes`; default: shadow, which records what it would have added and adds nothing. See docs/design-siem-features.md.
pub const RULE_SIEM_CONTEXT: &str = "siem_context";
/// The most points `siem_context` may add when the profile does not say otherwise.
pub const SIEM_CONTEXT_DEFAULT_MAX_POINTS: u32 = 15;
/// The most a profile may allow `siem_context` to add, whatever it asks for.
pub const SIEM_CONTEXT_HARD_CAP_POINTS: u32 = 30;
/// The most features one decision can carry: the vocabulary has ten names, each at most once per scope.
pub const MAX_CONTEXT_FEATURES: usize = 16;
/// The rules an operator can run in shadow or enforce mode, in display order.
pub const CONFIGURABLE_RULES: [&str; 3] = [
    RULE_UNFAMILIAR_HIGH_IMPACT,
    RULE_UNAPPROVED_ACTION,
    RULE_UNAPPROVED_RESOURCE,
];

/// What a rule does when a request trips it.
///
/// A `shadow` rule is evaluated and recorded as a would-block signal but never changes the outcome, so its effect can
/// be measured before anyone promotes it to `enforce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    Off,
    Shadow,
    Enforce,
}

impl RuleMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

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
    /// Per-rule overrides of the default mode. Empty means every rule uses its default, and an empty map is left out of
    /// the serialized profile so existing baselines keep their hash.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rule_modes: BTreeMap<String, RuleMode>,
    /// The most points the `siem_context` rule may add to a score (at most 30; default 15). Left out of the serialized profile when unset so existing
    /// baselines keep their hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siem_context_max_points: Option<u32>,
    /// Hostnames this task may open an encrypted connection to, checked at the network-path tunnel gate (the `egress_destination` rule). An
    /// entry is a hostname (`integrate.api.nvidia.com`) or a subdomain wildcard (`*.example.com`). Empty means not specified: nothing is
    /// refused. Left out of the serialized profile when empty so existing baselines keep their hash.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_egress_hosts: BTreeSet<String>,
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
    /// The mode a rule runs in for this profile.
    ///
    /// Defaults keep today's behavior: the explicit deny list always enforces, the high-impact rule follows
    /// `forbid_unfamiliar_high_impact` (an override can only soften it to shadow), and the two approved-list rules
    /// observe in shadow until an operator promotes them.
    #[must_use]
    pub fn rule_mode(&self, rule: &str) -> RuleMode {
        match rule {
            RULE_FORBIDDEN_ACTION => RuleMode::Enforce,
            RULE_UNFAMILIAR_HIGH_IMPACT if !self.forbid_unfamiliar_high_impact => RuleMode::Off,
            RULE_UNFAMILIAR_HIGH_IMPACT => match self.rule_modes.get(rule) {
                Some(RuleMode::Shadow) => RuleMode::Shadow,
                _ => RuleMode::Enforce,
            },
            _ => self
                .rule_modes
                .get(rule)
                .copied()
                .unwrap_or(RuleMode::Shadow),
        }
    }

    /// Whether a tunnel to `host` is within the task's approved egress hosts. An empty list approves everything. A destination that is an IP
    /// address never matches a non-empty list: the list names hosts, and an address could be anything.
    #[must_use]
    pub fn egress_host_allowed(&self, host: &str) -> bool {
        if self.approved_egress_hosts.is_empty() {
            return true;
        }
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
            return false;
        }
        self.approved_egress_hosts
            .iter()
            .any(|entry| match entry.strip_prefix("*.") {
                Some(suffix) => {
                    host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"))
                }
                None => entry == &host,
            })
    }

    /// Check the approved-egress list is well formed: lowercase hostnames or `*.` wildcards, no scheme, port, path or address.
    pub fn validate_egress_hosts(&self) -> std::result::Result<(), String> {
        for entry in &self.approved_egress_hosts {
            let name = entry.strip_prefix("*.").unwrap_or(entry);
            let valid = !name.is_empty()
                && name.len() <= 253
                && name.contains('.')
                && name.parse::<std::net::IpAddr>().is_err()
                && name.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                });
            if !valid {
                return Err(format!(
                    "approved_egress_hosts entry '{entry}' must be a lowercase hostname such as api.example.com or *.example.com"
                ));
            }
        }
        Ok(())
    }

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

/// Whose a SIEM risk feature is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureScope {
    /// The sandbox the request came from (also how a SPIFFE-subject feature is stored).
    Sandbox,
    /// The workload (agent) the sandbox belongs to.
    Workload,
    /// The whole fleet.
    Fleet,
}

/// One risk feature as the scorer saw it: stored with the decision so replay can supply the same one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContextFeature {
    pub scope: FeatureScope,
    pub name: String,
    pub value: u32,
    /// The subject it was published for (a sandbox id, an agent id or `fleet`), for the audit trail. The scorer does not read it.
    pub subject: String,
    /// How old the batch was when the decision was made.
    pub age_ms: i64,
}

/// The SIEM risk features available to one decision. Bounded (`MAX_CONTEXT_FEATURES`), sorted, at most one value per (scope, name) and empty by default;
/// an empty set leaves the score exactly as it is without the SIEM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextFeatures(Vec<ContextFeature>);

impl ContextFeatures {
    /// Keep the largest value for each (scope, name), sort, and cut to the bound, so the same inputs always make the same set.
    #[must_use]
    pub fn new(items: impl IntoIterator<Item = ContextFeature>) -> Self {
        let mut best: BTreeMap<(FeatureScope, String), ContextFeature> = BTreeMap::new();
        for item in items {
            let key = (item.scope, item.name.clone());
            match best.get(&key) {
                Some(kept) if kept.value >= item.value => {}
                _ => {
                    best.insert(key, item);
                }
            }
        }
        Self(best.into_values().take(MAX_CONTEXT_FEATURES).collect())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ContextFeature] {
        &self.0
    }

    /// The value of a feature, if the decision has it.
    #[must_use]
    pub fn get(&self, scope: FeatureScope, name: &str) -> Option<u32> {
        self.0
            .iter()
            .find(|f| f.scope == scope && f.name == name)
            .map(|f| f.value)
    }
}

/// Context passed into the pure detector evaluation.
#[derive(Debug, Clone)]
pub struct DetectorContext<'a> {
    pub epoch: &'a EpochRecord,
    pub baseline: &'a BaselineProfile,
    pub window: &'a WindowSnapshot,
    pub credentialed_endpoint: bool,
    /// Fresh SIEM risk features for this decision. Empty unless the SIEM has published some.
    pub features: ContextFeatures,
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
/// What a network-path gate needs to know about a sandbox's workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkState {
    /// An operator has quarantined the workload: it gets no network, whatever it has or has not done.
    pub quarantined: bool,
    /// The workload holds at least one strict-epoch restriction (some scope is latched). Scoped, so blunt as a network signal.
    pub restricted: bool,
    /// When Risk Guard last recorded a request decision for this sandbox's active epoch (its own clock), if it ever has.
    pub last_decision_ms: Option<i64>,
}

/// Everything needed to attach a freshly created sandbox to a workload.
#[derive(Debug, Clone, Copy)]
pub struct SandboxBinding<'a> {
    pub sandbox_id: &'a str,
    pub gateway_id: &'a str,
    pub agent_id: &'a str,
    pub agent_revision: &'a str,
    pub run_id: &'a str,
    /// Create the workload if nobody registered it.
    pub auto_register: bool,
    pub display_name: Option<&'a str>,
    /// The workspace the sandbox was created in. A workload scoped to a different
    /// workspace refuses the bind.
    pub workspace: &'a str,
    /// Scope the workload to `workspace` if it has no scope yet. True for workloads derived
    /// from the workspace and principal, whose ID already encodes the workspace.
    pub claim_workspace: bool,
}

/// One attempt to attach a sandbox to a workload, kept as evidence of who did it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingAudit {
    pub sandbox_id: String,
    pub workspace: String,
    pub principal_kind: String,
    pub principal_provider: String,
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
    fn auto_bind_sandbox_epoch(&self, _binding: &SandboxBinding) -> Result<()> {
        Ok(())
    }
    /// The baseline profile a sandbox's active epoch is pinned to; `None` if it has no active epoch.
    /// Record that a sandbox opened a tunnel after its supervisor had gone quiet. Best effort evidence for an operator; the default does nothing.
    fn record_supervisor_silence(
        &self,
        _sandbox_id: &str,
        _destination: &str,
        _silent_ms: i64,
        _mode: &str,
        _now_ms: i64,
    ) -> Result<()> {
        Ok(())
    }
    fn sandbox_baseline(&self, _sandbox_id: &str) -> Result<Option<BaselineProfile>> {
        Ok(None)
    }
    /// What the network path needs to know about a sandbox; `None` if Risk Guard has no active epoch for it.
    fn sandbox_network_state(&self, _sandbox_id: &str) -> Result<Option<NetworkState>> {
        Ok(None)
    }
    /// Append one workload-binding attempt (accepted or refused) to the audit trail.
    fn record_binding_audit(&self, _entry: &BindingAudit) -> Result<()> {
        Ok(())
    }
    /// Binding attempts for one sandbox, oldest first.
    fn list_binding_audit(&self, _sandbox_id: &str) -> Result<Vec<BindingAudit>> {
        Ok(Vec::new())
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

    // A frozen contract between the sidecar's parts; the argument list is the contract.
    #[allow(clippy::too_many_arguments)]
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

#[cfg(test)]
mod egress_tests {
    use super::*;

    fn profile(hosts: &[&str]) -> BaselineProfile {
        let mut profile = crate::fixture::build_standard_corpus().default_baseline;
        profile.approved_egress_hosts = hosts.iter().map(|host| (*host).to_string()).collect();
        profile
    }

    #[test]
    fn an_empty_list_approves_everything_and_a_listed_name_only_itself_or_its_subdomains() {
        assert!(profile(&[]).egress_host_allowed("anything.example.com"));
        assert!(profile(&[]).egress_host_allowed("203.0.113.7"));

        let p = profile(&["integrate.api.nvidia.com", "*.example.org"]);
        assert!(p.egress_host_allowed("integrate.api.nvidia.com"));
        assert!(
            p.egress_host_allowed("INTEGRATE.API.NVIDIA.COM."),
            "case and a trailing dot do not matter"
        );
        assert!(p.egress_host_allowed("api.example.org"));
        assert!(p.egress_host_allowed("a.b.example.org"));
        assert!(
            !p.egress_host_allowed("example.org"),
            "a wildcard does not match its apex"
        );
        assert!(
            !p.egress_host_allowed("evil-example.org"),
            "nor a name that merely ends the same way"
        );
        assert!(!p.egress_host_allowed("integrate.api.nvidia.com.evil.net"));
        assert!(!p.egress_host_allowed("api.nvidia.com"));
        assert!(
            !p.egress_host_allowed("93.184.216.34"),
            "an address cannot be matched to a name"
        );
        assert!(!p.egress_host_allowed(""));
    }

    #[test]
    fn the_list_must_be_well_formed_and_an_empty_one_leaves_the_hash_alone() {
        for bad in [
            "https://api.example.com",
            "api.example.com:443",
            "api.example.com/path",
            "Api.Example.com",
            "localhost",
            "10.0.0.1",
            "*.",
            "*",
            "-a.example.com",
            "a..example.com",
        ] {
            assert!(
                profile(&[bad]).validate_egress_hosts().is_err(),
                "{bad} must be refused"
            );
        }
        assert!(
            profile(&["a.example.com", "*.b.example.com"])
                .validate_egress_hosts()
                .is_ok()
        );

        let none = profile(&[]);
        assert!(
            !serde_json::to_string(&none)
                .unwrap()
                .contains("approved_egress_hosts")
        );
        let with = profile(&["a.example.com"]);
        assert_ne!(
            crate::detector::compute_baseline_hash(&none),
            crate::detector::compute_baseline_hash(&with)
        );
    }
}
