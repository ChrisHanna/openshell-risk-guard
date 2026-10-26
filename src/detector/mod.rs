// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Interaction-aware anomaly detector and baseline loader (Wave 1 - `t03-detector-scoring`).

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod siem;

use crate::error::{Result, RiskGuardError};
use crate::types::{
    BaselineMaturity, BaselineProfile, DecisionOutcome, DetectorContext, EnforcementMode,
    NormalizedRequest, REASON_BEHAVIORAL_RISK_DENIED, REASON_TASK_CONSTRAINT_DENIED,
    RULE_FORBIDDEN_ACTION, RULE_SIEM_CONTEXT, RULE_UNAPPROVED_ACTION, RULE_UNAPPROVED_RESOURCE,
    RULE_UNFAMILIAR_HIGH_IMPACT, RatchetAction, RiskDetector, RiskEvaluation, RuleMode,
    SignalContribution,
};

/// A task rule that a request tripped, and the mode it was running in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleHit {
    rule: &'static str,
    mode: RuleMode,
    detail: String,
}

/// Default observation alert threshold ($S \ge 20$).
pub const DEFAULT_OBSERVE_THRESHOLD: u32 = 20;

/// Default enforcement denial threshold ($S \ge 70$).
pub const DEFAULT_ENFORCE_THRESHOLD: u32 = 70;

/// Default Tier 2 cooldown window duration in milliseconds (5 minutes).
pub const DEFAULT_COOLDOWN_DURATION_MS: i64 = 300_000;

/// Stable reason code when a request is allowed with an observation alert ($20 \le S < 70$).
pub const REASON_BEHAVIORAL_RISK_OBSERVED: &str = "behavioral_risk_observed";

/// Stable reason code when a baseline profile has insufficient support for statistical enforcement.
pub const REASON_BASELINE_INSUFFICIENT: &str = "baseline_insufficient";

/// Stable reason code when a request is within normal behavioral bounds ($S < 20$).
pub const REASON_OK: &str = "ok";

/// Version identifier for the interaction-aware risk detector. It did NOT change when the `siem_context` rule (R1 to R4, see `siem`) was added, on purpose: the rule is
/// purely additive (with no SIEM features, or while it only watches, a decision scores exactly as before), and it can change an outcome only after a profile's baseline sets
/// it to enforce, which changes the baseline hash and so starts a new scoring context anyway. Changing this identifier would instead refuse every run that started before an
/// upgrade ("scoring configuration no longer matches its immutable binding"), and long-lived workloads (the SVID listener's, with a fixed run id) cannot start a new one.
pub const DETECTOR_VERSION: &str = "interaction-v1";

/// Scoring variant for comparative evaluation and ablation studies (`t10-eval-benchmark-harness`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoringVariant {
    /// Full contextual interaction-aware detector ($N_r, N_a, T, I, N_r \cdot I, C, V, F$ + Layer A).
    #[default]
    FullContextual,
    /// Novelty-only detector ($N_r$ and $N_a$ only, without semantic impact, rate, or Layer A rules).
    NoveltyOnly,
    /// Layer A operator task-constraint rules only, without learned behavioral history.
    TaskConstraintOnly,
    /// Contextual detector without the $15(N_r \cdot I)$ cross-resource impact interaction term.
    WithoutInteractionTerm,
}

impl ScoringVariant {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullContextual => "full_contextual",
            Self::NoveltyOnly => "novelty_only",
            Self::TaskConstraintOnly => "task_constraint_only",
            Self::WithoutInteractionTerm => "without_interaction_term",
        }
    }
}

/// Deterministic SHA-256 hex digest of a [`BaselineProfile`].
#[must_use]
pub fn compute_baseline_hash(profile: &BaselineProfile) -> String {
    let canonical = serde_json::to_vec(profile).unwrap_or_default();
    let digest = Sha256::digest(&canonical);
    hex::encode(digest)
}

/// Load a [`BaselineProfile`] from a JSON or YAML string.
pub fn parse_baseline_profile(raw: &str) -> Result<BaselineProfile> {
    let profile = match serde_json::from_str::<BaselineProfile>(raw) {
        Ok(profile) => profile,
        Err(_) => serde_yml::from_str::<BaselineProfile>(raw).map_err(|err| {
            RiskGuardError::InvalidArgument(format!("invalid baseline profile: {err}"))
        })?,
    };
    profile
        .validate_egress_hosts()
        .map_err(RiskGuardError::InvalidArgument)?;
    Ok(profile)
}

/// Load a [`BaselineProfile`] from disk (JSON or YAML).
pub fn load_baseline_profile(path: impl AsRef<Path>) -> Result<BaselineProfile> {
    let path_ref = path.as_ref();
    let raw = std::fs::read_to_string(path_ref).map_err(|err| {
        RiskGuardError::InvalidArgument(format!(
            "failed to read baseline profile '{}': {err}",
            path_ref.display()
        ))
    })?;
    parse_baseline_profile(&raw)
}

/// Pure, deterministic interaction-aware behavioral risk detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionRiskDetector {
    pub observe_threshold: u32,
    pub enforce_threshold: u32,
    pub cooldown_duration_ms: i64,
    pub variant: ScoringVariant,
}

impl Default for InteractionRiskDetector {
    fn default() -> Self {
        Self::new_default()
    }
}

impl InteractionRiskDetector {
    /// Construct an [`InteractionRiskDetector`] with default thresholds (`20` / `70`),
    /// 5-minute Tier 2 cooldown (`300_000` ms), and [`ScoringVariant::FullContextual`].
    #[must_use]
    pub const fn new_default() -> Self {
        Self {
            observe_threshold: DEFAULT_OBSERVE_THRESHOLD,
            enforce_threshold: DEFAULT_ENFORCE_THRESHOLD,
            cooldown_duration_ms: DEFAULT_COOLDOWN_DURATION_MS,
            variant: ScoringVariant::FullContextual,
        }
    }

    /// Construct an [`InteractionRiskDetector`] with explicit thresholds and cooldown duration.
    #[must_use]
    pub const fn new(
        observe_threshold: u32,
        enforce_threshold: u32,
        cooldown_duration_ms: i64,
    ) -> Self {
        Self {
            observe_threshold,
            enforce_threshold,
            cooldown_duration_ms,
            variant: ScoringVariant::FullContextual,
        }
    }

    /// Construct an [`InteractionRiskDetector`] configured for a specific [`ScoringVariant`].
    #[must_use]
    pub const fn with_variant(variant: ScoringVariant) -> Self {
        Self {
            observe_threshold: DEFAULT_OBSERVE_THRESHOLD,
            enforce_threshold: DEFAULT_ENFORCE_THRESHOLD,
            cooldown_duration_ms: DEFAULT_COOLDOWN_DURATION_MS,
            variant,
        }
    }

    /// Builder helper to override the [`ScoringVariant`].
    #[must_use]
    pub const fn variant(mut self, variant: ScoringVariant) -> Self {
        self.variant = variant;
        self
    }

    /// Builder helper to override `(observe_threshold, enforce_threshold)`.
    #[must_use]
    pub const fn with_thresholds(mut self, observe_threshold: u32, enforce_threshold: u32) -> Self {
        self.observe_threshold = observe_threshold;
        self.enforce_threshold = enforce_threshold;
        self
    }

    /// Builder helper to override `cooldown_duration_ms`.
    #[must_use]
    pub const fn with_cooldown_duration_ms(mut self, cooldown_duration_ms: i64) -> Self {
        self.cooldown_duration_ms = cooldown_duration_ms;
        self
    }

    /// Compute the deterministic SHA-256 hex digest of a [`BaselineProfile`].
    #[must_use]
    pub fn compute_baseline_hash(profile: &BaselineProfile) -> String {
        compute_baseline_hash(profile)
    }

    /// Every task rule this request trips, with the mode each runs in. Rules set to `off` are left out.
    ///
    /// These are the operator's declared task, not learned behavior, so they apply from the first request whatever the
    /// baseline's maturity. An empty approved list means "not specified" and trips nothing: it never blocks everything.
    fn rule_hits(&self, req: &NormalizedRequest, baseline: &BaselineProfile) -> Vec<RuleHit> {
        if matches!(self.variant, ScoringVariant::NoveltyOnly) {
            return Vec::new();
        }
        let mut hits = Vec::new();
        let mut hit = |rule: &'static str, detail: String| {
            let mode = baseline.rule_mode(rule);
            if mode != RuleMode::Off {
                hits.push(RuleHit { rule, mode, detail });
            }
        };

        let forbidden_action = baseline
            .forbidden_action_classes
            .contains(&req.action_class)
            || baseline.forbidden_action_classes.iter().any(|pattern| {
                pattern
                    .strip_suffix('*')
                    .is_some_and(|prefix| req.action_class.starts_with(prefix))
            });
        if forbidden_action {
            hit(
                RULE_FORBIDDEN_ACTION,
                format!("{} is on the forbidden list", req.action_class),
            );
        }

        let resource_approved = baseline.approved_resources.contains(&req.resource_id);
        if !resource_approved && req.high_impact {
            hit(
                RULE_UNFAMILIAR_HIGH_IMPACT,
                format!(
                    "{} is high-impact on {}, which the task does not approve",
                    req.action_class, req.resource_id
                ),
            );
        }
        if !baseline.allowed_action_classes.is_empty()
            && !baseline.allowed_action_classes.contains(&req.action_class)
        {
            hit(
                RULE_UNAPPROVED_ACTION,
                format!(
                    "{} is not in the task's {} approved actions",
                    req.action_class,
                    baseline.allowed_action_classes.len()
                ),
            );
        }
        if !baseline.approved_resources.is_empty() && !resource_approved {
            hit(
                RULE_UNAPPROVED_RESOURCE,
                format!(
                    "{} is not among the task's {} approved resources",
                    req.resource_id,
                    baseline.approved_resources.len()
                ),
            );
        }
        hits
    }
}

impl RiskDetector for InteractionRiskDetector {
    fn configuration_id(&self) -> String {
        let configuration = format!(
            "{}:{}:{}:{}:{}",
            self.detector_version(),
            self.observe_threshold,
            self.enforce_threshold,
            self.cooldown_duration_ms,
            self.variant.as_str()
        );
        hex::encode(Sha256::digest(configuration.as_bytes()))
    }

    fn evaluate(
        &self,
        req: &NormalizedRequest,
        ctx: &DetectorContext<'_>,
    ) -> Result<RiskEvaluation> {
        let baseline = ctx.baseline;
        let maturity = baseline.maturity();
        let is_mature = maturity == BaselineMaturity::Mature;

        let mut missing_context = Vec::new();
        if req.binary_path.is_none() {
            missing_context.push("missing_process_identity".to_string());
        }
        if req.route_template == "unknown" {
            missing_context.push("unknown_route_template".to_string());
        }
        if ctx.window.warming {
            missing_context.push("window_warming".to_string());
        }

        // Raw feature indicators
        let n_r: u32 =
            u32::from(is_mature && !baseline.approved_resources.contains(&req.resource_id));
        let n_a: u32 =
            u32::from(is_mature && !baseline.allowed_action_classes.contains(&req.action_class));

        let t: u32 = match &req.binary_path {
            Some(bin) => {
                let bin_ok = baseline.expected_binaries.contains(bin)
                    || req
                        .ancestors
                        .iter()
                        .any(|anc| baseline.expected_binaries.contains(anc));
                u32::from(!bin_ok)
            }
            None => 0,
        };

        let i: u32 = u32::from(req.high_impact);
        let j_nr_i: u32 =
            u32::from(matches!(self.variant, ScoringVariant::FullContextual) && n_r == 1 && i == 1);
        let c: u32 = u32::from(ctx.credentialed_endpoint);

        let (v_tier, next_1m) = {
            let next = ctx.window.req_count_1m.saturating_add(1);
            if !ctx.window.warming && is_mature {
                let severe_floor = baseline.max_req_1m_p95.saturating_mul(5).max(20);
                let elevated_floor = baseline.max_req_1m_p95.saturating_mul(2).max(10);
                if next > baseline.max_req_1m_p99 && next >= severe_floor {
                    (2u32, next)
                } else if next > baseline.max_req_1m_p95 && next >= elevated_floor {
                    (1u32, next)
                } else {
                    (0u32, next)
                }
            } else {
                (0u32, next)
            }
        };

        let (f_tier, next_fanout) = {
            let next = ctx
                .window
                .distinct_resources_15m
                .saturating_add(u32::from(n_r == 1));
            if !ctx.window.warming && is_mature {
                let severe_floor = baseline
                    .max_distinct_resources_15m_p95
                    .saturating_mul(5)
                    .max(10);
                let elevated_floor = baseline
                    .max_distinct_resources_15m_p95
                    .saturating_mul(2)
                    .max(5);
                if next > baseline.max_distinct_resources_15m_p99 && next >= severe_floor {
                    (2u32, next)
                } else if next > baseline.max_distinct_resources_15m_p95 && next >= elevated_floor {
                    (1u32, next)
                } else {
                    (0u32, next)
                }
            } else {
                (0u32, next)
            }
        };

        // Low-and-slow credentialed enumeration interaction: when a caller paces requests below the 1-minute velocity threshold
        // (v_tier == 0) while hitting severe 15-minute resource fan-out (f_tier == 2) across unfamiliar resources (n_r == 1) on a
        // credentialed endpoint (c == 1), boost the fan-out contribution by +15 under FullContextual so 15(N_r) + 10(C) + 45(F) = 70.
        let slow_cred_enum_bonus = u32::from(
            matches!(self.variant, ScoringVariant::FullContextual)
                && v_tier == 0
                && f_tier == 2
                && n_r == 1
                && c == 1,
        ) * 15;

        // Per-feature contributions under the active ScoringVariant
        let (
            contrib_nr,
            contrib_na,
            contrib_t,
            contrib_i,
            contrib_j,
            contrib_c,
            contrib_v,
            contrib_f,
        ) = match self.variant {
            ScoringVariant::FullContextual => (
                15 * n_r,
                15 * n_a,
                20 * t,
                30 * i,
                15 * j_nr_i,
                10 * c,
                15 * v_tier,
                15 * f_tier + slow_cred_enum_bonus,
            ),
            ScoringVariant::WithoutInteractionTerm => (
                15 * n_r,
                15 * n_a,
                20 * t,
                30 * i,
                0,
                10 * c,
                15 * v_tier,
                15 * f_tier,
            ),
            ScoringVariant::NoveltyOnly => (15 * n_r, 15 * n_a, 0, 0, 0, 0, 0, 0),
            ScoringVariant::TaskConstraintOnly => (0, 0, 0, 0, 0, 0, 0, 0),
        };

        let raw_sum = contrib_nr
            + contrib_na
            + contrib_t
            + contrib_i
            + contrib_j
            + contrib_c
            + contrib_v
            + contrib_f;
        let score_without_siem = raw_sum.min(100);
        // SIEM risk features (rule `siem_context`): a pure function of the features in the context plus the request's unfamiliar/credentialed posture.
        // Off, or no features, or no rule firing: nothing changes at all. Watching works out the points and records them. Enforcing adds them before
        // the outcome is chosen. Points are never negative.
        let siem_mode = baseline.rule_mode(RULE_SIEM_CONTEXT);
        let unfamiliar_cred_or_fanout =
            n_r == 1 && (ctx.credentialed_endpoint || f_tier >= 1 || v_tier >= 1);
        let siem = if siem_mode != RuleMode::Off
            && matches!(
                self.variant,
                ScoringVariant::FullContextual | ScoringVariant::WithoutInteractionTerm
            ) {
            siem::adjustment_with_request(
                &ctx.features,
                baseline.siem_context_max_points,
                unfamiliar_cred_or_fanout,
            )
        } else {
            None
        };
        let siem_added = match (&siem, siem_mode) {
            (Some(adjustment), RuleMode::Enforce) => adjustment.points,
            _ => 0,
        };
        let score = raw_sum.saturating_add(siem_added).min(100);

        let support_summary = format!(
            "sessions={},requests={},maturity={:?}",
            baseline.training_sessions, baseline.training_requests, maturity
        );

        let mut signals = vec![
            SignalContribution {
                feature: "N_r".to_string(),
                observed_summary: req.resource_id.clone(),
                baseline_summary: format!(
                    "approved_resources({})",
                    baseline.approved_resources.len()
                ),
                contribution: contrib_nr,
                support: support_summary.clone(),
            },
            SignalContribution {
                feature: "N_a".to_string(),
                observed_summary: req.action_class.clone(),
                baseline_summary: format!(
                    "allowed_action_classes({})",
                    baseline.allowed_action_classes.len()
                ),
                contribution: contrib_na,
                support: support_summary.clone(),
            },
            SignalContribution {
                feature: "T".to_string(),
                observed_summary: req
                    .binary_path
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                baseline_summary: format!(
                    "expected_binaries({})",
                    baseline.expected_binaries.len()
                ),
                contribution: contrib_t,
                support: support_summary.clone(),
            },
            SignalContribution {
                feature: "I".to_string(),
                observed_summary: format!(
                    "high_impact={},category={}",
                    req.high_impact, req.semantic_category
                ),
                baseline_summary: "curated_api_semantics".to_string(),
                contribution: contrib_i,
                support: "static_semantic_map".to_string(),
            },
            SignalContribution {
                feature: "J_Nr_I".to_string(),
                observed_summary: format!("N_r={n_r},I={i}"),
                baseline_summary: "unfamiliar_resource_x_high_impact".to_string(),
                contribution: contrib_j,
                support: support_summary.clone(),
            },
            SignalContribution {
                feature: "C".to_string(),
                observed_summary: format!("credentialed={}", ctx.credentialed_endpoint),
                baseline_summary: "policy_credential_binding".to_string(),
                contribution: contrib_c,
                support: "policy_snapshot".to_string(),
            },
            SignalContribution {
                feature: "V".to_string(),
                observed_summary: format!("next_1m={next_1m},tier={v_tier}"),
                baseline_summary: format!(
                    "p95={},p99={}",
                    baseline.max_req_1m_p95, baseline.max_req_1m_p99
                ),
                contribution: contrib_v,
                support: support_summary.clone(),
            },
            SignalContribution {
                feature: "F".to_string(),
                observed_summary: format!("next_fanout_15m={next_fanout},tier={f_tier}"),
                baseline_summary: format!(
                    "p95={},p99={}",
                    baseline.max_distinct_resources_15m_p95,
                    baseline.max_distinct_resources_15m_p99
                ),
                contribution: contrib_f,
                support: support_summary,
            },
        ];

        let hits = self.rule_hits(req, baseline);
        // Shadow rules never change the outcome. Each one is recorded so an operator can see how many requests it would
        // have blocked before deciding to promote it.
        for shadow in hits.iter().filter(|h| h.mode == RuleMode::Shadow) {
            signals.push(SignalContribution {
                feature: "shadow_rule".to_string(),
                observed_summary: shadow.detail.clone(),
                baseline_summary: format!("rule={}; mode=shadow", shadow.rule),
                contribution: 0,
                support: "would_block".to_string(),
            });
        }
        if let Some(adjustment) = &siem {
            // "Changed" means the points move the score across the observe threshold, or across the enforce threshold once the baseline is mature.
            let crosses = |threshold: u32| {
                score_without_siem < threshold
                    && score_without_siem
                        .saturating_add(adjustment.points)
                        .min(100)
                        >= threshold
            };
            let changes =
                crosses(self.observe_threshold) || (is_mature && crosses(self.enforce_threshold));
            let enforcing = siem_mode == RuleMode::Enforce;
            signals.push(SignalContribution {
                feature: "siem_context".to_string(),
                observed_summary: adjustment
                    .hits
                    .iter()
                    .map(|hit| format!("{}(+{}): {}", hit.rule, hit.points, hit.detail))
                    .collect::<Vec<_>>()
                    .join("; "),
                baseline_summary: format!(
                    "rule={RULE_SIEM_CONTEXT}; mode={}; {}={}; changes_outcome={}; uncapped={}; max={}",
                    if enforcing { "enforce" } else { "shadow" },
                    if enforcing { "added" } else { "would_add" },
                    adjustment.points,
                    u8::from(changes),
                    adjustment.uncapped,
                    adjustment.max
                ),
                contribution: score.saturating_sub(score_without_siem),
                support: if enforcing {
                    "siem_features".to_string()
                } else {
                    "would_add".to_string()
                },
            });
        }
        let enforced: Vec<&RuleHit> = hits
            .iter()
            .filter(|h| h.mode == RuleMode::Enforce)
            .collect();
        let task_constraint_triggered = !enforced.is_empty();
        // The deny list and the high-impact rule are hard constraints. The approved-list rules are softer: they
        // latch the strict lock only for a high-impact request, and otherwise just deny the request.
        let hard_constraint = enforced
            .iter()
            .any(|h| matches!(h.rule, RULE_FORBIDDEN_ACTION | RULE_UNFAMILIAR_HIGH_IMPACT));

        let (risk_score, outcome, reason_code, ratchet_action) = if task_constraint_triggered {
            let final_score = score.max(if hard_constraint {
                85
            } else {
                self.enforce_threshold
            });
            signals.push(SignalContribution {
                feature: "task_constraint".to_string(),
                observed_summary: format!("{} on {}", req.action_class, req.resource_id),
                baseline_summary: format!(
                    "rules={}; forbidden_actions={},forbid_unfamiliar_high_impact={}",
                    enforced
                        .iter()
                        .map(|h| h.rule)
                        .collect::<Vec<_>>()
                        .join(","),
                    baseline.forbidden_action_classes.len(),
                    baseline.forbid_unfamiliar_high_impact
                ),
                contribution: final_score.saturating_sub(score),
                support: "operator_task_constraint".to_string(),
            });

            match ctx.epoch.mode {
                EnforcementMode::Enforce => (
                    final_score,
                    DecisionOutcome::Deny,
                    REASON_TASK_CONSTRAINT_DENIED.to_string(),
                    if hard_constraint || req.high_impact {
                        RatchetAction::LatchTier1StrictEpoch {
                            scope: req.restriction_scope.clone(),
                        }
                    } else {
                        // A low-impact miss against the approved lists denies that request and nothing more. A route
                        // cooldown would also block the approved resources and actions that share the route.
                        RatchetAction::None
                    },
                ),
                EnforcementMode::Observe => (
                    final_score,
                    DecisionOutcome::AllowWithObservation,
                    REASON_TASK_CONSTRAINT_DENIED.to_string(),
                    RatchetAction::None,
                ),
            }
        } else if maturity == BaselineMaturity::Insufficient {
            // Cold-start safety: never deny on statistical rarity/novelty alone.
            if score >= self.observe_threshold {
                (
                    score,
                    DecisionOutcome::AllowWithObservation,
                    REASON_BASELINE_INSUFFICIENT.to_string(),
                    RatchetAction::None,
                )
            } else {
                (
                    score,
                    DecisionOutcome::Allow,
                    REASON_BASELINE_INSUFFICIENT.to_string(),
                    RatchetAction::None,
                )
            }
        } else if score >= self.enforce_threshold {
            match ctx.epoch.mode {
                EnforcementMode::Enforce => {
                    let ratchet = if req.high_impact {
                        RatchetAction::LatchTier1StrictEpoch {
                            scope: req.restriction_scope.clone(),
                        }
                    } else {
                        RatchetAction::TriggerTier2Cooldown {
                            scope: format!(
                                "{}://{}:{} {} {}",
                                req.scheme, req.host, req.port, req.method, req.route_template
                            ),
                            cooldown_duration_ms: self.cooldown_duration_ms,
                        }
                    };
                    (
                        score,
                        DecisionOutcome::Deny,
                        REASON_BEHAVIORAL_RISK_DENIED.to_string(),
                        ratchet,
                    )
                }
                EnforcementMode::Observe => (
                    score,
                    DecisionOutcome::AllowWithObservation,
                    REASON_BEHAVIORAL_RISK_DENIED.to_string(),
                    RatchetAction::None,
                ),
            }
        } else if score >= self.observe_threshold {
            (
                score,
                DecisionOutcome::AllowWithObservation,
                REASON_BEHAVIORAL_RISK_OBSERVED.to_string(),
                RatchetAction::None,
            )
        } else {
            (
                score,
                DecisionOutcome::Allow,
                REASON_OK.to_string(),
                RatchetAction::None,
            )
        };

        let baseline_hash = compute_baseline_hash(baseline);

        Ok(RiskEvaluation {
            request_id: req.request_id.clone(),
            sandbox_id: req.sandbox_id.clone(),
            epoch_id: ctx.epoch.epoch_id.clone(),
            mode: ctx.epoch.mode,
            outcome,
            reason_code,
            risk_score,
            threshold: self.enforce_threshold,
            ratchet_action,
            signals,
            missing_context,
            baseline_maturity: maturity,
            baseline_hash,
            detector_version: self.detector_version().to_string(),
            state_sequence: ctx.epoch.next_sequence,
            decision_timestamp_ms: req.timestamp_ms,
        })
    }

    fn detector_version(&self) -> &str {
        match self.variant {
            ScoringVariant::FullContextual => DETECTOR_VERSION,
            ScoringVariant::NoveltyOnly => "interaction-v1-novelty-only",
            ScoringVariant::TaskConstraintOnly => "interaction-v1-task-constraint-only",
            ScoringVariant::WithoutInteractionTerm => "interaction-v1-no-interaction",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::types::EpochRecord;

    fn mature_triage_baseline() -> BaselineProfile {
        BaselineProfile {
            task_profile: "repo-triage-readonly".to_string(),
            version: "1.0.0".to_string(),
            approved_by: "secops@example.com".to_string(),
            normalizer_version: "norm-v1".to_string(),
            training_sessions: 25,
            training_requests: 500,
            expected_binaries: BTreeSet::from([
                "/usr/bin/curl".to_string(),
                "/usr/bin/gh".to_string(),
            ]),
            approved_resources: BTreeSet::from(["org/docs-site".to_string()]),
            allowed_action_classes: BTreeSet::from([
                "GET /repos/{owner}/{repo}".to_string(),
                "GET /repos/{owner}/{repo}/issues".to_string(),
            ]),
            forbidden_action_classes: BTreeSet::new(),
            forbid_unfamiliar_high_impact: false,
            rule_modes: std::collections::BTreeMap::new(),
            approved_egress_hosts: Default::default(),
            siem_context_max_points: None,
            max_req_1m_p95: 4,
            max_req_1m_p99: 8,
            max_distinct_resources_15m_p95: 2,
            max_distinct_resources_15m_p99: 4,
        }
    }

    fn make_epoch(mode: EnforcementMode, baseline: &BaselineProfile) -> EpochRecord {
        EpochRecord {
            epoch_id: "ep_01".to_string(),
            gateway_id: "gw_01".to_string(),
            sandbox_id: "sbx_01".to_string(),
            task_profile: baseline.task_profile.clone(),
            baseline_hash: compute_baseline_hash(baseline),
            mode,
            active: true,
            next_sequence: 1,
            created_at_ms: 1_700_000_000_000,
            credentialed_endpoints: BTreeSet::from([("api.github.local".to_string(), 18443)]),
            active_policy_hash: Some("pol_hash_01".to_string()),
        }
    }

    fn make_request(
        method: &str,
        route_template: &str,
        resource_id: &str,
        high_impact: bool,
        binary_path: Option<&str>,
    ) -> NormalizedRequest {
        let action_class = format!("{method} {route_template}");
        let restriction_scope =
            format!("https://api.github.local:18443 {method} {route_template} {resource_id}");
        NormalizedRequest {
            request_id: "req_01".to_string(),
            sandbox_id: "sbx_01".to_string(),
            scheme: "https".to_string(),
            host: "api.github.local".to_string(),
            port: 18443,
            method: method.to_string(),
            route_template: route_template.to_string(),
            resource_id: resource_id.to_string(),
            resource_key: format!("hmac_{resource_id}"),
            action_class,
            restriction_scope,
            high_impact,
            semantic_category: if high_impact {
                "destructive_admin".to_string()
            } else {
                "read_only".to_string()
            },
            binary_path: binary_path.map(str::to_string),
            ancestors: vec!["/bin/bash".to_string()],
            fingerprint: "fp_01".to_string(),
            timestamp_ms: 1_700_000_001_000,
        }
    }

    #[test]
    fn scenario_1_benign_novel_read_allows_with_observation_score_25() {
        let detector = InteractionRiskDetector::new_default();
        let baseline = mature_triage_baseline();
        let epoch = make_epoch(EnforcementMode::Enforce, &baseline);
        let window = crate::types::WindowSnapshot::default();
        let req = make_request(
            "GET",
            "/repos/{owner}/{repo}",
            "org/new-docs",
            false,
            Some("/usr/bin/curl"),
        );

        let ctx = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };

        let eval = detector.evaluate(&req, &ctx).expect("evaluate");
        assert_eq!(eval.risk_score, 25);
        assert_eq!(eval.outcome, DecisionOutcome::AllowWithObservation);
        assert_eq!(eval.reason_code, REASON_BEHAVIORAL_RISK_OBSERVED);
        assert_eq!(eval.ratchet_action, RatchetAction::None);
        assert!(eval.missing_context.is_empty());
    }

    #[test]
    fn scenario_2_flagship_attack_expected_curl_denies_score_85_and_latches_tier1() {
        let detector = InteractionRiskDetector::new_default();
        let baseline = mature_triage_baseline();
        let epoch = make_epoch(EnforcementMode::Enforce, &baseline);
        let window = crate::types::WindowSnapshot::default();
        let req = make_request(
            "DELETE",
            "/repos/{owner}/{repo}",
            "org/payments-prod",
            true,
            Some("/usr/bin/curl"),
        );

        let ctx = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };

        let eval = detector.evaluate(&req, &ctx).expect("evaluate");
        assert_eq!(eval.risk_score, 85);
        assert_eq!(eval.outcome, DecisionOutcome::Deny);
        assert_eq!(eval.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
        assert_eq!(
            eval.ratchet_action,
            RatchetAction::LatchTier1StrictEpoch {
                scope: req.restriction_scope.clone()
            }
        );

        // Even without credentialed endpoint (C = 0), score is 75 >= 70 and still denies.
        let ctx_no_cred = DetectorContext {
            credentialed_endpoint: false,
            features: Default::default(),
            ..ctx
        };
        let eval_no_cred = detector.evaluate(&req, &ctx_no_cred).expect("evaluate");
        assert_eq!(eval_no_cred.risk_score, 75);
        assert_eq!(eval_no_cred.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn scenario_3_unexpected_binary_plus_mutation_denies_score_75_and_latches_tier1() {
        let detector = InteractionRiskDetector::new_default();
        let baseline = mature_triage_baseline();
        let epoch = make_epoch(EnforcementMode::Enforce, &baseline);
        let window = crate::types::WindowSnapshot::default();
        let req = make_request(
            "PUT",
            "/repos/{owner}/{repo}/contents/{path}",
            "org/docs-site",
            true,
            Some("/usr/bin/python3"),
        );

        let ctx = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };

        let eval = detector.evaluate(&req, &ctx).expect("evaluate");
        assert_eq!(eval.risk_score, 75);
        assert_eq!(eval.outcome, DecisionOutcome::Deny);
        assert_eq!(eval.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
        assert_eq!(
            eval.ratchet_action,
            RatchetAction::LatchTier1StrictEpoch {
                scope: req.restriction_scope.clone()
            }
        );
    }

    #[test]
    fn scenario_4_rapid_cross_repo_enumeration_denies_score_85_and_triggers_tier2_cooldown() {
        let detector = InteractionRiskDetector::new_default();
        let baseline = mature_triage_baseline();
        let epoch = make_epoch(EnforcementMode::Enforce, &baseline);
        let window = crate::types::WindowSnapshot {
            req_count_1m: 29,
            req_count_15m: 29,
            distinct_resources_1m: 29,
            distinct_resources_15m: 29,
            warming: false,
        };
        let req = make_request(
            "GET",
            "/repos/{owner}/{repo}",
            "org/repo-30",
            false,
            Some("/usr/bin/gh"),
        );

        let ctx = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };

        let eval = detector.evaluate(&req, &ctx).expect("evaluate");
        assert_eq!(eval.risk_score, 85);
        assert_eq!(eval.outcome, DecisionOutcome::Deny);
        assert_eq!(eval.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
        assert_eq!(
            eval.ratchet_action,
            RatchetAction::TriggerTier2Cooldown {
                scope: "https://api.github.local:18443 GET /repos/{owner}/{repo}".to_string(),
                cooldown_duration_ms: DEFAULT_COOLDOWN_DURATION_MS,
            }
        );
    }

    #[test]
    fn scenario_5_approved_maintenance_task_allows_score_40() {
        let detector = InteractionRiskDetector::new_default();
        let mut baseline = mature_triage_baseline();
        baseline.task_profile = "repo-maintenance-cleanup".to_string();
        baseline
            .approved_resources
            .insert("org/staging-sandbox".to_string());
        baseline
            .allowed_action_classes
            .insert("DELETE /repos/{owner}/{repo}".to_string());
        baseline.forbid_unfamiliar_high_impact = true;

        let epoch = make_epoch(EnforcementMode::Enforce, &baseline);
        let window = crate::types::WindowSnapshot::default();
        let req = make_request(
            "DELETE",
            "/repos/{owner}/{repo}",
            "org/staging-sandbox",
            true,
            Some("/usr/bin/gh"),
        );

        let ctx = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };

        let eval = detector.evaluate(&req, &ctx).expect("evaluate");
        assert_eq!(eval.risk_score, 40);
        assert_eq!(eval.outcome, DecisionOutcome::AllowWithObservation);
        assert_eq!(eval.reason_code, REASON_BEHAVIORAL_RISK_OBSERVED);
        assert_eq!(eval.ratchet_action, RatchetAction::None);
    }

    #[test]
    fn cold_start_insufficient_baseline_does_not_deny_without_layer_a_constraint() {
        let detector = InteractionRiskDetector::new_default();
        let mut baseline = mature_triage_baseline();
        baseline.training_sessions = 5;
        baseline.training_requests = 40;
        assert_eq!(baseline.maturity(), BaselineMaturity::Insufficient);

        let epoch = make_epoch(EnforcementMode::Enforce, &baseline);
        let window = crate::types::WindowSnapshot {
            req_count_1m: 100,
            req_count_15m: 100,
            distinct_resources_1m: 50,
            distinct_resources_15m: 50,
            warming: false,
        };
        // Even with unexpected binary (20) + high impact (30) + credentialed (10) = 60,
        // and even if enforce_threshold were lowered to 50, cold start must not deny on statistical signals alone.
        let strict_detector = detector.clone().with_thresholds(20, 50);
        let req = make_request(
            "DELETE",
            "/repos/{owner}/{repo}",
            "org/unseen-repo",
            true,
            Some("/usr/bin/python3"),
        );

        let ctx = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };

        let eval = strict_detector.evaluate(&req, &ctx).expect("evaluate");
        assert_eq!(eval.baseline_maturity, BaselineMaturity::Insufficient);
        assert_eq!(eval.risk_score, 60);
        assert_eq!(eval.outcome, DecisionOutcome::AllowWithObservation);
        assert_eq!(eval.reason_code, REASON_BASELINE_INSUFFICIENT);
        assert_eq!(eval.ratchet_action, RatchetAction::None);

        // Layer A task_constraint DOES still enforce during cold start.
        baseline.forbid_unfamiliar_high_impact = true;
        let ctx_layer_a = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };
        let eval_layer_a = detector.evaluate(&req, &ctx_layer_a).expect("evaluate");
        assert_eq!(eval_layer_a.risk_score, 85);
        assert_eq!(eval_layer_a.outcome, DecisionOutcome::Deny);
        assert_eq!(eval_layer_a.reason_code, REASON_TASK_CONSTRAINT_DENIED);
        assert_eq!(
            eval_layer_a.ratchet_action,
            RatchetAction::LatchTier1StrictEpoch {
                scope: req.restriction_scope.clone()
            }
        );
    }

    #[test]
    fn missing_context_and_ancestor_binary_allowance_behave_as_specified() {
        let detector = InteractionRiskDetector::new_default();
        let baseline = mature_triage_baseline();
        let epoch = make_epoch(EnforcementMode::Enforce, &baseline);
        let window = crate::types::WindowSnapshot {
            req_count_1m: 50,
            req_count_15m: 50,
            distinct_resources_1m: 30,
            distinct_resources_15m: 30,
            warming: true,
        };

        let mut req = make_request("GET", "unknown", "org/docs-site", false, None);
        req.action_class = "GET /repos/{owner}/{repo}".to_string();

        let ctx = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: false,
            features: Default::default(),
        };

        let eval = detector.evaluate(&req, &ctx).expect("evaluate");
        assert_eq!(eval.risk_score, 0);
        assert_eq!(eval.outcome, DecisionOutcome::Allow);
        assert_eq!(
            eval.missing_context,
            vec![
                "missing_process_identity".to_string(),
                "unknown_route_template".to_string(),
                "window_warming".to_string()
            ]
        );

        // If binary_path is unfamiliar but an ancestor is in expected_binaries, T == 0.
        let mut req_with_anc = make_request(
            "GET",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            false,
            Some("/usr/lib/git-core/git-remote-https"),
        );
        req_with_anc.ancestors = vec!["/usr/bin/gh".to_string()];
        let eval_anc = detector.evaluate(&req_with_anc, &ctx).expect("evaluate");
        assert_eq!(eval_anc.risk_score, 0);
    }

    #[test]
    fn scoring_variants_support_ablation_comparators() {
        let mut baseline = mature_triage_baseline();
        baseline.forbid_unfamiliar_high_impact = true;
        let epoch = make_epoch(EnforcementMode::Enforce, &baseline);
        let window = crate::types::WindowSnapshot::default();

        // Known action class on unfamiliar resource with high impact and C=1:
        // N_r=1 (15), N_a=0 (0), T=0 (0), I=1 (30), J_Nr_I=1 (15), C=1 (10) -> Full = 70 vs WithoutInteraction = 55
        let mut baseline_no_layer_a = baseline.clone();
        baseline_no_layer_a.forbid_unfamiliar_high_impact = false;
        baseline_no_layer_a
            .allowed_action_classes
            .insert("DELETE /repos/{owner}/{repo}".to_string());

        let req = make_request(
            "DELETE",
            "/repos/{owner}/{repo}",
            "org/payments-prod",
            true,
            Some("/usr/bin/curl"),
        );

        let ctx_no_layer_a = DetectorContext {
            epoch: &epoch,
            baseline: &baseline_no_layer_a,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };

        let full_eval = InteractionRiskDetector::with_variant(ScoringVariant::FullContextual)
            .evaluate(&req, &ctx_no_layer_a)
            .expect("full");
        assert_eq!(full_eval.risk_score, 70);
        assert_eq!(full_eval.outcome, DecisionOutcome::Deny);

        let no_inter_eval =
            InteractionRiskDetector::with_variant(ScoringVariant::WithoutInteractionTerm)
                .evaluate(&req, &ctx_no_layer_a)
                .expect("no interaction");
        assert_eq!(no_inter_eval.risk_score, 55);
        assert_eq!(no_inter_eval.outcome, DecisionOutcome::AllowWithObservation);

        let novelty_eval = InteractionRiskDetector::with_variant(ScoringVariant::NoveltyOnly)
            .evaluate(&req, &ctx_no_layer_a)
            .expect("novelty only");
        assert_eq!(novelty_eval.risk_score, 15);
        assert_eq!(novelty_eval.outcome, DecisionOutcome::Allow);

        let ctx_with_layer_a = DetectorContext {
            epoch: &epoch,
            baseline: &baseline,
            window: &window,
            credentialed_endpoint: true,
            features: Default::default(),
        };
        let tc_eval = InteractionRiskDetector::with_variant(ScoringVariant::TaskConstraintOnly)
            .evaluate(&req, &ctx_with_layer_a)
            .expect("task constraint only");
        assert_eq!(tc_eval.risk_score, 85);
        assert_eq!(tc_eval.outcome, DecisionOutcome::Deny);
        assert_eq!(tc_eval.reason_code, REASON_TASK_CONSTRAINT_DENIED);
    }

    #[test]
    fn observe_mode_and_velocity_fanout_tiers_and_cap_work_accurately() {
        let detector = InteractionRiskDetector::new_default();
        let mut baseline = mature_triage_baseline();
        baseline
            .forbidden_action_classes
            .insert("DELETE /repos/{owner}/{repo}".to_string());
        let epoch_observe = make_epoch(EnforcementMode::Observe, &baseline);

        // Layer A in Observe mode -> AllowWithObservation, RatchetAction::None
        let req_forbidden = make_request(
            "DELETE",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            true,
            Some("/usr/bin/curl"),
        );
        let window_default = crate::types::WindowSnapshot::default();
        let ctx_obs = DetectorContext {
            epoch: &epoch_observe,
            baseline: &baseline,
            window: &window_default,
            credentialed_endpoint: true,
            features: Default::default(),
        };
        let eval_obs = detector
            .evaluate(&req_forbidden, &ctx_obs)
            .expect("observe");
        assert_eq!(eval_obs.risk_score, 85);
        assert_eq!(eval_obs.outcome, DecisionOutcome::AllowWithObservation);
        assert_eq!(eval_obs.reason_code, REASON_TASK_CONSTRAINT_DENIED);
        assert_eq!(eval_obs.ratchet_action, RatchetAction::None);

        // V = 1 (next_1m = 10 > p95(4) and >= max(2*4, 10)=10, but <= p99(8) is false though < severe_floor(20))
        // F = 1 (next_fanout = 5 > p95(2) and >= max(2*2, 5)=5, < severe_floor(10))
        let window_t1 = crate::types::WindowSnapshot {
            req_count_1m: 9,
            req_count_15m: 9,
            distinct_resources_1m: 4,
            distinct_resources_15m: 4,
            warming: false,
        };
        let req_read = make_request(
            "GET",
            "/repos/{owner}/{repo}",
            "org/new-repo",
            false,
            Some("/usr/bin/curl"),
        );
        let ctx_t1 = DetectorContext {
            epoch: &epoch_observe,
            baseline: &baseline,
            window: &window_t1,
            credentialed_endpoint: false,
            features: Default::default(),
        };
        // N_r=1 (15) + V=1 (15) + F=1 (15) = 45
        let eval_t1 = detector
            .evaluate(&req_read, &ctx_t1)
            .expect("tier 1 rate/fanout");
        assert_eq!(eval_t1.risk_score, 45);
        assert_eq!(eval_t1.outcome, DecisionOutcome::AllowWithObservation);
        assert_eq!(eval_t1.reason_code, REASON_BEHAVIORAL_RISK_OBSERVED);

        // Score cap at 100 when all signals fire simultaneously
        let window_t2 = crate::types::WindowSnapshot {
            req_count_1m: 25,
            req_count_15m: 25,
            distinct_resources_1m: 15,
            distinct_resources_15m: 15,
            warming: false,
        };
        let mut baseline_clean = mature_triage_baseline();
        baseline_clean.forbid_unfamiliar_high_impact = false;
        let epoch_enforce = make_epoch(EnforcementMode::Enforce, &baseline_clean);
        let req_all = make_request(
            "POST",
            "/repos/{owner}/{repo}/releases",
            "org/unseen-prod",
            true,
            Some("/usr/bin/python3"),
        );
        let ctx_all = DetectorContext {
            epoch: &epoch_enforce,
            baseline: &baseline_clean,
            window: &window_t2,
            credentialed_endpoint: true,
            features: Default::default(),
        };
        let eval_all = detector.evaluate(&req_all, &ctx_all).expect("cap 100");
        assert_eq!(eval_all.risk_score, 100);
        assert_eq!(eval_all.outcome, DecisionOutcome::Deny);

        // Low-and-slow credentialed enumeration (v_tier == 0, f_tier == 2, N_r == 1, C == 1) reaches 70 and triggers Tier-2 cooldown
        let window_slow_enum = crate::types::WindowSnapshot {
            req_count_1m: 2,
            req_count_15m: 20,
            distinct_resources_1m: 2,
            distinct_resources_15m: 15,
            warming: false,
        };
        let ctx_slow_enum = DetectorContext {
            epoch: &epoch_enforce,
            baseline: &baseline_clean,
            window: &window_slow_enum,
            credentialed_endpoint: true,
            features: Default::default(),
        };
        let eval_slow_enum = detector
            .evaluate(&req_read, &ctx_slow_enum)
            .expect("slow credentialed enumeration");
        assert_eq!(eval_slow_enum.risk_score, 70);
        assert_eq!(eval_slow_enum.outcome, DecisionOutcome::Deny);
        assert!(matches!(
            eval_slow_enum.ratchet_action,
            RatchetAction::TriggerTier2Cooldown { .. }
        ));
    }

    #[test]
    fn baseline_hash_and_parser_are_deterministic() {
        let b1 = mature_triage_baseline();
        let b2 = mature_triage_baseline();
        let h1 = compute_baseline_hash(&b1);
        let h2 = InteractionRiskDetector::compute_baseline_hash(&b2);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);

        let json_str = serde_json::to_string(&b1).expect("serialize json");
        let parsed = parse_baseline_profile(&json_str).expect("parse json");
        assert_eq!(compute_baseline_hash(&parsed), h1);
    }

    // ---- Rule modes: shadow by default, enforce only when promoted ----

    fn evaluate_rule(
        baseline: &BaselineProfile,
        mode: EnforcementMode,
        req: &NormalizedRequest,
    ) -> RiskEvaluation {
        let epoch = make_epoch(mode, baseline);
        let window = crate::types::WindowSnapshot::default();
        InteractionRiskDetector::new_default()
            .evaluate(
                req,
                &DetectorContext {
                    epoch: &epoch,
                    baseline,
                    window: &window,
                    credentialed_endpoint: false,
                    features: Default::default(),
                },
            )
            .expect("evaluate")
    }

    fn shadow_rules(eval: &RiskEvaluation) -> Vec<String> {
        eval.signals
            .iter()
            .filter(|s| s.feature == "shadow_rule")
            .map(|s| s.baseline_summary.clone())
            .collect()
    }

    /// An action the task does not list, on a resource it does approve (the gap the approved-action list used to leave).
    fn off_list_action_on_approved_resource(high_impact: bool) -> NormalizedRequest {
        make_request(
            if high_impact { "DELETE" } else { "POST" },
            "/repos/{owner}/{repo}/issues",
            "org/docs-site",
            high_impact,
            Some("/usr/bin/curl"),
        )
    }

    #[test]
    fn an_unapproved_action_is_only_recorded_while_its_rule_is_in_shadow() {
        let baseline = mature_triage_baseline();
        let eval = evaluate_rule(
            &baseline,
            EnforcementMode::Enforce,
            &off_list_action_on_approved_resource(false),
        );
        assert_ne!(
            eval.outcome,
            DecisionOutcome::Deny,
            "a shadow rule must never block"
        );
        assert_eq!(
            shadow_rules(&eval),
            vec!["rule=unapproved_action; mode=shadow"]
        );
        let signal = eval
            .signals
            .iter()
            .find(|s| s.feature == "shadow_rule")
            .unwrap();
        assert_eq!(signal.support, "would_block");
        assert_eq!(
            signal.contribution, 0,
            "a shadow rule adds nothing to the score"
        );
        assert!(eval.signals.iter().all(|s| s.feature != "task_constraint"));
    }

    #[test]
    fn promoting_the_approved_action_rule_blocks_it_and_only_locks_for_high_impact() {
        let mut baseline = mature_triage_baseline();
        baseline
            .rule_modes
            .insert(RULE_UNAPPROVED_ACTION.to_string(), RuleMode::Enforce);

        let low = off_list_action_on_approved_resource(false);
        let eval = evaluate_rule(&baseline, EnforcementMode::Enforce, &low);
        assert_eq!(eval.outcome, DecisionOutcome::Deny);
        assert_eq!(eval.reason_code, REASON_TASK_CONSTRAINT_DENIED);
        assert!(
            eval.risk_score >= DEFAULT_ENFORCE_THRESHOLD,
            "a block always shows a score at the block line"
        );
        assert!(
            shadow_rules(&eval).is_empty(),
            "an enforced rule is not also reported as shadow"
        );
        let why = eval
            .signals
            .iter()
            .find(|s| s.feature == "task_constraint")
            .unwrap();
        assert!(
            why.baseline_summary.starts_with("rules=unapproved_action;"),
            "{}",
            why.baseline_summary
        );
        assert_eq!(
            eval.ratchet_action,
            RatchetAction::None,
            "a low-impact miss denies that request without locking the route or the workload"
        );

        let high = off_list_action_on_approved_resource(true);
        let eval = evaluate_rule(&baseline, EnforcementMode::Enforce, &high);
        assert_eq!(eval.outcome, DecisionOutcome::Deny);
        assert_eq!(
            eval.ratchet_action,
            RatchetAction::LatchTier1StrictEpoch {
                scope: high.restriction_scope.clone()
            },
            "a high-impact miss latches the strict lock"
        );
    }

    #[test]
    fn the_approved_resource_rule_is_shadow_until_promoted() {
        let mut baseline = mature_triage_baseline();
        let req = make_request(
            "GET",
            "/repos/{owner}/{repo}",
            "org/new-docs",
            false,
            Some("/usr/bin/curl"),
        );
        let eval = evaluate_rule(&baseline, EnforcementMode::Enforce, &req);
        assert_ne!(eval.outcome, DecisionOutcome::Deny);
        assert_eq!(
            shadow_rules(&eval),
            vec!["rule=unapproved_resource; mode=shadow"]
        );

        baseline
            .rule_modes
            .insert(RULE_UNAPPROVED_RESOURCE.to_string(), RuleMode::Enforce);
        let eval = evaluate_rule(&baseline, EnforcementMode::Enforce, &req);
        assert_eq!(eval.outcome, DecisionOutcome::Deny);
        assert!(shadow_rules(&eval).is_empty());
    }

    #[test]
    fn an_observe_epoch_reports_an_enforced_rule_without_blocking() {
        let mut baseline = mature_triage_baseline();
        baseline
            .rule_modes
            .insert(RULE_UNAPPROVED_ACTION.to_string(), RuleMode::Enforce);
        let eval = evaluate_rule(
            &baseline,
            EnforcementMode::Observe,
            &off_list_action_on_approved_resource(false),
        );
        assert_eq!(eval.outcome, DecisionOutcome::AllowWithObservation);
        assert_eq!(eval.reason_code, REASON_TASK_CONSTRAINT_DENIED);
        assert_eq!(eval.ratchet_action, RatchetAction::None);
    }

    #[test]
    fn an_empty_approved_list_means_unspecified_and_never_blocks_everything() {
        let mut baseline = mature_triage_baseline();
        baseline.allowed_action_classes.clear();
        baseline.approved_resources.clear();
        baseline
            .rule_modes
            .insert(RULE_UNAPPROVED_ACTION.to_string(), RuleMode::Enforce);
        baseline
            .rule_modes
            .insert(RULE_UNAPPROVED_RESOURCE.to_string(), RuleMode::Enforce);
        let eval = evaluate_rule(
            &baseline,
            EnforcementMode::Enforce,
            &off_list_action_on_approved_resource(false),
        );
        assert_ne!(eval.outcome, DecisionOutcome::Deny);
        assert!(shadow_rules(&eval).is_empty());
        assert!(eval.signals.iter().all(|s| s.feature != "task_constraint"));
    }

    #[test]
    fn a_rule_set_to_off_leaves_no_trace() {
        let mut baseline = mature_triage_baseline();
        baseline
            .rule_modes
            .insert(RULE_UNAPPROVED_ACTION.to_string(), RuleMode::Off);
        baseline
            .rule_modes
            .insert(RULE_UNAPPROVED_RESOURCE.to_string(), RuleMode::Off);
        let eval = evaluate_rule(
            &baseline,
            EnforcementMode::Enforce,
            &off_list_action_on_approved_resource(false),
        );
        assert!(shadow_rules(&eval).is_empty());
        assert_ne!(eval.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn the_high_impact_rule_can_be_softened_to_shadow_but_the_deny_list_always_enforces() {
        let mut baseline = mature_triage_baseline();
        baseline.forbid_unfamiliar_high_impact = true;
        let delete = make_request(
            "DELETE",
            "/repos/{owner}/{repo}",
            "org/payments-prod",
            true,
            Some("/usr/bin/curl"),
        );
        assert_eq!(
            baseline.rule_mode(RULE_UNFAMILIAR_HIGH_IMPACT),
            RuleMode::Enforce
        );
        assert_eq!(
            evaluate_rule(&baseline, EnforcementMode::Enforce, &delete).reason_code,
            REASON_TASK_CONSTRAINT_DENIED
        );

        baseline
            .rule_modes
            .insert(RULE_UNFAMILIAR_HIGH_IMPACT.to_string(), RuleMode::Shadow);
        let soft = evaluate_rule(&baseline, EnforcementMode::Enforce, &delete);
        assert!(
            shadow_rules(&soft).contains(&"rule=unfamiliar_high_impact; mode=shadow".to_string())
        );
        assert!(soft.signals.iter().all(|s| s.feature != "task_constraint"));

        // The checkbox still turns the rule off, and an override cannot turn it on.
        baseline.forbid_unfamiliar_high_impact = false;
        baseline
            .rule_modes
            .insert(RULE_UNFAMILIAR_HIGH_IMPACT.to_string(), RuleMode::Enforce);
        assert_eq!(
            baseline.rule_mode(RULE_UNFAMILIAR_HIGH_IMPACT),
            RuleMode::Off
        );

        // The deny list ignores any override.
        let mut deny_list = mature_triage_baseline();
        deny_list
            .forbidden_action_classes
            .insert("DELETE /repos/{owner}/{repo}".to_string());
        deny_list
            .rule_modes
            .insert(RULE_FORBIDDEN_ACTION.to_string(), RuleMode::Off);
        assert_eq!(
            deny_list.rule_mode(RULE_FORBIDDEN_ACTION),
            RuleMode::Enforce
        );
        assert_eq!(
            evaluate_rule(&deny_list, EnforcementMode::Enforce, &delete).outcome,
            DecisionOutcome::Deny
        );
    }

    #[test]
    fn default_rule_modes_do_not_change_a_baseline_hash() {
        // Existing baselines, and the contexts and restrictions keyed by their hash, must not be orphaned.
        let baseline = mature_triage_baseline();
        let json = serde_json::to_string(&baseline).unwrap();
        assert!(
            !json.contains("rule_modes"),
            "an empty map is not serialized"
        );
        let parsed: BaselineProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(
            compute_baseline_hash(&parsed),
            compute_baseline_hash(&baseline)
        );

        let mut promoted = baseline.clone();
        promoted
            .rule_modes
            .insert(RULE_UNAPPROVED_ACTION.to_string(), RuleMode::Enforce);
        assert_ne!(
            compute_baseline_hash(&promoted),
            compute_baseline_hash(&baseline),
            "a promotion is a new profile"
        );
        let round_trip: BaselineProfile =
            serde_json::from_str(&serde_json::to_string(&promoted).unwrap()).unwrap();
        assert_eq!(
            round_trip.rule_mode(RULE_UNAPPROVED_ACTION),
            RuleMode::Enforce
        );
    }
}
