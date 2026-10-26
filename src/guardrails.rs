use std::collections::{BTreeMap, BTreeSet};

use openshell_policy_schema::FilesystemPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detector::InteractionRiskDetector;
use crate::error::{Result, RiskGuardError};
use crate::types::{BaselineProfile, CONFIGURABLE_RULES, EnforcementMode, RuleMode};

pub const MAX_FANOUT_ENVELOPE: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentGuardrails {
    pub task_profile: String,
    pub mode: EnforcementMode,
    pub observe_threshold: u32,
    pub enforce_threshold: u32,
    pub cooldown_seconds: u32,
    pub approved_resources: BTreeSet<String>,
    pub allowed_action_classes: BTreeSet<String>,
    pub forbid_unfamiliar_high_impact: bool,
    /// Per-rule shadow or enforce choice. Omitted (or empty) means every rule uses its default, and an empty map is not
    /// serialized, so settings saved before rule modes existed keep their hash.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rule_modes: BTreeMap<String, RuleMode>,
    /// Optional cap on points contributed by the `siem_context` rule (0..=30; default 15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siem_context_max_points: Option<u32>,
    /// Hostnames or `*.example.com` wildcards approved at the outer tunnel gate and control-plane policy check.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub approved_egress_hosts: BTreeSet<String>,
    pub max_req_1m_p95: u32,
    pub max_req_1m_p99: u32,
    pub max_distinct_resources_15m_p95: u32,
    pub max_distinct_resources_15m_p99: u32,
    pub filesystem: Option<FilesystemPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardrailsUpdate {
    pub expected_revision: u64,
    pub settings: AgentGuardrails,
}

#[derive(Debug)]
pub enum GuardrailsSaveResult {
    Saved(Value),
    Conflict { current_revision: u64 },
}

fn text(value: &str, name: &str, max: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(RiskGuardError::InvalidArgument(format!(
            "{name} must contain 1..{max} bytes without control characters or surrounding whitespace"
        )));
    }
    Ok(())
}

fn envelope(p95: u32, p99: u32, name: &str, max: u32) -> Result<()> {
    if p95 == 0 || p95 > p99 || p99 > max {
        return Err(RiskGuardError::InvalidArgument(format!(
            "{name} requires 1 <= p95 <= p99 <= {max}"
        )));
    }
    Ok(())
}

impl AgentGuardrails {
    pub fn from_baseline(
        baseline: &BaselineProfile,
        mode: EnforcementMode,
        filesystem: Option<FilesystemPolicy>,
    ) -> Self {
        let detector = InteractionRiskDetector::new_default();
        Self {
            task_profile: baseline.task_profile.clone(),
            mode,
            observe_threshold: detector.observe_threshold,
            enforce_threshold: detector.enforce_threshold,
            cooldown_seconds: (detector.cooldown_duration_ms / 1000) as u32,
            approved_resources: baseline.approved_resources.clone(),
            allowed_action_classes: baseline.allowed_action_classes.clone(),
            forbid_unfamiliar_high_impact: baseline.forbid_unfamiliar_high_impact,
            rule_modes: baseline.rule_modes.clone(),
            siem_context_max_points: baseline.siem_context_max_points,
            approved_egress_hosts: baseline.approved_egress_hosts.clone(),
            max_req_1m_p95: baseline.max_req_1m_p95,
            max_req_1m_p99: baseline.max_req_1m_p99,
            max_distinct_resources_15m_p95: baseline.max_distinct_resources_15m_p95,
            max_distinct_resources_15m_p99: baseline.max_distinct_resources_15m_p99,
            filesystem,
        }
    }

    pub fn validate(&self) -> Result<()> {
        text(&self.task_profile, "task_profile", 128)?;
        if self.observe_threshold >= self.enforce_threshold || self.enforce_threshold > 100 {
            return Err(RiskGuardError::InvalidArgument(
                "thresholds require 0 <= observe < enforce <= 100".into(),
            ));
        }
        if !(1..=86_400).contains(&self.cooldown_seconds) {
            return Err(RiskGuardError::InvalidArgument(
                "cooldown_seconds must be between 1 and 86400".into(),
            ));
        }
        for (rule, mode) in &self.rule_modes {
            if !CONFIGURABLE_RULES.contains(&rule.as_str()) {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "unknown rule '{rule}'; configurable rules are {}",
                    CONFIGURABLE_RULES.join(", ")
                )));
            }
            if rule == crate::types::RULE_UNFAMILIAR_HIGH_IMPACT && *mode == RuleMode::Off {
                return Err(RiskGuardError::InvalidArgument(
                    "turn the high-impact rule off with forbid_unfamiliar_high_impact, not with a rule mode".into(),
                ));
            }
        }
        if let Some(points) = self.siem_context_max_points
            && points > 30
        {
            return Err(RiskGuardError::InvalidArgument(
                "siem_context_max_points may be at most 30".into(),
            ));
        }
        if self.approved_egress_hosts.len() > 256 {
            return Err(RiskGuardError::InvalidArgument(
                "approved_egress_hosts is limited to 256 entries".into(),
            ));
        }
        for host in &self.approved_egress_hosts {
            let name = host.strip_prefix("*.").unwrap_or(host);
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
                return Err(RiskGuardError::InvalidArgument(format!(
                    "approved_egress_hosts entry '{host}' must be a lowercase hostname or '*.example.com' wildcard, not an IP address"
                )));
            }
        }
        envelope(
            self.max_req_1m_p95,
            self.max_req_1m_p99,
            "request rate",
            1_000_000,
        )?;
        envelope(
            self.max_distinct_resources_15m_p95,
            self.max_distinct_resources_15m_p99,
            "resource fan-out",
            MAX_FANOUT_ENVELOPE,
        )?;
        for (name, values) in [
            ("approved_resources", &self.approved_resources),
            ("allowed_action_classes", &self.allowed_action_classes),
        ] {
            if values.len() > 256 {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "{name} is limited to 256 entries"
                )));
            }
            for value in values {
                text(value, name, 512)?;
                if name == "allowed_action_classes" {
                    let Some((method, path)) = value.split_once(' ') else {
                        return Err(RiskGuardError::InvalidArgument(
                            "action classes must use 'METHOD /route'".into(),
                        ));
                    };
                    if method.is_empty()
                        || !method.bytes().all(|c| c.is_ascii_uppercase())
                        || !path.starts_with('/')
                        || path.contains(char::is_whitespace)
                    {
                        return Err(RiskGuardError::InvalidArgument(
                            "action classes must use uppercase METHOD and an absolute route".into(),
                        ));
                    }
                }
            }
        }
        if let Some(filesystem) = &self.filesystem {
            for paths in [&filesystem.read_only, &filesystem.read_write] {
                if paths.len() > 128 {
                    return Err(RiskGuardError::InvalidArgument(
                        "filesystem path lists are limited to 128 entries".into(),
                    ));
                }
                let mut seen = BTreeSet::new();
                for path in paths {
                    text(path, "filesystem path", 1024)?;
                    if !path.starts_with('/')
                        || path.contains('\\')
                        || path.contains("//")
                        || (path.len() > 1 && path.ends_with('/'))
                        || path.split('/').any(|part| matches!(part, "." | ".."))
                        || !seen.insert(path)
                    {
                        return Err(RiskGuardError::InvalidArgument(
                            "filesystem paths must be unique canonical absolute Linux paths without traversal or trailing slashes".into(),
                        ));
                    }
                }
            }
            if filesystem
                .read_only
                .iter()
                .any(|path| filesystem.read_write.contains(path))
            {
                return Err(RiskGuardError::InvalidArgument(
                    "a filesystem path cannot be both read-only and read-write".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn detector(&self) -> InteractionRiskDetector {
        InteractionRiskDetector::new(
            self.observe_threshold,
            self.enforce_threshold,
            i64::from(self.cooldown_seconds) * 1000,
        )
    }

    pub fn apply_live_baseline(&self, baseline: &BaselineProfile) -> BaselineProfile {
        let mut effective = baseline.clone();
        effective.approved_resources = self.approved_resources.clone();
        effective.allowed_action_classes = self.allowed_action_classes.clone();
        effective.forbid_unfamiliar_high_impact = self.forbid_unfamiliar_high_impact;
        effective.rule_modes = self.rule_modes.clone();
        if self.siem_context_max_points.is_some() {
            effective.siem_context_max_points = self.siem_context_max_points;
        }
        if !self.approved_egress_hosts.is_empty() || baseline.approved_egress_hosts.is_empty() {
            effective.approved_egress_hosts = self.approved_egress_hosts.clone();
        }
        effective.max_req_1m_p95 = self.max_req_1m_p95;
        effective.max_req_1m_p99 = self.max_req_1m_p99;
        effective.max_distinct_resources_15m_p95 = self.max_distinct_resources_15m_p95;
        effective.max_distinct_resources_15m_p99 = self.max_distinct_resources_15m_p99;
        effective
    }

    /// Whether `self` loosens protection compared to `previous` (given the underlying `base` profile for default rule modes).
    /// Returns `Some(reason)` when any control is weakened, or `None` when the update only tightens or keeps protection equal.
    #[must_use]
    pub fn loosens(&self, previous: &Self, base: &BaselineProfile) -> Option<&'static str> {
        if previous.mode == EnforcementMode::Enforce && self.mode == EnforcementMode::Observe {
            return Some("switching guardrail mode from enforce to observe");
        }
        if self.enforce_threshold > previous.enforce_threshold
            || self.observe_threshold > previous.observe_threshold
        {
            return Some("raising a risk score threshold");
        }
        if self.cooldown_seconds < previous.cooldown_seconds {
            return Some("shortening the cooldown window");
        }
        if previous.forbid_unfamiliar_high_impact && !self.forbid_unfamiliar_high_impact {
            return Some("disabling forbid_unfamiliar_high_impact");
        }
        if self.max_req_1m_p95 > previous.max_req_1m_p95
            || self.max_req_1m_p99 > previous.max_req_1m_p99
            || self.max_distinct_resources_15m_p95 > previous.max_distinct_resources_15m_p95
            || self.max_distinct_resources_15m_p99 > previous.max_distinct_resources_15m_p99
        {
            return Some("raising rate or fan-out limits");
        }
        // An empty approved list means "not specified" (matches everything), so emptying a non-empty list or adding new entries loosens it.
        if (!previous.approved_resources.is_empty() && self.approved_resources.is_empty())
            || (!previous.approved_resources.is_empty()
                && !self.approved_resources.is_subset(&previous.approved_resources))
        {
            return Some("broadening approved resources");
        }
        if (!previous.allowed_action_classes.is_empty() && self.allowed_action_classes.is_empty())
            || (!previous.allowed_action_classes.is_empty()
                && !self
                    .allowed_action_classes
                    .is_subset(&previous.allowed_action_classes))
        {
            return Some("broadening allowed action classes");
        }
        if (!previous.approved_egress_hosts.is_empty() && self.approved_egress_hosts.is_empty())
            || (!previous.approved_egress_hosts.is_empty()
                && !self
                    .approved_egress_hosts
                    .is_subset(&previous.approved_egress_hosts))
        {
            return Some("broadening approved egress hosts");
        }
        let prev_siem_cap = previous
            .siem_context_max_points
            .or(base.siem_context_max_points)
            .unwrap_or(15);
        let next_siem_cap = self
            .siem_context_max_points
            .or(base.siem_context_max_points)
            .unwrap_or(15);
        if next_siem_cap < prev_siem_cap {
            return Some("lowering the SIEM context score cap");
        }
        let rank = |mode: RuleMode| match mode {
            RuleMode::Off => 0_u8,
            RuleMode::Shadow => 1_u8,
            RuleMode::Enforce => 2_u8,
        };
        let prev_live = previous.apply_live_baseline(base);
        let next_live = self.apply_live_baseline(base);
        for rule in CONFIGURABLE_RULES {
            if rank(next_live.rule_mode(rule)) < rank(prev_live.rule_mode(rule)) {
                return Some("weakening a guardrail rule mode");
            }
        }
        if let (Some(prev_fs), Some(next_fs)) = (&previous.filesystem, &self.filesystem) {
            let prev_ro: BTreeSet<_> = prev_fs.read_only.iter().collect();
            let next_ro: BTreeSet<_> = next_fs.read_only.iter().collect();
            let prev_rw: BTreeSet<_> = prev_fs.read_write.iter().collect();
            let next_rw: BTreeSet<_> = next_fs.read_write.iter().collect();
            if (!prev_fs.include_workdir && next_fs.include_workdir)
                || !next_rw.is_subset(&prev_rw)
                || !next_ro.is_subset(&prev_ro.union(&prev_rw).copied().collect())
            {
                return Some("broadening filesystem guardrails");
            }
        } else if previous.filesystem.is_some() && self.filesystem.is_none() {
            return Some("removing filesystem guardrails");
        }
        None
    }
}

pub(crate) fn filesystem_matches(a: &FilesystemPolicy, b: &FilesystemPolicy) -> bool {
    a.include_workdir == b.include_workdir
        && a.read_only.iter().collect::<BTreeSet<_>>() == b.read_only.iter().collect()
        && a.read_write.iter().collect::<BTreeSet<_>>() == b.read_write.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> AgentGuardrails {
        AgentGuardrails::from_baseline(
            &crate::fixture::build_standard_corpus().default_baseline,
            EnforcementMode::Enforce,
            Some(FilesystemPolicy {
                include_workdir: false,
                read_only: vec!["/usr".into()],
                read_write: vec!["/tmp".into()],
            }),
        )
    }

    #[test]
    fn rule_modes_are_validated_and_default_to_the_baseline() {
        let mut value = valid();
        assert!(value.rule_modes.is_empty());
        value
            .rule_modes
            .insert("unapproved_action".into(), RuleMode::Enforce);
        value
            .rule_modes
            .insert("unapproved_resource".into(), RuleMode::Shadow);
        value
            .rule_modes
            .insert("unfamiliar_high_impact".into(), RuleMode::Shadow);
        assert!(value.validate().is_ok());

        let mut unknown = valid();
        unknown
            .rule_modes
            .insert("made_up_rule".into(), RuleMode::Enforce);
        assert!(
            unknown.validate().is_err(),
            "an unknown rule name must be refused, not silently ignored"
        );

        let mut off = valid();
        off.rule_modes
            .insert("unfamiliar_high_impact".into(), RuleMode::Off);
        assert!(
            off.validate().is_err(),
            "the high-impact rule is switched off with its own setting"
        );

        let mut forbidden = valid();
        forbidden
            .rule_modes
            .insert("forbidden_action".into(), RuleMode::Off);
        assert!(
            forbidden.validate().is_err(),
            "the deny list is not configurable"
        );
    }

    #[test]
    fn settings_saved_before_rule_modes_existed_still_load_and_keep_their_form() {
        let value = valid();
        let json = serde_json::to_value(&value).unwrap();
        assert!(
            json.get("rule_modes").is_none(),
            "an empty map is not serialized"
        );
        let loaded: AgentGuardrails = serde_json::from_value(json).unwrap();
        assert_eq!(loaded, value);

        let mut promoted = valid();
        promoted
            .rule_modes
            .insert("unapproved_action".into(), RuleMode::Enforce);
        let baseline = crate::fixture::build_standard_corpus().default_baseline;
        assert_eq!(
            promoted
                .apply_live_baseline(&baseline)
                .rule_mode("unapproved_action"),
            RuleMode::Enforce,
            "saved settings apply to the live baseline"
        );
    }

    #[test]
    fn rejects_incoherent_thresholds_envelopes_and_cooldowns() {
        assert!(valid().validate().is_ok());
        let mut value = valid();
        value.observe_threshold = value.enforce_threshold;
        assert!(value.validate().is_err());
        let mut value = valid();
        value.max_req_1m_p95 = value.max_req_1m_p99 + 1;
        assert!(value.validate().is_err());
        let mut value = valid();
        value.max_distinct_resources_15m_p99 = MAX_FANOUT_ENVELOPE + 1;
        assert!(value.validate().is_err());
        let mut value = valid();
        value.cooldown_seconds = 0;
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_ambiguous_paths_and_unknown_json_fields() {
        for path in [
            "relative",
            "/tmp/../etc",
            "/tmp//cache",
            "/tmp/",
            "/tmp\0bad",
        ] {
            let mut value = valid();
            value.filesystem.as_mut().unwrap().read_write = vec![path.into()];
            assert!(value.validate().is_err(), "path accepted: {path:?}");
        }
        let mut value = valid();
        value.filesystem.as_mut().unwrap().read_write = vec!["/usr".into()];
        assert!(value.validate().is_err());
        let mut encoded = serde_json::to_value(valid()).unwrap();
        encoded["unrecognized_control"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AgentGuardrails>(encoded).is_err());
    }
}
