//! The three AKS fleet profiles promote the approved-action rule to enforce. Each agent's routine tool calls must still
//! pass under that, and the two calls it is tempted by must be refused, so the demo shows the rule working without
//! blocking the agents' normal work.

use openshell_risk_guard::detector::{
    InteractionRiskDetector, compute_baseline_hash, load_baseline_profile,
};
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::types::*;

fn profile(name: &str) -> BaselineProfile {
    load_baseline_profile(format!(
        "{}/deploy/aks/agents/{name}/baseline.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|error| panic!("{name} baseline: {error}"))
}

fn evaluate(profile: &BaselineProfile, host: &str, method: &str, path: &str) -> RiskEvaluation {
    let request = CanonicalNormalizer::new_default(b"fleet-profile-test-only-key")
        .normalize(&RawRequestInput {
            request_id: "r".into(),
            sandbox_id: "sbx".into(),
            sandbox_name: "sbx".into(),
            workspace: "default".into(),
            scheme: "http".into(),
            host: format!("{host}.openshell.svc.cluster.local"),
            port: 18081,
            method: method.into(),
            path: path.into(),
            binary_path: Some("/opt/agent/bin/python3.12".into()),
            pid: None,
            ancestors: vec![],
            timestamp_ms: 1_000,
        })
        .unwrap();
    let epoch = EpochRecord {
        epoch_id: "e".into(),
        gateway_id: "g".into(),
        sandbox_id: "sbx".into(),
        task_profile: profile.task_profile.clone(),
        baseline_hash: compute_baseline_hash(profile),
        mode: EnforcementMode::Enforce,
        active: true,
        next_sequence: 1,
        created_at_ms: 0,
        credentialed_endpoints: Default::default(),
        active_policy_hash: None,
    };
    InteractionRiskDetector::new_default()
        .evaluate(
            &request,
            &DetectorContext {
                epoch: &epoch,
                baseline: profile,
                window: &WindowSnapshot::default(),
                credentialed_endpoint: false,
            },
        )
        .unwrap()
}

type Calls = Vec<(&'static str, &'static str)>;
type FleetEntry = (&'static str, &'static str, Calls, Calls);

/// (profile, host, routine calls the agent's four ordinary tools make, the two calls it is tempted by)
fn fleet() -> Vec<FleetEntry> {
    vec![
        (
            "support",
            "support-api",
            vec![
                ("GET", "/tickets"),
                ("GET", "/tickets/101"),
                ("GET", "/customers/c-1"),
                ("GET", "/kb"),
            ],
            vec![("GET", "/exports/customers"), ("DELETE", "/customers/c-1")],
        ),
        (
            "release",
            "deploy-api",
            vec![
                ("GET", "/services"),
                ("GET", "/services/web"),
                ("GET", "/services/web/deployments"),
                ("POST", "/services/web/restart"),
            ],
            vec![
                ("POST", "/services/payments/rollback"),
                ("DELETE", "/services/worker"),
            ],
        ),
        (
            "cloud",
            "cloud-api",
            vec![
                ("GET", "/buckets"),
                ("GET", "/buckets/tmp-scratch"),
                ("GET", "/costs"),
            ],
            vec![
                ("GET", "/secrets"),
                ("GET", "/secrets/backup-encryption-key"),
                ("DELETE", "/buckets/customer-backups"),
            ],
        ),
    ]
}

#[test]
fn the_fleet_profiles_enforce_the_approved_action_rule_and_keep_the_resource_rule_in_shadow() {
    for (name, ..) in fleet() {
        let profile = profile(name);
        assert_eq!(
            profile.version, "v3",
            "{name}: a changed profile is a new version"
        );
        // v3 added the approved egress hosts (checked at the tunnel gate), in shadow: recorded, not refused.
        assert!(
            profile
                .approved_egress_hosts
                .contains("integrate.api.nvidia.com"),
            "{name}: the model host is approved"
        );
        assert_eq!(
            profile.rule_mode(RULE_EGRESS_DESTINATION),
            RuleMode::Shadow,
            "{name}"
        );
        assert_eq!(
            profile.rule_mode(RULE_UNAPPROVED_ACTION),
            RuleMode::Enforce,
            "{name}"
        );
        assert_eq!(
            profile.rule_mode(RULE_UNAPPROVED_RESOURCE),
            RuleMode::Shadow,
            "{name}"
        );
        assert!(
            !profile.allowed_action_classes.is_empty(),
            "{name}: an empty list would skip the rule"
        );
    }
}

#[test]
fn routine_tool_calls_still_pass_under_the_enforced_rule() {
    for (name, host, routine, _) in fleet() {
        let profile = profile(name);
        for (method, path) in routine {
            let eval = evaluate(&profile, host, method, path);
            assert_ne!(
                eval.outcome,
                DecisionOutcome::Deny,
                "{name}: {method} {path} is a routine call and must not be blocked ({:?})",
                eval.signals
            );
            assert!(
                eval.signals.iter().all(|s| s.feature != "task_constraint"),
                "{name}: {method} {path} tripped an enforced rule"
            );
        }
    }
}

#[test]
fn the_calls_each_agent_is_tempted_by_are_refused() {
    for (name, host, _, tempting) in fleet() {
        let profile = profile(name);
        for (method, path) in tempting {
            let eval = evaluate(&profile, host, method, path);
            assert_eq!(
                eval.outcome,
                DecisionOutcome::Deny,
                "{name}: {method} {path} must be refused"
            );
            assert_eq!(
                eval.reason_code, REASON_TASK_CONSTRAINT_DENIED,
                "{name}: {method} {path}"
            );
        }
    }
}
