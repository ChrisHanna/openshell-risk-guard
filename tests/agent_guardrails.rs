use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::guardrails::{AgentGuardrails, GuardrailsSaveResult, GuardrailsUpdate};
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::*;
use serde_json::{Value, json};

fn open_and_seed_store(path: impl AsRef<std::path::Path>) -> openshell_risk_guard::Result<SqliteRiskStore> {
    let store = seed_fixture_store(path)?;
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version = openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline)?;
    Ok(store)
}

fn bind(store: &SqliteRiskStore, agent: &str, sandbox: &str, run: &str) {
    let baseline = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    store
        .create_agent_run(
            agent,
            run,
            "revision-1",
            &baseline.task_profile,
            EnforcementMode::Enforce,
        )
        .unwrap();
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: format!("epoch-{sandbox}"),
            gateway_id: "gateway".into(),
            sandbox_id: sandbox.into(),
            task_profile: baseline.task_profile.clone(),
            baseline_hash: compute_baseline_hash(&baseline),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: 0,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
    store.bind_agent_run(run, sandbox, "gateway").unwrap();
}

fn request(sandbox: &str, id: &str, method: &str, resource: &str, ts: i64) -> NormalizedRequest {
    CanonicalNormalizer::new_default(b"guardrail-test-only-key")
        .normalize(&RawRequestInput {
            request_id: id.into(),
            sandbox_id: sandbox.into(),
            sandbox_name: sandbox.into(),
            workspace: "default".into(),
            scheme: "https".into(),
            host: "api.github.local".into(),
            port: 18443,
            method: method.into(),
            path: if method == "GET" {
                format!("/repos/org/{resource}/issues")
            } else {
                format!("/repos/org/{resource}")
            },
            binary_path: Some("/usr/bin/curl".into()),
            pid: None,
            ancestors: vec![],
            timestamp_ms: ts,
        })
        .unwrap()
}

fn settings(store: &SqliteRiskStore, agent: &str) -> AgentGuardrails {
    let view = store.agent_guardrails(agent, 60_000).unwrap().unwrap();
    serde_json::from_value(view["settings"].clone()).unwrap()
}

fn save(
    store: &SqliteRiskStore,
    agent: &str,
    settings: AgentGuardrails,
    expected_revision: u64,
) -> Value {
    match store
        .save_agent_guardrails(
            agent,
            &GuardrailsUpdate {
                expected_revision,
                settings,
            },
            "test-operator",
            60_000 + expected_revision as i64,
        )
        .unwrap()
    {
        GuardrailsSaveResult::Saved(view) => view,
        GuardrailsSaveResult::Conflict { current_revision } => {
            panic!("unexpected revision conflict: {current_revision}")
        }
    }
}

#[test]
fn saved_guardrails_survive_reopen_and_reject_stale_or_invalid_edits() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("guardrails.db");
    let store = open_and_seed_store(&db).unwrap();
    store.register_agent("a", "Agent A").unwrap();
    bind(&store, "a", "sandbox", "run");
    let mut desired = settings(&store, "a");
    desired.mode = EnforcementMode::Observe;
    desired.observe_threshold = 12;
    desired.enforce_threshold = 82;
    desired.cooldown_seconds = 45;
    desired.max_req_1m_p95 = 25;
    desired.max_req_1m_p99 = 50;
    desired.max_distinct_resources_15m_p95 = 3;
    desired.max_distinct_resources_15m_p99 = 6;
    desired.approved_resources.insert("org/approved".into());
    desired
        .allowed_action_classes
        .insert("POST /repos/{owner}/{repo}/issues".into());
    let first = save(&store, "a", desired.clone(), 0);
    assert_eq!(first["revision"], 1);
    drop(store);
    let reopened = SqliteRiskStore::open(&db).unwrap();
    assert_eq!(settings(&reopened, "a"), desired);
    assert!(matches!(
        reopened
            .save_agent_guardrails(
                "a",
                &GuardrailsUpdate {
                    expected_revision: 0,
                    settings: desired.clone()
                },
                "test-operator",
                61_000,
            )
            .unwrap(),
        GuardrailsSaveResult::Conflict {
            current_revision: 1
        }
    ));
    let mut invalid = desired;
    invalid.observe_threshold = invalid.enforce_threshold;
    assert!(
        reopened
            .save_agent_guardrails(
                "a",
                &GuardrailsUpdate {
                    expected_revision: 1,
                    settings: invalid
                },
                "test-operator",
                62_000,
            )
            .is_err()
    );
    let view = reopened.agent_guardrails("a", 62_000).unwrap().unwrap();
    assert_eq!(view["revision"], 1);
    assert_eq!(view["history"].as_array().unwrap().len(), 1);
    assert_eq!(view["history"][0]["updated_by"], "test-operator");
}

#[test]
fn live_mode_changes_cross_store_connections_without_clearing_strict_locks() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live.db");
    let evaluator = open_and_seed_store(&db).unwrap();
    evaluator.register_agent("a", "Agent A").unwrap();
    evaluator.register_agent("b", "Agent B").unwrap();
    bind(&evaluator, "a", "sandbox-a", "run-a");
    bind(&evaluator, "b", "sandbox-b", "run-b");
    let detector = InteractionRiskDetector::new_default();
    let locked = request("sandbox-a", "locked", "DELETE", "restricted", 60_000);
    assert_eq!(
        evaluator
            .evaluate_authenticated(&locked, &detector, "gateway", true)
            .unwrap()
            .outcome,
        DecisionOutcome::Deny
    );

    let operator = SqliteRiskStore::open(&db).unwrap();
    let mut desired = settings(&operator, "a");
    desired.mode = EnforcementMode::Observe;
    desired.enforce_threshold = 95;
    save(&operator, "a", desired, 0);

    let observed = request(
        "sandbox-a",
        "new-request",
        "DELETE",
        "another-resource",
        61_000,
    );
    let evaluation = evaluator
        .evaluate_authenticated(&observed, &detector, "gateway", true)
        .unwrap();
    assert_eq!(evaluation.mode, EnforcementMode::Observe);
    assert_eq!(evaluation.outcome, DecisionOutcome::AllowWithObservation);
    assert_eq!(evaluation.threshold, 95);
    assert!(
        evaluation
            .signals
            .iter()
            .any(|signal| signal.feature == "guardrails_revision")
    );

    let retry = request("sandbox-a", "retry", "DELETE", "restricted", 62_000);
    let denied = evaluator
        .evaluate_authenticated(&retry, &detector, "gateway", true)
        .unwrap();
    assert_eq!(denied.outcome, DecisionOutcome::Deny);
    assert_eq!(denied.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
    assert_eq!(denied.threshold, 95);
    assert_eq!(
        evaluator
            .evaluate_authenticated(&locked, &detector, "gateway", true)
            .unwrap()
            .mode,
        EnforcementMode::Enforce
    );

    let isolated = request(
        "sandbox-b",
        "other-agent",
        "DELETE",
        "another-resource",
        61_000,
    );
    assert_eq!(
        evaluator
            .evaluate_authenticated(&isolated, &detector, "gateway", true)
            .unwrap()
            .outcome,
        DecisionOutcome::Deny
    );
    let detail = evaluator
        .operator_agent_detail("a", 62_000)
        .unwrap()
        .unwrap();
    assert_eq!(detail["contexts"][0]["mode"], "enforce");
    assert_eq!(detail["guardrails"]["revision"], 1);
}

#[test]
fn thresholds_cooldown_and_envelopes_reach_the_real_detector() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("detector.db")).unwrap();
    store.register_agent("a", "Agent A").unwrap();
    bind(&store, "a", "sandbox", "run");
    let detector = InteractionRiskDetector::new_default();
    let initial = request("sandbox", "initial", "GET", "unfamiliar-one", 60_000);
    let before = store
        .evaluate_authenticated(&initial, &detector, "gateway", true)
        .unwrap();
    assert_ne!(before.outcome, DecisionOutcome::Deny);
    assert!(before.risk_score > 0 && before.risk_score < 70);
    let mut desired = settings(&store, "a");
    desired.observe_threshold = 0;
    desired.enforce_threshold = 1;
    desired.cooldown_seconds = 13;
    desired.max_req_1m_p95 = 1;
    desired.max_req_1m_p99 = 2;
    desired.max_distinct_resources_15m_p95 = 1;
    desired.max_distinct_resources_15m_p99 = 2;
    save(&store, "a", desired, 0);
    let next = request("sandbox", "next", "GET", "unfamiliar-two", 61_000);
    let after = store
        .evaluate_authenticated(&next, &detector, "gateway", true)
        .unwrap();
    assert_eq!(after.threshold, 1);
    assert_eq!(after.outcome, DecisionOutcome::Deny);
    assert!(matches!(
        after.ratchet_action,
        RatchetAction::TriggerTier2Cooldown {
            cooldown_duration_ms: 13_000,
            ..
        }
    ));
    for feature in ["V", "F"] {
        assert_eq!(
            after
                .signals
                .iter()
                .find(|s| s.feature == feature)
                .unwrap()
                .baseline_summary,
            "p95=1,p99=2"
        );
    }
}

#[test]
fn approved_resources_and_action_classes_are_used_without_rewriting_the_pinned_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("baseline.db")).unwrap();
    store.register_agent("a", "Agent A").unwrap();
    bind(&store, "a", "sandbox", "run");
    let pinned = store
        .get_active_epoch("sandbox")
        .unwrap()
        .unwrap()
        .baseline_hash;
    let mut desired = settings(&store, "a");
    desired.forbid_unfamiliar_high_impact = false;
    desired.approved_resources.insert("org/approved".into());
    desired
        .allowed_action_classes
        .insert("DELETE /repos/{owner}/{repo}".into());
    save(&store, "a", desired, 0);
    let evaluation = store
        .evaluate_authenticated(
            &request("sandbox", "approved", "DELETE", "approved", 60_000),
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
        )
        .unwrap();
    assert_ne!(evaluation.outcome, DecisionOutcome::Deny);
    assert_eq!(
        store
            .get_active_epoch("sandbox")
            .unwrap()
            .unwrap()
            .baseline_hash,
        pinned
    );
    assert_ne!(evaluation.baseline_hash, pinned);
}

#[test]
fn filesystem_changes_are_saved_as_pending_and_not_reported_as_hot_applied() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("filesystem.db")).unwrap();
    store.register_agent("a", "Agent A").unwrap();
    bind(&store, "a", "sandbox", "run");
    let policy = "version: 1\nfilesystem_policy:\n  include_workdir: true\n  read_only: [/usr]\n  read_write: [/sandbox, /tmp]\nnetwork_middlewares:\n  risk:\n    middleware: risk-guard\n    on_error: fail_closed\n    config: {task_profile: repo-triage-readonly, mode: enforce}\n";
    store
        .record_policy_snapshot(
            "sandbox",
            "policy-hash",
            policy,
            &Default::default(),
            "test",
            60_000,
        )
        .unwrap();
    let mut desired = settings(&store, "a");
    let fs = desired.filesystem.as_mut().unwrap();
    fs.include_workdir = false;
    fs.read_only.push("/sandbox".into());
    fs.read_write.retain(|path| path != "/sandbox");
    let saved = save(&store, "a", desired, 0);
    assert_eq!(
        saved["application"]["filesystem"]["status"],
        "new_sandbox_required"
    );
    let actual = store.latest_policy_snapshot("sandbox").unwrap().unwrap();
    assert_eq!(actual.1, policy);
    let exported = store.export_agent_guardrails_policy("a").unwrap().unwrap();
    let candidate = openshell_policy_schema::parse_policy(&exported).unwrap();
    assert!(!candidate.filesystem_policy.unwrap().include_workdir);
    assert_eq!(
        candidate.network_middlewares["risk"].on_error,
        "fail_closed"
    );
    assert_eq!(
        store.agent_guardrails("a", 62_000).unwrap().unwrap()["settings"]["filesystem"]["read_only"],
        json!(["/usr", "/sandbox"])
    );
}

#[test]
fn saved_static_settings_are_required_when_binding_new_sandboxes() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("binding.db")).unwrap();
    store.register_agent("a", "Agent A").unwrap();
    bind(&store, "a", "original", "original-run");
    let policy = "version: 1\nfilesystem_policy:\n  include_workdir: true\n  read_only: [/usr]\n  read_write: [/sandbox, /tmp]\nnetwork_middlewares:\n  risk:\n    middleware: risk-guard\n    on_error: fail_closed\n    config: {task_profile: repo-triage-readonly, mode: enforce}\n";
    store
        .record_policy_snapshot(
            "original",
            "original-policy",
            policy,
            &Default::default(),
            "test",
            60_000,
        )
        .unwrap();
    let mut desired = settings(&store, "a");
    desired.filesystem.as_mut().unwrap().include_workdir = false;
    save(&store, "a", desired, 0);
    let exported = store.export_agent_guardrails_policy("a").unwrap().unwrap();
    store
        .create_agent_run(
            "a",
            "next-run",
            "revision-1",
            "repo-triage-readonly",
            EnforcementMode::Enforce,
        )
        .unwrap();
    let base = store.get_active_epoch("original").unwrap().unwrap();
    for (sandbox, document) in [("old-policy", policy), ("new-policy", exported.as_str())] {
        let mut epoch = base.clone();
        epoch.sandbox_id = sandbox.into();
        epoch.epoch_id = format!("epoch-{sandbox}");
        store.upsert_epoch(&epoch).unwrap();
        store
            .record_policy_snapshot(
                sandbox,
                sandbox,
                document,
                &Default::default(),
                "test",
                61_000,
            )
            .unwrap();
    }
    assert!(
        store
            .bind_agent_run("next-run", "old-policy", "gateway")
            .is_err()
    );
    store
        .bind_agent_run("next-run", "new-policy", "gateway")
        .unwrap();
    let view = store.agent_guardrails("a", 62_000).unwrap().unwrap();
    assert!(
        view["application"]["sandboxes"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |item| item["sandbox_id"] == "new-policy" && item["filesystem"] == "recorded_match"
            )
    );
    assert_eq!(
        view["application"]["filesystem"]["status"],
        "new_sandbox_required"
    );
}

#[test]
fn task_profile_changes_are_pending_and_new_runs_use_the_approved_profile() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("profiles.db")).unwrap();
    store.register_agent("a", "Agent A").unwrap();
    bind(&store, "a", "original", "original-run");
    let original = store.get_active_epoch("original").unwrap().unwrap();
    let mut alternate = build_standard_corpus().default_baseline;
    alternate.task_profile = "another-approved-task".into();
    alternate.normalizer_version = openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&alternate).unwrap();
    let mut desired = settings(&store, "a");
    desired.task_profile = alternate.task_profile.clone();
    let view = save(&store, "a", desired, 0);
    assert_eq!(
        view["application"]["task_profile"]["status"],
        "new_run_required"
    );
    assert_eq!(
        store
            .get_active_epoch("original")
            .unwrap()
            .unwrap()
            .task_profile,
        original.task_profile
    );
    assert!(
        store
            .create_agent_run(
                "a",
                "wrong",
                "revision-1",
                &original.task_profile,
                EnforcementMode::Enforce
            )
            .is_err()
    );
    store
        .create_agent_run(
            "a",
            "approved",
            "revision-1",
            &alternate.task_profile,
            EnforcementMode::Enforce,
        )
        .unwrap();
}

fn shadow_hits(evaluation: &RiskEvaluation) -> Vec<String> {
    evaluation
        .signals
        .iter()
        .filter(|signal| signal.feature == "shadow_rule")
        .map(|signal| signal.baseline_summary.clone())
        .collect()
}

#[test]
fn an_operator_can_promote_a_shadow_rule_and_it_takes_effect_on_the_next_request() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("rules.db");
    let evaluator = open_and_seed_store(&db).unwrap();
    evaluator.register_agent("a", "Agent A").unwrap();
    bind(&evaluator, "a", "sandbox-a", "run-a");
    let detector = InteractionRiskDetector::new_default();

    // A read of a repository the task does not approve: allowed, but recorded as something the rule would block.
    let before = evaluator
        .evaluate_authenticated(
            &request("sandbox-a", "before", "GET", "unseen", 60_000),
            &detector,
            "gateway",
            true,
        )
        .unwrap();
    assert_ne!(before.outcome, DecisionOutcome::Deny, "a shadow rule never blocks");
    assert_eq!(shadow_hits(&before), vec!["rule=unapproved_resource; mode=shadow"]);

    // An administrator promotes the rule from another connection, as the console does.
    let operator = SqliteRiskStore::open(&db).unwrap();
    let mut desired = settings(&operator, "a");
    desired.rule_modes.insert("unapproved_resource".into(), RuleMode::Enforce);
    let saved = save(&operator, "a", desired, 0);
    assert_eq!(saved["revision"], 1);
    assert_eq!(saved["settings"]["rule_modes"]["unapproved_resource"], "enforce");

    let after = evaluator
        .evaluate_authenticated(
            &request("sandbox-a", "after", "GET", "unseen-2", 61_000),
            &detector,
            "gateway",
            true,
        )
        .unwrap();
    assert_eq!(after.outcome, DecisionOutcome::Deny);
    assert_eq!(after.reason_code, REASON_TASK_CONSTRAINT_DENIED);
    assert!(shadow_hits(&after).is_empty(), "an enforced rule is no longer reported as shadow");
    assert!(after.signals.iter().any(|s| s.feature == "guardrails_revision"), "the decision names the settings revision");

    // The approved resource still passes, and the promotion is on the audit trail with who made it.
    let approved = evaluator
        .evaluate_authenticated(
            &request("sandbox-a", "approved", "GET", "docs-site", 62_000),
            &detector,
            "gateway",
            true,
        )
        .unwrap();
    assert_ne!(approved.outcome, DecisionOutcome::Deny);
    let view = operator.agent_guardrails("a", 62_000).unwrap().unwrap();
    assert_eq!(view["history"][0]["updated_by"], "test-operator");

    // Promotion survives a restart.
    drop(operator);
    drop(evaluator);
    let reopened = SqliteRiskStore::open(&db).unwrap();
    assert_eq!(settings(&reopened, "a").rule_modes.get("unapproved_resource"), Some(&RuleMode::Enforce));
}
