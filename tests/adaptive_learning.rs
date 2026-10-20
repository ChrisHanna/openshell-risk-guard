use openshell_risk_guard::adaptive_controls::{
    AdaptiveOperation, AdaptiveUpdateResult, CaptureReview, LearningScope, ModelMode,
};
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::guardrails::{AgentGuardrails, GuardrailsUpdate};
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::*;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + 1_000
}

fn seed(path: &std::path::Path) -> SqliteRiskStore {
    let store = SqliteRiskStore::open(path).unwrap();
    let mut profile = build_standard_corpus().default_baseline;
    profile.normalizer_version = "v1".into();
    profile.training_sessions = 0;
    profile.training_requests = 0;
    profile.forbid_unfamiliar_high_impact = true;
    store.store_baseline(&profile).unwrap();
    store.register_agent("learner", "Learning test").unwrap();
    bind(&store, "run-1", "sandbox-1");
    store
}

fn bind(store: &SqliteRiskStore, run: &str, sandbox: &str) {
    let baseline = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    store
        .create_agent_run(
            "learner",
            run,
            "r1",
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

fn request(sandbox: &str, id: &str, method: &str, t: i64) -> NormalizedRequest {
    CanonicalNormalizer::new_default(b"adaptive-test-only-key")
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
                "/repos/org/docs-site/issues"
            } else {
                "/repos/org/unfamiliar"
            }
            .into(),
            binary_path: Some("/usr/bin/curl".into()),
            pid: None,
            ancestors: vec![],
            timestamp_ms: t,
        })
        .unwrap()
}

fn apply(store: &SqliteRiskStore, operation: AdaptiveOperation, t: i64) -> Value {
    match store
        .apply_adaptive_operation("learner", &operation, "test-operator", t)
        .unwrap()
    {
        AdaptiveUpdateResult::Applied(view) => view,
        AdaptiveUpdateResult::Conflict(message) => panic!("unexpected conflict: {message}"),
    }
}

fn start(store: &SqliteRiskStore, run: &str, scope: LearningScope, t: i64) -> String {
    let view = apply(
        store,
        AdaptiveOperation::StartCapture {
            run_id: run.into(),
            scope,
            expected_guardrails_revision: 0,
        },
        t,
    );
    view["sessions"][0]["session_id"].as_str().unwrap().into()
}

fn review(store: &SqliteRiskStore, session: &str, action: CaptureReview, t: i64) -> Value {
    apply(
        store,
        AdaptiveOperation::ReviewCapture {
            session_id: session.into(),
            action,
            notes: "Reviewed test evidence".into(),
        },
        t,
    )
}

fn native(store: &SqliteRiskStore, req: &NormalizedRequest) -> RiskEvaluation {
    store
        .evaluate_native_authenticated(
            req,
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
            NativeObservationSource::LocalTestSupervisor,
        )
        .unwrap()
}

fn reviewed_would_block(store: &SqliteRiskStore, t: i64) -> u64 {
    store.agent_adaptive("learner", t).unwrap().unwrap()["models"][0]["shadow_stats"]
        ["reviewable_would_block"]
        .as_u64()
        .unwrap()
}

fn train_one(store: &SqliteRiskStore, t: i64) -> Value {
    let session = start(store, "run-1", LearningScope::LocalDemo, t);
    for i in 0..12 {
        native(
            store,
            &request("sandbox-1", &format!("train-{i}"), "GET", t + 1 + i),
        );
    }
    review(store, &session, CaptureReview::Finish, t + 30);
    let view = review(store, &session, CaptureReview::Approve, t + 31);
    let context = view["sessions"][0]["context_id"]
        .as_str()
        .unwrap()
        .to_string();
    apply(
        store,
        AdaptiveOperation::Train {
            context_id: context,
            scope: LearningScope::LocalDemo,
            expected_guardrails_revision: 0,
        },
        t + 32,
    )
}

#[test]
fn only_fresh_native_calls_in_an_explicit_window_are_training_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("learning.db"));
    let t = now();
    let old = request("sandbox-1", "old-rehearsal", "GET", t - 100);
    native(&store, &old);
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::StartCapture {
                    run_id: "run-1".into(),
                    scope: LearningScope::LocalDemo,
                    expected_guardrails_revision: 0,
                },
                "operator",
                t
            )
            .is_err()
    );
    bind(&store, "fresh-run", "fresh-sandbox");
    let session = start(&store, "fresh-run", LearningScope::LocalDemo, t);
    let cli = request("fresh-sandbox", "cli-fixture", "GET", t + 1);
    store
        .evaluate_authenticated(
            &cli,
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
        )
        .unwrap();
    native(&store, &old);
    let fresh = request("fresh-sandbox", "fresh-native", "GET", t + 2);
    native(&store, &fresh);
    native(&store, &fresh);
    let view = review(&store, &session, CaptureReview::Finish, t + 3);
    assert_eq!(view["sessions"][0]["request_count"], 1);
    assert_eq!(view["sessions"][0]["status"], "pending_review");
    assert!(view["models"].as_array().unwrap().is_empty());
    let approved = review(&store, &session, CaptureReview::Approve, t + 4);
    assert_eq!(approved["sessions"][0]["status"], "approved");
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::StartCapture {
                    run_id: "fresh-run".into(),
                    scope: LearningScope::LocalDemo,
                    expected_guardrails_revision: 0,
                },
                "operator",
                t + 5
            )
            .is_err()
    );
}

#[test]
fn local_test_authentication_and_denied_requests_quarantine_whole_windows() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("learning.db"));
    let t = now();
    let verified = start(&store, "run-1", LearningScope::Verified, t);
    native(&store, &request("sandbox-1", "unverified", "GET", t + 1));
    let view = store.agent_adaptive("learner", t + 2).unwrap().unwrap();
    assert_eq!(view["sessions"][0]["status"], "quarantined");
    assert!(
        view["sessions"][0]["quarantine_reason"]
            .as_str()
            .unwrap()
            .contains("authentication")
    );
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::ReviewCapture {
                    session_id: verified,
                    action: CaptureReview::Approve,
                    notes: "".into(),
                },
                "operator",
                t + 3
            )
            .is_err()
    );
    bind(&store, "denied-run", "denied-sandbox");
    let denied = start(&store, "denied-run", LearningScope::LocalDemo, t + 4);
    assert_eq!(
        native(
            &store,
            &request("denied-sandbox", "delete", "DELETE", t + 5)
        )
        .outcome,
        DecisionOutcome::Deny
    );
    let view = store.agent_adaptive("learner", t + 6).unwrap().unwrap();
    assert_eq!(view["sessions"][0]["status"], "quarantined");
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::ReviewCapture {
                    session_id: denied,
                    action: CaptureReview::Approve,
                    notes: "".into(),
                },
                "operator",
                t + 7
            )
            .is_err()
    );
}

#[test]
fn provisional_models_shadow_without_changing_actual_decisions_and_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("learning.db");
    let store = seed(&path);
    let t = now();
    let view = train_one(&store, t);
    let model = &view["models"][0];
    assert_eq!(model["profile"]["training_runs"], 1);
    assert_eq!(model["profile"]["training_requests"], 12);
    assert_eq!(model["profile"]["holdout_requests"], 0);
    assert_eq!(model["profile"]["ready_for_enforcement"], false);
    assert_eq!(model["shadow"], true);
    assert_eq!(model["enforced"], false);
    assert!(!model["promotion_blockers"].as_array().unwrap().is_empty());
    let id = model["model_id"].as_str().unwrap().to_string();
    let req = request("sandbox-1", "after-fit", "GET", t + 40);
    let result = native(&store, &req);
    assert_eq!(result.outcome, DecisionOutcome::Allow);
    assert_eq!(result.risk_score, 0);
    let view = store.agent_adaptive("learner", t + 41).unwrap().unwrap();
    assert_eq!(view["models"][0]["shadow_stats"]["requests"], 1);
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::SetModel {
                    model_id: id.clone(),
                    mode: ModelMode::Enforce,
                    expected_active_model_id: None,
                    acknowledge_shadow_review: true,
                    reviewed_shadow_would_block: Some(0),
                },
                "operator",
                t + 42
            )
            .is_err()
    );
    drop(store);
    let reopened = SqliteRiskStore::open(&path).unwrap();
    let view = reopened.agent_adaptive("learner", t + 43).unwrap().unwrap();
    assert_eq!(view["models"][0]["model_id"], id);
    assert_eq!(view["models"][0]["shadow_stats"]["requests"], 1);
    assert_eq!(native(&reopened, &req), result);
    assert_eq!(
        reopened.agent_adaptive("learner", t + 44).unwrap().unwrap()["models"][0]["shadow_stats"]["requests"],
        1
    );
}

#[test]
fn unreadable_shadow_model_never_fails_requests_but_unreadable_enforced_model_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unreadable.db");
    let store = seed(&path);
    let t = now();
    let view = train_one(&store, t);
    let id = view["models"][0]["model_id"].as_str().unwrap().to_string();
    assert_eq!(view["models"][0]["shadow"], true);
    let tamper = rusqlite::Connection::open(&path).unwrap();
    tamper
        .busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    tamper
        .execute(
            "UPDATE adaptive_models SET model_hash = 'tampered' WHERE model_id = ?1",
            [&id],
        )
        .unwrap();

    let result = native(
        &store,
        &request("sandbox-1", "shadow-unreadable", "GET", t + 40),
    );
    assert_eq!(result.outcome, DecisionOutcome::Allow);
    let signal = result
        .signals
        .iter()
        .find(|signal| signal.feature == "adaptive_shadow")
        .expect("shadow model failure is recorded on the decision");
    assert_eq!(signal.contribution, 0);
    assert!(signal.observed_summary.contains("unavailable"));

    tamper
        .execute(
            "UPDATE adaptive_heads SET enforced_model_id = shadow_model_id",
            [],
        )
        .unwrap();
    let enforced = store.evaluate_native_authenticated(
        &request("sandbox-1", "enforced-unreadable", "GET", t + 41),
        &InteractionRiskDetector::new_default(),
        "gateway",
        true,
        NativeObservationSource::LocalTestSupervisor,
    );
    assert!(enforced.is_err(), "an enforced model that cannot load must fail closed");
}

#[test]
fn configuration_changes_invalidate_models_and_never_clear_existing_restrictions() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("learning.db"));
    let t = now();
    let view = train_one(&store, t);
    let id = view["models"][0]["model_id"].as_str().unwrap().to_string();
    let denied = request("sandbox-1", "locked", "DELETE", t + 40);
    assert_eq!(native(&store, &denied).outcome, DecisionOutcome::Deny);
    let current = store.agent_guardrails("learner", t + 41).unwrap().unwrap();
    let mut settings: AgentGuardrails =
        serde_json::from_value(current["settings"].clone()).unwrap();
    settings.mode = EnforcementMode::Observe;
    store
        .save_agent_guardrails(
            "learner",
            &GuardrailsUpdate {
                expected_revision: 0,
                settings,
            },
            "operator",
            t + 42,
        )
        .unwrap();
    let view = store.agent_adaptive("learner", t + 43).unwrap().unwrap();
    assert_eq!(view["models"][0]["compatible"], false);
    assert_eq!(view["models"][0]["shadow"], false);
    assert!(matches!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::StartCapture {
                    run_id: "run-1".into(),
                    scope: LearningScope::LocalDemo,
                    expected_guardrails_revision: 0,
                },
                "operator",
                t + 44
            )
            .unwrap(),
        AdaptiveUpdateResult::Conflict(_)
    ));
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::SetModel {
                    model_id: id,
                    mode: ModelMode::Shadow,
                    expected_active_model_id: None,
                    acknowledge_shadow_review: false,
                    reviewed_shadow_would_block: None,
                },
                "operator",
                t + 45
            )
            .is_err()
    );
    let next = request("sandbox-1", "still-locked", "DELETE", t + 46);
    assert_eq!(native(&store, &next).outcome, DecisionOutcome::Deny);
    assert_eq!(native(&store, &denied).outcome, DecisionOutcome::Deny);
}

#[test]
fn withdrawing_benign_approval_revokes_derived_models_without_deleting_history() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("learning.db"));
    let t = now();
    let view = train_one(&store, t);
    let hash = view["models"][0]["model_hash"].clone();
    let session = view["sessions"][0]["session_id"].as_str().unwrap();
    let view = review(&store, session, CaptureReview::Reject, t + 40);
    assert_eq!(view["sessions"][0]["status"], "rejected");
    assert_eq!(view["models"][0]["revoked"], true);
    assert_eq!(view["models"][0]["shadow"], false);
    assert_eq!(view["models"][0]["enforced"], false);
    assert_eq!(view["models"][0]["model_hash"], hash);
    assert_eq!(view["models"][0]["profile"]["training_requests"], 12);
    assert_eq!(store.list_decisions("sandbox-1", 50).unwrap().len(), 12);
}

#[test]
fn qualified_model_requires_shadow_review_then_enforces_and_keeps_its_ratchet_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("qualified.db"));
    let t = now();
    let mut context = String::new();
    for index in 0..25 {
        let run = format!("qualified-run-{index}");
        let sandbox = format!("qualified-sandbox-{index}");
        bind(&store, &run, &sandbox);
        let start_time = t + index * 60_000 + if index >= 20 { 1 } else { 0 };
        let session = start(&store, &run, LearningScope::LocalDemo, start_time);
        for event in 0..10 {
            native(
                &store,
                &request(
                    &sandbox,
                    &format!("sample-{index}-{event}"),
                    "GET",
                    start_time + 1_000 + event * 100,
                ),
            );
        }
        review(&store, &session, CaptureReview::Finish, start_time + 60_000);
        let view = review(
            &store,
            &session,
            CaptureReview::Approve,
            start_time + 60_001,
        );
        context = view["sessions"][0]["context_id"].as_str().unwrap().into();
    }
    let fitted_at = t + 25 * 60_000 + 10;
    let view = apply(
        &store,
        AdaptiveOperation::Train {
            context_id: context,
            scope: LearningScope::LocalDemo,
            expected_guardrails_revision: 0,
        },
        fitted_at,
    );
    let model_id = view["models"][0]["model_id"].as_str().unwrap().to_string();
    assert_eq!(view["models"][0]["profile"]["training_runs"], 20);
    assert_eq!(view["models"][0]["profile"]["holdout_runs"], 5);
    assert_eq!(view["models"][0]["profile"]["ready_for_enforcement"], true);
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::SetModel {
                    model_id: model_id.clone(),
                    mode: ModelMode::Enforce,
                    expected_active_model_id: None,
                    acknowledge_shadow_review: true,
                    reviewed_shadow_would_block: Some(0),
                },
                "operator",
                fitted_at + 1
            )
            .is_err()
    );

    let verified = request("sandbox-1", "different-source", "GET", fitted_at + 2);
    store
        .evaluate_native_authenticated(
            &verified,
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
            NativeObservationSource::VerifiedSupervisor,
        )
        .unwrap();
    assert_eq!(
        store
            .agent_adaptive("learner", fitted_at + 3)
            .unwrap()
            .unwrap()["models"][0]["shadow_stats"]["requests"],
        0
    );
    for index in 0..5 {
        for event in 0..10 {
            native(
                &store,
                &request(
                    &format!("qualified-sandbox-{index}"),
                    &format!("dataset-run-shadow-{index}-{event}"),
                    "GET",
                    fitted_at + 10 + event,
                ),
            );
        }
    }
    let same_runs = store
        .agent_adaptive("learner", fitted_at + 30)
        .unwrap()
        .unwrap();
    assert_eq!(same_runs["models"][0]["shadow_stats"]["requests"], 50);
    assert_eq!(
        same_runs["models"][0]["shadow_stats"]["reviewable_requests"],
        0
    );
    assert_eq!(same_runs["models"][0]["shadow_stats"]["reviewable_runs"], 0);
    for index in 0..5 {
        let run = format!("validation-run-{index}");
        let sandbox = format!("validation-sandbox-{index}");
        bind(&store, &run, &sandbox);
        for event in 0..10 {
            let result = native(
                &store,
                &request(
                    &sandbox,
                    &format!("shadow-{index}-{event}"),
                    "GET",
                    fitted_at + 60_000 + index * 60_000 + event * 100,
                ),
            );
            assert_eq!(result.outcome, DecisionOutcome::Allow);
            assert_eq!(result.risk_score, 0);
        }
    }
    let burst_time = fitted_at + 7 * 60_000;
    for event in 0..100 {
        let result = native(
            &store,
            &request("sandbox-1", &format!("burst-{event}"), "GET", burst_time),
        );
        assert_eq!(result.outcome, DecisionOutcome::Allow);
        assert_eq!(result.risk_score, 0);
    }
    let detail = store
        .operator_agent_detail("learner", burst_time)
        .unwrap()
        .unwrap();
    let burst = detail["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["request"]["request_id"] == "burst-99")
        .unwrap();
    assert!(
        burst["adaptive"][0]["assessment"]["score"]
            .as_u64()
            .unwrap()
            >= 70,
        "assessment={}, profile={}",
        burst["adaptive"],
        view["models"][0]["profile"]
    );
    assert_eq!(burst["adaptive"][0]["assessment"]["high_confidence"], true);
    let other = request(
        "validation-sandbox-4",
        "isolated-rate",
        "GET",
        burst_time + 1,
    );
    native(&store, &other);
    let detail = store
        .operator_agent_detail("learner", burst_time + 1)
        .unwrap()
        .unwrap();
    let other = detail["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["request"]["request_id"] == "isolated-rate")
        .unwrap();
    assert_eq!(other["adaptive"][0]["assessment"]["score"], 0);
    let reviewed = reviewed_would_block(&store, burst_time + 1);
    assert!(reviewed > 0, "the clean-run burst is unlabeled would-block evidence to review");
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::SetModel {
                    model_id: model_id.clone(),
                    mode: ModelMode::Enforce,
                    expected_active_model_id: None,
                    acknowledge_shadow_review: false,
                    reviewed_shadow_would_block: Some(reviewed),
                },
                "operator",
                burst_time + 2
            )
            .is_err()
    );
    for stale in [None, Some(reviewed - 1)] {
        let outcome = store.apply_adaptive_operation(
            "learner",
            &AdaptiveOperation::SetModel {
                model_id: model_id.clone(),
                mode: ModelMode::Enforce,
                expected_active_model_id: None,
                acknowledge_shadow_review: true,
                reviewed_shadow_would_block: stale,
            },
            "operator",
            burst_time + 2,
        );
        match stale {
            None => assert!(outcome.is_err(), "promotion must state what was reviewed"),
            Some(_) => assert!(
                matches!(outcome.unwrap(), AdaptiveUpdateResult::Conflict(_)),
                "a stale reviewed count must not promote"
            ),
        }
    }
    let view = apply(
        &store,
        AdaptiveOperation::SetModel {
            model_id: model_id.clone(),
            mode: ModelMode::Enforce,
            expected_active_model_id: None,
            acknowledge_shadow_review: true,
            reviewed_shadow_would_block: Some(reviewed),
        },
        burst_time + 3,
    );
    assert_eq!(
        view["audit"][0]["details"]["reviewed_shadow_would_block"],
        reviewed
    );
    assert_eq!(view["models"][0]["enforced"], true);
    let demoted = apply(
        &store,
        AdaptiveOperation::SetModel {
            model_id: model_id.clone(),
            mode: ModelMode::Shadow,
            expected_active_model_id: Some(model_id.clone()),
            acknowledge_shadow_review: false,
            reviewed_shadow_would_block: None,
        },
        burst_time + 4,
    );
    assert_eq!(demoted["models"][0]["enforced"], false);
    assert_eq!(demoted["models"][0]["shadow"], true);
    let shadow = native(
        &store,
        &request("sandbox-1", "demoted-burst", "GET", burst_time + 5),
    );
    assert_eq!(shadow.outcome, DecisionOutcome::Allow);
    assert_eq!(shadow.risk_score, 0);
    apply(
        &store,
        AdaptiveOperation::SetModel {
            model_id: model_id.clone(),
            mode: ModelMode::Enforce,
            expected_active_model_id: None,
            acknowledge_shadow_review: true,
            reviewed_shadow_would_block: Some(reviewed_would_block(&store, burst_time + 5)),
        },
        burst_time + 6,
    );
    let anomaly = request("sandbox-1", "enforced-burst", "GET", burst_time + 7);
    let denied = native(&store, &anomaly);
    assert_eq!(denied.outcome, DecisionOutcome::Deny);
    assert_eq!(denied.reason_code, "adaptive_anomaly_denied");
    assert!(matches!(
        denied.ratchet_action,
        RatchetAction::TriggerTier2Cooldown { .. }
    ));
    assert!(matches!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::SetModel {
                    model_id: model_id.clone(),
                    mode: ModelMode::Off,
                    expected_active_model_id: None,
                    acknowledge_shadow_review: false,
                    reviewed_shadow_would_block: None,
                },
                "operator",
                burst_time + 8
            )
            .unwrap(),
        AdaptiveUpdateResult::Conflict(_)
    ));
    apply(
        &store,
        AdaptiveOperation::SetModel {
            model_id,
            mode: ModelMode::Off,
            expected_active_model_id: Some(view["models"][0]["model_id"].as_str().unwrap().into()),
            acknowledge_shadow_review: false,
            reviewed_shadow_would_block: None,
        },
        burst_time + 9,
    );
    assert_eq!(native(&store, &anomaly), denied);
    let next = native(
        &store,
        &request("sandbox-1", "cooldown-survives", "GET", burst_time + 10),
    );
    assert_eq!(next.outcome, DecisionOutcome::Deny);
    assert_eq!(next.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
}

#[test]
fn captured_runs_cannot_be_reused_or_rebound_and_old_models_stay_frozen() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("windows.db"));
    let t = now();
    let first = train_one(&store, t);
    let first_id = first["models"][0]["model_id"].clone();
    let first_hash = first["models"][0]["model_hash"].clone();
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::StartCapture {
                    run_id: "run-1".into(),
                    scope: LearningScope::LocalDemo,
                    expected_guardrails_revision: 0,
                },
                "operator",
                t + 120_000
            )
            .is_err()
    );
    bind(&store, "new-run", "new-sandbox");
    assert!(
        store
            .bind_agent_run("run-1", "new-sandbox", "gateway")
            .is_err()
    );
    let session = start(&store, "new-run", LearningScope::LocalDemo, t + 120_000);
    for event in 0..12 {
        native(
            &store,
            &request(
                "new-sandbox",
                &format!("second-{event}"),
                "GET",
                t + 120_001 + event,
            ),
        );
    }
    review(&store, &session, CaptureReview::Finish, t + 120_100);
    let view = review(&store, &session, CaptureReview::Approve, t + 120_101);
    let view = apply(
        &store,
        AdaptiveOperation::Train {
            context_id: view["sessions"][0]["context_id"].as_str().unwrap().into(),
            scope: LearningScope::LocalDemo,
            expected_guardrails_revision: 0,
        },
        t + 120_102,
    );
    assert_eq!(view["models"][0]["profile"]["training_requests"], 12);
    assert_eq!(view["models"][0]["profile"]["training_sessions"], 1);
    assert_eq!(view["models"][0]["profile"]["training_runs"], 1);
    assert_eq!(view["models"][0]["profile"]["holdout_runs"], 1);
    let old = view["models"]
        .as_array()
        .unwrap()
        .iter()
        .find(|model| model["model_id"] == first_id)
        .unwrap();
    assert_eq!(old["model_hash"], first_hash);
    assert_eq!(old["profile"]["training_requests"], 12);
}

#[test]
fn capture_budget_overflow_quarantines_instead_of_training_a_truncated_subset() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("budget.db"));
    let t = now();
    let session = start(&store, "run-1", LearningScope::LocalDemo, t);
    for event in 0..501 {
        native(
            &store,
            &request("sandbox-1", &format!("budget-{event}"), "GET", t + 1),
        );
    }
    let view = store.agent_adaptive("learner", t + 2).unwrap().unwrap();
    assert_eq!(view["sessions"][0]["status"], "quarantined");
    assert_eq!(
        view["sessions"][0]["quarantine_reason"],
        "capture_sample_budget_exceeded"
    );
    assert_eq!(view["sessions"][0]["request_count"], 500);
    assert!(
        store
            .apply_adaptive_operation(
                "learner",
                &AdaptiveOperation::ReviewCapture {
                    session_id: session,
                    action: CaptureReview::Approve,
                    notes: "".into(),
                },
                "operator",
                t + 3
            )
            .is_err()
    );
}

#[test]
fn same_millisecond_finish_keeps_exclusive_capture_bounds_valid() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("clock.db"));
    let t = now();
    let session = start(&store, "run-1", LearningScope::LocalDemo, t);
    native(&store, &request("sandbox-1", "same-ms", "GET", t + 1));
    review(&store, &session, CaptureReview::Finish, t + 1);
    let view = review(&store, &session, CaptureReview::Approve, t + 3);
    let view = apply(
        &store,
        AdaptiveOperation::Train {
            context_id: view["sessions"][0]["context_id"].as_str().unwrap().into(),
            scope: LearningScope::LocalDemo,
            expected_guardrails_revision: 0,
        },
        t + 4,
    );
    assert_eq!(view["models"][0]["profile"]["training_requests"], 1);
}

#[test]
fn auto_learning_never_approves_flagged_windows_or_manual_captures() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("auto-gate.db"));
    let t = now();
    apply(&store, AdaptiveOperation::SetAutoLearning { enabled: true }, t);

    // A read-only request the detector flagged (unexpected binary) is "clean" enough
    // to keep recording, but not enough to approve without a human.
    bind(&store, "flagged-run", "flagged-sandbox");
    native(&store, &request("flagged-sandbox", "flagged-plain", "GET", t + 1));
    let mut odd = request("flagged-sandbox", "flagged-odd-binary", "GET", t + 2);
    odd.binary_path = Some("/tmp/unknown-tool".into());
    let flagged = native(&store, &odd);
    assert_eq!(flagged.outcome, DecisionOutcome::AllowWithObservation);
    store.end_agent_run("flagged-run").unwrap();

    // An operator-started capture always waits for its operator's review.
    bind(&store, "manual-run", "manual-sandbox");
    let manual = start(&store, "manual-run", LearningScope::LocalDemo, t + 10);
    native(&store, &request("manual-sandbox", "manual-get", "GET", t + 11));
    store.end_agent_run("manual-run").unwrap();

    let view = store.agent_adaptive("learner", t + 20).unwrap().unwrap();
    let session = |run: &str| {
        view["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["run_id"] == run)
            .unwrap()
            .clone()
    };
    for run in ["flagged-run", "manual-run"] {
        let found = session(run);
        assert_eq!(found["status"], "pending_review", "{run}");
        assert!(found["reviewed_by"].is_null(), "{run}");
    }
    assert_eq!(session("manual-run")["session_id"], manual.as_str());
    assert!(view["models"].as_array().unwrap().is_empty());
}

fn path_request(sandbox: &str, id: &str, method: &str, path: &str, t: i64) -> NormalizedRequest {
    CanonicalNormalizer::new_default(b"adaptive-test-only-key")
        .normalize(&RawRequestInput {
            request_id: id.into(),
            sandbox_id: sandbox.into(),
            sandbox_name: sandbox.into(),
            workspace: "default".into(),
            scheme: "https".into(),
            host: "api.github.local".into(),
            port: 18443,
            method: method.into(),
            path: path.into(),
            binary_path: Some("/usr/bin/curl".into()),
            pid: None,
            ancestors: vec![],
            timestamp_ms: t,
        })
        .unwrap()
}

#[test]
fn zero_click_auto_shadow_learning_enrolls_approves_and_fits_on_run_end_while_blocking_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("auto-shadow.db"));
    let t = now();

    // Shadow learning is on for every agent by default; no setup step.
    let view = store.agent_adaptive("learner", t).unwrap().unwrap();
    assert_eq!(view["auto_shadow_learning"], true);

    bind(&store, "auto-run-1", "auto-sandbox-1");
    for i in 0..12 {
        native(
            &store,
            &request("auto-sandbox-1", &format!("auto-get-{i}"), "GET", t + 1 + i),
        );
    }

    let view = store.agent_adaptive("learner", t + 20).unwrap().unwrap();
    assert_eq!(view["auto_shadow_learning"], true);
    let session = view["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["run_id"] == "auto-run-1")
        .expect("auto-enrolled session created on first native request");
    assert_eq!(session["status"], "recording");
    assert_eq!(session["notes"], "auto-enrolled");
    assert_eq!(session["request_count"], 12);

    store.end_agent_run("auto-run-1").unwrap();

    let view = store.agent_adaptive("learner", t + 30).unwrap().unwrap();
    let session = view["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["run_id"] == "auto-run-1")
        .unwrap();
    assert_eq!(session["status"], "approved");
    assert_eq!(session["reviewed_by"], "auto-clean-policy");
    assert_eq!(view["models"].as_array().unwrap().len(), 1);
    assert_eq!(view["models"][0]["shadow"], true);
    assert_eq!(view["models"][0]["enforced"], false);
    assert_eq!(view["models"][0]["profile"]["training_requests"], 12);
    assert_eq!(view["models"][0]["auto_approved_sessions"], 1);

    bind(&store, "auto-run-dirty", "auto-sandbox-dirty");
    native(
        &store,
        &request("auto-sandbox-dirty", "dirty-get", "GET", t + 100),
    );
    native(
        &store,
        &path_request(
            "auto-sandbox-dirty",
            "dirty-post-issue",
            "POST",
            "/repos/org/docs-site/issues",
            t + 101,
        ),
    );
    store.end_agent_run("auto-run-dirty").unwrap();
    let view = store.agent_adaptive("learner", t + 105).unwrap().unwrap();
    let dirty_session = view["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["run_id"] == "auto-run-dirty")
        .unwrap();
    assert_eq!(dirty_session["status"], "quarantined");

    bind(&store, "auto-run-graphql", "auto-sandbox-graphql");
    native(
        &store,
        &path_request(
            "auto-sandbox-graphql",
            "dirty-graphql",
            "POST",
            "/graphql",
            t + 200,
        ),
    );
    store.end_agent_run("auto-run-graphql").unwrap();
    let view = store.agent_adaptive("learner", t + 205).unwrap().unwrap();
    let gql_session = view["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["run_id"] == "auto-run-graphql")
        .unwrap();
    assert_eq!(gql_session["status"], "quarantined");

    let view = apply(
        &store,
        AdaptiveOperation::SetAutoLearning { enabled: false },
        t + 300,
    );
    assert_eq!(view["auto_shadow_learning"], false);
    bind(&store, "paused-run", "paused-sandbox");
    native(
        &store,
        &request("paused-sandbox", "paused-get", "GET", t + 301),
    );
    let view = store.agent_adaptive("learner", t + 302).unwrap().unwrap();
    assert!(
        !view["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["run_id"] == "paused-run"),
        "paused auto-learning must not auto-enroll runs"
    );

    let view = apply(
        &store,
        AdaptiveOperation::SetAutoLearning { enabled: true },
        t + 400,
    );
    assert_eq!(view["auto_shadow_learning"], true);
    bind(&store, "resumed-run", "resumed-sandbox");
    native(
        &store,
        &request("resumed-sandbox", "resumed-get", "GET", t + 401),
    );
    let view = store.agent_adaptive("learner", t + 402).unwrap().unwrap();
    assert!(
        view["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["run_id"] == "resumed-run" && s["status"] == "recording")
    );
}

