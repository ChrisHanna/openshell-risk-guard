use openshell_risk_guard::cli::open_and_seed_store;
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::*;

fn epoch(store: &SqliteRiskStore, sandbox: &str, epoch_id: &str) {
    let baseline = build_standard_corpus().default_baseline;
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: epoch_id.into(),
            gateway_id: "gateway".into(),
            sandbox_id: sandbox.into(),
            task_profile: baseline.task_profile.clone(),
            baseline_hash: compute_baseline_hash(&baseline),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: 0,
            credentialed_endpoints: [("api.github.local".into(), 18443)].into(),
            active_policy_hash: None,
        })
        .unwrap();
}

fn request(sandbox: &str, id: &str, method: &str, path: &str, time: i64) -> NormalizedRequest {
    CanonicalNormalizer::new_default(b"stable-test-key")
        .normalize(&RawRequestInput {
            request_id: id.into(),
            sandbox_id: sandbox.into(),
            sandbox_name: sandbox.into(),
            workspace: "display-only".into(),
            scheme: "https".into(),
            host: "api.github.local".into(),
            port: 18443,
            method: method.into(),
            path: path.into(),
            binary_path: Some("/usr/bin/curl".into()),
            pid: None,
            ancestors: vec![],
            timestamp_ms: time,
        })
        .unwrap()
}

fn run(store: &SqliteRiskStore, agent: &str, run_id: &str, revision: &str) {
    store
        .create_agent_run(
            agent,
            run_id,
            revision,
            "repo-triage-readonly",
            EnforcementMode::Enforce,
        )
        .unwrap();
}

#[test]
fn agent_restrictions_follow_new_runs_and_sandboxes_but_not_other_agents() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("agent.db");
    let store = open_and_seed_store(&db).unwrap();
    store.register_agent("agent-a", "Reviewer").unwrap();
    store.register_agent("agent-b", "Reviewer").unwrap();
    run(&store, "agent-a", "run-a1", "rev1");
    epoch(&store, "sandbox-a", "epoch-a");
    store
        .bind_agent_run("run-a1", "sandbox-a", "gateway")
        .unwrap();
    let detector = InteractionRiskDetector::new_default();
    let first = request(
        "sandbox-a",
        "delete-1",
        "DELETE",
        "/repos/org/unfamiliar",
        60_000,
    );
    assert_eq!(
        store
            .evaluate_and_commit_atomic(&first, &detector)
            .unwrap()
            .outcome,
        DecisionOutcome::Deny
    );
    drop(store);
    let store = SqliteRiskStore::open(&db).unwrap();
    run(&store, "agent-a", "run-a2", "rev1");
    epoch(&store, "sandbox-b", "epoch-b");
    store
        .bind_agent_run("run-a2", "sandbox-b", "gateway")
        .unwrap();
    let second = request(
        "sandbox-b",
        "delete-2",
        "DELETE",
        "/repos/org/unfamiliar",
        61_000,
    );
    let decision = store
        .evaluate_and_commit_atomic(&second, &detector)
        .unwrap();
    assert_eq!(decision.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
    assert_eq!(
        store
            .evaluate_and_commit_atomic(&second, &detector)
            .unwrap(),
        decision
    );
    let detail = store
        .operator_agent_detail("agent-a", 61_000)
        .unwrap()
        .unwrap();
    assert_eq!(detail["decisions"].as_array().unwrap().len(), 2);
    assert_eq!(detail["runs"].as_array().unwrap().len(), 2);
    assert_eq!(detail["contexts"].as_array().unwrap().len(), 1);
    assert_eq!(detail["decisions"][0]["identity"]["run_id"], "run-a2");
    assert_eq!(
        detail["contexts"][0]["active_restrictions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        detail["contexts"][0]["active_restrictions"][0]["trigger_epoch_id"],
        "epoch-a"
    );
    run(&store, "agent-b", "run-b1", "rev1");
    epoch(&store, "sandbox-c", "epoch-c");
    store
        .bind_agent_run("run-b1", "sandbox-c", "gateway")
        .unwrap();
    let other = request(
        "sandbox-c",
        "delete-3",
        "DELETE",
        "/repos/org/unfamiliar",
        62_000,
    );
    assert_ne!(
        store
            .evaluate_and_commit_atomic(&other, &detector)
            .unwrap()
            .reason_code,
        REASON_BEHAVIORAL_RISK_RESTRICTED
    );
    assert!(
        store
            .operator_agent_detail("unknown", 62_000)
            .unwrap()
            .is_none()
    );
}

#[test]
fn windows_are_shared_and_bindings_cannot_rewrite_history_or_downgrade() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("agent.db")).unwrap();
    store.register_agent("agent", "Reviewer").unwrap();
    run(&store, "agent", "run-1", "v1");
    epoch(&store, "sb1", "ep1");
    store.bind_agent_run("run-1", "sb1", "gateway").unwrap();
    let detector = InteractionRiskDetector::new_default();
    store
        .evaluate_and_commit_atomic(
            &request("sb1", "r1", "GET", "/repos/org/docs-site", 60_000),
            &detector,
        )
        .unwrap();
    run(&store, "agent", "run-2", "v1");
    epoch(&store, "sb2", "ep2");
    store.bind_agent_run("run-2", "sb2", "gateway").unwrap();
    store
        .evaluate_and_commit_atomic(
            &request("sb2", "r2", "GET", "/repos/org/docs-site", 61_000),
            &detector,
        )
        .unwrap();
    let detail = store
        .operator_agent_detail("agent", 61_000)
        .unwrap()
        .unwrap();
    assert_eq!(detail["contexts"][0]["window"]["req_count_1m"], 2);
    assert!(store.bind_agent_run("run-2", "sb1", "gateway").is_err());
    assert!(store.register_agent("agent", "different label").is_err());
    epoch(&store, "sb1", "ep3");
    assert!(
        store
            .evaluate_and_commit_atomic(
                &request("sb1", "unbound", "GET", "/repos/org/docs-site", 62_000),
                &detector
            )
            .is_err()
    );
    assert!(
        store
            .bind_agent_run("run-2", "sb1", "wrong-gateway")
            .is_err()
    );
    store.bind_agent_run("run-2", "sb1", "gateway").unwrap();
    assert!(
        store
            .evaluate_authenticated(
                &request("sb1", "wrong-caller", "GET", "/repos/org/docs-site", 62_000),
                &detector,
                "other-gateway",
                true
            )
            .is_err()
    );
    run(&store, "agent", "run-revision", "v2");
    epoch(&store, "sb3", "ep4");
    store
        .bind_agent_run("run-revision", "sb3", "gateway")
        .unwrap();
    let detail = store
        .operator_agent_detail("agent", 62_000)
        .unwrap()
        .unwrap();
    assert_eq!(detail["contexts"].as_array().unwrap().len(), 2);
}

#[test]
fn concurrent_sandboxes_share_atomic_windows_and_retries_do_not_double_count() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("agent.db");
    let store = open_and_seed_store(&db).unwrap();
    store
        .register_agent("agent", "Concurrent reviewer")
        .unwrap();
    run(&store, "agent", "run-1", "v1");
    for index in 0..4 {
        let sandbox = format!("sandbox-{index}");
        epoch(&store, &sandbox, &format!("epoch-{index}"));
        store.bind_agent_run("run-1", &sandbox, "gateway").unwrap();
    }
    let handles: Vec<_> = (0..20)
        .map(|index| {
            let db = db.clone();
            std::thread::spawn(move || {
                let store = SqliteRiskStore::open(db).unwrap();
                let req = request(
                    &format!("sandbox-{}", index % 4),
                    &format!("request-{index}"),
                    "GET",
                    "/repos/org/docs-site",
                    60_000,
                );
                let detector = InteractionRiskDetector::new_default();
                let first = store.evaluate_and_commit_atomic(&req, &detector).unwrap();
                assert_eq!(
                    first,
                    store.evaluate_and_commit_atomic(&req, &detector).unwrap()
                );
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let detail = store
        .operator_agent_detail("agent", 60_000)
        .unwrap()
        .unwrap();
    assert_eq!(detail["contexts"][0]["window"]["req_count_1m"], 20);
    assert_eq!(detail["decisions"].as_array().unwrap().len(), 20);
}

#[test]
fn baseline_mode_and_revision_changes_are_isolated_and_old_context_is_retained() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("agent.db")).unwrap();
    store.register_agent("agent", "Reviewer").unwrap();
    run(&store, "agent", "original", "v1");
    epoch(&store, "sandbox", "original-epoch");
    store
        .bind_agent_run("original", "sandbox", "gateway")
        .unwrap();
    let detector = InteractionRiskDetector::new_default();
    store
        .evaluate_and_commit_atomic(
            &request("sandbox", "r1", "DELETE", "/repos/org/unfamiliar", 60_000),
            &detector,
        )
        .unwrap();
    run(&store, "agent", "revision", "v2");
    store
        .create_agent_run(
            "agent",
            "observe",
            "v1",
            "repo-triage-readonly",
            EnforcementMode::Observe,
        )
        .unwrap();
    store
        .create_agent_run(
            "agent",
            "maintenance",
            "v1",
            "maintenance-cleanup",
            EnforcementMode::Enforce,
        )
        .unwrap();
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.version = "new-approved-version".into();
    store.store_baseline(&baseline).unwrap();
    run(&store, "agent", "new-baseline", "v1");
    let detail = store
        .operator_agent_detail("agent", 61_000)
        .unwrap()
        .unwrap();
    assert_eq!(detail["contexts"].as_array().unwrap().len(), 5);
    let original_context = detail["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["run_id"] == "original")
        .unwrap()["context_id"]
        .clone();
    assert_eq!(
        detail["contexts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["context_id"] == original_context)
            .unwrap()["active_restrictions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Existing run stays pinned to its original artifact even after a new import.
    epoch(&store, "replacement", "replacement-epoch");
    let mut latest = store.get_active_epoch("replacement").unwrap().unwrap();
    latest.baseline_hash = compute_baseline_hash(&baseline);
    store.upsert_epoch(&latest).unwrap();
    assert!(
        store
            .bind_agent_run("original", "replacement", "gateway")
            .is_err()
    );
    let mut pinned = store.get_active_epoch("replacement").unwrap().unwrap();
    pinned.baseline_hash = detail["contexts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["context_id"] == original_context)
        .unwrap()["baseline_hash"]
        .as_str()
        .unwrap()
        .into();
    store.upsert_epoch(&pinned).unwrap();
    store
        .bind_agent_run("original", "replacement", "gateway")
        .unwrap();
    assert_eq!(
        store
            .evaluate_and_commit_atomic(
                &request(
                    "replacement",
                    "r2",
                    "DELETE",
                    "/repos/org/unfamiliar",
                    62_000
                ),
                &detector
            )
            .unwrap()
            .reason_code,
        REASON_BEHAVIORAL_RISK_RESTRICTED
    );
}

#[test]
fn ended_runs_and_detector_drift_fail_closed_and_legacy_history_is_not_reattributed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("agent.db")).unwrap();
    epoch(&store, "legacy", "legacy-epoch");
    let detector = InteractionRiskDetector::new_default();
    let req = request(
        "legacy",
        "legacy-request",
        "GET",
        "/repos/org/docs-site",
        60_000,
    );
    let historical = store.evaluate_and_commit_atomic(&req, &detector).unwrap();
    store.register_agent("agent", "Reviewer").unwrap();
    run(&store, "agent", "run", "v1");
    assert!(store.bind_agent_run("run", "legacy", "gateway").is_err());
    assert_eq!(
        store
            .operator_agent_detail("agent", 61_000)
            .unwrap()
            .unwrap()["decisions"],
        serde_json::json!([])
    );
    assert_eq!(
        store.evaluate_and_commit_atomic(&req, &detector).unwrap(),
        historical
    );
    assert!(
        store
            .evaluate_authenticated(&req, &detector, "gateway", true)
            .is_err()
    );
    epoch(&store, "bound", "bound-epoch");
    store.bind_agent_run("run", "bound", "gateway").unwrap();
    let req = request(
        "bound",
        "new-request",
        "GET",
        "/repos/org/docs-site",
        61_000,
    );
    let mut changed = detector.clone();
    changed.enforce_threshold = 99;
    assert!(store.evaluate_and_commit_atomic(&req, &changed).is_err());
    let mut altered = store.get_active_epoch("bound").unwrap().unwrap();
    altered.task_profile = "other".into();
    assert!(store.upsert_epoch(&altered).is_err());
    store.end_agent_run("run").unwrap();
    assert!(store.evaluate_and_commit_atomic(&req, &detector).is_err());
    assert!(store.clear_runtime_tables().is_err());
}

#[test]
fn pre_identity_database_migrates_without_rewriting_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("legacy.db");
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(include_str!("../migrations/0001_initial.sql"))
            .unwrap();
        conn.execute_batch(
            "INSERT INTO epochs VALUES ('old','gateway','legacy','profile','missing','observe',1,2,0,'[]',NULL);
             INSERT INTO decisions VALUES ('old','request','legacy',1,'fingerprint','{}','{\"original\":true}','allow',0,100);"
        ).unwrap();
    }

    let store = SqliteRiskStore::open(&db).unwrap();
    store.register_agent("agent", "New agent").unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(&db).unwrap();
    let payload: String = conn
        .query_row("SELECT evaluation_json FROM decisions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(payload, "{\"original\":true}");
    let identities: i64 = conn
        .query_row("SELECT COUNT(*) FROM decision_identity", [], |r| r.get(0))
        .unwrap();
    assert_eq!(identities, 0);
    drop(conn);
    SqliteRiskStore::open(db).unwrap();
}

#[test]
fn distributed_bursts_are_scored_together_and_cooldown_strikes_survive_new_runs() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("agent.db")).unwrap();
    store
        .register_agent("agent", "Distributed reviewer")
        .unwrap();
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.max_req_1m_p95 = 1;
    baseline.max_req_1m_p99 = 1;
    baseline.max_distinct_resources_15m_p95 = 1;
    baseline.max_distinct_resources_15m_p99 = 1;
    let hash = store.store_baseline(&baseline).unwrap();
    let detector = InteractionRiskDetector::new_default();
    for strike in 0..3 {
        let run_id = format!("run-{strike}");
        run(&store, "agent", &run_id, "v1");
        for side in 0..2 {
            let sandbox = format!("sandbox-{strike}-{side}");
            epoch(&store, &sandbox, &format!("epoch-{strike}-{side}"));
            let mut ep = store.get_active_epoch(&sandbox).unwrap().unwrap();
            ep.baseline_hash = hash.clone();
            store.upsert_epoch(&ep).unwrap();
            store.bind_agent_run(&run_id, &sandbox, "gateway").unwrap();
        }

        let time = 1_000_000 * (strike + 1);
        let mut denied = false;
        for index in 0..10 {
            let req = request(
                &format!("sandbox-{strike}-{}", index % 2),
                &format!("r-{strike}-{index}"),
                "GET",
                &format!("/repos/org/unfamiliar-{index}"),
                time,
            );
            let eval = store.evaluate_and_commit_atomic(&req, &detector).unwrap();
            if index < 9 {
                assert_ne!(eval.outcome, DecisionOutcome::Deny);
            }
            if eval.outcome == DecisionOutcome::Deny {
                denied = true;
                assert!(
                    eval.signals
                        .iter()
                        .any(|s| s.feature == "V" && s.contribution > 0)
                );
                assert!(
                    eval.signals
                        .iter()
                        .any(|s| s.feature == "F" && s.contribution > 0)
                );
            }
        }
        assert!(
            denied,
            "distributed activity must reach the shared threshold"
        );
        let detail = store.operator_agent_detail("agent", time).unwrap().unwrap();
        let restriction = &detail["contexts"][0]["active_restrictions"][0];
        assert_eq!(restriction["strike_count"], strike + 1);
        assert_eq!(
            restriction["tier"],
            if strike == 2 {
                "strict_epoch"
            } else {
                "cooldown"
            }
        );
        store.end_agent_run(&run_id).unwrap();
    }
}

#[tokio::test]
async fn operator_cli_provisions_agent_run_and_authenticated_gateway_binding() {
    use clap::Parser;
    use openshell_risk_guard::cli::{Cli, execute_cli};
    async fn command(args: Vec<&str>) {
        execute_cli(Cli::try_parse_from(args).unwrap())
            .await
            .unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.db");
    let profile = dir.path().join("approved.json");
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version = "v1".into();
    std::fs::write(&profile, serde_json::to_vec(&baseline).unwrap()).unwrap();
    let db = path.to_str().unwrap();
    command(vec![
        "rg",
        "baseline-import",
        "--db",
        db,
        "--profile",
        profile.to_str().unwrap(),
    ])
    .await;
    command(vec![
        "rg",
        "agent-register",
        "--db",
        db,
        "--agent-id",
        "reviewer",
        "--display-name",
        "Reviewer",
    ])
    .await;
    command(vec![
        "rg",
        "run-create",
        "--db",
        db,
        "--agent-id",
        "reviewer",
        "--run-id",
        "run-1",
        "--agent-revision",
        "v1",
        "--task-profile",
        "repo-triage-readonly",
    ])
    .await;
    command(vec![
        "rg",
        "epoch-create",
        "--db",
        db,
        "--sandbox-id",
        "native-sandbox",
        "--gateway-id",
        "native-gateway",
    ])
    .await;
    command(vec![
        "rg",
        "run-bind",
        "--db",
        db,
        "--run-id",
        "run-1",
        "--sandbox-id",
        "native-sandbox",
        "--gateway-id",
        "native-gateway",
    ])
    .await;
    let store = SqliteRiskStore::open(&path).unwrap();
    let req = request(
        "native-sandbox",
        "request",
        "GET",
        "/repos/org/docs-site",
        60_000,
    );
    store
        .evaluate_authenticated(
            &req,
            &InteractionRiskDetector::new_default(),
            "native-gateway",
            true,
        )
        .unwrap();
    let detail = store
        .operator_agent_detail("reviewer", 60_000)
        .unwrap()
        .unwrap();
    assert_eq!(detail["decisions"][0]["identity"]["run_id"], "run-1");
    command(vec!["rg", "run-end", "--db", db, "--run-id", "run-1"]).await;
    assert!(
        store
            .evaluate_authenticated(
                &req,
                &InteractionRiskDetector::new_default(),
                "native-gateway",
                true
            )
            .is_err()
    );
}

#[test]
fn coverage_gaps_spanning_bindings_are_clipped_not_assigned_wholesale_to_an_agent() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_and_seed_store(dir.path().join("agent.db")).unwrap();
    for (agent, run_id, epoch_id, start) in [
        ("first-agent", "first-run", "first-epoch", 100),
        ("next-agent", "next-run", "next-epoch", 200),
    ] {
        store.register_agent(agent, agent).unwrap();
        run(&store, agent, run_id, "v1");
        epoch(&store, "reused-sandbox", epoch_id);
        let mut ep = store.get_active_epoch("reused-sandbox").unwrap().unwrap();
        ep.created_at_ms = start;
        store.upsert_epoch(&ep).unwrap();
        store
            .bind_agent_run(run_id, "reused-sandbox", "gateway")
            .unwrap();
    }
    store
        .record_coverage_gap("reused-sandbox", "collector unavailable", 150, 250)
        .unwrap();
    let first = store
        .operator_agent_detail("first-agent", 300)
        .unwrap()
        .unwrap();
    let next = store
        .operator_agent_detail("next-agent", 300)
        .unwrap()
        .unwrap();
    assert_eq!(first["recorded_coverage_gaps"][0]["start_ms"], 150);
    assert_eq!(first["recorded_coverage_gaps"][0]["end_ms"], 200);
    assert_eq!(next["recorded_coverage_gaps"][0]["start_ms"], 200);
    assert_eq!(next["recorded_coverage_gaps"][0]["end_ms"], 250);
    assert_eq!(
        first["recorded_coverage_gaps"][0]["attribution"],
        "sandbox_interval_correlation_only"
    );
}
