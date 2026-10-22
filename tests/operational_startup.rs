use clap::Parser;
use openshell_risk_guard::cli::{Cli, execute_cli};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::RiskStore;
use tempfile::TempDir;

#[tokio::test]
async fn operational_commands_do_not_seed_fixture_baselines() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("operational.db");
    let output = execute_cli(
        Cli::try_parse_from([
            "risk-guard",
            "decision-inspect",
            "--db",
            db.to_str().unwrap(),
            "--sandbox-id",
            "unknown",
        ])
        .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(output, "[]");
    let store = SqliteRiskStore::open(&db).unwrap();
    assert!(
        store
            .get_baseline("repo-triage-readonly")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn epoch_requires_an_explicitly_imported_baseline() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("operational.db");
    let args = [
        "risk-guard",
        "epoch-create",
        "--db",
        db.to_str().unwrap(),
        "--sandbox-id",
        "actual-sandbox",
        "--task-profile",
        "repo-triage-readonly",
    ];
    let err = execute_cli(Cli::try_parse_from(args).unwrap())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("baseline"));
    assert!(
        SqliteRiskStore::open(&db)
            .unwrap()
            .get_active_epoch("actual-sandbox")
            .unwrap()
            .is_none()
    );

    let profile = dir.path().join("approved.json");
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version = "v1".to_string();
    std::fs::write(&profile, serde_json::to_vec(&baseline).unwrap()).unwrap();
    execute_cli(
        Cli::try_parse_from([
            "risk-guard",
            "baseline-import",
            "--db",
            db.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
        ])
        .unwrap(),
    )
    .await
    .unwrap();
    execute_cli(Cli::try_parse_from(args).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn evidence_is_persisted_epoch_scoped_and_does_not_invent_process_or_outcome() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("operational.db");
    let store = SqliteRiskStore::open(&db).unwrap();
    let baseline = build_standard_corpus().default_baseline;
    store.store_baseline(&baseline).unwrap();
    execute_cli(
        Cli::try_parse_from([
            "risk-guard",
            "epoch-create",
            "--db",
            db.to_str().unwrap(),
            "--sandbox-id",
            "real-id",
            "--epoch-id",
            "first",
        ])
        .unwrap(),
    )
    .await
    .unwrap();
    execute_cli(
        Cli::try_parse_from([
            "risk-guard",
            "evaluate-request",
            "--db",
            db.to_str().unwrap(),
            "--sandbox-id",
            "real-id",
            "--request-id",
            "denied-action",
            "--method",
            "DELETE",
            "--path",
            "/repos/org/unfamiliar",
            // evaluate-request is a local debugging command: without a mounted HMAC key
            // it must be told explicitly that the public test key is acceptable.
            "--allow-insecure-local-test",
        ])
        .unwrap(),
    )
    .await
    .unwrap();

    let state = store.operator_inventory(i64::MAX - 1).unwrap();
    assert_eq!(
        state["sandboxes"][0]["behavioral_state"],
        "scoped_restrictions"
    );
    assert!(state["sandboxes"][0]["sandbox_compromise_probability"].is_null());
    let detail = store
        .operator_detail("real-id", i64::MAX - 1)
        .unwrap()
        .unwrap();
    assert_eq!(detail["decisions"][0]["request"]["method"], "DELETE");
    assert!(detail["decisions"][0]["request"]["binary_path"].is_null());
    assert_eq!(
        detail["decisions"][0]["request"]["ancestors"],
        serde_json::json!([])
    );
    assert!(detail["decisions"][0]["upstream_outcome"].is_null());
    assert_eq!(detail["active_restrictions"].as_array().unwrap().len(), 1);
    assert_eq!(detail["baseline"]["version"], baseline.version);
    drop(store);
    let store = SqliteRiskStore::open(&db).unwrap();
    assert_eq!(
        store
            .operator_detail("real-id", i64::MAX - 1)
            .unwrap()
            .unwrap(),
        detail
    );

    execute_cli(
        Cli::try_parse_from([
            "risk-guard",
            "epoch-create",
            "--db",
            db.to_str().unwrap(),
            "--sandbox-id",
            "real-id",
            "--epoch-id",
            "second",
        ])
        .unwrap(),
    )
    .await
    .unwrap();
    let next = store
        .operator_detail("real-id", i64::MAX - 1)
        .unwrap()
        .unwrap();
    assert_eq!(next["summary"]["behavioral_state"], "no_observations");
    assert_eq!(next["decisions"], serde_json::json!([]));
    assert_eq!(next["active_restrictions"], serde_json::json!([]));
}

#[test]
fn dashboard_inventory_excludes_expired_and_previous_epoch_restrictions() {
    use openshell_risk_guard::cli::open_and_seed_store;
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("operational.db");
    let store = open_and_seed_store(&db).unwrap();
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch(
        "INSERT INTO epochs (epoch_id, gateway_id, sandbox_id, task_profile, baseline_hash, mode, active, next_sequence, created_at_ms,
                             credentialed_endpoints_json, active_policy_hash)
         VALUES ('current','gateway','sandbox','repo-triage-readonly','hash','enforce',1,1,0,'[]',NULL);
         INSERT INTO epochs (epoch_id, gateway_id, sandbox_id, task_profile, baseline_hash, mode, active, next_sequence, created_at_ms,
                             credentialed_endpoints_json, active_policy_hash)
         VALUES ('old','gateway','sandbox','repo-triage-readonly','hash','enforce',0,1,0,'[]',NULL);
         INSERT INTO restrictions VALUES ('current','expired','cooldown',500,1,'expired',1);
         INSERT INTO restrictions VALUES ('old','old','strict_epoch',9223372036854775807,3,'old',1);"
    ).unwrap();
    let state = store.operator_inventory(1000).unwrap();
    assert_eq!(state["sandboxes"][0]["active_restriction_count"], 0);
    let detail = store.operator_detail("sandbox", 1000).unwrap().unwrap();
    assert_eq!(detail["active_restrictions"], serde_json::json!([]));
}

#[test]
fn operator_inventory_is_empty_without_observations() {
    let store = SqliteRiskStore::open_in_memory().unwrap();
    let state = store.operator_inventory(1000).unwrap();
    assert_eq!(state["sandboxes"], serde_json::json!([]));
    // Nothing observed is reported as "never seen", not as a blank, and with no invented figures.
    assert_eq!(state["gateway_connectivity"]["status"], "never_seen");
    assert_eq!(state["sandbox_lifecycle"]["sandboxes_recorded"], 0);
    assert_eq!(state["decision_latency"]["samples"], 0);
    assert!(store.operator_detail("missing", 1000).unwrap().is_none());
}

#[tokio::test]
async fn serve_rejects_missing_trust_configuration_before_listening() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("operational.db");
    let result = execute_cli(
        Cli::try_parse_from([
            "risk-guard",
            "serve",
            "--db",
            db.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ])
        .unwrap(),
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("public-key-pem"));
    assert!(!db.exists());
}
