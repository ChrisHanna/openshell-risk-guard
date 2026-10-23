// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Backup and restore: a verified snapshot taken while the database is in use brings back what was restricted, and every way it can be wrong is refused.

use openshell_risk_guard::backup::{backup, restore, verify};
use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::{RestrictionTarget, SqliteRiskStore};
use openshell_risk_guard::types::*;

const HMAC_KEY: &[u8] = b"backup-test-only-hmac-key";
const START: i64 = 1_800_000_000_000;

fn send(
    store: &SqliteRiskStore,
    id: &str,
    method: &str,
    resource: &str,
    at: i64,
) -> RiskEvaluation {
    let request = CanonicalNormalizer::new_default(HMAC_KEY)
        .normalize(&RawRequestInput {
            request_id: id.into(),
            sandbox_id: "sbx-1".into(),
            sandbox_name: "sbx-1".into(),
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
            timestamp_ms: at,
        })
        .unwrap();
    store
        .evaluate_authenticated(
            &request,
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
        )
        .unwrap()
}

/// A database where one workload has a latched restriction and another is quarantined.
fn populated(path: &std::path::Path) -> SqliteRiskStore {
    let store = seed_fixture_store(path).unwrap();
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline).unwrap();
    store.register_agent("agent-r", "Restricted agent").unwrap();
    store
        .register_agent("agent-q", "Quarantined agent")
        .unwrap();
    let baseline = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    store
        .create_agent_run(
            "agent-r",
            "run-1",
            "revision-1",
            &baseline.task_profile,
            EnforcementMode::Enforce,
        )
        .unwrap();
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: "epoch-sbx-1".into(),
            gateway_id: "gateway".into(),
            sandbox_id: "sbx-1".into(),
            task_profile: baseline.task_profile.clone(),
            baseline_hash: compute_baseline_hash(&baseline),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: START,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
    store.bind_agent_run("run-1", "sbx-1", "gateway").unwrap();
    for n in 0..4 {
        send(
            &store,
            &format!("get-{n}"),
            "GET",
            "docs-site",
            START + 1_000 * (n + 1),
        );
    }
    let denied = send(&store, "del-1", "DELETE", "payments-prod", START + 10_000);
    assert_eq!(denied.outcome, DecisionOutcome::Deny);
    store
        .quarantine_workload("agent-q", "alice", "investigating", START + 11_000)
        .unwrap();
    store
}

fn restricted(store: &SqliteRiskStore) -> bool {
    let view = store
        .list_restrictions(
            RestrictionTarget::Agent {
                agent_id: "agent-r",
                context_id: None,
            },
            START + 20_000,
        )
        .unwrap();
    !view.to_string().contains("\"restrictions\":[]")
}

#[test]
fn a_snapshot_taken_while_the_database_is_open_restores_what_was_restricted_and_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live.db");
    let live = populated(&db);
    assert!(restricted(&live));

    let file = dir.path().join("snapshot.db");
    let taken = backup(&db, &file).unwrap();
    assert_eq!(taken.integrity, "ok");
    assert!(taken.rows["decisions"] >= 5 && taken.rows["workload_quarantine"] == 1);
    assert_eq!(verify(&file).unwrap().sha256, taken.sha256);

    // The live database is lost; restore into a clean place.
    drop(live);
    let clean = dir.path().join("clean.db");
    let restored = restore(&file, &clean, false).unwrap();
    assert_eq!(restored.rows["decisions"], taken.rows["decisions"]);

    let store = SqliteRiskStore::open(&clean).unwrap();
    assert!(
        restricted(&store),
        "the workload that was restricted is still restricted"
    );
    assert_eq!(
        store.list_quarantined().unwrap()["quarantined"][0]["agent_id"],
        "agent-q"
    );
    // And it still decides: the same denied action is refused again, now by the carried restriction.
    let again = send(&store, "del-2", "DELETE", "payments-prod", START + 30_000);
    assert_eq!(again.outcome, DecisionOutcome::Deny);
    assert_eq!(again.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
}

#[test]
fn a_damaged_unchecked_or_existing_target_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live.db");
    drop(populated(&db));
    let file = dir.path().join("snapshot.db");
    backup(&db, &file).unwrap();

    // The directory for backups is created when it is missing (on the cluster's volume it does not exist until the first backup).
    let nested = dir
        .path()
        .join("backups")
        .join("nested")
        .join("snapshot.db");
    assert!(backup(&db, &nested).is_ok() && verify(&nested).is_ok());
    // A backup is never overwritten.
    assert!(backup(&db, &file).is_err());
    // A restore never replaces a database unless told to.
    assert!(restore(&file, &db, false).is_err());
    // A backup without a checksum file is not accepted.
    let bare = dir.path().join("bare.db");
    std::fs::copy(&file, &bare).unwrap();
    assert!(verify(&bare).is_err());
    assert!(restore(&bare, &dir.path().join("x.db"), false).is_err());
    // A changed byte is caught.
    let tampered = dir.path().join("tampered.db");
    let mut bytes = std::fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&tampered, bytes).unwrap();
    std::fs::copy(
        format!("{}.sha256", file.display()),
        format!("{}.sha256", tampered.display()),
    )
    .unwrap();
    assert!(verify(&tampered).is_err());
    assert!(restore(&tampered, &dir.path().join("y.db"), false).is_err());
    // Nothing was created by the refused restores.
    assert!(!dir.path().join("x.db").exists() && !dir.path().join("y.db").exists());
}

#[test]
fn restoring_an_older_snapshot_over_a_newer_database_loses_the_newer_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live.db");
    let live = populated(&db);
    let file = dir.path().join("older.db");
    let before = backup(&db, &file).unwrap();
    for n in 0..3 {
        send(
            &live,
            &format!("later-{n}"),
            "GET",
            "docs-site",
            START + 40_000 + n,
        );
    }
    drop(live);
    let restored = restore(&file, &db, true).unwrap();
    assert_eq!(
        restored.rows["decisions"], before.rows["decisions"],
        "the three later decisions are gone, and the report says so"
    );
    // ...but they are not destroyed: the database that was replaced is kept, verified, beside it.
    let kept = dir.path().join("live.db.before-restore");
    assert_eq!(
        verify(&kept).unwrap().rows["decisions"],
        before.rows["decisions"] + 3
    );
}
