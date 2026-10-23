// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Two-person approval: tightening stays one person's call; loosening takes a proposer and a different approver, and every way around that is closed or labelled.

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::error::RiskGuardError;
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::{RestrictionTarget, SqliteRiskStore};
use openshell_risk_guard::types::*;

const START: i64 = 1_800_000_000_000;
const DAY: i64 = 24 * 60 * 60 * 1000;

fn store(dir: &tempfile::TempDir) -> SqliteRiskStore {
    let store = seed_fixture_store(dir.path().join("rg.db")).unwrap();
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline).unwrap();
    store.register_agent("agent-r", "Release bot").unwrap();
    store.register_agent("agent-q", "Quarantined bot").unwrap();
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
    store
}

fn send(store: &SqliteRiskStore, id: &str, method: &str, resource: &str, at: i64) {
    let request = CanonicalNormalizer::new_default(b"two-person-test-key")
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
        .unwrap();
}

fn quarantined(store: &SqliteRiskStore) -> bool {
    !store.list_quarantined().unwrap()["quarantined"]
        .as_array()
        .unwrap()
        .is_empty()
}

fn denied(error: RiskGuardError) -> bool {
    matches!(error, RiskGuardError::PermissionDenied(_))
}

#[test]
fn without_the_rule_one_person_can_release_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    store
        .quarantine_workload("agent-q", "alice", "looking", START)
        .unwrap();
    assert!(
        store
            .release_workload("agent-q", "alice", "fine", START + 1)
            .unwrap()
    );
}

#[test]
fn with_the_rule_on_tightening_is_still_one_persons_call_and_loosening_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    store.require_two_person(START).unwrap();
    // Tightening: unaffected.
    store
        .quarantine_workload("agent-q", "alice", "suspicious", START)
        .unwrap();
    assert!(quarantined(&store));
    // Loosening alone: refused, and nothing changed.
    let error = store
        .release_workload("agent-q", "alice", "it was nothing", START + 1)
        .unwrap_err();
    assert!(denied(error));
    assert!(quarantined(&store));
}

#[test]
fn a_quarantine_is_released_only_when_someone_else_approves() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    store.require_two_person(START).unwrap();
    store
        .quarantine_workload("agent-q", "alice", "suspicious", START)
        .unwrap();

    let id = store
        .propose_change(
            "release_quarantine",
            "agent-q",
            &serde_json::json!({}),
            "reviewed: false alarm",
            "alice",
            START + 10,
        )
        .unwrap();
    // The proposer cannot approve their own request, in any capitalisation.
    for name in ["alice", "Alice ", "ALICE"] {
        let error = store
            .decide_change(&id, name, true, "yes", START + 20)
            .unwrap_err();
        assert!(denied(error), "{name}");
    }
    assert!(quarantined(&store));

    let done = store
        .decide_change(&id, "bob", true, "confirmed the logs", START + 30)
        .unwrap();
    assert!(
        done["outcome"].as_str().unwrap().starts_with("executed"),
        "{done}"
    );
    assert!(!quarantined(&store));

    // The audit trail names both people and the request.
    let changes = store.list_changes(10, START + 40).unwrap();
    assert_eq!(changes["changes"][0]["status"], "executed");
    assert_eq!(changes["changes"][0]["proposer"], "alice");
    assert_eq!(changes["changes"][0]["decided_by"], "bob");
    // A decided request cannot be decided again.
    assert!(
        store
            .decide_change(&id, "carol", true, "again", START + 50)
            .is_err()
    );
}

#[test]
fn a_rejected_or_expired_request_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    store.require_two_person(START).unwrap();
    store
        .quarantine_workload("agent-q", "alice", "suspicious", START)
        .unwrap();

    let id = store
        .propose_change(
            "release_quarantine",
            "agent-q",
            &serde_json::json!({}),
            "please",
            "alice",
            START + 1,
        )
        .unwrap();
    assert!(
        store
            .propose_change(
                "release_quarantine",
                "agent-q",
                &serde_json::json!({}),
                "again",
                "carol",
                START + 2
            )
            .is_err(),
        "no duplicate while one is waiting"
    );
    let rejected = store
        .decide_change(&id, "bob", false, "not yet", START + 3)
        .unwrap();
    assert_eq!(rejected["outcome"], "rejected");
    assert!(quarantined(&store));

    let late = store
        .propose_change(
            "release_quarantine",
            "agent-q",
            &serde_json::json!({}),
            "again",
            "alice",
            START + 4,
        )
        .unwrap();
    let error = store
        .decide_change(&late, "bob", true, "ok", START + 4 + DAY + 1)
        .unwrap_err();
    assert!(error.to_string().contains("expired"));
    assert!(quarantined(&store));
    assert_eq!(
        store.list_changes(10, START + 4 + DAY + 2).unwrap()["changes"][0]["status"],
        "expired"
    );
}

#[test]
fn a_latched_restriction_is_cleared_only_by_a_second_person_too() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    for n in 0..4 {
        send(
            &store,
            &format!("g{n}"),
            "GET",
            "docs-site",
            START + 1_000 * (n + 1),
        );
    }
    send(&store, "del", "DELETE", "payments-prod", START + 10_000);
    let listed = store
        .list_restrictions(
            RestrictionTarget::Agent {
                agent_id: "agent-r",
                context_id: None,
            },
            START + 11_000,
        )
        .unwrap();
    let scope = listed["restrictions"][0]["scope"]
        .as_str()
        .unwrap()
        .to_string();

    store.require_two_person(START + 12_000).unwrap();
    let target = || RestrictionTarget::Agent {
        agent_id: "agent-r",
        context_id: None,
    };
    assert!(denied(
        store
            .clear_restriction(target(), &scope, "alice", "false positive", START + 13_000)
            .unwrap_err()
    ));

    let id = store
        .propose_change(
            "clear_restriction",
            "agent-r",
            &serde_json::json!({"scope": scope}),
            "it was the migration job",
            "alice",
            START + 14_000,
        )
        .unwrap();
    assert!(denied(
        store
            .decide_change(&id, "alice", true, "me", START + 15_000)
            .unwrap_err()
    ));
    let done = store
        .decide_change(&id, "bob", true, "agreed", START + 16_000)
        .unwrap();
    assert!(
        done["outcome"].as_str().unwrap().starts_with("executed"),
        "{done}"
    );
    let after = store.list_restrictions(target(), START + 17_000).unwrap();
    assert_eq!(after["restrictions"].as_array().map_or(0, Vec::len), 0);

    // A proposal for a restriction that is not there is refused up front.
    assert!(
        store
            .propose_change(
                "clear_restriction",
                "agent-r",
                &serde_json::json!({"scope": "nothing"}),
                "x",
                "alice",
                START + 18_000
            )
            .is_err()
    );
}

#[test]
fn the_rule_cannot_be_switched_off_by_one_person() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    // Not on yet: nothing to switch off.
    assert!(
        store
            .propose_change(
                "disable_two_person",
                "two-person-rule",
                &serde_json::json!({}),
                "x",
                "alice",
                START
            )
            .is_err()
    );
    store.require_two_person(START).unwrap();
    let id = store
        .propose_change(
            "disable_two_person",
            "two-person-rule",
            &serde_json::json!({}),
            "the pilot is over",
            "alice",
            START + 1,
        )
        .unwrap();
    assert!(denied(
        store
            .decide_change(&id, "alice", true, "me", START + 2)
            .unwrap_err()
    ));
    assert!(store.two_person_required().unwrap());
    store
        .decide_change(&id, "bob", true, "agreed", START + 3)
        .unwrap();
    assert!(!store.two_person_required().unwrap());
}

#[test]
fn break_glass_works_and_is_labelled_in_the_audit_trail() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    store.require_two_person(START).unwrap();
    store
        .quarantine_workload("agent-q", "alice", "suspicious", START)
        .unwrap();
    assert!(
        store
            .release_workload_break_glass(
                "agent-q",
                "alice",
                "the on-call has no second person at 3 am",
                START + 1
            )
            .unwrap()
    );
    assert!(!quarantined(&store));
    // The audit row says so. (Read it back through the exported replay-free route: the audit table.)
    let conn = rusqlite::Connection::open(dir.path().join("rg.db")).unwrap();
    let (operator, reason): (String, String) = conn
        .query_row(
            "SELECT operator, reason FROM workload_quarantine_audit WHERE action = 'release' ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(
        operator.contains("BREAK-GLASS") && reason.starts_with("BREAK-GLASS"),
        "{operator} / {reason}"
    );
}
