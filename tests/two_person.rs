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

fn change(
    store: &SqliteRiskStore,
    params: serde_json::Value,
    who: &str,
) -> Result<String, RiskGuardError> {
    store.propose_change(
        "baseline_update",
        "repo-triage-readonly",
        &params,
        "steady for a week",
        who,
        START,
    )
}

#[test]
fn a_baseline_change_takes_a_second_person_even_when_the_rule_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    assert!(!store.two_person_required().unwrap());
    let id = change(&store, serde_json::json!({"add_action_classes": ["GET /repos/{owner}/{repo}/labels"], "add_egress_hosts": ["api.example.com"]}), "alice").unwrap();

    let own = store
        .decide_change(&id, "alice", true, "me too", START + 1)
        .unwrap_err();
    assert!(
        denied(own),
        "the proposer cannot approve their own baseline change"
    );
    let before = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    assert!(
        !before
            .allowed_action_classes
            .contains("GET /repos/{owner}/{repo}/labels")
    );

    let result = store
        .decide_change(&id, "bob", true, "evidence reviewed", START + 2)
        .unwrap();
    assert!(
        result["outcome"].as_str().unwrap().starts_with("executed"),
        "{result}"
    );
    let after = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    assert!(
        after
            .allowed_action_classes
            .contains("GET /repos/{owner}/{repo}/labels")
    );
    assert!(after.approved_egress_hosts.contains("api.example.com"));
    assert_eq!(
        after.approved_by, "alice+bob",
        "both people are named on the baseline"
    );
    assert!(after.version.contains("+c"), "{}", after.version);
    assert_ne!(after.version, before.version);
}

#[test]
fn a_baseline_change_can_only_add_reads_hosts_and_lower_limits() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    for bad in [
        serde_json::json!({"add_action_classes": ["DELETE /repos/{owner}/{repo}"]}),
        serde_json::json!({"add_action_classes": ["POST /repos/{owner}/{repo}/issues"]}),
        serde_json::json!({"add_action_classes": ["/no/method"]}),
        serde_json::json!({"tighten_rate": {"max_distinct_resources_15m_p95": 3}}),
        serde_json::json!({"tighten_rate": {"max_req_1m_p95": 0}}),
        serde_json::json!({"tighten_rate": "lower"}),
        serde_json::json!({}),
    ] {
        assert!(
            matches!(
                change(&store, bad.clone(), "alice"),
                Err(RiskGuardError::InvalidArgument(_))
            ),
            "{bad} should be refused when proposed"
        );
    }
    let unknown = store.propose_change(
        "baseline_update",
        "no-such-profile",
        &serde_json::json!({"add_egress_hosts": ["a.example.com"]}),
        "x",
        "alice",
        START,
    );
    assert!(matches!(unknown, Err(RiskGuardError::InvalidArgument(_))));
}

#[test]
fn a_baseline_change_never_raises_a_limit_and_a_noop_is_reported_as_failed() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let now = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    let raise = serde_json::json!({"tighten_rate": {"max_req_1m_p95": now.max_req_1m_p95 + 100}});
    let id = change(&store, raise, "alice").unwrap();
    let result = store
        .decide_change(&id, "bob", true, "ok", START + 1)
        .unwrap();
    assert!(
        result["outcome"].as_str().unwrap().starts_with("failed"),
        "{result}"
    );
    let after = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    assert_eq!(
        after.max_req_1m_p95, now.max_req_1m_p95,
        "a limit is never raised through a change request"
    );

    let lower = serde_json::json!({"tighten_rate": {"max_req_1m_p95": now.max_req_1m_p95 - 1}});
    let id = store
        .propose_change(
            "baseline_update",
            "repo-triage-readonly",
            &lower,
            "tighter",
            "alice",
            START + 10,
        )
        .unwrap();
    store
        .decide_change(&id, "bob", true, "ok", START + 11)
        .unwrap();
    assert_eq!(
        store
            .get_baseline("repo-triage-readonly")
            .unwrap()
            .unwrap()
            .max_req_1m_p95,
        now.max_req_1m_p95 - 1
    );
}

#[test]
fn a_rejected_baseline_change_leaves_the_baseline_alone() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let before = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    let id = change(
        &store,
        serde_json::json!({"add_egress_hosts": ["api.example.com"]}),
        "alice",
    )
    .unwrap();
    store
        .decide_change(&id, "bob", false, "not convinced", START + 1)
        .unwrap();
    assert_eq!(
        store.get_baseline("repo-triage-readonly").unwrap().unwrap(),
        before
    );
}

fn send_path(store: &SqliteRiskStore, id: &str, method: &str, path: &str, at: i64) {
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
            path: path.into(),
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

#[test]
fn suggestions_come_from_the_services_own_history_and_only_for_steady_unrefused_reads() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let hour = 3_600_000;
    // A read the baseline does not list, used 24 times over four hours.
    for n in 0..24 {
        send_path(
            &store,
            &format!("steady-{n}"),
            "GET",
            "/repos/org/docs/issues/7/comments",
            START + (n % 4) * hour + n,
        );
    }
    // A write the baseline does not list, in one burst: never suggested, whatever its count.
    for n in 0..24 {
        send_path(
            &store,
            &format!("burst-{n}"),
            "POST",
            "/repos/org/docs/issues",
            START + n,
        );
    }
    let view = store
        .suggest_baseline_changes(START - 1, START + 5 * hour)
        .unwrap();
    let profile = view["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["task_profile"] == "repo-triage-readonly")
        .expect("the profile is listed");
    let add: Vec<String> = profile["add_action_classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["action_class"].as_str().unwrap().to_string())
        .collect();
    let skipped: Vec<String> = profile["not_suggested"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| format!("{} {}", r["action_class"], r["why_not"]))
        .collect();
    println!("add: {add:?}\nskipped: {skipped:?}");
    assert!(
        add.iter().any(|r| r.contains("issues/**")),
        "a steady read is suggested: {add:?} / {skipped:?}"
    );
    assert!(
        !add.iter().any(|r| r.contains("POST")),
        "a write is never suggested: {add:?}"
    );
    assert!(
        skipped.iter().any(|r| r.contains("POST")),
        "it is listed with the reason it was left out: {skipped:?}"
    );
}

#[test]
fn with_two_person_on_guardrail_tightening_is_allowed_but_loosening_is_refused() {
    use openshell_risk_guard::guardrails::{AgentGuardrails, GuardrailsUpdate};

    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    store.require_two_person(START).unwrap();

    let view = store.agent_guardrails("agent-r", START).unwrap().unwrap();
    let base_settings: AgentGuardrails = serde_json::from_value(view["settings"].clone()).unwrap();

    // Tightening (lowering enforce_threshold from 70 to 60 and promoting a rule to Enforce) succeeds with one operator.
    let mut tightened = base_settings.clone();
    tightened.enforce_threshold = 60;
    tightened
        .rule_modes
        .insert(RULE_UNAPPROVED_ACTION.into(), RuleMode::Enforce);
    assert!(
        store
            .save_agent_guardrails(
                "agent-r",
                &GuardrailsUpdate {
                    expected_revision: 0,
                    settings: tightened.clone(),
                },
                "alice",
                START + 10,
            )
            .is_ok()
    );

    // Loosening (switching Enforce -> Observe, raising threshold, raising rate limits, or adding allowed actions) is refused!
    let mut loosen_mode = tightened.clone();
    loosen_mode.mode = EnforcementMode::Observe;
    let err = store
        .save_agent_guardrails(
            "agent-r",
            &GuardrailsUpdate {
                expected_revision: 1,
                settings: loosen_mode,
            },
            "alice",
            START + 20,
        )
        .unwrap_err();
    assert!(denied(err));

    let mut loosen_threshold = tightened;
    loosen_threshold.enforce_threshold = 80;
    let err = store
        .save_agent_guardrails(
            "agent-r",
            &GuardrailsUpdate {
                expected_revision: 1,
                settings: loosen_threshold.clone(),
            },
            "alice",
            START + 30,
        )
        .unwrap_err();
    assert!(denied(err));

    // Proposing the loosening change as primary Entra admin and approving as learningnemo-approver succeeds!
    let proposer = "christopher.g.hanna_gmail.com#EXT#@christopherghannagmail.onmicrosoft.com [entra:e017ee85-b0f4-405a-9301-1dd83669dbd6]";
    let second_approver = "learningnemo-approver@christopherghannagmail.onmicrosoft.com [entra:27dd6b51-06d3-4c68-ac2f-6d112ac034cc]";
    let update_payload = serde_json::to_value(GuardrailsUpdate {
        expected_revision: 1,
        settings: loosen_threshold,
    })
    .unwrap();
    let change_id = store
        .propose_change(
            "update_guardrails",
            "agent-r",
            &update_payload,
            "Relax threshold after incident review",
            proposer,
            START + 40,
        )
        .unwrap();
    assert!(denied(
        store
            .decide_change(&change_id, proposer, true, "self approve", START + 41)
            .unwrap_err()
    ));
    let decided = store
        .decide_change(
            &change_id,
            second_approver,
            true,
            "Verified by second approver",
            START + 42,
        )
        .unwrap();
    assert!(
        decided["outcome"].as_str().unwrap().starts_with("executed"),
        "{decided}"
    );
    let updated_view = store.agent_guardrails("agent-r", START + 43).unwrap().unwrap();
    assert_eq!(updated_view["revision"], 2);
    assert_eq!(updated_view["settings"]["enforce_threshold"], 80);
}
