// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The `policy_update` change: a candidate OpenShell policy built from a baseline and a sandbox's stored policy, proved no wider, approved by a second person, and never applied by
//! Risk Guard.

use openshell_risk_guard::detector::compute_baseline_hash;
use openshell_risk_guard::error::RiskGuardError;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::*;
use serde_json::{Value, json};

const START: i64 = 1_800_000_000_000;
const DAY: i64 = 24 * 60 * 60 * 1000;

const POLICY: &str = r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc]
  read_write: [/sandbox, /tmp]
network_middlewares:
  risk-guard:
    middleware: risk-guard
    order: 10
    on_error: fail_closed
    config: {task_profile: release-ops, mode: enforce}
    endpoints:
      include: [deploy-api.example.test]
network_policies:
  service:
    name: release-api
    endpoints:
      - host: deploy-api.example.test
        port: 18081
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {method: GET, path: /services}
          - allow: {method: GET, path: "/services/**"}
          - allow: {method: DELETE, path: "/services/**"}
    binaries:
      - path: /usr/bin/python3.12
"#;

fn baseline(routes: &[&str]) -> BaselineProfile {
    let mut baseline = BaselineProfile {
        task_profile: "release-ops".into(),
        version: "v3".into(),
        approved_by: "local-demo-operator".into(),
        normalizer_version: openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into(),
        training_sessions: 0,
        training_requests: 0,
        expected_binaries: Default::default(),
        approved_resources: Default::default(),
        allowed_action_classes: routes.iter().map(|r| r.to_string()).collect(),
        forbidden_action_classes: ["DELETE /services/*".to_string()].into(),
        forbid_unfamiliar_high_impact: true,
        rule_modes: Default::default(),
        approved_egress_hosts: Default::default(),
        siem_context_max_points: None,
        max_req_1m_p95: 60,
        max_req_1m_p99: 120,
        max_distinct_resources_15m_p95: 4,
        max_distinct_resources_15m_p99: 6,
    };
    baseline
        .expected_binaries
        .insert("/usr/bin/python3.12".into());
    baseline
}

fn epoch(store: &SqliteRiskStore, sandbox: &str, baseline: &BaselineProfile) {
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: format!("epoch-{sandbox}"),
            gateway_id: "gateway".into(),
            sandbox_id: sandbox.into(),
            task_profile: baseline.task_profile.clone(),
            baseline_hash: compute_baseline_hash(baseline),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: START,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
}

/// A store with a `release-ops` baseline and one sandbox, `sbx-1`, whose policy is on record.
fn store(dir: &tempfile::TempDir, routes: &[&str]) -> SqliteRiskStore {
    let store = SqliteRiskStore::open(dir.path().join("rg.db")).unwrap();
    let baseline = baseline(routes);
    store.store_baseline(&baseline).unwrap();
    epoch(&store, "sbx-1", &baseline);
    store
        .record_policy_snapshot(
            "sbx-1",
            "hash-1",
            POLICY,
            &Default::default(),
            "test",
            START,
        )
        .unwrap();
    store
}

const ROUTES: [&str; 2] = ["GET /services", "GET /services/{svc}"];

/// The prover has a 10 second budget and runs slowly in a debug build, so proposals take turns: parallel test threads would make it answer "inconclusive", which is refused.
static PROVER: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn propose(store: &SqliteRiskStore, params: Value, who: &str) -> Result<String, RiskGuardError> {
    let _turn = PROVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    store.propose_change(
        "policy_update",
        "release-ops",
        &params,
        "move the route list into policy",
        who,
        START + 1,
    )
}

fn change(store: &SqliteRiskStore, id: &str) -> Value {
    store.list_changes(100, START + 2).unwrap()["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
        .clone()
}

#[test]
fn a_proposal_carries_the_candidate_a_verified_proof_and_a_readable_diff() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &ROUTES);
    let id = propose(&store, json!({"enforcement": "audit"}), "alice").unwrap();
    let request = change(&store, &id);
    assert_eq!(request["kind"], "policy_update");
    assert_eq!(request["status"], "pending");
    assert_eq!(request["expires_at_ms"], START + 1 + DAY);
    let params = &request["params"];
    assert_eq!(params["proof"]["verified_no_wider"], true);
    assert_eq!(params["enforcement"], "audit");
    assert_eq!(
        params["sandbox"], "sbx-1",
        "defaults to the latest stored policy of the task profile"
    );
    assert_eq!(params["applied"], false);
    let diff = params["rule_diff"].as_str().unwrap();
    assert!(diff.contains("- allow DELETE /services/**"), "{diff}");
    assert!(diff.contains("+ enforcement: audit"), "{diff}");
    assert!(diff.contains("deny DELETE /services/**"), "{diff}");
    let candidate = params["candidate_yaml"].as_str().unwrap();
    assert!(candidate.contains("enforcement: audit"));
    // export_policy writes only network rules, and that is checked, not assumed.
    assert_eq!(params["requires_new_sandbox"], false);
}

#[test]
fn the_latest_snapshot_of_the_profile_is_used_and_a_named_sandbox_overrides_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &ROUTES);
    epoch(&store, "sbx-2", &baseline(&ROUTES));
    // sbx-2 has the same policy but was recorded later, so it is the default source.
    let newer = POLICY;
    store
        .record_policy_snapshot(
            "sbx-2",
            "hash-2",
            newer,
            &Default::default(),
            "test",
            START + 10,
        )
        .unwrap();
    let latest = propose(&store, json!({"enforcement": "enforce"}), "alice").unwrap();
    assert_eq!(change(&store, &latest)["params"]["sandbox"], "sbx-2");
    store
        .decide_change(&latest, "bob", false, "not now", START + 3)
        .unwrap();
    let named = propose(
        &store,
        json!({"enforcement": "enforce", "sandbox": "sbx-1"}),
        "alice",
    )
    .unwrap();
    assert_eq!(change(&store, &named)["params"]["sandbox"], "sbx-1");
}

#[test]
fn what_cannot_be_proved_or_built_is_refused_and_the_refusal_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    // A baseline that allows a route the sandbox's policy does not: wider, so the prover does not certify it.
    let wider = store(&dir, &["GET /services", "GET /admin/secrets"]);
    let error = propose(&wider, json!({"enforcement": "enforce"}), "alice").unwrap_err();
    assert!(error.to_string().contains("no wider"), "{error}");
    let kept = wider.list_changes(100, START + 2).unwrap();
    assert_eq!(kept["changes"][0]["status"], "refused");
    assert!(
        kept["changes"][0]["outcome"]
            .as_str()
            .unwrap()
            .starts_with("refused:")
    );
    assert!(kept["changes"][0]["params"]["candidate_yaml"].is_null());

    // Nothing approved in the baseline: "not specified", so nothing to write.
    let dir2 = tempfile::tempdir().unwrap();
    let empty = store(&dir2, &[]);
    let error = propose(&empty, json!({"enforcement": "audit"}), "alice").unwrap_err();
    assert!(error.to_string().contains("no approved routes"), "{error}");

    // No policy on record for the profile, or for the named sandbox.
    let dir3 = tempfile::tempdir().unwrap();
    let bare = SqliteRiskStore::open(dir3.path().join("rg.db")).unwrap();
    bare.store_baseline(&baseline(&ROUTES)).unwrap();
    epoch(&bare, "sbx-1", &baseline(&ROUTES));
    let error = propose(&bare, json!({"enforcement": "audit"}), "alice").unwrap_err();
    assert!(error.to_string().contains("no stored policy"), "{error}");
    let error = propose(
        &wider,
        json!({"enforcement": "audit", "sandbox": "nope"}),
        "alice",
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no stored policy for sandbox 'nope'"),
        "{error}"
    );

    // Bad mode, and a sandbox name that is not safe to put in a command.
    let error = propose(&bare, json!({"enforcement": "whatever"}), "alice").unwrap_err();
    assert!(matches!(error, RiskGuardError::InvalidArgument(_)));
    let error = propose(
        &wider,
        json!({"enforcement": "audit", "sandbox": "x; rm -rf /"}),
        "alice",
    )
    .unwrap_err();
    assert!(matches!(error, RiskGuardError::InvalidArgument(_)));
}

#[test]
fn the_proposer_cannot_approve_even_with_two_person_mode_off_and_a_second_person_gets_the_command_only()
 {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &ROUTES);
    assert!(
        !store.two_person_required().unwrap(),
        "two-person mode is off"
    );
    let id = propose(&store, json!({"enforcement": "enforce"}), "alice").unwrap();
    let error = store
        .decide_change(&id, "Alice", true, "me again", START + 2)
        .unwrap_err();
    assert!(matches!(error, RiskGuardError::PermissionDenied(_)));
    assert_eq!(change(&store, &id)["status"], "pending");
    // A second proposal for the same profile waits behind the first.
    assert!(propose(&store, json!({"enforcement": "audit"}), "carol").is_err());

    let before = store.latest_policy_snapshot("sbx-1").unwrap();
    let decision = store
        .decide_change(&id, "bob", true, "diff looks right", START + 3)
        .unwrap();
    let outcome = decision["outcome"].as_str().unwrap();
    assert!(
        outcome.starts_with(
            "approved: apply with `openshell policy set sbx-1 --policy policy-release-ops-"
        ),
        "{outcome}"
    );
    assert!(outcome.contains("--wait`"), "{outcome}");
    assert!(outcome.contains("applied nothing"), "{outcome}");
    let after = change(&store, &id);
    assert_eq!(
        after["status"], "approved",
        "approved is not executed: a person applies it"
    );
    assert_eq!(after["decided_by"], "bob");
    // Nothing was applied: the stored policy and the baseline are as they were.
    assert_eq!(store.latest_policy_snapshot("sbx-1").unwrap(), before);
    assert_eq!(
        store.get_baseline("release-ops").unwrap().unwrap().version,
        "v3"
    );
    // The candidate stays available to download, and it is the one that was reviewed.
    let (yaml, file) = store.change_policy(&id, START + 4).unwrap().unwrap();
    assert_eq!(yaml, after["params"]["candidate_yaml"].as_str().unwrap());
    assert!(outcome.contains(&file));
}

#[test]
fn a_rejected_or_expired_request_has_no_policy_to_download_and_cannot_be_approved_late() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &ROUTES);
    let id = propose(&store, json!({"enforcement": "audit"}), "alice").unwrap();
    assert!(store.change_policy(&id, START + 5).unwrap().is_some());
    assert!(
        store.change_policy(&id, START + 2 * DAY).unwrap().is_none(),
        "expired"
    );
    assert!(
        store
            .decide_change(&id, "bob", true, "late", START + 2 * DAY)
            .is_err()
    );
    // Proposed again (at the same early time, as the first), then rejected.
    let _turn = PROVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let again = store
        .propose_change(
            "policy_update",
            "release-ops",
            &json!({"enforcement": "audit"}),
            "second try",
            "alice",
            START + 2 * DAY + 1,
        )
        .unwrap();
    store
        .decide_change(&again, "bob", false, "no", START + 2 * DAY + 2)
        .unwrap();
    assert!(
        store
            .change_policy(&again, START + 2 * DAY + 3)
            .unwrap()
            .is_none(),
        "rejected"
    );
    assert!(store.change_policy("nosuchid", START).unwrap().is_none());
}

/// Each approved route change chooses its home. Keeping it in Risk Guard (the default) asks for nothing more; choosing OpenShell also asks for a policy candidate, generated from
/// the baseline as it then is and proved no wider, as an ordinary request for a person to review.
#[test]
fn an_approved_baseline_change_can_ask_for_an_openshell_policy_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &["GET /services"]);
    // The default home: Risk Guard keeps the entry, and no policy request appears. (A host, not a route: the prover's cost grows with the number of routes, and this test
    // must leave the baseline small enough for it to finish in a debug build.)
    let kept = store
        .propose_change(
            "baseline_update",
            "release-ops",
            &json!({"add_egress_hosts": ["api.example.org"]}),
            "steady",
            "alice",
            START + 1,
        )
        .unwrap();
    let result = store
        .decide_change(&kept, "bob", true, "reviewed", START + 2)
        .unwrap();
    assert!(
        result["outcome"].as_str().unwrap().starts_with("executed"),
        "{result}"
    );
    let listed = store.list_changes(100, START + 3).unwrap();
    assert!(
        listed["changes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["kind"] != "policy_update")
    );

    // OpenShell as the home: the baseline gets the route at once, and a policy candidate is requested and waits.
    let _turn = PROVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pushed = store
        .propose_change(
            "baseline_update",
            "release-ops",
            &json!({"add_action_classes": ["GET /services/{svc}"], "home": "openshell"}),
            "steady",
            "alice",
            START + 4,
        )
        .unwrap();
    let result = store
        .decide_change(&pushed, "bob", true, "reviewed", START + 5)
        .unwrap();
    let outcome = result["outcome"].as_str().unwrap();
    assert!(outcome.starts_with("executed"), "{result}");
    assert!(
        outcome.contains("OpenShell policy candidate requested"),
        "{outcome}"
    );
    let baseline = store.get_baseline("release-ops").unwrap().unwrap();
    assert!(
        baseline
            .allowed_action_classes
            .contains("GET /services/{svc}"),
        "Risk Guard enforces it at once"
    );

    let listed = store.list_changes(100, START + 6).unwrap();
    let candidates: Vec<&Value> = listed["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "policy_update")
        .collect();
    assert_eq!(candidates.len(), 1, "{listed}");
    assert_eq!(candidates[0]["status"], "pending");
    assert_eq!(candidates[0]["params"]["linked_change"], pushed.as_str());
    assert_eq!(candidates[0]["params"]["proof"]["verified_no_wider"], true);
    assert_eq!(
        candidates[0]["params"]["applied"], false,
        "nothing is applied by asking"
    );
    assert!(
        candidates[0]["params"]["candidate_yaml"]
            .as_str()
            .unwrap()
            .contains("/services/*")
    );
}

#[test]
fn the_home_choice_is_checked_and_rate_limits_never_move() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &ROUTES);
    let bad = store.propose_change(
        "baseline_update",
        "release-ops",
        &json!({"add_action_classes": ["GET /x"], "home": "elsewhere"}),
        "r",
        "alice",
        START + 1,
    );
    assert!(bad.is_err());
    let rates_only = store.propose_change(
        "baseline_update",
        "release-ops",
        &json!({"tighten_rate": {"max_req_1m_p95": 30}, "home": "openshell"}),
        "r",
        "alice",
        START + 1,
    );
    assert!(rates_only.is_err(), "a rate limit has no OpenShell home");
}
