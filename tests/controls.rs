// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The Controls overview: one list of every control, in the same words, saying plainly when a control lacks the data it needs.

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::*;
use serde_json::Value;

const START: i64 = 1_800_000_000_000;

/// A store with one task profile that has learned nothing (no training) and approves one route, with the approved-route rule only watching.
fn store(dir: &tempfile::TempDir) -> SqliteRiskStore {
    let store = seed_fixture_store(dir.path().join("rg.db")).unwrap();
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.task_profile = "new-task".into();
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    baseline.training_sessions = 0;
    baseline.training_requests = 0;
    baseline.allowed_action_classes = ["GET /repos/{owner}/{repo}".to_string()].into();
    baseline
        .rule_modes
        .insert(RULE_UNAPPROVED_ACTION.into(), RuleMode::Shadow);
    store.store_baseline(&baseline).unwrap();
    store.register_agent("agent-c", "Controls bot").unwrap();
    store
        .create_agent_run(
            "agent-c",
            "run-1",
            "revision-1",
            "new-task",
            EnforcementMode::Enforce,
        )
        .unwrap();
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: "epoch-sbx-c".into(),
            gateway_id: "gateway".into(),
            sandbox_id: "sbx-c".into(),
            task_profile: "new-task".into(),
            baseline_hash: compute_baseline_hash(&baseline),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: START,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
    store.bind_agent_run("run-1", "sbx-c", "gateway").unwrap();
    store
}

fn call(store: &SqliteRiskStore, id: &str, path: &str, at: i64) {
    let request = CanonicalNormalizer::new_default(b"controls-test-key")
        .normalize(&RawRequestInput {
            request_id: id.into(),
            sandbox_id: "sbx-c".into(),
            sandbox_name: "sbx-c".into(),
            workspace: "default".into(),
            scheme: "https".into(),
            host: "api.github.local".into(),
            port: 18443,
            method: "GET".into(),
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

fn control<'a>(view: &'a Value, id: &str) -> &'a Value {
    view["controls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no control {id}"))
}

#[test]
fn every_control_uses_the_same_words_and_says_whether_it_has_its_data() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let view = store.controls_overview(START + 1).unwrap();
    let modes = [
        "enforcing",
        "watching",
        "off",
        "mixed",
        "no_list",
        "not_built",
        "unknown",
    ];
    let states = ["ok", "not_enough_data", "not_applicable", "not_built"];
    for c in view["controls"].as_array().unwrap() {
        assert!(
            modes.contains(&c["mode"].as_str().unwrap()),
            "{} has mode {}",
            c["id"],
            c["mode"]
        );
        assert!(
            states.contains(&c["data"]["state"].as_str().unwrap()),
            "{}",
            c["id"]
        );
        assert!(
            !c["what"].as_str().unwrap().is_empty()
                && !c["data"]["note"].as_str().unwrap().is_empty(),
            "{} explains itself",
            c["id"]
        );
    }
    assert_eq!(
        control(&view, "openshell_network_policy")["mode"],
        "enforcing",
        "the floor is always listed first and does not depend on learning"
    );
    assert_eq!(view["controls"][0]["id"], "openshell_network_policy");
    assert_eq!(view["controls"][1]["id"], "openshell_filesystem");
}

#[test]
fn a_profile_that_has_learned_nothing_is_reported_as_not_enough_data_and_never_as_enforcing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let view = store.controls_overview(START + 1).unwrap();
    let score = control(&view, "behavioral_score");
    assert_eq!(score["data"]["state"], "not_enough_data");
    // The seeded standard profiles are mature, so across the fleet this reads "mixed"; what matters is that it is never "enforcing" while one profile has not learned enough.
    assert_eq!(score["mode"], "mixed");
    let note = score["data"]["note"].as_str().unwrap();
    assert!(
        note.contains("20 sessions and 200 requests") && note.contains("OpenShell policy"),
        "{note}"
    );
    let learned: Vec<_> = score["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["task_profile"] == "new-task")
        .collect();
    assert_eq!(learned.len(), 1);
    assert_eq!(learned[0]["enough"], false);
}

#[test]
fn a_watching_rule_counts_what_it_would_have_refused_and_lets_the_call_through() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    call(&store, "ok-1", "/repos/org/docs", START + 10);
    for n in 0..3 {
        call(
            &store,
            &format!("miss-{n}"),
            "/repos/org/docs/issues",
            START + 20 + n,
        );
    }
    let view = store.controls_overview(START + 1_000).unwrap();
    let rule = control(&view, "unapproved_action");
    let profile = rule["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["task_profile"] == "new-task")
        .unwrap();
    assert_eq!(profile["state"], "watching");
    assert_eq!(rule["evidence"]["would_refuse_24h"], 3, "{rule}");
    assert_eq!(
        rule["evidence"]["refused_24h"], 0,
        "a watching rule refuses nothing"
    );
    assert_eq!(rule["evidence"]["calls_24h"], 4);
}

#[test]
fn the_siem_door_is_reported_as_off_watching_or_enforcing_from_how_the_service_started() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let mode = |store: &SqliteRiskStore| {
        control(&store.controls_overview(START + 1).unwrap(), "siem_signals")["mode"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        mode(&store),
        "unknown",
        "nothing recorded: the mode cannot be known"
    );
    let before = store.controls_overview(START + 1).unwrap();
    assert_eq!(
        control(&before, "siem_signals")["data"]["state"],
        "not_applicable",
        "a database nobody has served does not claim a mode it cannot know"
    );
    store
        .record_runtime_facts(&[("signals_listening", "0")], START)
        .unwrap();
    assert_eq!(
        mode(&store),
        "off",
        "a running service that is not listening has the door closed"
    );
    store
        .record_runtime_facts(
            &[("signals_listening", "1"), ("signals_dry_run", "1")],
            START,
        )
        .unwrap();
    assert_eq!(mode(&store), "watching");
    store
        .record_runtime_facts(
            &[("signals_listening", "1"), ("signals_dry_run", "0")],
            START,
        )
        .unwrap();
    assert_eq!(mode(&store), "enforcing");
    let view = store.controls_overview(START + 1).unwrap();
    assert_eq!(
        control(&view, "siem_hints")["mode"],
        "not_built",
        "what is only designed is labelled that way"
    );
}
