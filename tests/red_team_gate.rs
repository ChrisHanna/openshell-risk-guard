// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The red-team gate: every attack in `conformance/red-team/catalog.json` is replayed against Risk Guard's real decision path, and the build fails if
//! Risk Guard stops refusing one it should refuse, starts refusing a benign control, or quietly changes on a gap that is documented as open.
//!
//! The catalog is data, so adding an attack is a JSON edit and a cargo test, not new code. The report is written to `target/red-team-report.json` (or the path in
//! `RED_TEAM_REPORT`) for CI to keep. Nothing here is a claim of accuracy against an unseen attacker: it is the author's own list, and the table of known misses is
//! part of it on purpose.

use std::collections::BTreeSet;

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::{
    InteractionRiskDetector, compute_baseline_hash, load_baseline_profile,
};
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::*;
use serde_json::{Value, json};

const START: i64 = 1_800_000_000_000;

fn profile(name: &str) -> BaselineProfile {
    load_baseline_profile(format!(
        "{}/deploy/aks/agents/{name}/baseline.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn bind(store: &SqliteRiskStore, agent: &str, sandbox: &str, profile: &BaselineProfile) {
    let _ = store.register_agent(agent, "Red-team agent");
    let run = format!("run-{sandbox}");
    store
        .create_agent_run(
            agent,
            &run,
            "revision-1",
            &profile.task_profile,
            EnforcementMode::Enforce,
        )
        .unwrap();
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: format!("epoch-{sandbox}"),
            gateway_id: "gateway".into(),
            sandbox_id: sandbox.into(),
            task_profile: profile.task_profile.clone(),
            baseline_hash: compute_baseline_hash(profile),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: START - 1,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
    store.bind_agent_run(&run, sandbox, "gateway").unwrap();
}

/// Why a call was refused, or `None` if it was allowed. "Could not be normalized" counts as refused: the supervisor's fail-closed binding turns that error
/// into a denial. The reason is recorded, so a refusal that comes only from an unknown route is not mistaken for one that was judged.
fn refused(
    store: &SqliteRiskStore,
    sandbox: &str,
    host: &str,
    method: &str,
    path: &str,
    at: i64,
    id: &str,
) -> Option<String> {
    let request = match CanonicalNormalizer::new_default(b"redteam-test-only-key").normalize(
        &RawRequestInput {
            request_id: id.into(),
            sandbox_id: sandbox.into(),
            sandbox_name: sandbox.into(),
            workspace: "default".into(),
            scheme: "http".into(),
            host: format!("{host}.openshell.svc.cluster.local"),
            port: 18081,
            method: method.into(),
            path: path.into(),
            binary_path: Some("/opt/agent/bin/python3.12".into()),
            pid: None,
            ancestors: vec![],
            timestamp_ms: at,
        },
    ) {
        Ok(request) => request,
        Err(_) => return Some("unknown_route_or_invalid_path".into()),
    };
    match store.evaluate_authenticated(
        &request,
        &InteractionRiskDetector::new_default(),
        "gateway",
        true,
    ) {
        Ok(evaluation) if evaluation.outcome == DecisionOutcome::Deny => {
            Some(evaluation.reason_code)
        }
        Ok(_) => None,
        Err(_) => Some("evaluation_error".into()),
    }
}

/// Run one attack on a fresh store. Returns how many calls were refused and whether the last one was.
fn run(attack: &Value) -> (usize, usize, bool, Option<String>) {
    let profile = profile(attack["profile"].as_str().unwrap());
    let store = seed_fixture_store(tempfile::tempdir().unwrap().keep().join("rt.db")).unwrap();
    store.store_baseline(&profile).unwrap();
    bind(&store, "agent", "sbx-1", &profile);
    let host = attack["host"].as_str().unwrap();

    let mut calls: Vec<(String, String, i64, bool)> = Vec::new();
    let mut clock = START;
    if let Some(steps) = attack["steps"].as_array() {
        for step in steps {
            clock += step["gap_ms"].as_i64().unwrap_or(0);
            calls.push((
                step["method"].as_str().unwrap().to_string(),
                step["path"].as_str().unwrap().to_string(),
                clock,
                step["new_sandbox"].as_bool().unwrap_or(false),
            ));
        }
    }
    if let Some(repeat) = attack.get("repeat") {
        for n in 0..repeat["count"].as_i64().unwrap() {
            clock += repeat["gap_ms"].as_i64().unwrap();
            calls.push((
                repeat["method"].as_str().unwrap().to_string(),
                repeat["path_template"]
                    .as_str()
                    .unwrap()
                    .replace("{n}", &n.to_string()),
                clock,
                false,
            ));
        }
    }

    let mut sandbox = "sbx-1".to_string();
    let mut refused_count = 0;
    let mut last = None;
    for (n, (method, path, at, new_sandbox)) in calls.iter().enumerate() {
        if *new_sandbox {
            sandbox = "sbx-2".into();
            bind(&store, "agent", &sandbox, &profile);
        }
        last = refused(&store, &sandbox, host, method, path, *at, &format!("c{n}"));
        refused_count += usize::from(last.is_some());
    }
    (calls.len(), refused_count, last.is_some(), last)
}

#[test]
fn every_attack_in_the_catalog_gets_the_answer_it_is_expected_to_get() {
    let catalog: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/conformance/red-team/catalog.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let attacks = catalog["attacks"].as_array().unwrap();

    let mut results = Vec::new();
    let mut failures = Vec::new();
    for attack in attacks {
        let id = attack["id"].as_str().unwrap();
        let expect = attack["expect"].as_str().unwrap();
        let (calls, refused_count, last_refused, reason) = run(attack);
        let (pass, why) = match expect {
            "refused" => (
                last_refused,
                "the last call must be refused: a regression if it is allowed",
            ),
            "allowed" => (
                refused_count == 0,
                "no call of a benign control may be refused: a false positive",
            ),
            "known_miss" => (
                refused_count == 0,
                "documented gap: now refused, so update docs/detection-results.md and change the expectation",
            ),
            other => panic!("{id}: unknown expectation '{other}'"),
        };
        results.push(json!({
            "id": id, "category": attack["category"], "owasp": attack["owasp"], "title": attack["title"],
            "profile": attack["profile"], "expect": expect, "calls": calls, "refused": refused_count,
            "last_call_refused": last_refused, "last_call_reason": reason, "pass": pass,
        }));
        if !pass {
            failures.push(format!(
                "{id} ({}): expected {expect}, but {refused_count} of {calls} calls were refused and the last was {}. {why}",
                attack["title"].as_str().unwrap(),
                if last_refused { "refused" } else { "allowed" },
            ));
        }
    }

    let count = |expect: &str| {
        attacks
            .iter()
            .filter(|attack| attack["expect"] == expect)
            .count()
    };
    let report = json!({
        "catalog_version": catalog["version"],
        "attacks": attacks.len(),
        "expected_refused": count("refused"), "controls": count("allowed"), "known_misses": count("known_miss"),
        "out_of_scope": catalog["out_of_scope"],
        "failures": failures,
        "gate": if failures.is_empty() { "pass" } else { "FAIL" },
        "results": results,
    });
    let path = std::env::var("RED_TEAM_REPORT")
        .unwrap_or_else(|_| format!("{}/target/red-team-report.json", env!("CARGO_MANIFEST_DIR")));
    let _ = std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap());
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    println!("red-team report: {path}");

    assert!(
        failures.is_empty(),
        "red-team gate failed:\n{}",
        failures.join("\n")
    );

    // The catalog must stay broad enough to mean something: removing attacks cannot make the gate pass.
    let categories: BTreeSet<_> = attacks
        .iter()
        .map(|attack| attack["category"].as_str().unwrap())
        .collect();
    assert!(
        count("refused") >= 15,
        "at least 15 attacks that must be refused"
    );
    assert!(count("allowed") >= 3, "at least 3 benign controls");
    assert!(
        categories.len() >= 8,
        "at least 8 categories, got {categories:?}"
    );
}
