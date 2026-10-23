// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Decision replay: a captured sequence, replayed from nothing, reproduces every decision and reason code.
//!
//! The sequence is built to need the state that makes replay hard: windowed counts, a restriction latched by an earlier run and carried into a
//! later one, a guardrail revision changed part-way through, and an operator clearance.

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::guardrails::{AgentGuardrails, GuardrailsSaveResult, GuardrailsUpdate};
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::replay::{ReplayEvent, replay};
use openshell_risk_guard::store::{RestrictionTarget, SqliteRiskStore};
use openshell_risk_guard::types::*;

const HMAC_KEY: &[u8] = b"replay-test-only-hmac-key";
const START: i64 = 1_800_000_000_000;

fn store(path: &std::path::Path) -> SqliteRiskStore {
    let store = seed_fixture_store(path).unwrap();
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline).unwrap();
    store
}

fn bind(store: &SqliteRiskStore, agent: &str, sandbox: &str, run: &str, created: i64) {
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
            created_at_ms: created,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
    store.bind_agent_run(run, sandbox, "gateway").unwrap();
}

fn send(
    store: &SqliteRiskStore,
    sandbox: &str,
    id: &str,
    method: &str,
    resource: &str,
    at: i64,
) -> RiskEvaluation {
    let request = CanonicalNormalizer::new_default(HMAC_KEY)
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

/// Run the whole scenario on a real database file and return the store, the file's directory and what was recorded.
fn record() -> (SqliteRiskStore, tempfile::TempDir, Vec<RiskEvaluation>) {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir.path().join("risk-guard.db"));
    store.register_agent("agent-r", "Replay agent").unwrap();
    let mut recorded = Vec::new();
    let t = std::cell::Cell::new(START);
    let tick = || {
        t.set(t.get() + 1_000);
        t.get()
    };

    bind(&store, "agent-r", "sbx-1", "run-1", START);
    for n in 0..6 {
        recorded.push(send(
            &store,
            "sbx-1",
            &format!("r1-get-{n}"),
            "GET",
            "docs-site",
            tick(),
        ));
    }
    // A destructive call latches a restriction on the agent's context, and later calls in that scope meet it.
    recorded.push(send(
        &store,
        "sbx-1",
        "r1-del-1",
        "DELETE",
        "payments-prod",
        tick(),
    ));
    recorded.push(send(
        &store,
        "sbx-1",
        "r1-del-2",
        "DELETE",
        "payments-prod",
        tick(),
    ));

    // The operator changes the agent's guardrails part-way through.
    let baseline = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    let view = store.agent_guardrails("agent-r", START).unwrap().unwrap();
    let mut settings: AgentGuardrails = serde_json::from_value(view["settings"].clone()).unwrap();
    settings.task_profile = baseline.task_profile.clone();
    settings.cooldown_seconds = 120;
    match store
        .save_agent_guardrails(
            "agent-r",
            &GuardrailsUpdate {
                expected_revision: 0,
                settings,
            },
            "operator",
            START + 30_000,
        )
        .unwrap()
    {
        GuardrailsSaveResult::Saved(_) => {}
        GuardrailsSaveResult::Conflict { current_revision } => {
            panic!("conflict at {current_revision}")
        }
    }
    for n in 0..4 {
        recorded.push(send(
            &store,
            "sbx-1",
            &format!("r1-late-{n}"),
            "GET",
            "docs-site",
            tick(),
        ));
    }

    // A second run of the same agent in another sandbox inherits the restriction.
    store.end_agent_run("run-1").unwrap();
    bind(&store, "agent-r", "sbx-2", "run-2", START + 60_000);
    t.set(START + 60_000);
    recorded.push(send(
        &store,
        "sbx-2",
        "r2-del-1",
        "DELETE",
        "payments-prod",
        tick(),
    ));
    for n in 0..3 {
        recorded.push(send(
            &store,
            "sbx-2",
            &format!("r2-get-{n}"),
            "GET",
            "docs-site",
            tick(),
        ));
    }
    (store, dir, recorded)
}

#[test]
fn a_recorded_sequence_replays_to_the_same_decisions_and_reason_codes() {
    let (store, _dir, recorded) = record();
    assert!(
        recorded.iter().any(|e| e.outcome == DecisionOutcome::Deny),
        "the scenario must include denials"
    );
    assert!(
        recorded.iter().any(|e| e.outcome != DecisionOutcome::Deny),
        "and allowed requests"
    );

    let bundle = store.export_replay_bundle("agent-r", None).unwrap();
    assert!(bundle.history.complete, "{:?}", bundle.history.problems);
    assert_eq!(bundle.runs.len(), 2);
    assert_eq!(bundle.epochs.len(), 2);
    assert_eq!(bundle.guardrail_revisions.len(), 1);
    let decisions = bundle
        .events
        .iter()
        .filter(|e| matches!(e, ReplayEvent::Decision { .. }))
        .count();
    assert_eq!(decisions, recorded.len());

    // The bundle holds no keys, no operator identity and no tokens.
    let text = serde_json::to_string(&bundle).unwrap();
    for secret in [
        std::str::from_utf8(HMAC_KEY).unwrap(),
        "authorization",
        "Bearer",
    ] {
        assert!(
            !text.contains(secret),
            "the bundle must not contain {secret:?}"
        );
    }

    // Operator identities and reasons (from guardrail saves and clearances) are not carried.
    assert!(!text.contains("updated_by") && !text.contains("cleared_by"));
    let report = replay(&bundle, false).unwrap();
    assert!(report.reproduced, "{:#?}", report.divergences);
    assert_eq!(report.matched, recorded.len());
    assert!(
        report.checks.content_hash_ok
            && report.checks.baseline_hash_ok
            && report.checks.configuration_matches
    );

    // The bundle survives a trip through JSON unchanged, as it would on disk.
    let reloaded: openshell_risk_guard::replay::ReplayBundle = serde_json::from_str(&text).unwrap();
    assert!(replay(&reloaded, false).unwrap().reproduced);
}

#[test]
fn replay_follows_an_operator_clearance_where_it_happened() {
    let (store, _dir, recorded) = record();
    assert!(
        recorded
            .iter()
            .any(|e| e.request_id == "r2-del-1" && e.reason_code == "behavioral_risk_restricted")
    );
    // Clear the restriction the second run met, then send the same call again.
    let scope = store
        .list_normalized_requests("sbx-2")
        .unwrap()
        .into_iter()
        .find(|(request, _)| request.request_id == "r2-del-1")
        .map(|(request, _)| request.restriction_scope)
        .unwrap();
    store
        .clear_restriction(
            RestrictionTarget::Agent {
                agent_id: "agent-r",
                context_id: None,
            },
            &scope,
            "operator",
            "reviewed",
            START + 70_000,
        )
        .expect("the restriction the second run met is on the call's own scope");
    send(
        &store,
        "sbx-2",
        "r2-after-clear",
        "DELETE",
        "payments-prod",
        START + 80_000,
    );
    let bundle = store.export_replay_bundle("agent-r", None).unwrap();
    assert!(
        bundle
            .events
            .iter()
            .any(|e| matches!(e, ReplayEvent::Clearance { .. }))
    );
    let report = replay(&bundle, false).unwrap();
    assert!(report.reproduced, "{:#?}", report.divergences);
    assert_eq!(report.clearances_applied, 1);
}

#[test]
fn a_changed_bundle_is_refused_and_a_resealed_edit_shows_up_as_a_divergence() {
    let (store, _dir, _) = record();
    let bundle = store.export_replay_bundle("agent-r", None).unwrap();

    // Edited without resealing: refused outright.
    let mut tampered = bundle.clone();
    if let Some(ReplayEvent::Decision { request, .. }) = tampered
        .events
        .iter_mut()
        .find(|e| matches!(e, ReplayEvent::Decision { .. }))
    {
        request.high_impact = true;
        request.action_class = "DELETE /repos/{owner}/{repo}".into();
        request.semantic_category = "destructive_admin".into();
    }
    assert!(
        replay(&tampered, false).is_err(),
        "an edited bundle must not replay"
    );

    // Edited and resealed (an insider rewriting history): the decisions no longer match what was recorded.
    let resealed = tampered.seal().unwrap();
    let report = replay(&resealed, false);
    // An edit that makes the sequence impossible to replay at all is also an acceptable outcome.
    if let Ok(report) = report {
        assert!(!report.reproduced && !report.divergences.is_empty());
    }

    // A different detector configuration is reported, not hidden.
    let mut other = bundle.clone();
    other.build.configuration_id = "some-other-configuration".into();
    let report = replay(&other.seal().unwrap(), false).unwrap();
    assert!(!report.checks.configuration_matches);

    // A baseline that does not match its hash is refused.
    let mut wrong = bundle;
    wrong.baselines[0].task_profile = "something-else".into();
    assert!(replay(&wrong.seal().unwrap(), false).is_err());
}

#[test]
fn missing_history_is_reported_and_replay_refuses_to_guess() {
    let (store, dir, _) = record();
    drop(store);
    // Lose the earliest decision in the first epoch, as pruning would.
    let conn = rusqlite::Connection::open(dir.path().join("risk-guard.db")).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    conn.execute(
        "DELETE FROM decisions WHERE epoch_id = 'epoch-sbx-1' AND sequence = 1",
        [],
    )
    .unwrap();
    drop(conn);
    let store = SqliteRiskStore::open(dir.path().join("risk-guard.db")).unwrap();
    let bundle = store.export_replay_bundle("agent-r", None).unwrap();
    assert!(!bundle.history.complete);
    assert!(
        bundle
            .history
            .problems
            .iter()
            .any(|p| p.contains("epoch-sbx-1"))
    );
    assert!(
        replay(&bundle, false).is_err(),
        "an incomplete history must not be replayed as if it were whole"
    );
    assert!(
        replay(&bundle, true).is_ok(),
        "but it can be replayed deliberately, as a best effort"
    );
}
