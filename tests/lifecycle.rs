//! Sandbox lifecycle and decision time, as the console and `/metrics` report them.
//!
//! Risk Guard learns of a deleted sandbox only from OpenShell's post-commit event, and OpenShell makes that hook fail-open, so a
//! missed event (a restart, an outage) leaves an epoch open for a sandbox that is gone. Risk Guard never queries the gateway
//! (that would need a credential able to create and delete sandboxes), so it derives "open" from activity on every read and
//! never writes it: a sandbox that speaks again is open again.

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::latency::LatencyInterval;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::*;
use serde_json::Value;

const HOUR: i64 = 3_600_000;
const NOW: i64 = 1_800_000_000_000;

fn store() -> SqliteRiskStore {
    let store =
        seed_fixture_store(tempfile::tempdir().unwrap().keep().join("lifecycle.db")).unwrap();
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline).unwrap();
    store
}

/// A workload's sandbox with its own run, bound and (optionally) heard from at `last_request_age` ms before `NOW`.
fn sandbox(store: &SqliteRiskStore, agent: &str, name: &str, last_request_age: Option<i64>) {
    let baseline = store.get_baseline("repo-triage-readonly").unwrap().unwrap();
    let run = format!("run-{name}");
    store
        .create_agent_run(
            agent,
            &run,
            "revision-1",
            &baseline.task_profile,
            EnforcementMode::Enforce,
        )
        .unwrap();
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: format!("epoch-{name}"),
            gateway_id: "gateway".into(),
            sandbox_id: name.into(),
            task_profile: baseline.task_profile.clone(),
            baseline_hash: compute_baseline_hash(&baseline),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: NOW - 30 * HOUR,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
    store.bind_agent_run(&run, name, "gateway").unwrap();
    if let Some(age) = last_request_age {
        let request = CanonicalNormalizer::new_default(b"lifecycle-test-only-key")
            .normalize(&RawRequestInput {
                request_id: format!("req-{name}"),
                sandbox_id: name.into(),
                sandbox_name: name.into(),
                workspace: "default".into(),
                scheme: "https".into(),
                host: "api.github.local".into(),
                port: 18443,
                method: "GET".into(),
                path: "/repos/org/docs-site/issues".into(),
                binary_path: Some("/usr/bin/curl".into()),
                pid: None,
                ancestors: vec![],
                timestamp_ms: NOW - age,
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
}

fn workload(inventory: &Value, agent: &str) -> Value {
    inventory["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["agent_id"] == agent)
        .unwrap_or_else(|| panic!("workload {agent} missing"))
        .clone()
}

#[test]
fn open_and_presumed_gone_are_derived_from_activity_and_never_written() {
    let store = store();
    store.register_agent("a", "Agent A").unwrap();
    sandbox(&store, "a", "sbx-busy", Some(60_000)); // spoke a minute ago
    sandbox(&store, "a", "sbx-quiet", Some(2 * HOUR)); // quiet, but within the window
    sandbox(&store, "a", "sbx-ghost", Some(24 * HOUR)); // gone, delete event missed
    sandbox(&store, "a", "sbx-deleted", Some(3 * HOUR));
    store.close_sandbox_lifecycle("sbx-deleted").unwrap(); // gone, delete event seen

    let inventory = store.operator_inventory(NOW).unwrap();
    let a = workload(&inventory, "a");
    assert_eq!(a["sandbox_count"], 4, "everything ever bound");
    assert_eq!(
        a["active_sandbox_count"], 3,
        "epochs no delete event has closed"
    );
    assert_eq!(
        a["open_sandbox_count"], 2,
        "of those, the ones seen within six hours"
    );
    assert_eq!(
        a["presumed_gone_sandbox_count"], 1,
        "the one nobody has heard from for a day"
    );

    let life = &inventory["sandbox_lifecycle"];
    assert_eq!(life["open"], 2);
    assert_eq!(life["presumed_gone"], 1);
    assert_eq!(life["sandboxes_closed"], 1);

    // Nothing was written: a day later the same data reads differently, and a sandbox that speaks again is open again.
    let later = store.operator_inventory(NOW + 8 * HOUR).unwrap();
    let a_later = workload(&later, "a");
    assert_eq!(
        a_later["open_sandbox_count"], 0,
        "eight hours on, all three have gone quiet"
    );
    assert_eq!(a_later["presumed_gone_sandbox_count"], 3);
    assert_eq!(
        a_later["active_sandbox_count"], 3,
        "no epoch was closed by guessing"
    );
}

#[test]
fn each_run_and_sandbox_reports_its_own_lifecycle() {
    let store = store();
    store.register_agent("a", "Agent A").unwrap();
    sandbox(&store, "a", "sbx-busy", Some(60_000));
    sandbox(&store, "a", "sbx-ghost", Some(24 * HOUR));
    sandbox(&store, "a", "sbx-deleted", Some(3 * HOUR));
    store.close_sandbox_lifecycle("sbx-deleted").unwrap();

    let detail = store.operator_agent_detail("a", NOW).unwrap().unwrap();
    let runs = detail["runs"].as_array().unwrap();
    let state = |run: &str| {
        runs.iter().find(|r| r["run_id"] == run).unwrap()["lifecycle"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(state("run-sbx-busy"), "open");
    assert_eq!(state("run-sbx-ghost"), "presumed_gone");
    assert_eq!(
        state("run-sbx-deleted"),
        "ended",
        "a delete event ended the run"
    );

    let sandbox_state = |run: &str| {
        runs.iter().find(|r| r["run_id"] == run).unwrap()["sandboxes"][0]["lifecycle"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(sandbox_state("run-sbx-busy"), "recently_active");
    assert_eq!(sandbox_state("run-sbx-ghost"), "not_seen_recently");
    assert_eq!(sandbox_state("run-sbx-deleted"), "closed");
}

#[test]
fn decision_time_is_summarized_over_the_last_hour_and_exported() {
    let store = store();
    let mut fast = LatencyInterval::default();
    for _ in 0..98 {
        fast.record(800);
    }
    fast.record(7_000);
    fast.record(40_000);
    let mut slow = LatencyInterval::default();
    slow.record(900_000); // past OpenShell's 500 ms timeout
    let mut stale = LatencyInterval::default();
    stale.record(400_000); // an hour and a half ago: outside the window
    store
        .record_latency_interval(NOW - 90 * 60_000, &stale)
        .unwrap();
    store
        .record_latency_interval(NOW - 20 * 60_000, &fast)
        .unwrap();
    store
        .record_latency_interval(NOW - 5 * 60_000, &slow)
        .unwrap();

    let summary = &store.operator_inventory(NOW).unwrap()["decision_latency"];
    assert_eq!(
        summary["samples"], 101,
        "the stale interval is outside the window"
    );
    assert_eq!(summary["over_timeout"], 1);
    assert_eq!(summary["max_us"], 900_000);
    assert_eq!(
        summary["p50_us"], 1_000,
        "98 of 101 samples are within 1 ms"
    );
    assert!(
        summary["p99_us"].as_u64().unwrap() >= 40_000,
        "the slow tail is not hidden by the median"
    );
    assert_eq!(summary["timeout_us"], 500_000);

    let metrics = store.prometheus_metrics(NOW).unwrap();
    for expected in [
        "openshell_risk_guard_decision_latency_seconds{quantile=\"0.5\"} 0.001",
        "openshell_risk_guard_decision_latency_samples 101",
        "openshell_risk_guard_decision_latency_over_timeout 1",
        "openshell_risk_guard_decision_latency_max_seconds 0.9",
        "openshell_risk_guard_sandboxes{state=\"open\"} 0",
    ] {
        assert!(
            metrics.contains(expected),
            "metrics must contain `{expected}`:\n{metrics}"
        );
    }
}

#[test]
fn with_no_samples_nothing_is_invented() {
    let store = store();
    let summary = &store.operator_inventory(NOW).unwrap()["decision_latency"];
    assert_eq!(summary["samples"], 0);
    assert!(summary["p99_us"].is_null() && summary["max_us"].is_null());
    let metrics = store.prometheus_metrics(NOW).unwrap();
    assert!(
        !metrics.contains("decision_latency_seconds{"),
        "no percentile line without samples"
    );
    assert!(metrics.contains("openshell_risk_guard_decision_latency_samples 0"));
    assert!(
        !metrics.contains("seconds_since_last_decision"),
        "no decision yet, so no staleness figure"
    );
}

#[test]
fn staleness_is_exported_once_a_decision_exists() {
    let store = store();
    store.register_agent("a", "Agent A").unwrap();
    sandbox(&store, "a", "sbx-busy", Some(10 * 60_000)); // decided ten minutes before NOW
    let metrics = store.prometheus_metrics(NOW).unwrap();
    let line = metrics
        .lines()
        .find(|l| l.starts_with("openshell_risk_guard_seconds_since_last_decision "))
        .unwrap_or_else(|| panic!("staleness gauge missing:\n{metrics}"));
    let seconds: f64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert!(
        (599.0..=601.0).contains(&seconds),
        "about ten minutes: {seconds}"
    );
}

#[test]
fn a_sandbox_shows_the_spiffe_id_spire_assigned_it_only_when_a_trust_domain_is_configured() {
    use openshell_risk_guard::detector::compute_baseline_hash;
    use openshell_risk_guard::fixture::build_standard_corpus;
    use openshell_risk_guard::types::{EnforcementMode, EpochRecord, RiskStore};

    let spiffe_id = |configured: bool, since_ms: i64| {
        let mut store = SqliteRiskStore::open_in_memory().unwrap();
        if configured {
            store = store
                .with_sandbox_spiffe_trust_domain("example.org")
                .with_sandbox_spiffe_since_ms(since_ms);
        }
        let mut baseline = build_standard_corpus().default_baseline;
        baseline.normalizer_version = "v1".into();
        store.store_baseline(&baseline).unwrap();
        store.register_agent("agent", "Agent").unwrap();
        store
            .create_agent_run(
                "agent",
                "run-1",
                "r1",
                &baseline.task_profile,
                EnforcementMode::Enforce,
            )
            .unwrap();
        store
            .upsert_epoch(&EpochRecord {
                epoch_id: "ep-1".into(),
                gateway_id: "gw".into(),
                sandbox_id: "sbx-1".into(),
                task_profile: baseline.task_profile.clone(),
                baseline_hash: compute_baseline_hash(&baseline),
                mode: EnforcementMode::Enforce,
                active: true,
                next_sequence: 1,
                created_at_ms: 1_800_000_000_000,
                credentialed_endpoints: Default::default(),
                active_policy_hash: None,
            })
            .unwrap();
        store.bind_agent_run("run-1", "sbx-1", "gw").unwrap();
        let detail = store
            .operator_agent_detail("agent", 1_800_000_001_000)
            .unwrap()
            .unwrap();
        detail["runs"][0]["sandboxes"][0]["spiffe_id"].clone()
    };
    assert_eq!(
        spiffe_id(true, 0),
        "spiffe://example.org/openshell/sandbox/sbx-1"
    );
    assert!(
        spiffe_id(false, 0).is_null(),
        "no trust domain, no identity shown"
    );
    assert!(
        spiffe_id(true, 1_800_000_000_001).is_null(),
        "a sandbox created before SPIFFE was enabled was never named by SPIRE"
    );
}
