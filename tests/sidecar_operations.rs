use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::{RestrictionTarget, SqliteRiskStore};
use openshell_risk_guard::types::*;

const AGENT: &str = "clearance-agent";

fn seed(path: &std::path::Path) -> SqliteRiskStore {
    let store = SqliteRiskStore::open(path).unwrap();
    let mut profile = build_standard_corpus().default_baseline;
    profile.normalizer_version = "v1".into();
    profile.forbid_unfamiliar_high_impact = true;
    store.store_baseline(&profile).unwrap();
    store.register_agent(AGENT, "Clearance test").unwrap();
    store
        .create_agent_run(AGENT, "run-1", "r1", &profile.task_profile, EnforcementMode::Enforce)
        .unwrap();
    store
        .upsert_epoch(&EpochRecord {
            epoch_id: "epoch-1".into(),
            gateway_id: "gateway".into(),
            sandbox_id: "sandbox-1".into(),
            task_profile: profile.task_profile.clone(),
            baseline_hash: compute_baseline_hash(&profile),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: 0,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
    store.bind_agent_run("run-1", "sandbox-1", "gateway").unwrap();
    store
}

fn evaluate(store: &SqliteRiskStore, id: &str, method: &str, path: &str) -> RiskEvaluation {
    let request = CanonicalNormalizer::new_default(b"sidecar-operations-test-key")
        .normalize(&RawRequestInput {
            request_id: id.into(),
            sandbox_id: "sandbox-1".into(),
            sandbox_name: "sandbox-1".into(),
            workspace: "default".into(),
            scheme: "https".into(),
            host: "api.github.local".into(),
            port: 18443,
            method: method.into(),
            path: path.into(),
            binary_path: Some("/usr/bin/curl".into()),
            pid: None,
            ancestors: vec![],
            timestamp_ms: 1_000_000 + id.len() as i64,
        })
        .unwrap();
    store
        .evaluate_native_authenticated(
            &request,
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
            NativeObservationSource::LocalTestSupervisor,
        )
        .unwrap()
}

#[test]
fn operator_clearance_is_audited_and_lets_the_scope_be_scored_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = seed(&dir.path().join("clearance.db"));
    let agent = RestrictionTarget::Agent { agent_id: AGENT, context_id: None };

    let first = evaluate(&store, "delete-1", "DELETE", "/repos/org/payments-prod");
    assert_eq!(first.outcome, DecisionOutcome::Deny);
    assert_eq!(
        evaluate(&store, "delete-2", "DELETE", "/repos/org/payments-prod").reason_code,
        REASON_BEHAVIORAL_RISK_RESTRICTED
    );
    let listed = store.list_restrictions(agent, 2_000_000).unwrap();
    let row = &listed["restrictions"][0];
    assert_eq!(row["tier"], "strict_epoch");
    assert_eq!(row["blocking"], true);
    let scope = row["scope"].as_str().unwrap().to_string();

    assert!(store.clear_restriction(agent, &scope, "", "reviewed", 2_000_001).is_err());
    assert!(store.clear_restriction(agent, &scope, "alice", " ", 2_000_001).is_err());
    assert!(store.clear_restriction(agent, "no-such-scope", "alice", "reviewed", 2_000_001).is_err());
    assert!(
        store
            .clear_restriction(
                RestrictionTarget::Sandbox { sandbox_id: "sandbox-1" },
                &scope, "alice", "reviewed", 2_000_001,
            )
            .is_err(),
        "agent-bound restrictions are not owned by the legacy sandbox epoch"
    );

    let cleared = store
        .clear_restriction(agent, &scope, "alice", "approved maintenance task", 2_000_002)
        .unwrap();
    assert_eq!(cleared["status"], "cleared");
    assert_eq!(cleared["trigger_request_id"], "delete-1");
    assert_eq!(cleared["cleared_by"], "alice");
    assert!(store.list_restrictions(agent, 2_000_003).unwrap()["restrictions"]
        .as_array()
        .unwrap()
        .is_empty());

    // The scope is scored again rather than short-circuited by the old restriction.
    let rescored = evaluate(&store, "delete-3", "DELETE", "/repos/org/payments-prod");
    assert_ne!(rescored.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
    // Original evidence is untouched.
    assert_eq!(store.list_decisions("sandbox-1", 10).unwrap().len(), 3);
}

#[test]
fn a_database_stays_bound_to_its_resource_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyed.db");
    let store = SqliteRiskStore::open(&path).unwrap();
    let key = [7u8; 32];
    store.bind_resource_key(&key, 1).unwrap();
    store.bind_resource_key(&key, 2).unwrap();
    drop(store);
    let reopened = SqliteRiskStore::open(&path).unwrap();
    assert!(reopened.bind_resource_key(&key, 3).is_ok());
    assert!(reopened.bind_resource_key(&[8u8; 32], 4).is_err());
}
