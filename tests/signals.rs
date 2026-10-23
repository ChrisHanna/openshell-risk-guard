// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Signals: a SIEM can ask Risk Guard to tighten, and only to tighten, for a while, within limits, with a record of every one.

use std::sync::Arc;

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::compute_baseline_hash;
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::signals::{SignalsState, router};
use openshell_risk_guard::store::{SignalPolicy, SignalRequest, SqliteRiskStore};
use openshell_risk_guard::types::*;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn store(dir: &tempfile::TempDir) -> SqliteRiskStore {
    let store = seed_fixture_store(dir.path().join("rg.db")).unwrap();
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline).unwrap();
    for agent in ["agent-a", "agent-b", "agent-c"] {
        store.register_agent(agent, "test agent").unwrap();
    }
    store
}

fn bind(store: &SqliteRiskStore, agent: &str, sandbox: &str, run: &str) {
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
            created_at_ms: now(),
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        })
        .unwrap();
    store.bind_agent_run(run, sandbox, "gateway").unwrap();
}

fn signal(id: &str, agent: &str) -> SignalRequest {
    SignalRequest {
        signal_id: id.into(),
        source: "opensearch-alerting".into(),
        alert_id: Some("alert-1".into()),
        agent_id: Some(agent.into()),
        sandbox_id: None,
        action: "quarantine".into(),
        ttl_seconds: 300,
        reason: "three middleware failures in five minutes".into(),
        dry_run: false,
    }
}

fn quarantined(store: &SqliteRiskStore) -> Vec<String> {
    store.list_quarantined().unwrap()["quarantined"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["agent_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn only_a_tightening_action_with_one_target_and_a_sane_ttl_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let policy = SignalPolicy::default();
    let mut release = signal("s1", "agent-a");
    release.action = "release".into();
    assert!(store.apply_signal(&release, &policy, now()).is_err());
    let mut both = signal("s2", "agent-a");
    both.sandbox_id = Some("sandbox-1".into());
    assert!(store.apply_signal(&both, &policy, now()).is_err());
    let mut neither = signal("s3", "agent-a");
    neither.agent_id = None;
    assert!(store.apply_signal(&neither, &policy, now()).is_err());
    for ttl in [0, 59, 3601, 86_400] {
        let mut request = signal("s4", "agent-a");
        request.ttl_seconds = ttl;
        assert!(
            store.apply_signal(&request, &policy, now()).is_err(),
            "ttl {ttl}"
        );
    }
    assert!(quarantined(&store).is_empty());
    // Refused requests leave no record: only signals that passed validation are kept.
    assert!(
        store.list_signals(10).unwrap()["signals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_signal_quarantines_for_its_time_and_then_lets_go_by_itself() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let policy = SignalPolicy::default();
    let outcome = store
        .apply_signal(&signal("live", "agent-a"), &policy, now())
        .unwrap();
    assert_eq!(outcome.outcome, "applied");
    assert!(outcome.expires_at_ms.unwrap() > now());
    assert_eq!(quarantined(&store), vec!["agent-a"]);

    // A signal that arrived long ago (its 60 s have passed) is no longer in force.
    let old = store
        .apply_signal(&signal("old", "agent-b"), &policy, now() - 600_000)
        .unwrap();
    assert_eq!(old.outcome, "applied");
    assert_eq!(quarantined(&store), vec!["agent-a"]);
}

#[test]
fn a_quarantine_holds_a_sandbox_at_the_network_gate_through_the_workload() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    bind(&store, "agent-a", "sandbox-1", "run-1");
    assert!(
        !store
            .sandbox_network_state("sandbox-1")
            .unwrap()
            .unwrap()
            .quarantined
    );
    let mut by_sandbox = signal("by-sandbox", "agent-a");
    by_sandbox.agent_id = None;
    by_sandbox.sandbox_id = Some("sandbox-1".into());
    let outcome = store
        .apply_signal(&by_sandbox, &SignalPolicy::default(), now())
        .unwrap();
    assert_eq!(
        (outcome.outcome.as_str(), outcome.agent_id.as_deref()),
        ("applied", Some("agent-a"))
    );
    assert!(
        store
            .sandbox_network_state("sandbox-1")
            .unwrap()
            .unwrap()
            .quarantined
    );
}

#[test]
fn a_signal_never_overrides_or_shortens_a_persons_quarantine() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    store
        .quarantine_workload("agent-a", "alice", "investigating", now())
        .unwrap();
    let outcome = store
        .apply_signal(&signal("s", "agent-a"), &SignalPolicy::default(), now())
        .unwrap();
    assert_eq!(outcome.outcome, "already_quarantined");
    // Still there, still without an end, still alice's.
    let listed = store.list_quarantined().unwrap();
    assert_eq!(listed["quarantined"][0]["operator"], "alice");
    assert!(listed["quarantined"][0]["expires_at_ms"].is_null());
}

#[test]
fn a_dry_run_records_but_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let mut asked = signal("asked", "agent-a");
    asked.dry_run = true;
    assert_eq!(
        store
            .apply_signal(&asked, &SignalPolicy::default(), now())
            .unwrap()
            .outcome,
        "dry_run"
    );
    let policy = SignalPolicy {
        dry_run: true,
        ..Default::default()
    };
    assert_eq!(
        store
            .apply_signal(&signal("policy", "agent-b"), &policy, now())
            .unwrap()
            .outcome,
        "dry_run"
    );
    assert!(quarantined(&store).is_empty());
    assert_eq!(
        store.list_signals(10).unwrap()["signals"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn limits_stop_a_flood_and_a_sweep_of_the_fleet() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let policy = SignalPolicy {
        max_active: 2,
        max_per_minute: 10,
        ..Default::default()
    };
    assert_eq!(
        store
            .apply_signal(&signal("1", "agent-a"), &policy, now())
            .unwrap()
            .outcome,
        "applied"
    );
    assert_eq!(
        store
            .apply_signal(&signal("2", "agent-b"), &policy, now())
            .unwrap()
            .outcome,
        "applied"
    );
    assert_eq!(
        store
            .apply_signal(&signal("3", "agent-c"), &policy, now())
            .unwrap()
            .outcome,
        "too_many_active"
    );
    assert_eq!(quarantined(&store).len(), 2);

    let dir = tempfile::tempdir().unwrap();
    let store = self::store(&dir);
    let policy = SignalPolicy {
        max_per_minute: 1,
        ..Default::default()
    };
    assert_eq!(
        store
            .apply_signal(&signal("1", "agent-a"), &policy, now())
            .unwrap()
            .outcome,
        "applied"
    );
    assert_eq!(
        store
            .apply_signal(&signal("2", "agent-b"), &policy, now())
            .unwrap()
            .outcome,
        "rate_limited"
    );
    assert_eq!(quarantined(&store), vec!["agent-a"]);
}

#[test]
fn a_repeated_signal_is_answered_not_applied_twice_and_an_unknown_target_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let policy = SignalPolicy::default();
    let first = store
        .apply_signal(&signal("same", "agent-a"), &policy, now())
        .unwrap();
    let again = store
        .apply_signal(&signal("same", "agent-a"), &policy, now() + 5_000)
        .unwrap();
    assert!(!first.duplicate && again.duplicate);
    assert_eq!(first.expires_at_ms, again.expires_at_ms);
    assert_eq!(
        store.list_signals(10).unwrap()["signals"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let unknown = store
        .apply_signal(&signal("x", "no-such-agent"), &policy, now())
        .unwrap();
    assert_eq!(unknown.outcome, "unknown_target");
}

async fn call(
    address: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (u16, serde_json::Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (
        code,
        serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn the_listener_wants_its_own_token_and_answers_with_the_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(store(&dir));
    let token = "ab".repeat(32);
    let state = SignalsState::new(Arc::clone(&store), &token, SignalPolicy::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });

    let body = serde_json::to_string(&serde_json::json!({
        "signal_id": "http-1", "source": "opensearch-alerting", "alert_id": "a-1", "agent_id": "agent-a",
        "action": "quarantine", "ttl_seconds": 120, "reason": "test"
    }))
    .unwrap();
    assert_eq!(
        call(&address, "POST", "/v1/signals", None, &body).await.0,
        401
    );
    assert_eq!(
        call(
            &address,
            "POST",
            "/v1/signals",
            Some(&"cd".repeat(32)),
            &body
        )
        .await
        .0,
        401
    );
    assert_eq!(
        call(&address, "POST", "/v1/signals", Some("short"), &body)
            .await
            .0,
        401
    );
    assert_eq!(call(&address, "GET", "/healthz", None, "").await.0, 200);

    let (code, reply) = call(&address, "POST", "/v1/signals", Some(&token), &body).await;
    assert_eq!((code, reply["outcome"].as_str()), (200, Some("applied")));
    assert_eq!(quarantined(&store), vec!["agent-a"]);

    // Unknown fields, and anything that is not a tightening action, are refused.
    let extra = body.replace("\"reason\"", "\"release\":true,\"reason\"");
    assert_eq!(
        call(&address, "POST", "/v1/signals", Some(&token), &extra)
            .await
            .0,
        400
    );
    let loosen = body
        .replace("quarantine", "release")
        .replace("http-1", "http-2");
    assert_eq!(
        call(&address, "POST", "/v1/signals", Some(&token), &loosen)
            .await
            .0,
        400
    );
    assert_eq!(
        call(&address, "POST", "/v1/signals", Some(&token), "not json")
            .await
            .0,
        400
    );

    let (code, listed) = call(&address, "GET", "/v1/signals", Some(&token), "").await;
    assert_eq!(code, 200);
    assert_eq!(listed["signals"].as_array().unwrap().len(), 1);
}

#[test]
fn a_token_that_is_not_64_hex_characters_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(store(&dir));
    for token in ["", "short", &"z".repeat(64), &"a".repeat(65)] {
        assert!(
            SignalsState::new(Arc::clone(&store), token, SignalPolicy::default()).is_err(),
            "{token}"
        );
    }
}
