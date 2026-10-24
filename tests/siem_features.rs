// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! SIEM risk features (docs/design-siem-features.md): who may send them, what is accepted, how they resolve to a workload, what they add to a score
//! (watching adds nothing, enforcing adds the documented points, never more than the cap, never a negative), and that a decision made with them replays.

use std::sync::Arc;

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::siem::{self, VOCABULARY};
use openshell_risk_guard::detector::{InteractionRiskDetector, compute_baseline_hash};
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::replay::replay;
use openshell_risk_guard::signals::{SignalsState, serve_mtls};
use openshell_risk_guard::store::{
    FeatureBatch, FeatureIngest, IngestStatus, SignalPolicy, SqliteRiskStore,
};
use openshell_risk_guard::types::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::{Value, json};

const HMAC_KEY: &[u8] = b"siem-features-test-only-hmac-key";
const START: i64 = 1_800_000_000_000;
const SOURCE: &str = "spiffe://example.org/ns/siem/sa/signal-forwarder";
const AGENT: &str = "agent-f";
const SANDBOX: &str = "sbx-f1";

// ---------------------------------------------------------------------------------------------------------------------------------------
// A store with a workload running in a sandbox, and helpers to publish features and score a request.
// ---------------------------------------------------------------------------------------------------------------------------------------

fn store_with(mode: Option<RuleMode>, max_points: Option<u32>) -> SqliteRiskStore {
    let dir = tempfile::tempdir().unwrap();
    let store = seed_fixture_store(dir.path().join("rg.db")).unwrap();
    // The directory must outlive the store; the test process ends soon after, so leak it rather than thread it through every helper.
    std::mem::forget(dir);
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    if let Some(mode) = mode {
        baseline.rule_modes.insert(RULE_SIEM_CONTEXT.into(), mode);
    }
    baseline.siem_context_max_points = max_points;
    store.store_baseline(&baseline).unwrap();
    store.register_agent(AGENT, "Feature agent").unwrap();
    bind(&store, AGENT, SANDBOX, "run-f1", START - 60_000);
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

fn batch(generated_at_ms: i64, subjects: Value) -> FeatureBatch {
    serde_json::from_value(json!({
        "schema": 1, "generated_at_ms": generated_at_ms, "window_seconds": 300, "subjects": subjects
    }))
    .unwrap()
}

fn ingest(store: &SqliteRiskStore, at: i64, subjects: Value) -> FeatureIngest {
    store
        .ingest_siem_features(SOURCE, 100, &batch(at - 1_000, subjects), at)
        .unwrap()
}

/// Every feature the rules read, at the values that make `rules` fire.
fn subjects_for(
    denials: u32,
    own_ratio: u32,
    fleet_ratio: u32,
    new_routes: u32,
    unique: u32,
    campaign: u32,
) -> Value {
    json!([
        {"kind": "sandbox", "id": SANDBOX, "features": {"openshell_denials_5m": denials}},
        {"kind": "workload", "id": AGENT, "features": {
            "refusal_ratio_15m_permille": own_ratio, "new_routes_1h": new_routes, "routes_unique_to_workload_permille": unique}},
        {"kind": "fleet", "id": "fleet", "features": {
            "fleet_refusal_ratio_15m_permille": fleet_ratio, "fleet_workloads_with_denials_5m": campaign}},
    ])
}

fn request(id: &str, method: &str, resource: &str, at: i64) -> NormalizedRequest {
    CanonicalNormalizer::new_default(HMAC_KEY)
        .normalize(&RawRequestInput {
            request_id: id.into(),
            sandbox_id: SANDBOX.into(),
            sandbox_name: SANDBOX.into(),
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
        .unwrap()
}

fn score(store: &SqliteRiskStore, id: &str, at: i64) -> RiskEvaluation {
    store
        .evaluate_authenticated(
            &request(id, "GET", "docs-site", at),
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
        )
        .unwrap()
}

fn siem_signal(eval: &RiskEvaluation) -> Option<&SignalContribution> {
    eval.signals.iter().find(|s| s.feature == "siem_context")
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Door: mutual TLS, the SPIFFE allow-list, the source from the certificate.
// ---------------------------------------------------------------------------------------------------------------------------------------

struct Authority {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Authority {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    fn svid(&self, uri: &str) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names =
            vec![SanType::URI(Ia5String::try_from(uri.to_string()).unwrap())];
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn server(&self) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

struct Running {
    port: u16,
    store: Arc<SqliteRiskStore>,
    authority: Authority,
    _dir: tempfile::TempDir,
}

async fn start() -> Running {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(seed_fixture_store(dir.path().join("rg.db")).unwrap());
    let authority = Authority::new();
    let bundle = dir.path().join("bundle.crt");
    std::fs::write(&bundle, authority.cert.pem()).unwrap();
    let (cert, key) = authority.server();
    let state = SignalsState::new_spiffe(
        Arc::clone(&store),
        &["example.org".to_string()],
        [SOURCE],
        SignalPolicy::default(),
    )
    .unwrap();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    tokio::spawn(async move {
        serve_mtls(
            format!("127.0.0.1:{port}").parse().unwrap(),
            state,
            cert.into_bytes(),
            key.into_bytes(),
            bundle,
            std::future::pending::<()>,
        )
        .await
        .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Running {
        port,
        store,
        authority,
        _dir: dir,
    }
}

fn client(running: &Running, identity: Option<(String, String)>) -> reqwest::Client {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(running.authority.cert.pem().as_bytes()).unwrap(),
        )
        .resolve("localhost", ([127, 0, 0, 1], running.port).into())
        .timeout(std::time::Duration::from_secs(10));
    if let Some((cert, key)) = identity {
        builder = builder
            .identity(reqwest::Identity::from_pem(format!("{cert}{key}").as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

fn wall_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn wire_body() -> Value {
    json!({
        "schema": 1, "generated_at_ms": wall_now() - 1_000, "window_seconds": 300,
        "subjects": [{"kind": "sandbox", "id": "sbx-wire", "features": {"openshell_denials_5m": 3}}]
    })
}

#[tokio::test]
async fn only_the_allowed_spiffe_identity_may_post_features_and_the_body_cannot_name_the_source() {
    let running = start().await;
    let url = format!("https://localhost:{}/features", running.port);

    // An identity that is valid but not on the list, in the list's trust domain or another, is refused, and nothing is stored.
    for other in [
        "spiffe://example.org/ns/siem/sa/someone-else",
        "spiffe://elsewhere.org/ns/siem/sa/signal-forwarder",
    ] {
        let http = client(&running, Some(running.authority.svid(other)));
        let status = http
            .post(&url)
            .json(&wire_body())
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 403, "{other}");
    }
    // No certificate, or one from an authority the bundle does not hold: no HTTP answer at all.
    assert!(
        client(&running, None)
            .post(&url)
            .json(&wire_body())
            .send()
            .await
            .is_err()
    );
    let rogue = Authority::new();
    assert!(
        client(&running, Some(rogue.svid(SOURCE)))
            .post(&url)
            .json(&wire_body())
            .send()
            .await
            .is_err()
    );
    assert!(
        running.store.list_siem_features().unwrap()["features"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        running.store.list_siem_feature_batches(10).unwrap()["batches"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // A body that tries to name its own source is refused outright: the schema has no such field.
    let http = client(&running, Some(running.authority.svid(SOURCE)));
    let mut spoof = wire_body();
    spoof["source"] = json!("spiffe://example.org/ns/someone/sa/else");
    let reply = http.post(&url).json(&spoof).send().await.unwrap();
    assert_eq!(reply.status(), 400);
    assert!(
        running.store.list_siem_features().unwrap()["features"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // The malformed body is in the audit table, under the certificate's identity, not the body's.
    let audit = running.store.list_siem_feature_batches(10).unwrap();
    assert_eq!(audit["batches"][0]["source"], SOURCE);
    assert_eq!(audit["batches"][0]["outcome"], "invalid");

    // The allowed identity posts a good batch; the source recorded is its certificate's SPIFFE ID.
    let reply = http.post(&url).json(&wire_body()).send().await.unwrap();
    assert_eq!(reply.status(), 200);
    let answer: Value = reply.json().await.unwrap();
    assert_eq!(answer["accepted"], 1);
    let stored = running.store.list_siem_features().unwrap();
    assert_eq!(stored["features"][0]["source"], SOURCE);
    assert_eq!(stored["features"][0]["name"], "openshell_denials_5m");

    // A second batch inside ten seconds is refused with 429.
    let again = http.post(&url).json(&wire_body()).send().await.unwrap();
    assert_eq!(again.status(), 429);

    // The body limit is 64 KiB: a batch over it is refused with 413 before it is read.
    let big = json!({"schema": 1, "generated_at_ms": wall_now(), "window_seconds": 300, "subjects": [], "pad": "x".repeat(70 * 1024)});
    let tight = client(&running, Some(running.authority.svid(SOURCE)));
    assert_eq!(
        tight.post(&url).json(&big).send().await.unwrap().status(),
        413
    );
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// What is accepted.
// ---------------------------------------------------------------------------------------------------------------------------------------

#[test]
fn only_the_closed_vocabulary_within_its_ranges_is_stored_and_every_refusal_is_counted() {
    let store = store_with(None, None);
    assert_eq!(VOCABULARY.len(), 10);
    let result = ingest(
        &store,
        START,
        json!([
            {"kind": "sandbox", "id": SANDBOX, "features": {
                "openshell_denials_5m": 4,               // good
                "openshell_denials_1h": 100_001,         // over the count range
                "openshell_would_block_5m": -1,          // negative
                "made_up_feature": 1,                    // not in the vocabulary
                "refusal_ratio_15m_permille": 10,        // a workload feature on a sandbox
                "openshell_denials_5m_extra": "3"        // not in the vocabulary either
            }},
            {"kind": "workload", "id": AGENT, "features": {
                "refusal_ratio_15m_permille": 1001,      // over the permille range
                "new_routes_1h": 2.5,                    // not an integer
                "routes_unique_to_workload_permille": 1000 // the top of the range is fine
            }},
            {"kind": "fleet", "id": "not-fleet", "features": {"fleet_active_workloads_15m": 3}},
            {"kind": "planet", "id": "x", "features": {"fleet_active_workloads_15m": 3}},
            {"kind": "fleet", "id": "fleet", "features": {"fleet_active_workloads_15m": 100_000}}
        ]),
    );
    assert_eq!(result.status, IngestStatus::Accepted);
    assert_eq!(result.accepted, 3, "{result:?}");
    assert_eq!(result.rejected, 9, "{result:?}");
    for (reason, n) in [
        ("value_out_of_range", 3),
        ("unknown_feature", 2),
        ("feature_not_allowed_for_kind", 1),
        ("value_not_an_integer", 1),
        ("fleet_id_must_be_fleet", 1),
        ("unknown_subject_kind", 1),
    ] {
        assert_eq!(
            result.reasons.get(reason),
            Some(&n),
            "{reason}: {:?}",
            result.reasons
        );
    }
    let stored = store.list_siem_features().unwrap();
    let names: Vec<(&str, i64)> = stored["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["name"].as_str().unwrap(), f["value"].as_i64().unwrap()))
        .collect();
    assert!(names.contains(&("openshell_denials_5m", 4)));
    assert!(names.contains(&("routes_unique_to_workload_permille", 1000)));
    assert!(names.contains(&("fleet_active_workloads_15m", 100_000)));
    assert_eq!(names.len(), 3);
    // The batch is in the audit table with its counts and reasons.
    let audit = store.list_siem_feature_batches(5).unwrap();
    assert_eq!(audit["batches"][0]["accepted"], 3);
    assert_eq!(audit["batches"][0]["rejected"], 9);
    assert_eq!(audit["batches"][0]["reasons"]["unknown_feature"], 2);
}

#[test]
fn a_batch_must_be_schema_one_fresh_small_and_no_more_than_one_per_ten_seconds() {
    let store = store_with(None, None);
    let good =
        json!([{"kind": "fleet", "id": "fleet", "features": {"fleet_active_workloads_15m": 3}}]);

    let wrong_schema: FeatureBatch = serde_json::from_value(json!({
        "schema": 2, "generated_at_ms": START, "window_seconds": 300, "subjects": good
    }))
    .unwrap();
    assert_eq!(
        store
            .ingest_siem_features(SOURCE, 1, &wrong_schema, START)
            .unwrap()
            .status,
        IngestStatus::Invalid
    );

    // Older than ten minutes: stale, nothing stored. Nine minutes old is still fine.
    let old = store
        .ingest_siem_features(
            SOURCE,
            1,
            &batch(START - 10 * 60_000 - 1, good.clone()),
            START + 10_000,
        )
        .unwrap();
    assert_eq!(old.status, IngestStatus::Stale);
    assert!(
        store.list_siem_features().unwrap()["features"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let recent = store
        .ingest_siem_features(
            SOURCE,
            1,
            &batch(START - 9 * 60_000, good.clone()),
            START + 20_000,
        )
        .unwrap();
    assert_eq!(recent.status, IngestStatus::Accepted);

    // Generated in the future: invalid (it would outlive what its sender meant).
    let future = store
        .ingest_siem_features(
            SOURCE,
            1,
            &batch(START + 20_000 + 6 * 60_000, good.clone()),
            START + 30_000,
        )
        .unwrap();
    assert_eq!(future.status, IngestStatus::Invalid);

    // More than 2,000 subjects.
    let many: Vec<Value> = (0..2_001)
        .map(|n| json!({"kind": "sandbox", "id": format!("s{n}"), "features": {"openshell_denials_5m": 1}}))
        .collect();
    let too_many = store
        .ingest_siem_features(
            SOURCE,
            1,
            &batch(START + 40_000, Value::Array(many)),
            START + 40_000,
        )
        .unwrap();
    assert_eq!(too_many.status, IngestStatus::Invalid);
    assert_eq!(too_many.reasons.get("too_many_subjects"), Some(&2_001));

    // Rate: one batch per source per ten seconds. A different source is not held up by it.
    let first = store
        .ingest_siem_features(
            SOURCE,
            1,
            &batch(START + 50_000, good.clone()),
            START + 50_000,
        )
        .unwrap();
    assert_eq!(first.status, IngestStatus::Accepted);
    let second = store
        .ingest_siem_features(
            SOURCE,
            1,
            &batch(START + 55_000, good.clone()),
            START + 55_000,
        )
        .unwrap();
    assert_eq!(second.status, IngestStatus::RateLimited);
    let other = store
        .ingest_siem_features(
            "spiffe://example.org/ns/siem/sa/other",
            1,
            &batch(START + 55_000, good.clone()),
            START + 55_000,
        )
        .unwrap();
    assert_eq!(other.status, IngestStatus::Accepted);
    let later = store
        .ingest_siem_features(SOURCE, 1, &batch(START + 60_000, good), START + 60_000)
        .unwrap();
    assert_eq!(later.status, IngestStatus::Accepted);
}

#[test]
fn a_value_lives_for_twice_the_window_and_a_late_older_batch_does_not_replace_a_newer_one() {
    let store = store_with(Some(RuleMode::Enforce), None);
    // generated at START - 1 s, window 300 s: fresh for 600 s from then.
    ingest(
        &store,
        START,
        json!([{"kind": "sandbox", "id": SANDBOX, "features": {"openshell_denials_5m": 12}}]),
    );
    assert_eq!(
        store
            .context_features_for(SANDBOX, START + 500_000)
            .unwrap()
            .as_slice()
            .len(),
        1
    );
    assert!(
        store
            .context_features_for(SANDBOX, START + 600_000)
            .unwrap()
            .is_empty(),
        "expired at generated + 2 x window"
    );

    // A batch generated earlier than the stored value arrives later: the newer value stays.
    let newer = batch(
        START + 100_000,
        json!([{"kind": "sandbox", "id": SANDBOX, "features": {"openshell_denials_5m": 7}}]),
    );
    store
        .ingest_siem_features(SOURCE, 1, &newer, START + 100_000)
        .unwrap();
    let older = batch(
        START + 50_000,
        json!([{"kind": "sandbox", "id": SANDBOX, "features": {"openshell_denials_5m": 1}}]),
    );
    let result = store
        .ingest_siem_features(SOURCE, 1, &older, START + 120_000)
        .unwrap();
    assert_eq!(result.reasons.get("older_than_stored_value"), Some(&1));
    let features = store
        .context_features_for(SANDBOX, START + 120_000)
        .unwrap();
    assert_eq!(
        features.get(FeatureScope::Sandbox, "openshell_denials_5m"),
        Some(7)
    );
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Resolution.
// ---------------------------------------------------------------------------------------------------------------------------------------

#[test]
fn sandbox_and_spiffe_subjects_resolve_to_their_workload_and_the_rest_are_stored_by_sandbox_and_counted()
 {
    let dir = tempfile::tempdir().unwrap();
    let store = seed_fixture_store(dir.path().join("rg.db"))
        .unwrap()
        .with_sandbox_spiffe_trust_domain("example.org");
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline).unwrap();
    store.register_agent(AGENT, "Feature agent").unwrap();
    bind(&store, AGENT, SANDBOX, "run-f1", START - 60_000);

    let result = ingest(
        &store,
        START,
        json!([
            {"kind": "sandbox", "id": SANDBOX, "features": {"openshell_denials_5m": 5}},
            {"kind": "spiffe", "id": format!("spiffe://example.org/openshell/sandbox/{SANDBOX}"), "features": {"openshell_denials_1h": 9}},
            {"kind": "sandbox", "id": "sbx-never-seen", "features": {"openshell_denials_5m": 2}},
            {"kind": "spiffe", "id": "spiffe://example.org/openshell/sandbox/sbx-also-unknown", "features": {"openshell_denials_5m": 2}},
            {"kind": "spiffe", "id": "spiffe://other.org/openshell/sandbox/sbx-f1", "features": {"openshell_denials_5m": 50}},
            {"kind": "spiffe", "id": "not a spiffe id", "features": {"openshell_denials_5m": 1}}
        ]),
    );
    assert_eq!(result.resolved, 2, "{result:?}");
    assert_eq!(result.unresolved, 2, "{result:?}");
    assert_eq!(result.reasons.get("spiffe_trust_domain_mismatch"), Some(&1));
    assert_eq!(result.reasons.get("invalid_spiffe_id"), Some(&1));

    let stored = store.list_siem_features().unwrap();
    let rows = stored["features"].as_array().unwrap();
    let find = |subject: &str| rows.iter().find(|r| r["subject"] == subject).unwrap();
    assert_eq!(find(SANDBOX)["agent_id"], AGENT);
    let spiffe = format!("spiffe://example.org/openshell/sandbox/{SANDBOX}");
    assert_eq!(find(&spiffe)["sandbox_id"], SANDBOX);
    assert_eq!(find(&spiffe)["agent_id"], AGENT);
    // Unresolvable: kept under the sandbox, with no workload.
    assert_eq!(find("sbx-never-seen")["sandbox_id"], "sbx-never-seen");
    assert!(find("sbx-never-seen")["agent_id"].is_null());
    // Scoring reads both the sandbox's and the SPIFFE subject's values for the sandbox.
    let features = store.context_features_for(SANDBOX, START).unwrap();
    assert_eq!(
        features.get(FeatureScope::Sandbox, "openshell_denials_5m"),
        Some(5)
    );
    assert_eq!(
        features.get(FeatureScope::Sandbox, "openshell_denials_1h"),
        Some(9)
    );
    assert!(
        store
            .context_features_for("sbx-never-seen", START)
            .unwrap()
            .get(FeatureScope::Sandbox, "openshell_denials_5m")
            == Some(2)
    );
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Rules R1 to R4, the cap, watching versus enforcing.
// ---------------------------------------------------------------------------------------------------------------------------------------

/// Score one request with `subjects` published, in a store whose `siem_context` rule is in `mode`.
fn scored(mode: Option<RuleMode>, max: Option<u32>, subjects: Option<Value>) -> RiskEvaluation {
    let store = store_with(mode, max);
    if let Some(subjects) = subjects {
        ingest(&store, START, subjects);
    }
    score(&store, "req-1", START + 1_000)
}

#[test]
fn each_rule_adds_its_documented_points_when_enforcing_and_only_when_its_condition_holds() {
    let enforce = Some(RuleMode::Enforce);
    let base = scored(enforce, None, None).risk_score;
    let added = |subjects: Value| scored(enforce, None, Some(subjects)).risk_score - base;

    // R1: 3 or more denials +4, 10 or more +8; fewer adds nothing.
    assert_eq!(added(subjects_for(2, 0, 0, 0, 0, 0)), 0);
    assert_eq!(added(subjects_for(3, 0, 0, 0, 0, 0)), 4);
    assert_eq!(added(subjects_for(9, 0, 0, 0, 0, 0)), 4);
    assert_eq!(added(subjects_for(10, 0, 0, 0, 0, 0)), 8);
    // R2: own refusals 300 or more while the fleet's are 100 or less.
    assert_eq!(added(subjects_for(0, 300, 100, 0, 0, 0)), 3);
    assert_eq!(added(subjects_for(0, 299, 100, 0, 0, 0)), 0);
    assert_eq!(added(subjects_for(0, 300, 101, 0, 0, 0)), 0);
    // R3: 3 or more new routes and half or more of the workload's routes unique to it.
    assert_eq!(added(subjects_for(0, 0, 500, 3, 500, 0)), 3);
    assert_eq!(added(subjects_for(0, 0, 500, 2, 500, 0)), 0);
    assert_eq!(added(subjects_for(0, 0, 500, 3, 499, 0)), 0);
    // R4: three or more workloads with denials and this sandbox has at least one.
    assert_eq!(added(subjects_for(1, 0, 500, 0, 0, 3)), 4);
    assert_eq!(
        added(subjects_for(0, 0, 500, 0, 0, 3)),
        0,
        "a campaign elsewhere does not tighten a sandbox with no denial"
    );
    assert_eq!(added(subjects_for(1, 0, 500, 0, 0, 2)), 0);

    // The decision explains itself.
    let eval = scored(enforce, None, Some(subjects_for(10, 0, 0, 0, 0, 0)));
    let signal = siem_signal(&eval).expect("a siem_context signal");
    assert_eq!(signal.contribution, 8);
    assert!(
        signal
            .observed_summary
            .contains("R1(+8): openshell_denials_5m=10"),
        "{}",
        signal.observed_summary
    );
    assert!(
        signal.baseline_summary.contains("added=8"),
        "{}",
        signal.baseline_summary
    );
}

#[test]
fn the_sum_is_capped_at_fifteen_by_default_and_a_profile_can_lower_or_raise_it_but_never_past_thirty()
 {
    let everything = subjects_for(12, 400, 50, 5, 800, 4); // R1 8 + R2 3 + R3 3 + R4 4 = 18
    let base = scored(Some(RuleMode::Enforce), None, None).risk_score;
    let added =
        |max| scored(Some(RuleMode::Enforce), max, Some(everything.clone())).risk_score - base;
    assert_eq!(added(None), 15, "default cap");
    assert_eq!(added(Some(10)), 10);
    assert_eq!(added(Some(0)), 0);
    assert_eq!(
        added(Some(30)),
        18,
        "the four rules together are 18, under the cap"
    );
    assert_eq!(
        added(Some(500)),
        18,
        "asking for more than 30 is held to 30"
    );
    assert_eq!(siem::effective_max(Some(500)), 30);
}

#[test]
fn watching_adds_nothing_and_records_what_it_would_have_added_while_off_leaves_no_trace() {
    let subjects = subjects_for(12, 400, 50, 5, 800, 4);
    let none = scored(None, None, None);
    // Default mode: no mode set in the profile, so shadow.
    let watching = scored(None, None, Some(subjects.clone()));
    assert_eq!(watching.risk_score, none.risk_score);
    assert_eq!(watching.outcome, none.outcome);
    let signal = siem_signal(&watching).expect("watching still records");
    assert_eq!(signal.contribution, 0);
    assert!(
        signal.baseline_summary.contains("mode=shadow"),
        "{}",
        signal.baseline_summary
    );
    assert!(
        signal.baseline_summary.contains("would_add=15"),
        "{}",
        signal.baseline_summary
    );
    assert_eq!(signal.support, "would_add");

    let off = scored(Some(RuleMode::Off), None, Some(subjects));
    assert_eq!(off.risk_score, none.risk_score);
    assert!(siem_signal(&off).is_none(), "an off rule leaves no trace");
}

#[test]
fn missing_stale_or_unrelated_features_leave_a_decision_exactly_as_it_was() {
    let plain = scored(Some(RuleMode::Enforce), None, None);
    assert!(siem_signal(&plain).is_none());

    // Features that exist but have expired by the time of the decision.
    let store = store_with(Some(RuleMode::Enforce), None);
    ingest(&store, START, subjects_for(12, 400, 50, 5, 800, 4));
    let late = score(&store, "req-late", START + 10 * 60_000);
    assert_eq!(late, with_request_id(&plain, "req-late", &late));

    // Features for another sandbox and workload.
    let store = store_with(Some(RuleMode::Enforce), None);
    ingest(
        &store,
        START,
        json!([
            {"kind": "sandbox", "id": "sbx-someone-else", "features": {"openshell_denials_5m": 50}},
            {"kind": "workload", "id": "agent-someone-else", "features": {"refusal_ratio_15m_permille": 900}}
        ]),
    );
    let other = score(&store, "req-other", START + 1_000);
    assert_eq!(other.risk_score, plain.risk_score);
    assert!(siem_signal(&other).is_none());

    // R2 needs both ratios and R4 needs both counts: half the evidence adds nothing.
    let store = store_with(Some(RuleMode::Enforce), None);
    ingest(
        &store,
        START,
        json!([{"kind": "workload", "id": AGENT, "features": {"refusal_ratio_15m_permille": 900}}]),
    );
    assert_eq!(
        score(&store, "req-half", START + 1_000).risk_score,
        plain.risk_score
    );
}

/// `plain` with the request id of `like`, so two decisions of the same shape can be compared whole.
fn with_request_id(plain: &RiskEvaluation, id: &str, like: &RiskEvaluation) -> RiskEvaluation {
    let mut copy = plain.clone();
    copy.request_id = id.to_string();
    copy.state_sequence = like.state_sequence;
    copy.decision_timestamp_ms = like.decision_timestamp_ms;
    copy
}

#[test]
fn a_decision_without_features_carries_nothing_new() {
    let eval = scored(None, None, None);
    assert!(eval.signals.iter().all(|s| s.feature != "siem_context"));
    assert_eq!(eval.detector_version, "interaction-v2");
    let json = serde_json::to_string(&eval).unwrap();
    assert!(!json.contains("siem"), "{json}");
}

#[test]
fn enough_points_move_a_decision_across_the_observe_threshold_and_the_controls_row_counts_it() {
    // A request that scores 0 plus 15 stays under the observe threshold (20); push the base up with a destructive call that is itself allowed in observe.
    let store = store_with(None, None);
    assert!(
        store.controls_overview(START).unwrap()["controls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "siem_context"
                && c["data"]["note"]
                    .as_str()
                    .unwrap()
                    .contains("no features received"))
    );

    ingest(&store, START, subjects_for(12, 400, 50, 5, 800, 4));
    // A request with a base score of 15 + 15: an unfamiliar-but-not-high-impact read of a new resource; see its score first.
    let eval = store
        .evaluate_authenticated(
            &request("req-novel", "GET", "never-seen-before", START + 1_000),
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
        )
        .unwrap();
    let signal = siem_signal(&eval).expect("signal while watching");
    assert_eq!(signal.contribution, 0);

    let view = store.controls_overview(START + 2_000).unwrap();
    let row = view["controls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "siem_context")
        .unwrap();
    assert_eq!(row["name"], "SIEM context (risk features)");
    assert_eq!(row["mode"], "watching");
    assert!(row["evidence"]["fresh_features"].as_i64().unwrap() >= 6);
    assert_eq!(row["evidence"]["scored_with_points_while_watching_24h"], 1);
    assert!(row["evidence"]["newest_batch_age_seconds"].is_number());
    assert!(
        !row["data"]["note"]
            .as_str()
            .unwrap()
            .contains("no features received")
    );
    let would = signal.baseline_summary.contains("changes_outcome=1");
    assert_eq!(row["evidence"]["would_have_changed_24h"], i64::from(would));
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Tighten only: features never lower any score or outcome.
// ---------------------------------------------------------------------------------------------------------------------------------------

fn rank(outcome: DecisionOutcome) -> u8 {
    match outcome {
        DecisionOutcome::Allow => 0,
        DecisionOutcome::AllowWithObservation => 1,
        DecisionOutcome::Deny => 2,
    }
}

/// A small deterministic generator, so the property test is repeatable.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, below: u32) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as u32) % below.max(1)
    }
}

#[test]
fn features_never_lower_a_score_or_an_outcome_whatever_the_mode_the_baseline_the_request_or_the_features()
 {
    let corpus = build_standard_corpus();
    let normalizer = CanonicalNormalizer::new_default(HMAC_KEY);
    let mut rng = Lcg(0x5eed_f00d);
    let mut moved_up = 0u32;
    for case in 0..1_500u32 {
        let mut baseline = corpus.default_baseline.clone();
        baseline.normalizer_version =
            openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
        let mode = [RuleMode::Off, RuleMode::Shadow, RuleMode::Enforce][rng.next(3) as usize];
        baseline.rule_modes.insert(RULE_SIEM_CONTEXT.into(), mode);
        baseline.siem_context_max_points =
            [None, Some(0), Some(5), Some(15), Some(30), Some(1_000)][rng.next(6) as usize];
        if rng.next(2) == 0 {
            baseline.training_sessions = 0; // an immature baseline never denies on novelty alone
        }
        let epoch_mode = if rng.next(2) == 0 {
            EnforcementMode::Enforce
        } else {
            EnforcementMode::Observe
        };
        let epoch = EpochRecord {
            epoch_id: "e".into(),
            gateway_id: "g".into(),
            sandbox_id: "s".into(),
            task_profile: baseline.task_profile.clone(),
            baseline_hash: compute_baseline_hash(&baseline),
            mode: epoch_mode,
            active: true,
            next_sequence: 1,
            created_at_ms: START,
            credentialed_endpoints: Default::default(),
            active_policy_hash: None,
        };
        let method = ["GET", "POST", "DELETE"][rng.next(3) as usize];
        let resource = ["docs-site", "payments-prod", "never-seen"][rng.next(3) as usize];
        let normalized = normalizer
            .normalize(&RawRequestInput {
                request_id: format!("p-{case}"),
                sandbox_id: "s".into(),
                sandbox_name: "s".into(),
                workspace: "default".into(),
                scheme: "https".into(),
                host: "api.github.local".into(),
                port: 18443,
                method: method.into(),
                path: format!("/repos/org/{resource}"),
                binary_path: [
                    Some("/usr/bin/curl".to_string()),
                    Some("/usr/bin/python3".to_string()),
                    None,
                ][rng.next(3) as usize]
                    .clone(),
                pid: None,
                ancestors: vec![],
                timestamp_ms: START,
            })
            .unwrap();
        let window = WindowSnapshot {
            req_count_1m: rng.next(40),
            req_count_15m: rng.next(200),
            distinct_resources_1m: rng.next(5),
            distinct_resources_15m: rng.next(30),
            warming: rng.next(5) == 0,
        };
        let credentialed_endpoint = rng.next(2) == 0;
        let mut items: Vec<ContextFeature> = Vec::new();
        for (name, scope, range) in VOCABULARY.iter() {
            if rng.next(3) == 0 {
                continue;
            }
            let value = if rng.next(4) == 0 {
                range.max()
            } else {
                rng.next(range.max().min(40) + 1) * (range.max() / 40).max(1) % (range.max() + 1)
            };
            items.push(ContextFeature {
                scope: *scope,
                name: (*name).to_string(),
                value,
                subject: "x".into(),
                age_ms: 0,
            });
        }
        let detector = InteractionRiskDetector::new_default();
        let without = detector
            .evaluate(
                &normalized,
                &DetectorContext {
                    epoch: &epoch,
                    baseline: &baseline,
                    window: &window,
                    credentialed_endpoint,
                    features: ContextFeatures::default(),
                },
            )
            .unwrap();
        let with = detector
            .evaluate(
                &normalized,
                &DetectorContext {
                    epoch: &epoch,
                    baseline: &baseline,
                    window: &window,
                    credentialed_endpoint,
                    features: ContextFeatures::new(items),
                },
            )
            .unwrap();
        assert!(
            with.risk_score >= without.risk_score,
            "case {case}: {} < {}",
            with.risk_score,
            without.risk_score
        );
        assert!(
            rank(with.outcome) >= rank(without.outcome),
            "case {case}: {:?} < {:?}",
            with.outcome,
            without.outcome
        );
        if mode != RuleMode::Enforce {
            assert_eq!(
                with.risk_score, without.risk_score,
                "case {case}: only an enforcing rule changes a score"
            );
            assert_eq!(with.outcome, without.outcome, "case {case}");
        }
        // The only extra thing is the siem_context signal; nothing else about the decision differs, and the points are within the cap.
        let extra: Vec<&SignalContribution> = with
            .signals
            .iter()
            .filter(|s| s.feature == "siem_context")
            .collect();
        assert!(extra.len() <= 1);
        assert!(with.risk_score - without.risk_score <= 30);
        moved_up += u32::from(with.risk_score > without.risk_score);
    }
    assert!(
        moved_up > 50,
        "the generator should exercise the rules ({moved_up} cases moved)"
    );
}

// ---------------------------------------------------------------------------------------------------------------------------------------
// Recording and replay.
// ---------------------------------------------------------------------------------------------------------------------------------------

#[test]
fn a_decision_made_with_features_records_them_and_replays_identically_and_without_them_it_would_not()
 {
    let store = store_with(Some(RuleMode::Enforce), None);
    let before = score(&store, "r-before", START + 1_000);
    ingest(&store, START + 2_000, subjects_for(12, 400, 50, 5, 800, 4));
    let during_a = score(&store, "r-during-a", START + 3_000);
    let during_b = store
        .evaluate_authenticated(
            &request("r-during-b", "DELETE", "payments-prod", START + 4_000),
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
        )
        .unwrap();
    let after = score(&store, "r-after", START + 20 * 60_000);
    assert_eq!(
        during_a.risk_score,
        before.risk_score + 15,
        "the capped sum was added"
    );
    assert!(
        after.signals.iter().all(|s| s.feature != "siem_context"),
        "expired by then"
    );

    let bundle = store.export_replay_bundle(AGENT, None).unwrap();
    assert!(bundle.history.complete, "{:?}", bundle.history.problems);
    let carried: Vec<usize> = bundle
        .events
        .iter()
        .filter_map(|e| match e {
            openshell_risk_guard::replay::ReplayEvent::Decision { features, .. } => {
                Some(features.len())
            }
            _ => None,
        })
        .collect();
    assert_eq!(carried.len(), 4);
    assert_eq!(carried[0], 0, "a decision without features carries none");
    assert!(
        carried[1] >= 6 && carried[2] >= 6,
        "the two decisions with features carry them: {carried:?}"
    );
    assert_eq!(carried[3], 0);
    let recorded_names: Vec<String> = match &bundle.events[1] {
        openshell_risk_guard::replay::ReplayEvent::Decision { features, .. } => {
            features.iter().map(|f| f.name.clone()).collect()
        }
        _ => unreachable!(),
    };
    assert!(recorded_names.contains(&"openshell_denials_5m".to_string()));

    // Replayed from nothing, every decision comes out the same, including the ones the features changed.
    let report = replay(&bundle, false).unwrap();
    assert!(report.reproduced, "{:?}", report.divergences);
    assert_eq!(report.decisions, 4);
    assert_eq!(report.matched, 4);
    assert!(during_b.risk_score >= 15);

    // Take the features out of the bundle (and reseal it): the replay now disagrees, which shows the recorded features are what it used.
    let mut stripped = bundle.clone();
    for event in &mut stripped.events {
        if let openshell_risk_guard::replay::ReplayEvent::Decision { features, .. } = event {
            features.clear();
        }
    }
    let stripped = stripped.seal().unwrap();
    let report = replay(&stripped, false).unwrap();
    assert!(!report.reproduced);
    assert!(report.divergences.iter().any(|d| d.field == "risk_score"));
}

#[test]
fn a_bundle_recorded_without_any_features_still_replays_and_looks_as_it_did_before() {
    let store = store_with(None, None);
    for n in 0..4 {
        score(&store, &format!("plain-{n}"), START + 1_000 * (n + 1));
    }
    let bundle = store.export_replay_bundle(AGENT, None).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    assert!(
        !json.contains("\"features\""),
        "no features key appears when none were used"
    );
    let report = replay(&bundle, false).unwrap();
    assert!(report.reproduced, "{:?}", report.divergences);
    assert_eq!(report.matched, 4);

    // An older bundle has no `features` key at all in its decisions; it reads back as no features.
    let mut value: Value = serde_json::to_value(&bundle).unwrap();
    for event in value["events"].as_array_mut().unwrap() {
        if event["type"] == "decision" {
            event.as_object_mut().unwrap().remove("features");
        }
    }
    let parsed: openshell_risk_guard::replay::ReplayBundle = serde_json::from_value(value).unwrap();
    assert_eq!(
        parsed.compute_hash().unwrap(),
        bundle.content_hash,
        "same bytes, same hash"
    );
}

#[test]
fn the_detector_version_and_configuration_hash_changed_on_purpose() {
    let detector = InteractionRiskDetector::new_default();
    assert_eq!(detector.detector_version(), "interaction-v2");
    // The v1 configuration was the hash of "interaction-v1:20:70:300000:full_contextual"; this build's differs.
    use sha2::{Digest, Sha256};
    let v1 = hex::encode(Sha256::digest(
        b"interaction-v1:20:70:300000:full_contextual",
    ));
    assert_ne!(detector.configuration_id(), v1);
}
