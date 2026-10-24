// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The feature publisher against a fake OpenSearch (plain HTTP, canned answers) and a fake Risk Guard (a real mutual-TLS listener that records the verified SPIFFE ID and the body).

use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use openshell_risk_guard::feature_publisher::{
    Counters, OpenSearchAccess, PublisherConfig, run, tick,
};
use openshell_risk_guard::spiffe::spiffe_id_from_certificate;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::{Value, json};
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

const FORWARDER_ID: &str = "spiffe://example.org/ns/siem/sa/signal-forwarder";
const NOW: i64 = 1_792_800_000_000;
type Peer = TlsConnectInfo<TcpConnectInfo>;

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---- fake Risk Guard -----------------------------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct RiskGuard {
    /// (verified SPIFFE ID, body)
    received: Arc<Mutex<Vec<(String, Value)>>>,
    /// The status to answer with.
    status: Arc<AtomicU16>,
}

async fn post_features(
    State(state): State<RiskGuard>,
    peer: Option<Extension<Peer>>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<Value>) {
    let identity = peer
        .and_then(|Extension(peer)| {
            peer.peer_certs().and_then(|certs| {
                certs
                    .first()
                    .map(|leaf| spiffe_id_from_certificate(leaf.as_ref()))
            })
        })
        .and_then(std::result::Result::ok)
        .map_or_else(|| "none".to_string(), |id| id.uri());
    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    state.received.lock().unwrap().push((identity, value));
    let status = StatusCode::from_u16(state.status.load(Ordering::SeqCst)).unwrap();
    (status, Json(json!({"accepted": 1})))
}

struct Setup {
    config: PublisherConfig,
    risk_guard: RiskGuard,
    opensearch: Opensearch,
    _dir: tempfile::TempDir,
}

/// `risk_guard_up = false` leaves Risk Guard's port dead.
async fn start(risk_guard_up: bool) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let authority = Authority::new();
    let bundle = dir.path().join("bundle.crt");
    std::fs::write(&bundle, authority.cert.pem()).unwrap();
    let (svid, svid_key) = authority.svid(FORWARDER_ID);
    // spiffe-helper's files need not end in a newline.
    std::fs::write(dir.path().join("svid.pem"), svid.trim_end()).unwrap();
    std::fs::write(dir.path().join("svid_key.pem"), svid_key).unwrap();
    std::fs::write(dir.path().join("user"), "rg-publisher\n").unwrap();
    std::fs::write(dir.path().join("password"), "not-a-real-password\n").unwrap();

    let risk_guard = RiskGuard::default();
    risk_guard.status.store(200, Ordering::SeqCst);
    let port = free_port();
    if risk_guard_up {
        let (cert, key) = authority.server();
        let tls = tonic::transport::ServerTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(cert, key))
            .client_ca_root(tonic::transport::Certificate::from_pem(
                authority.cert.pem(),
            ))
            .client_auth_optional(false);
        let routes = tonic::service::Routes::from(
            Router::new()
                .route("/features", post(post_features))
                .with_state(risk_guard.clone()),
        );
        let address = format!("127.0.0.1:{port}").parse().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .accept_http1(true)
                .tls_config(tls)
                .unwrap()
                .add_routes(routes)
                .serve(address)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let opensearch = Opensearch::start().await;
    let config = PublisherConfig {
        // "localhost" is on the server certificate.
        target: format!("https://localhost:{port}/features"),
        svid_cert: dir.path().join("svid.pem"),
        svid_key: dir.path().join("svid_key.pem"),
        server_ca: {
            let ca = dir.path().join("ca.crt");
            std::fs::write(&ca, authority.cert.pem()).unwrap();
            ca
        },
        opensearch: OpenSearchAccess {
            url: opensearch.url.clone(),
            user_file: dir.path().join("user"),
            password_file: dir.path().join("password"),
            ca_file: None,
            insecure: false,
        },
        trust_domain: Some("example.org".into()),
        trust_domain_from_svid: false,
        interval: Duration::from_millis(200),
    };
    Setup {
        config,
        risk_guard,
        opensearch,
        _dir: dir,
    }
}

// ---- fake OpenSearch -----------------------------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Opensearch_ {
    /// Answer every search with a 503.
    down: Arc<AtomicBool>,
    /// Answer only the per-workload refusal search with a 503.
    fail_refusals: Arc<AtomicBool>,
    auth_seen: Arc<Mutex<Vec<String>>>,
}

struct Opensearch {
    url: String,
    state: Opensearch_,
}

async fn search(
    State(state): State<Opensearch_>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state.auth_seen.lock().unwrap().push(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string(),
    );
    if state.down.load(Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "down"})),
        );
    }
    let aggs = &body["aggs"];
    let answer = if aggs["by_workload"].is_object() {
        if state.fail_refusals.load(Ordering::SeqCst) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "down"})),
            );
        }
        json!({"aggregations": {
            "by_workload": {"sum_other_doc_count": 0, "buckets": [
                {"key": "agent-a", "refused": {"value": 21.0}, "total": {"value": 50.0}},
                {"key": "agent-b", "refused": {"value": 0.0}, "total": {"value": 10.0}}]},
            "fleet_refused": {"value": 21.0}, "fleet_total": {"value": 60.0},
            "active": {"workloads": {"value": 2.0}}}})
    } else if aggs["pairs"].is_object() {
        let t = NOW as f64;
        let bucket = |workload: &str, route: &str, first: f64| json!({"key": {"workload": workload, "host": "api.local", "route": route}, "first": {"value": first}, "last": {"value": t}});
        json!({"aggregations": {"pairs": {"buckets": [
            bucket("agent-a", "/old", t - 3.0 * 86_400_000.0),
            bucket("agent-a", "/new", t - 600_000.0),
            bucket("agent-b", "/old", t - 3.0 * 86_400_000.0)]}}})
    } else if aggs["sandboxes"].is_object() {
        json!({"hits": {"total": {"value": 5, "relation": "eq"}}, "aggregations": {"sandboxes": {"value": 2.0}}})
    } else if aggs["by_sandbox"]["aggs"]["last_5m"].is_object() {
        json!({"aggregations": {"by_sandbox": {"sum_other_doc_count": 0, "buckets": [
            {"key": "sbx-1", "doc_count": 7, "last_5m": {"doc_count": 4}},
            {"key": "sbx-2", "doc_count": 2, "last_5m": {"doc_count": 1}}]}}})
    } else {
        json!({"aggregations": {"by_sandbox": {"buckets": [{"key": "sbx-1", "doc_count": 2}]}}})
    };
    (StatusCode::OK, Json(answer))
}

impl Opensearch {
    async fn start() -> Self {
        let state = Opensearch_::default();
        let app = Router::new()
            .route("/ocsf-openshell*/_search", post(search))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, state }
    }
}

fn expected_body(generated_at: i64, with_refusals: bool) -> Value {
    let mut fleet = json!({"fleet_openshell_denials_5m": 5, "fleet_workloads_with_denials_5m": 2});
    let mut agent_a = json!({"new_routes_1h": 1, "routes_unique_to_workload_permille": 500});
    let mut agent_b = json!({"new_routes_1h": 0, "routes_unique_to_workload_permille": 0});
    if with_refusals {
        fleet["fleet_refusal_ratio_15m_permille"] = json!(350);
        fleet["fleet_active_workloads_15m"] = json!(2);
        agent_a["refusal_ratio_15m_permille"] = json!(420);
        agent_b["refusal_ratio_15m_permille"] = json!(0);
    }
    let sandbox_1 = json!({"openshell_denials_1h": 7, "openshell_denials_5m": 4, "openshell_would_block_5m": 2});
    let sandbox_2 = json!({"openshell_denials_1h": 2, "openshell_denials_5m": 1});
    // Busiest first (the order is by the sum of a subject's values, then by the maps' order); the fleet subject is last.
    let mut subjects = vec![
        json!({"kind": "sandbox", "id": "sbx-1", "features": sandbox_1}),
        json!({"kind": "spiffe", "id": "spiffe://example.org/openshell/sandbox/sbx-1", "features": sandbox_1}),
    ];
    let mut workloads = vec![(
        if with_refusals { 421 } else { 501 },
        json!({"kind": "workload", "id": "agent-a", "features": agent_a}),
    )];
    // agent-b has an all-zero set of features except nothing non-zero: not sent.
    let _ = agent_b;
    subjects.extend([
        json!({"kind": "sandbox", "id": "sbx-2", "features": sandbox_2}),
        json!({"kind": "spiffe", "id": "spiffe://example.org/openshell/sandbox/sbx-2", "features": sandbox_2}),
    ]);
    subjects.extend(workloads.drain(..).map(|(_, subject)| subject));
    subjects.push(json!({"kind": "fleet", "id": "fleet", "features": fleet}));
    json!({"schema": 1, "generated_at_ms": generated_at, "window_seconds": 300, "subjects": subjects})
}

/// Subjects compared as sets (their order is the publisher's business), everything else exactly.
fn same_batch(actual: &Value, expected: &Value) -> bool {
    let sorted = |value: &Value| {
        let mut subjects: Vec<String> = value["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::to_string)
            .collect();
        subjects.sort();
        subjects
    };
    let mut a = actual.clone();
    let mut e = expected.clone();
    a["subjects"] = json!([]);
    e["subjects"] = json!([]);
    a == e && sorted(actual) == sorted(expected)
}

#[tokio::test]
async fn one_tick_posts_the_exact_batch_as_the_forwarders_own_identity() {
    let setup = start(true).await;
    let mut counters = Counters::default();
    tick(&setup.config, &mut counters, NOW).await;

    assert_eq!(counters.batches_accepted, 1, "{counters:?}");
    let received = setup.risk_guard.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    let (identity, body) = &received[0];
    assert_eq!(
        identity, FORWARDER_ID,
        "Risk Guard saw the SVID's SPIFFE ID"
    );
    let expected = expected_body(NOW, true);
    assert!(
        same_batch(body, &expected),
        "\nactual:   {body}\nexpected: {expected}"
    );
    // The OpenSearch credentials from the mounted files were used, with the trailing newline stripped.
    let auth = setup.opensearch.state.auth_seen.lock().unwrap().clone();
    assert!(auth.iter().all(|a| a.starts_with("Basic ")), "{auth:?}");
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth[0].trim_start_matches("Basic "))
        .unwrap();
    assert_eq!(decoded, b"rg-publisher:not-a-real-password");
}

#[tokio::test]
async fn a_refusal_is_not_retried_and_the_next_interval_sends_fresh_values_without_a_backlog() {
    let setup = start(true).await;
    let mut counters = Counters::default();
    setup.risk_guard.status.store(429, Ordering::SeqCst);
    tick(&setup.config, &mut counters, NOW).await;
    assert_eq!(
        (
            counters.batches_refused,
            counters.batches_rate_limited,
            counters.batches_accepted
        ),
        (1, 1, 0)
    );
    assert_eq!(
        setup.risk_guard.received.lock().unwrap().len(),
        1,
        "one attempt per interval, no retry loop"
    );

    setup.risk_guard.status.store(200, Ordering::SeqCst);
    tick(&setup.config, &mut counters, NOW + 30_000).await;
    assert_eq!(counters.batches_accepted, 1);
    let received = setup.risk_guard.received.lock().unwrap().clone();
    assert_eq!(received.len(), 2);
    // The second body is the second interval's own batch: same subjects as one batch, the new time, nothing carried over from the refused one.
    assert!(same_batch(
        &received[1].1,
        &expected_body(NOW + 30_000, true)
    ));
    assert_eq!(
        received[1].1["subjects"].as_array().unwrap().len(),
        received[0].1["subjects"].as_array().unwrap().len()
    );
}

#[tokio::test]
async fn one_failed_query_omits_only_its_features_and_a_dead_opensearch_sends_nothing() {
    let setup = start(true).await;
    let mut counters = Counters::default();
    setup
        .opensearch
        .state
        .fail_refusals
        .store(true, Ordering::SeqCst);
    tick(&setup.config, &mut counters, NOW).await;
    assert_eq!((counters.query_failures, counters.batches_accepted), (1, 1));
    let body = setup.risk_guard.received.lock().unwrap()[0].1.clone();
    assert!(same_batch(&body, &expected_body(NOW, false)), "{body}");
    let text = body.to_string();
    assert!(
        !text.contains("refusal_ratio") && !text.contains("fleet_active"),
        "no refusal feature is invented: {text}"
    );

    setup.opensearch.state.down.store(true, Ordering::SeqCst);
    tick(&setup.config, &mut counters, NOW + 30_000).await;
    assert_eq!(counters.ticks_without_batch, 1);
    assert_eq!(
        setup.risk_guard.received.lock().unwrap().len(),
        1,
        "nothing was learned, so nothing was sent"
    );
}

#[tokio::test]
async fn the_loop_survives_opensearch_going_away_and_coming_back() {
    let setup = start(true).await;
    setup.opensearch.state.down.store(true, Ordering::SeqCst);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(run(setup.config.clone(), async {
        let _ = stopped.await;
    }));
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !handle.is_finished(),
        "the loop keeps running while OpenSearch is down"
    );
    assert!(setup.risk_guard.received.lock().unwrap().is_empty());
    setup.opensearch.state.down.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !setup.risk_guard.received.lock().unwrap().is_empty(),
        "batches resume when OpenSearch is back"
    );
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn an_unreachable_risk_guard_is_counted_and_does_not_stop_anything() {
    let setup = start(false).await;
    let mut counters = Counters::default();
    tick(&setup.config, &mut counters, NOW).await;
    tick(&setup.config, &mut counters, NOW + 30_000).await;
    assert_eq!(
        (
            counters.ticks,
            counters.risk_guard_unreachable,
            counters.batches_accepted
        ),
        (2, 2, 0)
    );
}
