// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The SIEM-side forwarder: it takes the alert webhook and speaks to Risk Guard as its own SPIFFE identity. Nothing but a quarantine signal gets through.

use std::sync::Arc;

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::signal_forwarder::{ForwarderConfig, router};
use openshell_risk_guard::signals::{SignalsState, serve_mtls};
use openshell_risk_guard::store::{SignalPolicy, SqliteRiskStore};
use openshell_risk_guard::types::RiskStore;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

const DOMAIN: &str = "example.org";
const FORWARDER_ID: &str = "spiffe://example.org/ns/siem/sa/signal-forwarder";
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

struct Setup {
    forwarder: String,
    store: Arc<SqliteRiskStore>,
    _dir: tempfile::TempDir,
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

/// Risk Guard's mTLS signals listener (accepting only the forwarder's ID) with the forwarder in front of it. `risk_guard_up = false` leaves the target dead.
async fn start(risk_guard_up: bool) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(seed_fixture_store(dir.path().join("rg.db")).unwrap());
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline).unwrap();
    store.register_agent("agent-a", "Agent A").unwrap();

    let authority = Authority::new();
    let bundle = dir.path().join("bundle.crt");
    std::fs::write(&bundle, authority.cert.pem()).unwrap();
    let ca_file = dir.path().join("ca.crt");
    std::fs::write(&ca_file, authority.cert.pem()).unwrap();
    let (svid, svid_key) = authority.svid(FORWARDER_ID);
    std::fs::write(dir.path().join("svid.pem"), svid).unwrap();
    std::fs::write(dir.path().join("svid_key.pem"), svid_key).unwrap();

    let rg_port = free_port();
    if risk_guard_up {
        let (cert, key) = authority.server();
        let state = SignalsState::new_spiffe(
            Arc::clone(&store),
            &[DOMAIN.to_string()],
            [FORWARDER_ID],
            SignalPolicy::default(),
        )
        .unwrap();
        tokio::spawn(async move {
            serve_mtls(
                format!("127.0.0.1:{rg_port}").parse().unwrap(),
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
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let app = router(
        ForwarderConfig {
            // "localhost" is on the server certificate; the test resolves it to loopback by using that name.
            target: format!("https://localhost:{rg_port}/v1/signals"),
            svid_cert: dir.path().join("svid.pem"),
            svid_key: dir.path().join("svid_key.pem"),
            server_ca: ca_file,
        },
        TOKEN,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forwarder = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Setup {
        forwarder,
        store,
        _dir: dir,
    }
}

fn signal(id: &str) -> serde_json::Value {
    serde_json::json!({"signal_id": id, "source": "opensearch-alerting", "agent_id": "agent-a", "action": "quarantine", "ttl_seconds": 120, "reason": "test", "dry_run": true})
}

async fn post(
    setup: &Setup,
    token: Option<&str>,
    body: &serde_json::Value,
) -> (u16, serde_json::Value) {
    let mut request = reqwest::Client::new()
        .post(format!("{}/webhook", setup.forwarder))
        .json(body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let reply = request.send().await.unwrap();
    let status = reply.status().as_u16();
    (status, reply.json().await.unwrap_or_default())
}

#[tokio::test]
async fn an_alert_becomes_a_signal_from_the_forwarders_own_identity() {
    let setup = start(true).await;
    let (status, body) = post(&setup, Some(TOKEN), &signal("fw-1")).await;
    assert_eq!(
        (status, body["outcome"].as_str()),
        (200, Some("dry_run")),
        "{body}"
    );
    // Risk Guard recorded the sender as the forwarder's SPIFFE ID, not the "opensearch-alerting" the body named.
    assert_eq!(
        setup.store.list_signals(5).unwrap()["signals"][0]["source"],
        FORWARDER_ID
    );
    // Risk Guard's own answers (here a 404 for an unknown target) are relayed, not hidden.
    let mut unknown = signal("fw-2");
    unknown["agent_id"] = "no-such-agent".into();
    let (status, body) = post(&setup, Some(TOKEN), &unknown).await;
    assert_eq!(
        (status, body["outcome"].as_str()),
        (404, Some("unknown_target"))
    );
}

#[tokio::test]
async fn nothing_but_a_quarantine_with_the_right_token_leaves_the_forwarder() {
    let setup = start(true).await;
    assert_eq!(post(&setup, None, &signal("a")).await.0, 401);
    assert_eq!(
        post(&setup, Some(&"f".repeat(64)), &signal("b")).await.0,
        401
    );
    let mut release = signal("c");
    release["action"] = "release".into();
    assert_eq!(post(&setup, Some(TOKEN), &release).await.0, 400);
    let not_json = reqwest::Client::new()
        .post(format!("{}/webhook", setup.forwarder))
        .bearer_auth(TOKEN)
        .body("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(not_json.status(), 400);
    assert!(
        setup.store.list_signals(5).unwrap()["signals"]
            .as_array()
            .unwrap()
            .is_empty(),
        "none of those reached Risk Guard"
    );
}

#[tokio::test]
async fn when_risk_guard_cannot_be_reached_the_alert_gets_a_clear_failure() {
    let setup = start(false).await;
    let (status, body) = post(&setup, Some(TOKEN), &signal("d")).await;
    assert_eq!(status, 502, "{body}");
}

#[test]
fn the_forwarder_needs_a_real_token() {
    let config = ForwarderConfig {
        target: "https://x".into(),
        svid_cert: "a".into(),
        svid_key: "b".into(),
        server_ca: "c".into(),
    };
    assert!(router(config.clone(), "short").is_err());
    assert!(router(config, &"z".repeat(64)).is_err());
}
