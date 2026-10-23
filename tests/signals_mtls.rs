// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Signals over mutual TLS: the sender is the SPIFFE ID in its certificate, nothing it sends can change that, and no shared secret exists.

use std::sync::Arc;

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::signals::{SignalsState, serve_mtls};
use openshell_risk_guard::store::{SignalPolicy, SqliteRiskStore};
use openshell_risk_guard::types::RiskStore;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

const DOMAIN: &str = "example.org";
const SENDER: &str = "spiffe://example.org/ns/siem/sa/signal-forwarder";

/// A stand-in for a SPIRE server.
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
    let mut baseline = build_standard_corpus().default_baseline;
    baseline.normalizer_version =
        openshell_risk_guard::normalizer::DEFAULT_NORMALIZER_VERSION.into();
    store.store_baseline(&baseline).unwrap();
    store.register_agent("agent-a", "Agent A").unwrap();
    let authority = Authority::new();
    let bundle = dir.path().join("bundle.crt");
    std::fs::write(&bundle, authority.cert.pem()).unwrap();
    let (cert, key) = authority.server();
    let state = SignalsState::new_spiffe(
        Arc::clone(&store),
        &[DOMAIN.to_string()],
        [SENDER],
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

fn body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "signal_id": id, "source": "someone-pretending", "agent_id": "agent-a",
        "action": "quarantine", "ttl_seconds": 120, "reason": "test", "dry_run": true
    })
}

#[tokio::test]
async fn the_allowed_spiffe_identity_sends_and_is_recorded_as_the_sender_whatever_the_body_claims()
{
    let running = start().await;
    let http = client(&running, Some(running.authority.svid(SENDER)));
    let url = format!("https://localhost:{}/v1/signals", running.port);
    let reply = http.post(&url).json(&body("s-1")).send().await.unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(
        reply.json::<serde_json::Value>().await.unwrap()["outcome"],
        "dry_run"
    );
    // The source is the certificate's ID, not the "someone-pretending" the body asked for.
    let listed = running.store.list_signals(5).unwrap();
    assert_eq!(listed["signals"][0]["source"], SENDER);
    // And the sender can read the list.
    assert_eq!(http.get(&url).send().await.unwrap().status(), 200);
}

#[tokio::test]
async fn a_valid_identity_that_is_not_on_the_list_or_in_another_trust_domain_is_refused() {
    let running = start().await;
    let url = format!("https://localhost:{}/v1/signals", running.port);
    for other in [
        "spiffe://example.org/ns/siem/sa/someone-else",
        "spiffe://example.org/ns/openshell/sa/risk-guard",
        "spiffe://elsewhere.org/ns/siem/sa/signal-forwarder",
    ] {
        let http = client(&running, Some(running.authority.svid(other)));
        let status = http
            .post(&url)
            .json(&body("s-2"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 403, "{other}");
    }
    assert!(
        running.store.list_signals(5).unwrap()["signals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn no_certificate_or_one_from_an_untrusted_authority_never_gets_a_reply() {
    let running = start().await;
    let url = format!("https://localhost:{}/v1/signals", running.port);
    // No client certificate at all: the handshake fails, so there is no HTTP answer to read.
    assert!(
        client(&running, None)
            .post(&url)
            .json(&body("s-3"))
            .send()
            .await
            .is_err()
    );
    // A certificate for the right ID, signed by an authority the bundle does not contain.
    let rogue = Authority::new();
    let http = client(&running, Some(rogue.svid(SENDER)));
    assert!(http.post(&url).json(&body("s-4")).send().await.is_err());
    assert!(
        running.store.list_signals(5).unwrap()["signals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_state_needs_at_least_one_sender_and_a_real_spiffe_id() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(seed_fixture_store(dir.path().join("rg.db")).unwrap());
    let none: [&str; 0] = [];
    assert!(
        SignalsState::new_spiffe(
            Arc::clone(&store),
            &[DOMAIN.to_string()],
            none,
            SignalPolicy::default()
        )
        .is_err()
    );
    assert!(
        SignalsState::new_spiffe(
            Arc::clone(&store),
            &[DOMAIN.to_string()],
            ["not-a-spiffe-id"],
            SignalPolicy::default()
        )
        .is_err()
    );
}
