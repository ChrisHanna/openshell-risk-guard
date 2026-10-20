// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Standalone latency benchmark binary (`benches/eval_latency.rs`) for Gate G-06.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    Decision, HttpHeader, HttpRequestEvaluation, HttpRequestTarget, Process, RequestContext,
    SupervisorMiddlewarePhase,
};
use openshell_risk_guard::auth::JwtTestIssuer;
use openshell_risk_guard::detector::InteractionRiskDetector;
use openshell_risk_guard::fixture::build_standard_corpus;
use openshell_risk_guard::middleware_service::RiskGuardMiddlewareService;
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::{EnforcementMode, EpochRecord, RiskStore};
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

const BENCH_HMAC_KEY: &[u8] = b"openshell-risk-guard-bench-hmac-key-v1";
const BENCH_GATEWAY_ID: &str = "gw-bench-01";
const BENCH_AUDIENCE: &str = "urn:openshell:extension:middleware:risk-guard";

fn percentile_ms(sorted_samples_ms: &[f64], pct: f64) -> f64 {
    let n = sorted_samples_ms.len();
    let rank = ((pct / 100.0) * (n as f64)).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted_samples_ms[idx]
}

#[tokio::main]
async fn main() {
    let temp_db = NamedTempFile::new_in("/dev/shm")
        .or_else(|_| NamedTempFile::new())
        .expect("create on-disk NamedTempFile for SQLite");
    let store = Arc::new(
        SqliteRiskStore::open(temp_db.path()).expect("open on-disk SqliteRiskStore"),
    );

    let corpus = build_standard_corpus();
    let baseline = corpus.default_baseline.clone();
    let baseline_hash = store
        .store_baseline(&baseline)
        .expect("store default baseline");

    let issuer = JwtTestIssuer::new(BENCH_GATEWAY_ID);
    let verifier = Arc::new(
        issuer
            .verifier(BENCH_AUDIENCE)
            .expect("create Ed25519 JwtAuthVerifier"),
    );
    let normalizer = Arc::new(CanonicalNormalizer::new_default(BENCH_HMAC_KEY));
    let detector = Arc::new(InteractionRiskDetector::new_default());

    let num_workers = 20usize;
    let requests_per_worker = 10usize;
    let total_requests = num_workers * requests_per_worker;

    let mut worker_tokens = Vec::with_capacity(num_workers);
    for worker_id in 0..num_workers {
        let sandbox_id = format!("sbx-bench-{worker_id:02}");
        let epoch = EpochRecord {
            epoch_id: format!("epoch-bench-{worker_id:02}"),
            gateway_id: BENCH_GATEWAY_ID.to_string(),
            sandbox_id: sandbox_id.clone(),
            task_profile: baseline.task_profile.clone(),
            baseline_hash: baseline_hash.clone(),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: 1_760_000_000_000,
            credentialed_endpoints: BTreeSet::from([("api.github.local".to_string(), 443)]),
            active_policy_hash: Some("pol-bench-v1".to_string()),
        };
        store.upsert_epoch(&epoch).expect("upsert worker epoch");

        let token = issuer
            .mint_supervisor_token(BENCH_AUDIENCE, &sandbox_id, 600)
            .expect("mint worker supervisor JWT");
        worker_tokens.push((sandbox_id, token));
    }

    let service = RiskGuardMiddlewareService::new(
        verifier,
        normalizer,
        detector,
        store,
        BENCH_AUDIENCE,
    )
    .with_max_in_flight(128)
    .with_eval_timeout(Duration::from_secs(5));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral gRPC listener");
    let server_addr = listener.local_addr().expect("listener local_addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service.into_server())
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("tonic gRPC server exited cleanly");
    });

    let endpoint = format!("http://{server_addr}");
    let mut clients = Vec::with_capacity(num_workers);
    for (sandbox_id, token) in worker_tokens {
        let client = SupervisorMiddlewareClient::connect(endpoint.clone())
            .await
            .expect("connect tonic SupervisorMiddlewareClient");
        clients.push((client, sandbox_id, token));
    }

    let mut join_handles = Vec::with_capacity(num_workers);
    for (worker_idx, (mut client, sandbox_id, token)) in clients.into_iter().enumerate() {
        join_handles.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis((worker_idx as u64) * 10)).await;
            let mut latencies_ms = Vec::with_capacity(requests_per_worker);
            for step in 0..requests_per_worker {
                let metadata = JwtTestIssuer::bearer_metadata(&token).expect("bearer metadata");
                let eval_msg = HttpRequestEvaluation {
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    context: Some(RequestContext {
                        request_id: format!("req-bench-w{worker_idx:02}-s{step:02}"),
                        sandbox_id: sandbox_id.clone(),
                        originating_process: Some(Process {
                            binary: "/usr/bin/gh".to_string(),
                            pid: 4000 + (worker_idx as u32),
                            ancestors: vec!["/bin/bash".to_string()],
                        }),
                        sandbox: sandbox_id.clone(),
                        workspace: "/workspace".to_string(),
                    }),
                    config: None,
                    target: Some(HttpRequestTarget {
                        scheme: "https".to_string(),
                        host: "api.github.local".to_string(),
                        port: 443,
                        method: "GET".to_string(),
                        path: "/repos/org/docs-site".to_string(),
                        query: String::new(),
                    }),
                    headers: vec![HttpHeader {
                        name: "user-agent".to_string(),
                        value: "gh/2.60.0".to_string(),
                    }],
                    body: vec![b'a'; 1024],
                    middleware_name: "openshell/behavioral-risk-guard".to_string(),
                };
                let mut req = tonic::Request::new(eval_msg);
                *req.metadata_mut() = metadata;

                let start = Instant::now();
                let resp = client
                    .evaluate_http_request(req)
                    .await
                    .expect("evaluate_http_request")
                    .into_inner();
                latencies_ms.push(start.elapsed().as_secs_f64() * 1000.0);
                assert_eq!(resp.decision, Decision::Allow as i32);
                if step + 1 < requests_per_worker {
                    tokio::time::sleep(Duration::from_millis(190)).await;
                }
            }
            latencies_ms
        }));
    }

    let mut all_latencies_ms = Vec::with_capacity(total_requests);
    for handle in join_handles {
        all_latencies_ms.extend(handle.await.expect("worker panicked"));
    }

    let _ = shutdown_tx.send(());
    let _ = server_handle.await;

    all_latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = percentile_ms(&all_latencies_ms, 50.0);
    let p95 = percentile_ms(&all_latencies_ms, 95.0);
    let p99 = percentile_ms(&all_latencies_ms, 99.0);
    println!("Gate G-06 Benchmark (n={total_requests}): p50={p50:.2}ms p95={p95:.2}ms p99={p99:.2}ms");
}
