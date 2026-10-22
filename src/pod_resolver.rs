// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Which sandbox is behind a network address?
//!
//! When OpenShell chains a sandbox's TLS egress through an upstream proxy, the proxy sees a connection from the sandbox's
//! supervisor pod and nothing else: no request, no certificate. The only identity it has is the address the connection came
//! from. Kubernetes knows which pod owns that address and OpenShell labels every supervisor pod with its sandbox ID
//! (`openshell.ai/sandbox-id`), so the address can be turned back into the sandbox Risk Guard already tracks.
//!
//! The address is trustworthy only as far as the network is: the cluster's network policy engine stops a pod from sending traffic
//! with another pod's address. The mapping is read from the Kubernetes API (read-only, `pods` in one namespace) and cached briefly;
//! a pod that has just started is found by refreshing on a miss.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use crate::error::{Result, RiskGuardError};

pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<String>>> + Send + 'a>>;

/// Turns the address a connection came from into a sandbox ID, or `None` when no sandbox owns it.
pub trait PodResolver: Send + Sync {
    fn sandbox_for_ip(&self, ip: IpAddr) -> ResolveFuture<'_>;
}

/// A fixed table, for tests.
pub struct StaticPodResolver(pub HashMap<IpAddr, String>);

impl PodResolver for StaticPodResolver {
    fn sandbox_for_ip(&self, ip: IpAddr) -> ResolveFuture<'_> {
        let found = self.0.get(&ip).cloned();
        Box::pin(async move { Ok(found) })
    }
}

const SANDBOX_LABEL: &str = "openshell.ai/sandbox-id";
const SUPERVISOR_SELECTOR: &str = "openshell.ai/component=supervisor";
const REFRESH_AFTER: Duration = Duration::from_secs(10);
const MIN_REFRESH_GAP: Duration = Duration::from_secs(2);
const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

struct Cache {
    by_ip: HashMap<IpAddr, String>,
    fetched_at: Option<Instant>,
}

/// Reads supervisor pods from the Kubernetes API with the pod's own service account.
pub struct KubePodResolver {
    client: reqwest::Client,
    pods_url: String,
    cache: tokio::sync::Mutex<Cache>,
}

impl KubePodResolver {
    /// In-cluster configuration: the API server from the environment, the service account's CA and token.
    pub fn in_cluster(namespace: &str) -> Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
            RiskGuardError::InvalidArgument(
                "pod resolution needs to run inside Kubernetes (KUBERNETES_SERVICE_HOST is not set)".into(),
            )
        })?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let ca = std::fs::read(format!("{SERVICE_ACCOUNT_DIR}/ca.crt")).map_err(|error| {
            RiskGuardError::InvalidArgument(format!("cannot read the cluster CA: {error}"))
        })?;
        let client = http_client(&ca)?;
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        Ok(Self {
            client,
            pods_url: format!(
                "https://{host}:{port}/api/v1/namespaces/{namespace}/pods?labelSelector={}&fieldSelector=status.phase%3DRunning",
                SUPERVISOR_SELECTOR.replace('=', "%3D").replace('/', "%2F")
            ),
            cache: tokio::sync::Mutex::new(Cache {
                by_ip: HashMap::new(),
                fetched_at: None,
            }),
        })
    }

    async fn fetch(&self) -> Result<HashMap<IpAddr, String>> {
        // The service account token is rotated by the kubelet, so it is read on every refresh.
        let token =
            std::fs::read_to_string(format!("{SERVICE_ACCOUNT_DIR}/token")).map_err(|error| {
                RiskGuardError::Internal(format!("cannot read the service account token: {error}"))
            })?;
        let body: serde_json::Value = self
            .client
            .get(&self.pods_url)
            .bearer_auth(token.trim())
            .send()
            .await
            .map_err(|error| RiskGuardError::Internal(format!("listing pods: {error}")))?
            .error_for_status()
            .map_err(|error| RiskGuardError::Internal(format!("listing pods: {error}")))?
            .json()
            .await
            .map_err(|error| RiskGuardError::Internal(format!("reading pods: {error}")))?;
        Ok(parse_pods(&body))
    }
}

/// The client for the Kubernetes API: it trusts the cluster's own CA. reqwest is built without a default TLS crypto provider, so one
/// is installed first (this panicked at startup the first time it was used without it).
fn http_client(ca_pem: &[u8]) -> Result<reqwest::Client> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(ca_pem).map_err(|error| {
                RiskGuardError::InvalidArgument(format!("bad cluster CA: {error}"))
            })?,
        )
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| RiskGuardError::Internal(format!("http client: {error}")))
}

/// Supervisor pods with an address, keyed by it. A pod without the sandbox label is ignored.
fn parse_pods(body: &serde_json::Value) -> HashMap<IpAddr, String> {
    let mut by_ip = HashMap::new();
    for pod in body["items"].as_array().into_iter().flatten() {
        let (Some(ip), Some(sandbox)) = (
            pod["status"]["podIP"]
                .as_str()
                .and_then(|ip| ip.parse::<IpAddr>().ok()),
            pod["metadata"]["labels"][SANDBOX_LABEL].as_str(),
        ) else {
            continue;
        };
        by_ip.insert(ip, sandbox.to_string());
    }
    by_ip
}

impl PodResolver for KubePodResolver {
    fn sandbox_for_ip(&self, ip: IpAddr) -> ResolveFuture<'_> {
        Box::pin(async move {
            let mut cache = self.cache.lock().await;
            let age = cache.fetched_at.map(|at| at.elapsed());
            let fresh = age.is_some_and(|age| age < REFRESH_AFTER);
            if fresh && let Some(sandbox) = cache.by_ip.get(&ip) {
                return Ok(Some(sandbox.clone()));
            }
            // Refresh when the table is old, or when the address is unknown and we have not just looked (a new pod).
            if age.is_none_or(|age| age >= MIN_REFRESH_GAP) {
                cache.by_ip = self.fetch().await?;
                cache.fetched_at = Some(Instant::now());
            }
            Ok(cache.by_ip.get(&ip).cloned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_api_client_can_be_built_in_a_process_that_installed_no_crypto_provider() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&key).unwrap();
        http_client(ca.pem().as_bytes()).expect("the client builds");
    }

    #[test]
    fn only_running_supervisor_pods_with_a_sandbox_label_and_an_address_are_mapped() {
        let body = serde_json::json!({"items": [
            {"status": {"podIP": "10.244.2.238"}, "metadata": {"labels": {"openshell.ai/sandbox-id": "sbx-1"}}},
            {"status": {"podIP": "10.244.2.239"}, "metadata": {"labels": {}}},
            {"status": {}, "metadata": {"labels": {"openshell.ai/sandbox-id": "sbx-3"}}},
            {"status": {"podIP": "not-an-ip"}, "metadata": {"labels": {"openshell.ai/sandbox-id": "sbx-4"}}},
        ]});
        let mapped = parse_pods(&body);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[&"10.244.2.238".parse::<IpAddr>().unwrap()], "sbx-1");
    }
}
