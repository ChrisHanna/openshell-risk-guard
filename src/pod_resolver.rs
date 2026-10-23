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
/// How long a mapping is trusted without asking again. A pod address can be reused by another pod once the first is gone, so this is the longest a
/// stale mapping can be served.
const HIT_TTL: Duration = Duration::from_secs(5);
/// A lookup that finds nothing refreshes the list, but not more often than this.
const MIN_REFRESH_GAP: Duration = Duration::from_secs(2);
const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

struct Cache {
    by_ip: HashMap<IpAddr, String>,
    fetched_at: Option<Instant>,
}

pub type ListFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HashMap<IpAddr, String>>> + Send + 'a>>;

/// Where the address-to-sandbox table comes from.
pub trait PodLister: Send + Sync {
    fn list(&self) -> ListFuture<'_>;
}

/// Looks sandboxes up by pod address in a table it refreshes from a [`PodLister`].
///
/// Behaviour, in one place:
/// * **Stale information:** a mapping is trusted for `hit_ttl` only; after that the table is read again.
/// * **Address reuse:** every refresh replaces the whole table, so a reused address maps to its new pod, or to nothing; at worst the old mapping
///   is served for `hit_ttl`. Terminating pods are not mapped, and an address that two pods claim maps to nothing.
/// * **Missing labels or address:** the pod is not mapped, so its tunnels are refused as coming from an unknown sandbox.
/// * **Resolver failure:** an error, never a guess. The cache is emptied, so the next lookup starts clean, and the caller fails closed.
pub struct CachingResolver<L> {
    lister: L,
    hit_ttl: Duration,
    min_refresh_gap: Duration,
    cache: tokio::sync::Mutex<Cache>,
}

impl<L: PodLister> CachingResolver<L> {
    pub fn new(lister: L) -> Self {
        Self::with_timings(lister, HIT_TTL, MIN_REFRESH_GAP)
    }

    pub fn with_timings(lister: L, hit_ttl: Duration, min_refresh_gap: Duration) -> Self {
        Self {
            lister,
            hit_ttl,
            min_refresh_gap,
            cache: tokio::sync::Mutex::new(Cache {
                by_ip: HashMap::new(),
                fetched_at: None,
            }),
        }
    }
}

pub struct KubeLister {
    client: reqwest::Client,
    pods_url: String,
}

pub type KubePodResolver = CachingResolver<KubeLister>;

impl KubePodResolver {
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
        Ok(Self::new(KubeLister {
            client,
            pods_url: format!(
                "https://{host}:{port}/api/v1/namespaces/{namespace}/pods?labelSelector={}&fieldSelector=status.phase%3DRunning",
                SUPERVISOR_SELECTOR.replace('=', "%3D").replace('/', "%2F")
            ),
        }))
    }
}

impl PodLister for KubeLister {
    fn list(&self) -> ListFuture<'_> {
        Box::pin(async move {
            let token = std::fs::read_to_string(format!("{SERVICE_ACCOUNT_DIR}/token")).map_err(
                |error| {
                    RiskGuardError::Internal(format!(
                        "cannot read the service account token: {error}"
                    ))
                },
            )?;
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
        })
    }
}

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
    let mut by_ip: HashMap<IpAddr, String> = HashMap::new();
    let mut ambiguous: Vec<IpAddr> = Vec::new();
    for pod in body["items"].as_array().into_iter().flatten() {
        // A pod that is going away may be about to give its address to another; it is not mapped.
        if !pod["metadata"]["deletionTimestamp"].is_null() {
            continue;
        }
        let (Some(ip), Some(sandbox)) = (
            pod["status"]["podIP"]
                .as_str()
                .and_then(|ip| ip.parse::<IpAddr>().ok()),
            pod["metadata"]["labels"][SANDBOX_LABEL].as_str(),
        ) else {
            continue;
        };
        match by_ip.get(&ip) {
            Some(existing) if existing != sandbox => ambiguous.push(ip),
            _ => {
                by_ip.insert(ip, sandbox.to_string());
            }
        }
    }
    for ip in ambiguous {
        by_ip.remove(&ip);
    }
    by_ip
}

impl<L: PodLister> PodResolver for CachingResolver<L> {
    fn sandbox_for_ip(&self, ip: IpAddr) -> ResolveFuture<'_> {
        Box::pin(async move {
            let mut cache = self.cache.lock().await;
            let age = cache.fetched_at.map(|at| at.elapsed());
            let fresh = age.is_some_and(|age| age < self.hit_ttl);
            if fresh && let Some(sandbox) = cache.by_ip.get(&ip) {
                return Ok(Some(sandbox.clone()));
            }
            if age.is_none_or(|age| age >= self.min_refresh_gap) {
                match self.lister.list().await {
                    Ok(table) => {
                        cache.by_ip = table;
                        cache.fetched_at = Some(Instant::now());
                    }
                    Err(error) => {
                        // Nothing old is kept to be served by mistake later.
                        cache.by_ip.clear();
                        cache.fetched_at = None;
                        return Err(error);
                    }
                }
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

    // --- the table the resolver reads from: a scripted list of answers, one per refresh.
    struct Script(std::sync::Mutex<Vec<Result<HashMap<IpAddr, String>>>>);

    impl PodLister for Script {
        fn list(&self) -> ListFuture<'_> {
            let next = self.0.lock().unwrap().remove(0);
            Box::pin(async move { next })
        }
    }

    fn table(entries: &[(&str, &str)]) -> Result<HashMap<IpAddr, String>> {
        Ok(entries
            .iter()
            .map(|(ip, sandbox)| (ip.parse().unwrap(), (*sandbox).to_string()))
            .collect())
    }

    fn resolver(answers: Vec<Result<HashMap<IpAddr, String>>>) -> CachingResolver<Script> {
        CachingResolver::with_timings(
            Script(std::sync::Mutex::new(answers)),
            Duration::from_millis(60),
            Duration::from_millis(0),
        )
    }

    async fn lookup(resolver: &CachingResolver<Script>, ip: &str) -> Result<Option<String>> {
        resolver.sandbox_for_ip(ip.parse().unwrap()).await
    }

    #[tokio::test]
    async fn a_mapping_is_not_trusted_past_its_lifetime_so_a_reused_address_follows_its_new_owner()
    {
        let r = resolver(vec![
            table(&[("10.0.0.5", "sbx-old")]),
            table(&[("10.0.0.5", "sbx-new")]),
            table(&[]),
        ]);
        assert_eq!(
            lookup(&r, "10.0.0.5").await.unwrap().as_deref(),
            Some("sbx-old")
        );
        // Within the lifetime the cached answer stands (the documented window for a stale mapping).
        assert_eq!(
            lookup(&r, "10.0.0.5").await.unwrap().as_deref(),
            Some("sbx-old")
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            lookup(&r, "10.0.0.5").await.unwrap().as_deref(),
            Some("sbx-new"),
            "the address now belongs to another sandbox"
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            lookup(&r, "10.0.0.5").await.unwrap(),
            None,
            "the pod is gone, so the address maps to nothing"
        );
    }

    #[tokio::test]
    async fn a_failed_refresh_is_an_error_and_leaves_nothing_old_to_fall_back_on() {
        let r = resolver(vec![
            table(&[("10.0.0.5", "sbx-a")]),
            Err(RiskGuardError::Internal("api down".into())),
            table(&[]),
        ]);
        assert_eq!(
            lookup(&r, "10.0.0.5").await.unwrap().as_deref(),
            Some("sbx-a")
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            lookup(&r, "10.0.0.5").await.is_err(),
            "no answer is guessed when the table cannot be read"
        );
        // The next try reads afresh; the old mapping was not kept.
        assert_eq!(lookup(&r, "10.0.0.5").await.unwrap(), None);
    }

    #[tokio::test]
    async fn an_unknown_address_triggers_a_refresh_and_stays_unknown() {
        let r = resolver(vec![
            table(&[("10.0.0.5", "sbx-a")]),
            table(&[("10.0.0.5", "sbx-a")]),
        ]);
        assert_eq!(lookup(&r, "10.0.0.6").await.unwrap(), None);
    }

    #[test]
    fn terminating_pods_and_addresses_claimed_by_two_sandboxes_are_not_mapped() {
        let body = serde_json::json!({"items": [
            {"status": {"podIP": "10.0.0.1"}, "metadata": {"labels": {"openshell.ai/sandbox-id": "sbx-1"}, "deletionTimestamp": "2026-10-23T00:00:00Z"}},
            {"status": {"podIP": "10.0.0.2"}, "metadata": {"labels": {"openshell.ai/sandbox-id": "sbx-2"}}},
            {"status": {"podIP": "10.0.0.2"}, "metadata": {"labels": {"openshell.ai/sandbox-id": "sbx-3"}}},
            {"status": {"podIP": "10.0.0.4"}, "metadata": {"labels": {"openshell.ai/sandbox-id": "sbx-4"}}},
            {"status": {"podIP": "10.0.0.4"}, "metadata": {"labels": {"openshell.ai/sandbox-id": "sbx-4"}}},
        ]});
        let mapped = parse_pods(&body);
        assert!(
            !mapped.contains_key(&"10.0.0.1".parse::<IpAddr>().unwrap()),
            "a terminating pod"
        );
        assert!(
            !mapped.contains_key(&"10.0.0.2".parse::<IpAddr>().unwrap()),
            "an ambiguous address"
        );
        assert_eq!(mapped[&"10.0.0.4".parse::<IpAddr>().unwrap()], "sbx-4");
    }
}
