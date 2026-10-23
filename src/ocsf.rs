// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Risk Guard's own security events, as OCSF (1.8) JSON, sent to an OpenTelemetry Collector as OTLP logs over HTTP.
//!
//! OpenShell already exports its own OCSF events, but it reduces a middleware's answer to a generic "risk-guard" finding: the score, the threshold, the rule
//! and who the workload is do not survive. These events carry them: the workload (`actor.user.name`, its SPIFFE ID in `actor.user.uid`, the run in
//! `actor.session.uid`), the task profile, the score and threshold (`risk_score`, `unmapped.risk_guard`), the reason code and the signals behind it.
//!
//! What is sent: refusals at the supervisor middleware, tunnel refusals and shadow "would have blocked" notes at the tunnel gate, a silent supervisor, and each
//! signal received from a SIEM with its outcome. Allowed requests are not sent (OpenShell already records those, and they would drown the rest).
//!
//! Emitting never slows a decision: events go through a bounded queue to a background task, and when the queue is full or the collector is down they are dropped
//! and counted. The events are shaped after OCSF 1.8 but are not validated against its schema.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::store::SqliteRiskStore;

const QUEUE: usize = 1024;
const BATCH: usize = 100;
const FLUSH: Duration = Duration::from_secs(2);

/// Something that happened, before it is given an identity and turned into OCSF.
#[derive(Debug, Clone)]
pub enum Occurrence {
    /// A request the supervisor middleware did not simply allow.
    Decision {
        sandbox_id: String,
        request_id: String,
        outcome: String,
        reason_code: String,
        risk_score: u32,
        threshold: u32,
        mode: String,
        method: String,
        host: String,
        port: u16,
        path: String,
        signals: Vec<(String, u32)>,
        at_ms: i64,
    },
    /// A tunnel the network path refused, or would have refused in enforce mode.
    Tunnel {
        sandbox_id: String,
        destination: String,
        refused: bool,
        reason: String,
        silent_for_ms: Option<i64>,
        at_ms: i64,
    },
    /// What one sandbox's workload did in the last interval: every decision, allowed or refused, counted. Sent once a minute per active sandbox.
    Activity {
        sandbox_id: String,
        window_ms: i64,
        allowed: u32,
        refused: u32,
        max_score: u32,
        distinct_routes: u32,
        at_ms: i64,
    },
    /// What one sandbox's workload did on one route in the last interval (host, method, route template), allowed and refused counted.
    Route {
        sandbox_id: String,
        host: String,
        method: String,
        route: String,
        allowed: u32,
        refused: u32,
        max_score: u32,
        at_ms: i64,
    },
    /// Where one sandbox's workload opened (or was refused) network tunnels in the last interval.
    Egress {
        sandbox_id: String,
        destination: String,
        allowed: u32,
        refused: u32,
        shadow: u32,
        at_ms: i64,
    },
    /// A signal from a SIEM and what became of it.
    Signal {
        signal_id: String,
        source: String,
        alert_id: Option<String>,
        agent_id: Option<String>,
        sandbox_id: Option<String>,
        outcome: String,
        ttl_seconds: u64,
        reason: String,
        at_ms: i64,
    },
}

/// Who a sandbox is, as far as Risk Guard knows.
#[derive(Debug, Clone, Default)]
pub struct SandboxIdentity {
    pub agent_id: Option<String>,
    /// The name an operator gave the agent (`agents.display_name`), for people to read.
    pub display_name: Option<String>,
    pub run_id: Option<String>,
    pub task_profile: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OcsfConfig {
    /// Base URL of the collector's OTLP/HTTP receiver, e.g. `http://otel-collector:4318`.
    pub endpoint: String,
    /// The trust domain that gives sandboxes their SPIFFE IDs (`spiffe://<domain>/openshell/sandbox/<id>`), when there is one.
    pub trust_domain: Option<String>,
    pub version: String,
}

/// How many different routes one sandbox is counted for in an interval; beyond this they are counted together as "other" (a scanner is already obvious at this number).
const MAX_ROUTES: usize = 64;
const MAX_DESTINATIONS: usize = 64;

#[derive(Default, Clone, Copy)]
struct RouteStat {
    allowed: u32,
    refused: u32,
    max_score: u32,
}

#[derive(Default, Clone, Copy)]
struct EgressStat {
    allowed: u32,
    refused: u32,
    shadow: u32,
}

#[derive(Default)]
struct Bucket {
    allowed: u32,
    refused: u32,
    max_score: u32,
    routes: std::collections::HashMap<(String, String, String), RouteStat>,
    egress: std::collections::HashMap<String, EgressStat>,
}

/// What happened to one tunnel request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelOutcome {
    Allowed,
    Refused,
    /// Allowed now, but would be refused in enforce mode.
    Shadow,
}

/// Per-sandbox counts of decisions, kept in memory and emptied once a minute. Recording is a lock, a hash lookup and a few increments.
#[derive(Default)]
pub struct ActivityCounters {
    buckets: std::sync::Mutex<std::collections::HashMap<String, Bucket>>,
    since_ms: std::sync::atomic::AtomicI64,
}

impl ActivityCounters {
    /// One decision on a route (host, method, route template).
    pub fn record(
        &self,
        sandbox_id: &str,
        refused: bool,
        score: u32,
        host: &str,
        method: &str,
        route: &str,
    ) {
        let Ok(mut buckets) = self.buckets.lock() else {
            return;
        };
        let bucket = buckets.entry(sandbox_id.to_string()).or_default();
        if refused {
            bucket.refused = bucket.refused.saturating_add(1);
        } else {
            bucket.allowed = bucket.allowed.saturating_add(1);
        }
        bucket.max_score = bucket.max_score.max(score);
        let key = (host.to_string(), method.to_string(), route.to_string());
        let key = if bucket.routes.len() >= MAX_ROUTES && !bucket.routes.contains_key(&key) {
            (
                "other".to_string(),
                "other".to_string(),
                "other".to_string(),
            )
        } else {
            key
        };
        let stat = bucket.routes.entry(key).or_default();
        if refused {
            stat.refused = stat.refused.saturating_add(1);
        } else {
            stat.allowed = stat.allowed.saturating_add(1);
        }
        stat.max_score = stat.max_score.max(score);
    }

    /// One tunnel request to a destination (`host:port`).
    pub fn record_tunnel(&self, sandbox_id: &str, destination: &str, outcome: TunnelOutcome) {
        let Ok(mut buckets) = self.buckets.lock() else {
            return;
        };
        let bucket = buckets.entry(sandbox_id.to_string()).or_default();
        let key = if bucket.egress.len() >= MAX_DESTINATIONS
            && !bucket.egress.contains_key(destination)
        {
            "other"
        } else {
            destination
        };
        let stat = bucket.egress.entry(key.to_string()).or_default();
        let counter = match outcome {
            TunnelOutcome::Allowed => &mut stat.allowed,
            TunnelOutcome::Refused => &mut stat.refused,
            TunnelOutcome::Shadow => &mut stat.shadow,
        };
        *counter = counter.saturating_add(1);
    }

    /// Empty the counters into occurrences: per sandbox that made decisions one summary, plus one row per route, and one row per destination.
    /// A sandbox that did nothing produces nothing (silence is visible as a missing summary).
    pub fn take(&self, now_ms: i64) -> Vec<Occurrence> {
        let since = self.since_ms.swap(now_ms, Ordering::Relaxed);
        let window_ms = if since > 0 {
            (now_ms - since).max(1)
        } else {
            60_000
        };
        let drained = match self.buckets.lock() {
            Ok(mut buckets) => std::mem::take(&mut *buckets),
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for (sandbox_id, bucket) in drained {
            if bucket.allowed + bucket.refused > 0 {
                out.push(Occurrence::Activity {
                    sandbox_id: sandbox_id.clone(),
                    window_ms,
                    allowed: bucket.allowed,
                    refused: bucket.refused,
                    max_score: bucket.max_score,
                    distinct_routes: u32::try_from(bucket.routes.len()).unwrap_or(u32::MAX),
                    at_ms: now_ms,
                });
            }
            for ((host, method, route), stat) in bucket.routes {
                out.push(Occurrence::Route {
                    sandbox_id: sandbox_id.clone(),
                    host,
                    method,
                    route,
                    allowed: stat.allowed,
                    refused: stat.refused,
                    max_score: stat.max_score,
                    at_ms: now_ms,
                });
            }
            for (destination, stat) in bucket.egress {
                out.push(Occurrence::Egress {
                    sandbox_id: sandbox_id.clone(),
                    destination,
                    allowed: stat.allowed,
                    refused: stat.refused,
                    shadow: stat.shadow,
                    at_ms: now_ms,
                });
            }
        }
        out
    }
}

pub struct OcsfEmitter {
    queue: mpsc::Sender<Occurrence>,
    dropped: AtomicU64,
    activity: ActivityCounters,
}

impl OcsfEmitter {
    /// Start the background sender. Must be called inside a Tokio runtime.
    pub fn start(config: OcsfConfig, store: Arc<SqliteRiskStore>) -> Arc<Self> {
        let (queue, receiver) = mpsc::channel(QUEUE);
        let emitter = Arc::new(Self {
            queue,
            dropped: AtomicU64::new(0),
            activity: ActivityCounters::default(),
        });
        tokio::spawn(run(config, store, receiver, Arc::clone(&emitter)));
        // Once a minute, turn the counters into events.
        let counting = Arc::clone(&emitter);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await;
            loop {
                tick.tick().await;
                let now_ms = crate::store::now_wall_ms();
                for occurrence in counting.activity.take(now_ms) {
                    counting.emit(occurrence);
                }
            }
        });
        emitter
    }

    /// Count one decision toward its sandbox's activity. Cheap, never waits on the network.
    pub fn record_decision(
        &self,
        sandbox_id: &str,
        refused: bool,
        score: u32,
        host: &str,
        method: &str,
        route: &str,
    ) {
        self.activity
            .record(sandbox_id, refused, score, host, method, route);
    }

    /// Count one tunnel request toward its sandbox's egress.
    pub fn record_tunnel(&self, sandbox_id: &str, destination: &str, outcome: TunnelOutcome) {
        self.activity
            .record_tunnel(sandbox_id, destination, outcome);
    }

    /// Hand an event over. Never waits: a full queue drops the event and counts it.
    pub fn emit(&self, occurrence: Occurrence) {
        if self.queue.try_send(occurrence).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Events dropped because the queue was full or the sender had stopped.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

async fn run(
    config: OcsfConfig,
    store: Arc<SqliteRiskStore>,
    mut receiver: mpsc::Receiver<Occurrence>,
    emitter: Arc<OcsfEmitter>,
) {
    // reqwest is built without a bundled crypto provider; install one before building a client (a second install is harmless).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error, "OCSF export disabled: no HTTP client");
            return;
        }
    };
    let url = format!("{}/v1/logs", config.endpoint.trim_end_matches('/'));
    let mut failures = 0u32;
    loop {
        let Some(first) = receiver.recv().await else {
            return;
        };
        let mut batch = vec![first];
        let deadline = tokio::time::Instant::now() + FLUSH;
        while batch.len() < BATCH {
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(next)) => batch.push(next),
                _ => break,
            }
        }
        let lookup_store = Arc::clone(&store);
        let trust_domain = config.trust_domain.clone();
        let version = config.version.clone();
        let events = tokio::task::spawn_blocking(move || {
            batch
                .iter()
                .map(|occurrence| {
                    let sandbox = sandbox_of(occurrence);
                    let identity = sandbox
                        .and_then(|id| lookup_store.sandbox_identity(id).ok().flatten())
                        .unwrap_or_default();
                    to_ocsf(occurrence, &identity, trust_domain.as_deref(), &version)
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        if events.is_empty() {
            continue;
        }
        let count = events.len() as u64;
        match client.post(&url).json(&otlp_payload(&events)).send().await {
            Ok(response) if response.status().is_success() => failures = 0,
            Ok(response) => {
                emitter.dropped.fetch_add(count, Ordering::Relaxed);
                failures += 1;
                if failures == 1 || failures.is_power_of_two() {
                    tracing::warn!(status = %response.status(), count, "the collector refused OCSF events; they were dropped");
                }
            }
            Err(error) => {
                emitter.dropped.fetch_add(count, Ordering::Relaxed);
                failures += 1;
                if failures == 1 || failures.is_power_of_two() {
                    tracing::warn!(%error, count, "could not send OCSF events; they were dropped");
                }
            }
        }
    }
}

fn sandbox_of(occurrence: &Occurrence) -> Option<&str> {
    match occurrence {
        Occurrence::Decision { sandbox_id, .. }
        | Occurrence::Tunnel { sandbox_id, .. }
        | Occurrence::Activity { sandbox_id, .. }
        | Occurrence::Route { sandbox_id, .. }
        | Occurrence::Egress { sandbox_id, .. } => Some(sandbox_id),
        Occurrence::Signal { sandbox_id, .. } => sandbox_id.as_deref(),
    }
}

fn spiffe_id(sandbox_id: &str, trust_domain: Option<&str>) -> Option<String> {
    if sandbox_id.starts_with("spiffe://") {
        return Some(sandbox_id.to_string());
    }
    let domain = trust_domain?;
    (!sandbox_id.starts_with("svid-"))
        .then(|| format!("spiffe://{domain}/openshell/sandbox/{sandbox_id}"))
}

fn actor(identity: &SandboxIdentity, spiffe: Option<&str>) -> Value {
    json!({
        "user": {"name": identity.agent_id, "uid": spiffe, "full_name": identity.display_name},
        "session": {"uid": identity.run_id},
    })
}

fn base(version: &str, at_ms: i64) -> serde_json::Map<String, Value> {
    let Value::Object(map) = json!({
        "metadata": {
            "version": "1.8.0",
            "uid": uuid::Uuid::new_v4().to_string(),
            "product": {"name": "OpenShell Risk Guard", "vendor_name": "openshell-risk-guard", "version": version},
            "profiles": ["security_control"],
        },
        "time": at_ms,
    }) else {
        unreachable!("a JSON object literal")
    };
    map
}

/// One occurrence as an OCSF event.
pub fn to_ocsf(
    occurrence: &Occurrence,
    identity: &SandboxIdentity,
    trust_domain: Option<&str>,
    version: &str,
) -> Value {
    match occurrence {
        Occurrence::Decision {
            sandbox_id,
            request_id,
            outcome,
            reason_code,
            risk_score,
            threshold,
            mode,
            method,
            host,
            port,
            path,
            signals,
            at_ms,
        } => {
            let spiffe = spiffe_id(sandbox_id, trust_domain);
            let mut event = base(version, *at_ms);
            event.extend(
                json!({
                    "category_uid": 2, "category_name": "Findings",
                    "class_uid": 2004, "class_name": "Detection Finding",
                    "activity_id": 1, "activity_name": "Create",
                    "type_uid": 200_401, "type_name": "Detection Finding: Create",
                    "severity_id": 4, "severity": "High",
                    "status_id": 1, "status": "New",
                    "action_id": 2, "action": "Denied",
                    "disposition_id": 2, "disposition": "Blocked",
                    "message": format!("Risk Guard refused {method} {host}{path}: {reason_code} (score {risk_score}, threshold {threshold})"),
                    "status_detail": format!("risk_guard_denied:{reason_code}"),
                    "risk_score": risk_score,
                    "finding_info": {
                        "uid": request_id, "title": "Risk Guard refused a request",
                        "desc": format!("Behavioral risk {risk_score}/{threshold} ({outcome}); reason {reason_code}"),
                        "types": ["risk-guard", "middleware", reason_code],
                    },
                    "actor": actor(identity, spiffe.as_deref()),
                    "container": {"uid": sandbox_id},
                    "unmapped": {"risk_guard": {
                        "gate": "middleware", "agent_id": identity.agent_id, "run_id": identity.run_id,
                        "task_profile": identity.task_profile, "spiffe_id": spiffe,
                        "outcome": outcome, "reason_code": reason_code, "mode": mode,
                        "risk_score": risk_score, "threshold": threshold,
                        "http": {"method": method, "host": host, "port": port, "path": path},
                        "signals": signals.iter().map(|(feature, contribution)| json!({"feature": feature, "contribution": contribution})).collect::<Vec<_>>(),
                    }},
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            );
            Value::Object(event)
        }
        Occurrence::Tunnel {
            sandbox_id,
            destination,
            refused,
            reason,
            silent_for_ms,
            at_ms,
        } => {
            let spiffe = spiffe_id(sandbox_id, trust_domain);
            let silent = silent_for_ms.is_some();
            let (title, kind) = if silent {
                ("A sandbox's supervisor went quiet", "supervisor_silent")
            } else if *refused {
                ("Risk Guard refused a tunnel", "tunnel_refused")
            } else {
                (
                    "Risk Guard would refuse a tunnel in enforce mode",
                    "tunnel_would_refuse",
                )
            };
            let mut event = base(version, *at_ms);
            event.extend(
                json!({
                    "category_uid": 2, "category_name": "Findings",
                    "class_uid": 2004, "class_name": "Detection Finding",
                    "activity_id": 1, "activity_name": "Create",
                    "type_uid": 200_401, "type_name": "Detection Finding: Create",
                    "severity_id": if *refused { 4 } else { 3 }, "severity": if *refused { "High" } else { "Medium" },
                    "status_id": 1, "status": "New",
                    "action_id": if *refused { 2 } else { 1 }, "action": if *refused { "Denied" } else { "Allowed" },
                    "disposition_id": if *refused { 2 } else { 1 }, "disposition": if *refused { "Blocked" } else { "Allowed" },
                    "message": format!("{title}: {destination} ({reason})"),
                    "status_detail": format!("risk_guard_tunnel:{kind}"),
                    "finding_info": {"uid": uuid::Uuid::new_v4().to_string(), "title": title, "desc": reason, "types": ["risk-guard", "tunnel", kind]},
                    "actor": actor(identity, spiffe.as_deref()),
                    "container": {"uid": sandbox_id},
                    "dst_endpoint": {"domain": destination},
                    "unmapped": {"risk_guard": {
                        "gate": "tunnel", "kind": kind, "agent_id": identity.agent_id, "run_id": identity.run_id,
                        "task_profile": identity.task_profile, "spiffe_id": spiffe, "reason": reason,
                        "refused": refused, "silent_for_ms": silent_for_ms,
                    }},
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            );
            Value::Object(event)
        }
        Occurrence::Activity {
            sandbox_id,
            window_ms,
            allowed,
            refused,
            max_score,
            distinct_routes,
            at_ms,
        } => {
            let spiffe = spiffe_id(sandbox_id, trust_domain);
            let total = allowed + refused;
            let ratio = if total > 0 {
                f64::from(*refused) / f64::from(total)
            } else {
                0.0
            };
            let mut event = base(version, *at_ms);
            event.extend(
                json!({
                    "category_uid": 6, "category_name": "Application Activity",
                    "class_uid": 6003, "class_name": "API Activity",
                    "activity_id": 99, "activity_name": "Activity summary",
                    "type_uid": 600_399, "type_name": "API Activity: Other",
                    "severity_id": 1, "severity": "Informational",
                    "status_id": 1, "status": "Success",
                    "message": format!("Workload activity: {total} decisions ({refused} refused), highest score {max_score}, {distinct_routes} routes"),
                    "status_detail": "risk_guard_summary",
                    "risk_score": max_score,
                    "api": {"operation": "activity_summary", "service": {"name": "risk-guard"}},
                    "actor": actor(identity, spiffe.as_deref()),
                    "container": {"uid": sandbox_id},
                    "unmapped": {"risk_guard": {
                        "gate": "summary", "agent_id": identity.agent_id, "run_id": identity.run_id,
                        "task_profile": identity.task_profile, "spiffe_id": spiffe,
                        "window_seconds": window_ms / 1000, "allowed_calls": allowed, "refused_calls": refused, "total": total,
                        "refusal_ratio": ratio, "max_score": max_score, "distinct_routes": distinct_routes,
                    }},
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            );
            Value::Object(event)
        }
        Occurrence::Route {
            sandbox_id,
            host,
            method,
            route,
            allowed,
            refused,
            max_score,
            at_ms,
        } => {
            let spiffe = spiffe_id(sandbox_id, trust_domain);
            let total = allowed + refused;
            let mut event = base(version, *at_ms);
            event.extend(
                json!({
                    "category_uid": 6, "category_name": "Application Activity",
                    "class_uid": 6003, "class_name": "API Activity",
                    "activity_id": 99, "activity_name": "Route activity",
                    "type_uid": 600_399, "type_name": "API Activity: Other",
                    "severity_id": 1, "severity": "Informational",
                    "status_id": 1, "status": "Success",
                    "message": format!("{method} {host}{route}: {total} calls ({refused} refused), highest score {max_score}"),
                    "status_detail": "risk_guard_route",
                    "risk_score": max_score,
                    "api": {"operation": method, "service": {"name": host}},
                    "actor": actor(identity, spiffe.as_deref()),
                    "container": {"uid": sandbox_id},
                    "unmapped": {"risk_guard": {
                        "gate": "route", "agent_id": identity.agent_id, "task_profile": identity.task_profile,
                        "host": host, "method": method, "route": route,
                        "allowed_calls": allowed, "refused_calls": refused, "total": total, "max_score": max_score,
                    }},
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            );
            Value::Object(event)
        }
        Occurrence::Egress {
            sandbox_id,
            destination,
            allowed,
            refused,
            shadow,
            at_ms,
        } => {
            let spiffe = spiffe_id(sandbox_id, trust_domain);
            let total = allowed + refused + shadow;
            let mut event = base(version, *at_ms);
            event.extend(
                json!({
                    "category_uid": 4, "category_name": "Network Activity",
                    "class_uid": 4001, "class_name": "Network Activity",
                    "activity_id": 99, "activity_name": "Egress activity",
                    "type_uid": 400_199, "type_name": "Network Activity: Other",
                    "severity_id": 1, "severity": "Informational",
                    "status_id": 1, "status": "Success",
                    "message": format!("Tunnels to {destination}: {total} ({refused} refused, {shadow} would be refused in enforce mode)"),
                    "status_detail": "risk_guard_egress",
                    "dst_endpoint": {"domain": destination},
                    "actor": actor(identity, spiffe.as_deref()),
                    "container": {"uid": sandbox_id},
                    "unmapped": {"risk_guard": {
                        "gate": "egress", "agent_id": identity.agent_id, "task_profile": identity.task_profile,
                        "destination": destination,
                        "allowed_calls": allowed, "refused_calls": refused, "shadow_calls": shadow, "total": total,
                    }},
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            );
            Value::Object(event)
        }
        Occurrence::Signal {
            signal_id,
            source,
            alert_id,
            agent_id,
            sandbox_id,
            outcome,
            ttl_seconds,
            reason,
            at_ms,
        } => {
            let applied = outcome == "applied";
            let spiffe = sandbox_id
                .as_deref()
                .and_then(|id| spiffe_id(id, trust_domain));
            let target = agent_id.clone().or_else(|| identity.agent_id.clone());
            let mut event = base(version, *at_ms);
            event.extend(
                json!({
                    "category_uid": 6, "category_name": "Application Activity",
                    "class_uid": 6003, "class_name": "API Activity",
                    "activity_id": 1, "activity_name": "Create",
                    "type_uid": 600_301, "type_name": "API Activity: Create",
                    "severity_id": if applied { 3 } else { 2 }, "severity": if applied { "Medium" } else { "Low" },
                    "status_id": if matches!(outcome.as_str(), "applied" | "dry_run" | "already_quarantined") { 1 } else { 2 },
                    "status": if matches!(outcome.as_str(), "applied" | "dry_run" | "already_quarantined") { "Success" } else { "Failure" },
                    "message": format!("Signal {signal_id} from {source}: quarantine for {ttl_seconds} s -> {outcome}"),
                    "status_detail": format!("risk_guard_signal:{outcome}"),
                    "api": {"operation": "quarantine", "service": {"name": "risk-guard-signals"}, "request": {"uid": signal_id}},
                    "actor": {"user": {"name": source}},
                    "container": {"uid": sandbox_id},
                    "unmapped": {"risk_guard": {
                        "gate": "signal", "signal_id": signal_id, "source": source, "alert_id": alert_id, "outcome": outcome,
                        "ttl_seconds": ttl_seconds, "reason": reason, "target_agent_id": target, "spiffe_id": spiffe,
                        "task_profile": identity.task_profile,
                    }},
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            );
            Value::Object(event)
        }
    }
}

/// OTLP/HTTP JSON for a batch of events: one log record each, the event itself as a JSON string in the body (as OpenShell's own export does,
/// so the same collector pipeline parses both).
pub fn otlp_payload(events: &[Value]) -> Value {
    let records: Vec<Value> = events
        .iter()
        .map(|event| {
            let ms = event["time"].as_i64().unwrap_or(0).max(0);
            json!({
                "timeUnixNano": (ms.saturating_mul(1_000_000)).to_string(),
                "severityNumber": match event["severity_id"].as_i64().unwrap_or(1) { 4.. => 17, 3 => 13, 2 => 9, _ => 5 },
                "body": {"stringValue": event.to_string()},
                "attributes": [
                    {"key": "ocsf.class_uid", "value": {"intValue": event["class_uid"].as_i64().unwrap_or(0).to_string()}},
                    {"key": "event.producer", "value": {"stringValue": "risk-guard"}},
                ],
            })
        })
        .collect();
    json!({"resourceLogs": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "openshell-risk-guard"}},
        ]},
        "scopeLogs": [{"scope": {"name": "risk-guard-ocsf"}, "logRecords": records}],
    }]})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> SandboxIdentity {
        SandboxIdentity {
            agent_id: Some("agent-7".into()),
            display_name: Some("Release bot".into()),
            run_id: Some("run-9".into()),
            task_profile: Some("repo-triage-readonly".into()),
        }
    }

    fn decision() -> Occurrence {
        Occurrence::Decision {
            sandbox_id: "sbx-1".into(),
            request_id: "req-1".into(),
            outcome: "Deny".into(),
            reason_code: "behavioral_risk_denied".into(),
            risk_score: 92,
            threshold: 70,
            mode: "enforce".into(),
            method: "DELETE".into(),
            host: "api.example".into(),
            port: 443,
            path: "/repos/org/x".into(),
            signals: vec![("destructive_action".into(), 60)],
            at_ms: 1_800_000_000_000,
        }
    }

    #[test]
    fn a_refusal_carries_who_the_score_and_the_reason() {
        let event = to_ocsf(&decision(), &identity(), Some("example.org"), "0.1.0");
        assert_eq!(event["class_uid"], 2004);
        assert_eq!(event["risk_score"], 92);
        assert_eq!(event["actor"]["user"]["name"], "agent-7");
        assert_eq!(
            event["actor"]["user"]["uid"],
            "spiffe://example.org/openshell/sandbox/sbx-1"
        );
        assert_eq!(event["actor"]["session"]["uid"], "run-9");
        assert_eq!(event["container"]["uid"], "sbx-1");
        assert_eq!(event["unmapped"]["risk_guard"]["threshold"], 70);
        assert_eq!(
            event["unmapped"]["risk_guard"]["task_profile"],
            "repo-triage-readonly"
        );
        assert_eq!(
            event["unmapped"]["risk_guard"]["signals"][0]["feature"],
            "destructive_action"
        );
        assert_eq!(
            event["status_detail"],
            "risk_guard_denied:behavioral_risk_denied"
        );
        assert_eq!(event["metadata"]["version"], "1.8.0");
    }

    #[test]
    fn without_an_identity_or_trust_domain_the_fields_are_null_not_invented() {
        let event = to_ocsf(&decision(), &SandboxIdentity::default(), None, "0.1.0");
        assert!(event["actor"]["user"]["name"].is_null());
        assert!(event["actor"]["user"]["uid"].is_null());
        assert!(event["unmapped"]["risk_guard"]["agent_id"].is_null());
    }

    #[test]
    fn tunnel_events_say_refused_or_would_refuse_and_flag_a_silent_supervisor() {
        let refused = Occurrence::Tunnel {
            sandbox_id: "sbx-1".into(),
            destination: "evil.example:443".into(),
            refused: true,
            reason: "the sandbox's workload is quarantined".into(),
            silent_for_ms: None,
            at_ms: 1,
        };
        let event = to_ocsf(&refused, &identity(), None, "0.1.0");
        assert_eq!(event["action"], "Denied");
        assert_eq!(event["status_detail"], "risk_guard_tunnel:tunnel_refused");
        let silent = Occurrence::Tunnel {
            sandbox_id: "sbx-1".into(),
            destination: "x:443".into(),
            refused: false,
            reason: "shadow".into(),
            silent_for_ms: Some(700_000),
            at_ms: 1,
        };
        let event = to_ocsf(&silent, &identity(), None, "0.1.0");
        assert_eq!(event["action"], "Allowed");
        assert_eq!(
            event["status_detail"],
            "risk_guard_tunnel:supervisor_silent"
        );
        assert_eq!(event["unmapped"]["risk_guard"]["silent_for_ms"], 700_000);
    }

    #[test]
    fn a_signal_is_an_api_activity_event_with_its_outcome() {
        let signal = Occurrence::Signal {
            signal_id: "s-1".into(),
            source: "opensearch-alerting".into(),
            alert_id: Some("a-1".into()),
            agent_id: Some("agent-7".into()),
            sandbox_id: None,
            outcome: "rate_limited".into(),
            ttl_seconds: 600,
            reason: "test".into(),
            at_ms: 1,
        };
        let event = to_ocsf(&signal, &SandboxIdentity::default(), None, "0.1.0");
        assert_eq!(event["class_uid"], 6003);
        assert_eq!(event["status"], "Failure");
        assert_eq!(
            event["unmapped"]["risk_guard"]["target_agent_id"],
            "agent-7"
        );
    }

    fn rows(taken: &[Occurrence]) -> (Vec<&Occurrence>, Vec<&Occurrence>, Vec<&Occurrence>) {
        let pick = |f: fn(&Occurrence) -> bool| taken.iter().filter(|o| f(o)).collect::<Vec<_>>();
        (
            pick(|o| matches!(o, Occurrence::Activity { .. })),
            pick(|o| matches!(o, Occurrence::Route { .. })),
            pick(|o| matches!(o, Occurrence::Egress { .. })),
        )
    }

    #[test]
    fn counters_give_a_summary_route_rows_and_egress_rows_per_sandbox_and_then_start_again() {
        let counters = ActivityCounters::default();
        counters.record("sbx-1", false, 5, "api", "GET", "/services");
        counters.record("sbx-1", false, 9, "api", "GET", "/services");
        counters.record("sbx-1", true, 100, "api", "DELETE", "/services/{svc}");
        counters.record("sbx-2", false, 1, "api", "GET", "/costs");
        counters.record_tunnel(
            "sbx-1",
            "integrate.api.nvidia.com:443",
            TunnelOutcome::Allowed,
        );
        counters.record_tunnel(
            "sbx-1",
            "integrate.api.nvidia.com:443",
            TunnelOutcome::Allowed,
        );
        counters.record_tunnel("sbx-1", "evil.example:443", TunnelOutcome::Refused);
        counters.record_tunnel(
            "sbx-1",
            "integrate.api.nvidia.com:443",
            TunnelOutcome::Shadow,
        );
        let taken = counters.take(1_000_000);
        let (summaries, routes, egress) = rows(&taken);
        assert_eq!((summaries.len(), routes.len(), egress.len()), (2, 3, 2));

        let Some(Occurrence::Activity {
            allowed,
            refused,
            max_score,
            distinct_routes,
            window_ms,
            ..
        }) = summaries
            .iter()
            .find(|o| sandbox_of(o) == Some("sbx-1"))
            .copied()
        else {
            panic!("a summary for sbx-1")
        };
        assert_eq!(
            (*allowed, *refused, *max_score, *distinct_routes),
            (2, 1, 100, 2)
        );
        assert_eq!(*window_ms, 60_000, "the first window defaults to a minute");

        let Some(Occurrence::Route { allowed, refused, .. }) = routes
            .iter()
            .find(|o| matches!(o, Occurrence::Route { sandbox_id, method, .. } if sandbox_id == "sbx-1" && method == "GET"))
            .copied()
        else {
            panic!("the GET route row")
        };
        assert_eq!((*allowed, *refused), (2, 0));

        let Some(Occurrence::Egress { allowed, refused, shadow, .. }) = egress
            .iter()
            .find(|o| matches!(o, Occurrence::Egress { destination, .. } if destination.starts_with("integrate")))
            .copied()
        else {
            panic!("the model endpoint row")
        };
        assert_eq!((*allowed, *refused, *shadow), (2, 0, 1));

        // Nothing since: nothing is sent, and the next window is measured from the last take.
        assert!(counters.take(1_060_000).is_empty());
        counters.record("sbx-1", false, 0, "api", "GET", "/services");
        let again = counters.take(1_120_000);
        let (summaries, _, _) = rows(&again);
        let Occurrence::Activity {
            window_ms, allowed, ..
        } = summaries[0]
        else {
            panic!("a summary")
        };
        assert_eq!((*window_ms, *allowed), (60_000, 1));
    }

    #[test]
    fn a_sandbox_that_only_opened_tunnels_gets_egress_rows_and_no_decision_summary() {
        let counters = ActivityCounters::default();
        counters.record_tunnel("sbx", "a.example:443", TunnelOutcome::Allowed);
        let taken = counters.take(1);
        let (summaries, routes, egress) = rows(&taken);
        assert_eq!((summaries.len(), routes.len(), egress.len()), (0, 0, 1));
    }

    #[test]
    fn routes_and_destinations_saturate_into_other_instead_of_growing_without_bound() {
        let counters = ActivityCounters::default();
        for n in 0..(MAX_ROUTES + 200) {
            counters.record("sbx", false, 0, "api", "GET", &format!("/p/{n}"));
            counters.record_tunnel("sbx", &format!("h{n}.example:443"), TunnelOutcome::Allowed);
        }
        let taken = counters.take(1);
        let (summaries, routes, egress) = rows(&taken);
        assert_eq!(
            routes.len(),
            MAX_ROUTES + 1,
            "the limit, plus the row that holds the rest"
        );
        assert_eq!(egress.len(), MAX_DESTINATIONS + 1);
        let Occurrence::Activity {
            allowed,
            distinct_routes,
            ..
        } = summaries[0]
        else {
            panic!("a summary")
        };
        assert_eq!(
            *allowed as usize,
            MAX_ROUTES + 200,
            "every decision is still counted"
        );
        assert_eq!(*distinct_routes as usize, MAX_ROUTES + 1);
        let other = routes.iter().find_map(|o| match o {
            Occurrence::Route { route, allowed, .. } if route == "other" => Some(*allowed),
            _ => None,
        });
        assert_eq!(other, Some(200));
    }

    /// OpenSearch fixes a field's type when it first sees it, and rejects a document that later uses the same name for another type. All of Risk Guard's events share
    /// `unmapped.risk_guard.*`, so a key must mean the same JSON type in every kind of event. (An activity summary once used `refused` as a count where tunnel events
    /// use it as a flag; the collector dropped every summary.)
    #[test]
    fn a_key_has_the_same_type_in_every_kind_of_event() {
        let sample = [
            decision(),
            Occurrence::Tunnel {
                sandbox_id: "s".into(),
                destination: "d".into(),
                refused: true,
                reason: "r".into(),
                silent_for_ms: Some(1),
                at_ms: 1,
            },
            Occurrence::Signal {
                signal_id: "i".into(),
                source: "s".into(),
                alert_id: Some("a".into()),
                agent_id: Some("g".into()),
                sandbox_id: Some("s".into()),
                outcome: "applied".into(),
                ttl_seconds: 1,
                reason: "r".into(),
                at_ms: 1,
            },
            Occurrence::Activity {
                sandbox_id: "s".into(),
                window_ms: 60_000,
                allowed: 1,
                refused: 1,
                max_score: 1,
                distinct_routes: 1,
                at_ms: 1,
            },
            Occurrence::Route {
                sandbox_id: "s".into(),
                host: "h".into(),
                method: "GET".into(),
                route: "/r".into(),
                allowed: 1,
                refused: 1,
                max_score: 1,
                at_ms: 1,
            },
            Occurrence::Egress {
                sandbox_id: "s".into(),
                destination: "d:443".into(),
                allowed: 1,
                refused: 1,
                shadow: 1,
                at_ms: 1,
            },
        ];
        let kind = |v: &Value| match v {
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::Null => "null",
        };
        let mut seen: std::collections::HashMap<String, (&str, usize)> =
            std::collections::HashMap::new();
        for (n, occurrence) in sample.iter().enumerate() {
            let event = to_ocsf(occurrence, &identity(), Some("example.org"), "0.1.0");
            // Every top-level key as well as everything under unmapped.risk_guard.
            let mut keys: Vec<(String, &Value)> = event
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v))
                .collect();
            keys.extend(
                event["unmapped"]["risk_guard"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (format!("unmapped.risk_guard.{k}"), v)),
            );
            for (key, value) in keys {
                if value.is_null() {
                    continue;
                }
                if let Some((previous, from)) = seen.insert(key.clone(), (kind(value), n)) {
                    assert_eq!(
                        previous,
                        kind(value),
                        "{key} is a {previous} in event {from} and a {} in event {n}",
                        kind(value)
                    );
                }
            }
        }
    }

    #[test]
    fn recording_a_decision_costs_microseconds_not_milliseconds() {
        let counters = ActivityCounters::default();
        let started = std::time::Instant::now();
        for n in 0..100_000 {
            counters.record(
                "sbx",
                n % 7 == 0,
                10,
                "api",
                "GET",
                if n % 2 == 0 { "/a" } else { "/b" },
            );
        }
        let per_call = started.elapsed() / 100_000;
        println!("record() takes {per_call:?} per decision");
        assert!(
            per_call < Duration::from_micros(20),
            "{per_call:?} per decision is far too slow for the decision path"
        );
    }

    #[test]
    fn the_events_carry_the_workload_by_name_the_counts_and_the_route_or_destination() {
        let summary = Occurrence::Activity {
            sandbox_id: "sbx-1".into(),
            window_ms: 60_000,
            allowed: 8,
            refused: 2,
            max_score: 100,
            distinct_routes: 4,
            at_ms: 5,
        };
        let event = to_ocsf(&summary, &identity(), Some("example.org"), "0.1.0");
        assert_eq!(event["unmapped"]["risk_guard"]["gate"], "summary");
        assert_eq!(event["unmapped"]["risk_guard"]["total"], 10);
        assert_eq!(event["unmapped"]["risk_guard"]["refused_calls"], 2);
        assert_eq!(event["unmapped"]["risk_guard"]["refusal_ratio"], 0.2);
        assert_eq!(event["actor"]["user"]["name"], "agent-7");
        assert_eq!(event["actor"]["user"]["full_name"], "Release bot");

        let route = Occurrence::Route {
            sandbox_id: "sbx-1".into(),
            host: "deploy-api".into(),
            method: "DELETE".into(),
            route: "/services/{svc}".into(),
            allowed: 0,
            refused: 3,
            max_score: 100,
            at_ms: 5,
        };
        let event = to_ocsf(&route, &identity(), None, "0.1.0");
        assert_eq!(event["unmapped"]["risk_guard"]["gate"], "route");
        assert_eq!(event["unmapped"]["risk_guard"]["route"], "/services/{svc}");
        assert_eq!(event["unmapped"]["risk_guard"]["refused_calls"], 3);
        assert_eq!(event["actor"]["user"]["full_name"], "Release bot");

        let egress = Occurrence::Egress {
            sandbox_id: "sbx-1".into(),
            destination: "integrate.api.nvidia.com:443".into(),
            allowed: 4,
            refused: 0,
            shadow: 1,
            at_ms: 5,
        };
        let event = to_ocsf(&egress, &identity(), None, "0.1.0");
        assert_eq!(event["unmapped"]["risk_guard"]["gate"], "egress");
        assert_eq!(
            event["unmapped"]["risk_guard"]["destination"],
            "integrate.api.nvidia.com:443"
        );
        assert_eq!(event["unmapped"]["risk_guard"]["total"], 5);
    }

    #[test]
    fn the_otlp_body_is_the_event_as_a_json_string() {
        let event = to_ocsf(&decision(), &identity(), None, "0.1.0");
        let payload = otlp_payload(std::slice::from_ref(&event));
        let record = &payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(record["timeUnixNano"], "1800000000000000000");
        assert_eq!(record["severityNumber"], 17);
        let body: Value =
            serde_json::from_str(record["body"]["stringValue"].as_str().unwrap()).unwrap();
        assert_eq!(body, event);
    }

    #[tokio::test]
    async fn the_emitter_sends_batches_to_the_collector_and_counts_what_it_cannot() {
        use axum::{Router, extract::State, routing::post};
        let received: Arc<std::sync::Mutex<Vec<Value>>> = Arc::default();
        async fn collect(
            State(received): State<Arc<std::sync::Mutex<Vec<Value>>>>,
            axum::Json(body): axum::Json<Value>,
        ) {
            received.lock().unwrap().push(body);
        }
        let app = Router::new()
            .route("/v1/logs", post(collect))
            .with_state(Arc::clone(&received));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteRiskStore::open(dir.path().join("rg.db")).unwrap());
        let emitter = OcsfEmitter::start(
            OcsfConfig {
                endpoint: format!("http://{address}"),
                trust_domain: None,
                version: "0.1.0".into(),
            },
            store,
        );
        emitter.emit(decision());
        emitter.emit(decision());
        for _ in 0..50 {
            if !received.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let batches = received.lock().unwrap().clone();
        assert_eq!(batches.len(), 1, "both events travel in one batch");
        assert_eq!(
            batches[0]["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(emitter.dropped(), 0);
    }
}
