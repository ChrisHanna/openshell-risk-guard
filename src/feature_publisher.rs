// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The SIEM's feature publisher: every interval it asks OpenSearch what OpenShell and Risk Guard recorded and posts one batch of risk **features** to Risk Guard's `/features`
//! over mutual TLS with the forwarder's own SVID. The contract (vocabulary, body, limits) is `docs/design-siem-features.md`; the operations guide is `docs/siem-features-publisher.md`.
//!
//! Principles it keeps:
//! * Never in Risk Guard's hot path. If OpenSearch or Risk Guard is down the tick is logged and the next interval starts afresh; there is no queue and no backlog.
//! * Never a batch that mislabels data. Each OpenSearch query is independent; if one fails (or returns partial shards, or is truncated) only the features it produces are left out,
//!   and the log says which. A missing feature adds nothing in Risk Guard.
//! * Read-only. Every request is a `_search` against `ocsf-openshell*` with a user whose role can only read those indices.
//!
//! What counts as an OpenShell **denial**: an event from a sandbox (it has `container.uid`) whose `action` is `Denied` and that is either an enforced L7 decision
//! (`firewall_rule.type:"l7"`) or a Network Activity event (a denied connection, a refused DNS name). Risk Guard's own refusals are not counted: the supervisor echoes them as
//! `firewall_rule.type:"middleware"` events, and the gateway's `Authentication` denials carry no `container.uid`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

use crate::error::{Result, RiskGuardError};
use crate::signal_forwarder::{ForwarderConfig, mtls_client};

const SCHEMA: u32 = 1;
/// The batch's `window_seconds`: Risk Guard keeps a value for twice this long.
const WINDOW_SECONDS: u64 = 300;
const MAX_SUBJECTS: usize = 2_000;
/// Risk Guard rejects bodies over 64 KiB; stay clear of it.
const MAX_BODY_BYTES: usize = 60_000;
const MAX_COUNT: u64 = 100_000;
const MAX_PERMILLE: u64 = 1_000;
const TERMS_SIZE: usize = 2_000;
const COMPOSITE_PAGE: usize = 1_000;
/// More distinct (workload, host, route) triples than this and the route features are left out rather than computed from a truncated list.
const COMPOSITE_MAX_PAGES: usize = 30;

const MIN_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MIN_MS;
const DAY_MS: i64 = 24 * HOUR_MS;

// The whole vocabulary (docs/design-siem-features.md).
const DENIALS_5M: &str = "openshell_denials_5m";
const DENIALS_1H: &str = "openshell_denials_1h";
const WOULD_BLOCK_5M: &str = "openshell_would_block_5m";
const REFUSAL_RATIO: &str = "refusal_ratio_15m_permille";
const NEW_ROUTES: &str = "new_routes_1h";
const ROUTES_UNIQUE: &str = "routes_unique_to_workload_permille";
const ANOMALY_GRADE: &str = "anomaly_grade_15m_permille";
const FLEET_DENIALS: &str = "fleet_openshell_denials_5m";
const FLEET_SANDBOXES: &str = "fleet_workloads_with_denials_5m";
const FLEET_REFUSAL_RATIO: &str = "fleet_refusal_ratio_15m_permille";
const FLEET_ACTIVE: &str = "fleet_active_workloads_15m";

/// When the publisher runs on a fast sub-30s tick (e.g. 5s for near-real-time denial/anomaly ingestion), reuse the heavy 7-day composite
/// route scan for up to 25 seconds so OpenSearch is not hit with a 7-day scan every 5 seconds.
const FAST_ROUTE_CACHE_MS: i64 = 25_000;

type RouteCacheEntry = (i64, Vec<RouteSeen>);

fn route_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, RouteCacheEntry>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, RouteCacheEntry>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

type Features = BTreeMap<&'static str, u64>;

/// Clamp a value to the range the contract states for the feature (names ending `permille` are 0 to 1,000, everything else 0 to 100,000).
fn clamp(name: &str, value: u64) -> u64 {
    value.min(if name.ends_with("permille") {
        MAX_PERMILLE
    } else {
        MAX_COUNT
    })
}

fn permille(part: u64, whole: u64) -> Option<u64> {
    (whole > 0).then(|| {
        let scaled = (u128::from(part) * 1000 + u128::from(whole) / 2) / u128::from(whole);
        u64::try_from(scaled).unwrap_or(u64::MAX)
    })
}

fn count(value: &Value) -> u64 {
    let number = value.as_f64().unwrap_or(0.0);
    if number.is_finite() && number > 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            number.round() as u64
        }
    } else {
        0
    }
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
// The queries. Each `*_query` builds the exact request body; each `parse_*` reads the response. They are pure so they are unit tested against canned responses.
// All of them search `ocsf-openshell*`, set `size: 0` (only aggregations are wanted) and carry a server-side timeout.
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

fn time_since(ms: i64) -> Value {
    json!({"range": {"time": {"gte": ms}}})
}

/// OpenShell policy denials by a sandbox. See the module comment for what is and is not counted.
fn denial_filter() -> Vec<Value> {
    vec![
        json!({"term": {"action.keyword": "Denied"}}),
        json!({"exists": {"field": "container.uid"}}),
        json!({"bool": {"should": [
            {"term": {"firewall_rule.type.keyword": "l7"}},
            {"term": {"class_name.keyword": "Network Activity"}}
        ], "minimum_should_match": 1, "must_not": [
            {"term": {"firewall_rule.type.keyword": "middleware"}}
        ]}}),
    ]
}

/// Produces `openshell_denials_1h` and `openshell_denials_5m` (per sandbox, and per its SPIFFE ID).
/// One search: denial events in the last hour, bucketed by sandbox (`container.uid`); a nested `filter` aggregation counts the ones in the last five minutes.
///
/// ```text
/// POST ocsf-openshell*/_search   query: time >= now-1h AND <denial filter>
///   aggs: by_sandbox = terms(container.uid.keyword, size 2000) { last_5m = filter(time >= now-5m) }
/// ```
fn sandbox_denials_query(now_ms: i64) -> Value {
    let mut filter = vec![time_since(now_ms - HOUR_MS)];
    filter.extend(denial_filter());
    json!({
        "size": 0, "timeout": "10s", "track_total_hits": false,
        "query": {"bool": {"filter": filter}},
        "aggs": {"by_sandbox": {
            "terms": {"field": "container.uid.keyword", "size": TERMS_SIZE},
            "aggs": {"last_5m": {"filter": time_since(now_ms - 5 * MIN_MS)}}
        }}
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
struct SandboxDenials {
    /// sandbox id -> (denials in the last hour, denials in the last five minutes)
    per_sandbox: BTreeMap<String, (u64, u64)>,
    /// More sandboxes than the terms size: the quietest were not listed.
    truncated: bool,
}

fn parse_sandbox_denials(response: &Value) -> std::result::Result<SandboxDenials, String> {
    let aggregation = response["aggregations"]["by_sandbox"]
        .as_object()
        .ok_or("no by_sandbox aggregation in the response")?;
    let buckets = aggregation
        .get("buckets")
        .and_then(Value::as_array)
        .ok_or("by_sandbox has no buckets array")?;
    let mut out = SandboxDenials {
        truncated: count(
            &aggregation
                .get("sum_other_doc_count")
                .cloned()
                .unwrap_or_default(),
        ) > 0,
        ..SandboxDenials::default()
    };
    for bucket in buckets {
        let id = bucket["key"]
            .as_str()
            .ok_or("a bucket without a string key")?;
        out.per_sandbox.insert(
            id.to_string(),
            (
                count(&bucket["doc_count"]),
                count(&bucket["last_5m"]["doc_count"]),
            ),
        );
    }
    Ok(out)
}

/// Produces `openshell_would_block_5m` (per sandbox, and per its SPIFFE ID): requests an audit-mode policy logged as violations.
/// OpenShell writes them as `L7_REQUEST audit ... not permitted by policy`; the phrase is matched on the analysed `message` field.
///
/// ```text
/// POST ocsf-openshell*/_search   query: time >= now-5m AND match_phrase(message, "L7_REQUEST audit") AND exists(container.uid)
///   aggs: by_sandbox = terms(container.uid.keyword, size 2000)
/// ```
fn would_block_query(now_ms: i64) -> Value {
    json!({
        "size": 0, "timeout": "10s", "track_total_hits": false,
        "query": {"bool": {"filter": [
            time_since(now_ms - 5 * MIN_MS),
            {"match_phrase": {"message": "L7_REQUEST audit"}},
            {"exists": {"field": "container.uid"}}
        ]}},
        "aggs": {"by_sandbox": {"terms": {"field": "container.uid.keyword", "size": TERMS_SIZE}}}
    })
}

fn parse_would_block(response: &Value) -> std::result::Result<BTreeMap<String, u64>, String> {
    let buckets = response["aggregations"]["by_sandbox"]["buckets"]
        .as_array()
        .ok_or("no by_sandbox buckets in the response")?;
    buckets
        .iter()
        .map(|bucket| {
            Ok((
                bucket["key"]
                    .as_str()
                    .ok_or("a bucket without a string key")?
                    .to_string(),
                count(&bucket["doc_count"]),
            ))
        })
        .collect()
}

/// Produces `fleet_openshell_denials_5m` (the number of denial events) and `fleet_workloads_with_denials_5m` (distinct sandboxes among them), across all sandboxes.
/// Separate from the per-sandbox search so the fleet numbers stay exact when there are more sandboxes than the per-sandbox list holds.
///
/// ```text
/// POST ocsf-openshell*/_search   query: time >= now-5m AND <denial filter>   (track_total_hits: true)
///   aggs: sandboxes = cardinality(container.uid.keyword, precision_threshold 3000)
/// ```
fn fleet_denials_query(now_ms: i64) -> Value {
    let mut filter = vec![time_since(now_ms - 5 * MIN_MS)];
    filter.extend(denial_filter());
    json!({
        "size": 0, "timeout": "10s", "track_total_hits": true,
        "query": {"bool": {"filter": filter}},
        "aggs": {"sandboxes": {"cardinality": {"field": "container.uid.keyword", "precision_threshold": 3000}}}
    })
}

fn parse_fleet_denials(response: &Value) -> std::result::Result<(u64, u64), String> {
    let total = response["hits"]["total"]["value"]
        .as_u64()
        .ok_or("no hits.total.value in the response")?;
    let sandboxes = response["aggregations"]["sandboxes"]["value"]
        .as_f64()
        .ok_or("no sandboxes cardinality in the response")?;
    Ok((total, count(&json!(sandboxes))))
}

/// Produces `refusal_ratio_15m_permille` (per workload), `fleet_refusal_ratio_15m_permille` and `fleet_active_workloads_15m`.
/// Risk Guard writes a per-minute summary for each sandbox that made decisions (`gate: summary`) with `refused_calls` and `total`; refusals over decisions is the ratio.
/// A workload that made no decisions has no ratio (not zero).
///
/// ```text
/// POST ocsf-openshell*/_search   query: time >= now-15m AND unmapped.risk_guard.gate = "summary"
///   aggs: by_workload  = terms(unmapped.risk_guard.agent_id.keyword, size 2000) { refused = sum(refused_calls), total = sum(total) }
///         fleet_refused = sum(refused_calls), fleet_total = sum(total)
///         active        = filter(total > 0) { workloads = cardinality(agent_id.keyword, precision_threshold 3000) }
/// ```
fn refusals_query(now_ms: i64) -> Value {
    json!({
        "size": 0, "timeout": "10s", "track_total_hits": false,
        "query": {"bool": {"filter": [
            time_since(now_ms - 15 * MIN_MS),
            {"term": {"unmapped.risk_guard.gate.keyword": "summary"}}
        ]}},
        "aggs": {
            "by_workload": {
                "terms": {"field": "unmapped.risk_guard.agent_id.keyword", "size": TERMS_SIZE},
                "aggs": {
                    "refused": {"sum": {"field": "unmapped.risk_guard.refused_calls"}},
                    "total": {"sum": {"field": "unmapped.risk_guard.total"}}
                }
            },
            "fleet_refused": {"sum": {"field": "unmapped.risk_guard.refused_calls"}},
            "fleet_total": {"sum": {"field": "unmapped.risk_guard.total"}},
            "active": {
                "filter": {"range": {"unmapped.risk_guard.total": {"gt": 0}}},
                "aggs": {"workloads": {"cardinality": {"field": "unmapped.risk_guard.agent_id.keyword", "precision_threshold": 3000}}}
            }
        }
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Refusals {
    per_workload: BTreeMap<String, u64>,
    fleet_ratio: Option<u64>,
    fleet_active: u64,
    truncated: bool,
}

fn parse_refusals(response: &Value) -> std::result::Result<Refusals, String> {
    let aggregations = &response["aggregations"];
    let buckets = aggregations["by_workload"]["buckets"]
        .as_array()
        .ok_or("no by_workload buckets in the response")?;
    let mut out = Refusals {
        truncated: count(&aggregations["by_workload"]["sum_other_doc_count"]) > 0,
        ..Refusals::default()
    };
    for bucket in buckets {
        let id = bucket["key"]
            .as_str()
            .ok_or("a bucket without a string key")?;
        if let Some(ratio) = permille(
            count(&bucket["refused"]["value"]),
            count(&bucket["total"]["value"]),
        ) {
            out.per_workload.insert(id.to_string(), ratio);
        }
    }
    out.fleet_ratio = permille(
        count(&aggregations["fleet_refused"]["value"]),
        count(&aggregations["fleet_total"]["value"]),
    );
    out.fleet_active = count(&aggregations["active"]["workloads"]["value"]);
    Ok(out)
}

/// Produces `new_routes_1h` and `routes_unique_to_workload_permille` (per workload).
/// Risk Guard writes a route event (`gate: route`) for each (host, method, route) a workload called in a minute. One composite aggregation lists every (workload, host, route) seen
/// from seven days and one hour ago until now with the first and last time it was seen; both features are worked out from that list in [`route_features`].
/// The list is paged; if it does not fit in [`COMPOSITE_MAX_PAGES`] pages the route features are left out for this tick.
///
/// ```text
/// POST ocsf-openshell*/_search   query: time >= now-7d-1h AND unmapped.risk_guard.gate = "route"
///   aggs: pairs = composite(size 1000; agent_id.keyword, host.keyword, route.keyword) { first = min(time), last = max(time) }   (paged with "after")
/// ```
fn routes_query(now_ms: i64, after: Option<&Value>) -> Value {
    let mut composite = json!({
        "size": COMPOSITE_PAGE,
        "sources": [
            {"workload": {"terms": {"field": "unmapped.risk_guard.agent_id.keyword"}}},
            {"host": {"terms": {"field": "unmapped.risk_guard.host.keyword"}}},
            {"route": {"terms": {"field": "unmapped.risk_guard.route.keyword"}}}
        ]
    });
    if let Some(after) = after {
        composite["after"] = after.clone();
    }
    json!({
        "size": 0, "timeout": "20s", "track_total_hits": false,
        "query": {"bool": {"filter": [
            time_since(now_ms - 7 * DAY_MS - HOUR_MS),
            {"term": {"unmapped.risk_guard.gate.keyword": "route"}}
        ]}},
        "aggs": {"pairs": {
            "composite": composite,
            "aggs": {"first": {"min": {"field": "time"}}, "last": {"max": {"field": "time"}}}
        }}
    })
}

/// One (workload, host, route) and when it was first and last seen in the window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteSeen {
    workload: String,
    host: String,
    route: String,
    first_ms: i64,
    last_ms: i64,
}

/// A page of the composite aggregation: the entries and the key to continue from (None on the last page).
fn parse_routes_page(
    response: &Value,
) -> std::result::Result<(Vec<RouteSeen>, Option<Value>), String> {
    let pairs = &response["aggregations"]["pairs"];
    let buckets = pairs["buckets"]
        .as_array()
        .ok_or("no pairs buckets in the response")?;
    let mut seen = Vec::with_capacity(buckets.len());
    for bucket in buckets {
        let key = &bucket["key"];
        let text = |name: &str| key[name].as_str().map(str::to_string);
        let (Some(workload), Some(host), Some(route)) =
            (text("workload"), text("host"), text("route"))
        else {
            return Err("a composite key without workload, host and route".into());
        };
        #[allow(clippy::cast_possible_truncation)]
        let ms = |name: &str| bucket[name]["value"].as_f64().map(|v| v as i64);
        let (Some(first_ms), Some(last_ms)) = (ms("first"), ms("last")) else {
            return Err("a composite bucket without first/last times".into());
        };
        seen.push(RouteSeen {
            workload,
            host,
            route,
            first_ms,
            last_ms,
        });
    }
    let after = (buckets.len() >= COMPOSITE_PAGE)
        .then(|| pairs["after_key"].clone())
        .filter(|after| !after.is_null());
    Ok((seen, after))
}

/// `new_routes_1h`: (host, route) pairs whose first sighting in the window is within the last hour, so the workload did not use them in the seven days before.
/// `routes_unique_to_workload_permille`: of the pairs a workload used in the last 24 hours, the share no other workload used in those 24 hours.
fn route_features(seen: &[RouteSeen], now_ms: i64) -> BTreeMap<String, Features> {
    let mut by_workload: BTreeMap<&str, Features> = BTreeMap::new();
    let mut owners: BTreeMap<(&str, &str), BTreeSet<&str>> = BTreeMap::new();
    let mut routes_24h: BTreeMap<&str, u64> = BTreeMap::new();
    for entry in seen {
        let features = by_workload.entry(&entry.workload).or_default();
        let new = u64::from(entry.first_ms >= now_ms - HOUR_MS);
        *features.entry(NEW_ROUTES).or_insert(0) += new;
        if entry.last_ms >= now_ms - DAY_MS {
            *routes_24h.entry(&entry.workload).or_insert(0) += 1;
            owners
                .entry((&entry.host, &entry.route))
                .or_default()
                .insert(&entry.workload);
        }
    }
    let mut unique: BTreeMap<&str, u64> = BTreeMap::new();
    for entry in seen {
        if entry.last_ms >= now_ms - DAY_MS
            && owners
                .get(&(entry.host.as_str(), entry.route.as_str()))
                .is_some_and(|set| set.len() == 1)
        {
            *unique.entry(&entry.workload).or_insert(0) += 1;
        }
    }
    for (workload, features) in &mut by_workload {
        // A workload with no route in the last 24 hours has no share to report.
        if let Some(ratio) = permille(
            unique.get(workload).copied().unwrap_or(0),
            routes_24h.get(workload).copied().unwrap_or(0),
        ) {
            features.insert(ROUTES_UNIQUE, ratio);
        }
    }
    by_workload
        .into_iter()
        .map(|(id, features)| (id.to_string(), features))
        .collect()
}

/// Produces `anomaly_grade_15m_permille` (per workload) from OpenSearch's Anomaly Detection plugin (`workload-activity-by-agent`).
/// Queries `/_plugins/_anomaly_detection/detectors/results/_search` for anomaly results in the last 15 minutes with `anomaly_grade > 0`.
pub fn anomaly_grades_query(now_ms: i64) -> Value {
    json!({
        "size": 1000,
        "timeout": "10s",
        "_source": ["entity", "data_end_time", "anomaly_grade"],
        "query": {"bool": {"filter": [
            {"range": {"data_end_time": {"gte": now_ms - 15 * MIN_MS}}},
            {"range": {"anomaly_grade": {"gt": 0.0}}}
        ]}}
    })
}

/// Parse OpenSearch Anomaly Detection results into `workload_id -> max(anomaly_grade * 1000)` in permille (`0..=1000`).
/// Supports both `_source` hits (from `/_plugins/_anomaly_detection/detectors/results/_search`) and `by_workload` aggregation buckets.
pub fn parse_anomaly_grades(response: &Value) -> std::result::Result<BTreeMap<String, u64>, String> {
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    let to_permille = |grade: f64| -> u64 {
        if grade.is_finite() && grade > 0.0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                ((grade * 1000.0).round() as u64).min(MAX_PERMILLE)
            }
        } else {
            0
        }
    };
    if let Some(buckets) = response["aggregations"]["by_workload"]["buckets"].as_array() {
        for bucket in buckets {
            let Some(id) = bucket["key"].as_str() else {
                continue;
            };
            let grade = bucket["max_grade"]["value"].as_f64().unwrap_or(0.0);
            let permille = to_permille(grade);
            if permille > 0 {
                let entry = out.entry(id.to_string()).or_default();
                *entry = (*entry).max(permille);
            }
        }
        return Ok(out);
    }
    let hits = response["hits"]["hits"]
        .as_array()
        .ok_or("no hits.hits or aggregations.by_workload in anomaly detection response")?;
    for hit in hits {
        let source = &hit["_source"];
        let entity = source["entity"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|e| e["value"].as_str());
        let Some(workload) = entity else {
            continue;
        };
        let grade = source["anomaly_grade"].as_f64().unwrap_or(0.0);
        let permille = to_permille(grade);
        if permille > 0 {
            let entry = out.entry(workload.to_string()).or_default();
            *entry = (*entry).max(permille);
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Collecting and building the batch
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

/// Everything one tick learned. A query that failed contributes nothing and is named in `failed`.
#[derive(Debug, Default)]
pub struct Collected {
    sandboxes: BTreeMap<String, Features>,
    workloads: BTreeMap<String, Features>,
    fleet: Features,
    /// (query name, reason)
    pub failed: Vec<(&'static str, String)>,
    /// Queries whose results were cut off by a size limit (the features of the omitted subjects are missing, nothing is mislabeled).
    pub truncated: Vec<&'static str>,
}

impl Collected {
    fn absorb_sandbox_denials(&mut self, parsed: SandboxDenials) {
        if parsed.truncated {
            self.truncated.push("sandbox_denials");
        }
        for (id, (hour, five)) in parsed.per_sandbox {
            let features = self.sandboxes.entry(id).or_default();
            features.insert(DENIALS_1H, hour);
            features.insert(DENIALS_5M, five);
        }
    }

    fn absorb_would_block(&mut self, parsed: BTreeMap<String, u64>) {
        for (id, n) in parsed {
            self.sandboxes
                .entry(id)
                .or_default()
                .insert(WOULD_BLOCK_5M, n);
        }
    }

    fn absorb_fleet_denials(&mut self, (events, sandboxes): (u64, u64)) {
        self.fleet.insert(FLEET_DENIALS, events);
        self.fleet.insert(FLEET_SANDBOXES, sandboxes);
    }

    fn absorb_refusals(&mut self, parsed: Refusals) {
        if parsed.truncated {
            self.truncated.push("refusals");
        }
        for (id, ratio) in parsed.per_workload {
            self.workloads
                .entry(id)
                .or_default()
                .insert(REFUSAL_RATIO, ratio);
        }
        if let Some(ratio) = parsed.fleet_ratio {
            self.fleet.insert(FLEET_REFUSAL_RATIO, ratio);
        }
        self.fleet.insert(FLEET_ACTIVE, parsed.fleet_active);
    }

    fn absorb_routes(&mut self, parsed: BTreeMap<String, Features>) {
        for (id, features) in parsed {
            self.workloads.entry(id).or_default().extend(features);
        }
    }

    fn absorb_anomaly_grades(&mut self, parsed: BTreeMap<String, u64>) {
        for (id, grade_permille) in parsed {
            if grade_permille > 0 {
                self.workloads
                    .entry(id)
                    .or_default()
                    .insert(ANOMALY_GRADE, grade_permille.min(MAX_PERMILLE));
            }
        }
    }

    /// True when no query produced anything (there is nothing honest to send).
    fn is_empty(&self) -> bool {
        self.sandboxes.is_empty() && self.workloads.is_empty() && self.fleet.is_empty()
    }
}

/// Where OpenSearch is, with the read-only credentials. The files are read for every tick, so a rotated Secret is picked up without a restart.
#[derive(Clone)]
pub struct OpenSearchAccess {
    pub url: String,
    pub user_file: PathBuf,
    pub password_file: PathBuf,
    /// A CA to trust for OpenSearch's certificate. Without one the system roots are used.
    pub ca_file: Option<PathBuf>,
    /// Demo only: do not verify OpenSearch's self-signed certificate (the collector does the same). The traffic stays inside the siem namespace and is fenced by NetworkPolicy.
    pub insecure: bool,
}

struct SearchClient {
    http: reqwest::Client,
    url: String,
    user: String,
    password: String,
}

impl SearchClient {
    fn new(access: &OpenSearchAccess) -> Result<Self> {
        let read = |path: &PathBuf, what: &str| {
            std::fs::read_to_string(path)
                .map(|text| text.trim_end_matches(['\n', '\r']).to_string())
                .map_err(|error| {
                    RiskGuardError::Internal(format!(
                        "cannot read the OpenSearch {what} ({}): {error}",
                        path.display()
                    ))
                })
        };
        let user = read(&access.user_file, "user name")?;
        let password = read(&access.password_file, "password")?;
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(access.insecure);
        if let Some(ca) = &access.ca_file {
            let pem = std::fs::read(ca).map_err(|error| {
                RiskGuardError::Internal(format!("cannot read the OpenSearch CA: {error}"))
            })?;
            builder = builder
                .add_root_certificate(reqwest::Certificate::from_pem(&pem).map_err(|error| {
                    RiskGuardError::Internal(format!("OpenSearch CA: {error}"))
                })?);
        }
        Ok(Self {
            http: builder
                .build()
                .map_err(|error| RiskGuardError::Internal(format!("OpenSearch client: {error}")))?,
            url: access.url.trim_end_matches('/').to_string(),
            user,
            password,
        })
    }

    /// One read-only `_search`. A non-200 answer, a timeout, or any failed shard is an error: a partial answer would be a wrong number.
    async fn search(&self, body: &Value) -> std::result::Result<Value, String> {
        let response = self
            .http
            .post(format!("{}/ocsf-openshell*/_search", self.url))
            .basic_auth(&self.user, Some(&self.password))
            .json(body)
            .send()
            .await
            .map_err(|error| format!("request failed: {}", error_chain(&error)))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| format!("reading the response: {error}"))?;
        if !status.is_success() {
            return Err(format!("HTTP {status}: {}", snippet(&text)));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|error| format!("not JSON: {error}"))?;
        if value["timed_out"].as_bool().unwrap_or(false) {
            return Err("OpenSearch reported timed_out".into());
        }
        if value["_shards"]["failed"].as_u64().unwrap_or(0) > 0 {
            return Err("some shards failed, so the answer is partial".into());
        }
        Ok(value)
    }

    /// All pages of the route list, or an error if it is too large to read whole.
    /// On fast ticks (`0 < now_ms - cached_at_ms < FAST_ROUTE_CACHE_MS`), returns `(seen, true)` from the in-memory cache so the 7-day
    /// composite scan does not run on every 5-second tick.
    async fn route_list(
        &self,
        now_ms: i64,
    ) -> std::result::Result<(Vec<RouteSeen>, bool), String> {
        if let Ok(cache) = route_cache().lock()
            && let Some((cached_at, cached_seen)) = cache.get(&self.url)
            && now_ms > *cached_at
            && now_ms.saturating_sub(*cached_at) < FAST_ROUTE_CACHE_MS
        {
            return Ok((cached_seen.clone(), true));
        }
        let mut seen = Vec::new();
        let mut after: Option<Value> = None;
        for _ in 0..COMPOSITE_MAX_PAGES {
            let response = self.search(&routes_query(now_ms, after.as_ref())).await?;
            let (page, next) = parse_routes_page(&response)?;
            seen.extend(page);
            match next {
                Some(key) => after = Some(key),
                None => {
                    if let Ok(mut cache) = route_cache().lock() {
                        if cache.len() >= 32 {
                            cache.clear();
                        }
                        cache.insert(self.url.clone(), (now_ms, seen.clone()));
                    }
                    return Ok((seen, false));
                }
            }
        }
        Err(format!(
            "more than {} workload/host/route combinations in seven days; not computed from a truncated list",
            COMPOSITE_MAX_PAGES * COMPOSITE_PAGE
        ))
    }

    /// Query OpenSearch's Anomaly Detection plugin for recent per-workload anomaly grades (`0..=1000` permille).
    /// If the plugin endpoint is absent (404) or not permitted for the read-only index user (403), returns an empty map without failing the tick.
    async fn anomaly_grades(&self, now_ms: i64) -> std::result::Result<BTreeMap<String, u64>, String> {
        let response = self
            .http
            .post(format!(
                "{}/_plugins/_anomaly_detection/detectors/results/_search",
                self.url
            ))
            .basic_auth(&self.user, Some(&self.password))
            .json(&anomaly_grades_query(now_ms))
            .send()
            .await
            .map_err(|error| format!("request failed: {}", error_chain(&error)))?;
        let status = response.status();
        if matches!(status.as_u16(), 403 | 404) {
            return Ok(BTreeMap::new());
        }
        let text = response
            .text()
            .await
            .map_err(|error| format!("reading the response: {error}"))?;
        if !status.is_success() {
            return Err(format!("HTTP {status}: {}", snippet(&text)));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|error| format!("not JSON: {error}"))?;
        if value["timed_out"].as_bool().unwrap_or(false) {
            return Err("OpenSearch anomaly detection search timed_out".into());
        }
        parse_anomaly_grades(&value)
    }
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}

fn snippet(text: &str) -> String {
    text.chars()
        .take(200)
        .collect::<String>()
        .replace('\n', " ")
}

/// Run every query (concurrently; they are independent) and gather what they produce.
async fn collect(client: &SearchClient, now_ms: i64) -> Collected {
    let (sandbox_denials, would_block, fleet_denials, refusals, routes, anomalies) = tokio::join!(
        async {
            let response = client.search(&sandbox_denials_query(now_ms)).await?;
            parse_sandbox_denials(&response)
        },
        async {
            let response = client.search(&would_block_query(now_ms)).await?;
            parse_would_block(&response)
        },
        async {
            let response = client.search(&fleet_denials_query(now_ms)).await?;
            parse_fleet_denials(&response)
        },
        async {
            let response = client.search(&refusals_query(now_ms)).await?;
            parse_refusals(&response)
        },
        async { client.route_list(now_ms).await },
        async { client.anomaly_grades(now_ms).await },
    );
    let mut collected = Collected::default();
    let any_live_query_ok = sandbox_denials.is_ok()
        || would_block.is_ok()
        || fleet_denials.is_ok()
        || refusals.is_ok();
    match sandbox_denials {
        Ok(parsed) => collected.absorb_sandbox_denials(parsed),
        Err(reason) => collected.failed.push(("sandbox_denials", reason)),
    }
    match would_block {
        Ok(parsed) => collected.absorb_would_block(parsed),
        Err(reason) => collected.failed.push(("would_block", reason)),
    }
    match fleet_denials {
        Ok(parsed) => collected.absorb_fleet_denials(parsed),
        Err(reason) => collected.failed.push(("fleet_denials", reason)),
    }
    match refusals {
        Ok(parsed) => collected.absorb_refusals(parsed),
        Err(reason) => collected.failed.push(("refusals", reason)),
    }
    match routes {
        Ok((seen, from_cache)) => {
            if !from_cache || any_live_query_ok {
                collected.absorb_routes(route_features(&seen, now_ms));
            }
        }
        Err(reason) => collected.failed.push(("routes", reason)),
    }
    if let Ok(grades) = anomalies
        && any_live_query_ok
    {
        collected.absorb_anomaly_grades(grades);
    }
    collected
}

/// A batch ready to post.
#[derive(Debug)]
pub struct Batch {
    pub body: Vec<u8>,
    pub subjects: usize,
    /// Subjects left out to respect the 2,000-subject and size limits (the quietest go first).
    pub dropped: usize,
}

fn subject_json(kind: &str, id: &str, features: &Features) -> Value {
    let clamped: BTreeMap<&str, u64> = features
        .iter()
        .map(|(name, value)| (*name, clamp(name, *value)))
        .collect();
    json!({"kind": kind, "id": id, "features": clamped})
}

/// Build the batch: sandbox and workload subjects that have a non-zero feature (a sandbox also under its SPIFFE ID when `trust_domain` lets it be derived as
/// `ocsf::spiffe_id` does), and the fleet subject, which is always sent while any fleet feature exists. Returns `None` when nothing was learned at all.
pub fn build_batch(
    collected: &Collected,
    trust_domain: Option<&str>,
    now_ms: i64,
) -> Option<Batch> {
    if collected.is_empty() {
        return None;
    }
    let nonzero = |features: &Features| features.values().any(|value| clamp("", *value) > 0);
    // (weight for dropping, json)
    let mut subjects: Vec<(u64, Value)> = Vec::new();
    for (id, features) in &collected.sandboxes {
        if !nonzero(features) {
            continue;
        }
        let weight: u64 = features.values().sum();
        subjects.push((weight, subject_json("sandbox", id, features)));
        if let Some(spiffe) = crate::ocsf::spiffe_id(id, trust_domain) {
            subjects.push((weight, subject_json("spiffe", &spiffe, features)));
        }
    }
    for (id, features) in &collected.workloads {
        if nonzero(features) {
            let weight: u64 = features.values().sum();
            subjects.push((weight, subject_json("workload", id, features)));
        }
    }
    let fleet =
        (!collected.fleet.is_empty()).then(|| subject_json("fleet", "fleet", &collected.fleet));
    // Busiest first, so any cut removes the quietest. The sort is stable and the maps are ordered, so the result is deterministic.
    subjects.sort_by_key(|(weight, _)| std::cmp::Reverse(*weight));
    let mut kept: Vec<Value> = Vec::new();
    let mut bytes = 256
        + fleet
            .as_ref()
            .map_or(0, |value| value.to_string().len() + 1);
    let room = MAX_SUBJECTS - usize::from(fleet.is_some());
    let mut dropped = 0;
    for (_, subject) in subjects {
        let size = subject.to_string().len() + 1;
        if kept.len() >= room || bytes + size > MAX_BODY_BYTES {
            dropped += 1;
            continue;
        }
        bytes += size;
        kept.push(subject);
    }
    kept.extend(fleet);
    let body = json!({
        "schema": SCHEMA, "generated_at_ms": now_ms, "window_seconds": WINDOW_SECONDS,
        "subjects": kept,
    });
    Some(Batch {
        subjects: kept_len(&body),
        body: serde_json::to_vec(&body).ok()?,
        dropped,
    })
}

fn kept_len(body: &Value) -> usize {
    body["subjects"].as_array().map_or(0, Vec::len)
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
// The loop
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct PublisherConfig {
    /// The full URL of Risk Guard's feature endpoint, e.g. `https://risk-guard.openshell.svc:50063/features`.
    pub target: String,
    pub svid_cert: PathBuf,
    pub svid_key: PathBuf,
    pub server_ca: PathBuf,
    pub opensearch: OpenSearchAccess,
    /// The SPIFFE trust domain sandboxes' IDs are issued in. Without it (and without `trust_domain_from_svid`) no `spiffe` subjects are sent.
    pub trust_domain: Option<String>,
    /// Take the trust domain from this pod's own SVID (SPIRE gives the publisher and the sandboxes the same trust domain), when `trust_domain` is not given.
    pub trust_domain_from_svid: bool,
    pub interval: Duration,
}

/// Running totals, written to the log on every tick (the counters are the publisher's health surface).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    pub ticks: u64,
    pub batches_accepted: u64,
    /// Risk Guard answered with a non-success status.
    pub batches_refused: u64,
    /// Of those, answered 429 (the rate limit).
    pub batches_rate_limited: u64,
    /// Risk Guard could not be reached (or the SVID was unusable).
    pub risk_guard_unreachable: u64,
    pub ticks_without_batch: u64,
    pub query_failures: u64,
    pub subjects_dropped: u64,
}

fn now_ms() -> i64 {
    crate::store::now_wall_ms()
}

/// Run the queries once and return the batch that would be posted, as pretty JSON, plus a line per failed query. Posts nothing and needs no SVID.
/// (`validate` mode of the CLI: used to check the queries against a live OpenSearch before the publisher is deployed.)
pub async fn dry_run(
    access: &OpenSearchAccess,
    trust_domain: Option<&str>,
    now_ms: i64,
) -> Result<String> {
    let client = SearchClient::new(access)?;
    let collected = collect(&client, now_ms).await;
    let mut out = String::new();
    for (query, reason) in &collected.failed {
        out.push_str(&format!(
            "query {query} FAILED: {reason}
"
        ));
    }
    for query in &collected.truncated {
        out.push_str(&format!(
            "query {query} was truncated
"
        ));
    }
    match build_batch(&collected, trust_domain, now_ms) {
        Some(batch) => {
            let body: Value = serde_json::from_slice(&batch.body).unwrap_or(Value::Null);
            out.push_str(&format!(
                "subjects: {} (left out for limits: {}), body {} bytes
{}",
                batch.subjects,
                batch.dropped,
                batch.body.len(),
                serde_json::to_string_pretty(&body).unwrap_or_default()
            ));
        }
        None => out.push_str("nothing was learned; no batch would be sent"),
    }
    Ok(out)
}

/// The trust domain for SPIFFE subjects: the one given, else the one in this pod's own SVID (read each tick, like the SVID itself), else none.
fn resolve_trust_domain(config: &PublisherConfig) -> Option<String> {
    if config.trust_domain.is_some() || !config.trust_domain_from_svid {
        return config.trust_domain.clone();
    }
    let parsed = std::fs::read(&config.svid_cert)
        .map_err(|error| error.to_string())
        .and_then(|pem| crate::spiffe::spiffe_id_from_pem(&pem).map_err(|error| error.to_string()));
    match parsed {
        Ok(id) => Some(id.trust_domain().to_string()),
        Err(error) => {
            tracing::warn!(%error, "feature-publisher: cannot read the trust domain from the SVID; no spiffe subjects this interval");
            None
        }
    }
}

/// One tick: query, build, post. Nothing is carried to the next tick.
pub async fn tick(config: &PublisherConfig, counters: &mut Counters, now_ms: i64) {
    counters.ticks += 1;
    let trust_domain = resolve_trust_domain(config);
    let collected = match SearchClient::new(&config.opensearch) {
        Ok(client) => collect(&client, now_ms).await,
        Err(error) => {
            // Every feature depends on OpenSearch, so every feature is omitted.
            let mut all = Collected::default();
            for name in [
                "sandbox_denials",
                "would_block",
                "fleet_denials",
                "refusals",
                "routes",
            ] {
                all.failed.push((name, error.to_string()));
            }
            all
        }
    };
    counters.query_failures += collected.failed.len() as u64;
    for (query, reason) in &collected.failed {
        tracing::warn!(query, %reason, "feature-publisher: query failed; its features are left out of this batch");
    }
    for query in &collected.truncated {
        tracing::warn!(
            query,
            "feature-publisher: more subjects than the query returns; the quietest are not reported"
        );
    }
    let Some(batch) = build_batch(&collected, trust_domain.as_deref(), now_ms) else {
        counters.ticks_without_batch += 1;
        tracing::warn!(
            ?counters,
            "feature-publisher: nothing was learned this interval; no batch sent"
        );
        return;
    };
    counters.subjects_dropped += batch.dropped as u64;
    if batch.dropped > 0 {
        tracing::warn!(
            dropped = batch.dropped,
            "feature-publisher: subjects left out to stay within the batch limits"
        );
    }
    let forwarder = ForwarderConfig {
        target: config.target.clone(),
        svid_cert: config.svid_cert.clone(),
        svid_key: config.svid_key.clone(),
        server_ca: config.server_ca.clone(),
    };
    let client = match mtls_client(&forwarder) {
        Ok(client) => client,
        Err(error) => {
            counters.risk_guard_unreachable += 1;
            tracing::error!(%error, ?counters, "feature-publisher: no usable identity; batch dropped, will try again next interval");
            return;
        }
    };
    let sent = client
        .post(&config.target)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(batch.body)
        .send()
        .await;
    match sent {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            if status.is_success() {
                counters.batches_accepted += 1;
                tracing::info!(subjects = batch.subjects, answer = %snippet(&text), ?counters, "feature-publisher: batch accepted");
            } else {
                counters.batches_refused += 1;
                if status.as_u16() == 429 {
                    counters.batches_rate_limited += 1;
                }
                tracing::warn!(%status, answer = %snippet(&text), ?counters, "feature-publisher: Risk Guard refused the batch; it will not be retried, the next interval sends fresh values");
            }
        }
        Err(error) => {
            counters.risk_guard_unreachable += 1;
            tracing::warn!(error = %error_chain(&error), ?counters, "feature-publisher: could not reach Risk Guard; batch dropped, will try again next interval");
        }
    }
}

/// Run until `stop` resolves.
pub async fn run(config: PublisherConfig, stop: impl std::future::Future<Output = ()>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing::info!(
        target_url = %config.target, interval_seconds = config.interval.as_secs_f64(),
        spiffe_subjects = config.trust_domain.is_some() || config.trust_domain_from_svid, "feature publisher started"
    );
    let mut counters = Counters::default();
    tokio::pin!(stop);
    loop {
        tick(&config, &mut counters, now_ms()).await;
        tokio::select! {
            () = tokio::time::sleep(config.interval) => {}
            () = &mut stop => {
                tracing::info!(?counters, "feature publisher stopped");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_792_800_000_000;

    fn buckets(entries: &[(&str, u64, u64)]) -> Value {
        json!({"aggregations": {"by_sandbox": {"sum_other_doc_count": 0, "buckets":
            entries.iter().map(|(id, hour, five)| json!({"key": id, "doc_count": hour, "last_5m": {"doc_count": five}})).collect::<Vec<_>>()}}})
    }

    #[test]
    fn sandbox_denials_are_read_per_sandbox_and_an_empty_answer_is_empty() {
        let parsed = parse_sandbox_denials(&buckets(&[("sbx-1", 12, 3), ("sbx-2", 4, 0)])).unwrap();
        assert_eq!(parsed.per_sandbox["sbx-1"], (12, 3));
        assert_eq!(parsed.per_sandbox["sbx-2"], (4, 0));
        assert!(!parsed.truncated);
        assert!(
            parse_sandbox_denials(&buckets(&[]))
                .unwrap()
                .per_sandbox
                .is_empty()
        );
        // A response that is not an aggregation answer is an error, not zero.
        assert!(parse_sandbox_denials(&json!({"error": "x"})).is_err());
        // A cut-off list is flagged.
        let mut cut = buckets(&[("a", 1, 1)]);
        cut["aggregations"]["by_sandbox"]["sum_other_doc_count"] = json!(7);
        assert!(parse_sandbox_denials(&cut).unwrap().truncated);
    }

    #[test]
    fn the_denial_query_counts_sandbox_denials_and_not_risk_guards_or_the_gateways() {
        let body = sandbox_denials_query(NOW);
        let text = body.to_string();
        assert!(text.contains(r#""action.keyword":"Denied""#));
        assert!(text.contains(r#""exists":{"field":"container.uid"}"#));
        assert!(
            text.contains(r#""firewall_rule.type.keyword":"middleware""#),
            "Risk Guard's own refusals are excluded"
        );
        assert_eq!(
            body["query"]["bool"]["filter"][0]["range"]["time"]["gte"],
            NOW - HOUR_MS
        );
        assert_eq!(
            body["aggs"]["by_sandbox"]["aggs"]["last_5m"]["filter"]["range"]["time"]["gte"],
            NOW - 5 * MIN_MS
        );
        assert_eq!(body["size"], 0);
    }

    #[test]
    fn would_block_reads_audit_mode_violations() {
        let response = json!({"aggregations": {"by_sandbox": {"buckets": [{"key": "sbx-1", "doc_count": 5}]}}});
        assert_eq!(parse_would_block(&response).unwrap()["sbx-1"], 5);
        assert!(
            parse_would_block(&json!({"aggregations": {"by_sandbox": {"buckets": []}}}))
                .unwrap()
                .is_empty()
        );
        assert!(
            would_block_query(NOW)
                .to_string()
                .contains("L7_REQUEST audit")
        );
    }

    #[test]
    fn fleet_denials_need_both_numbers() {
        let response = json!({"hits": {"total": {"value": 9, "relation": "eq"}}, "aggregations": {"sandboxes": {"value": 3}}});
        assert_eq!(parse_fleet_denials(&response).unwrap(), (9, 3));
        let empty = json!({"hits": {"total": {"value": 0, "relation": "eq"}}, "aggregations": {"sandboxes": {"value": 0}}});
        assert_eq!(parse_fleet_denials(&empty).unwrap(), (0, 0));
        assert!(parse_fleet_denials(&json!({})).is_err());
    }

    fn refusal_response(workloads: &[(&str, f64, f64)], fleet: (f64, f64), active: f64) -> Value {
        json!({"aggregations": {
            "by_workload": {"sum_other_doc_count": 0, "buckets": workloads.iter().map(|(id, refused, total)|
                json!({"key": id, "refused": {"value": refused}, "total": {"value": total}})).collect::<Vec<_>>()},
            "fleet_refused": {"value": fleet.0}, "fleet_total": {"value": fleet.1},
            "active": {"workloads": {"value": active}}
        }})
    }

    #[test]
    fn refusal_ratios_are_permille_of_decisions_and_silent_workloads_have_none() {
        let parsed = parse_refusals(&refusal_response(
            &[("a", 21.0, 50.0), ("b", 0.0, 10.0), ("quiet", 0.0, 0.0)],
            (21.0, 60.0),
            2.0,
        ))
        .unwrap();
        assert_eq!(parsed.per_workload["a"], 420);
        assert_eq!(parsed.per_workload["b"], 0);
        assert!(!parsed.per_workload.contains_key("quiet"));
        assert_eq!(parsed.fleet_ratio, Some(350));
        assert_eq!(parsed.fleet_active, 2);
        // Nothing at all: no fleet ratio (not zero), no active workloads.
        let none = parse_refusals(&refusal_response(&[], (0.0, 0.0), 0.0)).unwrap();
        assert_eq!((none.fleet_ratio, none.fleet_active), (None, 0));
    }

    fn seen(workload: &str, route: &str, first_h_ago: f64, last_h_ago: f64) -> RouteSeen {
        #[allow(clippy::cast_possible_truncation)]
        let at = |hours: f64| NOW - (hours * HOUR_MS as f64) as i64;
        RouteSeen {
            workload: workload.into(),
            host: "api.local".into(),
            route: route.into(),
            first_ms: at(first_h_ago),
            last_ms: at(last_h_ago),
        }
    }

    #[test]
    fn new_routes_are_those_first_seen_in_the_last_hour_and_uniqueness_is_across_workloads() {
        let list = vec![
            // w1 used /old for days, /new only since 10 minutes ago, /shared with w2, and /mine alone.
            seen("w1", "/old", 100.0, 0.1),
            seen("w1", "/new", 0.16, 0.05),
            seen("w1", "/shared", 50.0, 1.0),
            seen("w1", "/mine", 50.0, 2.0),
            seen("w2", "/shared", 50.0, 3.0),
            // w2 used /ancient 30 hours ago only: not part of the 24-hour share.
            seen("w2", "/ancient", 40.0, 30.0),
        ];
        let features = route_features(&list, NOW);
        assert_eq!(features["w1"][NEW_ROUTES], 1);
        // w1's 24h routes: old, new, shared, mine = 4; unique to w1: old, new, mine = 3.
        assert_eq!(features["w1"][ROUTES_UNIQUE], 750);
        assert_eq!(features["w2"][NEW_ROUTES], 0);
        // w2's only 24h route is /shared, which w1 also used.
        assert_eq!(features["w2"][ROUTES_UNIQUE], 0);
    }

    #[test]
    fn a_workload_with_no_route_in_24_hours_has_no_uniqueness_share_and_an_empty_list_has_no_features()
     {
        let features = route_features(&[seen("w", "/x", 40.0, 30.0)], NOW);
        assert_eq!(features["w"][NEW_ROUTES], 0);
        assert!(!features["w"].contains_key(ROUTES_UNIQUE));
        assert!(route_features(&[], NOW).is_empty());
    }

    #[test]
    fn a_route_page_reports_where_to_continue_only_when_full() {
        let bucket = |route: &str| json!({"key": {"workload": "w", "host": "h", "route": route}, "first": {"value": NOW as f64}, "last": {"value": NOW as f64}});
        let short = json!({"aggregations": {"pairs": {"buckets": [bucket("/a")], "after_key": {"route": "/a"}}}});
        let (page, next) = parse_routes_page(&short).unwrap();
        assert_eq!(
            (page.len(), next),
            (1, None),
            "a short page is the last one"
        );
        let full: Vec<Value> = (0..COMPOSITE_PAGE)
            .map(|i| bucket(&format!("/{i}")))
            .collect();
        let response =
            json!({"aggregations": {"pairs": {"buckets": full, "after_key": {"route": "/999"}}}});
        assert_eq!(
            parse_routes_page(&response).unwrap().1,
            Some(json!({"route": "/999"}))
        );
        assert!(
            parse_routes_page(
                &json!({"aggregations": {"pairs": {"buckets": [{"key": {"workload": "w"}}]}}})
            )
            .is_err()
        );
    }

    fn collected_with(sandboxes: &[(&str, &[(&'static str, u64)])]) -> Collected {
        let mut collected = Collected::default();
        for (id, features) in sandboxes {
            collected
                .sandboxes
                .insert((*id).into(), features.iter().copied().collect());
        }
        collected
    }

    fn subjects(batch: &Batch) -> Vec<Value> {
        serde_json::from_slice::<Value>(&batch.body).unwrap()["subjects"]
            .as_array()
            .unwrap()
            .clone()
    }

    #[test]
    fn a_fleet_with_one_workload_and_nothing_wrong_sends_only_the_fleet_subject() {
        let mut collected = collected_with(&[("sbx-1", &[(DENIALS_5M, 0), (DENIALS_1H, 0)])]);
        collected.workloads.insert(
            "w1".into(),
            [(REFUSAL_RATIO, 0), (NEW_ROUTES, 0)].into_iter().collect(),
        );
        collected.absorb_fleet_denials((0, 0));
        collected.absorb_refusals(Refusals {
            fleet_ratio: Some(0),
            fleet_active: 1,
            ..Refusals::default()
        });
        let batch = build_batch(&collected, Some("example.org"), NOW).unwrap();
        let sent = subjects(&batch);
        assert_eq!(
            sent.len(),
            1,
            "zero-valued sandboxes and workloads are not sent"
        );
        assert_eq!(sent[0]["kind"], "fleet");
        assert_eq!(sent[0]["features"][FLEET_ACTIVE], 1);
        assert_eq!(sent[0]["features"][FLEET_SANDBOXES], 0);
    }

    #[test]
    fn spiffe_subjects_follow_ocsf_rules_and_need_a_trust_domain() {
        let mut collected = collected_with(&[
            ("sbx-1", &[(DENIALS_5M, 3), (DENIALS_1H, 5)]),
            ("svid-ns-a", &[(DENIALS_5M, 1)]),
        ]);
        collected.absorb_fleet_denials((4, 2));
        let with = subjects(&build_batch(&collected, Some("example.org"), NOW).unwrap());
        let ids: Vec<(String, String)> = with
            .iter()
            .map(|s| {
                (
                    s["kind"].as_str().unwrap().into(),
                    s["id"].as_str().unwrap().into(),
                )
            })
            .collect();
        assert!(ids.contains(&(
            "spiffe".into(),
            "spiffe://example.org/openshell/sandbox/sbx-1".into()
        )));
        assert!(ids.contains(&("sandbox".into(), "svid-ns-a".into())));
        assert!(
            !ids.iter()
                .any(|(kind, id)| kind == "spiffe" && id.contains("svid-")),
            "svid- sandboxes have no derived ID"
        );
        let spiffe = with.iter().find(|s| s["kind"] == "spiffe").unwrap();
        assert_eq!(spiffe["features"][DENIALS_5M], 3);
        let without = subjects(&build_batch(&collected, None, NOW).unwrap());
        assert!(!without.iter().any(|s| s["kind"] == "spiffe"));
    }

    #[test]
    fn values_are_clamped_to_the_contract_ranges() {
        let mut collected = collected_with(&[("sbx", &[(DENIALS_5M, 250_000)])]);
        collected
            .workloads
            .insert("w".into(), [(REFUSAL_RATIO, 5_000)].into_iter().collect());
        collected.absorb_fleet_denials((999_999, 7));
        let sent = subjects(&build_batch(&collected, None, NOW).unwrap());
        let value = |kind: &str, name: &str| {
            sent.iter().find(|s| s["kind"] == kind).unwrap()["features"][name]
                .as_u64()
                .unwrap()
        };
        assert_eq!(value("sandbox", DENIALS_5M), 100_000);
        assert_eq!(value("workload", REFUSAL_RATIO), 1_000);
        assert_eq!(value("fleet", FLEET_DENIALS), 100_000);
    }

    #[test]
    fn the_batch_keeps_the_fleet_and_the_busiest_subjects_within_the_limits() {
        let mut collected = Collected::default();
        for i in 0..3_000_u64 {
            collected.sandboxes.insert(
                format!("sbx-{i:05}"),
                [(DENIALS_5M, i + 1)].into_iter().collect(),
            );
        }
        collected.absorb_fleet_denials((1, 1));
        let batch = build_batch(&collected, None, NOW).unwrap();
        assert!(
            batch.body.len() <= MAX_BODY_BYTES + 300,
            "{}",
            batch.body.len()
        );
        assert!(batch.body.len() < 64 * 1024);
        assert!(batch.subjects <= MAX_SUBJECTS);
        assert!(batch.dropped > 0 && batch.subjects + batch.dropped == 3_001);
        let sent = subjects(&batch);
        assert!(
            sent.iter().any(|s| s["kind"] == "fleet"),
            "the fleet subject is never cut"
        );
        assert!(
            sent.iter().any(|s| s["id"] == "sbx-02999"),
            "the busiest are kept"
        );
        assert!(
            !sent.iter().any(|s| s["id"] == "sbx-00000"),
            "the quietest are cut first"
        );
    }

    #[test]
    fn a_failed_query_omits_only_its_own_features() {
        let mut collected = Collected::default();
        collected.absorb_fleet_denials((6, 2));
        collected.failed.push(("refusals", "down".into()));
        let sent = subjects(&build_batch(&collected, None, NOW).unwrap());
        let fleet = &sent[0]["features"];
        assert_eq!(fleet[FLEET_DENIALS], 6);
        assert!(fleet.get(FLEET_REFUSAL_RATIO).is_none() && fleet.get(FLEET_ACTIVE).is_none());
        assert!(
            build_batch(&Collected::default(), None, NOW).is_none(),
            "nothing learned, nothing sent"
        );
    }

    #[test]
    fn the_body_has_the_contract_shape() {
        let mut collected = Collected::default();
        collected.absorb_fleet_denials((1, 1));
        let batch = build_batch(&collected, None, NOW).unwrap();
        let body: Value = serde_json::from_slice(&batch.body).unwrap();
        assert_eq!(
            (
                body["schema"].as_u64(),
                body["generated_at_ms"].as_i64(),
                body["window_seconds"].as_u64()
            ),
            (Some(1), Some(NOW), Some(300))
        );
        // Only vocabulary names ever appear.
        let vocabulary = [
            DENIALS_5M,
            DENIALS_1H,
            WOULD_BLOCK_5M,
            REFUSAL_RATIO,
            NEW_ROUTES,
            ROUTES_UNIQUE,
            ANOMALY_GRADE,
            FLEET_DENIALS,
            FLEET_SANDBOXES,
            FLEET_REFUSAL_RATIO,
            FLEET_ACTIVE,
        ];
        for name in body["subjects"][0]["features"].as_object().unwrap().keys() {
            assert!(vocabulary.contains(&name.as_str()), "{name}");
        }
    }

    #[test]
    fn anomaly_grades_are_parsed_from_hits_or_buckets_and_scaled_to_permille() {
        let hits = json!({
            "hits": {"hits": [
                {"_source": {"entity": [{"name": "actor.user.name.keyword", "value": "agent-a"}], "data_end_time": NOW, "anomaly_grade": 0.425}},
                {"_source": {"entity": [{"name": "actor.user.name.keyword", "value": "agent-a"}], "data_end_time": NOW - 60_000, "anomaly_grade": 0.812}},
                {"_source": {"entity": [{"name": "actor.user.name.keyword", "value": "agent-b"}], "data_end_time": NOW, "anomaly_grade": 0.0}}
            ]}
        });
        let parsed = parse_anomaly_grades(&hits).unwrap();
        assert_eq!(parsed.get("agent-a"), Some(&812));
        assert!(!parsed.contains_key("agent-b"));

        let buckets = json!({
            "aggregations": {"by_workload": {"buckets": [
                {"key": "agent-c", "max_grade": {"value": 0.75}}
            ]}}
        });
        let parsed_buckets = parse_anomaly_grades(&buckets).unwrap();
        assert_eq!(parsed_buckets.get("agent-c"), Some(&750));
    }
}
