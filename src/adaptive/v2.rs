// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 of the empirical network-metadata learner: everything that v1 does, plus
//!
//! * **shrinkage** toward a pooled prior, so a workload with little history is scored against the statistics of its task profile
//!   (and, for rates only, the fleet) instead of against a handful of its own requests;
//! * **richer deterministic features** of the recent activity: burst peak, how regular the gaps are, route entropy, write share,
//!   a method that was never seen, and how many resources never seen before turned up in the last hour;
//! * **optional context inputs** (counts the SIEM can supply) that can only add a small, bounded amount to an anomaly that is
//!   already there;
//! * a deterministic battery of **reference probes** (the same attack shapes `scripts/ml` injects) that is replayed against a
//!   model so two models can be compared on the same inputs before one replaces the other.
//!
//! Interpretation weights are still fixed rules over learned statistics. Nothing here is a probability, a permission or a
//! trained neural weight. Every learned number is an integer so a model compares and hashes the same everywhere.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::{
    ALGORITHM_VERSION, AdaptiveAssessment, FANOUT_MS, LearnedEnvelope, LearnedProfile,
    MAX_PRIOR_SOURCES, MINUTE_MS, SHADOW_ALERT_THRESHOLD, TrainingSession, WOULD_BLOCK_THRESHOLD,
    add_temporal, destination, finish_readiness, fit_counts, valid_envelope,
};
use crate::error::Result;
use crate::types::{NormalizedRequest, SignalContribution, WindowSnapshot};

/// Pseudo-observations a prior is worth: a workload with this many requests of its own weighs its own counts and the prior's equally.
const PRIOR_REQUEST_STRENGTH: u64 = 200;
/// The same for per-minute windows (about ten hours of captured minutes).
const PRIOR_WINDOW_STRENGTH: u64 = 600;
/// A prior keeps at most this many keys per count map (the most frequent), so a model stays small however large the fleet is.
const MAX_PRIOR_KEYS: usize = 2_048;
/// Most recent events kept for shape and novelty features. The store asks the database for at most this many.
pub const MAX_ACTIVITY_EVENTS: usize = 600;
/// How far back activity reaches: the novelty window.
pub const ACTIVITY_MS: i64 = 60 * MINUTE_MS;
const SHAPE_MIN_EVENTS: usize = 8;
const SHAPE_MIN_SAMPLES: u64 = 50;
const BURST_SLICE_MS: i64 = 10_000;
/// Shape evidence alone can never reach the shadow alert line (40); it only adds to what other signals found.
const SHAPE_CAP: u32 = 30;
/// Context can add at most this much and only to an anomaly already scoring at least [`CONTEXT_FLOOR`].
const CONTEXT_CAP: u32 = 12;
const CONTEXT_FLOOR: u32 = 15;

// ---------------------------------------------------------------------------------------------------------------------------------
// Options, ranges, shape

/// Which v2 components a model uses. All on is the shipped learner; the evaluation turns them off one at a time to see what each earns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FitOptions {
    pub shrinkage: bool,
    pub method_mix: bool,
    pub shape: bool,
    pub novelty: bool,
    pub context: bool,
}

impl Default for FitOptions {
    fn default() -> Self {
        Self {
            shrinkage: true,
            method_mix: true,
            shape: true,
            novelty: true,
            context: true,
        }
    }
}

/// Nearest-rank quantiles of one feature over the windows a model was trained on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureRange {
    pub samples: u32,
    pub min: u32,
    pub p01: u32,
    pub median: u32,
    pub p99: u32,
    pub max: u32,
}

impl FeatureRange {
    fn from_samples(mut samples: Vec<u32>) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        samples.sort_unstable();
        let rank = |percent: usize| samples[(samples.len() * percent).div_ceil(100).max(1) - 1];
        Some(Self {
            samples: samples.len() as u32,
            min: samples[0],
            p01: rank(1),
            median: rank(50),
            p99: rank(99),
            max: samples[samples.len() - 1],
        })
    }
}

/// Learned ranges of the shape features. A feature is absent when too few windows supported it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShapeProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst_peak: Option<FeatureRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_entropy: Option<FeatureRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_share: Option<FeatureRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_regularity: Option<FeatureRange>,
}

/// One earlier call, as the shape and novelty features need it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityEvent {
    pub ts_ms: i64,
    pub action_class: String,
    pub resource_id: String,
    pub write: bool,
}

impl ActivityEvent {
    #[must_use]
    pub fn of(request: &NormalizedRequest) -> Self {
        Self {
            ts_ms: request.timestamp_ms,
            action_class: request.action_class.clone(),
            resource_id: request.resource_id.clone(),
            write: !matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS"),
        }
    }
}

/// The deterministic shape of recent activity at one instant. `None` means too few events to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShapeValues {
    /// The most calls in any 10-second slice of the last minute.
    pub burst_peak: u32,
    /// Shannon entropy of the action mix over 15 minutes, in tenths of a bit.
    pub route_entropy: Option<u32>,
    /// Share of the last 15 minutes' calls that were writes, in permille.
    pub write_share: Option<u32>,
    /// Median absolute deviation of the gaps between calls over the median gap, in permille. Near zero is machine-regular.
    pub gap_regularity: Option<u32>,
}

/// Compute the shape of `events` (oldest first, all at or before `now_ms`).
#[must_use]
pub fn shape_values(events: &[ActivityEvent], now_ms: i64) -> ShapeValues {
    let recent: Vec<&ActivityEvent> = events
        .iter()
        .filter(|event| event.ts_ms >= now_ms.saturating_sub(FANOUT_MS) && event.ts_ms <= now_ms)
        .collect();
    let minute: Vec<i64> = recent
        .iter()
        .filter(|event| event.ts_ms >= now_ms.saturating_sub(MINUTE_MS))
        .map(|event| event.ts_ms)
        .collect();
    let mut burst_peak = 0usize;
    let mut left = 0usize;
    for right in 0..minute.len() {
        while minute[right] - minute[left] >= BURST_SLICE_MS {
            left += 1;
        }
        burst_peak = burst_peak.max(right - left + 1);
    }
    let mut values = ShapeValues {
        burst_peak: burst_peak as u32,
        ..ShapeValues::default()
    };
    if recent.len() < SHAPE_MIN_EVENTS {
        return values;
    }
    let total = recent.len() as f64;
    let mut mix: BTreeMap<&str, u32> = BTreeMap::new();
    for event in &recent {
        *mix.entry(event.action_class.as_str()).or_default() += 1;
    }
    let entropy: f64 = mix
        .values()
        .map(|count| {
            let p = f64::from(*count) / total;
            -p * p.log2()
        })
        .sum();
    values.route_entropy = Some((entropy * 10.0).round() as u32);
    let writes = recent.iter().filter(|event| event.write).count();
    values.write_share = Some((writes * 1000 / recent.len()) as u32);
    let mut gaps: Vec<i64> = recent
        .windows(2)
        .map(|pair| pair[1].ts_ms - pair[0].ts_ms)
        .collect();
    gaps.sort_unstable();
    let median = gaps[gaps.len() / 2].max(1);
    let mut deviations: Vec<i64> = gaps.iter().map(|gap| (gap - median).abs()).collect();
    deviations.sort_unstable();
    let mad = deviations[deviations.len() / 2];
    values.gap_regularity = Some((mad.saturating_mul(1000) / median).min(100_000) as u32);
    values
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Trailing activity

/// Trailing activity of one run, advanced one call at a time. It yields the window counts and the recent events as they stood
/// *before* the call being scored, which is what production's query returns.
#[derive(Debug, Default)]
pub struct Tracker {
    events: VecDeque<ActivityEvent>,
}

impl Tracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Window counts and recent events at `now_ms`, before the call at `now_ms` is added.
    pub fn view(&mut self, now_ms: i64) -> (WindowSnapshot, &[ActivityEvent]) {
        while self
            .events
            .front()
            .is_some_and(|event| event.ts_ms < now_ms.saturating_sub(ACTIVITY_MS))
        {
            self.events.pop_front();
        }
        let in_window = |span: i64| {
            self.events
                .iter()
                .filter(move |event| event.ts_ms >= now_ms.saturating_sub(span))
        };
        let distinct = |span: i64| {
            in_window(span)
                .map(|event| event.resource_id.as_str())
                .collect::<BTreeSet<_>>()
                .len() as u32
        };
        let snapshot = WindowSnapshot {
            req_count_1m: in_window(MINUTE_MS).count() as u32,
            req_count_15m: in_window(FANOUT_MS).count() as u32,
            distinct_resources_1m: distinct(MINUTE_MS),
            distinct_resources_15m: distinct(FANOUT_MS),
            warming: false,
        };
        (snapshot, self.events.make_contiguous())
    }

    pub fn push(&mut self, request: &NormalizedRequest) {
        self.events.push_back(ActivityEvent::of(request));
        if self.events.len() > MAX_ACTIVITY_EVENTS {
            self.events.pop_front();
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Pooled prior

/// Statistics pooled from other workloads' models, kept inside the model that used them so the model is self-contained and its hash
/// covers them. `tier` says where they came from: `task_profile` (other workloads of the same task profile) or `fleet` (other
/// profiles; only rates and shape, since another profile's routes say nothing about this one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prior {
    pub tier: String,
    /// The models pooled, so an auditor can see exactly where the prior came from.
    pub sources: Vec<String>,
    pub requests: u32,
    pub runs: u32,
    pub known_binary_requests: u32,
    pub binary_training_runs: u32,
    pub destination_counts: BTreeMap<String, u32>,
    pub resource_counts: BTreeMap<String, u32>,
    pub action_counts: BTreeMap<String, u32>,
    pub method_counts: BTreeMap<String, u32>,
    pub binary_counts: BTreeMap<String, u32>,
    pub rate: LearnedEnvelope,
    pub fanout: LearnedEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<ShapeProfile>,
}

fn method_of(action: &str) -> &str {
    action.split(' ').next().unwrap_or(action)
}

/// Counts by method, from a model's own action counts when it has no method counts (a v1 model).
fn method_counts_of(profile: &LearnedProfile) -> BTreeMap<String, u32> {
    if !profile.method_counts.is_empty() {
        return profile.method_counts.clone();
    }
    let mut out = BTreeMap::new();
    for (action, count) in &profile.action_counts {
        *out.entry(method_of(action).to_string()).or_default() += count;
    }
    out
}

fn add_counts(into: &mut BTreeMap<String, u64>, from: &BTreeMap<String, u32>) {
    for (key, count) in from {
        *into.entry(key.clone()).or_default() += u64::from(*count);
    }
}

fn top_keys(counts: BTreeMap<String, u64>) -> BTreeMap<String, u32> {
    let mut ranked: Vec<_> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked
        .into_iter()
        .take(MAX_PRIOR_KEYS)
        .map(|(key, count)| (key, count.min(u64::from(u32::MAX)) as u32))
        .collect()
}

fn pool_envelopes(parts: &[&LearnedEnvelope]) -> LearnedEnvelope {
    let windows: u64 = parts.iter().map(|e| u64::from(e.windows)).sum();
    let weighted = |pick: fn(&LearnedEnvelope) -> u32| {
        let sum: u64 = parts
            .iter()
            .map(|e| u64::from(pick(e)) * u64::from(e.windows))
            .sum();
        sum.div_ceil(windows.max(1)) as u32
    };
    LearnedEnvelope {
        p95: weighted(|e| e.p95),
        p99: weighted(|e| e.p99),
        maximum: parts.iter().map(|e| e.maximum).max().unwrap_or(0),
        windows: windows.min(u64::from(u32::MAX)) as u32,
    }
}

fn pool_ranges(parts: &[&FeatureRange]) -> Option<FeatureRange> {
    let samples: u64 = parts.iter().map(|r| u64::from(r.samples)).sum();
    if samples == 0 {
        return None;
    }
    let weighted = |pick: fn(&FeatureRange) -> u32| {
        let sum: u64 = parts
            .iter()
            .map(|r| u64::from(pick(r)) * u64::from(r.samples))
            .sum();
        (sum / samples) as u32
    };
    Some(FeatureRange {
        samples: samples.min(u64::from(u32::MAX)) as u32,
        min: parts.iter().map(|r| r.min).min()?,
        p01: weighted(|r| r.p01),
        median: weighted(|r| r.median),
        p99: weighted(|r| r.p99),
        max: parts.iter().map(|r| r.max).max()?,
    })
}

/// Pool `sources` (model id, model) into a prior. Returns `None` when there is nothing usable to pool. `categories` is false for the
/// fleet tier, which keeps only rates and shape.
#[must_use]
pub fn pool(tier: &str, sources: &[(String, &LearnedProfile)], categories: bool) -> Option<Prior> {
    let mut usable: Vec<&(String, &LearnedProfile)> = sources
        .iter()
        .filter(|(_, p)| {
            p.training_requests > 0 && valid_envelope(&p.rate) && valid_envelope(&p.fanout)
        })
        .collect();
    usable.sort_by(|a, b| a.0.cmp(&b.0));
    usable.truncate(MAX_PRIOR_SOURCES);
    if usable.is_empty() {
        return None;
    }
    let profiles: Vec<&LearnedProfile> = usable.iter().map(|(_, p)| *p).collect();
    let (mut destinations, mut resources, mut actions, mut methods, mut binaries) = (
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    if categories {
        for p in &profiles {
            add_counts(&mut destinations, &p.destination_counts);
            add_counts(&mut resources, &p.resource_counts);
            add_counts(&mut actions, &p.action_counts);
            add_counts(&mut methods, &method_counts_of(p));
            add_counts(&mut binaries, &p.binary_counts);
        }
    }
    let sum = |pick: fn(&LearnedProfile) -> u32| -> u32 {
        profiles
            .iter()
            .map(|p| u64::from(pick(p)))
            .sum::<u64>()
            .min(u64::from(u32::MAX)) as u32
    };
    let shape = |pick: fn(&ShapeProfile) -> &Option<FeatureRange>| {
        let parts: Vec<&FeatureRange> = profiles
            .iter()
            .filter_map(|p| p.shape.as_ref())
            .filter_map(|s| pick(s).as_ref())
            .collect();
        pool_ranges(&parts)
    };
    let pooled_shape = ShapeProfile {
        burst_peak: shape(|s| &s.burst_peak),
        route_entropy: shape(|s| &s.route_entropy),
        write_share: shape(|s| &s.write_share),
        gap_regularity: shape(|s| &s.gap_regularity),
    };
    Some(Prior {
        tier: tier.to_string(),
        sources: usable.iter().map(|(id, _)| id.clone()).collect(),
        requests: if categories {
            sum(|p| p.training_requests)
        } else {
            0
        },
        runs: sum(|p| p.training_runs),
        known_binary_requests: if categories {
            sum(|p| p.known_binary_requests)
        } else {
            0
        },
        binary_training_runs: if categories {
            sum(|p| p.binary_training_runs)
        } else {
            0
        },
        destination_counts: top_keys(destinations),
        resource_counts: top_keys(resources),
        action_counts: top_keys(actions),
        method_counts: top_keys(methods),
        binary_counts: top_keys(binaries),
        rate: pool_envelopes(&profiles.iter().map(|p| &p.rate).collect::<Vec<_>>()),
        fanout: pool_envelopes(&profiles.iter().map(|p| &p.fanout).collect::<Vec<_>>()),
        shape: Some(pooled_shape),
    })
}

/// The workload's own envelope blended with the prior's, weighted by how many windows each has (the prior counts as at most
/// [`PRIOR_WINDOW_STRENGTH`] windows). Rounds up: a limit that errs high raises fewer false alerts. It never lowers the workload's own maximum.
fn blend_envelope(own: &LearnedEnvelope, prior: Option<&LearnedEnvelope>) -> LearnedEnvelope {
    let Some(prior) = prior.filter(|p| valid_envelope(p)) else {
        return own.clone();
    };
    let own_weight = u64::from(own.windows);
    let prior_weight = PRIOR_WINDOW_STRENGTH.min(u64::from(prior.windows));
    let total = (own_weight + prior_weight).max(1);
    let mix = |own: u32, prior: u32| {
        (u64::from(own) * own_weight + u64::from(prior) * prior_weight).div_ceil(total) as u32
    };
    LearnedEnvelope {
        p95: mix(own.p95, prior.p95),
        p99: mix(own.p99, prior.p99),
        maximum: own.maximum.max(mix(own.maximum, prior.maximum)),
        windows: own.windows,
    }
}

fn blend_range(own: Option<&FeatureRange>, prior: Option<&FeatureRange>) -> Option<FeatureRange> {
    let (own, prior) = match (own, prior) {
        (Some(own), Some(prior)) => (own, prior),
        (Some(only), None) | (None, Some(only)) => return Some(only.clone()),
        (None, None) => return None,
    };
    let own_weight = u64::from(own.samples);
    let prior_weight = PRIOR_WINDOW_STRENGTH.min(u64::from(prior.samples));
    let total = (own_weight + prior_weight).max(1);
    let mix = |own: u32, prior: u32| {
        ((u64::from(own) * own_weight + u64::from(prior) * prior_weight) / total) as u32
    };
    Some(FeatureRange {
        samples: (own_weight + prior_weight).min(u64::from(u32::MAX)) as u32,
        min: own.min.min(mix(own.min, prior.min)),
        p01: mix(own.p01, prior.p01),
        median: mix(own.median, prior.median),
        p99: mix(own.p99, prior.p99),
        max: own.max.max(mix(own.max, prior.max)),
    })
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Context inputs

/// Counts the SIEM can supply about this sandbox, this workload and the fleet. Every field is optional: the learner works with none,
/// and a field it does not get is simply not used. Values are clamped before use. Context can only raise a score (by at most 12
/// points) and only when other evidence already scores at least 15, so it cannot start an alert and cannot loosen anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextInputs {
    pub openshell_denials_5m: Option<u32>,
    pub openshell_denials_1h: Option<u32>,
    pub openshell_would_block_5m: Option<u32>,
    pub refusal_ratio_15m_permille: Option<u32>,
    #[serde(default)]
    pub anomaly_grade_15m_permille: Option<u32>,
    pub fleet_openshell_denials_5m: Option<u32>,
    pub fleet_workloads_with_denials_5m: Option<u32>,
    pub fleet_refusal_ratio_15m_permille: Option<u32>,
    pub fleet_active_workloads_15m: Option<u32>,
}

impl ContextInputs {
    /// True when no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Points context may add, before the cap, with the reason for each rule that fired.
    fn points(&self) -> (u32, Vec<String>) {
        let clamp = |value: Option<u32>, limit: u32| value.map(|v| v.min(limit));
        let denials = clamp(self.openshell_denials_5m, 100_000);
        let mut points = 0;
        let mut why = Vec::new();
        if let Some(count) = denials.filter(|c| *c >= 3) {
            let add = if count >= 10 { 8 } else { 4 };
            points += add;
            why.push(format!("openshell_denials_5m={count}:+{add}"));
        }
        if let Some(count) = clamp(self.openshell_would_block_5m, 100_000).filter(|c| *c >= 3) {
            points += 3;
            why.push(format!("openshell_would_block_5m={count}:+3"));
        }
        if let (Some(own), Some(fleet)) = (
            clamp(self.refusal_ratio_15m_permille, 1_000),
            clamp(self.fleet_refusal_ratio_15m_permille, 1_000),
        ) && own >= 300
            && fleet <= 100
        {
            points += 3;
            why.push(format!("refusals_unlike_fleet={own}/{fleet}:+3"));
        }
        if let (Some(campaign), Some(own)) = (
            clamp(self.fleet_workloads_with_denials_5m, 100_000),
            denials,
        ) && campaign >= 3
            && own >= 1
        {
            points += 4;
            why.push(format!("fleet_campaign={campaign}:+4"));
        }
        if let Some(grade) = clamp(self.anomaly_grade_15m_permille, 1_000).filter(|g| *g >= 400) {
            let add = if grade >= 700 { 6 } else { 3 };
            points += add;
            why.push(format!("anomaly_grade_15m_permille={grade}:+{add}"));
        }
        (points, why)
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Scoring

fn category(
    assessment: &mut AdaptiveAssessment,
    feature: &str,
    observed: &str,
    own: (&BTreeMap<String, u32>, u32),
    prior: Option<(&BTreeMap<String, u32>, u32)>,
    runs: u32,
    weight: u32,
) -> u32 {
    let (own_counts, own_total) = own;
    let own_count = own_counts.get(observed).copied().unwrap_or(0);
    let prior_count = prior
        .and_then(|(counts, _)| counts.get(observed))
        .copied()
        .unwrap_or(0);
    let prior_total = prior.map_or(0, |(_, total)| total);
    // The prior counts for at most PRIOR_REQUEST_STRENGTH pseudo-observations, spread by its own frequencies.
    let strength = if prior_total == 0 {
        0
    } else {
        PRIOR_REQUEST_STRENGTH.min(u64::from(prior_total))
    };
    let effective_total = u64::from(own_total) + strength;
    // effective_count = own + strength * prior_count / prior_total, kept as a fraction over prior_total.
    let scaled = u128::from(own_count) * u128::from(prior_total.max(1))
        + u128::from(strength) * u128::from(prior_count);
    let denominator = u128::from(prior_total.max(1));
    let (contribution, interpretation) = if own_count == 0 && prior_count == 0 {
        (weight, "unseen")
    } else if effective_total >= 200 && scaled * 100 < u128::from(effective_total) * denominator {
        (weight / 2, "rare")
    } else if own_count == 0 {
        (0, "seen_in_task_profile")
    } else {
        (0, "observed")
    };
    if contribution > 0 {
        assessment.reasons.push(format!(
            "{interpretation}_{}",
            feature.strip_prefix("adaptive_").unwrap_or(feature)
        ));
    }
    assessment.signals.push(SignalContribution {
        feature: feature.to_string(),
        observed_summary: observed.to_string(),
        baseline_summary: format!(
            "observed_count={own_count},total_observations={own_total},{interpretation}{}",
            if prior_total > 0 {
                format!(",prior_count={prior_count},prior_total={prior_total}")
            } else {
                String::new()
            }
        ),
        contribution,
        support: format!(
            "independent_training_runs={runs}; empirical frequency, fixed interpretation weight"
        ),
    });
    contribution
}

/// Score one feature value against a learned range: nothing inside the range, 8 beyond it, 15 when more than twice the range's
/// own spread beyond it. `upper` and `lower` choose which side counts.
fn range_points(value: u32, range: &FeatureRange, upper: bool, lower: bool) -> u32 {
    let hi = range.max.max(range.p99);
    let lo = range.min.min(range.p01);
    let spread_up = range.p99.saturating_sub(range.median).max(1);
    let spread_down = range.median.saturating_sub(range.p01).max(1);
    if upper && value > hi {
        return if (value - hi) / spread_up >= 2 { 15 } else { 8 };
    }
    if lower && value < lo {
        return if (lo - value) / spread_down >= 2 {
            15
        } else {
            8
        };
    }
    0
}

/// Score `request` against a v2 model. `activity` is the run's earlier calls (oldest first, none at or after this one); without it
/// the shape and novelty features are skipped and the rest still score. `context` is optional and may be `None`.
pub(super) fn assess(
    profile: &LearnedProfile,
    request: &NormalizedRequest,
    window: &WindowSnapshot,
    activity: Option<&[ActivityEvent]>,
    context: Option<&ContextInputs>,
) -> AdaptiveAssessment {
    let mut assessment = AdaptiveAssessment {
        score: 0,
        high_confidence: false,
        reasons: Vec::new(),
        signals: Vec::new(),
    };
    if !matches!(request.scheme.as_str(), "http" | "https") {
        assessment
            .reasons
            .push("unsupported_non_network_request".to_string());
        return assessment;
    }
    if profile.algorithm_version != ALGORITHM_VERSION
        || profile.training_requests == 0
        || profile.training_runs == 0
        || !valid_envelope(&profile.rate)
        || !valid_envelope(&profile.fanout)
    {
        assessment
            .reasons
            .push("unsupported_or_empty_profile".to_string());
        return assessment;
    }
    if !profile.ready_for_enforcement {
        assessment
            .reasons
            .push("provisional_shadow_only".to_string());
    }
    let options = profile.options.unwrap_or_default();
    let prior = profile.prior.as_ref().filter(|_| options.shrinkage);
    let prior_of = |counts: fn(&Prior) -> &BTreeMap<String, u32>, total: fn(&Prior) -> u32| {
        prior.map(|p| (counts(p), total(p)))
    };
    let destination_score = category(
        &mut assessment,
        "adaptive_destination",
        &destination(request),
        (&profile.destination_counts, profile.training_requests),
        prior_of(|p| &p.destination_counts, |p| p.requests),
        profile.training_runs,
        20,
    );
    let resource_score = category(
        &mut assessment,
        "adaptive_resource",
        &request.resource_id,
        (&profile.resource_counts, profile.training_requests),
        prior_of(|p| &p.resource_counts, |p| p.requests),
        profile.training_runs,
        15,
    );
    let action_score = category(
        &mut assessment,
        "adaptive_action",
        &request.action_class,
        (&profile.action_counts, profile.training_requests),
        prior_of(|p| &p.action_counts, |p| p.requests),
        profile.training_runs,
        15,
    );

    let method_score = if options.method_mix
        && u64::from(profile.training_requests)
            + prior.map_or(0, |p| u64::from(p.requests).min(PRIOR_REQUEST_STRENGTH))
            >= 100
    {
        category(
            &mut assessment,
            "adaptive_method",
            &request.method.to_ascii_uppercase(),
            (&profile.method_counts, profile.training_requests),
            prior_of(|p| &p.method_counts, |p| p.requests),
            profile.training_runs,
            20,
        )
    } else {
        0
    };

    let binary = request
        .binary_path
        .as_deref()
        .filter(|path| !path.trim().is_empty());
    let supported = |known: u32, runs: u32, requests: u32| {
        known >= 20 && runs >= 5 && u64::from(known) * 100 >= u64::from(requests) * 80
    };
    let own_binary_supported = supported(
        profile.known_binary_requests,
        profile.binary_training_runs,
        profile.training_requests,
    );
    let prior_binary_supported = prior
        .is_some_and(|p| supported(p.known_binary_requests, p.binary_training_runs, p.requests));
    let binary_score =
        if let Some(binary) = binary.filter(|_| own_binary_supported || prior_binary_supported) {
            category(
                &mut assessment,
                "adaptive_binary",
                binary,
                (&profile.binary_counts, profile.known_binary_requests),
                prior
                    .filter(|_| prior_binary_supported)
                    .map(|p| (&p.binary_counts, p.known_binary_requests)),
                profile.binary_training_runs,
                25,
            )
        } else {
            assessment.reasons.push(
                if binary.is_none() {
                    "missing_binary_identity"
                } else {
                    "binary_novelty_unsupported"
                }
                .to_string(),
            );
            assessment.signals.push(SignalContribution {
                feature: "adaptive_binary".to_string(),
                observed_summary: binary.unwrap_or("identity_not_observed").to_string(),
                baseline_summary: format!(
                    "known_binary_requests={},binary_training_runs={},training_requests={}",
                    profile.known_binary_requests,
                    profile.binary_training_runs,
                    profile.training_requests
                ),
                contribution: 0,
                support: "missing or insufficient process coverage is not evidence of normality"
                    .to_string(),
            });
            0
        };

    if window.warming {
        assessment.reasons.push("window_warming".to_string());
    }
    let rate_envelope = blend_envelope(&profile.rate, prior.map(|p| &p.rate));
    let fanout_envelope = blend_envelope(&profile.fanout, prior.map(|p| &p.fanout));
    let (rate_score, rate_severe) = add_temporal(
        &mut assessment,
        "adaptive_rate_1m",
        window.req_count_1m.saturating_add(1),
        &rate_envelope,
        window.warming,
        (20, 100),
    );
    let (fanout_score, fanout_severe) = add_temporal(
        &mut assessment,
        "adaptive_fanout_15m",
        window.distinct_resources_15m,
        &fanout_envelope,
        window.warming,
        (10, 30),
    );

    // Shape and novelty need the run's recent activity; without it they are skipped, not scored as normal.
    let mut shape_score = 0;
    let mut novelty_score = 0;
    if let Some(events) = activity {
        if options.shape {
            let values = shape_values(events, request.timestamp_ms);
            let own = profile.shape.as_ref();
            let pooled = prior.and_then(|p| p.shape.as_ref());
            let mut notes = Vec::new();
            for (name, value, range_own, range_prior, upper, lower) in [
                (
                    "burst_peak",
                    Some(values.burst_peak),
                    own.and_then(|s| s.burst_peak.as_ref()),
                    pooled.and_then(|s| s.burst_peak.as_ref()),
                    true,
                    false,
                ),
                (
                    "route_entropy",
                    values.route_entropy,
                    own.and_then(|s| s.route_entropy.as_ref()),
                    pooled.and_then(|s| s.route_entropy.as_ref()),
                    true,
                    true,
                ),
                (
                    "write_share",
                    values.write_share,
                    own.and_then(|s| s.write_share.as_ref()),
                    pooled.and_then(|s| s.write_share.as_ref()),
                    true,
                    false,
                ),
                (
                    "gap_regularity",
                    values.gap_regularity,
                    own.and_then(|s| s.gap_regularity.as_ref()),
                    pooled.and_then(|s| s.gap_regularity.as_ref()),
                    false,
                    true,
                ),
            ] {
                let (Some(value), Some(range)) = (value, blend_range(range_own, range_prior))
                else {
                    continue;
                };
                if u64::from(range.samples) < SHAPE_MIN_SAMPLES {
                    continue;
                }
                let points = range_points(value, &range, upper, lower);
                if points > 0 {
                    assessment.reasons.push(format!("shape_{name}"));
                    notes.push(format!(
                        "{name}={value} outside [{},{}]:+{points}",
                        range.min, range.max
                    ));
                }
                shape_score += points;
            }
            shape_score = shape_score.min(SHAPE_CAP);
            assessment.signals.push(SignalContribution {
                feature: "adaptive_shape".to_string(),
                observed_summary: format!(
                    "burst_peak={},route_entropy_dbit={},write_permille={},gap_regularity_permille={}",
                    values.burst_peak,
                    values.route_entropy.map_or("n/a".into(), |v| v.to_string()),
                    values.write_share.map_or("n/a".into(), |v| v.to_string()),
                    values.gap_regularity.map_or("n/a".into(), |v| v.to_string()),
                ),
                baseline_summary: if notes.is_empty() {
                    "within learned ranges or unsupported".to_string()
                } else {
                    notes.join("; ")
                },
                contribution: shape_score,
                support: "learned ranges of deterministic window features; capped at 30, never alerts alone"
                    .to_string(),
            });
        }
        let known_requests = u64::from(profile.training_requests)
            + prior.map_or(0, |p| u64::from(p.requests).min(PRIOR_REQUEST_STRENGTH));
        if options.novelty && known_requests >= 100 {
            let known = |resource: &str| {
                profile.resource_counts.contains_key(resource)
                    || prior.is_some_and(|p| p.resource_counts.contains_key(resource))
            };
            let novel: BTreeSet<&str> = events
                .iter()
                .filter(|event| event.ts_ms >= request.timestamp_ms.saturating_sub(ACTIVITY_MS))
                .map(|event| event.resource_id.as_str())
                .filter(|resource| !known(resource))
                .collect();
            novelty_score = match novel.len() {
                0 | 1 => 0,
                2 => 15,
                _ => 30,
            };
            if novelty_score > 0 {
                assessment.reasons.push("novel_resources_1h".to_string());
            }
            assessment.signals.push(SignalContribution {
                feature: "adaptive_novelty_1h".to_string(),
                observed_summary: format!("never_seen_resources_in_last_hour={}", novel.len()),
                baseline_summary: format!(
                    "known_resources={}",
                    profile.resource_counts.len()
                        + prior.map_or(0, |p| p.resource_counts.len())
                ),
                contribution: novelty_score,
                support: "fixed rule: 2 distinct never-seen resources in an hour add 15, 3 or more add 30"
                    .to_string(),
            });
        }
    }

    let mut score = [
        destination_score,
        resource_score,
        action_score,
        method_score,
        binary_score,
        rate_score,
        fanout_score,
        shape_score,
        novelty_score,
    ]
    .into_iter()
    .sum::<u32>();

    if options.context
        && score >= CONTEXT_FLOOR
        && let Some(context) = context.filter(|c| !c.is_empty())
    {
        let (points, why) = context.points();
        let added = points.min(CONTEXT_CAP);
        if added > 0 {
            assessment.reasons.push("context_raised".to_string());
        }
        assessment.signals.push(SignalContribution {
            feature: "adaptive_context".to_string(),
            observed_summary: if why.is_empty() {
                "no context rule fired".to_string()
            } else {
                why.join("; ")
            },
            baseline_summary: format!(
                "applies_only_above_score={CONTEXT_FLOOR}; cap={CONTEXT_CAP}"
            ),
            contribution: added,
            support: "optional SIEM-supplied counts; can only raise an existing anomaly"
                .to_string(),
        });
        score += added;
    }
    assessment.score = score.min(100);
    // Destination, resource and novelty share one target axis; action and method one action axis.
    let independent_axes = [
        destination_score > 0 || resource_score > 0 || novelty_score > 0,
        action_score > 0 || method_score > 0,
        binary_score > 0,
        rate_score > 0,
        fanout_score > 0,
        shape_score > 0,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    assessment.high_confidence = assessment.score >= WOULD_BLOCK_THRESHOLD
        && (rate_severe || fanout_severe || independent_axes >= 2);
    assessment
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Fitting

/// Fit a v2 model. `prior` (if any) is attached and used when `options.shrinkage` is set.
pub(super) fn fit(
    training: &[TrainingSession],
    holdout: &[TrainingSession],
    options: &FitOptions,
    prior: Option<Prior>,
) -> Result<LearnedProfile> {
    let (mut profile, training, holdout) = fit_counts(training, holdout, ALGORITHM_VERSION)?;
    profile.options = Some(*options);
    for session in &training {
        for observation in &session.observations {
            *profile
                .method_counts
                .entry(observation.request.method.to_ascii_uppercase())
                .or_default() += 1;
        }
    }
    if options.shape {
        profile.shape = Some(learn_shape(&training));
    }
    profile.prior = prior.filter(|_| options.shrinkage);
    for session in &holdout {
        let (alerts, would_block) = replay(&profile, session);
        profile.holdout_alerts += alerts;
        profile.holdout_would_block += would_block;
    }
    finish_readiness(&mut profile);
    profile.evaluation = Some(evaluate(&profile, &holdout));
    Ok(profile)
}

fn learn_shape(training: &[TrainingSession]) -> ShapeProfile {
    let (mut bursts, mut entropies, mut writes, mut regularities) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for session in training {
        let mut tracker = Tracker::new();
        for observation in &session.observations {
            let request = &observation.request;
            let (_, events) = tracker.view(request.timestamp_ms);
            let values = shape_values(events, request.timestamp_ms);
            bursts.push(values.burst_peak);
            entropies.extend(values.route_entropy);
            writes.extend(values.write_share);
            regularities.extend(values.gap_regularity);
            tracker.push(request);
        }
    }
    ShapeProfile {
        burst_peak: FeatureRange::from_samples(bursts),
        route_entropy: FeatureRange::from_samples(entropies),
        write_share: FeatureRange::from_samples(writes),
        gap_regularity: FeatureRange::from_samples(regularities),
    }
}

/// Replay one captured session causally through `profile`, counting shadow alerts and would-blocks.
#[must_use]
pub fn replay(profile: &LearnedProfile, session: &TrainingSession) -> (u32, u32) {
    let mut tracker = Tracker::new();
    let (mut alerts, mut would_block) = (0, 0);
    for observation in &session.observations {
        let request = &observation.request;
        let (window, events) = tracker.view(request.timestamp_ms);
        let assessment = super::assess_in_context(profile, request, &window, Some(events), None);
        alerts += u32::from(assessment.score >= SHADOW_ALERT_THRESHOLD);
        would_block +=
            u32::from(assessment.score >= WOULD_BLOCK_THRESHOLD && assessment.high_confidence);
        tracker.push(request);
    }
    (alerts, would_block)
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Reference probes and model comparison

/// How a model did on one shape of injected attack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    pub shape: String,
    pub probes: u32,
    pub alerted: u32,
    pub blocked: u32,
}

/// A model's measured behavior on a fixed set of inputs: reference probes built from the model's own most common traffic, and a
/// holdout of benign captures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub probes: Vec<ProbeResult>,
    pub holdout_requests: u32,
    pub holdout_alerts: u32,
    pub holdout_would_block: u32,
}

impl Evaluation {
    #[must_use]
    pub fn probe_totals(&self) -> (u32, u32, u32) {
        self.probes.iter().fold((0, 0, 0), |(n, a, b), p| {
            (n + p.probes, a + p.alerted, b + p.blocked)
        })
    }
}

fn top_key(counts: &BTreeMap<String, u32>) -> Option<&str> {
    counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(key, _)| key.as_str())
}

/// A request built from a model's most common destination, action, resource and binary. `None` when the model has too little to build one.
fn base_request(profile: &LearnedProfile) -> Option<NormalizedRequest> {
    let destination = top_key(&profile.destination_counts)?;
    let (scheme, rest) = destination.split_once("://")?;
    let (host, port) = rest.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let action = top_key(&profile.action_counts)?;
    let (method, route) = action.split_once(' ')?;
    let resource = top_key(&profile.resource_counts)?;
    Some(NormalizedRequest {
        request_id: "probe".into(),
        sandbox_id: "probe".into(),
        scheme: scheme.into(),
        host: host.into(),
        port: port.parse().ok()?,
        method: method.into(),
        route_template: route.into(),
        resource_id: resource.into(),
        resource_key: resource.into(),
        action_class: action.into(),
        restriction_scope: format!("{destination} {action} {resource}"),
        high_impact: false,
        semantic_category: "read_only".into(),
        binary_path: top_key(&profile.binary_counts).map(str::to_string),
        ancestors: Vec::new(),
        fingerprint: "probe".into(),
        timestamp_ms: 0,
    })
}

fn probe_sets(profile: &LearnedProfile) -> Vec<(&'static str, Vec<Vec<NormalizedRequest>>)> {
    let Some(base) = base_request(profile) else {
        return Vec::new();
    };
    let at = |request: &NormalizedRequest, ts: i64| NormalizedRequest {
        timestamp_ms: 1_000_000_000_000 + ts,
        request_id: format!("probe-{ts}"),
        ..request.clone()
    };
    let mut sets = Vec::new();
    sets.push((
        "burst",
        [40i64, 70, 100, 150]
            .iter()
            .map(|n| (0..*n).map(|i| at(&base, i * 250)).collect())
            .collect(),
    ));
    sets.push((
        "enumeration",
        [20i64, 30, 40]
            .iter()
            .map(|n| {
                (0..*n)
                    .map(|i| {
                        let mut r = at(&base, i * 400);
                        r.resource_id = format!("probe-enum-{i}");
                        r.resource_key = r.resource_id.clone();
                        r
                    })
                    .collect()
            })
            .collect(),
    ));
    sets.push((
        "slow_and_low",
        [5i64, 8, 10]
            .iter()
            .map(|n| {
                (0..*n)
                    .map(|i| {
                        let mut r = at(&base, i * 20 * MINUTE_MS);
                        r.resource_id = format!("probe-slow-{i}");
                        r.resource_key = r.resource_id.clone();
                        r
                    })
                    .collect()
            })
            .collect(),
    ));
    let mut actions: Vec<(&String, &u32)> = profile.action_counts.iter().collect();
    actions.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    sets.push((
        "tempting_call",
        actions
            .iter()
            .take(3)
            .filter_map(|(action, _)| {
                let (_, route) = action.split_once(' ')?;
                let mut r = at(&base, 0);
                r.method = "DELETE".into();
                r.route_template = route.into();
                r.action_class = format!("DELETE {route}");
                r.semantic_category = "write_mutation".into();
                Some(vec![r])
            })
            .collect(),
    ));
    sets.push((
        "off_profile_destination",
        vec![vec![{
            let mut r = at(&base, 0);
            r.host = "probe-exfil.invalid".into();
            r.resource_id = "probe-exfil".into();
            r.resource_key = r.resource_id.clone();
            r
        }]],
    ));
    sets
}

/// Replay `profile` over its own reference probes and over `holdout`.
#[must_use]
pub fn evaluate(profile: &LearnedProfile, holdout: &[TrainingSession]) -> Evaluation {
    evaluate_on(profile, profile, holdout)
}

/// Replay `subject` over the reference probes built from `reference`'s traffic and over `holdout`. Comparing two models means
/// evaluating both with the same `reference`.
#[must_use]
pub fn evaluate_on(
    subject: &LearnedProfile,
    reference: &LearnedProfile,
    holdout: &[TrainingSession],
) -> Evaluation {
    let mut probes = Vec::new();
    for (shape, episodes) in probe_sets(reference) {
        let (mut alerted, mut blocked) = (0, 0);
        for episode in &episodes {
            let mut tracker = Tracker::new();
            let (mut alert, mut block) = (false, false);
            for request in episode {
                let (window, events) = tracker.view(request.timestamp_ms);
                let assessment =
                    super::assess_in_context(subject, request, &window, Some(events), None);
                alert |= assessment.score >= SHADOW_ALERT_THRESHOLD;
                block |= assessment.score >= WOULD_BLOCK_THRESHOLD && assessment.high_confidence;
                tracker.push(request);
            }
            alerted += u32::from(alert);
            blocked += u32::from(block);
        }
        probes.push(ProbeResult {
            shape: shape.to_string(),
            probes: episodes.len() as u32,
            alerted,
            blocked,
        });
    }
    let (mut alerts, mut would_block) = (0, 0);
    for session in holdout {
        let (a, b) = replay(subject, session);
        alerts += a;
        would_block += b;
    }
    Evaluation {
        probes,
        holdout_requests: holdout.iter().map(|s| s.observations.len() as u32).sum(),
        holdout_alerts: alerts,
        holdout_would_block: would_block,
    }
}

/// Candidate against previous on the same inputs, with the reasons the candidate may not replace the previous model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub previous_model_id: String,
    pub previous_algorithm: String,
    pub candidate: Evaluation,
    pub previous: Evaluation,
    pub blockers: Vec<String>,
}

fn permille(k: u32, n: u32) -> String {
    if n == 0 {
        "n/a".to_string()
    } else {
        format!("{k}/{n} ({:.1}%)", f64::from(k) * 100.0 / f64::from(n))
    }
}

/// Compare `candidate` with `previous` on the candidate's reference probes and the candidate's holdout. The candidate is worse if it
/// would have blocked more of the benign holdout, or caught fewer of the injected probes (at the alert line or the would-block line).
#[must_use]
pub fn compare(
    candidate: &LearnedProfile,
    previous: &LearnedProfile,
    previous_model_id: &str,
    holdout: &[TrainingSession],
) -> Comparison {
    let new = evaluate_on(candidate, candidate, holdout);
    let old = evaluate_on(previous, candidate, holdout);
    let (probes, new_alerted, new_blocked) = new.probe_totals();
    let (_, old_alerted, old_blocked) = old.probe_totals();
    let mut blockers = Vec::new();
    let summary = |label: &str, e: &Evaluation| {
        let (n, a, b) = e.probe_totals();
        format!(
            "{label}: holdout would-blocks {}, holdout alerts {}, injected probes alerted {}, blocked {}",
            permille(e.holdout_would_block, e.holdout_requests),
            permille(e.holdout_alerts, e.holdout_requests),
            permille(a, n),
            permille(b, n)
        )
    };
    if new.holdout_would_block > old.holdout_would_block {
        blockers.push(format!(
            "The candidate would block more of the benign holdout than the previous model ({} against {}).",
            permille(new.holdout_would_block, new.holdout_requests),
            permille(old.holdout_would_block, old.holdout_requests)
        ));
    }
    if new_alerted < old_alerted || new_blocked < old_blocked {
        blockers.push(format!(
            "The candidate catches fewer injected attack probes than the previous model (alerted {} against {}, would-block {} against {}).",
            permille(new_alerted, probes),
            permille(old_alerted, probes),
            permille(new_blocked, probes),
            permille(old_blocked, probes)
        ));
    }
    if !blockers.is_empty() {
        blockers.push(format!(
            "{}. {}.",
            summary("Candidate", &new),
            summary("Previous", &old)
        ));
    }
    Comparison {
        previous_model_id: previous_model_id.to_string(),
        previous_algorithm: previous.algorithm_version.clone(),
        candidate: new,
        previous: old,
        blockers,
    }
}
