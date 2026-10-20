// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Phase-one empirical anomaly scoring for NETWORK request metadata only.
//!
//! The caller must select fresh, operator-reviewed benign native captures, exclude
//! rehearsals, and own provenance, storage, and explicit shadow-to-enforce promotion.
//! This module neither verifies that provenance nor changes permissions, manual
//! allowlists, or native policy. Observed categories are frequencies, not permissions.
//! Interpretation weights are fixed rules over learned statistics, not trained
//! neural weights or calibrated probabilities. No filesystem behavior is modeled.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, RiskGuardError};
use crate::types::{DecisionOutcome, NormalizedRequest, SignalContribution, WindowSnapshot};

/// Bump whenever feature definitions, admission rules, or interpretation weights change.
pub const ALGORITHM_VERSION: &str = "network-metadata-empirical-v1";
/// A shadow alert is an observed assessment at or above this score.
pub const SHADOW_ALERT_THRESHOLD: u32 = 40;
/// A phase-one would-block also requires [`AdaptiveAssessment::high_confidence`].
pub const WOULD_BLOCK_THRESHOLD: u32 = 70;

const MINUTE_MS: i64 = 60_000;
const FANOUT_MS: i64 = 15 * MINUTE_MS;
const MAX_SESSION_DURATION_MS: i64 = 24 * 60 * MINUTE_MS;
const MAX_SAMPLES_PER_SESSION: usize = 500;
const MAX_TOTAL_SAMPLES: usize = 50_000;
const MAX_SESSIONS: usize = 1_024;
const MAX_TOTAL_WINDOWS: usize = 100_000;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_ANCESTORS: usize = 32;
const MAX_DATASET_METADATA_BYTES: usize = 64 * 1_024 * 1_024;
const MIN_TRAINING_RUNS: u32 = 20;
const MIN_TRAINING_REQUESTS: u32 = 200;
const MIN_HOLDOUT_RUNS: u32 = 5;
const MIN_HOLDOUT_REQUESTS: u32 = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingObservation {
    pub request: NormalizedRequest,
    pub base_outcome: DecisionOutcome,
    pub base_risk_score: u32,
}

/// A complete captured interval `[started_at_ms, ended_at_ms)` for one sandbox.
/// One run can contain multiple sessions, but still counts as one independent run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingSession {
    pub session_id: String,
    pub run_id: String,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub observations: Vec<TrainingObservation>,
}

/// Nearest-rank empirical quantiles, including idle captured minute buckets.
/// Fanout is the trailing 15-minute distinct-resource count sampled each minute.
/// Partial final minutes contribute their actual counts, without extrapolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearnedEnvelope {
    pub p95: u32,
    pub p99: u32,
    pub maximum: u32,
    pub windows: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearnedProfile {
    pub algorithm_version: String,
    pub dataset_hash: String,
    pub training_sessions: u32,
    pub training_runs: u32,
    pub training_requests: u32,
    pub holdout_sessions: u32,
    pub holdout_runs: u32,
    pub holdout_requests: u32,
    pub holdout_alerts: u32,
    pub holdout_would_block: u32,
    pub resource_counts: BTreeMap<String, u32>,
    pub action_counts: BTreeMap<String, u32>,
    /// Keys are canonical `scheme://host:port` destinations, with bracketed IPv6.
    pub destination_counts: BTreeMap<String, u32>,
    pub binary_counts: BTreeMap<String, u32>,
    pub known_binary_requests: u32,
    /// Independent training runs with at least one actually observed binary identity.
    #[serde(default)]
    pub binary_training_runs: u32,
    /// Only a sample-support indicator (100 runs / 1,000 requests / 1,000 windows).
    /// This is not tail or false-positive-rate certification.
    /// Overlapping temporal windows are not independent tail observations.
    #[serde(default)]
    pub tail_reliable: bool,
    pub rate: LearnedEnvelope,
    pub fanout: LearnedEnvelope,
    /// Eligibility for explicit phase-one promotion, never automatic enforcement.
    pub ready_for_enforcement: bool,
    /// Includes gate failures AND sparse-tail/phase-one limitations, even when eligible.
    pub readiness_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveAssessment {
    /// Positive risk only, bounded to 0..=100; never a probability or permission.
    pub score: u32,
    /// A shadow would-block candidate, NOT authorization to enable enforcement.
    pub high_confidence: bool,
    pub reasons: Vec<String>,
    pub signals: Vec<SignalContribution>,
}

/// Fit clean network captures and causally replay strictly later, run-disjoint holdout.
/// Invalid or dirty records reject the entire dataset; none are silently filtered.
/// Limits: 500 observations/session, 50,000 combined observations, 24 hours/session,
/// 1,024 sessions, 100,000 captured minute buckets, and 64 MiB of metadata.
pub fn fit(training: &[TrainingSession], holdout: &[TrainingSession]) -> Result<LearnedProfile> {
    validate_dataset(training, holdout)?;
    let training = canonical_sessions(training);
    let holdout = canonical_sessions(holdout);
    let canonical = serde_json::to_vec(&(ALGORITHM_VERSION, &training, &holdout))?;
    let dataset_hash = format!("{:x}", Sha256::digest(&canonical));
    drop(canonical);
    let mut resource_counts = BTreeMap::new();
    let mut action_counts = BTreeMap::new();
    let mut destination_counts = BTreeMap::new();
    let mut binary_counts = BTreeMap::new();
    let mut binary_runs = BTreeSet::new();
    let mut known_binary_requests = 0;
    let mut rates = Vec::new();
    let mut fanouts = Vec::new();

    for session in &training {
        for observation in &session.observations {
            let request = &observation.request;
            increment(&mut resource_counts, &request.resource_id);
            increment(&mut action_counts, &request.action_class);
            increment(&mut destination_counts, &destination(request));
            if let Some(binary) = &request.binary_path {
                increment(&mut binary_counts, binary);
                known_binary_requests += 1;
                binary_runs.insert(session.run_id.as_str());
            }
        }
        session_distributions(session, &mut rates, &mut fanouts);
    }

    let mut profile = LearnedProfile {
        algorithm_version: ALGORITHM_VERSION.to_string(),
        dataset_hash,
        training_sessions: training.len() as u32,
        training_runs: independent_runs(&training),
        training_requests: request_count(&training),
        holdout_sessions: holdout.len() as u32,
        holdout_runs: independent_runs(&holdout),
        holdout_requests: request_count(&holdout),
        holdout_alerts: 0,
        holdout_would_block: 0,
        resource_counts,
        action_counts,
        destination_counts,
        binary_counts,
        known_binary_requests,
        binary_training_runs: binary_runs.len() as u32,
        tail_reliable: false,
        rate: envelope(rates),
        fanout: envelope(fanouts),
        ready_for_enforcement: false,
        readiness_reasons: Vec::new(),
    };
    profile.tail_reliable = profile.training_runs >= 100
        && profile.training_requests >= 1_000
        && profile.rate.windows >= 1_000
        && profile.fanout.windows >= 1_000;
    for session in &holdout {
        let (alerts, would_block) = replay_holdout(&profile, session);
        profile.holdout_alerts += alerts;
        profile.holdout_would_block += would_block;
    }

    for (label, actual, minimum) in [
        ("training_runs", profile.training_runs, MIN_TRAINING_RUNS),
        (
            "training_requests",
            profile.training_requests,
            MIN_TRAINING_REQUESTS,
        ),
        ("holdout_runs", profile.holdout_runs, MIN_HOLDOUT_RUNS),
        (
            "holdout_requests",
            profile.holdout_requests,
            MIN_HOLDOUT_REQUESTS,
        ),
    ] {
        if actual < minimum {
            profile.readiness_reasons.push(format!(
                "insufficient_{label}: observed={actual},required={minimum}"
            ));
        }
    }
    if profile.holdout_would_block != 0 {
        profile.readiness_reasons.push(format!(
            "holdout_would_block: observed={},required=0",
            profile.holdout_would_block
        ));
    }
    profile.ready_for_enforcement = profile.readiness_reasons.is_empty();
    if !profile.tail_reliable {
        profile.readiness_reasons.push(format!(
            "sparse_empirical_p99: training_runs={},training_requests={},rate_windows={},fanout_windows={}; \
             idle and overlapping windows are not independent tail evidence",
            profile.training_runs,
            profile.training_requests,
            profile.rate.windows,
            profile.fanout.windows
        ));
    }
    profile.readiness_reasons.push(
        "phase1_only: minimum quality gates are not production p99 or false-positive-rate certification"
            .to_string(),
    );
    Ok(profile)
}

/// Add positive risk from empirical network metadata; never mutate a profile or policy.
/// The caller must independently require explicit enforcement and a promotion-ready model.
pub fn assess(
    profile: &LearnedProfile,
    request: &NormalizedRequest,
    window: &WindowSnapshot,
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
    let destination_score = add_category(
        &mut assessment,
        "adaptive_destination",
        &destination(request),
        &profile.destination_counts,
        profile.training_requests,
        profile.training_runs,
        20,
    );
    let resource_score = add_category(
        &mut assessment,
        "adaptive_resource",
        &request.resource_id,
        &profile.resource_counts,
        profile.training_requests,
        profile.training_runs,
        15,
    );
    let action_score = add_category(
        &mut assessment,
        "adaptive_action",
        &request.action_class,
        &profile.action_counts,
        profile.training_requests,
        profile.training_runs,
        15,
    );
    let binary = request
        .binary_path
        .as_deref()
        .filter(|path| !path.trim().is_empty());
    let binary_supported = profile.known_binary_requests >= 20
        && profile.binary_training_runs >= 5
        && u64::from(profile.known_binary_requests) * 100
            >= u64::from(profile.training_requests) * 80;
    let binary_score = if let Some(binary) = binary.filter(|_| binary_supported) {
        add_category(
            &mut assessment,
            "adaptive_binary",
            binary,
            &profile.binary_counts,
            profile.known_binary_requests,
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
    let (rate_score, rate_severe) = add_temporal(
        &mut assessment,
        "adaptive_rate_1m",
        window.req_count_1m.saturating_add(1),
        &profile.rate,
        window.warming,
        (20, 100),
    );
    // The snapshot lacks membership information: adding one could count a repeated
    // unseen resource twice. Use the observed pre-event distinct-resource count.
    let (fanout_score, fanout_severe) = add_temporal(
        &mut assessment,
        "adaptive_fanout_15m",
        window.distinct_resources_15m,
        &profile.fanout,
        window.warming,
        (10, 30),
    );
    assessment.score = [
        destination_score,
        resource_score,
        action_score,
        binary_score,
        rate_score,
        fanout_score,
    ]
    .into_iter()
    .sum::<u32>()
    .min(100);
    // Destination and resource novelty share one target axis, not two independent votes.
    let independent_axes = [
        destination_score > 0 || resource_score > 0,
        action_score > 0,
        binary_score > 0,
        rate_score > 0,
        fanout_score > 0,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    assessment.high_confidence = assessment.score >= WOULD_BLOCK_THRESHOLD
        && (rate_severe || fanout_severe || independent_axes >= 2);
    assessment
}

fn invalid(message: impl Into<String>) -> RiskGuardError {
    RiskGuardError::InvalidArgument(format!("adaptive dataset: {}", message.into()))
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= MAX_FIELD_BYTES
        && !value.chars().any(char::is_control)
}

fn minute_windows(session: &TrainingSession) -> usize {
    ((session.ended_at_ms - session.started_at_ms) as usize).div_ceil(MINUTE_MS as usize)
}

fn validate_dataset(training: &[TrainingSession], holdout: &[TrainingSession]) -> Result<()> {
    if training.is_empty() {
        return Err(invalid("no training data"));
    }
    if training.len().saturating_add(holdout.len()) > MAX_SESSIONS {
        return Err(invalid("too many sessions"));
    }
    let total_samples = training
        .iter()
        .chain(holdout)
        .fold(0usize, |count, session| {
            count.saturating_add(session.observations.len())
        });
    if total_samples > MAX_TOTAL_SAMPLES {
        return Err(invalid("more than 50000 total observations"));
    }
    let training_runs: BTreeSet<_> = training.iter().map(|session| &session.run_id).collect();
    let last_training_end = training
        .iter()
        .map(|session| session.ended_at_ms)
        .max()
        .unwrap_or(0);
    let mut sessions = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut windows = 0usize;
    let mut metadata_bytes = 0usize;
    for (is_holdout, captures) in [(false, training), (true, holdout)] {
        for session in captures {
            if !valid_text(&session.session_id) || !valid_text(&session.run_id) {
                return Err(invalid("empty or invalid session/run identity"));
            }
            if !sessions.insert(session.session_id.as_str()) {
                return Err(invalid("duplicate session identity"));
            }
            if session.started_at_ms < 0
                || session.ended_at_ms <= session.started_at_ms
                || session.ended_at_ms.saturating_sub(session.started_at_ms)
                    > MAX_SESSION_DURATION_MS
            {
                return Err(invalid(
                    "invalid session interval or duration exceeds 24 hours",
                ));
            }
            if session.observations.is_empty()
                || session.observations.len() > MAX_SAMPLES_PER_SESSION
            {
                return Err(invalid(
                    "sessions require 1..=500 observations; no truncation",
                ));
            }
            if is_holdout
                && (training_runs.contains(&session.run_id)
                    || session.started_at_ms <= last_training_end)
            {
                return Err(invalid(
                    "holdout runs must be disjoint and strictly later than training",
                ));
            }
            windows += minute_windows(session);
            if windows > MAX_TOTAL_WINDOWS {
                return Err(invalid("more than 100000 captured minute windows"));
            }
            metadata_bytes += session.session_id.len() + session.run_id.len();
            let sandbox = &session.observations[0].request.sandbox_id;
            for observation in &session.observations {
                let request = &observation.request;
                if request.timestamp_ms < session.started_at_ms
                    || request.timestamp_ms >= session.ended_at_ms
                {
                    return Err(invalid(
                        "observation outside captured half-open session interval",
                    ));
                }
                if &request.sandbox_id != sandbox {
                    return Err(invalid("one session cannot combine different sandboxes"));
                }
                validate_observation(observation, &mut metadata_bytes)?;
                if !identities.insert((request.sandbox_id.as_str(), request.request_id.as_str())) {
                    return Err(invalid("duplicate sandbox/request identity"));
                }
                if metadata_bytes > MAX_DATASET_METADATA_BYTES {
                    return Err(invalid("dataset metadata exceeds 64 MiB"));
                }
            }
        }
    }
    Ok(())
}

fn validate_observation(
    observation: &TrainingObservation,
    metadata_bytes: &mut usize,
) -> Result<()> {
    let request = &observation.request;
    if observation.base_outcome == DecisionOutcome::Deny
        || observation.base_risk_score >= WOULD_BLOCK_THRESHOLD
        || request.high_impact
        || !matches!(
            request.semantic_category.as_str(),
            "read_only" | "read_only_query"
        )
        || !matches!(request.scheme.as_str(), "http" | "https")
        || !matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "POST")
        || (request.method == "POST"
            && (request.semantic_category != "read_only_query"
                || request.route_template == "/graphql"))
        || !request.route_template.starts_with('/')
        || request.route_template.chars().any(char::is_whitespace)
        || request.action_class != format!("{} {}", request.method, request.route_template)
    {
        return Err(invalid(
            "denied, high-risk, high-impact, unknown-route, or non-read network sample",
        ));
    }
    if request.port == 0
        || request.host != request.host.to_ascii_lowercase()
        || request.host.chars().any(|character| {
            character.is_whitespace() || matches!(character, '/' | '\\' | '@' | '?' | '#')
        })
    {
        return Err(invalid("invalid normalized network destination"));
    }
    for value in [
        &request.request_id,
        &request.sandbox_id,
        &request.scheme,
        &request.host,
        &request.method,
        &request.route_template,
        &request.resource_id,
        &request.resource_key,
        &request.action_class,
        &request.restriction_scope,
        &request.semantic_category,
        &request.fingerprint,
    ] {
        if !valid_text(value) {
            return Err(invalid(
                "empty, oversized, or invalid normalized metadata field",
            ));
        }
        *metadata_bytes += value.len();
    }
    if request.ancestors.len() > MAX_ANCESTORS {
        return Err(invalid("too many process ancestors"));
    }
    for path in request.ancestors.iter().chain(request.binary_path.iter()) {
        if !valid_text(path) {
            return Err(invalid("invalid observed process identity"));
        }
        *metadata_bytes += path.len();
    }
    Ok(())
}

fn canonical_sessions(sessions: &[TrainingSession]) -> Vec<TrainingSession> {
    let mut canonical = sessions.to_vec();
    canonical.sort_by(|left, right| {
        (
            left.started_at_ms,
            left.ended_at_ms,
            &left.run_id,
            &left.session_id,
        )
            .cmp(&(
                right.started_at_ms,
                right.ended_at_ms,
                &right.run_id,
                &right.session_id,
            ))
    });
    for session in &mut canonical {
        session.observations.sort_by(|left, right| {
            let left = &left.request;
            let right = &right.request;
            (left.timestamp_ms, &left.sandbox_id, &left.request_id).cmp(&(
                right.timestamp_ms,
                &right.sandbox_id,
                &right.request_id,
            ))
        });
    }
    canonical
}

fn independent_runs(sessions: &[TrainingSession]) -> u32 {
    sessions
        .iter()
        .map(|session| &session.run_id)
        .collect::<BTreeSet<_>>()
        .len() as u32
}

fn request_count(sessions: &[TrainingSession]) -> u32 {
    sessions
        .iter()
        .map(|session| session.observations.len() as u32)
        .sum()
}

fn destination(request: &NormalizedRequest) -> String {
    let host = if request.host.contains(':') && !request.host.starts_with('[') {
        format!("[{}]", request.host)
    } else {
        request.host.clone()
    };
    format!("{}://{}:{}", request.scheme, host, request.port)
}

fn increment(counts: &mut BTreeMap<String, u32>, key: &str) {
    *counts.entry(key.to_string()).or_default() += 1;
}

fn remove_resource(counts: &mut BTreeMap<&str, u32>, key: &str) {
    if let Some(count) = counts.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(key);
        }
    }
}

fn session_distributions(session: &TrainingSession, rates: &mut Vec<u32>, fanouts: &mut Vec<u32>) {
    let observations = &session.observations;
    let mut right = 0;
    let mut left = 0;
    let mut resources = BTreeMap::new();
    for minute in 1..=minute_windows(session) {
        let end = session
            .started_at_ms
            .saturating_add(minute as i64 * MINUTE_MS)
            .min(session.ended_at_ms);
        let previous_right = right;
        while right < observations.len() && observations[right].request.timestamp_ms < end {
            *resources
                .entry(observations[right].request.resource_id.as_str())
                .or_insert(0) += 1;
            right += 1;
        }
        let cutoff = end.saturating_sub(FANOUT_MS);
        while left < right && observations[left].request.timestamp_ms < cutoff {
            remove_resource(&mut resources, &observations[left].request.resource_id);
            left += 1;
        }
        rates.push((right - previous_right) as u32);
        fanouts.push(resources.len() as u32);
    }
}

fn envelope(mut samples: Vec<u32>) -> LearnedEnvelope {
    samples.sort_unstable();
    LearnedEnvelope {
        p95: samples[(samples.len() * 95).div_ceil(100) - 1],
        p99: samples[(samples.len() * 99).div_ceil(100) - 1],
        maximum: samples.last().copied().unwrap_or(0),
        windows: samples.len() as u32,
    }
}

fn valid_envelope(envelope: &LearnedEnvelope) -> bool {
    envelope.windows > 0 && envelope.p95 <= envelope.p99 && envelope.p99 <= envelope.maximum
}

fn add_category(
    assessment: &mut AdaptiveAssessment,
    feature: &str,
    observed: &str,
    counts: &BTreeMap<String, u32>,
    total: u32,
    runs: u32,
    weight: u32,
) -> u32 {
    let count = counts.get(observed).copied().unwrap_or(0);
    let (contribution, interpretation) = if count == 0 {
        (weight, "unseen")
    } else if total >= 200 && u64::from(count) * 100 < u64::from(total) {
        (weight / 2, "rare")
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
        baseline_summary: format!("observed_count={count},total_observations={total}"),
        contribution,
        support: format!(
            "independent_training_runs={runs}; empirical frequency, fixed interpretation weight"
        ),
    });
    contribution
}

fn add_temporal(
    assessment: &mut AdaptiveAssessment,
    feature: &str,
    observed: u32,
    envelope: &LearnedEnvelope,
    warming: bool,
    floors: (u32, u32),
) -> (u32, bool) {
    let elevated = envelope
        .maximum
        .saturating_mul(2)
        .max(envelope.p99.saturating_mul(3))
        .max(floors.0);
    let severe = envelope
        .maximum
        .saturating_mul(5)
        .max(envelope.p99.saturating_mul(8))
        .max(floors.1);
    let is_severe = !warming && observed > elevated && observed >= severe;
    let contribution = if is_severe {
        80
    } else if !warming && observed > elevated {
        35
    } else {
        0
    };
    if contribution > 0 {
        assessment.reasons.push(format!(
            "{}_{}",
            feature.strip_prefix("adaptive_").unwrap_or(feature),
            if is_severe { "severe" } else { "elevated" }
        ));
    }
    assessment.signals.push(SignalContribution {
        feature: feature.to_string(),
        observed_summary: format!("count={observed},warming={warming}"),
        baseline_summary: format!(
            "empirical_p95={},empirical_p99={},maximum={},windows={},elevated_above={},severe_at={}",
            envelope.p95, envelope.p99, envelope.maximum, envelope.windows, elevated, severe
        ),
        contribution,
        support: "per-session captured minute windows; conservative headroom; fixed weights".to_string(),
    });
    (contribution, is_severe)
}

fn replay_holdout(profile: &LearnedProfile, session: &TrainingSession) -> (u32, u32) {
    let observations = &session.observations;
    let mut left_1m = 0;
    let mut left_15m = 0;
    let mut resources_1m = BTreeMap::new();
    let mut resources_15m = BTreeMap::new();
    let mut alerts = 0;
    let mut would_block = 0;
    for (index, observation) in observations.iter().enumerate() {
        let request = &observation.request;
        while left_1m < index
            && observations[left_1m].request.timestamp_ms
                < request.timestamp_ms.saturating_sub(MINUTE_MS)
        {
            remove_resource(
                &mut resources_1m,
                &observations[left_1m].request.resource_id,
            );
            left_1m += 1;
        }
        while left_15m < index
            && observations[left_15m].request.timestamp_ms
                < request.timestamp_ms.saturating_sub(FANOUT_MS)
        {
            remove_resource(
                &mut resources_15m,
                &observations[left_15m].request.resource_id,
            );
            left_15m += 1;
        }
        // Captures replay from their own recorded session boundary; no other run's
        // workload or later event is available to this pre-event snapshot.
        let window = WindowSnapshot {
            req_count_1m: (index - left_1m) as u32,
            req_count_15m: (index - left_15m) as u32,
            distinct_resources_1m: resources_1m.len() as u32,
            distinct_resources_15m: resources_15m.len() as u32,
            warming: false,
        };
        let assessment = assess(profile, request, &window);
        alerts += u32::from(assessment.score >= SHADOW_ALERT_THRESHOLD);
        would_block +=
            u32::from(assessment.score >= WOULD_BLOCK_THRESHOLD && assessment.high_confidence);
        *resources_1m
            .entry(request.resource_id.as_str())
            .or_insert(0) += 1;
        *resources_15m
            .entry(request.resource_id.as_str())
            .or_insert(0) += 1;
    }
    (alerts, would_block)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: &str, timestamp_ms: i64) -> NormalizedRequest {
        NormalizedRequest {
            request_id: id.to_string(),
            sandbox_id: "native-sandbox".to_string(),
            scheme: "https".to_string(),
            host: "api.example.test".to_string(),
            port: 443,
            method: "GET".to_string(),
            route_template: "/repos/{owner}/{repo}".to_string(),
            resource_id: "team/docs".to_string(),
            resource_key: "resource-key".to_string(),
            action_class: "GET /repos/{owner}/{repo}".to_string(),
            restriction_scope: "https://api.example.test:443 GET /repos/{owner}/{repo} team/docs"
                .to_string(),
            high_impact: false,
            semantic_category: "read_only".to_string(),
            binary_path: Some("/usr/bin/curl".to_string()),
            ancestors: Vec::new(),
            fingerprint: format!("fingerprint-{id}"),
            timestamp_ms,
        }
    }

    fn session(id: &str, run: &str, start: i64, count: usize) -> TrainingSession {
        TrainingSession {
            session_id: id.to_string(),
            run_id: run.to_string(),
            started_at_ms: start,
            ended_at_ms: start + 60_000,
            observations: (0..count)
                .map(|index| TrainingObservation {
                    request: request(&format!("{id}-{index}"), start + index as i64 + 1),
                    base_outcome: DecisionOutcome::Allow,
                    base_risk_score: 0,
                })
                .collect(),
        }
    }

    fn mature_training() -> Vec<TrainingSession> {
        (0..20)
            .map(|index| {
                session(
                    &format!("training-{index}"),
                    &format!("training-run-{index}"),
                    1_000_000 + index * 60_000,
                    10,
                )
            })
            .collect()
    }

    fn later_holdout() -> Vec<TrainingSession> {
        (0..5)
            .map(|index| {
                session(
                    &format!("holdout-{index}"),
                    &format!("holdout-run-{index}"),
                    5_000_000 + index * 60_000,
                    10,
                )
            })
            .collect()
    }

    fn contribution(assessment: &AdaptiveAssessment, feature: &str) -> u32 {
        assessment
            .signals
            .iter()
            .find(|signal| signal.feature == feature)
            .expect("signal must be present")
            .contribution
    }

    #[test]
    fn learns_actual_counts_and_nearest_rank_quantiles_including_idle_minutes() {
        let mut captured = session("captured", "one-run", 1_000_000, 4);
        captured.ended_at_ms = captured.started_at_ms + 100 * 60_000;
        captured.observations[3].request.timestamp_ms = captured.started_at_ms + 120_001;
        captured.observations[3].request.resource_id = "team/other".to_string();
        captured.observations[3].request.binary_path = None;
        let profile = fit(&[captured], &[]).unwrap();

        assert_eq!(profile.training_sessions, 1);
        assert_eq!(profile.training_runs, 1);
        assert_eq!(profile.training_requests, 4);
        assert_eq!(profile.resource_counts["team/docs"], 3);
        assert_eq!(profile.resource_counts["team/other"], 1);
        assert_eq!(profile.action_counts["GET /repos/{owner}/{repo}"], 4);
        assert_eq!(
            profile.destination_counts["https://api.example.test:443"],
            4
        );
        assert_eq!(profile.binary_counts["/usr/bin/curl"], 3);
        assert_eq!(profile.known_binary_requests, 3);
        assert_eq!(profile.binary_training_runs, 1);
        assert_eq!(
            profile.rate,
            LearnedEnvelope {
                p95: 0,
                p99: 1,
                maximum: 3,
                windows: 100,
            }
        );
        assert_eq!(
            profile.fanout,
            LearnedEnvelope {
                p95: 2,
                p99: 2,
                maximum: 2,
                windows: 100,
            }
        );
        assert!(
            profile
                .readiness_reasons
                .iter()
                .any(|reason| reason.contains("sparse"))
        );
        assert!(!profile.tail_reliable);
    }

    #[test]
    fn independent_runs_are_not_pooled_into_simultaneous_workloads() {
        let training: Vec<_> = (0..20)
            .map(|index| session(&format!("s-{index}"), &format!("r-{index}"), 1_000_000, 10))
            .collect();
        let profile = fit(&training, &later_holdout()).unwrap();
        assert_eq!(profile.rate.maximum, 10);
        assert_eq!(profile.fanout.maximum, 1);
        assert_eq!(profile.training_runs, 20);
        assert!(profile.ready_for_enforcement);
    }

    #[test]
    fn fanout_idle_buckets_and_partial_minutes_are_actual_not_extrapolated() {
        let mut idle = session("idle", "idle-run", 1_000_001, 1);
        idle.ended_at_ms = idle.started_at_ms + 400 * 60_000;
        let profile = fit(&[idle], &[]).unwrap();
        assert_eq!(profile.fanout.windows, 400);
        assert_eq!(profile.fanout.p95, 0);
        assert_eq!(profile.fanout.p99, 1);
        assert_eq!(profile.fanout.maximum, 1);

        let mut partial = session("partial", "partial-run", 1_000_001, 4);
        partial.ended_at_ms += 1;
        partial.observations[3].request.timestamp_ms = partial.ended_at_ms - 1;
        let profile = fit(&[partial], &[]).unwrap();
        assert_eq!(profile.rate.windows, 2);
        assert_eq!(profile.rate.maximum, 3);
        assert_eq!(profile.training_requests, 4);
    }

    #[test]
    fn multiple_sessions_from_one_run_do_not_satisfy_independent_run_floors() {
        let mut training = mature_training();
        for capture in &mut training {
            capture.run_id = "one-rehearsal-is-not-twenty-runs".to_string();
        }
        let profile = fit(&training, &later_holdout()).unwrap();
        assert_eq!(profile.training_sessions, 20);
        assert_eq!(profile.training_runs, 1);
        assert_eq!(profile.binary_training_runs, 1);
        assert!(!profile.ready_for_enforcement);
    }

    #[test]
    fn small_captures_remain_provisional_and_missing_holdout_is_not_invented() {
        let profile = fit(&[session("small", "small-run", 1_000_000, 1)], &[]).unwrap();
        assert!(!profile.ready_for_enforcement);
        assert_eq!(profile.holdout_sessions, 0);
        assert_eq!(profile.holdout_runs, 0);
        assert_eq!(profile.holdout_requests, 0);
        assert_eq!(profile.holdout_alerts, 0);
        assert_eq!(profile.holdout_would_block, 0);
        assert!(!profile.readiness_reasons.is_empty());
    }

    #[test]
    fn phase1_readiness_uses_real_run_request_and_holdout_floors() {
        let training = mature_training();
        let holdout = later_holdout();
        let profile = fit(&training, &holdout).unwrap();
        assert_eq!(profile.training_requests, 200);
        assert_eq!(profile.holdout_runs, 5);
        assert_eq!(profile.holdout_requests, 50);
        assert!(profile.ready_for_enforcement);
        assert!(!profile.tail_reliable);
        assert!(
            profile
                .readiness_reasons
                .iter()
                .any(|reason| reason.contains("certification"))
        );

        let mut fewer_requests = training.clone();
        fewer_requests[0].observations.pop();
        assert!(
            !fit(&fewer_requests, &holdout)
                .unwrap()
                .ready_for_enforcement
        );
        assert!(!fit(&training, &holdout[..4]).unwrap().ready_for_enforcement);
        let mut fewer_holdout_requests = holdout;
        fewer_holdout_requests[0].observations.pop();
        assert!(
            !fit(&training, &fewer_holdout_requests)
                .unwrap()
                .ready_for_enforcement
        );
    }

    #[test]
    fn canonical_dataset_hash_is_order_independent_and_covers_both_partitions() {
        let mut training = mature_training();
        let mut holdout = later_holdout();
        let first = fit(&training, &holdout).unwrap();
        training.reverse();
        holdout.reverse();
        for capture in training.iter_mut().chain(&mut holdout) {
            capture.observations.reverse();
        }
        let reordered = fit(&training, &holdout).unwrap();
        assert_eq!(first.dataset_hash, reordered.dataset_hash);
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&reordered).unwrap()
        );
        holdout[0].observations[0].base_risk_score = 1;
        assert_ne!(
            first.dataset_hash,
            fit(&training, &holdout).unwrap().dataset_hash
        );
    }

    #[test]
    fn rejects_entire_dirty_captures_instead_of_learning_a_clean_subset() {
        let clean = session("clean", "run", 1_000_000, 2);
        for contamination in 0..8 {
            let mut dirty = clean.clone();
            let sample = &mut dirty.observations[1];
            match contamination {
                0 => sample.base_outcome = DecisionOutcome::Deny,
                1 => sample.base_risk_score = WOULD_BLOCK_THRESHOLD,
                2 => sample.request.high_impact = true,
                3 => sample.request.route_template = "unknown".to_string(),
                4 => sample.request.semantic_category = "unknown".to_string(),
                5 => sample.request.semantic_category = "write_mutation".to_string(),
                6 => sample.request.scheme = "file".to_string(),
                _ => sample.request.method = "DELETE".to_string(),
            }
            assert!(
                fit(&[dirty.clone()], &[]).is_err(),
                "contamination {contamination}"
            );
            dirty.session_id = "dirty-holdout".to_string();
            dirty.run_id = "later-run".to_string();
            dirty.started_at_ms += 1_000_000;
            dirty.ended_at_ms += 1_000_000;
            for sample in &mut dirty.observations {
                sample.request.timestamp_ms += 1_000_000;
                sample.request.request_id.push_str("-holdout");
            }
            assert!(fit(std::slice::from_ref(&clean), &[dirty]).is_err());
        }
    }

    #[test]
    fn rejects_post_graphql_while_allowing_non_graphql_read_only_query_posts() {
        let mut graphql = session("graphql", "run-gql", 1_000_000, 2);
        graphql.observations[1].request.method = "POST".to_string();
        graphql.observations[1].request.route_template = "/graphql".to_string();
        graphql.observations[1].request.action_class = "POST /graphql".to_string();
        graphql.observations[1].request.semantic_category = "read_only_query".to_string();
        assert!(fit(&[graphql], &[]).is_err());

        let mut git_upload_pack = session("git-pack", "run-pack", 1_000_000, 2);
        git_upload_pack.observations[1].request.method = "POST".to_string();
        git_upload_pack.observations[1].request.route_template =
            "/repos/:owner/:repo/git-upload-pack".to_string();
        git_upload_pack.observations[1].request.action_class =
            "POST /repos/:owner/:repo/git-upload-pack".to_string();
        git_upload_pack.observations[1].request.semantic_category = "read_only_query".to_string();
        assert!(fit(&[git_upload_pack], &[]).is_ok());
    }

    #[test]
    fn rejects_invalid_intervals_empty_inputs_and_out_of_capture_events() {
        assert!(fit(&[], &[]).is_err());
        assert!(fit(&[session("empty", "run", 1_000_000, 0)], &[]).is_err());
        let clean = session("s", "r", 1_000_000, 1);
        for invalid in 0..5 {
            let mut capture = clean.clone();
            match invalid {
                0 => capture.started_at_ms = -1,
                1 => capture.ended_at_ms = capture.started_at_ms,
                2 => capture.ended_at_ms = capture.started_at_ms - 1,
                3 => capture.observations[0].request.timestamp_ms = capture.started_at_ms - 1,
                _ => capture.observations[0].request.timestamp_ms = capture.ended_at_ms,
            }
            assert!(fit(&[capture], &[]).is_err(), "invalid interval {invalid}");
        }
    }

    #[test]
    fn rejects_duplicate_identities_run_overlap_and_chronological_leakage() {
        let clean = session("s", "r", 1_000_000, 2);
        let mut duplicate = clean.clone();
        duplicate.observations[1].request.request_id =
            duplicate.observations[0].request.request_id.clone();
        assert!(fit(&[duplicate], &[]).is_err());
        let mut other = session("other", "other-run", 1_000_000, 2);
        other.observations[0].request.request_id = clean.observations[0].request.request_id.clone();
        assert!(fit(&[clean.clone(), other], &[]).is_err());
        let mut holdout = session("h", "r", 2_000_000, 1);
        assert!(fit(std::slice::from_ref(&clean), &[holdout.clone()]).is_err());
        holdout.run_id = "new-run".to_string();
        holdout.started_at_ms = clean.ended_at_ms;
        assert!(fit(std::slice::from_ref(&clean), &[holdout.clone()]).is_err());
        holdout.started_at_ms = 1_010_000;
        assert!(fit(&[clean], &[holdout]).is_err());
    }

    #[test]
    fn identical_request_fingerprints_are_not_fake_duplicate_events() {
        let mut capture = session("s", "r", 1_000_000, 2);
        capture.observations[1].request.fingerprint =
            capture.observations[0].request.fingerprint.clone();
        assert_eq!(fit(&[capture], &[]).unwrap().training_requests, 2);
    }

    #[test]
    fn bounded_datasets_error_instead_of_truncating_samples_or_idle_windows() {
        assert!(fit(&[session("large", "r", 1_000_000, 501)], &[]).is_err());
        let mut too_long = session("long", "r", 1_000_000, 1);
        too_long.ended_at_ms = too_long.started_at_ms + 86_400_001;
        assert!(fit(&[too_long], &[]).is_err());
        let too_many: Vec<_> = (0..101)
            .map(|index| session(&format!("s-{index}"), &format!("r-{index}"), 1_000_000, 500))
            .collect();
        assert!(fit(&too_many, &[]).is_err());
        let too_many_windows: Vec<_> = (0..70)
            .map(|index| {
                let mut capture = session(&format!("s-{index}"), "run", 1_000_000, 1);
                capture.ended_at_ms += 86_340_000;
                capture
            })
            .collect();
        assert!(fit(&too_many_windows, &[]).is_err());
    }

    #[test]
    fn scoring_changes_with_learned_data_without_creating_permissions() {
        let known = fit(&mature_training(), &[]).unwrap();
        let mut different = mature_training();
        for capture in &mut different {
            for sample in &mut capture.observations {
                sample.request.host = "other.example.test".to_string();
                sample.request.resource_id = "team/other".to_string();
                sample.request.route_template = "/search".to_string();
                sample.request.action_class = "GET /search".to_string();
                sample.request.binary_path = Some("/usr/bin/wget".to_string());
            }
        }
        let other = fit(&different, &[]).unwrap();
        let current = request("live", 10_000_000);
        let before = serde_json::to_vec(&other).unwrap();
        assert_eq!(
            assess(&known, &current, &WindowSnapshot::default()).score,
            0
        );
        let unexpected = assess(&other, &current, &WindowSnapshot::default());
        assert!(unexpected.score >= WOULD_BLOCK_THRESHOLD);
        assert!(unexpected.high_confidence);
        assert_eq!(before, serde_json::to_vec(&other).unwrap());
        assert!(!other.ready_for_enforcement);
    }

    #[test]
    fn one_unseen_benign_category_or_target_is_never_a_confident_block() {
        let profile = fit(&mature_training(), &[]).unwrap();
        let mut benign = request("new-read", 10_000_000);
        benign.route_template = "/new-read".to_string();
        benign.action_class = "GET /new-read".to_string();
        let single = assess(&profile, &benign, &WindowSnapshot::default());
        assert!(single.score > 0);
        assert!(!single.high_confidence);
        benign.host = "new.example.test".to_string();
        benign.resource_id = "team/new".to_string();
        let target_and_action = assess(&profile, &benign, &WindowSnapshot::default());
        assert!(target_and_action.score < WOULD_BLOCK_THRESHOLD);
        assert!(!target_and_action.high_confidence);
    }

    #[test]
    fn empirical_rare_category_frequency_changes_positive_risk() {
        let mut rare = mature_training();
        rare[0].observations[0].request.resource_id = "team/rare".to_string();
        let mut common = rare.clone();
        for sample in &mut common[0].observations {
            sample.request.resource_id = "team/rare".to_string();
        }
        let rare_profile = fit(&rare, &[]).unwrap();
        let common_profile = fit(&common, &[]).unwrap();
        let mut current = request("live", 10_000_000);
        current.resource_id = "team/rare".to_string();
        assert!(
            assess(&rare_profile, &current, &WindowSnapshot::default()).score
                > assess(&common_profile, &current, &WindowSnapshot::default()).score
        );
    }

    #[test]
    fn temporal_excess_uses_headroom_and_warming_skips_temporal_signals() {
        let profile = fit(&mature_training(), &[]).unwrap();
        let current = request("live", 10_000_000);
        let modest = WindowSnapshot {
            req_count_1m: 20,
            distinct_resources_15m: 2,
            ..WindowSnapshot::default()
        };
        assert_eq!(assess(&profile, &current, &modest).score, 0);
        let excessive = WindowSnapshot {
            req_count_1m: 200,
            distinct_resources_15m: 100,
            ..WindowSnapshot::default()
        };
        let severe = assess(&profile, &current, &excessive);
        assert!(severe.high_confidence);
        assert!(contribution(&severe, "adaptive_rate_1m") >= WOULD_BLOCK_THRESHOLD);
        assert!(contribution(&severe, "adaptive_fanout_15m") >= WOULD_BLOCK_THRESHOLD);
        let warming = assess(
            &profile,
            &current,
            &WindowSnapshot {
                warming: true,
                ..excessive
            },
        );
        assert_eq!(warming.score, 0);
        assert!(!warming.high_confidence);
        assert!(
            warming
                .reasons
                .iter()
                .any(|reason| reason == "window_warming")
        );
    }

    #[test]
    fn temporal_risk_changes_when_the_observed_training_workload_changes() {
        let quiet = fit(&mature_training(), &[]).unwrap();
        let mut busier = mature_training();
        for capture in &mut busier {
            *capture = session(
                &capture.session_id,
                &capture.run_id,
                capture.started_at_ms,
                50,
            );
        }
        let busier = fit(&busier, &[]).unwrap();
        let current = request("live", 10_000_000);
        let window = WindowSnapshot {
            req_count_1m: 100,
            ..WindowSnapshot::default()
        };
        assert!(assess(&quiet, &current, &window).high_confidence);
        let expected_busier = assess(&busier, &current, &window);
        assert_eq!(expected_busier.score, 0);
        assert!(!expected_busier.high_confidence);
    }

    #[test]
    fn missing_process_identity_is_missing_coverage_not_a_learned_binary() {
        let profile = fit(&mature_training(), &[]).unwrap();
        let mut current = request("live", 10_000_000);
        current.binary_path = None;
        let missing = assess(&profile, &current, &WindowSnapshot::default());
        assert_eq!(contribution(&missing, "adaptive_binary"), 0);
        assert!(
            missing
                .reasons
                .iter()
                .any(|reason| reason == "missing_binary_identity")
        );
        let mut uncovered = mature_training();
        for capture in &mut uncovered {
            for sample in &mut capture.observations {
                sample.request.binary_path = None;
            }
        }
        let no_identity = fit(&uncovered, &[]).unwrap();
        assert_eq!(no_identity.known_binary_requests, 0);
        assert!(no_identity.binary_counts.is_empty());
        current.binary_path = Some("/usr/bin/new".to_string());
        let unsupported = assess(&no_identity, &current, &WindowSnapshot::default());
        assert_eq!(contribution(&unsupported, "adaptive_binary"), 0);
        assert!(
            unsupported
                .reasons
                .iter()
                .any(|reason| reason == "binary_novelty_unsupported")
        );
    }

    #[test]
    fn repeated_new_resources_do_not_fabricate_current_window_fanout() {
        let profile = fit(&mature_training(), &[]).unwrap();
        let mut current = request("new", 10_000_000);
        current.resource_id = "team/new".to_string();
        let assessment = assess(
            &profile,
            &current,
            &WindowSnapshot {
                distinct_resources_15m: 10,
                ..WindowSnapshot::default()
            },
        );
        assert_eq!(contribution(&assessment, "adaptive_fanout_15m"), 0);
    }

    #[test]
    fn binary_novelty_needs_independent_runs_and_observed_coverage() {
        let single_run = fit(&[session("single", "one-run", 1_000_000, 200)], &[]).unwrap();
        let mut current = request("live", 10_000_000);
        current.binary_path = Some("/usr/bin/unseen".to_string());
        assert_eq!(
            contribution(
                &assess(&single_run, &current, &WindowSnapshot::default()),
                "adaptive_binary"
            ),
            0
        );
        let mut partial = mature_training();
        for capture in &mut partial {
            for sample in &mut capture.observations[..5] {
                sample.request.binary_path = None;
            }
        }
        let partial = fit(&partial, &[]).unwrap();
        assert_eq!(partial.binary_training_runs, 20);
        assert_eq!(partial.known_binary_requests, 100);
        assert_eq!(
            contribution(
                &assess(&partial, &current, &WindowSnapshot::default()),
                "adaptive_binary"
            ),
            0
        );
    }

    #[test]
    fn network_model_never_makes_filesystem_or_other_transport_claims() {
        let profile = fit(&mature_training(), &[]).unwrap();
        let mut current = request("not-network", 10_000_000);
        current.scheme = "file".to_string();
        let assessment = assess(
            &profile,
            &current,
            &WindowSnapshot {
                req_count_1m: 10_000,
                ..WindowSnapshot::default()
            },
        );
        assert_eq!(assessment.score, 0);
        assert!(!assessment.high_confidence);
        assert!(assessment.signals.is_empty());
        assert!(
            assessment
                .reasons
                .iter()
                .any(|reason| reason == "unsupported_non_network_request")
        );
    }

    #[test]
    fn heldout_false_blocks_prevent_promotion_and_replay_is_causal() {
        let mut holdout = later_holdout();
        holdout[0] = session("holdout-burst", "holdout-burst-run", 5_000_000, 110);
        let profile = fit(&mature_training(), &holdout).unwrap();
        assert_eq!(profile.holdout_requests, 150);
        assert_eq!(profile.holdout_would_block, 11);
        assert_eq!(profile.holdout_alerts, 11);
        assert!(!profile.ready_for_enforcement);
        assert!(
            profile
                .readiness_reasons
                .iter()
                .any(|reason| reason.contains("would_block"))
        );
    }

    #[test]
    fn holdout_replay_expires_old_events_instead_of_accumulating_a_session_total() {
        let mut holdout = later_holdout();
        let mut separated = session("separated", "separated-run", 5_000_000, 120);
        separated.ended_at_ms = separated.started_at_ms + 120_000;
        for (index, sample) in separated.observations.iter_mut().enumerate() {
            sample.request.timestamp_ms =
                separated.started_at_ms + if index < 60 { 1 } else { 61_001 } + (index % 60) as i64;
        }
        holdout[0] = separated;
        let profile = fit(&mature_training(), &holdout).unwrap();
        assert_eq!(profile.holdout_requests, 160);
        assert_eq!(profile.holdout_alerts, 0);
        assert_eq!(profile.holdout_would_block, 0);
        assert!(profile.ready_for_enforcement);
    }

    #[test]
    fn heldout_would_blocks_require_confidence_not_just_correlated_novelty() {
        let mut holdout = later_holdout();
        for capture in &mut holdout {
            for sample in &mut capture.observations {
                sample.request.host = "new.example.test".to_string();
                sample.request.resource_id = "team/new".to_string();
                sample.request.route_template = "/new-read".to_string();
                sample.request.action_class = "GET /new-read".to_string();
            }
        }
        let profile = fit(&mature_training(), &holdout).unwrap();
        assert_eq!(profile.holdout_alerts, 50);
        assert_eq!(profile.holdout_would_block, 0);
        assert!(profile.ready_for_enforcement);
    }

    #[test]
    fn dataset_and_model_wire_types_reject_unknown_fields() {
        let capture = session("s", "r", 1_000_000, 1);
        let mut dataset = serde_json::to_value(&capture).unwrap();
        dataset["approved_permissions"] = serde_json::json!(["*"]);
        assert!(serde_json::from_value::<TrainingSession>(dataset).is_err());
        let mut sample = serde_json::to_value(&capture.observations[0]).unwrap();
        sample["training_requests"] = serde_json::json!(999_999);
        assert!(serde_json::from_value::<TrainingObservation>(sample).is_err());
        let profile = fit(&[capture], &[]).unwrap();
        let mut model = serde_json::to_value(profile).unwrap();
        model["probability"] = serde_json::json!(0.99);
        assert!(serde_json::from_value::<LearnedProfile>(model).is_err());
    }
}
