// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Offline evaluation of the adaptive learner. No cluster, no network, no clock: the same seeds give the same numbers.
//!
//! It generates scripted traffic for the fleet's sample agents (a Rust port of `scripts/ml/agents.py` and `generate.py`; the agent
//! models come from `testdata/adaptive-eval/fleet.json`, which `agents.py --dump` writes, so the two cannot drift apart), cuts the
//! benign part into hour-long captures the way the store does, fits the learner, then replays held-out later traffic, which holds
//! injected attacks, one event at a time with causal windows. It reports, per workload and overall, how many injected attack
//! episodes were caught and how many benign calls were falsely flagged or falsely blocked, each with a Wilson 95% interval.
//!
//! What the numbers are and are not: the traffic is scripted, small and written by the same hands as the attacks. A result is a
//! regression check on named shapes, not an accuracy figure against an unseen attacker. The real-data path
//! ([`evaluate_summaries`]) reads Risk Guard's exported per-minute activity summaries. They carry no attack labels, so it can only
//! report how often the learned rate and fan-out limits would have alerted on minutes that had no refusal, and it says which
//! workloads had too little history to be evaluated at all.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::adaptive::{
    self, AdaptiveAssessment, ContextInputs, FitOptions, LearnedProfile, Prior,
    SHADOW_ALERT_THRESHOLD, Tracker, TrainingObservation, TrainingSession, WOULD_BLOCK_THRESHOLD,
};
use crate::error::{Result, RiskGuardError};
use crate::types::{DecisionOutcome, NormalizedRequest};

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MINUTE_MS;
/// Start of every generated stream (the same constant as `generate.py`).
pub const START_MS: i64 = 1_800_000_000_000;
const FLEET_JSON: &str = include_str!("../testdata/adaptive-eval/fleet.json");
/// Benign calls within this long after an attack call are not scored as benign: the attack is still in their window.
const AFTERMATH_MS: i64 = 15 * MINUTE_MS;

// ---------------------------------------------------------------------------------------------------------------------------------
// Statistics

/// Wilson score interval for `k` successes in `n` trials at 95% confidence. `(0, 1)` when there are no trials.
#[must_use]
pub fn wilson(k: u32, n: u32) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let z = 1.959_963_984_540_054_f64;
    let n = f64::from(n);
    let p = f64::from(k) / n;
    let denominator = 1.0 + z * z / n;
    let centre = (p + z * z / (2.0 * n)) / denominator;
    let half = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt() / denominator;
    ((centre - half).max(0.0), (centre + half).min(1.0))
}

/// `k` of `n`, with its Wilson interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Rate {
    pub k: u32,
    pub n: u32,
    pub point: f64,
    pub low: f64,
    pub high: f64,
}

impl Rate {
    #[must_use]
    pub fn new(k: u32, n: u32) -> Self {
        let (low, high) = wilson(k, n);
        Self {
            k,
            n,
            point: if n == 0 {
                0.0
            } else {
                f64::from(k) / f64::from(n)
            },
            low,
            high,
        }
    }

    fn text(&self) -> String {
        if self.n == 0 {
            return "n/a".to_string();
        }
        format!(
            "{}/{} = {:.1}% [{:.1}, {:.1}]",
            self.k,
            self.n,
            self.point * 100.0,
            self.low * 100.0,
            self.high * 100.0
        )
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Deterministic random numbers (SplitMix64). Not the stream Python's `random` produces: the models are shared, the draws are not.

struct Rng(u64);

impl Rng {
    fn new(seed: u64, salt: u64) -> Self {
        let mut rng = Self(
            seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt.wrapping_mul(0xD1B5_4A32_D192_ED03),
        );
        rng.next_u64();
        rng
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Inclusive on both ends.
    fn range(&mut self, low: i64, high: i64) -> i64 {
        low + (self.next_u64() % (high - low + 1) as u64) as i64
    }
    fn exponential(&mut self, rate: f64) -> f64 {
        -(1.0 - self.unit()).ln() / rate
    }
    fn normal(&mut self) -> f64 {
        let u1 = 1.0 - self.unit();
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
    fn weighted(&mut self, weights: &[f64]) -> usize {
        let total: f64 = weights.iter().sum();
        let mut pick = self.unit() * total;
        for (index, weight) in weights.iter().enumerate() {
            if pick < *weight {
                return index;
            }
            pick -= weight;
        }
        weights.len() - 1
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The fleet and the traffic

#[derive(Debug, Clone, Deserialize)]
pub struct RouteModel {
    pub method: String,
    pub template: String,
    pub weight: f64,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentModel {
    pub task_profile: String,
    pub host: String,
    pub routes: Vec<RouteModel>,
    pub tempting: Vec<RouteModel>,
    pub sessions_per_hour: f64,
    pub calls_per_session: (i64, i64),
    pub think_ms: (f64, f64),
    pub binary: String,
}

/// The four sample agents, keyed by their fleet name.
pub fn fleet() -> Result<BTreeMap<String, AgentModel>> {
    Ok(serde_json::from_str(FLEET_JSON)?)
}

/// One call. `attack` is empty for benign traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub ts_ms: i64,
    pub workload: String,
    pub method: String,
    pub template: String,
    pub path: String,
    pub attack: String,
    pub episode: String,
}

impl Event {
    #[must_use]
    pub fn is_attack(&self) -> bool {
        !self.attack.is_empty()
    }
}

const ATTACK_KINDS: [&str; 5] = [
    "tempting_call",
    "enumeration",
    "burst",
    "slow_and_low",
    "subtle_write",
];

fn pick(rng: &mut Rng, routes: &[RouteModel]) -> (String, String, String) {
    let route = &routes[rng.weighted(&routes.iter().map(|r| r.weight).collect::<Vec<_>>())];
    let mut path = route.template.clone();
    if !route.values.is_empty() {
        let value = &route.values[rng.range(0, route.values.len() as i64 - 1) as usize];
        for placeholder in ["{svc}", "{name}", "{id}"] {
            path = path.replace(placeholder, value);
        }
    }
    (route.method.clone(), route.template.clone(), path)
}

fn routine(
    model: &AgentModel,
    workload: &str,
    rng: &mut Rng,
    hours: f64,
    novelty_permille: u32,
) -> Vec<Event> {
    let mut events = Vec::new();
    let end = START_MS + (hours * HOUR_MS as f64) as i64;
    let mut t = START_MS;
    loop {
        t += (rng.exponential(model.sessions_per_hour / 60.0) * MINUTE_MS as f64) as i64;
        if t >= end {
            return events;
        }
        let mut clock = t;
        for _ in 0..rng.range(model.calls_per_session.0, model.calls_per_session.1) {
            let (method, template, mut path) = pick(rng, &model.routes);
            // A benign call to a record the workload has never touched (a new ticket, a new bucket).
            if novelty_permille > 0
                && template.contains('{')
                && rng.range(0, 999) < i64::from(novelty_permille)
            {
                let fresh = format!("new-{}", rng.range(1, 1_000_000));
                path = template.clone();
                for placeholder in ["{svc}", "{name}", "{id}"] {
                    path = path.replace(placeholder, &fresh);
                }
            }
            events.push(Event {
                ts_ms: clock,
                workload: workload.to_string(),
                method,
                template,
                path,
                attack: String::new(),
                episode: String::new(),
            });
            clock += ((rng.normal() * model.think_ms.1).exp() * model.think_ms.0) as i64;
        }
    }
}

fn inject(
    kind: &str,
    model: &AgentModel,
    workload: &str,
    rng: &mut Rng,
    at: i64,
    episode: &str,
) -> Vec<Event> {
    let make = |ts_ms: i64, method: &str, template: &str, path: String| Event {
        ts_ms,
        workload: workload.to_string(),
        method: method.to_string(),
        template: template.to_string(),
        path,
        attack: kind.to_string(),
        episode: episode.to_string(),
    };
    match kind {
        "tempting_call" | "subtle_write" => {
            let (method, template, path) = pick(rng, &model.tempting);
            vec![make(at, &method, &template, path)]
        }
        "enumeration" => {
            let template = &model.routes[usize::from(model.routes.len() > 1)].template;
            (0..rng.range(25, 40))
                .map(|n| {
                    let id = rng.range(1000, 9999);
                    make(at + n * 400, "GET", template, format!("/probe/{id}"))
                })
                .collect()
        }
        "burst" => {
            let (method, template, path) = pick(rng, &model.routes);
            (0..rng.range(60, 120))
                .map(|n| make(at + n * 250, &method, &template, path.clone()))
                .collect()
        }
        _ => {
            let template = &model.routes[0].template;
            (0..rng.range(6, 10))
                .map(|n| {
                    make(
                        at + n * 20 * MINUTE_MS,
                        "GET",
                        template,
                        format!("/probe/{n}"),
                    )
                })
                .collect()
        }
    }
}

/// One generated workload: its id (the fleet name, plus a suffix for a second instance of the same model) and the model it follows.
#[derive(Debug, Clone)]
pub struct WorkloadSpec {
    pub id: String,
    pub model: String,
    /// Different instances of one model draw different traffic.
    pub instance: u64,
}

/// A seeded trace for `specs`. Routine traffic runs for `hours`; attacks land only after `split_ms` (70% of the time), away from the
/// edges. Returns the events per workload, each sorted by time.
pub fn generate(
    specs: &[WorkloadSpec],
    seed: u64,
    hours: f64,
    attacks_per_workload: u32,
    novelty_permille: u32,
) -> Result<(BTreeMap<String, Vec<Event>>, i64)> {
    let models = fleet()?;
    let split_ms = START_MS + (hours * 0.7 * HOUR_MS as f64) as i64;
    let end_ms = START_MS + (hours * HOUR_MS as f64) as i64;
    let mut out = BTreeMap::new();
    for spec in specs {
        let model = models
            .get(&spec.model)
            .ok_or_else(|| RiskGuardError::InvalidArgument(format!("no model {}", spec.model)))?;
        let mut rng = Rng::new(
            seed,
            spec.instance.wrapping_mul(1_000_003) + hash_text(&spec.id),
        );
        let mut events = routine(model, &spec.id, &mut rng, hours, novelty_permille);
        for n in 0..attacks_per_workload {
            let kind = ATTACK_KINDS[n as usize % ATTACK_KINDS.len()];
            let at = rng.range(split_ms + 30 * MINUTE_MS, end_ms - 3 * HOUR_MS);
            events.extend(inject(
                kind,
                model,
                &spec.id,
                &mut rng,
                at,
                &format!("{}-{n}", spec.id),
            ));
        }
        events.sort_by(|a, b| (a.ts_ms, &a.episode).cmp(&(b.ts_ms, &b.episode)));
        out.insert(spec.id.clone(), events);
    }
    Ok((out, split_ms))
}

fn hash_text(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The normalized request the store would hold for `event`. Routine calls are marked read-only so the learner admits them; whether the
/// store would admit a real write is a separate rule this harness does not model.
#[must_use]
pub fn to_request(event: &Event, model: &AgentModel, index: usize) -> NormalizedRequest {
    let action_class = format!("{} {}", event.method, event.template);
    NormalizedRequest {
        request_id: format!("{}-{index}", event.workload),
        sandbox_id: event.workload.clone(),
        scheme: "https".to_string(),
        host: model.host.clone(),
        port: 443,
        method: event.method.clone(),
        route_template: event.template.clone(),
        resource_id: event.path.clone(),
        resource_key: event.path.clone(),
        restriction_scope: format!("https://{}:443 {action_class} {}", model.host, event.path),
        action_class,
        high_impact: false,
        semantic_category: if event.method == "GET" {
            "read_only"
        } else {
            "read_only_query"
        }
        .to_string(),
        binary_path: Some(model.binary.clone()),
        ancestors: Vec::new(),
        fingerprint: format!("fp-{}-{index}", event.workload),
        timestamp_ms: event.ts_ms,
    }
}

/// Hour-long captures of `events` for hours in `[from_hour, to_hour)`, one run per hour, skipping empty hours.
fn captures(
    events: &[(NormalizedRequest, &Event)],
    workload: &str,
    from_hour: i64,
    to_hour: i64,
) -> Vec<TrainingSession> {
    let mut out = Vec::new();
    for hour in from_hour..to_hour {
        let start = START_MS + hour * HOUR_MS;
        let end = start + HOUR_MS;
        let observations: Vec<_> = events
            .iter()
            .filter(|(request, event)| {
                !event.is_attack() && request.timestamp_ms >= start && request.timestamp_ms < end
            })
            .map(|(request, _)| TrainingObservation {
                request: request.clone(),
                base_outcome: DecisionOutcome::Allow,
                base_risk_score: 0,
            })
            .collect();
        if !observations.is_empty() {
            out.push(TrainingSession {
                session_id: format!("{workload}-session-{hour}"),
                run_id: format!("{workload}-run-{hour}"),
                started_at_ms: start,
                ended_at_ms: end,
                observations,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Scoring a held-out stream

/// How one event was scored.
#[derive(Debug, Clone, Copy)]
pub struct Scored {
    pub score: u32,
    pub alert: bool,
    pub block: bool,
}

fn judge(assessment: &AdaptiveAssessment) -> Scored {
    Scored {
        score: assessment.score,
        alert: assessment.score >= SHADOW_ALERT_THRESHOLD,
        block: assessment.score >= WOULD_BLOCK_THRESHOLD && assessment.high_confidence,
    }
}

/// Synthetic SIEM context to feed the learner. There is no real context data, so this only exercises the mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextMode {
    /// None supplied.
    Off,
    /// Counts unrelated to the attacks: about one call in twenty carries four recent OpenShell denials.
    Noise,
    /// Counts correlated with the attacks by construction: denials in the five minutes around an attack call. Shows that the
    /// mechanism raises scores; it says nothing about whether real denials track real attacks.
    Correlated,
}

fn synthetic_context(
    mode: ContextMode,
    index: usize,
    ts_ms: i64,
    attack_times: &[i64],
) -> Option<ContextInputs> {
    match mode {
        ContextMode::Off => None,
        ContextMode::Noise => {
            hash_text(&index.to_string())
                .is_multiple_of(20)
                .then(|| ContextInputs {
                    openshell_denials_5m: Some(4),
                    ..ContextInputs::default()
                })
        }
        ContextMode::Correlated => attack_times
            .iter()
            .any(|at| *at <= ts_ms && ts_ms - *at <= 5 * MINUTE_MS)
            .then(|| ContextInputs {
                openshell_denials_5m: Some(4 + (index % 9) as u32),
                fleet_workloads_with_denials_5m: Some(3),
                ..ContextInputs::default()
            }),
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Experiments

/// Where a model's prior comes from in the cold-start experiments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriorMode {
    None,
    /// Pooled from a second, independent instance of the same task profile (a sibling workload).
    TaskProfile,
    /// Pooled from workloads of other task profiles (rates and shape only).
    Fleet,
}

/// What to train on and what to hold back, in hours from the start of the stream.
#[derive(Debug, Clone)]
pub struct Plan {
    pub seeds: Vec<u64>,
    pub hours: f64,
    pub attacks_per_workload: u32,
    /// Training captures come from hours `[0, train_hours)`.
    pub train_hours: i64,
    /// Gate-holdout captures come from hours `[holdout_from, holdout_from + holdout_hours)`.
    pub holdout_from: i64,
    pub holdout_hours: i64,
    /// Chance in a thousand that a benign call to a route with a variable touches a resource never seen before. Zero is the closed
    /// world `scripts/ml` generates; a few per thousand is a more honest stand-in for real agents meeting new records.
    pub novelty_permille: u32,
    pub context: ContextMode,
}

impl Plan {
    /// 72 hours, 12 attacks per workload (as `generate.py`), 40 training hours, a gap, 10 holdout hours, then the test period.
    #[must_use]
    pub fn standard(seeds: Vec<u64>) -> Self {
        Self {
            seeds,
            hours: 72.0,
            attacks_per_workload: 12,
            train_hours: 40,
            holdout_from: 41,
            holdout_hours: 10,
            novelty_permille: 0,
            context: ContextMode::Off,
        }
    }
}

/// Counts for one workload (or the sum over all of them).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Row {
    pub workload: String,
    pub benign_events: u32,
    pub aftermath_excluded: u32,
    pub false_alerts: Rate,
    pub false_blocks: Rate,
    /// Attack episodes caught at the alert line (score 40) and at the would-block line (score 70 with confidence), per shape.
    pub alert_by_kind: BTreeMap<String, Rate>,
    pub block_by_kind: BTreeMap<String, Rate>,
    pub alert_overall: Rate,
    pub block_overall: Rate,
    /// Models fitted for this row, and how many met the learner's own promotion gates.
    pub models: u32,
    pub models_ready: u32,
}

#[derive(Debug, Clone, Default)]
struct Tally {
    benign: u32,
    aftermath: u32,
    false_alerts: u32,
    false_blocks: u32,
    alert: BTreeMap<String, (u32, u32)>,
    block: BTreeMap<String, (u32, u32)>,
    models: u32,
    ready: u32,
}

impl Tally {
    fn merge(&mut self, other: &Tally) {
        self.benign += other.benign;
        self.aftermath += other.aftermath;
        self.false_alerts += other.false_alerts;
        self.false_blocks += other.false_blocks;
        self.models += other.models;
        self.ready += other.ready;
        for (kind, (k, n)) in &other.alert {
            let entry = self.alert.entry(kind.clone()).or_default();
            entry.0 += k;
            entry.1 += n;
        }
        for (kind, (k, n)) in &other.block {
            let entry = self.block.entry(kind.clone()).or_default();
            entry.0 += k;
            entry.1 += n;
        }
    }

    fn row(&self, workload: &str) -> Row {
        let sum = |map: &BTreeMap<String, (u32, u32)>| {
            Rate::new(
                map.values().map(|(k, _)| k).sum(),
                map.values().map(|(_, n)| n).sum(),
            )
        };
        let rates = |map: &BTreeMap<String, (u32, u32)>| {
            map.iter()
                .map(|(kind, (k, n))| (kind.clone(), Rate::new(*k, *n)))
                .collect()
        };
        Row {
            workload: workload.to_string(),
            benign_events: self.benign,
            aftermath_excluded: self.aftermath,
            false_alerts: Rate::new(self.false_alerts, self.benign),
            false_blocks: Rate::new(self.false_blocks, self.benign),
            alert_by_kind: rates(&self.alert),
            block_by_kind: rates(&self.block),
            alert_overall: sum(&self.alert),
            block_overall: sum(&self.block),
            models: self.models,
            models_ready: self.ready,
        }
    }
}

/// A named way to fit and score. The evaluation is the same for every method; only these choices change.
#[derive(Debug, Clone)]
pub struct Method {
    pub name: String,
    /// Fit and score with the first learner, which ignores everything below.
    pub v1: bool,
    pub options: FitOptions,
    pub prior: PriorMode,
}

impl Method {
    /// The first learner, exactly as it was before version 2.
    #[must_use]
    pub fn v1() -> Self {
        Self {
            name: format!("v1 ({})", adaptive::ALGORITHM_VERSION_V1),
            v1: true,
            options: FitOptions::default(),
            prior: PriorMode::None,
        }
    }

    /// The learner as it ships: every v2 component on, no pooled prior.
    #[must_use]
    pub fn current() -> Self {
        Self::v2(
            "v2 (all components, no prior)",
            FitOptions::default(),
            PriorMode::None,
        )
    }

    #[must_use]
    pub fn v2(name: &str, options: FitOptions, prior: PriorMode) -> Self {
        Self {
            name: name.to_string(),
            v1: false,
            options,
            prior,
        }
    }

    fn fit(
        &self,
        training: &[TrainingSession],
        holdout: &[TrainingSession],
        prior: Option<Prior>,
    ) -> Result<LearnedProfile> {
        if self.v1 {
            adaptive::fit_v1(training, holdout)
        } else {
            adaptive::fit_with(training, holdout, &self.options, prior)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub method: String,
    pub scenario: String,
    pub seeds: Vec<u64>,
    pub rows: Vec<Row>,
    pub overall: Row,
    pub notes: Vec<String>,
}

fn score_stream(
    profile: &LearnedProfile,
    context: ContextMode,
    stream: &[(NormalizedRequest, &Event)],
    split_ms: i64,
    tally: &mut Tally,
) {
    let mut tracker = Tracker::new();
    let attack_times: Vec<i64> = stream
        .iter()
        .filter(|(_, event)| event.is_attack())
        .map(|(request, _)| request.timestamp_ms)
        .collect();
    let mut episodes: BTreeMap<&str, (&str, bool, bool)> = BTreeMap::new();
    for (index, (request, event)) in stream.iter().enumerate() {
        if request.timestamp_ms >= split_ms {
            let (window, events) = tracker.view(request.timestamp_ms);
            let supplied = synthetic_context(context, index, request.timestamp_ms, &attack_times);
            let scored = judge(&adaptive::assess_in_context(
                profile,
                request,
                &window,
                Some(events),
                supplied.as_ref(),
            ));
            if event.is_attack() {
                let entry = episodes.entry(event.episode.as_str()).or_insert((
                    event.attack.as_str(),
                    false,
                    false,
                ));
                entry.1 |= scored.alert;
                entry.2 |= scored.block;
            } else if attack_times
                .iter()
                .any(|at| *at < request.timestamp_ms && request.timestamp_ms - *at <= AFTERMATH_MS)
            {
                tally.aftermath += 1;
            } else {
                tally.benign += 1;
                tally.false_alerts += u32::from(scored.alert);
                tally.false_blocks += u32::from(scored.block);
            }
        }
        tracker.push(request);
    }
    for (kind, alert, block) in episodes.values() {
        let a = tally.alert.entry((*kind).to_string()).or_default();
        a.0 += u32::from(*alert);
        a.1 += 1;
        let b = tally.block.entry((*kind).to_string()).or_default();
        b.0 += u32::from(*block);
        b.1 += 1;
    }
}

type Stream<'a> = Vec<(NormalizedRequest, &'a Event)>;

fn stream_of<'a>(events: &'a [Event], model: &AgentModel) -> Stream<'a> {
    events
        .iter()
        .enumerate()
        .map(|(index, event)| (to_request(event, model, index), event))
        .collect()
}

/// Fit on each workload's own training captures (plus the prior `method` asks for) and score its held-out stream. Every fleet model
/// runs as two independent instances: the first is evaluated, the second is its sibling, a workload of the same task profile that
/// supplies the pooled prior.
pub fn evaluate(method: &Method, plan: &Plan, scenario: &str, train_hours: i64) -> Result<Report> {
    let models = fleet()?;
    let mut specs = Vec::new();
    for name in models.keys() {
        specs.push(WorkloadSpec {
            id: name.clone(),
            model: name.clone(),
            instance: 0,
        });
        specs.push(WorkloadSpec {
            id: format!("{name}-sibling"),
            model: name.clone(),
            instance: 1,
        });
    }
    let mut by_workload: BTreeMap<String, Tally> = BTreeMap::new();
    for seed in &plan.seeds {
        let (traffic, split_ms) = generate(
            &specs,
            *seed,
            plan.hours,
            plan.attacks_per_workload,
            plan.novelty_permille,
        )?;
        let holdout_range = plan.holdout_from..plan.holdout_from + plan.holdout_hours;
        // Sibling models, trained on their full training hours without a prior: the raw material for the pooled priors.
        let mut siblings: BTreeMap<String, LearnedProfile> = BTreeMap::new();
        if !method.v1 && method.prior != PriorMode::None {
            for name in models.keys() {
                let id = format!("{name}-sibling");
                let stream = stream_of(&traffic[&id], &models[name]);
                let fitted = adaptive::fit_with(
                    &captures(&stream, &id, 0, plan.train_hours),
                    &captures(&stream, &id, holdout_range.start, holdout_range.end),
                    &method.options,
                    None,
                );
                if let Ok(profile) = fitted {
                    siblings.insert(name.clone(), profile);
                }
            }
        }
        for name in models.keys() {
            let model = &models[name];
            let events = &traffic[name];
            let stream = stream_of(events, model);
            let training = captures(&stream, name, 0, train_hours);
            let holdout = captures(&stream, name, holdout_range.start, holdout_range.end);
            let prior = match method.prior {
                PriorMode::None => None,
                PriorMode::TaskProfile => siblings.get(name).and_then(|profile| {
                    adaptive::pool(
                        "task_profile",
                        &[(format!("{name}-sibling"), profile)],
                        true,
                    )
                }),
                PriorMode::Fleet => {
                    let others: Vec<(String, &LearnedProfile)> = siblings
                        .iter()
                        .filter(|(other, _)| *other != name)
                        .map(|(other, profile)| (format!("{other}-sibling"), profile))
                        .collect();
                    adaptive::pool("fleet", &others, false)
                }
            };
            let tally = by_workload.entry(name.clone()).or_default();
            let Ok(profile) = method.fit(&training, &holdout, prior) else {
                continue;
            };
            tally.models += 1;
            tally.ready += u32::from(profile.ready_for_enforcement);
            score_stream(&profile, plan.context, &stream, split_ms, tally);
        }
    }
    let mut overall = Tally::default();
    let mut rows = Vec::new();
    for (workload, tally) in &by_workload {
        overall.merge(tally);
        rows.push(tally.row(workload));
    }
    Ok(Report {
        method: method.name.clone(),
        scenario: scenario.to_string(),
        seeds: plan.seeds.clone(),
        rows,
        overall: overall.row("all workloads"),
        notes: vec![
            "Scripted traffic generated by a Rust port of scripts/ml; attacks are written by the same hands as the generator. This is a regression check on named shapes, not accuracy against an unseen attacker.".to_string(),
            "Episodes are the unit for detection. Benign events are the unit for false flags, and events in one session are correlated, so those intervals are narrower than the truth.".to_string(),
            format!("Benign calls within {} minutes after an attack call are excluded (their window still holds the attack) and counted as aftermath.", AFTERMATH_MS / MINUTE_MS),
        ],
    })
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Real summaries

/// One line of `data/real/summaries.jsonl`, as `scripts/ml/summaries.py --export` writes it.
#[derive(Debug, Clone, Deserialize)]
pub struct SummaryRow {
    pub ts: i64,
    pub workload: String,
    pub total: f64,
    pub refused_calls: f64,
    #[serde(default)]
    pub distinct_routes: f64,
}

#[derive(Deserialize)]
struct RawSummary {
    ts: Option<i64>,
    workload: Option<String>,
    total: Option<f64>,
    refused_calls: Option<f64>,
    distinct_routes: Option<f64>,
}

/// Parse the export. Rows the SIEM could not attribute to a workload (no name or no time) are left out: they cannot be placed in a
/// workload's history.
pub fn parse_summaries(text: &str) -> Result<Vec<SummaryRow>> {
    let mut rows = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let raw: RawSummary = serde_json::from_str(line).map_err(RiskGuardError::from)?;
        if let (Some(ts), Some(workload)) = (raw.ts, raw.workload) {
            rows.push(SummaryRow {
                ts,
                workload,
                total: raw.total.unwrap_or(0.0),
                refused_calls: raw.refused_calls.unwrap_or(0.0),
                distinct_routes: raw.distinct_routes.unwrap_or(0.0),
            });
        }
    }
    Ok(rows)
}

/// What the real summaries can and cannot tell us about one workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealRow {
    /// A stable label by rank of history, not the workload's identity.
    pub label: String,
    pub active_minutes: u32,
    pub status: String,
    pub trained_on: u32,
    pub tested: u32,
    /// Test minutes with no refusal that the learned rate or fan-out limit would have alerted on.
    pub quiet_minutes: u32,
    pub false_alerts: Rate,
    /// Test minutes in which Risk Guard refused something. They are not labelled attacks; this is only how many of them the
    /// learned limits would also have alerted on.
    pub refusal_minutes: u32,
    pub refusal_minutes_alerted: u32,
}

/// Minimum active minutes before a workload is evaluated (the same floor `summaries.py` uses).
pub const MIN_REAL_MINUTES: usize = 120;

/// Fit the learner's rate and fan-out limits on the first 70% of each workload's active minutes and count alerts on the rest.
/// The summary rows hold a count per minute and no requests, so the categorical parts of the learner cannot be evaluated here.
#[must_use]
pub fn evaluate_summaries(rows: &[SummaryRow]) -> Vec<RealRow> {
    let mut by_workload: BTreeMap<&str, Vec<&SummaryRow>> = BTreeMap::new();
    for row in rows {
        by_workload
            .entry(row.workload.as_str())
            .or_default()
            .push(row);
    }
    let mut ranked: Vec<_> = by_workload.into_iter().collect();
    ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    ranked
        .into_iter()
        .enumerate()
        .map(|(rank, (_, mut mine))| {
            mine.sort_by_key(|row| row.ts);
            let label = format!("workload-{}", rank + 1);
            if mine.len() < MIN_REAL_MINUTES {
                return RealRow {
                    label,
                    active_minutes: mine.len() as u32,
                    status: format!(
                        "not evaluated: {} active minutes, needs {MIN_REAL_MINUTES}",
                        mine.len()
                    ),
                    trained_on: 0,
                    tested: 0,
                    quiet_minutes: 0,
                    false_alerts: Rate::new(0, 0),
                    refusal_minutes: 0,
                    refusal_minutes_alerted: 0,
                };
            }
            let cut = mine.len() * 7 / 10;
            let rate =
                adaptive::learn_envelope(mine[..cut].iter().map(|r| r.total as u32).collect());
            let fanout = adaptive::learn_envelope(
                mine[..cut]
                    .iter()
                    .map(|r| r.distinct_routes as u32)
                    .collect(),
            );
            let alerts = |row: &SummaryRow| {
                adaptive::temporal_excess(row.total as u32 + 1, &rate, (20, 100)).0 > 0
                    || adaptive::temporal_excess(row.distinct_routes as u32, &fanout, (10, 30)).0
                        > 0
            };
            let (mut quiet, mut quiet_alerts, mut refusal, mut refusal_alerts) = (0, 0, 0, 0);
            for row in &mine[cut..] {
                if row.refused_calls > 0.0 {
                    refusal += 1;
                    refusal_alerts += u32::from(alerts(row));
                } else {
                    quiet += 1;
                    quiet_alerts += u32::from(alerts(row));
                }
            }
            RealRow {
                label,
                active_minutes: mine.len() as u32,
                status: "evaluated (rate and fan-out limits only; no attack labels exist)"
                    .to_string(),
                trained_on: cut as u32,
                tested: (mine.len() - cut) as u32,
                quiet_minutes: quiet,
                false_alerts: Rate::new(quiet_alerts, quiet),
                refusal_minutes: refusal,
                refusal_minutes_alerted: refusal_alerts,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Text

impl Report {
    /// A Markdown table suitable for pasting into a document.
    #[must_use]
    pub fn markdown(&self) -> String {
        let mut text = format!(
            "**{}** , {} , seeds {:?}\n\n",
            self.method, self.scenario, self.seeds
        );
        text.push_str("| workload | models (ready) | benign calls | false alerts (score 40+) | false blocks (would-block) | attacks caught: alert | attacks caught: block |\n|---|---|---|---|---|---|---|\n");
        for row in self.rows.iter().chain(std::iter::once(&self.overall)) {
            text.push_str(&format!(
                "| {} | {} ({}) | {} | {} | {} | {} | {} |\n",
                row.workload,
                row.models,
                row.models_ready,
                row.benign_events,
                row.false_alerts.text(),
                row.false_blocks.text(),
                row.alert_overall.text(),
                row.block_overall.text()
            ));
        }
        text.push_str("\n| attack shape (all workloads) | caught at alert | caught at would-block |\n|---|---|---|\n");
        for (kind, alert) in &self.overall.alert_by_kind {
            text.push_str(&format!(
                "| {kind} | {} | {} |\n",
                alert.text(),
                self.overall
                    .block_by_kind
                    .get(kind)
                    .copied()
                    .unwrap_or_default()
                    .text()
            ));
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn wilson_matches_known_values() {
        let (low, high) = wilson(5, 10);
        assert!((low - 0.2366).abs() < 0.001 && (high - 0.7634).abs() < 0.001);
        let (low, high) = wilson(0, 20);
        assert!(low == 0.0 && (high - 0.1611).abs() < 0.001);
        let (low, high) = wilson(20, 20);
        assert!((low - 0.8389).abs() < 0.001 && high == 1.0);
        assert_eq!(wilson(0, 0), (0.0, 1.0));
    }

    #[test]
    fn the_same_seed_gives_the_same_traffic_and_attacks_land_after_the_split() {
        let specs = [WorkloadSpec {
            id: "release".into(),
            model: "release".into(),
            instance: 0,
        }];
        let (a, split) = generate(&specs, 3, 72.0, 12, 0).unwrap();
        let (b, _) = generate(&specs, 3, 72.0, 12, 0).unwrap();
        let (c, _) = generate(&specs, 4, 72.0, 12, 0).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        let events = &a["release"];
        assert!(events.windows(2).all(|pair| pair[0].ts_ms <= pair[1].ts_ms));
        assert!(
            events
                .iter()
                .filter(|event| event.is_attack())
                .all(|event| event.ts_ms >= split)
        );
        let episodes: BTreeSet<_> = events
            .iter()
            .filter(|event| event.is_attack())
            .map(|event| &event.episode)
            .collect();
        assert_eq!(episodes.len(), 12);
    }
}
