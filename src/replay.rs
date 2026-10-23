// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Decision replay: re-run a recorded sequence of decisions from a known initial state and check that the same decisions come out.
//!
//! Version numbers alone cannot do this, because a decision depends on state that earlier decisions built: request counts in time windows,
//! latched restrictions and their carry-over between runs, and the guardrail settings in force at each moment. The unit of replay is
//! therefore one **scoring context** (an agent's revision, task profile, baseline, detector configuration and mode), which is the unit
//! that owns that state. A bundle holds everything needed to rebuild it from nothing, and the recorded outcome of every decision.
//!
//! What a bundle contains: the normalized requests (method, host, route template, resource names, a keyed hash of each resource, binary
//! paths), the baseline profiles, the guardrail revisions, the run and epoch structure, restriction clearances (scope and time only), and the
//! recorded results. What it does not contain: bodies, headers, tokens, signing or HMAC keys, operator identities or reasons, or network policy text.
//!
//! What it cannot do, and says so: if history was pruned, if decisions lack attribution, or if an adaptive model was enforced, the bundle is
//! marked incomplete and replay refuses it unless told to continue.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::detector::{InteractionRiskDetector, compute_baseline_hash};
use crate::error::{Result, RiskGuardError};
use crate::guardrails::{AgentGuardrails, GuardrailsSaveResult, GuardrailsUpdate};
use crate::store::RestrictionTarget;
use crate::store::SqliteRiskStore;
use crate::types::{
    BaselineProfile, EnforcementMode, EpochRecord, NormalizedRequest, RiskDetector, RiskEvaluation,
    RiskStore,
};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub format_version: u32,
    pub exported_at_ms: i64,
    pub build: ReplayBuild,
    pub agent: ReplayAgent,
    pub context: ReplayContext,
    /// The context's baseline first, then every profile a guardrail revision refers to.
    pub baselines: Vec<BaselineProfile>,
    pub guardrail_revisions: Vec<ReplayGuardrailRevision>,
    pub runs: Vec<String>,
    pub epochs: Vec<ReplayEpoch>,
    /// In the order the decisions were committed, with operator clearances placed where they happened.
    pub events: Vec<ReplayEvent>,
    pub history: ReplayHistory,
    pub limits: Vec<String>,
    /// SHA-256 of the rest of the bundle, to detect damage or editing. It does not prove who made it.
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBuild {
    pub crate_version: String,
    pub detector_version: String,
    pub configuration_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayAgent {
    pub agent_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayContext {
    pub context_id: String,
    pub agent_revision: String,
    pub task_profile: String,
    pub baseline_hash: String,
    pub mode: EnforcementMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayGuardrailRevision {
    pub revision: u64,
    pub settings: AgentGuardrails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEpoch {
    pub epoch_id: String,
    pub sandbox_id: String,
    pub gateway_id: String,
    pub run_id: String,
    pub task_profile: String,
    pub baseline_hash: String,
    pub mode: EnforcementMode,
    pub created_at_ms: i64,
    pub initial_next_sequence: u64,
    pub credentialed_endpoints: BTreeSet<(String, u16)>,
    pub active_policy_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReplayEvent {
    Decision {
        order: u64,
        epoch_id: String,
        guardrail_revision: Option<u64>,
        request: Box<NormalizedRequest>,
        recorded: Box<RiskEvaluation>,
    },
    Clearance {
        scope: String,
        tier: String,
        cleared_at_ms: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayHistory {
    /// False when the stored history cannot rebuild the starting state, so a replay would be a guess.
    pub complete: bool,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayReport {
    pub reproduced: bool,
    pub decisions: usize,
    pub matched: usize,
    pub clearances_applied: usize,
    pub checks: ReplayChecks,
    pub divergences: Vec<Divergence>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayChecks {
    pub content_hash_ok: bool,
    pub baseline_hash_ok: bool,
    pub history_complete: bool,
    pub detector_version_matches: bool,
    pub configuration_matches: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Divergence {
    pub order: u64,
    pub request_id: String,
    pub field: String,
    pub recorded: String,
    pub replayed: String,
}

impl ReplayBundle {
    pub fn compute_hash(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.content_hash = String::new();
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&copy)?)))
    }

    pub fn seal(mut self) -> Result<Self> {
        self.content_hash = self.compute_hash()?;
        Ok(self)
    }
}

pub fn current_build() -> Result<ReplayBuild> {
    let detector = InteractionRiskDetector::new_default();
    Ok(ReplayBuild {
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
        detector_version: detector.detector_version().to_string(),
        configuration_id: detector.configuration_id(),
    })
}

fn invalid(message: impl Into<String>) -> RiskGuardError {
    RiskGuardError::InvalidArgument(message.into())
}

/// Rebuild the scoring context in a fresh in-memory store and feed it the recorded requests in order.
pub fn replay(bundle: &ReplayBundle, allow_incomplete: bool) -> Result<ReplayReport> {
    let build = current_build()?;
    let mut notes = Vec::new();
    let content_hash_ok = bundle.compute_hash()? == bundle.content_hash;
    let main_baseline = bundle
        .baselines
        .first()
        .ok_or_else(|| invalid("the bundle has no baseline"))?;
    let baseline_hash_ok = compute_baseline_hash(main_baseline) == bundle.context.baseline_hash;
    let checks = ReplayChecks {
        content_hash_ok,
        baseline_hash_ok,
        history_complete: bundle.history.complete,
        detector_version_matches: build.detector_version == bundle.build.detector_version,
        configuration_matches: build.configuration_id == bundle.build.configuration_id,
    };
    if !content_hash_ok {
        return Err(invalid(
            "the bundle was changed after it was written (content hash does not match)",
        ));
    }
    if !baseline_hash_ok {
        return Err(invalid(
            "the bundle's baseline does not match the baseline hash it names",
        ));
    }
    if bundle.format_version != FORMAT_VERSION {
        return Err(invalid(format!(
            "unsupported replay format {}",
            bundle.format_version
        )));
    }
    if !bundle.history.complete && !allow_incomplete {
        return Err(invalid(format!(
            "the recorded history is incomplete, so the starting state is unknown: {}",
            bundle.history.problems.join("; ")
        )));
    }
    if !checks.configuration_matches {
        notes.push("this build's detector configuration differs from the one that made the decisions; differences below may come from that".into());
    }

    let store = SqliteRiskStore::open_in_memory()?;
    for profile in &bundle.baselines {
        store.store_baseline(profile)?;
    }
    store.register_agent(&bundle.agent.agent_id, &bundle.agent.display_name)?;

    // Guardrail revisions are applied one at a time, in order, just before the first decision that was made under them.
    let mut applied = 0u64;
    let first_revision = bundle
        .events
        .iter()
        .find_map(|event| match event {
            ReplayEvent::Decision {
                guardrail_revision, ..
            } => *guardrail_revision,
            ReplayEvent::Clearance { .. } => None,
        })
        .unwrap_or(0);
    // The store numbers its revisions consecutively; the original numbers may have gaps, and scoring does not read them.
    let mut store_revision = 0u64;
    let mut apply = |store: &SqliteRiskStore, target: u64| -> Result<()> {
        for revision in bundle
            .guardrail_revisions
            .iter()
            .filter(|r| r.revision <= target)
        {
            if revision.revision <= applied {
                continue;
            }
            match store.save_agent_guardrails(
                &bundle.agent.agent_id,
                &GuardrailsUpdate {
                    expected_revision: store_revision,
                    settings: revision.settings.clone(),
                },
                "replay",
                0,
            )? {
                GuardrailsSaveResult::Saved(_) => store_revision += 1,
                GuardrailsSaveResult::Conflict { current_revision } => {
                    return Err(invalid(format!(
                        "guardrail revision conflict at {current_revision} while replaying"
                    )));
                }
            }
            applied = revision.revision;
        }
        Ok(())
    };
    apply(&store, first_revision)?;

    for run in &bundle.runs {
        store.create_agent_run(
            &bundle.agent.agent_id,
            run,
            &bundle.context.agent_revision,
            &bundle.context.task_profile,
            bundle.context.mode,
        )?;
    }
    let epochs: BTreeMap<&str, &ReplayEpoch> = bundle
        .epochs
        .iter()
        .map(|e| (e.epoch_id.as_str(), e))
        .collect();
    let mut active: BTreeMap<String, String> = BTreeMap::new();
    let detector = InteractionRiskDetector::new_default();
    let mut report = ReplayReport {
        reproduced: false,
        decisions: 0,
        matched: 0,
        clearances_applied: 0,
        checks,
        divergences: Vec::new(),
        notes,
    };

    for event in &bundle.events {
        match event {
            ReplayEvent::Clearance {
                scope,
                cleared_at_ms,
                ..
            } => {
                let result = store.clear_restriction(
                    RestrictionTarget::Agent {
                        agent_id: &bundle.agent.agent_id,
                        context_id: None,
                    },
                    scope,
                    "replay",
                    "replay of a recorded operator clearance",
                    *cleared_at_ms,
                );
                match result {
                    Ok(_) => report.clearances_applied += 1,
                    Err(error) => report.divergences.push(Divergence {
                        order: 0,
                        request_id: String::new(),
                        field: "clearance".into(),
                        recorded: format!("restriction at {scope} cleared"),
                        replayed: format!("could not clear: {error}"),
                    }),
                }
            }
            ReplayEvent::Decision {
                order,
                epoch_id,
                guardrail_revision,
                request,
                recorded,
            } => {
                if let Some(revision) = guardrail_revision {
                    apply(&store, *revision)?;
                }
                let epoch = epochs.get(epoch_id.as_str()).ok_or_else(|| {
                    invalid(format!(
                        "decision {} names an epoch the bundle does not describe",
                        request.request_id
                    ))
                })?;
                if active.get(&request.sandbox_id) != Some(epoch_id) {
                    store.upsert_epoch(&EpochRecord {
                        epoch_id: epoch.epoch_id.clone(),
                        gateway_id: epoch.gateway_id.clone(),
                        sandbox_id: epoch.sandbox_id.clone(),
                        task_profile: epoch.task_profile.clone(),
                        baseline_hash: epoch.baseline_hash.clone(),
                        mode: epoch.mode,
                        active: true,
                        next_sequence: epoch.initial_next_sequence,
                        created_at_ms: epoch.created_at_ms,
                        credentialed_endpoints: epoch.credentialed_endpoints.clone(),
                        active_policy_hash: epoch.active_policy_hash.clone(),
                    })?;
                    store.bind_agent_run(&epoch.run_id, &epoch.sandbox_id, &epoch.gateway_id)?;
                    active.insert(request.sandbox_id.clone(), epoch_id.clone());
                }
                let replayed = store.evaluate_authenticated(
                    request,
                    &detector as &dyn RiskDetector,
                    &epoch.gateway_id,
                    true,
                )?;
                report.decisions += 1;
                let mut diverged = false;
                let mut compare = |field: &str, recorded: String, replayed: String| {
                    if recorded != replayed {
                        diverged = true;
                        report.divergences.push(Divergence {
                            order: *order,
                            request_id: request.request_id.clone(),
                            field: field.to_string(),
                            recorded,
                            replayed,
                        });
                    }
                };
                compare(
                    "outcome",
                    format!("{:?}", recorded.outcome),
                    format!("{:?}", replayed.outcome),
                );
                compare(
                    "reason_code",
                    recorded.reason_code.clone(),
                    replayed.reason_code.clone(),
                );
                compare(
                    "risk_score",
                    recorded.risk_score.to_string(),
                    replayed.risk_score.to_string(),
                );
                compare(
                    "ratchet_action",
                    format!("{:?}", recorded.ratchet_action),
                    format!("{:?}", replayed.ratchet_action),
                );
                compare(
                    "state_sequence",
                    recorded.state_sequence.to_string(),
                    replayed.state_sequence.to_string(),
                );
                if !diverged {
                    report.matched += 1;
                }
            }
        }
    }
    report.reproduced = report.divergences.is_empty()
        && report.checks.baseline_hash_ok
        && report.checks.content_hash_ok
        && report.checks.history_complete;
    Ok(report)
}
