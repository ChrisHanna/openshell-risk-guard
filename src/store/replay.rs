// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Reads one scoring context's history out of the database as a replay bundle. See `crate::replay`.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::detector::compute_baseline_hash;
use crate::replay::{
    FORMAT_VERSION, ReplayAgent, ReplayBundle, ReplayContext, ReplayEpoch, ReplayEvent,
    ReplayGuardrailRevision, ReplayHistory, current_build,
};

impl SqliteRiskStore {
    /// Export an agent's scoring context (the newest one unless `context_id` is given) as a sealed bundle.
    pub fn export_replay_bundle(
        &self,
        agent_id: &str,
        context_id: Option<&str>,
    ) -> Result<ReplayBundle> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let display_name: String = tx
            .query_row(
                "SELECT display_name FROM agents WHERE agent_id = ?1",
                params![agent_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| RiskGuardError::InvalidArgument("agent does not exist".into()))?;
        let context: (String, String, String, String, String) = match context_id {
            Some(id) => tx.query_row(
                "SELECT context_id, agent_revision, task_profile, baseline_hash, mode FROM scoring_contexts WHERE context_id = ?1 AND agent_id = ?2",
                params![id, agent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            ),
            None => tx.query_row(
                "SELECT context_id, agent_revision, task_profile, baseline_hash, mode FROM scoring_contexts
                 WHERE agent_id = ?1 ORDER BY created_at_ms DESC, rowid DESC LIMIT 1",
                params![agent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            ),
        }
        .optional()?
        .ok_or_else(|| RiskGuardError::InvalidArgument("the agent has no scoring context".into()))?;
        let (context_id, agent_revision, task_profile, baseline_hash, mode) = context;

        let baseline_of = |hash: &str| -> Result<BaselineProfile> {
            let payload: String = tx
                .query_row(
                    "SELECT payload_json FROM artifacts WHERE artifact_hash = ?1 AND artifact_type = 'baseline_profile'",
                    params![hash],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or_else(|| RiskGuardError::Storage(format!("baseline artifact {hash} is missing")))?;
            Ok(serde_json::from_str(&payload)?)
        };
        let mut baselines = vec![baseline_of(&baseline_hash)?];

        let runs: Vec<String> = tx
            .prepare(
                "SELECT run_id FROM agent_runs WHERE context_id = ?1 ORDER BY created_at_ms, rowid",
            )?
            .query_map(params![context_id], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;

        let mut problems = Vec::new();

        // Decisions, in the order they were committed (SQLite's row id, which only grows). Each carries the guardrail revision it ran under.
        let mut raw = tx.prepare(
            "SELECT d.rowid, d.epoch_id, d.request_id, d.sequence, d.normalized_request_json, d.evaluation_json, g.revision, d.created_at_ms
             FROM decisions d
             JOIN decision_identity i ON i.epoch_id = d.epoch_id AND i.request_id = d.request_id
             JOIN agent_runs r ON r.run_id = i.run_id
             LEFT JOIN decision_guardrail_revisions g ON g.epoch_id = d.epoch_id AND g.request_id = d.request_id
             WHERE r.context_id = ?1
             ORDER BY d.rowid",
        )?;
        let rows = raw
            .query_map(params![context_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(raw);

        let mut decisions = Vec::new();
        let mut sequences: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for (
            rowid,
            epoch_id,
            _request_id,
            sequence,
            request_json,
            evaluation_json,
            revision,
            created,
        ) in rows
        {
            let request: NormalizedRequest = serde_json::from_str(&request_json)?;
            let recorded: RiskEvaluation = serde_json::from_str(&evaluation_json)?;
            sequences
                .entry(epoch_id.clone())
                .or_default()
                .push(u64::try_from(sequence).unwrap_or(0));
            decisions.push((
                rowid,
                created,
                ReplayEvent::Decision {
                    order: u64::try_from(rowid).unwrap_or(0),
                    epoch_id,
                    guardrail_revision: revision.and_then(|r| u64::try_from(r).ok()),
                    request: Box::new(request),
                    recorded: Box::new(recorded),
                    features: super::siem_features::recorded_for(&tx, rowid)?,
                },
            ));
        }

        // Epochs bound to the context's runs.
        let mut epochs = Vec::new();
        {
            let mut statement = tx.prepare(
                "SELECT e.epoch_id, e.sandbox_id, e.gateway_id, b.run_id, e.task_profile, e.baseline_hash, e.mode, e.created_at_ms,
                        e.credentialed_endpoints_json, e.active_policy_hash
                 FROM epoch_bindings b
                 JOIN agent_runs r ON r.run_id = b.run_id
                 JOIN epochs e ON e.epoch_id = b.epoch_id
                 WHERE r.context_id = ?1 ORDER BY e.created_at_ms, e.rowid",
            )?;
            let found = statement
                .query_map(params![context_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for (
                epoch_id,
                sandbox_id,
                gateway_id,
                run_id,
                profile,
                hash,
                epoch_mode,
                created,
                endpoints,
                policy,
            ) in found
            {
                // Every epoch should start at sequence 1 and have no gaps: otherwise earlier decisions were pruned or lost.
                if let Some(seen) = sequences.get(&epoch_id) {
                    let mut sorted = seen.clone();
                    sorted.sort_unstable();
                    let contiguous = sorted.iter().enumerate().all(|(i, s)| *s == i as u64 + 1);
                    if !contiguous {
                        problems.push(format!("epoch {epoch_id} has gaps or does not start at sequence 1 (earlier decisions were pruned or lost)"));
                    }
                }
                epochs.push(ReplayEpoch {
                    epoch_id,
                    sandbox_id,
                    gateway_id,
                    run_id,
                    task_profile: profile,
                    baseline_hash: hash,
                    mode: parse_enforcement_mode(&epoch_mode)?,
                    created_at_ms: created,
                    initial_next_sequence: 1,
                    credentialed_endpoints: serde_json::from_str(&endpoints)?,
                    active_policy_hash: policy,
                });
            }
        }
        let epoch_ids: BTreeSet<&str> = epochs.iter().map(|e| e.epoch_id.as_str()).collect();

        // Decisions in those epochs that were not attributed to a run cannot be placed in the context.
        let mut unattributed = 0i64;
        for epoch in &epochs {
            unattributed += tx.query_row(
                "SELECT COUNT(*) FROM decisions d WHERE d.epoch_id = ?1
                 AND NOT EXISTS (SELECT 1 FROM decision_identity i WHERE i.epoch_id = d.epoch_id AND i.request_id = d.request_id)",
                params![epoch.epoch_id],
                |row| row.get::<_, i64>(0),
            )?;
        }
        if unattributed > 0 {
            problems.push(format!("{unattributed} decisions in these epochs were made without an agent run and are not in the bundle"));
        }
        if decisions.iter().any(|(_, _, event)| matches!(event, ReplayEvent::Decision { epoch_id, .. } if !epoch_ids.contains(epoch_id.as_str()))) {
            problems.push("a decision belongs to an epoch that is not bound to this context".into());
        }
        // Adaptive models change a decision only when one was enforced; those are not replayed.
        let enforced: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM adaptive_assessments a JOIN agent_runs r ON r.run_id = a.run_id
                 WHERE r.context_id = ?1 AND a.mode = 'enforce'",
                params![context_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if enforced > 0 {
            problems.push(format!("{enforced} decisions were scored with an enforced adaptive model, which a bundle does not carry"));
        }

        // A maturity credit from an adaptive promotion changes a decision's baseline; a bundle does not carry credits.
        let credited = decisions
            .iter()
            .filter(|(_, _, event)| {
                matches!(event, ReplayEvent::Decision { recorded, .. }
                    if recorded.signals.iter().any(|s| s.feature == "maturity_credit"))
            })
            .count();
        if credited > 0 {
            problems.push(format!("{credited} decisions were scored under baseline maturity credited from an adaptive model, which a bundle does not carry"));
        }

        // Guardrail revisions up to the newest one any decision used.
        let newest_revision = decisions
            .iter()
            .filter_map(|(_, _, event)| match event {
                ReplayEvent::Decision {
                    guardrail_revision, ..
                } => *guardrail_revision,
                ReplayEvent::Clearance { .. } => None,
            })
            .max()
            .unwrap_or(0);
        let mut guardrail_revisions = Vec::new();
        {
            let mut statement = tx.prepare(
                "SELECT revision, settings_json, profile_artifact_hash FROM agent_guardrail_revisions
                 WHERE agent_id = ?1 AND revision <= ?2 ORDER BY revision",
            )?;
            let found = statement
                .query_map(
                    params![agent_id, i64::try_from(newest_revision).unwrap_or(0)],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for (revision, settings_json, profile_hash) in found {
                if !baselines
                    .iter()
                    .any(|b| compute_baseline_hash(b) == profile_hash)
                {
                    baselines.push(baseline_of(&profile_hash)?);
                }
                guardrail_revisions.push(ReplayGuardrailRevision {
                    revision: u64::try_from(revision).unwrap_or(0),
                    settings: serde_json::from_str(&settings_json)?,
                });
            }
        }

        // Operator clearances, placed before the first decision made after them. (Clearance time and request time are both wall-clock
        // milliseconds, so a clearance made within the same millisecond as a decision is placed after it.)
        let clearances: Vec<(String, String, i64)> = tx
            .prepare("SELECT scope, tier, cleared_at_ms FROM restriction_clearances WHERE owner_kind = 'agent_context' AND owner_id = ?1 ORDER BY id")?
            .query_map(params![context_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let mut events = Vec::new();
        let mut pending = clearances.into_iter().peekable();
        for (_, created, event) in decisions {
            while let Some((scope, tier, at)) = pending.peek().cloned() {
                if at < created {
                    events.push(ReplayEvent::Clearance {
                        scope,
                        tier,
                        cleared_at_ms: at,
                    });
                    pending.next();
                } else {
                    break;
                }
            }
            events.push(event);
        }
        for (scope, tier, at) in pending {
            events.push(ReplayEvent::Clearance {
                scope,
                tier,
                cleared_at_ms: at,
            });
        }

        let mut limits = vec![
            "Scoring state is rebuilt from the recorded decisions in commit order; if the database was vacuumed or restored from a copy that renumbered rows, the order may differ.".to_string(),
            "Network policy text is not included; only each epoch's credentialed endpoints and policy hash are.".to_string(),
            "Adaptive (shadow) scoring is not replayed; it does not change a decision unless a model was enforced, which is checked above.".to_string(),
        ];
        if events.is_empty() {
            limits.push("The context has no recorded decisions.".into());
        }
        let bundle = ReplayBundle {
            format_version: FORMAT_VERSION,
            exported_at_ms: current_time_ms(),
            build: current_build()?,
            agent: ReplayAgent {
                agent_id: agent_id.to_string(),
                display_name,
            },
            context: ReplayContext {
                context_id,
                agent_revision,
                task_profile,
                baseline_hash,
                mode: parse_enforcement_mode(&mode)?,
            },
            baselines,
            guardrail_revisions,
            runs,
            epochs,
            events,
            history: ReplayHistory {
                complete: problems.is_empty(),
                problems,
            },
            limits,
            content_hash: String::new(),
        };
        tx.commit()?;
        bundle.seal()
    }
}
