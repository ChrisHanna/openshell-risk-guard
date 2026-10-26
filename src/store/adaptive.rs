use super::*;
use crate::adaptive::{
    self as learner, AdaptiveAssessment, FitOptions, LearnedProfile, TrainingObservation,
    TrainingSession,
};
use crate::adaptive_controls::{
    AdaptiveOperation, AdaptiveUpdateResult, CaptureReview, LearningScope, ModelMode,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MAX_CAPTURE_REQUESTS: i64 = 500;
const MAX_CAPTURE_MS: i64 = 3_600_000;
const MAX_DATASET_SESSIONS: usize = 100;
const MIN_SHADOW_REQUESTS: i64 = 50;
const MIN_SHADOW_RUNS: i64 = 5;

#[derive(Default)]
struct Head {
    shadow: Option<String>,
    enforced: Option<String>,
}

struct Model {
    id: String,
    agent: String,
    context: String,
    revision: u64,
    scope: String,
    profile: LearnedProfile,
    hash: String,
    created: i64,
    revoked: bool,
}

pub(super) struct Frame<'a> {
    pub identity: Option<&'a AgentIdentity>,
    pub revision: u64,
    pub source: Option<NativeObservationSource>,
    pub request: &'a NormalizedRequest,
    pub window: &'a WindowSnapshot,
    pub cooldown_ms: i64,
    /// The fresh SIEM features the detector used for this same decision (none on a path that never loaded any). The learner receives them as
    /// bounded context: they can add to an anomaly it already sees, never start one.
    pub features: Option<&'a ContextFeatures>,
}

/// The counts OpenSearch published, in the learner's vocabulary. `None` when there are no features, so a decision without them scores exactly as before.
fn context_inputs(features: Option<&ContextFeatures>) -> Option<learner::ContextInputs> {
    use crate::types::FeatureScope::{Fleet, Sandbox, Workload};
    let features = features.filter(|features| !features.is_empty())?;
    let inputs = learner::ContextInputs {
        openshell_denials_5m: features.get(Sandbox, "openshell_denials_5m"),
        openshell_denials_1h: features.get(Sandbox, "openshell_denials_1h"),
        openshell_would_block_5m: features.get(Sandbox, "openshell_would_block_5m"),
        refusal_ratio_15m_permille: features.get(Workload, "refusal_ratio_15m_permille"),
        anomaly_grade_15m_permille: features.get(Workload, "anomaly_grade_15m_permille"),
        fleet_openshell_denials_5m: features.get(Fleet, "fleet_openshell_denials_5m"),
        fleet_workloads_with_denials_5m: features.get(Fleet, "fleet_workloads_with_denials_5m"),
        fleet_refusal_ratio_15m_permille: features.get(Fleet, "fleet_refusal_ratio_15m_permille"),
        fleet_active_workloads_15m: features.get(Fleet, "fleet_active_workloads_15m"),
    };
    (!inputs.is_empty()).then_some(inputs)
}

pub(super) struct Assessment {
    model_id: String,
    mode: &'static str,
    would_block: bool,
    result: AdaptiveAssessment,
}

fn invalid(message: impl Into<String>) -> RiskGuardError {
    RiskGuardError::InvalidArgument(message.into())
}

fn current_revision(conn: &Connection, agent: &str) -> Result<u64> {
    Ok(guardrails::query_saved(conn, agent)?.map_or(0, |saved| saved.revision))
}

/// Shadow learning is on for every agent unless an operator turns it off. It is safe
/// to automate because it can never block: auto-approval accepts only unflagged
/// read-only windows, models only reach shadow, and enforcement needs an explicit,
/// evidence-bound promotion that discloses how much training data was unreviewed.
fn auto_learning_enabled(conn: &Connection, agent: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT auto_shadow_learning != 0 FROM adaptive_agent_settings WHERE agent_id = ?1",
            params![agent],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(true))
}

const AUTO_ENROLLED_NOTE: &str = "auto-enrolled";
const AUTO_REVIEWER: &str = "auto-clean-policy";

fn head(conn: &Connection, context: &str, revision: u64, scope: &str) -> Result<Head> {
    Ok(conn
        .query_row(
            "SELECT shadow_model_id, enforced_model_id FROM adaptive_heads
         WHERE context_id = ?1 AND guardrails_revision = ?2 AND scope = ?3",
            params![context, revision, scope],
            |row| {
                Ok(Head {
                    shadow: row.get(0)?,
                    enforced: row.get(1)?,
                })
            },
        )
        .optional()?
        .unwrap_or_default())
}

fn model_hash(context: &str, revision: u64, scope: &str, payload: &str) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        context, revision, scope, payload,
    ))?)))
}

type CachedModelKey = (String, String, u64, String, String);
type CachedModelEntry = (String, LearnedProfile);

fn model_cache() -> &'static Mutex<std::collections::HashMap<CachedModelKey, CachedModelEntry>> {
    static CACHE: std::sync::OnceLock<
        Mutex<std::collections::HashMap<CachedModelKey, CachedModelEntry>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn model(conn: &Connection, id: &str) -> Result<Option<Model>> {
    let raw = conn
        .query_row(
            "SELECT agent_id, context_id, guardrails_revision, scope, profile_json,
                model_hash, created_at_ms, revoked_at_ms IS NOT NULL
         FROM adaptive_models WHERE model_id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, bool>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((agent, context, revision, scope, payload, hash, created, revoked)) = raw else {
        return Ok(None);
    };
    let key = (
        id.to_string(),
        context.clone(),
        revision,
        scope.clone(),
        hash.clone(),
    );
    if let Ok(cache) = model_cache().lock()
        && let Some((cached_payload, cached_profile)) = cache.get(&key)
        && *cached_payload == payload
    {
        return Ok(Some(Model {
            id: id.into(),
            agent,
            context,
            revision,
            scope,
            profile: cached_profile.clone(),
            hash,
            created,
            revoked,
        }));
    }
    if model_hash(&context, revision, &scope, &payload)? != hash {
        return Err(RiskGuardError::Storage(
            "adaptive model hash mismatch".into(),
        ));
    }
    let profile: LearnedProfile = serde_json::from_str(&payload)?;
    // Models fitted under an earlier version keep scoring as they did; only an unknown version is refused.
    if !matches!(
        profile.algorithm_version.as_str(),
        learner::ALGORITHM_VERSION | learner::ALGORITHM_VERSION_V1
    ) {
        return Err(RiskGuardError::Storage(
            "unsupported adaptive model algorithm".into(),
        ));
    }
    if let Ok(mut cache) = model_cache().lock() {
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(key, (payload, profile.clone()));
    }
    Ok(Some(Model {
        id: id.into(),
        agent,
        context,
        revision,
        scope,
        profile,
        hash,
        created,
        revoked,
    }))
}

fn shadow_stats(conn: &Connection, id: &str) -> Result<Value> {
    let (requests, alerts, would_block, runs, clean, clean_runs, clean_would_block): (
        i64, i64, i64, i64, i64, i64, i64,
    ) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(score >= ?2),0), COALESCE(SUM(would_block),0),
                COUNT(DISTINCT run_id),
                COALESCE(SUM(clean_native = 1 AND run_id NOT IN
                    (SELECT s.run_id FROM adaptive_model_sessions m JOIN adaptive_sessions s USING(session_id)
                     WHERE m.model_id = ?1)),0),
                COUNT(DISTINCT CASE WHEN clean_native = 1 AND run_id NOT IN
                    (SELECT s.run_id FROM adaptive_model_sessions m JOIN adaptive_sessions s USING(session_id)
                     WHERE m.model_id = ?1) THEN run_id END),
                COALESCE(SUM(would_block = 1 AND clean_native = 1 AND run_id NOT IN
                    (SELECT s.run_id FROM adaptive_model_sessions m JOIN adaptive_sessions s USING(session_id)
                     WHERE m.model_id = ?1)),0)
         FROM adaptive_assessments WHERE model_id = ?1",
            params![id, learner::SHADOW_ALERT_THRESHOLD],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )?;
    Ok(json!({
        "requests": requests, "alerts": alerts, "would_block": would_block,
        "distinct_runs": runs, "reviewable_requests": clean, "reviewable_runs": clean_runs,
        "reviewable_would_block": clean_would_block,
        "labels": "unlabeled_live_observations_not_a_false_positive_rate",
    }))
}

fn promotion_blockers(conn: &Connection, model: &Model, revision: u64) -> Result<Vec<String>> {
    let mut reasons = Vec::new();
    if model.revoked {
        reasons.push("A training session's approval was withdrawn; this model is revoked.".into());
    }
    if model.revision != revision {
        reasons.push("Guardrails changed; collect and train against the current revision.".into());
    }
    if !model.profile.ready_for_enforcement {
        reasons.extend(model.profile.readiness_reasons.clone());
        if reasons.is_empty() {
            reasons.push("The candidate does not meet the learning quality gates.".into());
        }
    }
    // Worse than the model it would replace, on the same inputs: more benign holdout would-blocks, or fewer injected probes caught.
    if let Some(comparison) = &model.profile.comparison {
        reasons.extend(comparison.blockers.clone());
    }
    let stats = shadow_stats(conn, &model.id)?;
    if stats["reviewable_requests"].as_i64().unwrap_or(0) < MIN_SHADOW_REQUESTS {
        reasons.push(format!(
            "Need {MIN_SHADOW_REQUESTS} fresh, clean native shadow observations after training."
        ));
    }
    if stats["reviewable_runs"].as_i64().unwrap_or(0) < MIN_SHADOW_RUNS {
        reasons.push(format!(
            "Need shadow observations from {MIN_SHADOW_RUNS} independent runs."
        ));
    }
    Ok(reasons)
}

fn model_view(conn: &Connection, model: Model, revision: u64) -> Result<Value> {
    let head = head(conn, &model.context, model.revision, &model.scope)?;
    let compatible = !model.revoked && model.revision == revision;
    let (recent, alerts): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(score >= ?2),0) FROM
         (SELECT score FROM adaptive_assessments WHERE model_id = ?1
          ORDER BY observed_at_ms DESC, rowid DESC LIMIT 100)",
        params![model.id, learner::SHADOW_ALERT_THRESHOLD],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut membership = conn.prepare(
        "SELECT session_id, split FROM adaptive_model_sessions WHERE model_id = ?1 ORDER BY session_id",
    )?;
    let dataset = membership
        .query_map(params![model.id], |row| {
            Ok(json!({
                "session_id": row.get::<_, String>(0)?, "split": row.get::<_, String>(1)?,
            }))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let auto_approved: i64 = conn.query_row(
        "SELECT COUNT(*) FROM adaptive_model_sessions m JOIN adaptive_sessions s USING(session_id)
         WHERE m.model_id = ?1 AND s.reviewed_by = ?2",
        params![model.id, AUTO_REVIEWER],
        |row| row.get(0),
    )?;
    Ok(json!({
        "model_id": model.id, "context_id": model.context,
        "auto_approved_sessions": auto_approved,
        "guardrails_revision": model.revision, "scope": model.scope,
        "created_at_ms": model.created, "model_hash": model.hash,
        "compatible": compatible, "revoked": model.revoked,
        "shadow": compatible && head.shadow.as_deref() == Some(model.id.as_str()),
        "enforced": compatible && head.enforced.as_deref() == Some(model.id.as_str()),
        "profile": model.profile, "dataset": dataset,
        "shadow_stats": shadow_stats(conn, &model.id)?,
        "promotion_blockers": promotion_blockers(conn, &model, revision)?,
        "comparison": model.profile.comparison,
        "drift_suspected": recent >= 50 && alerts * 5 >= recent,
        "drift_sample_size": recent,
        "drift_note": "Anomaly frequency is a review cue, not proof of compromise or a false-positive estimate.",
    }))
}

fn view(conn: &Connection, agent: &str, now_ms: i64) -> Result<Option<Value>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
        params![agent],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let revision = current_revision(conn, agent)?;
    let runs = {
        let mut stmt = conn.prepare(
            "SELECT r.run_id, r.context_id, c.agent_revision, c.task_profile, r.ended_at_ms,
                    (SELECT COUNT(*) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
                     WHERE b.run_id = r.run_id AND e.active != 0),
                    EXISTS(SELECT 1 FROM decision_identity d WHERE d.run_id = r.run_id),
                    EXISTS(SELECT 1 FROM adaptive_sessions s WHERE s.run_id = r.run_id)
             FROM agent_runs r JOIN scoring_contexts c USING(context_id)
             WHERE c.agent_id = ?1 ORDER BY r.created_at_ms DESC, r.rowid DESC LIMIT 100",
        )?;
        stmt.query_map(params![agent], |row| {
            let ended: Option<i64> = row.get(4)?;
            let bound: i64 = row.get(5)?;
            let prior: bool = row.get(6)?;
            let captured: bool = row.get(7)?;
            let blocker = if ended.is_some() { Some("Run ended") }
                else if bound != 1 { Some("Exactly one active sandbox binding is required") }
                else if captured { Some("This run already has a capture; create a fresh run") }
                else if prior { Some("Run already has request history; create a pristine run") }
                else { None };
            Ok(json!({
            "run_id": row.get::<_, String>(0)?, "context_id": row.get::<_, String>(1)?,
            "agent_revision": row.get::<_, String>(2)?, "task_profile": row.get::<_, String>(3)?,
            "ended_at_ms": ended, "bound_sandboxes": bound,
            "capture_eligible": blocker.is_none(), "capture_blocker": blocker,
        }))})?.collect::<std::result::Result<Vec<_>, _>>()?
    };
    let sessions = {
        let mut stmt = conn.prepare(
            "SELECT s.session_id, s.run_id, s.context_id, s.guardrails_revision, s.scope,
                    s.status, s.started_at_ms, s.ended_at_ms, s.quarantine_reason, s.notes,
                    s.reviewed_by, (SELECT COUNT(*) FROM adaptive_observations o WHERE o.session_id = s.session_id)
             FROM adaptive_sessions s WHERE s.agent_id = ?1 ORDER BY s.started_at_ms DESC, s.rowid DESC LIMIT 100",
        )?;
        stmt.query_map(params![agent], |row| Ok(json!({
            "session_id": row.get::<_, String>(0)?, "run_id": row.get::<_, String>(1)?,
            "context_id": row.get::<_, String>(2)?, "guardrails_revision": row.get::<_, u64>(3)?,
            "scope": row.get::<_, String>(4)?, "status": row.get::<_, String>(5)?,
            "started_at_ms": row.get::<_, i64>(6)?, "ended_at_ms": row.get::<_, Option<i64>>(7)?,
            "quarantine_reason": row.get::<_, Option<String>>(8)?, "notes": row.get::<_, String>(9)?,
            "reviewed_by": row.get::<_, Option<String>>(10)?, "request_count": row.get::<_, i64>(11)?,
        })))?.collect::<std::result::Result<Vec<_>, _>>()?
    };
    let ids = {
        let mut stmt = conn.prepare(
            "SELECT model_id FROM adaptive_models WHERE agent_id = ?1
             ORDER BY created_at_ms DESC, rowid DESC LIMIT 30",
        )?;
        stmt.query_map(params![agent], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut models = Vec::new();
    for id in ids {
        let model = model(conn, &id)?
            .ok_or_else(|| RiskGuardError::Storage("adaptive model disappeared".into()))?;
        models.push(model_view(conn, model, revision)?);
    }
    let audit = {
        let mut stmt = conn.prepare(
            "SELECT operation, actor, created_at_ms, details_json FROM adaptive_audit
             WHERE agent_id = ?1 ORDER BY id DESC LIMIT 30",
        )?;
        let rows = stmt
            .query_map(params![agent], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(operation, actor, created, details)| {
                Ok(json!({
                    "operation": operation, "actor": actor, "created_at_ms": created,
                    "details": serde_json::from_str::<Value>(&details)?,
                }))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let auto_shadow_learning = auto_learning_enabled(conn, agent)?;
    Ok(Some(json!({
        "agent_id": agent, "guardrails_revision": revision, "generated_at_ms": now_ms,
        "auto_shadow_learning": auto_shadow_learning,
        "coverage": "network_metadata_only",
        "minimums": { "training_runs": 20, "training_requests": 200,
            "holdout_runs": 5, "holdout_requests": 50, "shadow_runs": MIN_SHADOW_RUNS,
            "shadow_requests": MIN_SHADOW_REQUESTS },
        "limits": {"capture_requests": MAX_CAPTURE_REQUESTS, "capture_duration_ms": MAX_CAPTURE_MS,
            "sessions": 100, "models": 30},
        "runs": runs, "sessions": sessions, "models": models, "audit": audit,
        "maturity_credits": credit_views(conn, agent, revision)?,
        "maturity_thresholds": {"sessions": MATURE_SESSIONS, "requests": MATURE_REQUESTS},
    })))
}

fn audit(
    conn: &Connection,
    agent: &str,
    actor: &str,
    operation: &str,
    now: i64,
    details: Value,
) -> Result<()> {
    conn.execute(
        "INSERT INTO adaptive_audit (agent_id, operation, actor, created_at_ms, details_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            agent,
            operation,
            actor,
            now,
            serde_json::to_string(&details)?
        ],
    )?;
    Ok(())
}

impl SqliteRiskStore {
    pub fn agent_adaptive(&self, agent: &str, now_ms: i64) -> Result<Option<Value>> {
        let mut conn = self.lock_read_conn()?;
        let tx = conn.transaction()?;
        let result = view(&tx, agent, now_ms)?;
        tx.commit()?;
        Ok(result)
    }

    pub(super) fn demote_adaptive_model_approved(
        &self,
        agent: &str,
        model_id: &str,
        mode_str: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<String> {
        let mode = match mode_str {
            "shadow" => ModelMode::Shadow,
            "off" => ModelMode::Off,
            _ => {
                return Err(invalid(
                    "demote_adaptive_model mode must be 'shadow' or 'off'",
                ));
            }
        };
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let selected = model(&tx, model_id)?.ok_or_else(|| invalid("model not found"))?;
        if selected.agent != agent {
            return Err(invalid("model does not belong to this workload"));
        }
        let revision = current_revision(&tx, agent)?;
        set_model_inner(&tx, &selected, mode, false, revision, true)?;
        audit(
            &tx,
            agent,
            actor,
            "set_model",
            now_ms,
            json!({"model_id": model_id, "mode": mode, "two_person_approved": true}),
        )?;
        tx.commit()?;
        Ok(format!("model {model_id} set to {mode_str}"))
    }

    pub fn apply_adaptive_operation(
        &self,
        agent: &str,
        operation: &AdaptiveOperation,
        actor: &str,
        now_ms: i64,
    ) -> Result<AdaptiveUpdateResult> {
        if actor.trim().is_empty() || actor.len() > 128 || now_ms < 0 {
            return Err(invalid(
                "adaptive operations require an operator identity and valid time",
            ));
        }
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
            params![agent],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(invalid("workload not found"));
        }
        let revision = current_revision(&tx, agent)?;
        let expected = match operation {
            AdaptiveOperation::StartCapture {
                expected_guardrails_revision,
                ..
            }
            | AdaptiveOperation::Train {
                expected_guardrails_revision,
                ..
            } => Some(*expected_guardrails_revision),
            _ => None,
        };
        if expected.is_some_and(|expected| expected != revision) {
            return Ok(AdaptiveUpdateResult::Conflict(
                "Guardrails changed; reload before starting learning.".into(),
            ));
        }
        match operation {
            AdaptiveOperation::StartCapture { run_id, scope, .. } => {
                start_capture(&tx, agent, run_id, *scope, revision, actor, now_ms)?;
            }
            AdaptiveOperation::ReviewCapture {
                session_id,
                action,
                notes,
            } => {
                review_capture(&tx, agent, session_id, *action, notes, actor, now_ms)?;
            }
            AdaptiveOperation::Train {
                context_id, scope, ..
            } => {
                train(&tx, agent, context_id, *scope, revision, actor, now_ms)?;
            }
            AdaptiveOperation::SetModel {
                model_id,
                mode,
                expected_active_model_id,
                acknowledge_shadow_review,
                reviewed_shadow_would_block,
            } => {
                let selected = model(&tx, model_id)?.ok_or_else(|| invalid("model not found"))?;
                if selected.agent != agent {
                    return Err(invalid("model does not belong to this workload"));
                }
                let head = head(&tx, &selected.context, selected.revision, &selected.scope)?;
                if head.enforced != *expected_active_model_id {
                    return Ok(AdaptiveUpdateResult::Conflict(
                        "Active model changed; reload before changing model mode.".into(),
                    ));
                }
                if *mode == ModelMode::Enforce {
                    // Shadow evidence is unlabeled, so the acknowledgement binds to what was reviewed.
                    let reviewed = reviewed_shadow_would_block.ok_or_else(|| {
                        invalid("enforce promotion requires the reviewed clean shadow would-block count")
                    })?;
                    let current = shadow_stats(&tx, &selected.id)?["reviewable_would_block"]
                        .as_u64()
                        .unwrap_or(0);
                    if reviewed != current {
                        return Ok(AdaptiveUpdateResult::Conflict(format!(
                            "Clean shadow would-blocks changed from {reviewed} to {current}; review the new evidence before promotion."
                        )));
                    }
                }
                set_model(&tx, &selected, *mode, *acknowledge_shadow_review, revision)?;
                audit(
                    &tx,
                    agent,
                    actor,
                    "set_model",
                    now_ms,
                    json!({"model_id":model_id, "mode":mode,
                        "reviewed_shadow_would_block":reviewed_shadow_would_block}),
                )?;
            }
            AdaptiveOperation::CreditMaturity {
                model_id,
                acknowledge_behavioral_enforcement,
                note,
            } => {
                credit_maturity(
                    &tx,
                    agent,
                    model_id,
                    *acknowledge_behavioral_enforcement,
                    note,
                    revision,
                    actor,
                    now_ms,
                )?;
            }
            AdaptiveOperation::RevokeMaturityCredit { context_id, reason } => {
                revoke_maturity_credit(&tx, agent, context_id, reason, actor, now_ms)?;
            }
            AdaptiveOperation::SetAutoLearning { enabled } => {
                tx.execute(
                    "INSERT INTO adaptive_agent_settings (agent_id, auto_shadow_learning, updated_at_ms, updated_by)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(agent_id) DO UPDATE SET
                       auto_shadow_learning = excluded.auto_shadow_learning,
                       updated_at_ms = excluded.updated_at_ms,
                       updated_by = excluded.updated_by",
                    params![agent, i64::from(*enabled), now_ms, actor],
                )?;
                audit(
                    &tx,
                    agent,
                    actor,
                    "set_auto_learning",
                    now_ms,
                    json!({"enabled": enabled}),
                )?;
            }
        }
        let result = view(&tx, agent, now_ms)?
            .ok_or_else(|| RiskGuardError::Storage("agent disappeared".into()))?;
        tx.commit()?;
        Ok(AdaptiveUpdateResult::Applied(result))
    }
}

/// What one scheduled pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScheduledPass {
    /// Workloads looked at (auto-learning on, and at least one capture session).
    pub workloads: usize,
    /// Shadow models trained because approved windows were newer than the newest model.
    pub trained: usize,
    /// Trainings that could not run (too few windows, too many, a changed scoring context); nothing was changed for them.
    pub skipped: usize,
    /// Captured sessions waiting for a person, across the workloads looked at.
    pub waiting_for_review: usize,
}

impl SqliteRiskStore {
    /// The scheduled half of adaptive learning. A run that ends clean is approved and trained at once; this pass catches what that path leaves behind: windows a person
    /// approved by hand (approving does not train), and trainings that were skipped. For each workload with auto-learning on, any approved window newer than the newest
    /// model for its (context, scope, guardrails revision) gets one new SHADOW model. Never approves a window, never promotes a model, never grants a maturity credit:
    /// those stay with a person. Workloads whose auto-learning a person paused are left alone.
    pub fn scheduled_adaptive_pass(&self, now_ms: i64) -> Result<ScheduledPass> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let agents: Vec<String> = {
            let mut stmt =
                tx.prepare("SELECT DISTINCT agent_id FROM adaptive_sessions ORDER BY agent_id")?;
            stmt.query_map([], |row| row.get(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        let mut pass = ScheduledPass::default();
        for agent in agents {
            if !auto_learning_enabled(&tx, &agent)? {
                continue;
            }
            pass.workloads += 1;
            let revision = current_revision(&tx, &agent)?;
            let windows: Vec<(String, String, i64)> = {
                let mut stmt = tx.prepare(
                    "SELECT context_id, scope, MAX(COALESCE(ended_at_ms, started_at_ms)) FROM adaptive_sessions
                     WHERE agent_id = ?1 AND status = 'approved' AND guardrails_revision = ?2 GROUP BY context_id, scope",
                )?;
                stmt.query_map(params![agent, revision], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .collect::<std::result::Result<_, _>>()?
            };
            for (context, scope_text, newest_window) in windows {
                let newest_model: Option<i64> = tx.query_row(
                    "SELECT MAX(created_at_ms) FROM adaptive_models
                     WHERE agent_id = ?1 AND context_id = ?2 AND scope = ?3 AND guardrails_revision = ?4",
                    params![agent, context, scope_text, revision],
                    |row| row.get(0),
                )?;
                if newest_model.is_some_and(|model| model >= newest_window) {
                    continue;
                }
                let scope = match scope_text.as_str() {
                    "verified" => LearningScope::Verified,
                    "local_demo" => LearningScope::LocalDemo,
                    _ => continue,
                };
                // One savepoint per training: a failure must leave no half-written model behind.
                tx.execute_batch("SAVEPOINT scheduled_train")?;
                match train(
                    &tx,
                    &agent,
                    &context,
                    scope,
                    revision,
                    "scheduled-trainer",
                    now_ms,
                ) {
                    Ok(()) => {
                        tx.execute_batch("RELEASE scheduled_train")?;
                        audit(
                            &tx,
                            &agent,
                            "scheduled-trainer",
                            "scheduled_train",
                            now_ms,
                            json!({"context_id": context, "scope": scope_text, "newest_window_ms": newest_window}),
                        )?;
                        pass.trained += 1;
                    }
                    Err(error) => {
                        tx.execute_batch("ROLLBACK TO scheduled_train; RELEASE scheduled_train")?;
                        tracing::info!(%agent, %context, %error, "scheduled adaptive training skipped");
                        pass.skipped += 1;
                    }
                }
            }
            pass.waiting_for_review += usize::try_from(tx.query_row(
                "SELECT COUNT(*) FROM adaptive_sessions WHERE agent_id = ?1 AND status = 'pending_review'",
                params![agent],
                |row| row.get::<_, i64>(0),
            )?)
            .unwrap_or(0);
        }
        tx.commit()?;
        Ok(pass)
    }
}

fn start_capture(
    conn: &Connection,
    agent: &str,
    run: &str,
    scope: LearningScope,
    revision: u64,
    actor: &str,
    now: i64,
) -> Result<()> {
    let context: Option<String> = conn
        .query_row(
            "SELECT r.context_id FROM agent_runs r JOIN scoring_contexts c USING(context_id)
         WHERE r.run_id = ?1 AND c.agent_id = ?2 AND r.ended_at_ms IS NULL
         AND (SELECT COUNT(*) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
              WHERE b.run_id = r.run_id AND e.active != 0) = 1",
            params![run, agent],
            |row| row.get(0),
        )
        .optional()?;
    let context = context.ok_or_else(|| {
        invalid("capture requires this workload's active, trusted sandbox-bound run")
    })?;
    let used: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM adaptive_sessions WHERE run_id = ?1)
         OR EXISTS(SELECT 1 FROM decision_identity WHERE run_id = ?1)",
        params![run],
        |row| row.get(0),
    )?;
    if used {
        return Err(invalid(
            "phase-1 learning requires a pristine single-sandbox run and one capture per run; create a fresh trusted run before collection",
        ));
    }
    let id = format!("learn-{}", uuid::Uuid::new_v4());
    conn.execute(
        "INSERT INTO adaptive_sessions
         (session_id, agent_id, run_id, context_id, guardrails_revision, scope, status, started_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'recording', ?7)",
        params![id, agent, run, context, revision, scope.as_str(), now],
    )?;
    audit(
        conn,
        agent,
        actor,
        "start_capture",
        now,
        json!({"session_id":id,"run_id":run,"scope":scope}),
    )?;
    Ok(())
}

fn review_capture(
    conn: &Connection,
    agent: &str,
    session: &str,
    action: CaptureReview,
    notes: &str,
    actor: &str,
    now: i64,
) -> Result<()> {
    if notes.len() > 1_000 {
        return Err(invalid("review notes exceed 1000 bytes"));
    }
    let record: Option<(String, i64, Option<i64>, u64)> = conn
        .query_row(
            "SELECT status, started_at_ms, ended_at_ms, guardrails_revision FROM adaptive_sessions
         WHERE session_id = ?1 AND agent_id = ?2",
            params![session, agent],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (status, started, ended, revision) =
        record.ok_or_else(|| invalid("capture not found for this workload"))?;
    if now < started {
        return Err(invalid("review cannot precede capture"));
    }
    match action {
        CaptureReview::Finish => {
            if status != "recording" {
                return Err(invalid("only a recording capture can be finished"));
            }
            if now - started > MAX_CAPTURE_MS {
                quarantine(conn, session, "capture_duration_exceeded", now)?;
            } else {
                let last: Option<i64> = conn.query_row(
                    "SELECT MAX(p.observed_at_ms) FROM adaptive_observations o
                     JOIN native_decision_provenance p USING(epoch_id,request_id) WHERE o.session_id = ?1",
                    params![session], |row| row.get(0),
                )?;
                let end = now
                    .max(started.saturating_add(1))
                    .max(last.map_or(started, |last| last.saturating_add(1)));
                conn.execute(
                    "UPDATE adaptive_sessions SET status = 'pending_review', ended_at_ms = ?2 WHERE session_id = ?1",
                    params![session, end],
                )?;
            }
        }
        CaptureReview::Approve => {
            if status != "pending_review" || ended.is_none() {
                return Err(invalid(
                    "finish a clean capture before explicitly approving it as benign",
                ));
            }
            if current_revision(conn, agent)? != revision {
                return Err(invalid(
                    "guardrails changed; old-revision evidence cannot be newly approved",
                ));
            }
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM adaptive_observations WHERE session_id = ?1",
                params![session],
                |row| row.get(0),
            )?;
            if count == 0 {
                return Err(invalid("an empty window is not training evidence"));
            }
            conn.execute(
                "UPDATE adaptive_sessions SET status = 'approved', notes = ?2, reviewed_by = ?3 WHERE session_id = ?1",
                params![session, notes, actor],
            )?;
        }
        CaptureReview::Reject => {
            if status == "rejected" {
                return Err(invalid("capture is already rejected"));
            }
            conn.execute(
                "UPDATE adaptive_sessions SET status = 'rejected', ended_at_ms = COALESCE(ended_at_ms, ?2),
                 notes = ?3, reviewed_by = ?4 WHERE session_id = ?1",
                params![session, now.max(started.saturating_add(1)), notes, actor],
            )?;
            conn.execute(
                "UPDATE adaptive_models SET revoked_at_ms = ?2 WHERE model_id IN
                 (SELECT model_id FROM adaptive_model_sessions WHERE session_id = ?1)
                 AND revoked_at_ms IS NULL",
                params![session, now],
            )?;
            conn.execute(
                "UPDATE adaptive_heads SET
                 shadow_model_id = CASE WHEN shadow_model_id IN
                    (SELECT model_id FROM adaptive_models WHERE revoked_at_ms IS NOT NULL) THEN NULL ELSE shadow_model_id END,
                 enforced_model_id = CASE WHEN enforced_model_id IN
                    (SELECT model_id FROM adaptive_models WHERE revoked_at_ms IS NOT NULL) THEN NULL ELSE enforced_model_id END",
                [],
            )?;
        }
    }
    audit(
        conn,
        agent,
        actor,
        "review_capture",
        now,
        json!({"session_id":session,"action":action,"notes":notes}),
    )?;
    Ok(())
}

fn train(
    conn: &Connection,
    agent: &str,
    context: &str,
    scope: LearningScope,
    revision: u64,
    actor: &str,
    now: i64,
) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT session_id, run_id, started_at_ms, ended_at_ms FROM adaptive_sessions
         WHERE agent_id = ?1 AND context_id = ?2 AND guardrails_revision = ?3
           AND scope = ?4 AND status = 'approved' ORDER BY started_at_ms, session_id LIMIT 101",
    )?;
    let records = stmt
        .query_map(params![agent, context, revision, scope.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if records.is_empty() {
        return Err(invalid(
            "no approved native windows for this exact context, scope and guardrails revision",
        ));
    }
    if records.len() > MAX_DATASET_SESSIONS {
        return Err(invalid(
            "phase-1 dataset exceeds 100 windows; curate a new context rather than silently truncating",
        ));
    }
    let mut runs: BTreeMap<String, Vec<TrainingSession>> = BTreeMap::new();
    for (id, run, start, end) in records {
        runs.entry(run.clone())
            .or_default()
            .push(load_session(conn, id, run, start, end)?);
    }
    let mut groups: Vec<Vec<TrainingSession>> = runs.into_values().collect();
    groups.sort_by_key(|group| {
        group
            .iter()
            .map(|s| s.started_at_ms)
            .min()
            .unwrap_or(i64::MAX)
    });
    let target = groups.len().saturating_sub(groups.len().div_ceil(5)).max(1);
    let split = (1..=target)
        .rev()
        .find(|index| {
            let end = groups[..*index]
                .iter()
                .flatten()
                .map(|s| s.ended_at_ms)
                .max();
            let start = groups[*index..]
                .iter()
                .flatten()
                .map(|s| s.started_at_ms)
                .min();
            matches!((end, start), (Some(end), Some(start)) if end <= start)
        })
        .unwrap_or(groups.len());
    let training: Vec<_> = groups[..split].iter().flatten().cloned().collect();
    let holdout: Vec<_> = groups[split..].iter().flatten().cloned().collect();
    let prior = pooled_prior(conn, agent, context, scope)?;
    let mut profile = learner::fit_with(&training, &holdout, &FitOptions::default(), prior)?;
    // The model this one would replace, compared with it on the same probes and the same holdout.
    if let Some(previous) = previous_model(conn, context, revision, scope.as_str())? {
        profile.comparison = Some(learner::compare(
            &profile,
            &previous.profile,
            &previous.id,
            &holdout,
        ));
    }
    let payload = serde_json::to_string(&profile)?;
    let hash = model_hash(context, revision, scope.as_str(), &payload)?;
    let id = format!("model-{}", uuid::Uuid::new_v4());
    conn.execute(
        "INSERT INTO adaptive_models
         (model_id, agent_id, context_id, guardrails_revision, scope, profile_json, model_hash, created_at_ms, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![id, agent, context, revision, scope.as_str(), payload, hash, now, actor],
    )?;
    for (split, sessions) in [("training", &training), ("holdout", &holdout)] {
        for session in sessions {
            conn.execute(
                "INSERT INTO adaptive_model_sessions (model_id, session_id, split) VALUES (?1, ?2, ?3)",
                params![id, session.session_id, split],
            )?;
        }
    }
    conn.execute(
        "INSERT INTO adaptive_heads (context_id, guardrails_revision, scope, shadow_model_id)
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT(context_id, guardrails_revision, scope)
         DO UPDATE SET shadow_model_id = excluded.shadow_model_id",
        params![context, revision, scope.as_str(), id],
    )?;
    audit(
        conn,
        agent,
        actor,
        "train_shadow_candidate",
        now,
        json!({
            "model_id":id,"model_hash":hash,"dataset_hash":profile.dataset_hash,
            "training_runs":profile.training_runs,"training_requests":profile.training_requests,
            "holdout_runs":profile.holdout_runs,"holdout_requests":profile.holdout_requests,
            "algorithm_version":profile.algorithm_version,
            "prior": profile.prior.as_ref().map(|p| json!({"tier":p.tier,"sources":p.sources})),
            "compared_with": profile.comparison.as_ref().map(|c| json!({
                "previous_model_id":c.previous_model_id,"blockers":c.blockers.len()})),
        }),
    )?;
    Ok(())
}

fn load_session(
    conn: &Connection,
    id: String,
    run: String,
    start: i64,
    end: i64,
) -> Result<TrainingSession> {
    let mut stmt = conn.prepare(
        "SELECT d.normalized_request_json, o.base_outcome, o.base_risk_score
         FROM adaptive_observations o JOIN decisions d USING(epoch_id, request_id)
         WHERE o.session_id = ?1 ORDER BY d.created_at_ms, d.rowid",
    )?;
    let rows = stmt
        .query_map(params![id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let observations = rows
        .into_iter()
        .map(|(request, outcome, score)| {
            Ok(TrainingObservation {
                request: serde_json::from_str(&request)?,
                base_outcome: serde_json::from_str(&outcome)?,
                base_risk_score: score,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(TrainingSession {
        session_id: id,
        run_id: run,
        started_at_ms: start,
        ended_at_ms: end,
        observations,
    })
}

/// Statistics pooled from the newest usable model of each other workload, to shrink a sparse model toward. Workloads of the same
/// task profile (everything is pooled). `None` when there is no such workload with a usable model.
fn pooled_prior(
    conn: &Connection,
    agent: &str,
    context: &str,
    scope: LearningScope,
) -> Result<Option<learner::Prior>> {
    let task_profile: Option<String> = conn
        .query_row(
            "SELECT task_profile FROM scoring_contexts WHERE context_id = ?1",
            params![context],
            |row| row.get(0),
        )
        .optional()?;
    let Some(task_profile) = task_profile else {
        return Ok(None);
    };
    // Only the task-profile tier: the offline evaluation (docs/adaptive-v2.md) found a fleet-wide prior for rates and shape caught fewer
    // attacks than no prior at all, with no fewer false alerts, so it is not used. `learner::pool` still supports it.
    {
        let (tier, same_profile) = ("task_profile", true);
        let mut stmt = conn.prepare(
            "SELECT m.model_id, m.agent_id FROM adaptive_models m
             JOIN scoring_contexts c ON c.context_id = m.context_id
             WHERE m.agent_id != ?1 AND m.scope = ?2 AND m.revoked_at_ms IS NULL
               AND ((?3 = 1 AND c.task_profile = ?4) OR (?3 = 0 AND c.task_profile != ?4))
             ORDER BY m.created_at_ms DESC, m.rowid DESC LIMIT 200",
        )?;
        let candidates = stmt
            .query_map(
                params![agent, scope.as_str(), i64::from(same_profile), task_profile],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut seen = BTreeSet::new();
        let mut models = Vec::new();
        for (id, other) in candidates {
            if models.len() >= 32 || !seen.insert(other) {
                continue;
            }
            // A sibling that fails its integrity check is left out of the pool; it never blocks this workload's training.
            if let Ok(Some(sibling)) = model(conn, &id) {
                models.push(sibling);
            }
        }
        let sources: Vec<(String, &LearnedProfile)> = models
            .iter()
            .map(|sibling| (sibling.id.clone(), &sibling.profile))
            .collect();
        if let Some(prior) = learner::pool(tier, &sources, same_profile) {
            return Ok(Some(prior));
        }
    }
    Ok(None)
}

/// The model a new candidate would replace: the enforced one, else the current shadow, else the newest usable earlier model.
fn previous_model(
    conn: &Connection,
    context: &str,
    revision: u64,
    scope: &str,
) -> Result<Option<Model>> {
    let heads = head(conn, context, revision, scope)?;
    let id = match heads.enforced.or(heads.shadow) {
        Some(id) => Some(id),
        None => conn
            .query_row(
                "SELECT model_id FROM adaptive_models
                 WHERE context_id = ?1 AND guardrails_revision = ?2 AND scope = ?3 AND revoked_at_ms IS NULL
                 ORDER BY created_at_ms DESC, rowid DESC LIMIT 1",
                params![context, revision, scope],
                |row| row.get::<_, String>(0),
            )
            .optional()?,
    };
    Ok(match id {
        Some(id) => model(conn, &id).ok().flatten().filter(|m| !m.revoked),
        None => None,
    })
}

fn holdout_of(conn: &Connection, model_id: &str) -> Result<Vec<TrainingSession>> {
    let mut stmt = conn.prepare(
        "SELECT s.session_id, s.run_id, s.started_at_ms, COALESCE(s.ended_at_ms, s.started_at_ms + 1)
         FROM adaptive_model_sessions m JOIN adaptive_sessions s USING(session_id)
         WHERE m.model_id = ?1 AND m.split = 'holdout' ORDER BY s.started_at_ms, s.session_id",
    )?;
    let rows = stmt
        .query_map(params![model_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, run, start, end)| load_session(conn, id, run, start, end))
        .collect()
}

/// The candidate against the model that is enforced now, when that is not the model its stored comparison was made against.
fn live_comparison(conn: &Connection, candidate: &Model) -> Result<Option<learner::Comparison>> {
    let heads = head(
        conn,
        &candidate.context,
        candidate.revision,
        &candidate.scope,
    )?;
    let Some(enforced) = heads.enforced.filter(|id| *id != candidate.id) else {
        return Ok(None);
    };
    let stored = candidate
        .profile
        .comparison
        .as_ref()
        .map(|comparison| comparison.previous_model_id.as_str());
    if stored == Some(enforced.as_str()) {
        return Ok(None);
    }
    let Some(previous) = model(conn, &enforced).ok().flatten() else {
        return Ok(None);
    };
    Ok(Some(learner::compare(
        &candidate.profile,
        &previous.profile,
        &previous.id,
        &holdout_of(conn, &candidate.id)?,
    )))
}

fn set_model(
    conn: &Connection,
    model: &Model,
    mode: ModelMode,
    acknowledged: bool,
    revision: u64,
) -> Result<()> {
    set_model_inner(conn, model, mode, acknowledged, revision, false)
}

fn set_model_inner(
    conn: &Connection,
    model: &Model,
    mode: ModelMode,
    acknowledged: bool,
    revision: u64,
    bypass_two_person: bool,
) -> Result<()> {
    if mode != ModelMode::Off && (model.revoked || model.revision != revision) {
        return Err(invalid(
            "revoked or incompatible models cannot be activated",
        ));
    }
    let current_head = head(conn, &model.context, model.revision, &model.scope)?;
    if !bypass_two_person
        && mode != ModelMode::Enforce
        && current_head.enforced.as_deref() == Some(model.id.as_str())
    {
        let two_person_on: bool = conn
            .query_row(
                "SELECT value FROM service_settings WHERE name = 'two_person_required'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_some_and(|v| v == "1");
        if two_person_on {
            return Err(RiskGuardError::PermissionDenied(
                "demoting or disabling an enforced adaptive model loosens protection, and two-person approval is on: propose it and have someone else approve it".into(),
            ));
        }
    }
    if mode == ModelMode::Enforce {
        let mut reasons = promotion_blockers(conn, model, revision)?;
        // The enforced model may have changed since this candidate was trained; compare against the one in force now.
        if let Some(live) = live_comparison(conn, model)? {
            reasons.extend(live.blockers);
        }
        if !reasons.is_empty() {
            return Err(invalid(format!("promotion refused: {}", reasons.join(" "))));
        }
        if !acknowledged {
            return Err(invalid(
                "explicit operator acknowledgement of shadow review is required",
            ));
        }
        if current_head.shadow.as_deref() != Some(&model.id) {
            return Err(invalid(
                "select this candidate for shadow evaluation before promotion",
            ));
        }
    }
    match mode {
        ModelMode::Shadow => {
            conn.execute(
            "UPDATE adaptive_heads SET shadow_model_id = ?4,
             enforced_model_id = CASE WHEN enforced_model_id = ?4 THEN NULL ELSE enforced_model_id END
             WHERE context_id = ?1 AND guardrails_revision = ?2 AND scope = ?3",
            params![model.context, model.revision, model.scope, model.id],
        )?;
        }
        ModelMode::Enforce => {
            conn.execute(
            "UPDATE adaptive_heads SET enforced_model_id = ?4 WHERE context_id = ?1 AND guardrails_revision = ?2 AND scope = ?3",
            params![model.context, model.revision, model.scope, model.id],
        )?;
        }
        ModelMode::Off => {
            conn.execute(
            "UPDATE adaptive_heads SET
             shadow_model_id = CASE WHEN shadow_model_id = ?4 THEN NULL ELSE shadow_model_id END,
             enforced_model_id = CASE WHEN enforced_model_id = ?4 THEN NULL ELSE enforced_model_id END
             WHERE context_id = ?1 AND guardrails_revision = ?2 AND scope = ?3",
            params![model.context, model.revision, model.scope, model.id],
        )?;
        }
    }
    Ok(())
}

fn clean_request(request: &NormalizedRequest, base: &RiskEvaluation) -> bool {
    base.outcome != DecisionOutcome::Deny
        && base.risk_score < learner::WOULD_BLOCK_THRESHOLD
        && !request.high_impact
        && !request.route_template.is_empty()
        && request.route_template != "unknown"
        && matches!(
            request.semantic_category.as_str(),
            "read_only" | "read_only_query"
        )
        && matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS" | "POST")
        && (request.method != "POST"
            || (request.semantic_category == "read_only_query"
                && request.route_template != "/graphql"))
        && !base
            .signals
            .iter()
            .any(|s| s.feature == "task_constraint" && s.contribution > 0)
}

/// The run's trailing window counts and its recent calls, as they stood before the call being scored.
type RunWindow = (WindowSnapshot, Vec<learner::ActivityEvent>);

fn run_window(conn: &Connection, frame: &Frame<'_>, run: &str, scope: &str) -> Result<RunWindow> {
    let now = frame.request.timestamp_ms;
    let (one, fifteen, distinct_one, distinct_fifteen): (u32, u32, u32, u32) = conn.query_row(
        "SELECT COALESCE(SUM(p.observed_at_ms >= ?3),0), COUNT(*),
           COUNT(DISTINCT CASE WHEN p.observed_at_ms >= ?3 THEN
             COALESCE(NULLIF(json_extract(d.normalized_request_json,'$.resource_key'),''),
                      json_extract(d.normalized_request_json,'$.resource_id')) END),
           COUNT(DISTINCT COALESCE(NULLIF(json_extract(d.normalized_request_json,'$.resource_key'),''),
                                  json_extract(d.normalized_request_json,'$.resource_id')))
         FROM native_decision_provenance p JOIN decisions d USING(epoch_id,request_id)
         WHERE p.run_id = ?1 AND p.auth_scope = ?2 AND p.observed_at_ms >= ?4 AND p.observed_at_ms <= ?5",
        params![run, scope, now.saturating_sub(60_000), now.saturating_sub(900_000), now],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let snapshot = WindowSnapshot {
        req_count_1m: one,
        req_count_15m: fifteen,
        distinct_resources_1m: distinct_one,
        distinct_resources_15m: distinct_fifteen,
        warming: frame.window.warming,
    };
    // The run's last hour of calls across all sandboxes bound to this run, newest first from the database and oldest first for the learner.
    // Bounded; a version 1 model ignores it. The call being scored is not recorded yet, so this is the window before it.
    let mut stmt = conn.prepare(
        "SELECT p.observed_at_ms,
                COALESCE(json_extract(d.normalized_request_json,'$.action_class'), ''),
                COALESCE(json_extract(d.normalized_request_json,'$.resource_id'), ''),
                COALESCE(json_extract(d.normalized_request_json,'$.method'), '')
         FROM native_decision_provenance p JOIN decisions d USING(epoch_id,request_id)
         WHERE p.run_id = ?1 AND p.auth_scope = ?2 AND p.observed_at_ms >= ?3 AND p.observed_at_ms <= ?4
         ORDER BY p.observed_at_ms DESC, p.rowid DESC LIMIT ?5",
    )?;
    let mut activity = stmt
        .query_map(
            params![
                run,
                scope,
                now.saturating_sub(learner::ACTIVITY_MS),
                now,
                learner::MAX_ACTIVITY_EVENTS as i64
            ],
            |row| {
                let method: String = row.get(3)?;
                Ok(learner::ActivityEvent {
                    ts_ms: row.get(0)?,
                    action_class: row.get(1)?,
                    resource_id: row.get(2)?,
                    write: !matches!(
                        method.to_ascii_uppercase().as_str(),
                        "GET" | "HEAD" | "OPTIONS"
                    ),
                })
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    activity.reverse();
    Ok((snapshot, activity))
}

pub(super) fn evaluate(
    conn: &Connection,
    frame: &Frame<'_>,
    eval: &mut RiskEvaluation,
) -> Result<Vec<Assessment>> {
    let (Some(identity), Some(source)) = (frame.identity, frame.source) else {
        return Ok(Vec::new());
    };
    let scope = source.learning_scope().as_str();
    let head = head(conn, &identity.context_id, frame.revision, scope)?;
    let ids: BTreeSet<_> = head
        .shadow
        .iter()
        .chain(head.enforced.iter())
        .cloned()
        .collect();
    let window = if ids.is_empty() {
        None
    } else {
        Some(run_window(conn, frame, &identity.run_id, scope))
    };
    let mut assessments = Vec::new();
    for id in ids {
        let enforced = head.enforced.as_deref() == Some(id.as_str());
        let (model, result) = match load_and_assess(
            conn,
            frame,
            identity,
            scope,
            &id,
            window.as_ref(),
        ) {
            Ok(Some(assessed)) => assessed,
            Ok(None) => continue,
            // An enforced model is part of the decision, so its failure fails closed.
            Err(error) if enforced => return Err(error),
            // A shadow model is observation only; its failure must never decide a request.
            Err(error) => {
                tracing::warn!(model_id = %id, %error, "shadow adaptive model unavailable; request evaluated without it");
                eval.signals.push(SignalContribution {
                    feature: "adaptive_shadow".to_string(),
                    observed_summary: format!("model={id}; unavailable: {error}"),
                    baseline_summary: "shadow_model_unavailable".to_string(),
                    contribution: 0,
                    support: "shadow failures are recorded, never enforced".to_string(),
                });
                continue;
            }
        };
        let would_block = result.high_confidence
            && result.score >= eval.threshold.max(learner::WOULD_BLOCK_THRESHOLD);
        let mode = if enforced { "enforce" } else { "shadow" };
        let enforce = mode == "enforce"
            && model.profile.ready_for_enforcement
            && eval.mode == EnforcementMode::Enforce
            && eval.outcome != DecisionOutcome::Deny
            && would_block;
        let contribution = if enforce {
            result.score.saturating_sub(eval.risk_score)
        } else {
            0
        };
        if enforce {
            eval.risk_score = eval.risk_score.max(result.score);
            eval.outcome = DecisionOutcome::Deny;
            eval.reason_code = "adaptive_anomaly_denied".into();
            eval.ratchet_action = RatchetAction::TriggerTier2Cooldown {
                scope: frame.request.restriction_scope.clone(),
                cooldown_duration_ms: frame.cooldown_ms,
            };
        }
        eval.signals.push(SignalContribution {
            feature: format!("adaptive_{mode}"),
            observed_summary: format!(
                "model={id}; score={}; would_block={would_block}; {}",
                result.score,
                result.reasons.join("; ")
            ),
            baseline_summary: format!(
                "algorithm={}; hash={}",
                model.profile.algorithm_version, model.hash
            ),
            contribution,
            support: format!(
                "training_runs={},training_requests={},holdout_runs={},holdout_requests={}",
                model.profile.training_runs,
                model.profile.training_requests,
                model.profile.holdout_runs,
                model.profile.holdout_requests
            ),
        });
        assessments.push(Assessment {
            model_id: id,
            mode,
            would_block,
            result,
        });
    }
    Ok(assessments)
}

/// Load one head model, verify it still belongs to this trusted context, and assess
/// the request. `Ok(None)` means the request predates the model.
fn load_and_assess(
    conn: &Connection,
    frame: &Frame<'_>,
    identity: &AgentIdentity,
    scope: &str,
    id: &str,
    window: Option<&Result<RunWindow>>,
) -> Result<Option<(Model, AdaptiveAssessment)>> {
    let model = model(conn, id)?
        .ok_or_else(|| RiskGuardError::Storage("active adaptive model missing".into()))?;
    if model.revoked
        || model.context != identity.context_id
        || model.agent != identity.agent_id
        || model.revision != frame.revision
        || model.scope != scope
    {
        return Err(RiskGuardError::Storage(
            "adaptive head does not match its trusted scoring context".into(),
        ));
    }
    if frame.request.timestamp_ms < model.created {
        return Ok(None);
    }
    let window = match window {
        Some(Ok(window)) => window,
        Some(Err(error)) => {
            return Err(RiskGuardError::Storage(format!(
                "adaptive window unavailable: {error}"
            )));
        }
        None => {
            return Err(RiskGuardError::Storage(
                "adaptive window unavailable".into(),
            ));
        }
    };
    let result = learner::assess_in_context(
        &model.profile,
        frame.request,
        &window.0,
        Some(&window.1),
        context_inputs(frame.features).as_ref(),
    );
    Ok(Some((model, result)))
}

fn quarantine(conn: &Connection, id: &str, reason: &str, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE adaptive_sessions SET status = 'quarantined', quarantine_reason = ?2, ended_at_ms = ?3
         WHERE session_id = ?1 AND status = 'recording'", params![id, reason, now],
    )?;
    Ok(())
}

pub(super) fn record(
    conn: &Connection,
    frame: &Frame<'_>,
    base: &RiskEvaluation,
    assessments: &[Assessment],
) -> Result<()> {
    let Some(source) = frame.source else {
        return Ok(());
    };
    let request = frame.request;
    let scope = source.learning_scope().as_str();
    conn.execute(
        "INSERT INTO native_decision_provenance (epoch_id, request_id, auth_scope, observed_at_ms, run_id)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            base.epoch_id,
            request.request_id,
            scope,
            request.timestamp_ms,
            frame.identity.map(|identity| identity.run_id.as_str()),
        ],
    )?;
    let Some(identity) = frame.identity else {
        return Ok(());
    };
    let clean = clean_request(request, base);
    for assessment in assessments {
        conn.execute(
            "INSERT INTO adaptive_assessments
             (epoch_id, request_id, model_id, run_id, mode, score, would_block, clean_native, assessment_json, observed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![base.epoch_id, request.request_id, assessment.model_id, identity.run_id, assessment.mode,
                assessment.result.score, assessment.would_block, clean, serde_json::to_string(&assessment.result)?, request.timestamp_ms],
        )?;
    }
    let has_session: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM adaptive_sessions WHERE run_id = ?1)",
        params![identity.run_id],
        |row| row.get(0),
    )?;
    if !has_session && request.timestamp_ms >= 0 && auto_learning_enabled(conn, &identity.agent_id)?
    {
        let eligible: bool = conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM agent_runs r
                 WHERE r.run_id = ?1 AND r.ended_at_ms IS NULL
                   AND (SELECT COUNT(*) FROM decision_identity d WHERE d.run_id = r.run_id) = 1
                   AND (SELECT COUNT(*) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
                        WHERE b.run_id = r.run_id AND e.active != 0) = 1
             )",
            params![identity.run_id],
            |row| row.get(0),
        )?;
        if eligible {
            let id = format!("learn-{}", uuid::Uuid::new_v4());
            conn.execute(
                "INSERT INTO adaptive_sessions
                 (session_id, agent_id, run_id, context_id, guardrails_revision, scope, status, started_at_ms, notes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'recording', ?7, 'auto-enrolled')",
                params![
                    id,
                    identity.agent_id,
                    identity.run_id,
                    identity.context_id,
                    frame.revision,
                    scope,
                    request.timestamp_ms,
                ],
            )?;
            audit(
                conn,
                &identity.agent_id,
                "auto-shadow",
                "auto_start_capture",
                request.timestamp_ms,
                json!({"session_id": id, "run_id": identity.run_id, "scope": scope}),
            )?;
        }
    }
    let capture: Option<(String, u64, String, i64)> = conn
        .query_row(
            "SELECT session_id, guardrails_revision, scope, started_at_ms FROM adaptive_sessions
         WHERE run_id = ?1 AND status = 'recording'",
            params![identity.run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((session, revision, expected_scope, started)) = capture else {
        return Ok(());
    };
    if request.timestamp_ms < started {
        return Ok(());
    }
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM adaptive_observations WHERE session_id = ?1",
        params![session],
        |row| row.get(0),
    )?;
    let reason = if revision != frame.revision {
        Some("guardrails_revision_changed")
    } else if expected_scope != scope {
        Some("authentication_scope_mismatch")
    } else if request.timestamp_ms.saturating_sub(started) >= MAX_CAPTURE_MS {
        Some("capture_duration_exceeded")
    } else if count >= MAX_CAPTURE_REQUESTS {
        Some("capture_sample_budget_exceeded")
    } else if !clean {
        Some("denied_high_impact_task_constraint_or_unknown_route")
    } else {
        None
    };
    if count < MAX_CAPTURE_REQUESTS {
        conn.execute(
            "INSERT INTO adaptive_observations (session_id, epoch_id, request_id, base_outcome, base_risk_score)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session, base.epoch_id, request.request_id, serde_json::to_string(&base.outcome)?, base.risk_score],
        )?;
    }
    if let Some(reason) = reason {
        quarantine(conn, &session, reason, request.timestamp_ms)?;
        audit(
            conn,
            &identity.agent_id,
            "native-capture",
            "quarantine_capture",
            request.timestamp_ms,
            json!({"session_id":session,"reason":reason}),
        )?;
    }
    Ok(())
}

pub(super) fn finalize_run_captures(conn: &Connection, run_id: &str, now_ms: i64) -> Result<()> {
    let capture: Option<(String, String, String, u64, String, i64, String)> = conn
        .query_row(
            "SELECT session_id, agent_id, context_id, guardrails_revision, scope, started_at_ms, notes
             FROM adaptive_sessions
             WHERE run_id = ?1 AND status = 'recording'",
            params![run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((session_id, agent_id, context_id, revision, scope_str, started_at_ms, notes)) =
        capture
    else {
        return Ok(());
    };
    // Without a human reviewer, accept only windows the detector found unremarkable:
    // every request a plain allow, none merely "allowed with observation".
    let plain_allow = serde_json::to_string(&DecisionOutcome::Allow)?;
    let flagged: i64 = conn.query_row(
        "SELECT COUNT(*) FROM adaptive_observations WHERE session_id = ?1 AND base_outcome != ?2",
        params![session_id, plain_allow],
        |row| row.get(0),
    )?;
    let (count, last_ms): (i64, Option<i64>) = conn.query_row(
        "SELECT COUNT(*), MAX(p.observed_at_ms)
         FROM adaptive_observations o
         JOIN native_decision_provenance p USING(epoch_id, request_id)
         WHERE o.session_id = ?1",
        params![session_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let end_ms = now_ms
        .max(started_at_ms.saturating_add(1))
        .max(last_ms.map_or(started_at_ms, |l| l.saturating_add(1)));
    if end_ms.saturating_sub(started_at_ms) > MAX_CAPTURE_MS {
        quarantine(conn, &session_id, "capture_duration_exceeded", end_ms)?;
        audit(
            conn,
            &agent_id,
            "auto-clean-policy",
            "quarantine_capture",
            end_ms,
            json!({"session_id": session_id, "reason": "capture_duration_exceeded"}),
        )?;
    } else if count == 0 {
        conn.execute(
            "UPDATE adaptive_sessions
             SET status = 'rejected', ended_at_ms = ?2, notes = 'auto-closed empty capture', reviewed_by = 'auto-clean-policy'
             WHERE session_id = ?1",
            params![session_id, end_ms],
        )?;
        audit(
            conn,
            &agent_id,
            "auto-clean-policy",
            "auto_reject_empty_capture",
            end_ms,
            json!({"session_id": session_id, "run_id": run_id}),
        )?;
    } else if notes == AUTO_ENROLLED_NOTE
        && flagged == 0
        && auto_learning_enabled(conn, &agent_id)?
        && current_revision(conn, &agent_id)? == revision
    {
        conn.execute(
            "UPDATE adaptive_sessions
             SET status = 'approved', ended_at_ms = ?2, notes = 'auto-approved clean read-only run', reviewed_by = 'auto-clean-policy'
             WHERE session_id = ?1",
            params![session_id, end_ms],
        )?;
        audit(
            conn,
            &agent_id,
            "auto-clean-policy",
            "auto_approve_capture",
            end_ms,
            json!({"session_id": session_id, "run_id": run_id, "request_count": count}),
        )?;
        let scope = match scope_str.as_str() {
            "verified" => Some(LearningScope::Verified),
            "local_demo" => Some(LearningScope::LocalDemo),
            _ => None,
        };
        if let Some(scope) = scope
            && let Err(error) = train(
                conn,
                &agent_id,
                &context_id,
                scope,
                revision,
                "auto-shadow-trainer",
                end_ms,
            )
        {
            // The approval stands; the candidate simply was not refreshed. Make that visible.
            tracing::warn!(%agent_id, %context_id, %error, "automatic shadow training skipped");
            audit(
                conn,
                &agent_id,
                "auto-shadow-trainer",
                "auto_train_skipped",
                end_ms,
                json!({"session_id": session_id, "context_id": context_id, "reason": error.to_string()}),
            )?;
        }
    } else {
        // Manual captures, flagged windows, paused auto-learning or a changed
        // guardrail revision all wait for an explicit human decision.
        conn.execute(
            "UPDATE adaptive_sessions SET status = 'pending_review', ended_at_ms = ?2 WHERE session_id = ?1",
            params![session_id, end_ms],
        )?;
    }
    Ok(())
}

pub(super) fn decision_assessments(conn: &Connection, epoch: &str, request: &str) -> Result<Value> {
    let mut stmt = conn.prepare(
        "SELECT a.model_id, a.mode, a.would_block, a.assessment_json, m.model_hash
         FROM adaptive_assessments a JOIN adaptive_models m USING(model_id)
         WHERE a.epoch_id = ?1 AND a.request_id = ?2 ORDER BY a.model_id",
    )?;
    let rows = stmt
        .query_map(params![epoch, request], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(id, mode, would_block, assessment, hash)| {
                Ok(json!({
                    "model_id":id,"mode":mode,"would_block":would_block,"model_hash":hash,
                    "assessment":serde_json::from_str::<Value>(&assessment)?,
                }))
            })
            .collect::<Result<Vec<_>>>()?,
    ))
}

pub(super) fn decision_transport(
    conn: &Connection,
    epoch: &str,
    request: &str,
) -> Result<&'static str> {
    let scope: Option<String> = conn.query_row(
        "SELECT auth_scope FROM native_decision_provenance WHERE epoch_id = ?1 AND request_id = ?2",
        params![epoch, request], |row| row.get(0),
    ).optional()?;
    match scope.as_deref() {
        Some("verified") => Ok("native_supervisor_http_rpc_verified"),
        Some("local_demo") => Ok("native_supervisor_http_rpc_local_test"),
        None => Ok("not_recorded"),
        _ => Err(RiskGuardError::Storage(
            "invalid native provenance scope".into(),
        )),
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Baseline maturity backed by what the learner observed

/// The thresholds `BaselineProfile::maturity` uses. A test keeps these in step with it.
pub(crate) const MATURE_SESSIONS: u32 = 20;
pub(crate) const MATURE_REQUESTS: u32 = 200;

/// What the model observed that the baseline's hand-kept lists leave out. Once maturity is credited the detector treats a call off those
/// lists as new, so a list that contradicts the observed traffic has to be fixed first.
fn baseline_disagreement(conn: &Connection, model: &Model) -> Result<Vec<String>> {
    let payload: Option<String> = conn
        .query_row(
            "SELECT a.payload_json FROM scoring_contexts c JOIN artifacts a ON a.artifact_hash = c.baseline_hash
             WHERE c.context_id = ?1",
            params![model.context],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(vec![
            "The scoring context's baseline could not be read.".to_string(),
        ]);
    };
    let baseline: BaselineProfile = serde_json::from_str(&payload)?;
    let profile = &model.profile;
    let off_list = |counts: &BTreeMap<String, u32>, total: u32, listed: &BTreeSet<String>| {
        if listed.is_empty() || total == 0 {
            return Vec::new();
        }
        counts
            .iter()
            .filter(|(key, count)| {
                u64::from(**count) * 100 >= u64::from(total) && !listed.contains(*key)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>()
    };
    let mut missing = off_list(
        &profile.action_counts,
        profile.training_requests,
        &baseline.allowed_action_classes,
    );
    missing.extend(off_list(
        &profile.binary_counts,
        profile.known_binary_requests,
        &baseline.expected_binaries,
    ));
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    missing.truncate(5);
    Ok(vec![format!(
        "The baseline's approved lists leave out traffic the model observed (at least 1% of it): {}. Credited maturity would count those calls as new, so update the baseline or retrain first.",
        missing.join(", ")
    )])
}

#[allow(clippy::too_many_arguments)]
fn credit_maturity(
    conn: &Connection,
    agent: &str,
    model_id: &str,
    acknowledged: bool,
    note: &str,
    revision: u64,
    actor: &str,
    now: i64,
) -> Result<()> {
    if !acknowledged {
        return Err(invalid(
            "crediting maturity needs explicit acknowledgement that the behavioral score can then refuse on rarity for this workload",
        ));
    }
    if note.len() > 1_000 {
        return Err(invalid("maturity note exceeds 1000 bytes"));
    }
    let selected = model(conn, model_id)?.ok_or_else(|| invalid("model not found"))?;
    if selected.agent != agent {
        return Err(invalid("model does not belong to this workload"));
    }
    let heads = head(conn, &selected.context, selected.revision, &selected.scope)?;
    if heads.enforced.as_deref() != Some(model_id) || selected.revision != revision {
        return Err(invalid(
            "only the model that is enforced now, under the current guardrails revision, can be credited: promote it first",
        ));
    }
    let mut problems = promotion_blockers(conn, &selected, revision)?;
    let profile = &selected.profile;
    if profile.training_runs < MATURE_SESSIONS || profile.training_requests < MATURE_REQUESTS {
        problems.push(format!(
            "The model was trained on {} independent runs and {} requests; maturity needs {MATURE_SESSIONS} and {MATURE_REQUESTS}.",
            profile.training_runs, profile.training_requests
        ));
    }
    problems.extend(baseline_disagreement(conn, &selected)?);
    if !problems.is_empty() {
        return Err(invalid(format!(
            "maturity credit refused: {}",
            problems.join(" ")
        )));
    }
    let (auto, total): (i64, i64) = conn.query_row(
        "SELECT COALESCE(SUM(s.reviewed_by = ?2), 0), COUNT(*)
         FROM adaptive_model_sessions m JOIN adaptive_sessions s USING(session_id)
         WHERE m.model_id = ?1 AND m.split = 'training'",
        params![model_id, AUTO_REVIEWER],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let task_profile: String = conn.query_row(
        "SELECT task_profile FROM scoring_contexts WHERE context_id = ?1",
        params![selected.context],
        |row| row.get(0),
    )?;
    conn.execute(
        "UPDATE adaptive_maturity_credits SET revoked_by = ?2, revoked_at_ms = ?3,
         revoke_reason = 'replaced by a newer credit' WHERE context_id = ?1 AND revoked_at_ms IS NULL",
        params![selected.context, actor, now],
    )?;
    let id = format!("credit-{}", uuid::Uuid::new_v4());
    conn.execute(
        "INSERT INTO adaptive_maturity_credits
         (credit_id, agent_id, context_id, task_profile, model_id, model_hash, training_sessions, training_requests,
          holdout_runs, holdout_requests, holdout_would_block, person_approved_sessions, auto_approved_sessions,
          granted_by, granted_at_ms, note)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            id,
            agent,
            selected.context,
            task_profile,
            model_id,
            selected.hash,
            profile.training_runs,
            profile.training_requests,
            profile.holdout_runs,
            profile.holdout_requests,
            profile.holdout_would_block,
            total - auto,
            auto,
            actor,
            now,
            note
        ],
    )?;
    audit(
        conn,
        agent,
        actor,
        "credit_maturity",
        now,
        json!({"credit_id":id,"model_id":model_id,"model_hash":selected.hash,"context_id":selected.context,
            "task_profile":task_profile,"training_sessions":profile.training_runs,
            "training_requests":profile.training_requests,"person_approved_sessions":total - auto,
            "auto_approved_sessions":auto,"note":note}),
    )?;
    Ok(())
}

fn revoke_maturity_credit(
    conn: &Connection,
    agent: &str,
    context: &str,
    reason: &str,
    actor: &str,
    now: i64,
) -> Result<()> {
    if reason.trim().is_empty() || reason.len() > 1_000 {
        return Err(invalid("a reason of 1 to 1000 bytes is required"));
    }
    let changed = conn.execute(
        "UPDATE adaptive_maturity_credits SET revoked_by = ?3, revoked_at_ms = ?4, revoke_reason = ?5
         WHERE agent_id = ?1 AND context_id = ?2 AND revoked_at_ms IS NULL",
        params![agent, context, actor, now, reason],
    )?;
    if changed == 0 {
        return Err(invalid(
            "no live maturity credit for this workload and context",
        ));
    }
    audit(
        conn,
        agent,
        actor,
        "revoke_maturity_credit",
        now,
        json!({"context_id":context,"reason":reason}),
    )?;
    Ok(())
}

/// Every credit for a workload, newest first, with whether it counts right now.
fn credit_views(conn: &Connection, agent: &str, revision: u64) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare(
        "SELECT c.credit_id, c.context_id, c.task_profile, c.model_id, c.model_hash, c.training_sessions,
                c.training_requests, c.holdout_runs, c.holdout_requests, c.holdout_would_block,
                c.person_approved_sessions, c.auto_approved_sessions, c.granted_by, c.granted_at_ms, c.note,
                c.revoked_by, c.revoked_at_ms, c.revoke_reason,
                (c.revoked_at_ms IS NULL AND m.revoked_at_ms IS NULL AND m.guardrails_revision = ?2
                 AND EXISTS (SELECT 1 FROM adaptive_heads h WHERE h.context_id = m.context_id
                    AND h.guardrails_revision = m.guardrails_revision AND h.scope = m.scope
                    AND h.enforced_model_id = c.model_id))
         FROM adaptive_maturity_credits c JOIN adaptive_models m ON m.model_id = c.model_id
         WHERE c.agent_id = ?1 ORDER BY c.granted_at_ms DESC, c.rowid DESC LIMIT 20",
    )?;
    let rows = stmt
        .query_map(params![agent, revision], |row| {
            Ok(json!({
                "credit_id": row.get::<_, String>(0)?, "context_id": row.get::<_, String>(1)?,
                "task_profile": row.get::<_, String>(2)?, "model_id": row.get::<_, String>(3)?,
                "model_hash": row.get::<_, String>(4)?, "training_sessions": row.get::<_, i64>(5)?,
                "training_requests": row.get::<_, i64>(6)?, "holdout_runs": row.get::<_, i64>(7)?,
                "holdout_requests": row.get::<_, i64>(8)?, "holdout_would_block": row.get::<_, i64>(9)?,
                "person_approved_sessions": row.get::<_, i64>(10)?,
                "auto_approved_sessions": row.get::<_, i64>(11)?,
                "granted_by": row.get::<_, String>(12)?, "granted_at_ms": row.get::<_, i64>(13)?,
                "note": row.get::<_, String>(14)?, "revoked_by": row.get::<_, Option<String>>(15)?,
                "revoked_at_ms": row.get::<_, Option<i64>>(16)?,
                "revoke_reason": row.get::<_, Option<String>>(17)?,
                "counts_now": row.get::<_, bool>(18)?,
            }))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Raise `base`'s hand-kept maturity counters to what an operator-credited model observed, when a credit counts for this scoring
/// context right now. The raised profile is stored as an artifact (of its own type, so it is not listed as a task profile) and a
/// `maturity_credit` signal is returned for the decision to carry: replay uses it to mark a bundle incomplete, because a bundle does not
/// carry credits. With no counting credit the baseline comes back untouched.
pub(super) fn credited_baseline(
    conn: &Connection,
    identity: &AgentIdentity,
    revision: u64,
    base: BaselineProfile,
) -> Result<(BaselineProfile, Option<SignalContribution>)> {
    let credit: Option<(String, String, u32, u32)> = conn
        .query_row(
            "SELECT c.credit_id, c.model_id, c.training_sessions, c.training_requests
             FROM adaptive_maturity_credits c JOIN adaptive_models m ON m.model_id = c.model_id
             JOIN adaptive_heads h ON h.context_id = m.context_id
              AND h.guardrails_revision = m.guardrails_revision AND h.scope = m.scope
             WHERE c.context_id = ?1 AND c.revoked_at_ms IS NULL AND m.revoked_at_ms IS NULL
               AND m.guardrails_revision = ?2 AND h.enforced_model_id = c.model_id",
            params![identity.context_id, revision],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((credit_id, model_id, sessions, requests)) = credit else {
        return Ok((base, None));
    };
    if base.training_sessions >= sessions && base.training_requests >= requests {
        return Ok((base, None));
    }
    let mut credited = base.clone();
    credited.training_sessions = base.training_sessions.max(sessions);
    credited.training_requests = base.training_requests.max(requests);
    credited.version = format!("{}+maturity-credit-{credit_id}", base.version);
    let payload = serde_json::to_string(&credited)?;
    conn.execute(
        "INSERT INTO artifacts (artifact_hash, artifact_type, name, version, payload_json, created_at_ms)
         VALUES (?1, 'baseline_profile_maturity_credit', ?2, ?3, ?4, ?5) ON CONFLICT(artifact_hash) DO NOTHING",
        params![
            crate::detector::compute_baseline_hash(&credited),
            format!("agent:{}:maturity-credit", identity.agent_id),
            credited.version,
            payload,
            current_time_ms()
        ],
    )?;
    let signal = SignalContribution {
        feature: "maturity_credit".to_string(),
        observed_summary: format!("credit={credit_id}; model={model_id}"),
        baseline_summary: format!(
            "baseline counters raised from sessions={},requests={} to sessions={},requests={}",
            base.training_sessions,
            base.training_requests,
            credited.training_sessions,
            credited.training_requests
        ),
        contribution: 0,
        support: "baseline maturity backed by an operator-credited adaptive model; a replay bundle does not carry credits"
            .to_string(),
    };
    Ok((credited, Some(signal)))
}

/// One workload whose baseline maturity is backed by a credit that counts right now.
pub(super) struct CountingCredit {
    pub task_profile: String,
    pub agent_id: String,
    pub sessions: u32,
    pub requests: u32,
    pub granted_by: String,
    pub granted_at_ms: i64,
    pub model_id: String,
}

/// Credits that count now, for the Controls page.
pub(super) fn counting_credits(conn: &Connection) -> Result<Vec<CountingCredit>> {
    let mut stmt = conn.prepare(
        "SELECT c.task_profile, c.agent_id, c.training_sessions, c.training_requests, c.granted_by, c.granted_at_ms, c.model_id
         FROM adaptive_maturity_credits c JOIN adaptive_models m ON m.model_id = c.model_id
         JOIN adaptive_heads h ON h.context_id = m.context_id
          AND h.guardrails_revision = m.guardrails_revision AND h.scope = m.scope
         WHERE c.revoked_at_ms IS NULL AND m.revoked_at_ms IS NULL AND h.enforced_model_id = c.model_id
           AND m.guardrails_revision = COALESCE(
               (SELECT g.revision FROM agent_guardrail_heads g WHERE g.agent_id = c.agent_id), 0)
         ORDER BY c.task_profile, c.agent_id",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(CountingCredit {
                task_profile: row.get(0)?,
                agent_id: row.get(1)?,
                sessions: row.get(2)?,
                requests: row.get(3)?,
                granted_by: row.get(4)?,
                granted_at_ms: row.get(5)?,
                model_id: row.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub(super) fn ensure_maturity_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(include_str!(
        "../../migrations/0008_adaptive_maturity_credits.sql"
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContextFeature, FeatureScope};

    fn feature(scope: FeatureScope, name: &str, value: u32) -> ContextFeature {
        ContextFeature {
            scope,
            name: name.to_string(),
            value,
            subject: "test".to_string(),
            age_ms: 0,
        }
    }

    #[test]
    fn no_features_means_no_learner_context() {
        assert!(context_inputs(None).is_none());
        assert!(context_inputs(Some(&ContextFeatures::default())).is_none());
    }

    #[test]
    fn the_siem_features_reach_the_learner_under_their_own_names() {
        let features = ContextFeatures::new([
            feature(FeatureScope::Sandbox, "openshell_denials_5m", 4),
            feature(FeatureScope::Workload, "refusal_ratio_15m_permille", 400),
            feature(FeatureScope::Fleet, "fleet_workloads_with_denials_5m", 3),
            // Route features are not the learner's vocabulary; they are used only by the rule `siem_context`.
            feature(FeatureScope::Workload, "new_routes_1h", 9),
        ]);
        let inputs = context_inputs(Some(&features)).expect("context");
        assert_eq!(inputs.openshell_denials_5m, Some(4));
        assert_eq!(inputs.refusal_ratio_15m_permille, Some(400));
        assert_eq!(inputs.fleet_workloads_with_denials_5m, Some(3));
        assert_eq!(inputs.openshell_denials_1h, None);
    }
}
