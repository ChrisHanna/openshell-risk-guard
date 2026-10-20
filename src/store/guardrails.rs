use super::*;
use crate::detector::InteractionRiskDetector;
use crate::guardrails::{
    AgentGuardrails, GuardrailsSaveResult, GuardrailsUpdate, filesystem_matches,
};
use openshell_policy_schema::{FilesystemPolicy, PolicyDocument};
use serde_json::{Value, json};

pub(super) struct SavedGuardrails {
    pub revision: u64,
    pub settings: AgentGuardrails,
    pub settings_hash: String,
    pub profile_hash: String,
    pub updated_by: String,
    pub created_at_ms: i64,
}

pub(super) fn query_saved(conn: &Connection, agent_id: &str) -> Result<Option<SavedGuardrails>> {
    let row = conn
        .query_row(
            "SELECT r.revision, r.settings_json, r.settings_hash, r.profile_artifact_hash,
                r.updated_by, r.created_at_ms
         FROM agent_guardrail_heads h JOIN agent_guardrail_revisions r
           ON r.agent_id = h.agent_id AND r.revision = h.revision
         WHERE h.agent_id = ?1",
            params![agent_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((revision, payload, settings_hash, profile_hash, updated_by, created_at_ms)) = row
    else {
        return Ok(None);
    };
    if hex::encode(Sha256::digest(payload.as_bytes())) != settings_hash {
        return Err(RiskGuardError::Storage(
            "agent guardrail settings hash mismatch".into(),
        ));
    }
    let settings: AgentGuardrails = serde_json::from_str(&payload)
        .map_err(|error| RiskGuardError::Storage(format!("corrupt agent guardrails: {error}")))?;
    settings
        .validate()
        .map_err(|error| RiskGuardError::Storage(format!("invalid saved guardrails: {error}")))?;
    Ok(Some(SavedGuardrails {
        revision: u64::try_from(revision)
            .map_err(|_| RiskGuardError::Storage("invalid guardrail revision".into()))?,
        settings,
        settings_hash,
        profile_hash,
        updated_by,
        created_at_ms,
    }))
}

fn latest_agent_policy(conn: &Connection, agent_id: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT p.policy_yaml FROM policy_snapshots p
         JOIN epochs e ON e.sandbox_id = p.sandbox_id
         JOIN epoch_bindings b ON b.epoch_id = e.epoch_id
         JOIN agent_runs r ON r.run_id = b.run_id
         JOIN scoring_contexts c ON c.context_id = r.context_id
         WHERE c.agent_id = ?1 ORDER BY p.captured_at_ms DESC, p.id DESC LIMIT 1",
        params![agent_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn parsed_policy(raw: &str) -> Result<PolicyDocument> {
    openshell_policy_schema::parse_policy(raw).map_err(|error| {
        RiskGuardError::Policy(format!("recorded policy cannot be parsed: {error}"))
    })
}

pub(super) fn query_view(conn: &Connection, agent_id: &str, _now_ms: i64) -> Result<Option<Value>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
        params![agent_id],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let saved = query_saved(conn, agent_id)?;
    let seed: Option<(String, String, String)> = conn
        .query_row(
            "SELECT baseline_hash, mode, configuration_id FROM scoring_contexts
         WHERE agent_id = ?1 ORDER BY created_at_ms DESC, rowid DESC LIMIT 1",
            params![agent_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let mut seed_profile_hash = None;
    let mut seed_settings = None;
    let mut policy_errors = Vec::new();
    if let Some((hash, mode, configuration)) = seed {
        if configuration == InteractionRiskDetector::new_default().configuration_id() {
            let profile = query_baseline_by_name_or_hash(conn, &hash, &hash)?
                .ok_or_else(|| RiskGuardError::Storage("pinned baseline is unavailable".into()))?;
            let filesystem = match latest_agent_policy(conn, agent_id)? {
                Some(raw) => match parsed_policy(&raw) {
                    Ok(policy) => policy.filesystem_policy,
                    Err(error) => {
                        tracing::warn!(%agent_id, %error, "recorded filesystem policy is unavailable");
                        policy_errors.push(error.to_string());
                        None
                    }
                },
                None => None,
            };
            let mode = match mode.as_str() {
                "observe" => EnforcementMode::Observe,
                "enforce" => EnforcementMode::Enforce,
                _ => return Err(RiskGuardError::Storage("invalid context mode".into())),
            };
            seed_settings = Some(AgentGuardrails::from_baseline(&profile, mode, filesystem));
            seed_profile_hash = Some(hash);
        }
    }
    let settings = saved
        .as_ref()
        .map(|record| &record.settings)
        .or(seed_settings.as_ref());
    let revision = saved.as_ref().map_or(0, |record| record.revision);
    let mut history_stmt = conn.prepare(
        "SELECT revision, updated_by, created_at_ms, settings_hash
         FROM agent_guardrail_revisions WHERE agent_id = ?1 ORDER BY revision DESC LIMIT 20",
    )?;
    let history = history_stmt
        .query_map(params![agent_id], |row| {
            Ok(json!({
                "revision": row.get::<_, i64>(0)?,
                "updated_by": row.get::<_, String>(1)?,
                "created_at_ms": row.get::<_, i64>(2)?,
                "settings_hash": row.get::<_, String>(3)?,
            }))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let observed: i64 = conn.query_row(
        "SELECT COUNT(*) FROM decision_guardrail_revisions WHERE agent_id = ?1 AND revision = ?2",
        params![agent_id, revision],
        |row| row.get(0),
    )?;
    let total_active: i64 = conn.query_row(
        "SELECT COUNT(*) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
         JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
         WHERE c.agent_id = ?1 AND e.active != 0 AND r.ended_at_ms IS NULL",
        params![agent_id],
        |row| row.get(0),
    )?;
    let mut sandbox_stmt = conn.prepare(
        "SELECT e.sandbox_id, c.task_profile, c.baseline_hash,
           (SELECT p.policy_yaml FROM policy_snapshots p WHERE p.sandbox_id = e.sandbox_id
            ORDER BY p.captured_at_ms DESC, p.id DESC LIMIT 1)
         FROM epoch_bindings b JOIN epochs e USING(epoch_id)
         JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
         WHERE c.agent_id = ?1 AND e.active != 0 AND r.ended_at_ms IS NULL
         ORDER BY e.created_at_ms DESC, e.epoch_id DESC LIMIT 200",
    )?;
    let rows = sandbox_stmt
        .query_map(params![agent_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut filesystem_pending = 0;
    let mut filesystem_unknown = 0;
    let mut profile_pending = 0;
    let mut sandboxes = Vec::new();
    for (sandbox_id, profile, baseline_hash, policy) in rows {
        let profile_matches = settings.is_some_and(|setting| setting.task_profile == profile)
            && saved
                .as_ref()
                .is_none_or(|saved| saved.profile_hash == baseline_hash);
        if !profile_matches {
            profile_pending += 1;
        }
        let filesystem_status = if let Some(desired) = settings.and_then(|s| s.filesystem.as_ref())
        {
            let recorded = match policy {
                Some(raw) => match parsed_policy(&raw) {
                    Ok(policy) => policy.filesystem_policy,
                    Err(error) => {
                        tracing::warn!(%agent_id, %sandbox_id, %error, "recorded filesystem policy is unavailable");
                        policy_errors.push(format!("{sandbox_id}: {error}"));
                        None
                    }
                },
                None => None,
            };
            match recorded {
                Some(actual) if filesystem_matches(desired, &actual) => "recorded_match",
                Some(_) => {
                    filesystem_pending += 1;
                    "new_sandbox_required"
                }
                None => {
                    filesystem_unknown += 1;
                    "not_recorded"
                }
            }
        } else {
            "not_managed"
        };
        sandboxes.push(json!({
            "sandbox_id": sandbox_id,
            "task_profile": if profile_matches { "recorded_match" } else { "new_run_required" },
            "filesystem": filesystem_status,
        }));
    }
    let limited = total_active > sandboxes.len() as i64;
    let filesystem_status = if settings.is_none_or(|s| s.filesystem.is_none()) {
        "not_managed"
    } else if filesystem_pending > 0 {
        "new_sandbox_required"
    } else if limited || filesystem_unknown > 0 {
        "not_fully_recorded"
    } else if total_active == 0 {
        "next_sandbox"
    } else {
        "recorded_match"
    };
    Ok(Some(json!({
        "agent_id": agent_id,
        "revision": revision,
        "settings": settings,
        "has_saved_settings": saved.is_some(),
        "source_profile_hash": saved.as_ref().map(|s| &s.profile_hash).or(seed_profile_hash.as_ref()),
        "updated_by": saved.as_ref().map(|s| &s.updated_by),
        "saved_at_ms": saved.as_ref().map(|s| s.created_at_ms),
        "history": history,
        "policy_errors": policy_errors,
        "application": {
            "risk_guard": {
                "status": if saved.is_some() { "active_for_subsequent_requests" } else { "baseline" },
                "observed_decisions": observed,
            },
            "task_profile": {
                "status": if total_active == 0 || profile_pending > 0 { "new_run_required" } else if limited { "coverage_limited" } else { "recorded_match" },
                "pending_sandboxes": profile_pending,
            },
            "filesystem": {
                "status": filesystem_status,
                "pending_sandboxes": filesystem_pending,
                "unknown_sandboxes": filesystem_unknown,
                "runtime_load_state": "not_collected",
            },
            "total_active_sandboxes": total_active,
            "sample_limit": 200,
            "sandboxes": sandboxes,
        },
    })))
}

impl SqliteRiskStore {
    pub fn agent_guardrails(&self, agent_id: &str, now_ms: i64) -> Result<Option<Value>> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let view = query_view(&tx, agent_id, now_ms)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn save_agent_guardrails(
        &self,
        agent_id: &str,
        update: &GuardrailsUpdate,
        actor: &str,
        now_ms: i64,
    ) -> Result<GuardrailsSaveResult> {
        update.settings.validate()?;
        if actor.is_empty() || actor.len() > 128 || actor.chars().any(char::is_control) {
            return Err(RiskGuardError::InvalidArgument(
                "invalid operator identity".into(),
            ));
        }
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
            params![agent_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(RiskGuardError::InvalidArgument(
                "agent does not exist".into(),
            ));
        }
        let current = query_saved(&tx, agent_id)?.map_or(0, |record| record.revision);
        if current != update.expected_revision {
            return Ok(GuardrailsSaveResult::Conflict {
                current_revision: current,
            });
        }
        let revision = current
            .checked_add(1)
            .and_then(|v| i64::try_from(v).ok())
            .ok_or_else(|| RiskGuardError::Storage("guardrail revision limit exceeded".into()))?;
        let profile = query_baseline_by_name_or_hash(
            &tx,
            &update.settings.task_profile,
            &update.settings.task_profile,
        )?
        .ok_or_else(|| {
            RiskGuardError::InvalidArgument(
                "task profile must be imported and approved before it can be selected".into(),
            )
        })?;
        if profile.task_profile != update.settings.task_profile {
            return Err(RiskGuardError::InvalidArgument(
                "select the approved task profile name, not an artifact alias".into(),
            ));
        }
        if profile.normalizer_version != crate::normalizer::DEFAULT_NORMALIZER_VERSION
            || profile.approved_by.trim().is_empty()
        {
            return Err(RiskGuardError::InvalidArgument(
                "task profile must be approved and compatible with normalizer v1".into(),
            ));
        }
        let profile_hash = crate::detector::compute_baseline_hash(&profile);
        let payload = serde_json::to_string(&update.settings)?;
        let hash = hex::encode(Sha256::digest(payload.as_bytes()));
        tx.execute(
            "INSERT INTO agent_guardrail_revisions
             (agent_id, revision, settings_json, settings_hash, profile_artifact_hash, updated_by, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![agent_id, revision, payload, hash, profile_hash, actor, now_ms],
        )?;
        tx.execute(
            "INSERT INTO agent_guardrail_heads (agent_id, revision) VALUES (?1, ?2)
             ON CONFLICT(agent_id) DO UPDATE SET revision = excluded.revision",
            params![agent_id, revision],
        )?;
        let view = query_view(&tx, agent_id, now_ms)?
            .ok_or_else(|| RiskGuardError::Storage("saved agent disappeared".into()))?;
        tx.commit()?;
        Ok(GuardrailsSaveResult::Saved(view))
    }

    pub fn export_agent_guardrails_policy(&self, agent_id: &str) -> Result<Option<String>> {
        let conn = self.lock_conn()?;
        let Some(saved) = query_saved(&conn, agent_id)? else {
            return Ok(None);
        };
        let raw = latest_agent_policy(&conn, agent_id)?.ok_or_else(|| {
            RiskGuardError::Policy("no recorded policy template is available".into())
        })?;
        let mut policy = parsed_policy(&raw)?;
        if let Some(filesystem) = saved.settings.filesystem {
            policy.filesystem_policy = Some(filesystem);
        }
        let mut found = false;
        for middleware in policy
            .network_middlewares
            .values_mut()
            .filter(|middleware| middleware.middleware == "risk-guard")
        {
            if middleware.on_error != "fail_closed" {
                return Err(RiskGuardError::Policy(
                    "policy template must retain fail_closed risk-guard".into(),
                ));
            }
            middleware
                .config
                .insert("task_profile".into(), json!(saved.profile_hash));
            middleware
                .config
                .insert("mode".into(), json!(saved.settings.mode.as_str()));
            found = true;
        }
        if !found {
            return Err(RiskGuardError::Policy(
                "policy template has no risk-guard middleware".into(),
            ));
        }
        let yaml = serde_yml::to_string(&policy)
            .map_err(|error| RiskGuardError::Policy(format!("policy export failed: {error}")))?;
        openshell_policy_schema::parse_policy(&yaml).map_err(|error| {
            RiskGuardError::Policy(format!("exported policy is invalid: {error}"))
        })?;
        Ok(Some(yaml))
    }
}

pub(super) fn effective_baseline(
    conn: &Connection,
    agent_id: &str,
    base: &BaselineProfile,
    saved: &SavedGuardrails,
) -> Result<BaselineProfile> {
    let mut effective = saved.settings.apply_live_baseline(base);
    effective.version = format!("{}+guardrails-{agent_id}-r{}", base.version, saved.revision);
    effective.approved_by = saved.updated_by.clone();
    let payload = serde_json::to_string(&effective)?;
    let hash = hex::encode(Sha256::digest(payload.as_bytes()));
    conn.execute(
        "INSERT INTO artifacts
         (artifact_hash, artifact_type, name, version, payload_json, created_at_ms)
         VALUES (?1, 'baseline_profile', ?2, ?3, ?4, ?5)
         ON CONFLICT(artifact_hash) DO NOTHING",
        params![
            hash,
            format!("agent:{agent_id}:guardrails:{}", saved.revision),
            effective.version,
            payload,
            saved.created_at_ms
        ],
    )?;
    Ok(effective)
}

pub(super) fn annotate_revision(
    agent_id: &str,
    saved: &SavedGuardrails,
    evaluation: &mut RiskEvaluation,
) {
    evaluation.signals.push(SignalContribution {
        feature: "guardrails_revision".into(),
        observed_summary: format!("agent={agent_id}; revision={}", saved.revision),
        baseline_summary: format!("settings_hash={}", saved.settings_hash),
        contribution: 0,
        support: "Versioned Risk Guard overrides; static policy rollout is tracked separately"
            .into(),
    });
}

pub(super) fn record_revision(
    conn: &Connection,
    epoch_id: &str,
    agent_id: &str,
    saved: &SavedGuardrails,
    evaluation: &RiskEvaluation,
) -> Result<()> {
    conn.execute(
        "INSERT INTO decision_guardrail_revisions (epoch_id, request_id, agent_id, revision)
         VALUES (?1, ?2, ?3, ?4)",
        params![epoch_id, evaluation.request_id, agent_id, saved.revision],
    )?;
    Ok(())
}

pub(super) fn validate_new_binding(
    conn: &Connection,
    agent_id: &str,
    epoch: &EpochRecord,
) -> Result<()> {
    if let Some(saved) = query_saved(conn, agent_id)? {
        if saved.settings.task_profile != epoch.task_profile
            || saved.settings.mode != epoch.mode
            || saved.profile_hash != epoch.baseline_hash
        {
            return Err(RiskGuardError::PermissionDenied(
                "new run must use the saved agent task profile and mode".into(),
            ));
        }
        if let Some(desired) = saved.settings.filesystem {
            let raw: Option<String> = conn
                .query_row(
                    "SELECT policy_yaml FROM policy_snapshots WHERE sandbox_id = ?1
                 ORDER BY captured_at_ms DESC, id DESC LIMIT 1",
                    params![epoch.sandbox_id],
                    |row| row.get(0),
                )
                .optional()?;
            let actual: Option<FilesystemPolicy> = raw
                .map(|raw| parsed_policy(&raw))
                .transpose()?
                .and_then(|policy| policy.filesystem_policy);
            if !actual
                .as_ref()
                .is_some_and(|actual| filesystem_matches(&desired, actual))
            {
                return Err(RiskGuardError::PermissionDenied(
                    "new sandbox policy must match saved filesystem guardrails; use the next-run policy export".into(),
                ));
            }
        }
    }
    Ok(())
}
