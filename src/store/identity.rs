use super::*;
use crate::detector::InteractionRiskDetector;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Serialize)]
pub(super) struct AgentIdentity {
    pub agent_id: String,
    pub run_id: String,
    pub context_id: String,
    pub agent_revision: String,
}

fn identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(RiskGuardError::InvalidArgument(format!(
            "{field} must contain 1..128 ASCII letters, digits, '.', '_' or '-'"
        )));
    }
    Ok(())
}

/// Who attached a sandbox to its workload, from the audit trail. `null` for sandboxes bound
/// explicitly with `run-bind`, which records no creating principal.
fn binding_info(tx: &Transaction, sandbox_id: &str) -> rusqlite::Result<Value> {
    let row: Option<(String, String, String, String, String)> = tx
        .query_row(
            "SELECT workspace, principal_kind, principal_provider, principal_subject, source FROM workload_binding_audit
             WHERE sandbox_id = ?1 AND outcome = 'bound' ORDER BY audit_id DESC LIMIT 1",
            params![sandbox_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    Ok(match row {
        Some((workspace, kind, provider, subject, source)) => json!({
            "workspace": workspace, "principal_kind": kind, "principal_provider": provider,
            "principal_subject": subject, "source": source
        }),
        None => Value::Null,
    })
}

impl SqliteRiskStore {
    /// Change the name people see for an agent. Decisions are keyed on the agent_id, which does not change.
    pub fn rename_agent(&self, agent_id: &str, display_name: &str) -> Result<()> {
        if display_name.trim().is_empty()
            || display_name.len() > 256
            || display_name.chars().any(char::is_control)
        {
            return Err(RiskGuardError::InvalidArgument(
                "display_name must contain 1..256 bytes without control characters".into(),
            ));
        }
        let changed = self.lock_conn()?.execute(
            "UPDATE agents SET display_name = ?2 WHERE agent_id = ?1",
            params![agent_id, display_name],
        )?;
        if changed == 0 {
            return Err(RiskGuardError::InvalidArgument(format!(
                "agent '{agent_id}' not found"
            )));
        }
        Ok(())
    }

    pub fn register_agent(&self, agent_id: &str, display_name: &str) -> Result<()> {
        identifier(agent_id, "agent_id")?;
        if display_name.trim().is_empty() || display_name.len() > 256 {
            return Err(RiskGuardError::InvalidArgument(
                "display_name must contain 1..256 bytes".into(),
            ));
        }
        self.lock_conn()?.execute(
            "INSERT INTO agents (agent_id, display_name, created_at_ms) VALUES (?1, ?2, ?3)",
            params![agent_id, display_name, current_time_ms()],
        )?;
        Ok(())
    }

    pub fn record_binding_audit(&self, entry: &BindingAudit) -> Result<()> {
        self.lock_conn()?.execute(
            "INSERT INTO workload_binding_audit
             (sandbox_id, workspace, principal_kind, principal_provider, principal_subject, agent_id, source, outcome, reason, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                entry.sandbox_id,
                entry.workspace,
                entry.principal_kind,
                entry.principal_provider,
                entry.principal_subject,
                entry.agent_id,
                entry.source,
                if entry.bound { "bound" } else { "refused" },
                entry.reason,
                current_time_ms()
            ],
        )?;
        Ok(())
    }

    /// Binding attempts for one sandbox, oldest first, as `(source, outcome, agent_id, principal)`.
    pub fn list_binding_audit(&self, sandbox_id: &str) -> Result<Vec<BindingAudit>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT sandbox_id, workspace, principal_kind, principal_provider, principal_subject, agent_id, source, outcome, reason
             FROM workload_binding_audit WHERE sandbox_id = ?1 ORDER BY audit_id",
        )?;
        let rows = stmt.query_map(params![sandbox_id], |row| {
            let source: String = row.get(6)?;
            let outcome: String = row.get(7)?;
            Ok(BindingAudit {
                sandbox_id: row.get(0)?,
                workspace: row.get(1)?,
                principal_kind: row.get(2)?,
                principal_provider: row.get(3)?,
                principal_subject: row.get(4)?,
                agent_id: row.get(5)?,
                source: if source == "principal" {
                    "principal"
                } else {
                    "label"
                },
                bound: outcome == "bound",
                reason: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Register a workload that can only be bound from sandboxes created in `workspace`.
    pub fn register_agent_in_workspace(
        &self,
        agent_id: &str,
        display_name: &str,
        workspace: &str,
    ) -> Result<()> {
        identifier(agent_id, "agent_id")?;
        if workspace.trim().is_empty()
            || workspace.len() > 128
            || workspace.chars().any(char::is_control)
        {
            return Err(RiskGuardError::InvalidArgument(
                "workspace must contain 1..128 bytes without control characters".into(),
            ));
        }
        self.register_agent(agent_id, display_name)?;
        self.lock_conn()?.execute(
            "INSERT INTO agent_workspaces (agent_id, workspace) VALUES (?1, ?2)",
            params![agent_id, workspace.trim()],
        )?;
        Ok(())
    }

    pub fn create_agent_run(
        &self,
        agent_id: &str,
        run_id: &str,
        revision: &str,
        task_profile: &str,
        mode: EnforcementMode,
    ) -> Result<()> {
        identifier(run_id, "run_id")?;
        identifier(revision, "agent_revision")?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let saved = super::guardrails::query_saved(&tx, agent_id)?;
        let profile_reference = if let Some(saved) = &saved {
            if (task_profile != saved.settings.task_profile && task_profile != saved.profile_hash)
                || mode != saved.settings.mode
            {
                return Err(RiskGuardError::InvalidArgument(
                    "new runs must select the agent's saved task profile and mode".into(),
                ));
            }
            saved.profile_hash.as_str()
        } else {
            task_profile
        };
        let profile = query_baseline_by_name_or_hash(&tx, profile_reference, profile_reference)?
            .ok_or_else(|| {
                RiskGuardError::InvalidArgument(
                    "baseline must be imported before creating a run".into(),
                )
            })?;
        let baseline_hash = crate::detector::compute_baseline_hash(&profile);
        let detector = InteractionRiskDetector::new_default();
        let configuration_id = detector.configuration_id();
        let context_key = serde_json::to_vec(&(
            agent_id,
            revision,
            &profile.task_profile,
            &baseline_hash,
            &configuration_id,
            mode.as_str(),
        ))?;
        let context_id = format!("ctx-{}", hex::encode(Sha256::digest(context_key)));
        let now = current_time_ms();
        tx.execute(
            "INSERT INTO scoring_contexts
             (context_id, agent_id, agent_revision, task_profile, baseline_hash,
              detector_version, configuration_id, mode, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(context_id) DO NOTHING",
            params![
                context_id,
                agent_id,
                revision,
                profile.task_profile,
                baseline_hash,
                detector.detector_version(),
                configuration_id,
                mode.as_str(),
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO agent_runs (run_id, context_id, created_at_ms) VALUES (?1, ?2, ?3)",
            params![run_id, context_id, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Bind only a pristine active epoch. Existing evidence is never reattributed.
    pub fn bind_agent_run(&self, run_id: &str, sandbox_id: &str, gateway_id: &str) -> Result<()> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch = query_active_epoch(&tx, sandbox_id)?
            .ok_or_else(|| RiskGuardError::InvalidArgument("sandbox has no active epoch".into()))?;
        if epoch.gateway_id != gateway_id {
            return Err(RiskGuardError::PermissionDenied(
                "binding gateway does not match epoch".into(),
            ));
        }
        let learning_started: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM adaptive_sessions WHERE run_id = ?1)",
            params![run_id],
            |row| row.get(0),
        )?;
        if learning_started {
            return Err(RiskGuardError::PermissionDenied(
                "learning runs freeze their sandbox binding; use a fresh run for another sandbox"
                    .into(),
            ));
        }
        let context: Option<(String, String, String, String)> = tx
            .query_row(
                "SELECT c.task_profile, c.baseline_hash, c.mode, c.agent_id FROM agent_runs r
             JOIN scoring_contexts c ON c.context_id = r.context_id
             WHERE r.run_id = ?1 AND r.ended_at_ms IS NULL",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((profile, hash, mode, agent_id)) = context else {
            return Err(RiskGuardError::InvalidArgument(
                "run is missing or ended".into(),
            ));
        };
        if profile != epoch.task_profile
            || hash != epoch.baseline_hash
            || mode != epoch.mode.as_str()
        {
            return Err(RiskGuardError::PermissionDenied(
                "run task profile, pinned baseline and mode must match the epoch".into(),
            ));
        }
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM decisions WHERE epoch_id = ?1",
            params![epoch.epoch_id],
            |row| row.get(0),
        )?;
        if count != 0 {
            return Err(RiskGuardError::PermissionDenied(
                "cannot bind an epoch with existing decisions; create a new epoch".into(),
            ));
        }
        super::guardrails::validate_new_binding(&tx, &agent_id, &epoch)?;
        let existing_gateway: Option<String> = tx
            .query_row(
                "SELECT gateway_id FROM identity_required_sandboxes WHERE sandbox_id = ?1",
                params![sandbox_id],
                |row| row.get(0),
            )
            .optional()?;
        if existing_gateway
            .as_deref()
            .is_some_and(|gateway| gateway != gateway_id)
        {
            return Err(RiskGuardError::PermissionDenied(
                "sandbox is owned by another gateway".into(),
            ));
        }
        tx.execute(
            "INSERT INTO epoch_bindings (epoch_id, run_id, created_at_ms) VALUES (?1, ?2, ?3)",
            params![epoch.epoch_id, run_id, current_time_ms()],
        )?;
        tx.execute(
            "INSERT INTO identity_required_sandboxes (sandbox_id, gateway_id) VALUES (?1, ?2)
             ON CONFLICT(sandbox_id) DO NOTHING",
            params![sandbox_id, gateway_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn end_agent_run(&self, run_id: &str) -> Result<()> {
        let now = current_time_ms();
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE agent_runs SET ended_at_ms = ?2 WHERE run_id = ?1 AND ended_at_ms IS NULL",
            params![run_id, now],
        )?;
        if changed != 1 {
            return Err(RiskGuardError::InvalidArgument(
                "run is missing or already ended".into(),
            ));
        }
        super::adaptive::finalize_run_captures(&tx, run_id, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Attach a freshly created sandbox to a workload ID.
    ///
    /// The caller has already authorized the creating principal. This still refuses
    /// to (a) invent a workload ID unless `auto_register` is set, and (b) attach
    /// the sandbox to an existing run owned by a different workload or revision, so a
    /// creator cannot pollute another agent's windows or learning evidence.
    pub fn auto_bind_sandbox_epoch(&self, binding: &SandboxBinding) -> Result<()> {
        let SandboxBinding {
            sandbox_id,
            gateway_id,
            agent_id,
            agent_revision,
            run_id,
            auto_register,
            display_name,
            workspace,
            claim_workspace,
        } = *binding;
        identifier(agent_id, "agent_id")?;
        identifier(agent_revision, "agent_revision")?;
        identifier(run_id, "run_id")?;
        let default_run_prefix = format!("run-{sandbox_id}");
        let mut effective_run_id = run_id.to_string();
        let (epoch, run_exists) = {
            let mut conn = self.lock_conn()?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let epoch = query_active_epoch(&tx, sandbox_id)?.ok_or_else(|| {
                RiskGuardError::InvalidArgument("sandbox has no active epoch".into())
            })?;
            let existing_binding: Option<String> = tx
                .query_row(
                    "SELECT run_id FROM epoch_bindings WHERE epoch_id = ?1",
                    params![epoch.epoch_id],
                    |row| row.get(0),
                )
                .optional()?;
            if existing_binding.as_deref() == Some(run_id) {
                return Ok(());
            }
            let registered: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
                params![agent_id],
                |row| row.get(0),
            )?;
            if !registered && !auto_register {
                return Err(RiskGuardError::PermissionDenied(format!(
                    "workload '{agent_id}' is not registered; run agent-register or start serve with --auto-register-agents"
                )));
            }
            let scoped_workspace: Option<String> = tx
                .query_row(
                    "SELECT workspace FROM agent_workspaces WHERE agent_id = ?1",
                    params![agent_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(owner_workspace) = &scoped_workspace
                && owner_workspace != workspace
            {
                return Err(RiskGuardError::PermissionDenied(format!(
                    "workload '{agent_id}' belongs to workspace '{owner_workspace}', not '{workspace}'"
                )));
            }
            // If the run_id is the default `run-{sandbox_id}` and a previous run with that ID already ended (or froze its
            // capture session when the earlier sandbox was deleted), advance to the next unused generation `run-{sandbox_id}-{n}`.
            if effective_run_id == default_run_prefix {
                for generation in 1..=10_000_u32 {
                    let candidate = if generation == 1 {
                        default_run_prefix.clone()
                    } else {
                        format!("{default_run_prefix}-{generation}")
                    };
                    let state: Option<(Option<i64>, bool)> = tx
                        .query_row(
                            "SELECT r.ended_at_ms, EXISTS(SELECT 1 FROM adaptive_sessions s WHERE s.run_id = r.run_id)
                             FROM agent_runs r WHERE r.run_id = ?1",
                            params![candidate],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    match state {
                        None => {
                            effective_run_id = candidate;
                            break;
                        }
                        Some((None, false)) => {
                            effective_run_id = candidate;
                            break;
                        }
                        Some(_) => continue,
                    }
                }
            }
            let run_owner: Option<(String, String)> = tx
                .query_row(
                    "SELECT c.agent_id, c.agent_revision FROM agent_runs r
                     JOIN scoring_contexts c ON c.context_id = r.context_id
                     WHERE r.run_id = ?1",
                    params![effective_run_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((owner_agent, owner_revision)) = &run_owner
                && (owner_agent != agent_id || owner_revision != agent_revision)
            {
                return Err(RiskGuardError::PermissionDenied(
                    "run belongs to a different workload or revision".into(),
                ));
            }
            if !registered {
                tx.execute(
                    "INSERT INTO agents (agent_id, display_name, created_at_ms) VALUES (?1, ?2, ?3)",
                    params![agent_id, display_name.unwrap_or(agent_id), current_time_ms()],
                )?;
            } else if let Some(name) = display_name {
                // A workload that was auto-registered shows its ID as its name. Give it the readable name once, but
                // never replace a name an operator chose.
                tx.execute(
                    "UPDATE agents SET display_name = ?2 WHERE agent_id = ?1 AND display_name = agent_id",
                    params![agent_id, name],
                )?;
            }
            if scoped_workspace.is_none() && (!registered || claim_workspace) {
                tx.execute(
                    "INSERT OR IGNORE INTO agent_workspaces (agent_id, workspace) VALUES (?1, ?2)",
                    params![agent_id, workspace],
                )?;
            }
            tx.commit()?;
            (epoch, run_owner.is_some())
        };
        if !run_exists {
            self.create_agent_run(
                agent_id,
                &effective_run_id,
                agent_revision,
                &epoch.task_profile,
                epoch.mode,
            )?;
        }
        self.bind_agent_run(&effective_run_id, sandbox_id, gateway_id)?;
        Ok(())
    }

    pub fn close_sandbox_lifecycle(&self, sandbox_id: &str) -> Result<Option<String>> {
        let Some(epoch) = self.get_active_epoch(sandbox_id)? else {
            return Ok(None);
        };
        let bound_run: Option<String> = {
            let conn = self.lock_conn()?;
            conn.query_row(
                "SELECT run_id FROM epoch_bindings WHERE epoch_id = ?1",
                params![epoch.epoch_id],
                |row| row.get(0),
            )
            .optional()?
        };
        self.terminate_epoch(&epoch.epoch_id)?;
        if let Some(ref run_id) = bound_run {
            let should_end_run: bool = {
                let conn = self.lock_conn()?;
                let active_epochs: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
                     WHERE b.run_id = ?1 AND e.active != 0",
                    params![run_id],
                    |row| row.get(0),
                )?;
                let unended: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE run_id = ?1 AND ended_at_ms IS NULL)",
                    params![run_id],
                    |row| row.get(0),
                )?;
                active_epochs == 0 && unended
            };
            if should_end_run {
                let _ = self.end_agent_run(run_id);
            }
        }
        Ok(bound_run)
    }

    pub fn operator_agent_detail(&self, agent_id: &str, now_ms: i64) -> Result<Option<Value>> {
        let mut conn = self.lock_read_conn()?;
        let tx = conn.transaction()?;
        let agent = tx.query_row(
            "SELECT agent_id, display_name, created_at_ms FROM agents WHERE agent_id = ?1",
            params![agent_id], |row| Ok(json!({
                "agent_id": row.get::<_, String>(0)?, "display_name": row.get::<_, String>(1)?,
                "created_at_ms": row.get::<_, i64>(2)?
            })),
        ).optional()?;
        let Some(agent) = agent else {
            return Ok(None);
        };
        let mut contexts = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT context_id, agent_revision, task_profile, baseline_hash, detector_version, mode
                 FROM scoring_contexts WHERE agent_id = ?1 ORDER BY created_at_ms, context_id LIMIT 100",
            )?;
            let rows = stmt.query_map(params![agent_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?;
            for row in rows {
                let (id, revision, task, baseline, detector, mode) = row?;
                let owner = StateOwner {
                    id: &id,
                    agent: true,
                };
                let baseline_profile = query_baseline_by_name_or_hash(&tx, &task, &baseline)?;
                contexts.push(json!({
                    "context_id": id, "agent_id": agent_id, "agent_revision": revision,
                    "task_profile": task, "baseline_hash": baseline, "detector_version": detector,
                    "mode": mode, "baseline": baseline_profile,
                    "active_restrictions": active_restrictions(&tx, owner, now_ms)?,
                    "window": compute_window_snapshot(&tx, owner, now_ms)?
                }));
            }
        }
        let mut runs = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT r.run_id, c.agent_revision, c.task_profile, c.context_id, r.created_at_ms, r.ended_at_ms
                 FROM agent_runs r JOIN scoring_contexts c ON c.context_id = r.context_id
                 WHERE c.agent_id = ?1 ORDER BY r.created_at_ms DESC, r.rowid DESC LIMIT 100",
            )?;
            let rows = stmt.query_map(params![agent_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            })?;
            for row in rows {
                let (id, revision, task, context, created, ended) = row?;
                let mut sandboxes = tx.prepare(
                    "SELECT e.sandbox_id, e.epoch_id, e.gateway_id, e.active, e.mode, e.task_profile, e.created_at_ms, e.active_policy_hash,
                            MAX(e.created_at_ms, COALESCE((SELECT MAX(d.created_at_ms) FROM decisions d WHERE d.epoch_id = e.epoch_id), 0))
                     FROM epoch_bindings b JOIN epochs e ON e.epoch_id = b.epoch_id
                     WHERE b.run_id = ?1 ORDER BY b.created_at_ms DESC, b.rowid DESC LIMIT 100",
                )?;
                let sandboxes = sandboxes.query_map(params![id], |row| Ok(json!({
                    "binding": binding_info(&tx, &row.get::<_, String>(0)?)?,
                    "sandbox_id": row.get::<_, String>(0)?, "epoch_id": row.get::<_, String>(1)?,
                    "gateway_id": row.get::<_, String>(2)?, "active": row.get::<_, bool>(3)?,
                    "mode": row.get::<_, String>(4)?, "task_profile": row.get::<_, String>(5)?,
                    "created_at_ms": row.get::<_, i64>(6)?, "active_policy_hash": row.get::<_, Option<String>>(7)?,
                    "last_activity_at_ms": row.get::<_, i64>(8)?,
                    // The name SPIRE assigned this sandbox. Assigned, not presented: Risk Guard does not receive the certificate.
                    "spiffe_id": self.sandbox_spiffe_id(&row.get::<_, String>(0)?, row.get::<_, i64>(6)?),
                    // closed: a delete event ended it. Otherwise how recently it was seen; "not_seen_recently" means presumed gone.
                    "lifecycle": if row.get::<_, bool>(3)? { super::lifecycle_state(row.get::<_, i64>(8)?, now_ms) } else { "closed" }
                })))?.collect::<std::result::Result<Vec<_>, _>>()?;
                let run_lifecycle = if ended.is_some() {
                    "ended"
                } else if sandboxes.is_empty()
                    || sandboxes.iter().any(|s| {
                        matches!(s["lifecycle"].as_str(), Some("recently_active" | "idle"))
                    })
                {
                    "open"
                } else {
                    "presumed_gone"
                };
                runs.push(json!({
                    "run_id": id, "agent_revision": revision, "task_profile": task,
                    "context_id": context, "created_at_ms": created, "ended_at_ms": ended, "sandboxes": sandboxes,
                    "lifecycle": run_lifecycle
                }));
            }
        }
        let decisions = {
            let mut stmt = tx.prepare(
                "WITH recent_ids AS (
                     SELECT d.rowid AS rid
                     FROM decision_identity i JOIN decisions d USING(epoch_id, request_id)
                     JOIN agent_runs r ON r.run_id = i.run_id
                     JOIN scoring_contexts c ON c.context_id = r.context_id
                     WHERE c.agent_id = ?1
                     ORDER BY d.created_at_ms DESC, d.rowid DESC LIMIT 100
                 ),
                 risky_ids AS (
                     SELECT d.rowid AS rid
                     FROM decision_identity i JOIN decisions d USING(epoch_id, request_id)
                     JOIN agent_runs r ON r.run_id = i.run_id
                     JOIN scoring_contexts c ON c.context_id = r.context_id
                     WHERE c.agent_id = ?1 AND (d.outcome != 'allow' OR d.risk_score >= 20)
                     ORDER BY d.created_at_ms DESC, d.rowid DESC LIMIT 40
                 ),
                 chosen AS (
                     SELECT rid FROM recent_ids
                     UNION
                     SELECT rid FROM risky_ids
                 )
                 SELECT d.normalized_request_json, d.evaluation_json, i.run_id, c.context_id, c.agent_revision,
                        g.revision, s.settings_json, s.settings_hash
                 FROM chosen ch
                 JOIN decisions d ON d.rowid = ch.rid
                 JOIN decision_identity i USING(epoch_id, request_id)
                 JOIN agent_runs r ON r.run_id = i.run_id
                 JOIN scoring_contexts c ON c.context_id = r.context_id
                 LEFT JOIN decision_guardrail_revisions g
                   ON g.epoch_id = d.epoch_id AND g.request_id = d.request_id
                 LEFT JOIN agent_guardrail_revisions s
                   ON s.agent_id = g.agent_id AND s.revision = g.revision
                 ORDER BY d.created_at_ms DESC, d.rowid DESC",
            )?;
            let rows = stmt.query_map(params![agent_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })?;
            let mut decisions = Vec::new();
            for row in rows {
                let (
                    request,
                    eval,
                    run,
                    context,
                    revision,
                    settings_revision,
                    settings_json,
                    settings_hash,
                ) = row?;
                let guardrails = match (settings_revision, settings_json, settings_hash) {
                    (Some(revision), Some(payload), Some(hash)) => {
                        if hex::encode(Sha256::digest(payload.as_bytes())) != hash {
                            return Err(RiskGuardError::Storage(
                                "decision guardrail settings hash mismatch".into(),
                            ));
                        }
                        let settings: crate::guardrails::AgentGuardrails =
                            serde_json::from_str(&payload).map_err(|error| {
                                RiskGuardError::Storage(format!(
                                    "invalid decision guardrails: {error}"
                                ))
                            })?;
                        Some(json!({
                            "revision": revision,
                            "observe_threshold": settings.observe_threshold,
                            "enforce_threshold": settings.enforce_threshold,
                            "settings_hash": hash,
                        }))
                    }
                    (None, None, None) => None,
                    _ => {
                        return Err(RiskGuardError::Storage(
                            "incomplete decision guardrail revision".into(),
                        ));
                    }
                };
                let evaluation: RiskEvaluation = serde_json::from_str(&eval)?;
                let transport = super::adaptive::decision_transport(
                    &tx,
                    &evaluation.epoch_id,
                    &evaluation.request_id,
                )?;
                let adaptive = super::adaptive::decision_assessments(
                    &tx,
                    &evaluation.epoch_id,
                    &evaluation.request_id,
                )?;
                decisions.push(json!({
                    "request": serde_json::from_str::<NormalizedRequest>(&request)?,
                    "evaluation": evaluation,
                    "identity": AgentIdentity { agent_id: agent_id.into(), run_id: run, context_id: context, agent_revision: revision },
                    "guardrails": guardrails,
                    "adaptive": adaptive,
                    "upstream_outcome": null, "transport_provenance": transport
                }));
            }
            decisions
        };
        let recommendations = {
            let mut stmt = tx.prepare(
                "SELECT x.payload_json, r.run_id, c.context_id, c.agent_revision
                 FROM recommendations x JOIN epoch_bindings b ON b.epoch_id = x.epoch_id
                 JOIN agent_runs r ON r.run_id = b.run_id
                 JOIN scoring_contexts c ON c.context_id = r.context_id
                 WHERE c.agent_id = ?1 ORDER BY x.created_at_ms DESC, x.recommendation_id DESC LIMIT 20",
            )?;
            let rows = stmt.query_map(params![agent_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            let mut records = Vec::new();
            for row in rows {
                let (payload, run_id, context_id, agent_revision) = row?;
                records.push(json!({
                    "identity": AgentIdentity { agent_id: agent_id.into(), run_id, context_id, agent_revision },
                    "recommendation": serde_json::from_str::<HardeningCandidate>(&payload)?
                }));
            }
            records
        };
        let recorded_coverage_gaps = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT g.id, e.sandbox_id, e.epoch_id, g.gap_reason,
                    MAX(g.start_ms, e.created_at_ms),
                    MIN(g.end_ms, COALESCE(
                        (SELECT MIN(next.created_at_ms) FROM epochs next
                         WHERE next.sandbox_id = e.sandbox_id AND next.created_at_ms > e.created_at_ms),
                        g.end_ms)),
                    g.start_ms, g.end_ms
                 FROM coverage_intervals g JOIN epochs e ON e.sandbox_id = g.sandbox_id
                 JOIN epoch_bindings b ON b.epoch_id = e.epoch_id
                 JOIN agent_runs r ON r.run_id = b.run_id JOIN scoring_contexts c USING(context_id)
                 WHERE c.agent_id = ?1 AND g.end_ms >= e.created_at_ms
                 AND NOT EXISTS(SELECT 1 FROM epochs next
                     WHERE next.sandbox_id = e.sandbox_id AND next.created_at_ms > e.created_at_ms
                     AND next.created_at_ms <= g.start_ms)
                 ORDER BY g.start_ms DESC, g.id DESC LIMIT 100",
            )?;
            stmt.query_map(params![agent_id], |row| {
                Ok(json!({
                    "sandbox_id": row.get::<_, String>(1)?, "epoch_id": row.get::<_, String>(2)?,
                    "reason": row.get::<_, String>(3)?, "start_ms": row.get::<_, i64>(4)?,
                    "end_ms": row.get::<_, i64>(5)?,
                    "source_start_ms": row.get::<_, i64>(6)?,
                    "source_end_ms": row.get::<_, i64>(7)?,
                    "attribution": "sandbox_interval_correlation_only"
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let policy_snapshots = {
            let mut stmt = tx.prepare(
                "SELECT p.id, p.sandbox_id, p.policy_hash, p.policy_yaml, p.source, p.captured_at_ms, r.run_id
                 FROM policy_snapshots p
                 JOIN epochs e ON e.sandbox_id = p.sandbox_id
                 JOIN epoch_bindings b ON b.epoch_id = e.epoch_id
                 JOIN agent_runs r ON r.run_id = b.run_id
                 JOIN scoring_contexts c ON c.context_id = r.context_id
                 WHERE c.agent_id = ?1
                 ORDER BY p.captured_at_ms DESC, p.id DESC LIMIT 50",
            )?;
            let rows = stmt.query_map(params![agent_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?;
            let mut snaps = Vec::new();
            for row in rows {
                let (id, sandbox_id, policy_hash, policy_yaml, source, captured_at_ms, run_id) =
                    row?;
                let parsed = parsed_policy_cached(&policy_hash, &policy_yaml);
                snaps.push(json!({
                    "id": id,
                    "sandbox_id": sandbox_id,
                    "run_id": run_id,
                    "policy_hash": policy_hash,
                    "source": source,
                    "captured_at_ms": captured_at_ms,
                    "policy_yaml": policy_yaml,
                    "parsed_policy": parsed
                }));
            }
            snaps
        };
        let guardrails = super::guardrails::query_view(&tx, agent_id, now_ms)?;
        let mut sandbox_ids = Vec::new();
        for run in &runs {
            if let Some(sbs) = run["sandboxes"].as_array() {
                for sb in sbs {
                    if let Some(sb_id) = sb["sandbox_id"].as_str()
                        && !sandbox_ids.iter().any(|s| s == sb_id)
                    {
                        sandbox_ids.push(sb_id.to_string());
                    }
                }
            }
        }
        let quarantine = tx
            .query_row(
                "SELECT agent_id, reason, operator, quarantined_at_ms, expires_at_ms
                 FROM workload_quarantine
                 WHERE agent_id = ?1 AND (expires_at_ms IS NULL OR expires_at_ms > ?2)
                 ORDER BY quarantined_at_ms DESC LIMIT 1",
                params![agent_id, now_ms],
                |row| {
                    Ok(json!({
                        "agent_id": row.get::<_, String>(0)?,
                        "reason": row.get::<_, String>(1)?,
                        "operator": row.get::<_, String>(2)?,
                        "quarantined_at_ms": row.get::<_, i64>(3)?,
                        "expires_at_ms": row.get::<_, Option<i64>>(4)?,
                    }))
                },
            )
            .optional()?;
        let primary_sandbox = sandbox_ids.first().map_or("", String::as_str);
        let ctx_features =
            self.load_siem_context_cached(&tx, primary_sandbox, Some(agent_id), now_ms)?;
        let mut sandbox_denials = Vec::new();
        let mut total_os_1h = 0_u32;
        let mut total_os_5m = 0_u32;
        let mut total_os_wb = 0_u32;
        {
            let mut stmt = tx.prepare(
                "SELECT COALESCE(sf.sandbox_id, sf.subject_id) AS sbx,
                        MAX(CASE WHEN sf.name = 'openshell_denials_1h' THEN sf.value ELSE 0 END) AS d1h,
                        MAX(CASE WHEN sf.name = 'openshell_denials_5m' THEN sf.value ELSE 0 END) AS d5m,
                        MAX(CASE WHEN sf.name = 'openshell_would_block_5m' THEN sf.value ELSE 0 END) AS wb5m,
                        MAX(sf.generated_at_ms) AS gen_ms
                 FROM siem_features sf
                 WHERE sf.agent_id = ?1 AND sf.expires_at_ms > ?2
                   AND sf.name IN ('openshell_denials_1h', 'openshell_denials_5m', 'openshell_would_block_5m')
                 GROUP BY COALESCE(sf.sandbox_id, sf.subject_id)
                 ORDER BY d1h DESC, d5m DESC",
            )?;
            let rows = stmt.query_map(params![agent_id, now_ms], |row| {
                let sbx: String = row.get(0)?;
                let d1h = u32::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
                let d5m = u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0);
                let wb5m = u32::try_from(row.get::<_, i64>(3)?).unwrap_or(0);
                let gen_ms: i64 = row.get(4)?;
                Ok((sbx, d1h, d5m, wb5m, gen_ms))
            })?;
            for r in rows {
                let (sbx, d1h, d5m, wb5m, gen_ms) = r?;
                total_os_1h = total_os_1h.saturating_add(d1h);
                total_os_5m = total_os_5m.saturating_add(d5m);
                total_os_wb = total_os_wb.saturating_add(wb5m);
                if d1h > 0 || d5m > 0 || wb5m > 0 {
                    sandbox_denials.push(json!({
                        "sandbox_id": sbx,
                        "openshell_denials_1h": d1h,
                        "openshell_denials_5m": d5m,
                        "openshell_would_block_5m": wb5m,
                        "generated_at_ms": gen_ms
                    }));
                }
            }
        }
        let siem_features = if ctx_features.is_empty() && sandbox_denials.is_empty() {
            None
        } else {
            let mut map = std::collections::BTreeMap::new();
            let mut age_ms = 0_i64;
            for item in ctx_features.as_slice() {
                let current = map.entry(item.name.clone()).or_insert(0_u32);
                *current = (*current).max(item.value);
                age_ms = age_ms.max(item.age_ms);
            }
            if total_os_1h > 0 {
                let e = map.entry("openshell_denials_1h".to_string()).or_insert(0);
                *e = (*e).max(total_os_1h);
            }
            if total_os_5m > 0 {
                let e = map.entry("openshell_denials_5m".to_string()).or_insert(0);
                *e = (*e).max(total_os_5m);
            }
            if total_os_wb > 0 {
                let e = map.entry("openshell_would_block_5m".to_string()).or_insert(0);
                *e = (*e).max(total_os_wb);
            }
            Some(json!({
                "features": map,
                "items": ctx_features.as_slice(),
                "sandbox_denials": sandbox_denials,
                "age_ms": age_ms,
                "stale": false
            }))
        };
        let supervisor_silence = {
            let mut events = Vec::new();
            let mut stmt = tx.prepare(
                "SELECT s.sandbox_id, s.destination, s.silent_ms, s.mode, s.at_ms
                 FROM supervisor_silence_events s
                 WHERE EXISTS (
                     SELECT 1 FROM epochs e
                     JOIN epoch_bindings b ON b.epoch_id = e.epoch_id
                     JOIN agent_runs r ON r.run_id = b.run_id
                     JOIN scoring_contexts c ON c.context_id = r.context_id
                     WHERE c.agent_id = ?1 AND e.sandbox_id = s.sandbox_id
                 )
                 ORDER BY s.at_ms DESC LIMIT 20",
            )?;
            let rows = stmt.query_map(params![agent_id], |row| {
                Ok(json!({
                    "sandbox_id": row.get::<_, String>(0)?,
                    "destination": row.get::<_, String>(1)?,
                    "silent_for_ms": row.get::<_, i64>(2)?,
                    "rule_mode": row.get::<_, String>(3)?,
                    "at_ms": row.get::<_, i64>(4)?,
                }))
            })?;
            for row in rows {
                events.push(row?);
            }
            events
        };
        let two_person_required: bool = tx
            .query_row(
                "SELECT value FROM service_settings WHERE name = 'two_person_required'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_some_and(|v| v == "1");
        tx.commit()?;
        Ok(Some(json!({
            "agent": agent, "contexts": contexts, "runs": runs, "decisions": decisions,
            "recommendations": recommendations, "recorded_coverage_gaps": recorded_coverage_gaps,
            "policy_snapshots": policy_snapshots,
            "guardrails": guardrails,
            "quarantine": quarantine,
            "siem_features": siem_features,
            "supervisor_silence": supervisor_silence,
            "two_person_required": two_person_required,
            "limits": {"contexts": 100, "runs": 100, "sandboxes_per_run": 100, "decisions": 100,
                "recommendations": 20, "coverage_gaps": 100, "policy_snapshots": 50}
        })))
    }
}

fn parsed_policy_cached(policy_hash: &str, policy_yaml: &str) -> Option<Value> {
    use std::collections::HashMap;
    use std::sync::{OnceLock, RwLock};
    static CACHE: OnceLock<RwLock<HashMap<String, Option<Value>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if !policy_hash.is_empty()
        && let Ok(guard) = cache.read()
        && let Some(cached) = guard.get(policy_hash)
    {
        return cached.clone();
    }
    let parsed = openshell_policy_schema::parse_policy(policy_yaml)
        .ok()
        .and_then(|doc| serde_json::to_value(doc).ok());
    if !policy_hash.is_empty()
        && let Ok(mut guard) = cache.write()
    {
        if guard.len() >= 256 {
            guard.clear();
        }
        guard.insert(policy_hash.to_string(), parsed.clone());
    }
    parsed
}

pub(super) fn resolve_identity(
    conn: &Connection,
    epoch: &EpochRecord,
) -> Result<Option<AgentIdentity>> {
    conn.query_row(
        "SELECT c.agent_id, r.run_id, c.context_id, c.agent_revision
         FROM epoch_bindings b JOIN agent_runs r ON r.run_id = b.run_id
         JOIN scoring_contexts c ON c.context_id = r.context_id WHERE b.epoch_id = ?1",
        params![epoch.epoch_id],
        |row| {
            Ok(AgentIdentity {
                agent_id: row.get(0)?,
                run_id: row.get(1)?,
                context_id: row.get(2)?,
                agent_revision: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub(super) fn agent_inventory(conn: &Connection, now_ms: i64) -> Result<Vec<Value>> {
    // A sandbox whose epoch is not closed but that has produced nothing for this long is presumed gone: its delete event
    // was most likely missed (OpenShell's post-commit hook is fail-open). This is derived from activity on every read, never
    // written, so a sandbox that speaks again counts as open again.
    let not_seen_ms = super::SANDBOX_NOT_SEEN_AFTER_MS;
    let mut stmt = conn.prepare(&format!(
        "SELECT a.agent_id, a.display_name, a.created_at_ms,
          (SELECT COUNT(*) FROM agent_runs r JOIN scoring_contexts c USING(context_id) WHERE c.agent_id = a.agent_id),
          (SELECT COUNT(*) FROM decision_identity i JOIN agent_runs r USING(run_id)
           JOIN scoring_contexts c USING(context_id) WHERE c.agent_id = a.agent_id),
          (SELECT MAX(d.created_at_ms) FROM decision_identity i JOIN decisions d USING(epoch_id,request_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id) WHERE c.agent_id = a.agent_id),
          (SELECT COUNT(*) FROM agent_restrictions x JOIN scoring_contexts c ON c.context_id = x.epoch_id
           WHERE c.agent_id = a.agent_id AND (x.tier = 'strict_epoch' OR x.cooldown_until_ms > ?1)),
          (SELECT COUNT(*) FROM decision_identity i JOIN decisions d USING(epoch_id,request_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
           WHERE c.agent_id = a.agent_id AND d.outcome = 'deny'),
          (SELECT COUNT(*) FROM decision_identity i JOIN decisions d USING(epoch_id,request_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
           WHERE c.agent_id = a.agent_id AND d.outcome = 'allow_with_observation'),
          (SELECT MAX(d.risk_score) FROM decision_identity i JOIN decisions d USING(epoch_id,request_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
           WHERE c.agent_id = a.agent_id),
          (SELECT d.risk_score FROM decision_identity i JOIN decisions d USING(epoch_id,request_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
           WHERE c.agent_id = a.agent_id ORDER BY d.created_at_ms DESC, d.rowid DESC LIMIT 1),
          (SELECT COUNT(DISTINCT e.sandbox_id) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
           WHERE c.agent_id = a.agent_id),
          (SELECT COUNT(*) FROM scoring_contexts c WHERE c.agent_id = a.agent_id),
          (SELECT COUNT(*) FROM recommendations x JOIN epoch_bindings b USING(epoch_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
           WHERE c.agent_id = a.agent_id),
          (SELECT COUNT(DISTINCT e.sandbox_id) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
           WHERE c.agent_id = a.agent_id AND e.active != 0),
          (SELECT COUNT(DISTINCT e.sandbox_id) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
           JOIN agent_runs r USING(run_id) JOIN scoring_contexts c USING(context_id)
           WHERE c.agent_id = a.agent_id AND e.active != 0
             AND MAX(e.created_at_ms, COALESCE((SELECT MAX(d.created_at_ms) FROM decisions d WHERE d.epoch_id = e.epoch_id), 0))
                 > ?1 - {not_seen_ms}),
          EXISTS(SELECT 1 FROM workload_quarantine q WHERE q.agent_id = a.agent_id AND (q.expires_at_ms IS NULL OR q.expires_at_ms > ?1)),
          COALESCE((SELECT SUM(v) FROM (
            SELECT MAX(sf.value) AS v FROM siem_features sf
            WHERE sf.agent_id = a.agent_id AND sf.name = 'openshell_denials_1h' AND sf.expires_at_ms > ?1
            GROUP BY COALESCE(sf.sandbox_id, sf.subject_id)
          )), 0),
          COALESCE((SELECT SUM(v) FROM (
            SELECT MAX(sf.value) AS v FROM siem_features sf
            WHERE sf.agent_id = a.agent_id AND sf.name = 'openshell_denials_5m' AND sf.expires_at_ms > ?1
            GROUP BY COALESCE(sf.sandbox_id, sf.subject_id)
          )), 0),
          COALESCE((SELECT SUM(v) FROM (
            SELECT MAX(sf.value) AS v FROM siem_features sf
            WHERE sf.agent_id = a.agent_id AND sf.name = 'openshell_would_block_5m' AND sf.expires_at_ms > ?1
            GROUP BY COALESCE(sf.sandbox_id, sf.subject_id)
          )), 0)
         FROM agents a
         WHERE a.agent_id NOT LIKE 'epprobe-%' AND a.agent_id NOT LIKE 'auditprobe-%'
         ORDER BY a.agent_id LIMIT 200",
    ))?;
    Ok(stmt.query_map(params![now_ms], |row| Ok(json!({
        "agent_id": row.get::<_, String>(0)?, "display_name": row.get::<_, String>(1)?,
        "created_at_ms": row.get::<_, i64>(2)?, "run_count": row.get::<_, i64>(3)?,
        "decision_count": row.get::<_, i64>(4)?, "last_observed_at_ms": row.get::<_, Option<i64>>(5)?,
        "active_restriction_count": row.get::<_, i64>(6)?,
        "denied_count": row.get::<_, i64>(7)?,
        "observed_alert_count": row.get::<_, i64>(8)?,
        "max_risk_score": row.get::<_, Option<i64>>(9)?,
        "latest_risk_score": row.get::<_, Option<i64>>(10)?,
        "sandbox_count": row.get::<_, i64>(11)?,
        "context_count": row.get::<_, i64>(12)?,
        "recommendation_count": row.get::<_, i64>(13)?,
        // `sandbox_count` is every sandbox ever bound to this workload. `active_sandbox_count` is those whose epoch has not been
        // closed by a delete event. `open_sandbox_count` is the subset of those seen recently; the rest are presumed gone.
        "active_sandbox_count": row.get::<_, i64>(14)?,
        "open_sandbox_count": row.get::<_, i64>(15)?,
        "presumed_gone_sandbox_count": (row.get::<_, i64>(14)? - row.get::<_, i64>(15)?).max(0),
        "quarantined": row.get::<_, bool>(16)?,
        "openshell_denials_1h": row.get::<_, i64>(17)?,
        "openshell_denials_5m": row.get::<_, i64>(18)?,
        "openshell_would_block_5m": row.get::<_, i64>(19)?
    })))?.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub(super) fn active_restrictions(
    conn: &Connection,
    owner: StateOwner<'_>,
    now_ms: i64,
) -> Result<Vec<Value>> {
    let (origin, join) = if owner.agent {
        (
            "o.epoch_id",
            "LEFT JOIN agent_restriction_origins o ON o.context_id = x.epoch_id AND o.scope = x.scope",
        )
    } else {
        ("NULL", "")
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT x.scope, x.tier, x.cooldown_until_ms, x.strike_count, x.trigger_request_id, {origin}
         FROM {} x {join}
         WHERE x.epoch_id = ?1 AND (x.tier = 'strict_epoch' OR x.cooldown_until_ms > ?2)
         ORDER BY x.created_sequence DESC, x.scope LIMIT 100", owner.restrictions()
    ))?;
    Ok(stmt
        .query_map(params![owner.id, now_ms], |row| {
            Ok(json!({
                "scope": row.get::<_, String>(0)?, "tier": row.get::<_, String>(1)?,
                "cooldown_until_ms": row.get::<_, i64>(2)?, "strike_count": row.get::<_, i64>(3)?,
                "trigger_request_id": row.get::<_, String>(4)?,
                "trigger_epoch_id": row.get::<_, Option<String>>(5)?
            }))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
