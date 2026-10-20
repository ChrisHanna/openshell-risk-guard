//! Sidecar operator operations: resource-key binding and audited restriction clearing.

use super::*;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};

const RESOURCE_KEY_SETTING: &str = "resource_key_fingerprint";

/// Whose restrictions an operator is inspecting or clearing.
#[derive(Debug, Clone, Copy)]
pub enum RestrictionTarget<'a> {
    /// Agent-attributed restrictions, optionally narrowed to one scoring context.
    Agent {
        agent_id: &'a str,
        context_id: Option<&'a str>,
    },
    /// Legacy unattributed restrictions owned by a sandbox's active epoch.
    Sandbox { sandbox_id: &'a str },
}

struct Owner {
    kind: &'static str,
    table: &'static str,
    id: String,
}

fn key_fingerprint(key: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"openshell-risk-guard/resource-key-id/v1");
    hex::encode(mac.finalize().into_bytes())
}

fn operator_text(value: &str, name: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(RiskGuardError::InvalidArgument(format!(
            "{name} must be 1..{max} bytes without control characters"
        )));
    }
    Ok(())
}

fn owners(tx: &Transaction<'_>, target: RestrictionTarget<'_>) -> Result<Vec<Owner>> {
    match target {
        RestrictionTarget::Agent { agent_id, context_id } => {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
                params![agent_id],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(RiskGuardError::InvalidArgument(format!("workload '{agent_id}' not found")));
            }
            let mut stmt = tx.prepare(
                "SELECT context_id FROM scoring_contexts
                 WHERE agent_id = ?1 AND (?2 IS NULL OR context_id = ?2) ORDER BY context_id",
            )?;
            let ids = stmt
                .query_map(params![agent_id, context_id], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if ids.is_empty() && context_id.is_some() {
                return Err(RiskGuardError::InvalidArgument(
                    "that scoring context does not belong to this workload".into(),
                ));
            }
            Ok(ids
                .into_iter()
                .map(|id| Owner { kind: "agent_context", table: "agent_restrictions", id })
                .collect())
        }
        RestrictionTarget::Sandbox { sandbox_id } => {
            let epoch = query_active_epoch(tx, sandbox_id)?.ok_or_else(|| {
                RiskGuardError::InvalidArgument(format!("no active epoch for sandbox '{sandbox_id}'"))
            })?;
            Ok(vec![Owner { kind: "epoch", table: "restrictions", id: epoch.epoch_id }])
        }
    }
}

impl SqliteRiskStore {
    /// Bind the database to one resource HMAC key. Rolling windows and fan-out sets
    /// are keyed by it, so a different key on an existing database is refused rather
    /// than silently splitting behavioral history.
    pub fn bind_resource_key(&self, key: &[u8], now_ms: i64) -> Result<()> {
        let fingerprint = key_fingerprint(key);
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let recorded: Option<String> = tx
            .query_row(
                "SELECT value FROM service_settings WHERE name = ?1",
                params![RESOURCE_KEY_SETTING],
                |row| row.get(0),
            )
            .optional()?;
        match recorded {
            Some(value) if value == fingerprint => {}
            Some(_) => {
                return Err(RiskGuardError::InvalidArgument(
                    "this database was created with a different resource HMAC key; use the original key file or a new database".into(),
                ));
            }
            None => {
                tx.execute(
                    "INSERT INTO service_settings (name, value, recorded_at_ms) VALUES (?1, ?2, ?3)",
                    params![RESOURCE_KEY_SETTING, fingerprint, now_ms],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// List stored restrictions, including whether each still blocks new requests.
    pub fn list_restrictions(&self, target: RestrictionTarget<'_>, now_ms: i64) -> Result<Value> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let mut rows = Vec::new();
        for owner in owners(&tx, target)? {
            let mut stmt = tx.prepare(&format!(
                "SELECT scope, tier, cooldown_until_ms, strike_count, trigger_request_id
                 FROM {} WHERE epoch_id = ?1 ORDER BY created_sequence",
                owner.table
            ))?;
            let found = stmt
                .query_map(params![owner.id], |row| {
                    let tier: String = row.get(1)?;
                    let until: i64 = row.get(2)?;
                    Ok(json!({
                        "owner_kind": owner.kind, "owner_id": owner.id,
                        "scope": row.get::<_, String>(0)?, "tier": tier.clone(),
                        "cooldown_until_ms": until, "strike_count": row.get::<_, i64>(3)?,
                        "trigger_request_id": row.get::<_, String>(4)?,
                        "blocking": tier == "strict_epoch" || until > now_ms,
                    }))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows.extend(found);
        }
        tx.commit()?;
        Ok(json!({ "restrictions": rows }))
    }

    /// Clear one restriction after explicit operator review.
    ///
    /// The cleared row is copied to `restriction_clearances` with the operator and
    /// reason. New requests in that scope are scored again from scratch; OpenShell
    /// policy, baselines and the original decision evidence are unchanged.
    pub fn clear_restriction(
        &self,
        target: RestrictionTarget<'_>,
        scope: &str,
        operator: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<Value> {
        operator_text(scope, "scope", 2048)?;
        operator_text(operator, "operator", 128)?;
        operator_text(reason, "reason", 1000)?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut matches = Vec::new();
        for owner in owners(&tx, target)? {
            let row: Option<(String, i64, String)> = tx
                .query_row(
                    &format!(
                        "SELECT tier, strike_count, trigger_request_id FROM {} WHERE epoch_id = ?1 AND scope = ?2",
                        owner.table
                    ),
                    params![owner.id, scope],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if let Some(row) = row {
                matches.push((owner, row));
            }
        }
        let (owner, (tier, strikes, trigger)) = match matches.len() {
            0 => {
                let hint = if matches!(target, RestrictionTarget::Sandbox { .. }) {
                    "; workload-bound sandboxes keep restrictions on the workload, so use --agent-id"
                } else {
                    ""
                };
                return Err(RiskGuardError::InvalidArgument(format!(
                    "no restriction with that exact scope{hint}"
                )));
            }
            1 => matches.remove(0),
            _ => {
                return Err(RiskGuardError::InvalidArgument(
                    "that scope is restricted in several scoring contexts; pass --context-id".into(),
                ));
            }
        };
        let origin: Option<(String, String)> = if owner.kind == "agent_context" {
            let origin = tx
                .query_row(
                    "SELECT epoch_id, request_id FROM agent_restriction_origins
                     WHERE context_id = ?1 AND scope = ?2",
                    params![owner.id, scope],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            tx.execute(
                "DELETE FROM agent_restriction_origins WHERE context_id = ?1 AND scope = ?2",
                params![owner.id, scope],
            )?;
            origin
        } else {
            None
        };
        tx.execute(
            "INSERT INTO restriction_clearances
             (owner_kind, owner_id, scope, tier, strike_count, trigger_request_id,
              origin_epoch_id, origin_request_id, cleared_by, reason, cleared_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                owner.kind, owner.id, scope, tier, strikes, trigger,
                origin.as_ref().map(|o| o.0.as_str()), origin.as_ref().map(|o| o.1.as_str()),
                operator, reason, now_ms
            ],
        )?;
        let clearance_id = tx.last_insert_rowid();
        tx.execute(
            &format!("DELETE FROM {} WHERE epoch_id = ?1 AND scope = ?2", owner.table),
            params![owner.id, scope],
        )?;
        tx.commit()?;
        Ok(json!({
            "status": "cleared", "clearance_id": clearance_id,
            "owner_kind": owner.kind, "owner_id": owner.id, "scope": scope,
            "tier": tier, "strike_count": strikes, "trigger_request_id": trigger,
            "cleared_by": operator, "cleared_at_ms": now_ms,
            "note": "new requests in this scope are scored again; OpenShell policy and recorded evidence are unchanged",
        }))
    }

    /// Export operational counters and gauges in Prometheus text exposition format.
    pub fn prometheus_metrics(&self, now_ms: i64) -> Result<String> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;

        let agents_total: i64 =
            tx.query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))?;
        let active_epochs_total: i64 = tx.query_row(
            "SELECT COUNT(*) FROM epochs WHERE active != 0",
            [],
            |row| row.get(0),
        )?;

        let (mut allow, mut allow_with_observation, mut deny) = (0_i64, 0_i64, 0_i64);
        {
            let mut stmt =
                tx.prepare("SELECT outcome, COUNT(*) FROM decisions GROUP BY outcome")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (outcome, count) = row?;
                match outcome.as_str() {
                    "allow" => allow = count,
                    "allow_with_observation" => allow_with_observation = count,
                    "deny" => deny = count,
                    _ => {}
                }
            }
        }

        let (mut strict_epoch, mut cooldown) = (0_i64, 0_i64);
        {
            let mut stmt = tx.prepare(
                "SELECT tier, COUNT(*) FROM (
                     SELECT tier FROM restrictions WHERE tier = 'strict_epoch' OR cooldown_until_ms > ?1
                     UNION ALL
                     SELECT tier FROM agent_restrictions WHERE tier = 'strict_epoch' OR cooldown_until_ms > ?1
                 ) GROUP BY tier",
            )?;
            let rows = stmt.query_map(params![now_ms], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (tier, count) = row?;
                match tier.as_str() {
                    "strict_epoch" => strict_epoch = count,
                    "cooldown" => cooldown = count,
                    _ => {}
                }
            }
        }

        let restriction_clearances_total: i64 = tx.query_row(
            "SELECT COUNT(*) FROM restriction_clearances",
            [],
            |row| row.get(0),
        )?;
        let adaptive_models_total: i64 = tx.query_row(
            "SELECT COUNT(*) FROM adaptive_models WHERE revoked_at_ms IS NULL",
            [],
            |row| row.get(0),
        )?;

        tx.commit()?;

        let mut out = String::with_capacity(1024);
        out.push_str("# HELP openshell_risk_guard_store_healthy Whether the SQLite risk store is reachable.\n");
        out.push_str("# TYPE openshell_risk_guard_store_healthy gauge\n");
        out.push_str("openshell_risk_guard_store_healthy 1\n");
        out.push_str("# HELP openshell_risk_guard_agents_total Total registered agents.\n");
        out.push_str("# TYPE openshell_risk_guard_agents_total gauge\n");
        out.push_str(&format!("openshell_risk_guard_agents_total {agents_total}\n"));
        out.push_str("# HELP openshell_risk_guard_active_epochs_total Active sandbox epochs.\n");
        out.push_str("# TYPE openshell_risk_guard_active_epochs_total gauge\n");
        out.push_str(&format!(
            "openshell_risk_guard_active_epochs_total {active_epochs_total}\n"
        ));
        out.push_str("# HELP openshell_risk_guard_decisions_total Total recorded risk decisions by outcome.\n");
        out.push_str("# TYPE openshell_risk_guard_decisions_total counter\n");
        out.push_str(&format!(
            "openshell_risk_guard_decisions_total{{outcome=\"allow\"}} {allow}\n"
        ));
        out.push_str(&format!(
            "openshell_risk_guard_decisions_total{{outcome=\"allow_with_observation\"}} {allow_with_observation}\n"
        ));
        out.push_str(&format!(
            "openshell_risk_guard_decisions_total{{outcome=\"deny\"}} {deny}\n"
        ));
        out.push_str("# HELP openshell_risk_guard_active_restrictions_total Active blocking restrictions by tier.\n");
        out.push_str("# TYPE openshell_risk_guard_active_restrictions_total gauge\n");
        out.push_str(&format!(
            "openshell_risk_guard_active_restrictions_total{{tier=\"strict_epoch\"}} {strict_epoch}\n"
        ));
        out.push_str(&format!(
            "openshell_risk_guard_active_restrictions_total{{tier=\"cooldown\"}} {cooldown}\n"
        ));
        out.push_str("# HELP openshell_risk_guard_restriction_clearances_total Total audited operator restriction clearances.\n");
        out.push_str("# TYPE openshell_risk_guard_restriction_clearances_total counter\n");
        out.push_str(&format!(
            "openshell_risk_guard_restriction_clearances_total {restriction_clearances_total}\n"
        ));
        out.push_str("# HELP openshell_risk_guard_adaptive_models_total Non-revoked adaptive models.\n");
        out.push_str("# TYPE openshell_risk_guard_adaptive_models_total gauge\n");
        out.push_str(&format!(
            "openshell_risk_guard_adaptive_models_total {adaptive_models_total}\n"
        ));
        Ok(out)
    }
}
