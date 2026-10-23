// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Signals from outside systems (a SIEM, for example) that ask Risk Guard to tighten. See `crate::signals` for the HTTP side.
//!
//! The rules, all enforced here so no transport can skip them:
//! - tighten only: the one action is `quarantine`; a signal can never release, loosen or clear anything;
//! - it expires: a signal's quarantine ends by itself after its time-to-live (60 s to an hour);
//! - it cannot override a person: a workload an operator quarantined stays quarantined, and a longer signal is not shortened;
//! - it is limited: at most N applied per minute, and at most M workloads quarantined by signals at once, so a wrong or hijacked
//!   sender cannot take down the whole fleet;
//! - a dry run records what would have happened and changes nothing;
//! - every signal that passes validation is recorded with its outcome, and every applied one is also in the quarantine audit.

use super::*;

/// The limits a signal receiver runs under.
#[derive(Debug, Clone)]
pub struct SignalPolicy {
    /// Record and answer, but change nothing. A request can also ask for a dry run; this makes it the rule.
    pub dry_run: bool,
    pub max_per_minute: u32,
    pub max_active: u32,
    pub min_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
}

impl Default for SignalPolicy {
    fn default() -> Self {
        Self {
            dry_run: false,
            max_per_minute: 10,
            max_active: 5,
            min_ttl_seconds: 60,
            max_ttl_seconds: 3600,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalRequest {
    /// Chosen by the sender and unique per alert firing; a repeat of an applied signal is answered, not applied twice.
    pub signal_id: String,
    /// Who is sending, e.g. `opensearch-alerting`.
    pub source: String,
    /// The alert or finding behind it, for the audit trail.
    #[serde(default)]
    pub alert_id: Option<String>,
    /// The target: a workload (`agent_id`) or a sandbox that belongs to one (`sandbox_id`). Exactly one.
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Only `quarantine` is accepted.
    pub action: String,
    pub ttl_seconds: u64,
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalOutcome {
    /// `applied`, `dry_run`, `already_quarantined`, `rate_limited`, `too_many_active` or `unknown_target`.
    pub outcome: String,
    pub agent_id: Option<String>,
    pub expires_at_ms: Option<i64>,
    /// True when this is the stored answer to a signal that was already handled.
    pub duplicate: bool,
}

fn plain(value: &str, name: &str, max: usize) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(RiskGuardError::InvalidArgument(format!(
            "{name} must be 1..{max} characters of letters, digits and - . _ : /"
        )))
    }
}

fn validate(request: &SignalRequest, policy: &SignalPolicy) -> Result<()> {
    plain(&request.signal_id, "signal_id", 128)?;
    plain(&request.source, "source", 160)?;
    if let Some(alert) = &request.alert_id {
        plain(alert, "alert_id", 128)?;
    }
    if request.action != "quarantine" {
        return Err(RiskGuardError::InvalidArgument(
            "only a tightening action is accepted: \"quarantine\"".into(),
        ));
    }
    match (&request.agent_id, &request.sandbox_id) {
        (Some(id), None) => plain(id, "agent_id", 128)?,
        (None, Some(id)) => plain(id, "sandbox_id", 128)?,
        _ => {
            return Err(RiskGuardError::InvalidArgument(
                "give exactly one of agent_id and sandbox_id".into(),
            ));
        }
    }
    if request.ttl_seconds < policy.min_ttl_seconds || request.ttl_seconds > policy.max_ttl_seconds
    {
        return Err(RiskGuardError::InvalidArgument(format!(
            "ttl_seconds must be between {} and {}",
            policy.min_ttl_seconds, policy.max_ttl_seconds
        )));
    }
    if request.reason.trim().is_empty()
        || request.reason.len() > 500
        || request.reason.chars().any(char::is_control)
    {
        return Err(RiskGuardError::InvalidArgument(
            "reason must be 1..500 bytes without control characters".into(),
        ));
    }
    Ok(())
}

impl SqliteRiskStore {
    /// Handle one signal. Validation errors are returned as errors (nothing recorded); everything else is an outcome, recorded.
    pub fn apply_signal(
        &self,
        request: &SignalRequest,
        policy: &SignalPolicy,
        now_ms: i64,
    ) -> Result<SignalOutcome> {
        validate(request, policy)?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // A repeat of a signal already handled returns its answer and changes nothing.
        let previous: Option<(String, Option<String>, Option<i64>)> = tx
            .query_row(
                "SELECT outcome, agent_id, expires_at_ms FROM siem_signals
                 WHERE signal_id = ?1 AND outcome IN ('applied', 'dry_run', 'already_quarantined') ORDER BY id LIMIT 1",
                params![request.signal_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((outcome, agent_id, expires_at_ms)) = previous {
            return Ok(SignalOutcome {
                outcome,
                agent_id,
                expires_at_ms,
                duplicate: true,
            });
        }

        let agent_id: Option<String> = match (&request.agent_id, &request.sandbox_id) {
            (Some(agent), _) => tx
                .query_row(
                    "SELECT agent_id FROM agents WHERE agent_id = ?1",
                    params![agent],
                    |row| row.get(0),
                )
                .optional()?,
            (None, Some(sandbox)) => match query_active_epoch(&tx, sandbox)? {
                Some(epoch) => resolve_identity(&tx, &epoch)?.map(|identity| identity.agent_id),
                None => None,
            },
            (None, None) => None,
        };
        let expires_at_ms = now_ms.saturating_add(
            i64::try_from(request.ttl_seconds)
                .unwrap_or(0)
                .saturating_mul(1000),
        );
        let operator = format!("signal:{}", request.source);
        let dry_run = request.dry_run || policy.dry_run;

        let outcome: &str = match &agent_id {
            None => "unknown_target",
            Some(agent) => {
                let current: Option<(String, Option<i64>)> = tx
                    .query_row(
                        "SELECT operator, expires_at_ms FROM workload_quarantine
                         WHERE agent_id = ?1 AND (expires_at_ms IS NULL OR expires_at_ms > ?2)",
                        params![agent, now_ms],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let applied_last_minute: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM siem_signals WHERE outcome = 'applied' AND received_at_ms > ?1",
                    params![now_ms - 60_000],
                    |row| row.get(0),
                )?;
                let active_by_signals: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM workload_quarantine
                     WHERE operator LIKE 'signal:%' AND expires_at_ms > ?1",
                    params![now_ms],
                    |row| row.get(0),
                )?;
                match current {
                    // Already held for at least as long (an operator's has no end): nothing to add.
                    Some((_, None)) => "already_quarantined",
                    Some((_, Some(until))) if until >= expires_at_ms => "already_quarantined",
                    _ if applied_last_minute >= i64::from(policy.max_per_minute) => "rate_limited",
                    // Extending one this receiver already holds does not add to the count.
                    None if active_by_signals >= i64::from(policy.max_active) => "too_many_active",
                    _ if dry_run => "dry_run",
                    _ => {
                        tx.execute(
                            "INSERT OR REPLACE INTO workload_quarantine (agent_id, reason, operator, quarantined_at_ms, expires_at_ms)
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![agent, request.reason, operator, now_ms, expires_at_ms],
                        )?;
                        let reason = match &request.alert_id {
                            Some(alert) => format!(
                                "{} (alert {alert}, signal {})",
                                request.reason, request.signal_id
                            ),
                            None => format!("{} (signal {})", request.reason, request.signal_id),
                        };
                        tx.execute(
                            "INSERT INTO workload_quarantine_audit (agent_id, action, operator, reason, at_ms) VALUES (?1, 'quarantine', ?2, ?3, ?4)",
                            params![agent, operator, reason, now_ms],
                        )?;
                        "applied"
                    }
                }
            }
        };
        let recorded_expiry = matches!(outcome, "applied" | "dry_run").then_some(expires_at_ms);
        tx.execute(
            "INSERT INTO siem_signals (signal_id, received_at_ms, source, alert_id, agent_id, sandbox_id, action, ttl_seconds, reason, outcome, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                request.signal_id,
                now_ms,
                request.source,
                request.alert_id,
                agent_id,
                request.sandbox_id,
                request.action,
                i64::try_from(request.ttl_seconds).unwrap_or(0),
                request.reason,
                outcome,
                recorded_expiry,
            ],
        )?;
        tx.commit()?;
        Ok(SignalOutcome {
            outcome: outcome.to_string(),
            agent_id,
            expires_at_ms: recorded_expiry,
            duplicate: false,
        })
    }

    /// The most recent signals and what became of them, newest first.
    pub fn list_signals(&self, limit: u32) -> Result<serde_json::Value> {
        let conn = self.lock_read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT signal_id, received_at_ms, source, alert_id, agent_id, sandbox_id, action, ttl_seconds, reason, outcome, expires_at_ms
             FROM siem_signals ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit.min(500)], |row| {
                Ok(serde_json::json!({
                    "signal_id": row.get::<_, String>(0)?,
                    "received_at_ms": row.get::<_, i64>(1)?,
                    "source": row.get::<_, String>(2)?,
                    "alert_id": row.get::<_, Option<String>>(3)?,
                    "agent_id": row.get::<_, Option<String>>(4)?,
                    "sandbox_id": row.get::<_, Option<String>>(5)?,
                    "action": row.get::<_, String>(6)?,
                    "ttl_seconds": row.get::<_, i64>(7)?,
                    "reason": row.get::<_, String>(8)?,
                    "outcome": row.get::<_, String>(9)?,
                    "expires_at_ms": row.get::<_, Option<i64>>(10)?,
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({ "signals": rows }))
    }
}
