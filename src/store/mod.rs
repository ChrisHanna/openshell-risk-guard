// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Transactional SQLite store and Two-Tier Monotonic Ratchet (Wave 1 - `t04-sqlite-store`).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::error::{Result, RiskGuardError};
use crate::types::{
    BaselineProfile, BindingAudit, DecisionOutcome, DetectorContext, EnforcementMode, EpochRecord,
    HardeningCandidate, NativeObservationSource, NetworkState, NormalizedRequest,
    REASON_BEHAVIORAL_RISK_RESTRICTED, RatchetAction, RiskDetector, RiskEvaluation, RiskStore,
    SandboxBinding, SignalContribution, WindowSnapshot,
};

mod adaptive;
mod guardrails;
mod identity;
mod operations;
use identity::{AgentIdentity, resolve_identity};
pub use operations::RestrictionTarget;

const INITIAL_MIGRATION_SQL: &str = include_str!("../../migrations/0001_initial.sql");
const AGENT_MIGRATION_SQL: &str = include_str!("../../migrations/0002_agent_identity.sql");
const GUARDRAIL_MIGRATION_SQL: &str = include_str!("../../migrations/0003_agent_guardrails.sql");
const ADAPTIVE_MIGRATION_SQL: &str = include_str!("../../migrations/0004_adaptive_learning.sql");
const BINDING_AUDIT_MIGRATION_SQL: &str =
    include_str!("../../migrations/0005_workload_binding_audit.sql");
const AGENT_WORKSPACES_MIGRATION_SQL: &str =
    include_str!("../../migrations/0006_agent_workspaces.sql");
const SIDECAR_MIGRATION_SQL: &str = include_str!("../../migrations/0005_sidecar_operations.sql");
const MAX_BUCKET_RESOURCES: usize = crate::guardrails::MAX_FANOUT_ENVELOPE as usize;
const WINDOW_RETENTION_MS: i64 = 3_600_000;
/// Default maximum number of retained non-pinned decisions per epoch before automatic pruning.
pub const MAX_RETAINED_DECISIONS_PER_EPOCH: usize = 10_000;

/// Durable SQLite store implementing [`RiskStore`] with `WAL` + `synchronous=FULL`
/// and the Two-Tier Monotonic Ratchet.
#[derive(Debug, Clone)]
pub struct SqliteRiskStore {
    conn: Arc<Mutex<Connection>>,
    read_conn: Option<Arc<Mutex<Connection>>>,
    /// When set, each sandbox's SPIFFE ID (`spiffe://<domain>/openshell/sandbox/<id>`, the name SPIRE registers it under, see
    /// deploy/aks/sandbox-spiffe.yaml) is shown beside it. It is the name SPIRE assigned; Risk Guard does not receive the certificate.
    sandbox_spiffe_trust_domain: Option<String>,
}

#[derive(Debug, Clone)]
struct MatchedRestriction {
    scope: String,
    tier: String,
    cooldown_until_ms: i64,
    strike_count: i64,
    trigger_request_id: String,
}

#[derive(Clone, Copy)]
struct StateOwner<'a> {
    id: &'a str,
    agent: bool,
}

impl StateOwner<'_> {
    fn windows(self) -> &'static str {
        if self.agent {
            "agent_window_buckets"
        } else {
            "window_buckets"
        }
    }

    fn restrictions(self) -> &'static str {
        if self.agent {
            "agent_restrictions"
        } else {
            "restrictions"
        }
    }
}

impl SqliteRiskStore {
    /// Open or create a file-backed SQLite database with `WAL`, `synchronous=FULL`,
    /// `foreign_keys=ON`, `busy_timeout=5000`, and apply schema migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                RiskGuardError::Storage(format!(
                    "failed to create parent directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }

        let conn = Connection::open(path_ref)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path_ref, std::fs::Permissions::from_mode(0o600));
        }

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        conn.execute_batch(INITIAL_MIGRATION_SQL)?;
        conn.execute_batch(AGENT_MIGRATION_SQL)?;
        conn.execute_batch(GUARDRAIL_MIGRATION_SQL)?;
        conn.execute_batch(ADAPTIVE_MIGRATION_SQL)?;
        conn.execute_batch(BINDING_AUDIT_MIGRATION_SQL)?;
        conn.execute_batch(AGENT_WORKSPACES_MIGRATION_SQL)?;
        ensure_binding_audit_provider_column(&conn)?;
        ensure_epoch_closed_at_column(&conn)?;
        ensure_latency_table(&conn)?;
        ensure_quarantine_tables(&conn)?;
        conn.execute_batch(SIDECAR_MIGRATION_SQL)?;

        let read_conn = Connection::open(path_ref)?;
        read_conn.execute_batch(
            "PRAGMA query_only = ON;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            read_conn: Some(Arc::new(Mutex::new(read_conn))),
            sandbox_spiffe_trust_domain: sandbox_spiffe_trust_domain_from_env(),
        })
    }

    /// Open an in-memory SQLite database for tests and apply schema migrations.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        conn.execute_batch(INITIAL_MIGRATION_SQL)?;
        conn.execute_batch(AGENT_MIGRATION_SQL)?;
        conn.execute_batch(GUARDRAIL_MIGRATION_SQL)?;
        conn.execute_batch(ADAPTIVE_MIGRATION_SQL)?;
        conn.execute_batch(BINDING_AUDIT_MIGRATION_SQL)?;
        conn.execute_batch(AGENT_WORKSPACES_MIGRATION_SQL)?;
        ensure_binding_audit_provider_column(&conn)?;
        ensure_epoch_closed_at_column(&conn)?;
        ensure_latency_table(&conn)?;
        ensure_quarantine_tables(&conn)?;
        conn.execute_batch(SIDECAR_MIGRATION_SQL)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            read_conn: None,
            sandbox_spiffe_trust_domain: None,
        })
    }

    /// Return `(journal_mode, synchronous, foreign_keys)` pragmas for Gate G-11 verification.
    ///
    /// On a file-backed database configured with `SqliteRiskStore::open`, this returns
    /// `("wal", 2, 1)` where `2` corresponds to `synchronous = FULL`.
    pub fn verify_pragmas(&self) -> Result<(String, i64, i64)> {
        let conn = self.lock_conn()?;
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |row| row.get::<_, String>(0))?
            .to_ascii_lowercase();
        let synchronous: i64 = conn.query_row("PRAGMA synchronous;", [], |row| row.get(0))?;
        let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys;", [], |row| row.get(0))?;
        Ok((journal_mode, synchronous, foreign_keys))
    }

    /// Inventory reflects governed epochs, not a claim about live gateway lifecycle.
    pub fn operator_inventory(&self, now_ms: i64) -> Result<serde_json::Value> {
        let mut conn = self.lock_read_conn()?;
        let tx = conn.transaction()?;
        let total: i64 = tx.query_row(
            "SELECT COUNT(DISTINCT sandbox_id) FROM epochs WHERE active != 0",
            [],
            |row| row.get(0),
        )?;
        let ids = {
            let mut stmt = tx.prepare(
                "SELECT sandbox_id FROM epochs WHERE active != 0
                 GROUP BY sandbox_id ORDER BY sandbox_id LIMIT 200",
            )?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut sandboxes = Vec::new();
        for id in ids {
            if let Some(epoch) = query_active_epoch(&tx, &id)? {
                sandboxes.push(operator_epoch_summary(&tx, &epoch, now_ms)?);
            }
        }
        let agents = identity::agent_inventory(&tx, now_ms)?;
        let total_agents: i64 =
            tx.query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))?;
        let (lifecycle, connectivity) = lifecycle_overview(&tx, now_ms)?;
        let latency = operations::latency_summary(&tx, now_ms, operations::LATENCY_WINDOW_MS)?;
        tx.commit()?;
        Ok(serde_json::json!({
            "source": "persisted_risk_guard_evidence",
            "generated_at_ms": now_ms,
            "gateway_connectivity": connectivity,
            "sandbox_lifecycle": lifecycle,
            "decision_latency": latency,
            "coverage": "selected_inspected_http_requests_only",
            "transport_provenance": "per_decision_when_recorded_legacy_history_unknown",
            "total_sandboxes": total,
            "limit": 200,
            "agents": agents,
            "total_agents": total_agents,
            "sandboxes": sandboxes
        }))
    }

    /// Return bounded persisted evidence without synthesizing missing request fields.
    pub fn operator_detail(
        &self,
        sandbox_id: &str,
        now_ms: i64,
    ) -> Result<Option<serde_json::Value>> {
        let mut conn = self.lock_read_conn()?;
        let tx = conn.transaction()?;
        let Some(epoch) = query_active_epoch(&tx, sandbox_id)? else {
            return Ok(None);
        };
        let summary = operator_epoch_summary(&tx, &epoch, now_ms)?;
        let baseline_json: Option<String> = tx
            .query_row(
                "SELECT payload_json FROM artifacts
             WHERE artifact_type = 'baseline_profile' AND artifact_hash = ?1",
                params![epoch.baseline_hash],
                |row| row.get(0),
            )
            .optional()?;
        let baseline = baseline_json
            .map(|raw| serde_json::from_str::<BaselineProfile>(&raw))
            .transpose()?;
        let mut decisions = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT normalized_request_json, evaluation_json FROM decisions
                 WHERE epoch_id = ?1 ORDER BY sequence DESC LIMIT 100",
            )?;
            let rows = stmt.query_map(params![epoch.epoch_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (request, evaluation) = row?;
                let evaluation: RiskEvaluation = serde_json::from_str(&evaluation)?;
                let transport = adaptive::decision_transport(
                    &tx,
                    &evaluation.epoch_id,
                    &evaluation.request_id,
                )?;
                let adaptive = adaptive::decision_assessments(
                    &tx,
                    &evaluation.epoch_id,
                    &evaluation.request_id,
                )?;
                decisions.push(serde_json::json!({
                    "request": serde_json::from_str::<NormalizedRequest>(&request)?,
                    "evaluation": evaluation,
                    "adaptive": adaptive,
                    "upstream_outcome": null,
                    "transport_provenance": transport
                }));
            }
        }
        let identity = resolve_identity(&tx, &epoch)?;
        let owner = state_owner(&epoch, identity.as_ref());
        let restrictions = identity::active_restrictions(&tx, owner, now_ms)?;
        let recommendations = {
            let mut stmt = tx.prepare(
                "SELECT payload_json FROM recommendations WHERE epoch_id = ?1
                 ORDER BY created_at_ms DESC, recommendation_id DESC LIMIT 20",
            )?;
            let rows = stmt.query_map(params![epoch.epoch_id], |row| row.get::<_, String>(0))?;
            let mut records = Vec::new();
            for raw in rows {
                records.push(serde_json::from_str::<HardeningCandidate>(&raw?)?);
            }
            records
        };
        let coverage_gaps = {
            let mut stmt = tx.prepare(
                "SELECT gap_reason, start_ms, end_ms FROM coverage_intervals
                 WHERE sandbox_id = ?1 AND end_ms >= ?2
                 ORDER BY start_ms DESC LIMIT 100",
            )?;
            stmt.query_map(params![sandbox_id, epoch.created_at_ms], |row| {
                Ok(serde_json::json!({
                    "reason": row.get::<_, String>(0)?,
                    "start_ms": row.get::<_, i64>(1)?,
                    "end_ms": row.get::<_, i64>(2)?
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        tx.commit()?;
        Ok(Some(serde_json::json!({
            "summary": summary,
            "baseline": baseline,
            "decisions": decisions,
            "active_restrictions": restrictions,
            "recommendations": recommendations,
            "recorded_coverage_gaps": coverage_gaps,
            "limits": {"decisions": 100, "restrictions": 100, "recommendations": 20, "coverage_gaps": 100}
        })))
    }

    /// List saved hardening recommendations for a sandbox in reverse chronological order.
    pub fn list_recommendations(&self, sandbox_id: &str) -> Result<Vec<HardeningCandidate>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT payload_json
             FROM recommendations
             WHERE sandbox_id = ?1
             ORDER BY created_at_ms DESC, recommendation_id DESC",
        )?;
        let rows = stmt.query_map(params![sandbox_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let payload_json = row?;
            let candidate: HardeningCandidate =
                serde_json::from_str(&payload_json).map_err(|e| {
                    RiskGuardError::Storage(format!("corrupt recommendation payload_json: {e}"))
                })?;
            out.push(candidate);
        }
        Ok(out)
    }

    /// List recorded coverage gap intervals for a sandbox in chronological order.
    pub fn list_coverage_gaps(&self, sandbox_id: &str) -> Result<Vec<(String, i64, i64)>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT gap_reason, start_ms, end_ms
             FROM coverage_intervals
             WHERE sandbox_id = ?1
             ORDER BY start_ms ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![sandbox_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// List active restrictions across all epochs (or for a specific epoch) for the live dashboard.
    pub fn list_all_restrictions(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT epoch_id, scope, tier, cooldown_until_ms, strike_count, trigger_request_id, created_sequence
             FROM restrictions
             ORDER BY created_sequence DESC, scope ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "epoch_id": row.get::<_, String>(0)?,
                "scope": row.get::<_, String>(1)?,
                "tier": row.get::<_, String>(2)?,
                "cooldown_until_ms": row.get::<_, i64>(3)?,
                "strike_count": row.get::<_, i64>(4)?,
                "trigger_request_id": row.get::<_, String>(5)?,
                "created_sequence": row.get::<_, i64>(6)?,
            }))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Clear runtime epoch/decision/restriction rows for a clean live demo reset while keeping baseline artifacts.
    pub fn clear_runtime_tables(&self) -> Result<()> {
        let conn = self.lock_conn()?;
        let attributed: bool =
            conn.query_row("SELECT EXISTS(SELECT 1 FROM agents)", [], |row| row.get(0))?;
        if attributed {
            return Err(RiskGuardError::PermissionDenied(
                "demo reset is not permitted on an agent-registered database".into(),
            ));
        }
        conn.execute_batch(
            "DELETE FROM recommendations;
             DELETE FROM coverage_intervals;
             DELETE FROM policy_snapshots;
             DELETE FROM restrictions;
             DELETE FROM window_buckets;
             DELETE FROM decisions;
             DELETE FROM epochs;",
        )?;
        Ok(())
    }

    /// Prune old non-pinned decisions exceeding `max_per_epoch` per epoch.
    ///
    /// Preserves decisions referenced in `adaptive_observations` (pinned training data),
    /// `agent_restriction_origins`, `restrictions.trigger_request_id`, or
    /// `agent_restrictions.trigger_request_id`.
    pub fn prune_old_decisions(&self, max_per_epoch: usize) -> Result<usize> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch_ids = {
            let mut stmt =
                tx.prepare("SELECT DISTINCT epoch_id FROM decisions ORDER BY epoch_id")?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut total_deleted = 0usize;
        for epoch_id in epoch_ids {
            total_deleted += prune_epoch_decisions(&tx, &epoch_id, max_per_epoch)?;
        }
        tx.commit()?;
        Ok(total_deleted)
    }

    /// Prune decisions recorded before `cutoff_ms` (age-based retention), keeping anything that is still pinned
    /// (see `UNPINNED_DECISION_SQL`). Works in small transactions so the single writer is never held for long.
    /// Epochs, restrictions and the clearance audit are never pruned. Returns the number of decisions removed.
    pub fn prune_decisions_older_than(&self, cutoff_ms: i64) -> Result<usize> {
        const BATCH: usize = 2_000;
        let select = format!(
            "SELECT d.epoch_id, d.request_id FROM decisions d
             WHERE d.created_at_ms < ?1 {UNPINNED_DECISION_SQL}
             ORDER BY d.created_at_ms ASC LIMIT ?2"
        );
        let mut total = 0usize;
        loop {
            let mut conn = self.lock_conn()?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let rows = {
                let mut stmt = tx.prepare(&select)?;
                stmt.query_map(params![cutoff_ms, BATCH as i64], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
            };
            for (epoch_id, request_id) in &rows {
                total += delete_decision_row(&tx, epoch_id, request_id)?;
            }
            tx.commit()?;
            drop(conn);
            if rows.len() < BATCH {
                return Ok(total);
            }
        }
    }

    /// The baseline a sandbox's active epoch is pinned to.
    pub fn sandbox_baseline(&self, sandbox_id: &str) -> Result<Option<BaselineProfile>> {
        let conn = self.lock_read_conn()?;
        let Some(epoch) = query_active_epoch(&conn, sandbox_id)? else {
            return Ok(None);
        };
        query_baseline_by_name_or_hash(&conn, &epoch.task_profile, &epoch.baseline_hash)
    }

    /// Show each sandbox's SPIFFE ID under this trust domain (see `sandbox_spiffe_trust_domain`).
    #[must_use]
    pub fn with_sandbox_spiffe_trust_domain(mut self, domain: impl Into<String>) -> Self {
        self.sandbox_spiffe_trust_domain = Some(domain.into());
        self
    }

    /// The SPIFFE ID SPIRE assigns a sandbox, when a trust domain is configured. Sandboxes of the SVID listener already are SPIFFE IDs.
    pub(crate) fn sandbox_spiffe_id(&self, sandbox_id: &str) -> Option<String> {
        let domain = self.sandbox_spiffe_trust_domain.as_deref()?;
        if sandbox_id.starts_with("svid-") {
            return None;
        }
        Some(format!("spiffe://{domain}/openshell/sandbox/{sandbox_id}"))
    }

    /// What the network path needs to know about a sandbox. `None` when the sandbox has no active epoch.
    pub fn sandbox_network_state(&self, sandbox_id: &str) -> Result<Option<NetworkState>> {
        let conn = self.lock_read_conn()?;
        let Some(epoch) = query_active_epoch(&conn, sandbox_id)? else {
            return Ok(None);
        };
        let identity = resolve_identity(&conn, &epoch)?;
        let owner = state_owner(&epoch, identity.as_ref());
        let restricted: bool = conn.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE epoch_id = ?1 AND tier = 'strict_epoch')",
                owner.restrictions()
            ),
            params![owner.id],
            |row| row.get(0),
        )?;
        let quarantined = match &identity {
            Some(identity) => conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM workload_quarantine WHERE agent_id = ?1)",
                params![identity.agent_id],
                |row| row.get(0),
            )?,
            None => false,
        };
        Ok(Some(NetworkState {
            quarantined,
            restricted,
        }))
    }

    /// Quarantine a workload: from now on the network path refuses its sandboxes any tunnel. Recorded with who and why.
    pub fn quarantine_workload(
        &self,
        agent_id: &str,
        operator: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<()> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
            params![agent_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(RiskGuardError::InvalidArgument(format!(
                "workload '{agent_id}' not found"
            )));
        }
        for (value, name) in [(operator, "operator"), (reason, "reason")] {
            if value.trim().is_empty() || value.len() > 1000 || value.chars().any(char::is_control)
            {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "{name} must be 1..1000 bytes without control characters"
                )));
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO workload_quarantine (agent_id, reason, operator, quarantined_at_ms) VALUES (?1, ?2, ?3, ?4)",
            params![agent_id, reason, operator, now_ms],
        )?;
        tx.execute(
            "INSERT INTO workload_quarantine_audit (agent_id, action, operator, reason, at_ms) VALUES (?1, 'quarantine', ?2, ?3, ?4)",
            params![agent_id, operator, reason, now_ms],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// End a workload's quarantine. Returns whether it was quarantined.
    pub fn release_workload(
        &self,
        agent_id: &str,
        operator: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute(
            "DELETE FROM workload_quarantine WHERE agent_id = ?1",
            params![agent_id],
        )? > 0;
        if removed {
            tx.execute(
                "INSERT INTO workload_quarantine_audit (agent_id, action, operator, reason, at_ms) VALUES (?1, 'release', ?2, ?3, ?4)",
                params![agent_id, operator, reason, now_ms],
            )?;
        }
        tx.commit()?;
        Ok(removed)
    }

    /// Workloads currently quarantined, newest first.
    pub fn list_quarantined(&self) -> Result<serde_json::Value> {
        let conn = self.lock_read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT agent_id, reason, operator, quarantined_at_ms FROM workload_quarantine ORDER BY quarantined_at_ms DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "agent_id": row.get::<_, String>(0)?,
                    "reason": row.get::<_, String>(1)?,
                    "operator": row.get::<_, String>(2)?,
                    "quarantined_at_ms": row.get::<_, i64>(3)?,
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({ "quarantined": rows }))
    }

    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| RiskGuardError::Internal("sqlite connection mutex poisoned".to_string()))
    }

    fn lock_read_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        let target = self.read_conn.as_ref().unwrap_or(&self.conn);
        target.lock().map_err(|_| {
            RiskGuardError::Internal("sqlite read connection mutex poisoned".to_string())
        })
    }
}

fn operator_epoch_summary(
    conn: &Connection,
    epoch: &EpochRecord,
    now_ms: i64,
) -> Result<serde_json::Value> {
    let (count, last_observed): (i64, Option<i64>) = conn.query_row(
        "SELECT COUNT(*), MAX(created_at_ms) FROM decisions WHERE epoch_id = ?1",
        params![epoch.epoch_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let identity = resolve_identity(conn, epoch)?;
    let owner = state_owner(epoch, identity.as_ref());
    let restrictions: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {} WHERE epoch_id = ?1
         AND (tier = 'strict_epoch' OR cooldown_until_ms > ?2)",
            owner.restrictions()
        ),
        params![owner.id, now_ms],
        |row| row.get(0),
    )?;
    let last_score: Option<u32> = conn
        .query_row(
            "SELECT risk_score FROM decisions WHERE epoch_id = ?1 ORDER BY sequence DESC LIMIT 1",
            params![epoch.epoch_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(serde_json::json!({
        "epoch": epoch,
        "identity": identity,
        "behavioral_state": if restrictions > 0 { "scoped_restrictions" }
            else if count == 0 { "no_observations" } else { "observed" },
        "decision_count": count,
        "last_observed_at_ms": last_observed,
        "last_request_score": last_score,
        "active_restriction_count": restrictions,
        "sandbox_compromise_probability": null,
        "sandbox_lifecycle": lifecycle_state(last_observed.unwrap_or(0).max(epoch.created_at_ms), now_ms)
    }))
}

impl RiskStore for SqliteRiskStore {
    fn upsert_epoch(&self, epoch: &EpochRecord) -> Result<()> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let bound: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM epoch_bindings WHERE epoch_id = ?1)",
            params![epoch.epoch_id],
            |row| row.get(0),
        )?;
        if bound {
            let original = query_active_epoch(&tx, &epoch.sandbox_id)?.ok_or_else(|| {
                RiskGuardError::PermissionDenied(
                    "bound epoch cannot be reactivated or moved".into(),
                )
            })?;
            if original.epoch_id != epoch.epoch_id
                || original.gateway_id != epoch.gateway_id
                || original.task_profile != epoch.task_profile
                || original.baseline_hash != epoch.baseline_hash
                || original.mode != epoch.mode
                || original.created_at_ms != epoch.created_at_ms
            {
                return Err(RiskGuardError::PermissionDenied(
                    "bound epoch identity, baseline and mode are immutable".into(),
                ));
            }
        }

        if epoch.active {
            tx.execute(
                "UPDATE epochs SET active = 0, closed_at_ms = ?3 WHERE sandbox_id = ?1 AND epoch_id != ?2 AND active != 0",
                params![epoch.sandbox_id, epoch.epoch_id, current_time_ms()],
            )?;
        }

        let credentialed_endpoints_json = serde_json::to_string(&epoch.credentialed_endpoints)?;
        let active_int = i64::from(epoch.active);
        let next_sequence_i64 = i64::try_from(epoch.next_sequence).map_err(|_| {
            RiskGuardError::InvalidArgument("epoch.next_sequence overflows i64".to_string())
        })?;

        tx.execute(
            "INSERT INTO epochs (
                epoch_id,
                gateway_id,
                sandbox_id,
                task_profile,
                baseline_hash,
                mode,
                active,
                next_sequence,
                created_at_ms,
                credentialed_endpoints_json,
                active_policy_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(epoch_id) DO UPDATE SET
                gateway_id = excluded.gateway_id,
                sandbox_id = excluded.sandbox_id,
                task_profile = excluded.task_profile,
                baseline_hash = excluded.baseline_hash,
                mode = excluded.mode,
                active = excluded.active,
                next_sequence = MAX(epochs.next_sequence, excluded.next_sequence),
                created_at_ms = excluded.created_at_ms,
                credentialed_endpoints_json = excluded.credentialed_endpoints_json,
                active_policy_hash = excluded.active_policy_hash",
            params![
                epoch.epoch_id,
                epoch.gateway_id,
                epoch.sandbox_id,
                epoch.task_profile,
                epoch.baseline_hash,
                epoch.mode.as_str(),
                active_int,
                next_sequence_i64,
                epoch.created_at_ms,
                credentialed_endpoints_json,
                epoch.active_policy_hash,
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    fn get_active_epoch(&self, sandbox_id: &str) -> Result<Option<EpochRecord>> {
        let conn = self.lock_conn()?;
        query_active_epoch(&conn, sandbox_id)
    }

    fn get_effective_active_epoch(&self, sandbox_id: &str) -> Result<Option<EpochRecord>> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction()?;
        let mut epoch = query_active_epoch(&tx, sandbox_id)?;
        if let Some(epoch) = epoch.as_mut()
            && let Some(identity) = resolve_identity(&tx, epoch)?
            && let Some(saved) = guardrails::query_saved(&tx, &identity.agent_id)?
        {
            epoch.mode = saved.settings.mode;
        }
        tx.commit()?;
        Ok(epoch)
    }

    fn terminate_epoch(&self, epoch_id: &str) -> Result<()> {
        let now = current_time_ms();
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE epochs SET active = 0, closed_at_ms = ?2 WHERE epoch_id = ?1",
            params![epoch_id, now],
        )?;
        let bound_run: Option<String> = tx
            .query_row(
                "SELECT run_id FROM epoch_bindings WHERE epoch_id = ?1",
                params![epoch_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(run_id) = bound_run {
            let active_epochs: i64 = tx.query_row(
                "SELECT COUNT(*) FROM epoch_bindings b JOIN epochs e USING(epoch_id)
                 WHERE b.run_id = ?1 AND e.active != 0",
                params![run_id],
                |row| row.get(0),
            )?;
            if active_epochs == 0 {
                adaptive::finalize_run_captures(&tx, &run_id, now)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn store_baseline(&self, profile: &BaselineProfile) -> Result<String> {
        let payload_json = serde_json::to_string(profile)?;
        let artifact_hash = hex::encode(Sha256::digest(payload_json.as_bytes()));
        let created_at_ms = current_time_ms();

        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO artifacts (
                artifact_hash,
                artifact_type,
                name,
                version,
                payload_json,
                created_at_ms
            ) VALUES (?1, 'baseline_profile', ?2, ?3, ?4, ?5)",
            params![
                artifact_hash,
                profile.task_profile,
                profile.version,
                payload_json,
                created_at_ms,
            ],
        )?;
        Ok(artifact_hash)
    }

    fn get_baseline(&self, task_profile: &str) -> Result<Option<BaselineProfile>> {
        let conn = self.lock_conn()?;
        query_baseline_by_name_or_hash(&conn, task_profile, task_profile)
    }

    fn record_policy_snapshot(
        &self,
        sandbox_id: &str,
        policy_hash: &str,
        policy_yaml: &str,
        credentialed_endpoints: &BTreeSet<(String, u16)>,
        source: &str,
        timestamp_ms: i64,
    ) -> Result<()> {
        let credentialed_endpoints_json = serde_json::to_string(credentialed_endpoints)?;
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        tx.execute(
            "INSERT INTO policy_snapshots (
                sandbox_id,
                policy_hash,
                policy_yaml,
                credentialed_endpoints_json,
                source,
                captured_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                sandbox_id,
                policy_hash,
                policy_yaml,
                credentialed_endpoints_json,
                source,
                timestamp_ms,
            ],
        )?;

        tx.execute(
            "UPDATE epochs
             SET active_policy_hash = ?1,
                 credentialed_endpoints_json = ?2
             WHERE sandbox_id = ?3 AND active != 0",
            params![policy_hash, credentialed_endpoints_json, sandbox_id],
        )?;

        tx.commit()?;
        Ok(())
    }

    fn latest_policy_snapshot(&self, sandbox_id: &str) -> Result<Option<(String, String)>> {
        let conn = self.lock_conn()?;
        let row = conn
            .query_row(
                "SELECT policy_hash, policy_yaml
                 FROM policy_snapshots
                 WHERE sandbox_id = ?1
                 ORDER BY captured_at_ms DESC, id DESC
                 LIMIT 1",
                params![sandbox_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        Ok(row)
    }

    fn record_coverage_gap(
        &self,
        sandbox_id: &str,
        reason: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO coverage_intervals (
                sandbox_id,
                gap_reason,
                start_ms,
                end_ms
            ) VALUES (?1, ?2, ?3, ?4)",
            params![sandbox_id, reason, start_ms, end_ms],
        )?;
        Ok(())
    }

    fn evaluate_and_commit_atomic(
        &self,
        req: &NormalizedRequest,
        detector: &dyn RiskDetector,
    ) -> Result<RiskEvaluation> {
        self.evaluate_with_identity(req, detector, None, false, None)
    }

    fn evaluate_authenticated(
        &self,
        req: &NormalizedRequest,
        detector: &dyn RiskDetector,
        gateway_id: &str,
        require_agent: bool,
    ) -> Result<RiskEvaluation> {
        self.evaluate_with_identity(req, detector, Some(gateway_id), require_agent, None)
    }

    fn evaluate_native_authenticated(
        &self,
        req: &NormalizedRequest,
        detector: &dyn RiskDetector,
        gateway_id: &str,
        require_agent: bool,
        source: NativeObservationSource,
    ) -> Result<RiskEvaluation> {
        self.evaluate_with_identity(req, detector, Some(gateway_id), require_agent, Some(source))
    }

    fn list_decisions(&self, sandbox_id: &str, limit: usize) -> Result<Vec<RiskEvaluation>> {
        self.list_stored_decisions(sandbox_id, limit)
    }

    fn list_normalized_requests(
        &self,
        sandbox_id: &str,
    ) -> Result<Vec<(NormalizedRequest, DecisionOutcome)>> {
        self.list_stored_requests(sandbox_id)
    }

    fn save_recommendation(&self, candidate: &HardeningCandidate) -> Result<()> {
        self.save_stored_recommendation(candidate)
    }

    fn auto_bind_sandbox_epoch(&self, binding: &SandboxBinding) -> Result<()> {
        SqliteRiskStore::auto_bind_sandbox_epoch(self, binding)
    }

    fn record_binding_audit(&self, entry: &BindingAudit) -> Result<()> {
        SqliteRiskStore::record_binding_audit(self, entry)
    }

    fn list_binding_audit(&self, sandbox_id: &str) -> Result<Vec<BindingAudit>> {
        SqliteRiskStore::list_binding_audit(self, sandbox_id)
    }

    fn close_sandbox_lifecycle(&self, sandbox_id: &str) -> Result<Option<String>> {
        SqliteRiskStore::close_sandbox_lifecycle(self, sandbox_id)
    }

    fn sandbox_network_state(&self, sandbox_id: &str) -> Result<Option<NetworkState>> {
        SqliteRiskStore::sandbox_network_state(self, sandbox_id)
    }

    fn sandbox_baseline(&self, sandbox_id: &str) -> Result<Option<BaselineProfile>> {
        SqliteRiskStore::sandbox_baseline(self, sandbox_id)
    }
}

/// Databases created before the identity provider was recorded get the column added in place.
fn ensure_binding_audit_provider_column(conn: &Connection) -> Result<()> {
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('workload_binding_audit') WHERE name = 'principal_provider'",
        [],
        |row| row.get(0),
    )?;
    if present == 0 {
        conn.execute_batch(
            "ALTER TABLE workload_binding_audit ADD COLUMN principal_provider TEXT NOT NULL DEFAULT ''",
        )?;
    }
    Ok(())
}

/// The trust domain SPIRE names sandboxes under, from `RISK_GUARD_SANDBOX_SPIFFE_TRUST_DOMAIN`. Anything that is not a valid trust domain
/// (lowercase letters, digits, `-`, `.`, `_`) is ignored, so a bad value shows no identity instead of a wrong one.
fn sandbox_spiffe_trust_domain_from_env() -> Option<String> {
    let value = std::env::var("RISK_GUARD_SANDBOX_SPIFFE_TRUST_DOMAIN").ok()?;
    let value = value.trim();
    (!value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b)))
    .then(|| value.to_string())
}

/// Workloads an operator has quarantined (their sandboxes get no network tunnels), and the audit of who did what and why.
fn ensure_quarantine_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS workload_quarantine (
            agent_id TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            operator TEXT NOT NULL,
            quarantined_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS workload_quarantine_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            operator TEXT NOT NULL,
            reason TEXT NOT NULL,
            at_ms INTEGER NOT NULL
         )",
    )?;
    Ok(())
}

/// One row per flushed interval of the middleware's server-side decision time (see `crate::latency`).
fn ensure_latency_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS latency_intervals (
            at_ms INTEGER PRIMARY KEY,
            count INTEGER NOT NULL,
            sum_us INTEGER NOT NULL,
            max_us INTEGER NOT NULL,
            buckets_json TEXT NOT NULL
         )",
    )?;
    Ok(())
}

fn ensure_epoch_closed_at_column(conn: &Connection) -> Result<()> {
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('epochs') WHERE name = 'closed_at_ms'",
        [],
        |row| row.get(0),
    )?;
    if present == 0 {
        conn.execute_batch("ALTER TABLE epochs ADD COLUMN closed_at_ms INTEGER")?;
    }
    Ok(())
}

/// A sandbox that has produced no request for this long is "idle": still governed, but quiet.
const SANDBOX_RECENT_ACTIVITY_MS: i64 = 15 * 60_000;
/// An active epoch with no activity for this long is "not seen": its sandbox is most likely gone and the
/// delete event was missed (OpenShell's post-commit hook is fail-open, so a restart or outage can drop one).
const SANDBOX_NOT_SEEN_AFTER_MS: i64 = 6 * 3_600_000;

/// How recently an epoch was seen, from observed evidence only (its creation and its decisions).
fn lifecycle_state(last_activity_ms: i64, now_ms: i64) -> &'static str {
    let age = now_ms.saturating_sub(last_activity_ms);
    if age <= SANDBOX_RECENT_ACTIVITY_MS {
        "recently_active"
    } else if age <= SANDBOX_NOT_SEEN_AFTER_MS {
        "idle"
    } else {
        "not_seen_recently"
    }
}

/// Lifecycle and connectivity as Risk Guard can honestly know them. It learns about sandboxes only from the calls
/// it receives (gateway interceptor events and supervisor requests); it never queries the gateway.
fn lifecycle_overview(
    conn: &Connection,
    now_ms: i64,
) -> Result<(serde_json::Value, serde_json::Value)> {
    let recorded: i64 =
        conn.query_row("SELECT COUNT(DISTINCT sandbox_id) FROM epochs", [], |r| {
            r.get(0)
        })?;
    let active: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT sandbox_id) FROM epochs WHERE active != 0",
        [],
        |r| r.get(0),
    )?;
    let mut recently_active = 0_i64;
    let mut idle = 0_i64;
    let mut not_seen = 0_i64;
    {
        let mut stmt = conn.prepare(
            "SELECT MAX(e.created_at_ms, COALESCE((SELECT MAX(d.created_at_ms) FROM decisions d
                    WHERE d.epoch_id = e.epoch_id), 0))
             FROM epochs e WHERE e.active != 0",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        for last in rows {
            match lifecycle_state(last?, now_ms) {
                "recently_active" => recently_active += 1,
                "idle" => idle += 1,
                _ => not_seen += 1,
            }
        }
    }
    let decisions_total: i64 =
        conn.query_row("SELECT COUNT(*) FROM decisions", [], |r| r.get(0))?;
    let decisions_on_active: i64 = conn.query_row(
        "SELECT COUNT(*) FROM decisions d JOIN epochs e USING(epoch_id) WHERE e.active != 0",
        [],
        |r| r.get(0),
    )?;
    let last_request: Option<i64> =
        conn.query_row("SELECT MAX(created_at_ms) FROM decisions", [], |r| r.get(0))?;
    let last_event: Option<i64> = conn.query_row(
        "SELECT MAX(MAX(created_at_ms), COALESCE(MAX(closed_at_ms), 0)) FROM epochs",
        [],
        |r| r.get(0),
    )?;
    let newest = last_request.into_iter().chain(last_event).max();
    let status = match newest {
        None => "never_seen",
        Some(ts) if now_ms.saturating_sub(ts) <= SANDBOX_RECENT_ACTIVITY_MS => "receiving",
        Some(_) => "quiet",
    };
    let lifecycle = serde_json::json!({
        "source": "gateway_events_and_request_activity",
        "sandboxes_recorded": recorded,
        "sandboxes_with_active_epoch": active,
        "sandboxes_closed": recorded - active,
        "recently_active": recently_active,
        "idle": idle,
        "not_seen_recently": not_seen,
        // The same counts under the names the console uses: open = seen within the window, presumed gone = not seen for it.
        "open": recently_active + idle,
        "presumed_gone": not_seen,
        "recent_activity_window_ms": SANDBOX_RECENT_ACTIVITY_MS,
        "not_seen_after_ms": SANDBOX_NOT_SEEN_AFTER_MS,
        "decisions_recorded": decisions_total,
        "decisions_on_active_epochs": decisions_on_active,
        "note": "Risk Guard learns of sandboxes only from gateway interceptor events and supervisor requests. \
    An epoch with no activity for the not-seen window most likely belongs to a deleted sandbox whose event was missed.",
    });
    let connectivity = serde_json::json!({
        "status": status,
        "last_supervisor_request_ms": last_request,
        "last_gateway_event_ms": last_event.filter(|ts| *ts > 0),
        "evidence": "Inferred from calls Risk Guard has received. It does not probe the gateway.",
    });
    Ok((lifecycle, connectivity))
}

fn state_owner<'a>(epoch: &'a EpochRecord, identity: Option<&'a AgentIdentity>) -> StateOwner<'a> {
    match identity {
        Some(identity) => StateOwner {
            id: &identity.context_id,
            agent: true,
        },
        None => StateOwner {
            id: &epoch.epoch_id,
            agent: false,
        },
    }
}

impl SqliteRiskStore {
    fn evaluate_with_identity(
        &self,
        req: &NormalizedRequest,
        detector: &dyn RiskDetector,
        gateway_id: Option<&str>,
        require_agent: bool,
        source: Option<NativeObservationSource>,
    ) -> Result<RiskEvaluation> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // 1. Look up the active EpochRecord for req.sandbox_id.
        let epoch = query_active_epoch(&tx, &req.sandbox_id)?.ok_or_else(|| {
            RiskGuardError::PermissionDenied(format!(
                "no active epoch for sandbox '{}'",
                req.sandbox_id
            ))
        })?;
        if gateway_id.is_some_and(|gateway| epoch.gateway_id != gateway) {
            return Err(RiskGuardError::PermissionDenied(
                "authenticated gateway does not own sandbox epoch".into(),
            ));
        }
        let identity = resolve_identity(&tx, &epoch)?;
        let identity_required: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM identity_required_sandboxes WHERE sandbox_id = ?1)",
            params![req.sandbox_id],
            |row| row.get(0),
        )?;
        if identity.is_none() && (require_agent || identity_required) {
            return Err(RiskGuardError::PermissionDenied(
                "trusted workload/run binding required; refusing unattributed fallback".into(),
            ));
        }
        if let Some(identity) = &identity {
            let (ended, profile, hash, mode, config): (
                Option<i64>,
                String,
                String,
                String,
                String,
            ) = tx.query_row(
                "SELECT r.ended_at_ms, c.task_profile, c.baseline_hash, c.mode, c.configuration_id
                 FROM agent_runs r JOIN scoring_contexts c USING(context_id) WHERE r.run_id = ?1",
                params![identity.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )?;
            if ended.is_some()
                || profile != epoch.task_profile
                || hash != epoch.baseline_hash
                || mode != epoch.mode.as_str()
                || config != detector.configuration_id()
            {
                return Err(RiskGuardError::PermissionDenied(
                    "run ended or scoring configuration no longer matches its immutable binding"
                        .into(),
                ));
            }
            let pinned_baseline: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM artifacts
                 WHERE artifact_hash = ?1 AND artifact_type = 'baseline_profile')",
                params![hash],
                |row| row.get(0),
            )?;
            if !pinned_baseline {
                return Err(RiskGuardError::Storage(
                    "pinned agent baseline is unavailable".into(),
                ));
            }
        }
        let owner = state_owner(&epoch, identity.as_ref());

        // 2. Check decisions for (epoch.epoch_id, req.request_id).
        if let Some((stored_fingerprint, evaluation_json)) = tx
            .query_row(
                "SELECT fingerprint, evaluation_json
                 FROM decisions
                 WHERE epoch_id = ?1 AND request_id = ?2",
                params![epoch.epoch_id, req.request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if stored_fingerprint == req.fingerprint {
                let eval: RiskEvaluation = serde_json::from_str(&evaluation_json).map_err(|e| {
                    RiskGuardError::Storage(format!("corrupt decision evaluation_json: {e}"))
                })?;
                return Ok(eval);
            }
            return Err(RiskGuardError::ConflictingDuplicateRequestId {
                epoch_id: epoch.epoch_id,
                request_id: req.request_id.clone(),
            });
        }

        let saved_guardrails = identity
            .as_ref()
            .map(|identity| guardrails::query_saved(&tx, &identity.agent_id))
            .transpose()?
            .flatten();
        let base_baseline = load_baseline_for_epoch(&tx, &epoch)?;
        let baseline = if let (Some(saved), Some(identity)) = (&saved_guardrails, &identity) {
            guardrails::effective_baseline(&tx, &identity.agent_id, &base_baseline, saved)?
        } else {
            base_baseline
        };
        let configured_detector = saved_guardrails
            .as_ref()
            .map(|saved| saved.settings.detector());
        let effective_detector: &dyn RiskDetector = match configured_detector.as_ref() {
            Some(configured) => configured,
            None => detector,
        };
        let mut effective_epoch = epoch.clone();
        if let Some(saved) = &saved_guardrails {
            effective_epoch.mode = saved.settings.mode;
        }
        let adaptive_revision = saved_guardrails.as_ref().map_or(0, |saved| saved.revision);
        let adaptive_cooldown_ms = saved_guardrails.as_ref().map_or(300_000, |saved| {
            i64::from(saved.settings.cooldown_seconds) * 1_000
        });

        // 3. Check restrictions for (epoch.epoch_id, req.restriction_scope) AND route-level cooldown scope.
        let route_scope = format!(
            "{}://{}:{} {} {}",
            req.scheme, req.host, req.port, req.method, req.route_template
        );
        let method_scope = format!("{}://{}:{} {}", req.scheme, req.host, req.port, req.method);
        let host_scope = format!("{}://{}:{}", req.scheme, req.host, req.port);

        if let Some(matched) = find_active_restriction(
            &tx,
            owner,
            &req.restriction_scope,
            &route_scope,
            &method_scope,
            &host_scope,
            req.timestamp_ms,
        )? {
            let state_sequence = epoch.next_sequence;
            let next_sequence_i64 = i64::try_from(state_sequence.saturating_add(1))
                .map_err(|_| RiskGuardError::Storage("epoch.next_sequence overflow".to_string()))?;

            tx.execute(
                "UPDATE epochs SET next_sequence = ?1 WHERE epoch_id = ?2",
                params![next_sequence_i64, epoch.epoch_id],
            )?;

            let ratchet_action = if matched.tier == "strict_epoch" {
                RatchetAction::LatchTier1StrictEpoch {
                    scope: matched.scope.clone(),
                }
            } else {
                RatchetAction::None
            };

            let mut eval = RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: epoch.epoch_id.clone(),
                mode: effective_epoch.mode,
                outcome: DecisionOutcome::Deny,
                reason_code: REASON_BEHAVIORAL_RISK_RESTRICTED.to_string(),
                risk_score: 100,
                threshold: saved_guardrails
                    .as_ref()
                    .map_or(70, |saved| saved.settings.enforce_threshold),
                ratchet_action,
                signals: vec![SignalContribution {
                    feature: format!("restriction:{}", matched.tier),
                    observed_summary: matched.scope,
                    baseline_summary: format!("trigger_request_id={}", matched.trigger_request_id),
                    contribution: 100,
                    support: format!(
                        "strikes={},cooldown_until_ms={}",
                        matched.strike_count, matched.cooldown_until_ms
                    ),
                }],
                missing_context: Vec::new(),
                baseline_maturity: baseline.maturity(),
                baseline_hash: if saved_guardrails.is_some() {
                    crate::detector::compute_baseline_hash(&baseline)
                } else {
                    epoch.baseline_hash.clone()
                },
                detector_version: effective_detector.detector_version().to_string(),
                state_sequence,
                decision_timestamp_ms: req.timestamp_ms,
            };

            let window = WindowSnapshot {
                warming: true,
                ..Default::default()
            };
            let adaptive_frame = adaptive::Frame {
                identity: identity.as_ref(),
                revision: adaptive_revision,
                source,
                request: req,
                window: &window,
                cooldown_ms: adaptive_cooldown_ms,
            };
            let base_evaluation = eval.clone();
            let assessments = adaptive::evaluate(&tx, &adaptive_frame, &mut eval)?;
            if let (Some(saved), Some(identity)) = (&saved_guardrails, &identity) {
                guardrails::annotate_revision(&identity.agent_id, saved, &mut eval);
            }
            insert_decision_row(&tx, &epoch.epoch_id, req, &eval)?;
            insert_identity(&tx, req, &epoch, identity.as_ref())?;
            adaptive::record(&tx, &adaptive_frame, &base_evaluation, &assessments)?;
            if let (Some(saved), Some(identity)) = (&saved_guardrails, &identity) {
                guardrails::record_revision(
                    &tx,
                    &epoch.epoch_id,
                    &identity.agent_id,
                    saved,
                    &eval,
                )?;
            }
            if epoch.next_sequence > MAX_RETAINED_DECISIONS_PER_EPOCH as u64
                && epoch.next_sequence % 1_000 == 0
            {
                let _ =
                    prune_epoch_decisions(&tx, &epoch.epoch_id, MAX_RETAINED_DECISIONS_PER_EPOCH)?;
            }
            tx.commit()?;
            return Ok(eval);
        }

        // 4. Load the BaselineProfile for epoch.task_profile.
        // 5. Compute WindowSnapshot from window_buckets in [t - 60_000, t] and [t - 900_000, t].
        let window = compute_window_snapshot(&tx, owner, req.timestamp_ms)?;

        // 6. Check credentialed_endpoint.
        let lower_host = req.host.to_ascii_lowercase();
        let credentialed_endpoint = epoch
            .credentialed_endpoints
            .contains(&(lower_host, req.port))
            || epoch
                .credentialed_endpoints
                .iter()
                .any(|(h, p)| *p == req.port && h.eq_ignore_ascii_case(&req.host));

        // 7. Call detector.evaluate(...).
        let mut eval = effective_detector.evaluate(
            req,
            &DetectorContext {
                epoch: &effective_epoch,
                baseline: &baseline,
                window: &window,
                credentialed_endpoint,
            },
        )?;
        let adaptive_frame = adaptive::Frame {
            identity: identity.as_ref(),
            revision: adaptive_revision,
            source,
            request: req,
            window: &window,
            cooldown_ms: adaptive_cooldown_ms,
        };
        let base_evaluation = eval.clone();
        let assessments = adaptive::evaluate(&tx, &adaptive_frame, &mut eval)?;

        // 8. Set eval.state_sequence = epoch.next_sequence, update epochs.next_sequence = epoch.next_sequence + 1.
        eval.state_sequence = epoch.next_sequence;
        let next_sequence_i64 = i64::try_from(epoch.next_sequence.saturating_add(1))
            .map_err(|_| RiskGuardError::Storage("epoch.next_sequence overflow".to_string()))?;
        tx.execute(
            "UPDATE epochs SET next_sequence = ?1 WHERE epoch_id = ?2",
            params![next_sequence_i64, epoch.epoch_id],
        )?;

        // 9. Update window_buckets (1m and 15m buckets anchored at req.timestamp_ms / 60_000 * 60_000).
        let bucket_start_ms = (req.timestamp_ms / 60_000) * 60_000;
        let resource_token = if !req.resource_key.is_empty() {
            req.resource_key.as_str()
        } else {
            req.resource_id.as_str()
        };
        update_window_bucket(&tx, owner, "1m", bucket_start_ms, resource_token)?;
        update_window_bucket(&tx, owner, "15m", bucket_start_ms, resource_token)?;
        prune_expired_window_buckets(&tx, owner, req.timestamp_ms)?;

        // 10. Apply eval.ratchet_action.
        let seq_i64 = i64::try_from(eval.state_sequence)
            .map_err(|_| RiskGuardError::Storage("eval.state_sequence overflow".to_string()))?;
        match eval.ratchet_action.clone() {
            RatchetAction::None => {}
            RatchetAction::LatchTier1StrictEpoch { scope } => {
                tx.execute(
                    &format!(
                        "INSERT OR REPLACE INTO {} (
                        epoch_id,
                        scope,
                        tier,
                        cooldown_until_ms,
                        strike_count,
                        trigger_request_id,
                        created_sequence
                    ) VALUES (?1, ?2, 'strict_epoch', ?3, 3, ?4, ?5)",
                        owner.restrictions()
                    ),
                    params![owner.id, scope, i64::MAX, req.request_id, seq_i64],
                )?;
            }
            RatchetAction::TriggerTier2Cooldown {
                scope,
                cooldown_duration_ms,
            } => {
                let existing: Option<(String, i64)> = tx
                    .query_row(
                        &format!(
                            "SELECT tier, strike_count
                         FROM {} WHERE epoch_id = ?1 AND scope = ?2",
                            owner.restrictions()
                        ),
                        params![owner.id, scope],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;

                let prev_strikes = existing.as_ref().map_or(0, |(_, strikes)| *strikes);
                let already_strict = existing
                    .as_ref()
                    .is_some_and(|(tier, _)| tier == "strict_epoch");
                let new_strikes = prev_strikes.saturating_add(1);

                let (new_tier, new_cooldown_until_ms) = if already_strict || new_strikes >= 3 {
                    eval.ratchet_action = RatchetAction::LatchTier1StrictEpoch {
                        scope: scope.clone(),
                    };
                    ("strict_epoch", i64::MAX)
                } else {
                    (
                        "cooldown",
                        req.timestamp_ms.saturating_add(cooldown_duration_ms),
                    )
                };

                let persisted_strikes = if new_tier == "strict_epoch" {
                    new_strikes.max(3)
                } else {
                    new_strikes
                };

                tx.execute(
                    &format!(
                        "INSERT OR REPLACE INTO {} (
                        epoch_id,
                        scope,
                        tier,
                        cooldown_until_ms,
                        strike_count,
                        trigger_request_id,
                        created_sequence
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        owner.restrictions()
                    ),
                    params![
                        owner.id,
                        scope,
                        new_tier,
                        new_cooldown_until_ms,
                        persisted_strikes,
                        req.request_id,
                        seq_i64,
                    ],
                )?;
            }
        }

        // 11. Insert the decisions row and COMMIT.
        if let (Some(saved), Some(identity)) = (&saved_guardrails, &identity) {
            guardrails::annotate_revision(&identity.agent_id, saved, &mut eval);
        }
        insert_decision_row(&tx, &epoch.epoch_id, req, &eval)?;
        insert_identity(&tx, req, &epoch, identity.as_ref())?;
        adaptive::record(&tx, &adaptive_frame, &base_evaluation, &assessments)?;
        if let (Some(saved), Some(identity)) = (&saved_guardrails, &identity) {
            guardrails::record_revision(&tx, &epoch.epoch_id, &identity.agent_id, saved, &eval)?;
        }
        if owner.agent {
            let scope = match &eval.ratchet_action {
                RatchetAction::None => None,
                RatchetAction::LatchTier1StrictEpoch { scope }
                | RatchetAction::TriggerTier2Cooldown { scope, .. } => Some(scope),
            };
            if let Some(scope) = scope {
                tx.execute(
                    "INSERT INTO agent_restriction_origins (context_id, scope, epoch_id, request_id)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(context_id, scope) DO UPDATE SET
                       epoch_id = excluded.epoch_id, request_id = excluded.request_id",
                    params![owner.id, scope, epoch.epoch_id, req.request_id],
                )?;
            }
        }
        if epoch.next_sequence > MAX_RETAINED_DECISIONS_PER_EPOCH as u64
            && epoch.next_sequence % 1_000 == 0
        {
            let _ = prune_epoch_decisions(&tx, &epoch.epoch_id, MAX_RETAINED_DECISIONS_PER_EPOCH)?;
        }
        tx.commit()?;
        Ok(eval)
    }

    fn list_stored_decisions(&self, sandbox_id: &str, limit: usize) -> Result<Vec<RiskEvaluation>> {
        let conn = self.lock_read_conn()?;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare(
            "SELECT evaluation_json
             FROM decisions
             WHERE sandbox_id = ?1
             ORDER BY sequence ASC, created_at_ms ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![sandbox_id, limit_i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut evaluations = Vec::new();
        for row in rows {
            let evaluation_json = row?;
            let eval: RiskEvaluation = serde_json::from_str(&evaluation_json).map_err(|e| {
                RiskGuardError::Storage(format!("corrupt decision evaluation_json: {e}"))
            })?;
            evaluations.push(eval);
        }
        Ok(evaluations)
    }

    fn list_stored_requests(
        &self,
        sandbox_id: &str,
    ) -> Result<Vec<(NormalizedRequest, DecisionOutcome)>> {
        let conn = self.lock_read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT normalized_request_json, outcome
             FROM decisions
             WHERE sandbox_id = ?1
             ORDER BY sequence ASC, created_at_ms ASC",
        )?;
        let rows = stmt.query_map(params![sandbox_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (req_json, outcome_raw) = row?;
            let normalized: NormalizedRequest = serde_json::from_str(&req_json).map_err(|e| {
                RiskGuardError::Storage(format!("corrupt normalized_request_json: {e}"))
            })?;
            let outcome = parse_outcome(&outcome_raw)?;
            out.push((normalized, outcome));
        }
        Ok(out)
    }

    fn save_stored_recommendation(&self, candidate: &HardeningCandidate) -> Result<()> {
        let payload_json = serde_json::to_string(candidate)?;
        let created_at_ms = if candidate.interval_end_ms > 0 {
            candidate.interval_end_ms
        } else {
            current_time_ms()
        };

        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO recommendations (
                recommendation_id,
                sandbox_id,
                epoch_id,
                payload_json,
                created_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                candidate.recommendation_id,
                candidate.sandbox_id,
                candidate.epoch_id,
                payload_json,
                created_at_ms,
            ],
        )?;
        Ok(())
    }
}

fn query_active_epoch(conn: &Connection, sandbox_id: &str) -> Result<Option<EpochRecord>> {
    let row = conn
        .query_row(
            "SELECT
                epoch_id,
                gateway_id,
                sandbox_id,
                task_profile,
                baseline_hash,
                mode,
                active,
                next_sequence,
                created_at_ms,
                credentialed_endpoints_json,
                active_policy_hash
             FROM epochs
             WHERE sandbox_id = ?1 AND active != 0
             ORDER BY created_at_ms DESC, rowid DESC
             LIMIT 1",
            params![sandbox_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .optional()?;

    let Some((
        epoch_id,
        gateway_id,
        sandbox_id,
        task_profile,
        baseline_hash,
        mode_raw,
        active_raw,
        next_sequence_raw,
        created_at_ms,
        credentialed_endpoints_json,
        active_policy_hash,
    )) = row
    else {
        return Ok(None);
    };

    let mode = parse_enforcement_mode(&mode_raw)?;
    let next_sequence = u64::try_from(next_sequence_raw).map_err(|_| {
        RiskGuardError::Storage(format!(
            "negative next_sequence in database: {next_sequence_raw}"
        ))
    })?;
    let credentialed_endpoints: BTreeSet<(String, u16)> =
        serde_json::from_str(&credentialed_endpoints_json).map_err(|e| {
            RiskGuardError::Storage(format!("corrupt credentialed_endpoints_json: {e}"))
        })?;

    Ok(Some(EpochRecord {
        epoch_id,
        gateway_id,
        sandbox_id,
        task_profile,
        baseline_hash,
        mode,
        active: active_raw != 0,
        next_sequence,
        created_at_ms,
        credentialed_endpoints,
        active_policy_hash,
    }))
}

fn query_baseline_by_name_or_hash(
    conn: &Connection,
    task_profile: &str,
    baseline_hash: &str,
) -> Result<Option<BaselineProfile>> {
    let payload_json: Option<String> = conn
        .query_row(
            "SELECT payload_json
             FROM artifacts
             WHERE artifact_type = 'baseline_profile'
               AND (name = ?1 OR artifact_hash = ?2)
             ORDER BY CASE WHEN artifact_hash = ?2 THEN 0 ELSE 1 END,
                      created_at_ms DESC,
                      rowid DESC
             LIMIT 1",
            params![task_profile, baseline_hash],
            |row| row.get(0),
        )
        .optional()?;

    match payload_json {
        Some(raw) => {
            let profile: BaselineProfile = serde_json::from_str(&raw).map_err(|e| {
                RiskGuardError::Storage(format!("corrupt baseline payload_json: {e}"))
            })?;
            Ok(Some(profile))
        }
        None => Ok(None),
    }
}

fn load_baseline_for_epoch(conn: &Connection, epoch: &EpochRecord) -> Result<BaselineProfile> {
    if let Some(profile) =
        query_baseline_by_name_or_hash(conn, &epoch.task_profile, &epoch.baseline_hash)?
    {
        return Ok(profile);
    }

    Ok(BaselineProfile {
        task_profile: epoch.task_profile.clone(),
        version: "0.0.0-cold-start".to_string(),
        approved_by: "unapproved-cold-start".to_string(),
        normalizer_version: "v1".to_string(),
        training_sessions: 0,
        training_requests: 0,
        expected_binaries: BTreeSet::new(),
        approved_resources: BTreeSet::new(),
        allowed_action_classes: BTreeSet::new(),
        forbidden_action_classes: BTreeSet::new(),
        forbid_unfamiliar_high_impact: false,
        rule_modes: std::collections::BTreeMap::new(),
        approved_egress_hosts: Default::default(),
        max_req_1m_p95: 0,
        max_req_1m_p99: 0,
        max_distinct_resources_15m_p95: 0,
        max_distinct_resources_15m_p99: 0,
    })
}

fn find_active_restriction(
    conn: &Connection,
    owner: StateOwner<'_>,
    restriction_scope: &str,
    route_scope: &str,
    method_scope: &str,
    host_scope: &str,
    timestamp_ms: i64,
) -> Result<Option<MatchedRestriction>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT scope, tier, cooldown_until_ms, strike_count, trigger_request_id
         FROM {}
         WHERE epoch_id = ?1 AND scope IN (?2, ?3, ?4, ?5)
         ORDER BY CASE WHEN tier = 'strict_epoch' THEN 0 ELSE 1 END,
                  created_sequence ASC",
        owner.restrictions()
    ))?;
    let rows = stmt.query_map(
        params![
            owner.id,
            restriction_scope,
            route_scope,
            method_scope,
            host_scope
        ],
        |row| {
            Ok(MatchedRestriction {
                scope: row.get(0)?,
                tier: row.get(1)?,
                cooldown_until_ms: row.get(2)?,
                strike_count: row.get(3)?,
                trigger_request_id: row.get(4)?,
            })
        },
    )?;

    for row in rows {
        let candidate = row?;
        if candidate.tier == "strict_epoch"
            || (candidate.tier == "cooldown" && candidate.cooldown_until_ms > timestamp_ms)
        {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn compute_window_snapshot(
    conn: &Connection,
    owner: StateOwner<'_>,
    timestamp_ms: i64,
) -> Result<WindowSnapshot> {
    let (req_count_1m, distinct_resources_1m) = query_window_range(
        conn,
        owner,
        "1m",
        timestamp_ms.saturating_sub(60_000),
        timestamp_ms,
    )?;
    let (req_count_15m, distinct_resources_15m) = query_window_range(
        conn,
        owner,
        "15m",
        timestamp_ms.saturating_sub(900_000),
        timestamp_ms,
    )?;

    Ok(WindowSnapshot {
        req_count_1m,
        req_count_15m,
        distinct_resources_1m,
        distinct_resources_15m,
        warming: false,
    })
}

fn query_window_range(
    conn: &Connection,
    owner: StateOwner<'_>,
    bucket_kind: &str,
    min_bucket_start_ms: i64,
    max_bucket_start_ms: i64,
) -> Result<(u32, u32)> {
    let mut stmt = conn.prepare(&format!(
        "SELECT req_count, resources_json
         FROM {}
         WHERE epoch_id = ?1
           AND bucket_kind = ?2
           AND bucket_start_ms >= ?3
           AND bucket_start_ms <= ?4",
        owner.windows()
    ))?;
    let rows = stmt.query_map(
        params![
            owner.id,
            bucket_kind,
            min_bucket_start_ms,
            max_bucket_start_ms
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )?;

    let mut total_count: u32 = 0;
    let mut distinct_resources = BTreeSet::new();
    for row in rows {
        let (req_count_raw, resources_json) = row?;
        let count_u32 = u32::try_from(req_count_raw.max(0)).unwrap_or(u32::MAX);
        total_count = total_count.saturating_add(count_u32);
        let bucket_resources: BTreeSet<String> =
            serde_json::from_str(&resources_json).map_err(|e| {
                RiskGuardError::Storage(format!("corrupt window_buckets resources_json: {e}"))
            })?;
        for res in bucket_resources {
            if distinct_resources.len() < MAX_BUCKET_RESOURCES {
                distinct_resources.insert(res);
            }
        }
    }

    let distinct_len = u32::try_from(distinct_resources.len()).unwrap_or(u32::MAX);
    Ok((total_count, distinct_len))
}

fn update_window_bucket(
    tx: &Transaction<'_>,
    owner: StateOwner<'_>,
    bucket_kind: &str,
    bucket_start_ms: i64,
    resource_token: &str,
) -> Result<()> {
    let existing: Option<(i64, String)> = tx
        .query_row(
            &format!(
                "SELECT req_count, resources_json
             FROM {} WHERE epoch_id = ?1 AND bucket_kind = ?2 AND bucket_start_ms = ?3",
                owner.windows()
            ),
            params![owner.id, bucket_kind, bucket_start_ms],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let (new_count, mut resources) = match existing {
        Some((count, resources_json)) => {
            let parsed: BTreeSet<String> = serde_json::from_str(&resources_json).map_err(|e| {
                RiskGuardError::Storage(format!("corrupt window_buckets resources_json: {e}"))
            })?;
            (count.saturating_add(1), parsed)
        }
        None => (1_i64, BTreeSet::new()),
    };

    if !resource_token.is_empty() && resources.len() < MAX_BUCKET_RESOURCES {
        resources.insert(resource_token.to_string());
    }
    let resources_json = serde_json::to_string(&resources)?;

    tx.execute(
        &format!(
            "INSERT OR REPLACE INTO {} (
            epoch_id,
            bucket_kind,
            bucket_start_ms,
            req_count,
            resources_json
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
            owner.windows()
        ),
        params![
            owner.id,
            bucket_kind,
            bucket_start_ms,
            new_count,
            resources_json
        ],
    )?;
    Ok(())
}

fn prune_expired_window_buckets(
    tx: &Transaction<'_>,
    owner: StateOwner<'_>,
    timestamp_ms: i64,
) -> Result<()> {
    let cutoff_ms = timestamp_ms.saturating_sub(WINDOW_RETENTION_MS);
    tx.execute(
        &format!(
            "DELETE FROM {} WHERE epoch_id = ?1 AND bucket_start_ms < ?2",
            owner.windows()
        ),
        params![owner.id, cutoff_ms],
    )?;
    Ok(())
}

fn prune_epoch_decisions(
    tx: &Transaction<'_>,
    epoch_id: &str,
    max_per_epoch: usize,
) -> Result<usize> {
    let keep_limit = i64::try_from(max_per_epoch).unwrap_or(i64::MAX);
    let prunable_request_ids = {
        let mut stmt = tx.prepare(
            "SELECT d.request_id
             FROM decisions d
             WHERE d.epoch_id = ?1
               AND d.request_id NOT IN (
                   SELECT request_id
                   FROM decisions
                   WHERE epoch_id = ?1
                   ORDER BY sequence DESC
                   LIMIT ?2
               )
               AND NOT EXISTS (
                   SELECT 1 FROM adaptive_observations ao
                   WHERE ao.epoch_id = d.epoch_id AND ao.request_id = d.request_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM agent_restriction_origins aro
                   WHERE aro.epoch_id = d.epoch_id AND aro.request_id = d.request_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM restrictions r
                   WHERE r.epoch_id = d.epoch_id AND r.trigger_request_id = d.request_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM agent_restrictions ar
                   WHERE ar.trigger_request_id = d.request_id
               )
             ORDER BY d.sequence ASC",
        )?;
        stmt.query_map(params![epoch_id, keep_limit], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };

    let mut deleted = 0usize;
    for request_id in prunable_request_ids {
        deleted += delete_decision_row(tx, epoch_id, &request_id)?;
    }
    Ok(deleted)
}

/// Delete one decision and the rows that hang off it. Callers must have checked that nothing pins the decision.
fn delete_decision_row(tx: &Transaction<'_>, epoch_id: &str, request_id: &str) -> Result<usize> {
    tx.execute(
        "DELETE FROM decision_guardrail_revisions WHERE epoch_id = ?1 AND request_id = ?2",
        params![epoch_id, request_id],
    )?;
    tx.execute(
        "DELETE FROM adaptive_assessments WHERE epoch_id = ?1 AND request_id = ?2",
        params![epoch_id, request_id],
    )?;
    tx.execute(
        "DELETE FROM native_decision_provenance WHERE epoch_id = ?1 AND request_id = ?2",
        params![epoch_id, request_id],
    )?;
    tx.execute(
        "DELETE FROM decision_identity WHERE epoch_id = ?1 AND request_id = ?2",
        params![epoch_id, request_id],
    )?;
    Ok(tx.execute(
        "DELETE FROM decisions WHERE epoch_id = ?1 AND request_id = ?2",
        params![epoch_id, request_id],
    )?)
}

/// Decisions that something still depends on are never pruned: adaptive training data, restriction origins and the
/// request that triggered a lock. Appended to a query over `decisions d`.
const UNPINNED_DECISION_SQL: &str = "
    AND NOT EXISTS (SELECT 1 FROM adaptive_observations ao
                    WHERE ao.epoch_id = d.epoch_id AND ao.request_id = d.request_id)
    AND NOT EXISTS (SELECT 1 FROM agent_restriction_origins aro
                    WHERE aro.epoch_id = d.epoch_id AND aro.request_id = d.request_id)
    AND NOT EXISTS (SELECT 1 FROM restrictions r
                    WHERE r.epoch_id = d.epoch_id AND r.trigger_request_id = d.request_id)
    AND NOT EXISTS (SELECT 1 FROM agent_restrictions ar WHERE ar.trigger_request_id = d.request_id)";

fn insert_identity(
    tx: &Transaction<'_>,
    req: &NormalizedRequest,
    epoch: &EpochRecord,
    identity: Option<&AgentIdentity>,
) -> Result<()> {
    if let Some(identity) = identity {
        tx.execute(
            "INSERT INTO decision_identity (epoch_id, request_id, run_id) VALUES (?1, ?2, ?3)",
            params![epoch.epoch_id, req.request_id, identity.run_id],
        )?;
    }
    Ok(())
}

fn insert_decision_row(
    tx: &Transaction<'_>,
    epoch_id: &str,
    req: &NormalizedRequest,
    eval: &RiskEvaluation,
) -> Result<()> {
    let normalized_request_json = serde_json::to_string(req)?;
    let evaluation_json = serde_json::to_string(eval)?;
    let sequence_i64 = i64::try_from(eval.state_sequence)
        .map_err(|_| RiskGuardError::Storage("eval.state_sequence overflows i64".to_string()))?;
    let risk_score_i64 = i64::from(eval.risk_score);

    tx.execute(
        "INSERT INTO decisions (
            epoch_id,
            request_id,
            sandbox_id,
            sequence,
            fingerprint,
            normalized_request_json,
            evaluation_json,
            outcome,
            risk_score,
            created_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            epoch_id,
            req.request_id,
            req.sandbox_id,
            sequence_i64,
            req.fingerprint,
            normalized_request_json,
            evaluation_json,
            outcome_as_str(eval.outcome),
            risk_score_i64,
            req.timestamp_ms,
        ],
    )?;
    Ok(())
}

fn parse_enforcement_mode(raw: &str) -> Result<EnforcementMode> {
    match raw {
        "observe" => Ok(EnforcementMode::Observe),
        "enforce" => Ok(EnforcementMode::Enforce),
        other => Err(RiskGuardError::Storage(format!(
            "invalid enforcement mode in database: '{other}'"
        ))),
    }
}

const fn outcome_as_str(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "allow",
        DecisionOutcome::AllowWithObservation => "allow_with_observation",
        DecisionOutcome::Deny => "deny",
    }
}

fn parse_outcome(raw: &str) -> Result<DecisionOutcome> {
    match raw {
        "allow" => Ok(DecisionOutcome::Allow),
        "allow_with_observation" => Ok(DecisionOutcome::AllowWithObservation),
        "deny" => Ok(DecisionOutcome::Deny),
        other => Err(RiskGuardError::Storage(format!(
            "invalid decision outcome in database: '{other}'"
        ))),
    }
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::types::{
        BaselineMaturity, REASON_BEHAVIORAL_RISK_DENIED, REASON_BEHAVIORAL_RISK_RESTRICTED,
        TwoStepProofResult,
    };

    struct ScriptedDetector<F> {
        calls: AtomicUsize,
        last_window: Mutex<Option<WindowSnapshot>>,
        last_credentialed: Mutex<Option<bool>>,
        handler: F,
    }

    impl<F> ScriptedDetector<F>
    where
        F: Fn(&NormalizedRequest, &DetectorContext<'_>) -> Result<RiskEvaluation> + Send + Sync,
    {
        fn new(handler: F) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                last_window: Mutex::new(None),
                last_credentialed: Mutex::new(None),
                handler,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn take_last_window(&self) -> Option<WindowSnapshot> {
            self.last_window.lock().unwrap().clone()
        }

        fn take_last_credentialed(&self) -> Option<bool> {
            *self.last_credentialed.lock().unwrap()
        }
    }

    impl<F> RiskDetector for ScriptedDetector<F>
    where
        F: Fn(&NormalizedRequest, &DetectorContext<'_>) -> Result<RiskEvaluation> + Send + Sync,
    {
        fn evaluate(
            &self,
            req: &NormalizedRequest,
            ctx: &DetectorContext<'_>,
        ) -> Result<RiskEvaluation> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last_window.lock().unwrap() = Some(ctx.window.clone());
            *self.last_credentialed.lock().unwrap() = Some(ctx.credentialed_endpoint);
            (self.handler)(req, ctx)
        }

        fn detector_version(&self) -> &str {
            "test-detector-v1"
        }
    }

    fn sample_epoch(sandbox_id: &str) -> EpochRecord {
        let mut credentialed_endpoints = BTreeSet::new();
        credentialed_endpoints.insert(("api.github.local".to_string(), 18443));
        EpochRecord {
            epoch_id: format!("ep-{sandbox_id}"),
            gateway_id: "gw-test".to_string(),
            sandbox_id: sandbox_id.to_string(),
            task_profile: "repo-triage-readonly".to_string(),
            baseline_hash: "sha256:baseline-01".to_string(),
            mode: EnforcementMode::Enforce,
            active: true,
            next_sequence: 1,
            created_at_ms: 1_700_000_000_000,
            credentialed_endpoints,
            active_policy_hash: Some("sha256:policy-01".to_string()),
        }
    }

    fn sample_baseline() -> BaselineProfile {
        let mut expected_binaries = BTreeSet::new();
        expected_binaries.insert("/usr/bin/curl".to_string());
        let mut approved_resources = BTreeSet::new();
        approved_resources.insert("org/docs-site".to_string());
        let mut allowed_action_classes = BTreeSet::new();
        allowed_action_classes.insert("GET /repos/{owner}/{repo}".to_string());

        BaselineProfile {
            task_profile: "repo-triage-readonly".to_string(),
            version: "1.0.0".to_string(),
            approved_by: "secops@nvidia.com".to_string(),
            normalizer_version: "v1".to_string(),
            training_sessions: 25,
            training_requests: 500,
            expected_binaries,
            approved_resources,
            allowed_action_classes,
            forbidden_action_classes: BTreeSet::new(),
            forbid_unfamiliar_high_impact: true,
            rule_modes: std::collections::BTreeMap::new(),
            approved_egress_hosts: Default::default(),
            max_req_1m_p95: 10,
            max_req_1m_p99: 20,
            max_distinct_resources_15m_p95: 3,
            max_distinct_resources_15m_p99: 5,
        }
    }

    fn sample_request(
        request_id: &str,
        sandbox_id: &str,
        method: &str,
        route_template: &str,
        resource_id: &str,
        timestamp_ms: i64,
        fingerprint: &str,
    ) -> NormalizedRequest {
        NormalizedRequest {
            request_id: request_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            scheme: "https".to_string(),
            host: "api.github.local".to_string(),
            port: 18443,
            method: method.to_string(),
            route_template: route_template.to_string(),
            resource_id: resource_id.to_string(),
            resource_key: format!("rk:{resource_id}"),
            action_class: format!("{method} {route_template}"),
            restriction_scope: format!(
                "https://api.github.local:18443 {method} {route_template} {resource_id}"
            ),
            high_impact: method == "DELETE",
            semantic_category: if method == "DELETE" {
                "destructive_admin".to_string()
            } else {
                "read_only".to_string()
            },
            binary_path: Some("/usr/bin/curl".to_string()),
            ancestors: vec!["/bin/sh".to_string()],
            fingerprint: fingerprint.to_string(),
            timestamp_ms,
        }
    }

    #[test]
    fn test_verify_pragmas_on_disk_wal_full_fk() {
        let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        let store = SqliteRiskStore::open(tmp.path()).expect("open on-disk store");
        let (journal_mode, synchronous, foreign_keys) =
            store.verify_pragmas().expect("verify pragmas");

        assert_eq!(journal_mode, "wal");
        assert_eq!(synchronous, 2); // FULL = 2
        assert_eq!(foreign_keys, 1);
    }

    #[test]
    fn test_idempotent_duplicate_request_id_does_not_double_count() {
        let store = SqliteRiskStore::open_in_memory().expect("open in-memory store");
        let epoch = sample_epoch("sbx-dup");
        store.upsert_epoch(&epoch).expect("upsert epoch");
        store
            .store_baseline(&sample_baseline())
            .expect("store baseline");

        let detector = ScriptedDetector::new(|req, ctx| {
            Ok(RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: ctx.epoch.epoch_id.clone(),
                mode: ctx.epoch.mode,
                outcome: DecisionOutcome::Allow,
                reason_code: "ok".to_string(),
                risk_score: 10,
                threshold: 70,
                ratchet_action: RatchetAction::None,
                signals: Vec::new(),
                missing_context: Vec::new(),
                baseline_maturity: ctx.baseline.maturity(),
                baseline_hash: ctx.epoch.baseline_hash.clone(),
                detector_version: "test-detector-v1".to_string(),
                state_sequence: 0,
                decision_timestamp_ms: req.timestamp_ms,
            })
        });

        let req1 = sample_request(
            "req-001",
            "sbx-dup",
            "GET",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            1_700_000_010_000,
            "fp-req-001",
        );

        let first_eval = store
            .evaluate_and_commit_atomic(&req1, &detector)
            .expect("first eval");
        assert_eq!(first_eval.state_sequence, 1);
        assert_eq!(detector.call_count(), 1);
        assert_eq!(detector.take_last_credentialed(), Some(true));
        let w1 = detector.take_last_window().expect("window 1");
        assert_eq!(w1.req_count_1m, 0);
        assert_eq!(w1.distinct_resources_1m, 0);

        // Replay identical request_id + fingerprint: must return cached evaluation without calling detector
        // or incrementing state_sequence / window_buckets.
        let replay_eval = store
            .evaluate_and_commit_atomic(&req1, &detector)
            .expect("replay eval");
        assert_eq!(replay_eval, first_eval);
        assert_eq!(detector.call_count(), 1);

        let active_epoch = store
            .get_active_epoch("sbx-dup")
            .expect("get epoch")
            .expect("active epoch exists");
        assert_eq!(active_epoch.next_sequence, 2);

        // Subsequent distinct request must see req_count_1m == 1 (not 2) and state_sequence == 2.
        let req2 = sample_request(
            "req-002",
            "sbx-dup",
            "GET",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            1_700_000_020_000,
            "fp-req-002",
        );
        let second_eval = store
            .evaluate_and_commit_atomic(&req2, &detector)
            .expect("second eval");
        assert_eq!(second_eval.state_sequence, 2);
        assert_eq!(detector.call_count(), 2);
        let w2 = detector.take_last_window().expect("window 2");
        assert_eq!(w2.req_count_1m, 1);
        assert_eq!(w2.req_count_15m, 1);
        assert_eq!(w2.distinct_resources_1m, 1);
        assert_eq!(w2.distinct_resources_15m, 1);
    }

    #[test]
    fn test_conflicting_duplicate_request_id_rejected() {
        let store = SqliteRiskStore::open_in_memory().expect("open in-memory store");
        store
            .upsert_epoch(&sample_epoch("sbx-conflict"))
            .expect("upsert epoch");

        let detector = ScriptedDetector::new(|req, ctx| {
            Ok(RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: ctx.epoch.epoch_id.clone(),
                mode: ctx.epoch.mode,
                outcome: DecisionOutcome::Allow,
                reason_code: "ok".to_string(),
                risk_score: 0,
                threshold: 70,
                ratchet_action: RatchetAction::None,
                signals: Vec::new(),
                missing_context: Vec::new(),
                baseline_maturity: BaselineMaturity::Mature,
                baseline_hash: ctx.epoch.baseline_hash.clone(),
                detector_version: "test-detector-v1".to_string(),
                state_sequence: 0,
                decision_timestamp_ms: req.timestamp_ms,
            })
        });

        let req_a = sample_request(
            "req-dup-conflict",
            "sbx-conflict",
            "GET",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            1_700_000_010_000,
            "fp-original",
        );
        store
            .evaluate_and_commit_atomic(&req_a, &detector)
            .expect("initial evaluation succeeds");

        let mut req_b = req_a.clone();
        req_b.fingerprint = "fp-tampered".to_string();

        let err = store
            .evaluate_and_commit_atomic(&req_b, &detector)
            .expect_err("conflicting duplicate must fail");
        match err {
            RiskGuardError::ConflictingDuplicateRequestId {
                epoch_id,
                request_id,
            } => {
                assert_eq!(epoch_id, "ep-sbx-conflict");
                assert_eq!(request_id, "req-dup-conflict");
            }
            other => panic!("expected ConflictingDuplicateRequestId, got {other:?}"),
        }
    }

    #[test]
    fn test_tier1_strict_epoch_persists_across_reopen_and_blocks() {
        let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        let db_path = tmp.path().to_path_buf();

        let deny_detector = ScriptedDetector::new(|req, ctx| {
            Ok(RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: ctx.epoch.epoch_id.clone(),
                mode: ctx.epoch.mode,
                outcome: DecisionOutcome::Deny,
                reason_code: REASON_BEHAVIORAL_RISK_DENIED.to_string(),
                risk_score: 85,
                threshold: 70,
                ratchet_action: RatchetAction::LatchTier1StrictEpoch {
                    scope: req.restriction_scope.clone(),
                },
                signals: Vec::new(),
                missing_context: Vec::new(),
                baseline_maturity: BaselineMaturity::Mature,
                baseline_hash: ctx.epoch.baseline_hash.clone(),
                detector_version: "test-detector-v1".to_string(),
                state_sequence: 0,
                decision_timestamp_ms: req.timestamp_ms,
            })
        });

        {
            let store = SqliteRiskStore::open(&db_path).expect("open store first time");
            store
                .upsert_epoch(&sample_epoch("sbx-tier1"))
                .expect("upsert epoch");

            let req1 = sample_request(
                "req-del-1",
                "sbx-tier1",
                "DELETE",
                "/repos/{owner}/{repo}",
                "org/payments-prod",
                1_700_000_010_000,
                "fp-del-1",
            );
            let eval1 = store
                .evaluate_and_commit_atomic(&req1, &deny_detector)
                .expect("eval1");
            assert_eq!(eval1.outcome, DecisionOutcome::Deny);
            assert_eq!(eval1.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
            assert_eq!(eval1.state_sequence, 1);
        }

        // Reopen the SQLite file and verify the Tier 1 restriction persists and short-circuits
        // before calling the detector.
        let allow_detector = ScriptedDetector::new(|req, ctx| {
            Ok(RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: ctx.epoch.epoch_id.clone(),
                mode: ctx.epoch.mode,
                outcome: DecisionOutcome::Allow,
                reason_code: "ok".to_string(),
                risk_score: 0,
                threshold: 70,
                ratchet_action: RatchetAction::None,
                signals: Vec::new(),
                missing_context: Vec::new(),
                baseline_maturity: BaselineMaturity::Mature,
                baseline_hash: ctx.epoch.baseline_hash.clone(),
                detector_version: "test-detector-v1".to_string(),
                state_sequence: 0,
                decision_timestamp_ms: req.timestamp_ms,
            })
        });

        let reopened_store = SqliteRiskStore::open(&db_path).expect("reopen store");
        let req2 = sample_request(
            "req-del-2",
            "sbx-tier1",
            "DELETE",
            "/repos/{owner}/{repo}",
            "org/payments-prod",
            1_700_050_000_000,
            "fp-del-2",
        );
        let eval2 = reopened_store
            .evaluate_and_commit_atomic(&req2, &allow_detector)
            .expect("eval2 after reopen");
        assert_eq!(eval2.outcome, DecisionOutcome::Deny);
        assert_eq!(eval2.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
        assert_eq!(eval2.risk_score, 100);
        assert_eq!(eval2.state_sequence, 2);
        assert_eq!(allow_detector.call_count(), 0);
    }

    #[test]
    fn test_tier2_cooldown_window_expiry_and_promotion_to_tier1_on_third_strike() {
        let store = SqliteRiskStore::open_in_memory().expect("open in-memory store");
        store
            .upsert_epoch(&sample_epoch("sbx-tier2"))
            .expect("upsert epoch");

        let route_scope = "https://api.github.local:18443 GET /repos/{owner}/{repo}".to_string();
        let route_scope_for_detector = route_scope.clone();

        // Detector triggers Tier 2 cooldown (duration 300_000 ms) whenever req_id starts with "burst-",
        // otherwise allows.
        let detector = ScriptedDetector::new(move |req, ctx| {
            if req.request_id.starts_with("burst-") {
                Ok(RiskEvaluation {
                    request_id: req.request_id.clone(),
                    sandbox_id: req.sandbox_id.clone(),
                    epoch_id: ctx.epoch.epoch_id.clone(),
                    mode: ctx.epoch.mode,
                    outcome: DecisionOutcome::Deny,
                    reason_code: REASON_BEHAVIORAL_RISK_DENIED.to_string(),
                    risk_score: 80,
                    threshold: 70,
                    ratchet_action: RatchetAction::TriggerTier2Cooldown {
                        scope: route_scope_for_detector.clone(),
                        cooldown_duration_ms: 300_000,
                    },
                    signals: Vec::new(),
                    missing_context: Vec::new(),
                    baseline_maturity: BaselineMaturity::Mature,
                    baseline_hash: ctx.epoch.baseline_hash.clone(),
                    detector_version: "test-detector-v1".to_string(),
                    state_sequence: 0,
                    decision_timestamp_ms: req.timestamp_ms,
                })
            } else {
                Ok(RiskEvaluation {
                    request_id: req.request_id.clone(),
                    sandbox_id: req.sandbox_id.clone(),
                    epoch_id: ctx.epoch.epoch_id.clone(),
                    mode: ctx.epoch.mode,
                    outcome: DecisionOutcome::Allow,
                    reason_code: "ok".to_string(),
                    risk_score: 5,
                    threshold: 70,
                    ratchet_action: RatchetAction::None,
                    signals: Vec::new(),
                    missing_context: Vec::new(),
                    baseline_maturity: BaselineMaturity::Mature,
                    baseline_hash: ctx.epoch.baseline_hash.clone(),
                    detector_version: "test-detector-v1".to_string(),
                    state_sequence: 0,
                    decision_timestamp_ms: req.timestamp_ms,
                })
            }
        });

        let t0 = 1_700_000_000_000_i64;

        // Strike 1 at t0 -> cooldown_until_ms = t0 + 300_000
        let strike1 = sample_request(
            "burst-1",
            "sbx-tier2",
            "GET",
            "/repos/{owner}/{repo}",
            "org/repo-1",
            t0,
            "fp-burst-1",
        );
        let eval_s1 = store
            .evaluate_and_commit_atomic(&strike1, &detector)
            .expect("strike 1");
        assert_eq!(eval_s1.outcome, DecisionOutcome::Deny);
        assert_eq!(eval_s1.reason_code, REASON_BEHAVIORAL_RISK_DENIED);
        assert_eq!(
            eval_s1.ratchet_action,
            RatchetAction::TriggerTier2Cooldown {
                scope: route_scope.clone(),
                cooldown_duration_ms: 300_000,
            }
        );

        // Request during cooldown window (t0 + 100_000 < t0 + 300_000) must be blocked by restriction.
        let during_cd = sample_request(
            "benign-during-cd",
            "sbx-tier2",
            "GET",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            t0 + 100_000,
            "fp-during-cd",
        );
        let eval_during = store
            .evaluate_and_commit_atomic(&during_cd, &detector)
            .expect("during cooldown");
        assert_eq!(eval_during.outcome, DecisionOutcome::Deny);
        assert_eq!(eval_during.reason_code, REASON_BEHAVIORAL_RISK_RESTRICTED);
        assert_eq!(detector.call_count(), 1); // detector was not invoked while restricted

        // Request after cooldown expiry (t0 + 300_001 > t0 + 300_000) is evaluated and allowed!
        let after_cd = sample_request(
            "benign-after-cd",
            "sbx-tier2",
            "GET",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            t0 + 300_001,
            "fp-after-cd",
        );
        let eval_after = store
            .evaluate_and_commit_atomic(&after_cd, &detector)
            .expect("after cooldown");
        assert_eq!(eval_after.outcome, DecisionOutcome::Allow);
        assert_eq!(detector.call_count(), 2);

        // Strike 2 at t1 = t0 + 400_000 -> cooldown_until_ms = t1 + 300_000
        let t1 = t0 + 400_000;
        let strike2 = sample_request(
            "burst-2",
            "sbx-tier2",
            "GET",
            "/repos/{owner}/{repo}",
            "org/repo-2",
            t1,
            "fp-burst-2",
        );
        let eval_s2 = store
            .evaluate_and_commit_atomic(&strike2, &detector)
            .expect("strike 2");
        assert_eq!(eval_s2.outcome, DecisionOutcome::Deny);
        assert_eq!(
            eval_s2.ratchet_action,
            RatchetAction::TriggerTier2Cooldown {
                scope: route_scope.clone(),
                cooldown_duration_ms: 300_000,
            }
        );

        // Strike 3 after second cooldown expires (t2 = t1 + 400_000) -> promotes to LatchTier1StrictEpoch!
        let t2 = t1 + 400_000;
        let strike3 = sample_request(
            "burst-3",
            "sbx-tier2",
            "GET",
            "/repos/{owner}/{repo}",
            "org/repo-3",
            t2,
            "fp-burst-3",
        );
        let eval_s3 = store
            .evaluate_and_commit_atomic(&strike3, &detector)
            .expect("strike 3");
        assert_eq!(eval_s3.outcome, DecisionOutcome::Deny);
        assert_eq!(
            eval_s3.ratchet_action,
            RatchetAction::LatchTier1StrictEpoch {
                scope: route_scope.clone(),
            }
        );

        // Even far in the future (t2 + 10_000_000), the promoted strict_epoch restriction blocks requests.
        let calls_before = detector.call_count();
        let after_promo = sample_request(
            "benign-after-promo",
            "sbx-tier2",
            "GET",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            t2 + 10_000_000,
            "fp-after-promo",
        );
        let eval_after_promo = store
            .evaluate_and_commit_atomic(&after_promo, &detector)
            .expect("after promotion");
        assert_eq!(eval_after_promo.outcome, DecisionOutcome::Deny);
        assert_eq!(
            eval_after_promo.reason_code,
            REASON_BEHAVIORAL_RISK_RESTRICTED
        );
        assert_eq!(detector.call_count(), calls_before);
    }

    #[test]
    fn test_auxiliary_store_operations() {
        let store = SqliteRiskStore::open_in_memory().expect("open in-memory store");
        let epoch = sample_epoch("sbx-aux");
        store.upsert_epoch(&epoch).expect("upsert epoch");

        let baseline = sample_baseline();
        let hash = store.store_baseline(&baseline).expect("store baseline");
        assert!(!hash.is_empty());
        let loaded = store
            .get_baseline(&baseline.task_profile)
            .expect("get baseline")
            .expect("baseline present");
        assert_eq!(loaded, baseline);

        let mut creds = BTreeSet::new();
        creds.insert(("api.internal.local".to_string(), 8443));
        store
            .record_policy_snapshot(
                "sbx-aux",
                "sha256:pol-2",
                "version: 1\n",
                &creds,
                "post_commit",
                1_700_000_050_000,
            )
            .expect("record snapshot");
        let snap = store
            .latest_policy_snapshot("sbx-aux")
            .expect("latest snapshot")
            .expect("snapshot exists");
        assert_eq!(
            snap,
            ("sha256:pol-2".to_string(), "version: 1\n".to_string())
        );

        store
            .record_coverage_gap("sbx-aux", "stream_lag", 100, 200)
            .expect("record gap");
        let gaps = store.list_coverage_gaps("sbx-aux").expect("list gaps");
        assert_eq!(gaps, vec![("stream_lag".to_string(), 100, 200)]);

        let candidate = HardeningCandidate {
            recommendation_id: "rec-01".to_string(),
            sandbox_id: "sbx-aux".to_string(),
            epoch_id: epoch.epoch_id.clone(),
            interval_start_ms: 1000,
            interval_end_ms: 2000,
            observed_requests: 5,
            completeness_ok: true,
            coverage_gaps: Vec::new(),
            source_policy_hash: "sha256:pol-2".to_string(),
            candidate_policy_hash: "sha256:pol-3".to_string(),
            candidate_yaml: "version: 1\n".to_string(),
            diff_summary: vec!["narrowed rules".to_string()],
            two_step_proof: TwoStepProofResult {
                raw_prover_status: "unsupported_middleware".to_string(),
                step1_middleware_invariant: true,
                step1_detail: "ok".to_string(),
                step2_prover_verdict: "within_boundary".to_string(),
                step2_counterexample_or_reason: None,
                coverage_domains: vec!["network_rest".to_string()],
                verified_non_expanding: true,
            },
            replay_total_requests: 5,
            replay_would_block: 0,
            status: "pending_review".to_string(),
        };
        store
            .save_recommendation(&candidate)
            .expect("save recommendation");
        let recs = store
            .list_recommendations("sbx-aux")
            .expect("list recommendations");
        assert_eq!(recs, vec![candidate]);

        store
            .terminate_epoch(&epoch.epoch_id)
            .expect("terminate epoch");
        assert!(
            store
                .get_active_epoch("sbx-aux")
                .expect("get active epoch")
                .is_none()
        );
    }

    #[test]
    fn test_wal_concurrent_read_connection_does_not_block_on_write_mutex() {
        let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        let store = SqliteRiskStore::open(tmp.path()).expect("open on-disk store");
        let epoch = sample_epoch("sbx-wal-read");
        store.upsert_epoch(&epoch).expect("upsert epoch");

        let detector = ScriptedDetector::new(|req, ctx| {
            Ok(RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: ctx.epoch.epoch_id.clone(),
                mode: ctx.epoch.mode,
                outcome: DecisionOutcome::Allow,
                reason_code: "ok".to_string(),
                risk_score: 0,
                threshold: 70,
                ratchet_action: RatchetAction::None,
                signals: Vec::new(),
                missing_context: Vec::new(),
                baseline_maturity: BaselineMaturity::Mature,
                baseline_hash: ctx.epoch.baseline_hash.clone(),
                detector_version: "test-detector-v1".to_string(),
                state_sequence: 0,
                decision_timestamp_ms: req.timestamp_ms,
            })
        });

        let req = sample_request(
            "req-wal-1",
            "sbx-wal-read",
            "GET",
            "/repos/{owner}/{repo}",
            "org/docs-site",
            1_700_000_010_000,
            "fp-wal-1",
        );
        store
            .evaluate_and_commit_atomic(&req, &detector)
            .expect("eval 1");

        // Hold the primary write mutex and verify read paths succeed via the separate WAL read connection.
        let _write_guard = store.lock_conn().expect("lock write conn");
        let inv = store
            .operator_inventory(1_700_000_020_000)
            .expect("operator_inventory via read_conn");
        assert_eq!(inv["total_sandboxes"], 1);
        let detail = store
            .operator_detail("sbx-wal-read", 1_700_000_020_000)
            .expect("operator_detail via read_conn")
            .expect("sandbox detail exists");
        assert_eq!(detail["decisions"].as_array().unwrap().len(), 1);
        let decisions = store
            .list_decisions("sbx-wal-read", 10)
            .expect("list_decisions via read_conn");
        assert_eq!(decisions.len(), 1);
        let requests = store
            .list_normalized_requests("sbx-wal-read")
            .expect("list_normalized_requests via read_conn");
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn inventory_reports_lifecycle_and_connectivity_from_observed_activity() {
        let store = SqliteRiskStore::open_in_memory().expect("open in-memory store");
        let detector = ScriptedDetector::new(|req, ctx| {
            Ok(RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: ctx.epoch.epoch_id.clone(),
                mode: ctx.epoch.mode,
                outcome: DecisionOutcome::Allow,
                reason_code: "ok".to_string(),
                risk_score: 0,
                threshold: 70,
                ratchet_action: RatchetAction::None,
                signals: Vec::new(),
                missing_context: Vec::new(),
                baseline_maturity: BaselineMaturity::Mature,
                baseline_hash: ctx.epoch.baseline_hash.clone(),
                detector_version: "test-detector-v1".to_string(),
                state_sequence: 0,
                decision_timestamp_ms: req.timestamp_ms,
            })
        });
        let now = 1_700_100_000_000_i64;
        let hour = 3_600_000_i64;

        // Nothing recorded yet: honest "never seen", not a blank.
        let empty = store.operator_inventory(now).expect("empty inventory");
        assert_eq!(empty["gateway_connectivity"]["status"], "never_seen");
        assert_eq!(empty["sandbox_lifecycle"]["sandboxes_recorded"], 0);

        // A busy sandbox (request a minute ago), a quiet one (request 2h ago) and a long-gone one (a day ago).
        for (sandbox, last_request_age) in [
            ("sbx-busy", 60_000),
            ("sbx-quiet", 2 * hour),
            ("sbx-gone", 24 * hour),
        ] {
            let mut epoch = sample_epoch(sandbox);
            epoch.created_at_ms = now - 25 * hour;
            store.upsert_epoch(&epoch).expect("upsert epoch");
            let req = sample_request(
                &format!("req-{sandbox}"),
                sandbox,
                "GET",
                "/repos/{owner}/{repo}",
                "org/docs-site",
                now - last_request_age,
                &format!("fp-{sandbox}"),
            );
            store
                .evaluate_and_commit_atomic(&req, &detector)
                .expect("decision");
        }
        // A fourth sandbox is deleted: its epoch closes, and the close time is recorded.
        store
            .upsert_epoch(&sample_epoch("sbx-deleted"))
            .expect("upsert epoch");
        store
            .terminate_epoch("ep-sbx-deleted")
            .expect("terminate epoch");
        {
            // terminate_epoch stamps the real clock; pin it to this test's synthetic clock.
            let conn = store.lock_conn().expect("lock");
            let closed: Option<i64> = conn
                .query_row(
                    "SELECT closed_at_ms FROM epochs WHERE epoch_id = 'ep-sbx-deleted'",
                    [],
                    |r| r.get(0),
                )
                .expect("closed_at_ms");
            assert!(closed.is_some(), "closing an epoch records when it closed");
            conn.execute(
                "UPDATE epochs SET closed_at_ms = ?1 WHERE epoch_id = 'ep-sbx-deleted'",
                params![now - 3 * hour],
            )
            .expect("pin close time");
        }

        let inv = store.operator_inventory(now).expect("inventory");
        let life = &inv["sandbox_lifecycle"];
        assert_eq!(life["sandboxes_recorded"], 4);
        assert_eq!(life["sandboxes_with_active_epoch"], 3);
        assert_eq!(life["sandboxes_closed"], 1);
        assert_eq!(
            life["recently_active"], 1,
            "only the sandbox with a request a minute ago"
        );
        assert_eq!(life["idle"], 1, "the one quiet for two hours");
        assert_eq!(
            life["not_seen_recently"], 1,
            "the one quiet for a day, most likely deleted"
        );
        assert_eq!(life["decisions_recorded"], 3);
        // The headline total counts active epochs; the lifecycle block explains the difference from "recorded".
        assert_eq!(inv["total_sandboxes"], 3);
        assert_eq!(inv["gateway_connectivity"]["status"], "receiving");
        assert!(inv["gateway_connectivity"]["last_supervisor_request_ms"].is_number());
        // Each listed sandbox carries its own state.
        let states: std::collections::BTreeMap<String, String> = inv["sandboxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["epoch"]["sandbox_id"].as_str().unwrap().to_string(),
                    s["sandbox_lifecycle"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(states["sbx-busy"], "recently_active");
        assert_eq!(states["sbx-quiet"], "idle");
        assert_eq!(states["sbx-gone"], "not_seen_recently");

        // Long after the last activity the link is reported as quiet, not as connected.
        let later = store
            .operator_inventory(now + 2 * hour)
            .expect("later inventory");
        assert_eq!(later["gateway_connectivity"]["status"], "quiet");
    }

    #[test]
    fn age_based_retention_prunes_old_decisions_but_keeps_what_a_lock_still_needs() {
        let store = SqliteRiskStore::open_in_memory().expect("open in-memory store");
        store
            .upsert_epoch(&sample_epoch("sbx-retention"))
            .expect("upsert epoch");
        let detector = ScriptedDetector::new(|req, ctx| {
            // req-2 trips a cooldown, so it becomes the trigger of a restriction and is pinned.
            let ratchet_action = if req.request_id == "req-2" {
                RatchetAction::TriggerTier2Cooldown {
                    scope: req.restriction_scope.clone(),
                    cooldown_duration_ms: 10_000,
                }
            } else {
                RatchetAction::None
            };
            Ok(RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: ctx.epoch.epoch_id.clone(),
                mode: ctx.epoch.mode,
                outcome: DecisionOutcome::Allow,
                reason_code: "ok".to_string(),
                risk_score: 0,
                threshold: 70,
                ratchet_action,
                signals: Vec::new(),
                missing_context: Vec::new(),
                baseline_maturity: BaselineMaturity::Mature,
                baseline_hash: ctx.epoch.baseline_hash.clone(),
                detector_version: "test-detector-v1".to_string(),
                state_sequence: 0,
                decision_timestamp_ms: req.timestamp_ms,
            })
        });
        let base = 1_700_000_000_000_i64;
        for i in 1..=6_i64 {
            let req = sample_request(
                &format!("req-{i}"),
                "sbx-retention",
                "GET",
                "/repos/{owner}/{repo}",
                &format!("org/repo-{i}"),
                base + i * 20_000,
                &format!("fp-{i}"),
            );
            store
                .evaluate_and_commit_atomic(&req, &detector)
                .expect("eval");
        }
        let ids = |store: &SqliteRiskStore| -> Vec<String> {
            let mut ids: Vec<String> = store
                .list_decisions("sbx-retention", 100)
                .expect("list")
                .into_iter()
                .map(|d| d.request_id)
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(&store).len(), 6);

        // Keep only decisions from req-4 on. req-1 and req-3 are old and unpinned; req-2 is old but still pinned.
        let deleted = store
            .prune_decisions_older_than(base + 4 * 20_000)
            .expect("prune by age");
        assert_eq!(deleted, 2, "the two old, unpinned decisions");
        assert_eq!(ids(&store), vec!["req-2", "req-4", "req-5", "req-6"]);

        // Pruning again is a no-op, and a cutoff before everything removes nothing.
        assert_eq!(
            store
                .prune_decisions_older_than(base + 4 * 20_000)
                .expect("repeat"),
            0
        );
        assert_eq!(
            store
                .prune_decisions_older_than(base)
                .expect("early cutoff"),
            0
        );
    }

    #[test]
    fn test_prune_old_decisions_preserves_pinned_and_newest() {
        let store = SqliteRiskStore::open_in_memory().expect("open in-memory store");
        let epoch = sample_epoch("sbx-prune");
        store.upsert_epoch(&epoch).expect("upsert epoch");

        let detector = ScriptedDetector::new(|req, ctx| {
            let ratchet_action = if req.request_id == "req-2" {
                RatchetAction::TriggerTier2Cooldown {
                    scope: req.restriction_scope.clone(),
                    cooldown_duration_ms: 10_000,
                }
            } else {
                RatchetAction::None
            };
            Ok(RiskEvaluation {
                request_id: req.request_id.clone(),
                sandbox_id: req.sandbox_id.clone(),
                epoch_id: ctx.epoch.epoch_id.clone(),
                mode: ctx.epoch.mode,
                outcome: DecisionOutcome::Allow,
                reason_code: "ok".to_string(),
                risk_score: 0,
                threshold: 70,
                ratchet_action,
                signals: Vec::new(),
                missing_context: Vec::new(),
                baseline_maturity: BaselineMaturity::Mature,
                baseline_hash: ctx.epoch.baseline_hash.clone(),
                detector_version: "test-detector-v1".to_string(),
                state_sequence: 0,
                decision_timestamp_ms: req.timestamp_ms,
            })
        });

        for i in 1..=6 {
            let req = sample_request(
                &format!("req-{i}"),
                "sbx-prune",
                "GET",
                "/repos/{owner}/{repo}",
                &format!("org/repo-{i}"),
                1_700_000_000_000 + i * 20_000,
                &format!("fp-{i}"),
            );
            store
                .evaluate_and_commit_atomic(&req, &detector)
                .expect("eval");
        }

        // Pin req-1 in adaptive_observations (and native_decision_provenance) so it must not be pruned,
        // while req-2 is pinned via restrictions.trigger_request_id.
        {
            // store_baseline takes the connection lock itself; holding it here self-deadlocks.
            let baseline_hash = store.store_baseline(&sample_baseline()).expect("baseline");
            let conn = store.lock_conn().expect("lock");
            conn.execute(
                "INSERT INTO agents (agent_id, display_name, created_at_ms) VALUES ('ag-1', 'Agent 1', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO scoring_contexts (context_id, agent_id, agent_revision, task_profile, baseline_hash, detector_version, configuration_id, mode, created_at_ms)
                 VALUES ('ctx-1', 'ag-1', 'rev-1', 'repo-triage-readonly', ?1, 'v1', 'cfg-1', 'enforce', 1)",
                params![baseline_hash],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO agent_runs (run_id, context_id, created_at_ms) VALUES ('run-1', 'ctx-1', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO adaptive_sessions (session_id, agent_id, run_id, context_id, guardrails_revision, scope, status, started_at_ms)
                 VALUES ('sess-1', 'ag-1', 'run-1', 'ctx-1', 0, 'local_demo', 'recording', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO native_decision_provenance (epoch_id, request_id, auth_scope, run_id, observed_at_ms)
                 VALUES (?1, 'req-1', 'local_demo', 'run-1', 1)",
                params![epoch.epoch_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO adaptive_observations (session_id, epoch_id, request_id, base_outcome, base_risk_score)
                 VALUES ('sess-1', ?1, 'req-1', 'allow', 0)",
                params![epoch.epoch_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO native_decision_provenance (epoch_id, request_id, auth_scope, run_id, observed_at_ms)
                 VALUES (?1, 'req-3', 'local_demo', 'run-1', 1)",
                params![epoch.epoch_id],
            )
            .unwrap();
        }

        // Retain newest 2 decisions (req-5, req-6). Older decisions are req-1..req-4:
        // - req-1 is pinned in adaptive_observations -> preserved
        // - req-2 is pinned in restrictions.trigger_request_id -> preserved
        // - req-3 and req-4 are unpinned -> pruned!
        let deleted = store.prune_old_decisions(2).expect("prune_old_decisions");
        assert_eq!(deleted, 2);

        let remaining: Vec<String> = store
            .list_decisions("sbx-prune", 100)
            .expect("list decisions")
            .into_iter()
            .map(|d| d.request_id)
            .collect();
        assert_eq!(remaining, vec!["req-1", "req-2", "req-5", "req-6"]);
    }
}
