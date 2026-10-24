// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Risk features published by the SIEM (OpenShell policy denials per sandbox, refusal ratios per workload, fleet-wide counts), kept so scoring can read them
//! from a local table. See docs/design-siem-features.md; the HTTP door is `POST /features` in `crate::signals`.
//!
//! The rules, all enforced here so no transport can skip them:
//! - the vocabulary is closed (`crate::detector::siem::VOCABULARY`): an unknown name, a name for the wrong kind of subject or a value out of range is
//!   rejected and counted, never stored;
//! - the source of a batch is the caller's verified identity, passed in by the listener; the body has no field for it;
//! - one batch per 10 seconds per source, at most 2,000 subjects, and a batch generated more than 10 minutes ago (or in the future) is refused;
//! - only the latest value per (kind, subject, name) is kept, and it expires `2 x window_seconds` after it was generated;
//! - every batch, accepted or not, leaves a row in the audit table;
//! - scoring never waits on any of this: the decision path reads two small indexed tables and, finding nothing fresh, adds nothing.

use super::*;
use crate::detector::siem::{self as vocabulary};
use crate::spiffe::SpiffeId;
use crate::types::{ContextFeature, ContextFeatures, FeatureScope};
use std::collections::{BTreeMap, HashMap};

pub const SCHEMA: u32 = 1;
pub const MAX_SUBJECTS: usize = 2_000;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// One batch per source per this long.
pub const MIN_INTERVAL_MS: i64 = 10_000;
/// A batch generated longer ago than this is refused.
pub const STALE_AFTER_MS: i64 = 10 * 60_000;
/// A batch generated further ahead than this is refused (it would live longer than its sender meant).
const FUTURE_SKEW_MS: i64 = 5 * 60_000;
const MIN_WINDOW_SECONDS: u32 = 60;
const MAX_WINDOW_SECONDS: u32 = 3_600;
const BATCH_AUDIT_KEEP_MS: i64 = 7 * 24 * 3_600_000;
const EXPIRED_FEATURE_KEEP_MS: i64 = 3_600_000;

/// The body of `POST /features`, schema 1. Unknown fields are refused, so a body cannot carry a `source` or anything else the contract does not name.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureBatch {
    pub schema: u32,
    pub generated_at_ms: i64,
    pub window_seconds: u32,
    pub subjects: Vec<FeatureSubject>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSubject {
    /// `sandbox`, `spiffe`, `workload` or `fleet`.
    pub kind: String,
    pub id: String,
    /// Feature name to value. Values are checked one by one, so one bad value does not spoil the rest.
    pub features: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestStatus {
    /// The batch was read; some or all features may still have been rejected (see `reasons`).
    Accepted,
    /// The batch itself is malformed (wrong schema, too many subjects, a bad window or a timestamp from the future).
    Invalid,
    /// The batch was generated more than ten minutes ago.
    Stale,
    /// The source sent another batch less than ten seconds ago.
    RateLimited,
}

impl IngestStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Invalid => "invalid",
            Self::Stale => "stale",
            Self::RateLimited => "rate_limited",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FeatureIngest {
    pub status: IngestStatus,
    pub batch_id: i64,
    pub subjects: usize,
    /// Features stored.
    pub accepted: u64,
    /// Features (or whole subjects that could not be read) refused, by reason in `reasons`.
    pub rejected: u64,
    pub reasons: BTreeMap<String, u64>,
    /// Sandbox and SPIFFE subjects that resolved to a workload, and those stored by sandbox only.
    pub resolved: u64,
    pub unresolved: u64,
}

pub(super) fn ensure_siem_feature_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS siem_features (
            kind TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            name TEXT NOT NULL,
            value INTEGER NOT NULL,
            generated_at_ms INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            source TEXT NOT NULL,
            received_at_ms INTEGER NOT NULL,
            sandbox_id TEXT,
            agent_id TEXT,
            PRIMARY KEY (kind, subject_id, name)
         );
         CREATE INDEX IF NOT EXISTS idx_siem_features_sandbox ON siem_features (sandbox_id, expires_at_ms);
         CREATE INDEX IF NOT EXISTS idx_siem_features_expiry ON siem_features (expires_at_ms);
         CREATE TABLE IF NOT EXISTS siem_feature_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            received_at_ms INTEGER NOT NULL,
            generated_at_ms INTEGER,
            bytes INTEGER NOT NULL,
            subjects INTEGER NOT NULL,
            accepted INTEGER NOT NULL,
            rejected INTEGER NOT NULL,
            resolved INTEGER NOT NULL,
            unresolved INTEGER NOT NULL,
            outcome TEXT NOT NULL,
            reasons_json TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_siem_feature_batches_source ON siem_feature_batches (source, received_at_ms)",
    )?;
    // The features a decision used, kept on the decision itself so they live and are pruned with it and travel in a replay bundle.
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('decisions') WHERE name = 'siem_features_json'",
        [],
        |row| row.get(0),
    )?;
    if present == 0 {
        conn.execute_batch("ALTER TABLE decisions ADD COLUMN siem_features_json TEXT")?;
    }
    Ok(())
}

fn subject_scope(kind: &str) -> Option<FeatureScope> {
    match kind {
        "sandbox" | "spiffe" => Some(FeatureScope::Sandbox),
        "workload" => Some(FeatureScope::Workload),
        "fleet" => Some(FeatureScope::Fleet),
        _ => None,
    }
}

fn plain_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:/@".contains(&b))
}

fn count(reasons: &mut BTreeMap<String, u64>, reason: &str, n: u64) {
    *reasons.entry(reason.to_string()).or_default() += n;
}

impl SqliteRiskStore {
    /// The sandbox a SPIFFE subject names: `spiffe://<domain>/openshell/sandbox/<id>` is the sandbox `<id>` (the reverse of how `crate::ocsf` builds a
    /// sandbox's SPIFFE ID, with the domain checked when this store knows its own); any other SPIFFE ID is a workload on the SVID listener, whose
    /// sandbox id is derived from the ID.
    fn sandbox_of_spiffe(&self, id: &SpiffeId) -> std::result::Result<String, &'static str> {
        if let Some(sandbox) = id.path().strip_prefix("/openshell/sandbox/")
            && !sandbox.is_empty()
            && !sandbox.contains('/')
        {
            if self
                .sandbox_spiffe_trust_domain
                .as_deref()
                .is_some_and(|domain| domain != id.trust_domain())
            {
                return Err("spiffe_trust_domain_mismatch");
            }
            return Ok(sandbox.to_string());
        }
        Ok(id.sandbox_id())
    }

    /// Store a batch of features from `source` (the caller's verified identity). Only malformed storage is an `Err`; a batch that is refused is an
    /// outcome, recorded in the audit table like an accepted one.
    #[allow(clippy::too_many_lines)]
    pub fn ingest_siem_features(
        &self,
        source: &str,
        bytes: usize,
        batch: &FeatureBatch,
        now_ms: i64,
    ) -> Result<FeatureIngest> {
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut result = FeatureIngest {
            status: IngestStatus::Accepted,
            batch_id: 0,
            subjects: batch.subjects.len(),
            accepted: 0,
            rejected: 0,
            reasons: BTreeMap::new(),
            resolved: 0,
            unresolved: 0,
        };
        let audit = |tx: &Transaction<'_>, result: &mut FeatureIngest| -> Result<()> {
            tx.execute(
                "INSERT INTO siem_feature_batches
                   (source, received_at_ms, generated_at_ms, bytes, subjects, accepted, rejected, resolved, unresolved, outcome, reasons_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    source,
                    now_ms,
                    batch.generated_at_ms,
                    i64::try_from(bytes).unwrap_or(i64::MAX),
                    i64::try_from(result.subjects).unwrap_or(i64::MAX),
                    i64::try_from(result.accepted).unwrap_or(i64::MAX),
                    i64::try_from(result.rejected).unwrap_or(i64::MAX),
                    i64::try_from(result.resolved).unwrap_or(i64::MAX),
                    i64::try_from(result.unresolved).unwrap_or(i64::MAX),
                    result.status.as_str(),
                    serde_json::to_string(&result.reasons)?,
                ],
            )?;
            result.batch_id = tx.last_insert_rowid();
            Ok(())
        };

        // One batch per source per ten seconds. A batch refused for rate, or a body that was not a batch at all (no generated time), does not move the clock, so a flood or a bad body cannot lock a sender out.
        let last: Option<i64> = tx.query_row(
            "SELECT MAX(received_at_ms) FROM siem_feature_batches WHERE source = ?1 AND outcome != 'rate_limited' AND generated_at_ms IS NOT NULL",
            params![source],
            |row| row.get(0),
        )?;
        let refuse = |tx: &Transaction<'_>,
                      result: &mut FeatureIngest,
                      status: IngestStatus,
                      reason: &str|
         -> Result<()> {
            result.status = status;
            result.rejected = result.subjects as u64;
            count(&mut result.reasons, reason, result.subjects.max(1) as u64);
            audit(tx, result)
        };
        if last.is_some_and(|last| now_ms.saturating_sub(last) < MIN_INTERVAL_MS) {
            refuse(&tx, &mut result, IngestStatus::RateLimited, "rate_limited")?;
            tx.commit()?;
            return Ok(result);
        }
        let invalid = if batch.schema != SCHEMA {
            Some("unsupported_schema")
        } else if batch.subjects.len() > MAX_SUBJECTS {
            Some("too_many_subjects")
        } else if !(MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(&batch.window_seconds) {
            Some("window_seconds_out_of_range")
        } else if batch.generated_at_ms > now_ms.saturating_add(FUTURE_SKEW_MS) {
            Some("generated_in_the_future")
        } else {
            None
        };
        if let Some(reason) = invalid {
            refuse(&tx, &mut result, IngestStatus::Invalid, reason)?;
            tx.commit()?;
            return Ok(result);
        }
        if batch.generated_at_ms < now_ms.saturating_sub(STALE_AFTER_MS) {
            refuse(&tx, &mut result, IngestStatus::Stale, "stale_batch")?;
            tx.commit()?;
            return Ok(result);
        }

        let expires_at_ms = batch
            .generated_at_ms
            .saturating_add(i64::from(batch.window_seconds) * 2_000);
        let mut agent_of: HashMap<String, Option<String>> = HashMap::new();
        for subject in &batch.subjects {
            let unreadable = i64::try_from(subject.features.len().max(1)).unwrap_or(1) as u64;
            let Some(scope) = subject_scope(&subject.kind) else {
                result.rejected += unreadable;
                count(&mut result.reasons, "unknown_subject_kind", unreadable);
                continue;
            };
            // Who the subject is, in the form scoring looks it up by.
            let mut sandbox_id: Option<String> = None;
            let id_problem = match subject.kind.as_str() {
                "fleet" => (subject.id != "fleet").then_some("fleet_id_must_be_fleet"),
                "spiffe" => match SpiffeId::parse(&subject.id) {
                    Ok(id) => match self.sandbox_of_spiffe(&id) {
                        Ok(sandbox) => {
                            sandbox_id = Some(sandbox);
                            None
                        }
                        Err(reason) => Some(reason),
                    },
                    Err(_) => Some("invalid_spiffe_id"),
                },
                "sandbox" => {
                    sandbox_id = Some(subject.id.clone());
                    (!plain_id(&subject.id)).then_some("invalid_subject_id")
                }
                _ => (!plain_id(&subject.id)).then_some("invalid_subject_id"),
            };
            if let Some(reason) = id_problem {
                result.rejected += unreadable;
                count(&mut result.reasons, reason, unreadable);
                continue;
            }
            // The sandbox's workload, through its latest epoch and run. A sandbox Risk Guard has not met is stored by sandbox only.
            let agent_id: Option<String> = match &sandbox_id {
                Some(sandbox) => agent_of
                    .entry(sandbox.clone())
                    .or_insert_with(|| {
                        tx.query_row(
                            "SELECT c.agent_id FROM epochs e
                             JOIN epoch_bindings b ON b.epoch_id = e.epoch_id
                             JOIN agent_runs r ON r.run_id = b.run_id
                             JOIN scoring_contexts c ON c.context_id = r.context_id
                             WHERE e.sandbox_id = ?1 ORDER BY e.created_at_ms DESC, e.rowid DESC LIMIT 1",
                            params![sandbox],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .ok()
                        .flatten()
                    })
                    .clone(),
                None => None,
            };
            let mut stored_any = false;
            for (name, raw) in &subject.features {
                let Some((allowed_scope, range)) = vocabulary::lookup(name) else {
                    result.rejected += 1;
                    count(&mut result.reasons, "unknown_feature", 1);
                    continue;
                };
                if allowed_scope != scope {
                    result.rejected += 1;
                    count(&mut result.reasons, "feature_not_allowed_for_kind", 1);
                    continue;
                }
                let value = match (raw.as_u64(), raw.as_i64()) {
                    (Some(value), _) => value,
                    (None, Some(_)) => {
                        result.rejected += 1;
                        count(&mut result.reasons, "value_out_of_range", 1);
                        continue;
                    }
                    _ => {
                        result.rejected += 1;
                        count(&mut result.reasons, "value_not_an_integer", 1);
                        continue;
                    }
                };
                if value > u64::from(range.max()) {
                    result.rejected += 1;
                    count(&mut result.reasons, "value_out_of_range", 1);
                    continue;
                }
                let changed = tx.execute(
                    "INSERT INTO siem_features
                       (kind, subject_id, name, value, generated_at_ms, expires_at_ms, source, received_at_ms, sandbox_id, agent_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                     ON CONFLICT(kind, subject_id, name) DO UPDATE SET
                       value = excluded.value, generated_at_ms = excluded.generated_at_ms, expires_at_ms = excluded.expires_at_ms,
                       source = excluded.source, received_at_ms = excluded.received_at_ms, sandbox_id = excluded.sandbox_id, agent_id = excluded.agent_id
                     WHERE excluded.generated_at_ms >= siem_features.generated_at_ms",
                    params![
                        subject.kind,
                        subject.id,
                        name,
                        i64::try_from(value).unwrap_or(i64::MAX),
                        batch.generated_at_ms,
                        expires_at_ms,
                        source,
                        now_ms,
                        sandbox_id,
                        agent_id,
                    ],
                )?;
                if changed == 0 {
                    result.rejected += 1;
                    count(&mut result.reasons, "older_than_stored_value", 1);
                } else {
                    result.accepted += 1;
                    stored_any = true;
                }
            }
            if stored_any && sandbox_id.is_some() {
                if agent_id.is_some() {
                    result.resolved += 1;
                } else {
                    result.unresolved += 1;
                }
            }
        }
        audit(&tx, &mut result)?;
        tx.execute(
            "DELETE FROM siem_features WHERE expires_at_ms < ?1",
            params![now_ms.saturating_sub(EXPIRED_FEATURE_KEEP_MS)],
        )?;
        tx.execute(
            "DELETE FROM siem_feature_batches WHERE received_at_ms < ?1",
            params![now_ms.saturating_sub(BATCH_AUDIT_KEEP_MS)],
        )?;
        tx.commit()?;
        Ok(result)
    }

    /// Record a body that could not be read as a batch (not JSON, an unknown field, a wrong type, or over the size limit), so it shows in the audit table.
    pub fn record_rejected_feature_body(
        &self,
        source: &str,
        bytes: usize,
        reason: &str,
        now_ms: i64,
    ) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO siem_feature_batches
               (source, received_at_ms, generated_at_ms, bytes, subjects, accepted, rejected, resolved, unresolved, outcome, reasons_json)
             VALUES (?1, ?2, NULL, ?3, 0, 0, 1, 0, 0, 'invalid', ?4)",
            params![
                source,
                now_ms,
                i64::try_from(bytes).unwrap_or(i64::MAX),
                serde_json::to_string(&BTreeMap::from([(reason.to_string(), 1u64)]))?
            ],
        )?;
        Ok(())
    }

    /// The batches received, newest first (for the audit view and tests).
    pub fn list_siem_feature_batches(&self, limit: u32) -> Result<serde_json::Value> {
        let conn = self.lock_read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, source, received_at_ms, generated_at_ms, bytes, subjects, accepted, rejected, resolved, unresolved, outcome, reasons_json
             FROM siem_feature_batches ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                let reasons: String = row.get(11)?;
                Ok(serde_json::json!({
                    "id": row.get::<_, i64>(0)?, "source": row.get::<_, String>(1)?, "received_at_ms": row.get::<_, i64>(2)?,
                    "generated_at_ms": row.get::<_, Option<i64>>(3)?, "bytes": row.get::<_, i64>(4)?, "subjects": row.get::<_, i64>(5)?,
                    "accepted": row.get::<_, i64>(6)?, "rejected": row.get::<_, i64>(7)?, "resolved": row.get::<_, i64>(8)?,
                    "unresolved": row.get::<_, i64>(9)?, "outcome": row.get::<_, String>(10)?,
                    "reasons": serde_json::from_str::<serde_json::Value>(&reasons).unwrap_or_default(),
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({ "batches": rows }))
    }

    /// Every stored feature, for tests and the audit view: (kind, subject, name, value, sandbox, workload, source, expires_at_ms).
    pub fn list_siem_features(&self) -> Result<serde_json::Value> {
        let conn = self.lock_read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT kind, subject_id, name, value, sandbox_id, agent_id, source, generated_at_ms, expires_at_ms
             FROM siem_features ORDER BY kind, subject_id, name",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "kind": row.get::<_, String>(0)?, "subject": row.get::<_, String>(1)?, "name": row.get::<_, String>(2)?,
                    "value": row.get::<_, i64>(3)?, "sandbox_id": row.get::<_, Option<String>>(4)?, "agent_id": row.get::<_, Option<String>>(5)?,
                    "source": row.get::<_, String>(6)?, "generated_at_ms": row.get::<_, i64>(7)?, "expires_at_ms": row.get::<_, i64>(8)?,
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({ "features": rows }))
    }

    /// What the Controls page says about the features: whether any batch ever arrived, how many features are fresh, how old the newest batch is.
    pub(super) fn siem_features_status(&self, now_ms: i64) -> Result<(bool, i64, Option<i64>)> {
        let conn = self.lock_read_conn()?;
        let newest: Option<i64> = conn.query_row(
            "SELECT MAX(received_at_ms) FROM siem_feature_batches WHERE outcome = 'accepted'",
            [],
            |row| row.get(0),
        )?;
        let fresh: i64 = conn.query_row(
            "SELECT COUNT(*) FROM siem_features WHERE expires_at_ms > ?1",
            params![now_ms],
            |row| row.get(0),
        )?;
        Ok((
            newest.is_some(),
            fresh,
            newest.map(|at| (now_ms - at).max(0)),
        ))
    }

    /// Run the decision path's lookup on its own (for tests and tooling): the features a request from `sandbox_id` would be scored with at `now_ms`.
    pub fn context_features_for(&self, sandbox_id: &str, now_ms: i64) -> Result<ContextFeatures> {
        let conn = self.lock_read_conn()?;
        let agent_id = query_active_epoch(&conn, sandbox_id)?
            .map(|epoch| resolve_identity(&conn, &epoch))
            .transpose()?
            .flatten()
            .map(|identity| identity.agent_id);
        load_context(&conn, sandbox_id, agent_id.as_deref(), now_ms)
    }
}

/// The fresh features for one decision: the sandbox's own (sandbox and SPIFFE subjects), its workload's, and the fleet's. Where a sandbox has the same
/// feature under both a sandbox and a SPIFFE subject, the larger value is used.
pub(super) fn load_context(
    conn: &Connection,
    sandbox_id: &str,
    agent_id: Option<&str>,
    now_ms: i64,
) -> Result<ContextFeatures> {
    let mut found = Vec::new();
    let mut read =
        |sql: &str, params: &[&dyn rusqlite::ToSql], scope: FeatureScope| -> Result<()> {
            let mut stmt = conn.prepare_cached(sql)?;
            let rows = stmt
                .query_map(params, |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for (name, value, subject, generated_at_ms) in rows {
                if vocabulary::lookup(&name).is_some_and(|(allowed, _)| allowed == scope) {
                    found.push(ContextFeature {
                        scope,
                        name,
                        value: u32::try_from(value).unwrap_or(0),
                        subject,
                        age_ms: (now_ms - generated_at_ms).max(0),
                    });
                }
            }
            Ok(())
        };
    read(
        "SELECT name, value, subject_id, generated_at_ms FROM siem_features
         WHERE sandbox_id = ?1 AND kind IN ('sandbox', 'spiffe') AND expires_at_ms > ?2 ORDER BY name, value DESC, kind, subject_id",
        &[&sandbox_id, &now_ms],
        FeatureScope::Sandbox,
    )?;
    if let Some(agent_id) = agent_id {
        read(
            "SELECT name, value, subject_id, generated_at_ms FROM siem_features
             WHERE kind = 'workload' AND subject_id = ?1 AND expires_at_ms > ?2 ORDER BY name",
            &[&agent_id, &now_ms],
            FeatureScope::Workload,
        )?;
    }
    read(
        "SELECT name, value, subject_id, generated_at_ms FROM siem_features
         WHERE kind = 'fleet' AND subject_id = 'fleet' AND expires_at_ms > ?1 ORDER BY name",
        &[&now_ms],
        FeatureScope::Fleet,
    )?;
    Ok(ContextFeatures::new(found))
}

/// Keep the features a decision used on the decision row (nothing is written when there were none, so a decision without features is stored as before).
pub(super) fn record_used(
    tx: &Transaction<'_>,
    epoch_id: &str,
    request_id: &str,
    features: &ContextFeatures,
) -> Result<()> {
    if features.is_empty() {
        return Ok(());
    }
    tx.execute(
        "UPDATE decisions SET siem_features_json = ?3 WHERE epoch_id = ?1 AND request_id = ?2",
        params![
            epoch_id,
            request_id,
            serde_json::to_string(features.as_slice())?
        ],
    )?;
    Ok(())
}

/// The features a stored decision used (empty for a decision made without any).
pub(super) fn recorded_for(conn: &Connection, rowid: i64) -> Result<Vec<ContextFeature>> {
    let json: Option<String> = conn
        .query_row(
            "SELECT siem_features_json FROM decisions WHERE rowid = ?1",
            params![rowid],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    match json {
        Some(json) => Ok(serde_json::from_str(&json)?),
        None => Ok(Vec::new()),
    }
}
