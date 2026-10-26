// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Two-person approval for anything that loosens protection.
//!
//! Tightening is cheap and fast: a person, a rule or a SIEM signal can quarantine a workload at once. Loosening is the dangerous direction, so once two-person mode is on
//! (`two-person-enable`) a quarantine cannot be released and a restriction cannot be cleared by one person. Someone **proposes** the change with a reason; someone **else** approves it;
//! only then does it happen. The rule is enforced here, in the store, so every door (the console API, the command line) is behind it.
//!
//! * The proposer can never approve their own request. A request expires after 24 hours.
//! * Turning the rule off is itself a loosening and goes through a request.
//! * The one way around it is `--break-glass` on the command line, which needs a shell on the pod (so cluster access); it is allowed, labelled as break-glass in the audit
//!   trail, and logged. A control that cannot be bypassed in an emergency gets bypassed in an unrecorded way.
//! * Every request is kept with who proposed, who decided, when and why. Executing it writes the usual audit rows with both names.

use super::*;
use serde_json::Value;

const TWO_PERSON: &str = "two_person_required";
const EXPIRY_MS: i64 = 24 * 60 * 60 * 1000;
const KINDS: [&str; 7] = [
    "release_quarantine",
    "clear_restriction",
    "disable_two_person",
    "baseline_update",
    "policy_update",
    "update_guardrails",
    "demote_adaptive_model",
];
/// A baseline change may add at most this many routes or hosts at once, so a request stays reviewable.
const MAX_BASELINE_ADDITIONS: usize = 50;
const RATE_SETTINGS: [&str; 2] = ["max_req_1m_p95", "max_req_1m_p99"];

pub(super) fn ensure_change_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS change_requests (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            target TEXT NOT NULL,
            params_json TEXT NOT NULL,
            reason TEXT NOT NULL,
            proposer TEXT NOT NULL,
            proposed_at_ms INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            status TEXT NOT NULL,
            decided_by TEXT,
            decided_at_ms INTEGER,
            decision_reason TEXT,
            outcome TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_change_requests_status ON change_requests (status, proposed_at_ms)",
    )?;
    Ok(())
}

fn person(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(RiskGuardError::InvalidArgument(format!(
            "{name} must be 1..128 bytes without control characters"
        )));
    }
    Ok(())
}

/// The strings under `params[key]`, which must be an array of short non-empty strings.
fn string_list(params: &Value, key: &str) -> Result<Vec<String>> {
    let Some(value) = params.get(key).filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| RiskGuardError::InvalidArgument(format!("params.{key} must be a list")))?;
    if items.len() > MAX_BASELINE_ADDITIONS {
        return Err(RiskGuardError::InvalidArgument(format!(
            "params.{key} may hold at most {MAX_BASELINE_ADDITIONS} entries"
        )));
    }
    items
        .iter()
        .map(|item| {
            let text = item.as_str().map(str::trim).unwrap_or_default();
            if text.is_empty() || text.len() > 200 || text.chars().any(char::is_control) {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "params.{key} entries must be 1..200 characters without control characters"
                )));
            }
            Ok(text.to_string())
        })
        .collect()
}

/// A baseline change as asked for, checked for shape. It can add routes that only read (GET or HEAD), add egress hosts, and lower the rate limits. Nothing else is
/// expressible, so a request can never remove a deny-list entry, add a destructive route or raise a limit.
struct BaselineChange {
    routes: Vec<String>,
    hosts: Vec<String>,
    rates: Vec<(String, u32)>,
    /// Where the approved routes and hosts are kept: `risk_guard` (the default: Risk Guard's list, which can run in watching mode and follows a workload between sandboxes), or
    /// `openshell` (also written into a policy candidate for OpenShell, the better home for a path or host list). Rate limits always stay in Risk Guard.
    home: Home,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Home {
    RiskGuard,
    OpenShell,
}

fn parse_baseline_change(params: &Value) -> Result<BaselineChange> {
    let routes = string_list(params, "add_action_classes")?;
    for route in &routes {
        let method = route.split_whitespace().next().unwrap_or_default();
        if !matches!(method, "GET" | "HEAD") || !route.contains(' ') {
            return Err(RiskGuardError::InvalidArgument(format!(
                "'{route}': a baseline change may only add routes that read (GET or HEAD); add anything else deliberately, by importing a baseline"
            )));
        }
    }
    let hosts = string_list(params, "add_egress_hosts")?;
    let mut rates = Vec::new();
    if let Some(object) = params.get("tighten_rate").and_then(Value::as_object) {
        for (name, value) in object {
            let number = value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 0);
            if !RATE_SETTINGS.contains(&name.as_str()) || number.is_none() {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "params.tighten_rate.{name} must be one of {} with a positive whole number",
                    RATE_SETTINGS.join(", ")
                )));
            }
            rates.push((name.clone(), number.unwrap_or_default()));
        }
    }
    if routes.is_empty() && hosts.is_empty() && rates.is_empty() {
        return Err(RiskGuardError::InvalidArgument(
            "a baseline change must add a route, add an egress host or lower a rate limit".into(),
        ));
    }
    let home = match params
        .get("home")
        .filter(|v| !v.is_null())
        .map(Value::as_str)
    {
        None | Some(Some("risk_guard")) => Home::RiskGuard,
        Some(Some("openshell")) => Home::OpenShell,
        Some(_) => {
            return Err(RiskGuardError::InvalidArgument(
                "params.home must be risk_guard (keep the list in Risk Guard) or openshell (also write it into an OpenShell policy candidate)".into(),
            ));
        }
    };
    if home == Home::OpenShell && routes.is_empty() && hosts.is_empty() {
        return Err(RiskGuardError::InvalidArgument(
            "params.home openshell needs a route or host to move; rate limits stay in Risk Guard"
                .into(),
        ));
    }
    Ok(BaselineChange {
        routes,
        hosts,
        rates,
        home,
    })
}

/// Letters, digits, `.`, `_` and `-` only, so a name can be put into a command line without quoting.
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The file a person saves the candidate policy as.
fn policy_file_name(task_profile: &str, change_id: &str) -> String {
    let profile: String = task_profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!(
        "policy-{profile}-{}.yaml",
        &change_id[..change_id.len().min(8)]
    )
}

/// What approving a `policy_update` records: the exact command, and a plain statement that nothing was applied.
fn policy_update_outcome(params: &Value, change_id: &str) -> String {
    let sandbox = params["sandbox"].as_str().unwrap_or_default();
    let file = policy_file_name(
        params["task_profile"].as_str().unwrap_or("policy"),
        change_id,
    );
    let mut text = format!(
        "approved: apply with `openshell policy set {sandbox} --policy {file} --wait` (download the file from /api/changes/{change_id}/policy first). Risk Guard applied nothing; a person runs this."
    );
    if params["requires_new_sandbox"] == true {
        text.push_str(" This candidate differs from the sandbox's policy outside network rules, which cannot be changed on a running sandbox: create a new sandbox with it instead.");
    }
    text
}

fn same_person(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

impl SqliteRiskStore {
    /// Is the rule on?
    pub fn two_person_required(&self) -> Result<bool> {
        let conn = self.lock_read_conn()?;
        Ok(conn
            .query_row(
                "SELECT value FROM service_settings WHERE name = ?1",
                params![TWO_PERSON],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_some_and(|value| value == "1"))
    }

    /// Turn the rule on. (Turning it off needs a change request.)
    pub fn require_two_person(&self, now_ms: i64) -> Result<()> {
        self.lock_conn()?.execute(
            "INSERT OR REPLACE INTO service_settings (name, value, recorded_at_ms) VALUES (?1, '1', ?2)",
            params![TWO_PERSON, now_ms],
        )?;
        Ok(())
    }

    fn needs_second_person(&self, what: &str) -> Result<()> {
        if self.two_person_required()? {
            return Err(RiskGuardError::PermissionDenied(format!(
                "{what} loosens protection, and two-person approval is on: propose it and have someone else approve it"
            )));
        }
        Ok(())
    }

    /// Release a workload's quarantine. Refused when two-person approval is on.
    pub fn release_workload(
        &self,
        agent_id: &str,
        operator: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool> {
        self.needs_second_person("releasing a quarantine")?;
        self.release_workload_unchecked(agent_id, operator, reason, now_ms)
    }

    /// The emergency way around two-person approval, labelled as such in the audit trail.
    pub fn release_workload_break_glass(
        &self,
        agent_id: &str,
        operator: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool> {
        tracing::warn!(
            agent_id,
            operator,
            "BREAK-GLASS: a quarantine is being released without a second person"
        );
        self.release_workload_unchecked(
            agent_id,
            &format!("{operator} (BREAK-GLASS)"),
            &format!("BREAK-GLASS: {reason}"),
            now_ms,
        )
    }

    /// Clear a restriction. Refused when two-person approval is on.
    pub fn clear_restriction(
        &self,
        target: RestrictionTarget<'_>,
        scope: &str,
        operator: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<Value> {
        self.needs_second_person("clearing a restriction")?;
        person(operator, "operator")?;
        if reason.trim().is_empty() || reason.len() > 1000 || reason.chars().any(char::is_control) {
            return Err(RiskGuardError::InvalidArgument(
                "reason must be 1..1000 bytes without control characters".into(),
            ));
        }
        self.clear_restriction_unchecked(target, scope, operator, reason, now_ms)
    }

    pub fn clear_restriction_break_glass(
        &self,
        target: RestrictionTarget<'_>,
        scope: &str,
        operator: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<Value> {
        tracing::warn!(
            operator,
            scope,
            "BREAK-GLASS: a restriction is being cleared without a second person"
        );
        self.clear_restriction_unchecked(
            target,
            scope,
            &format!("{operator} (BREAK-GLASS)"),
            &format!("BREAK-GLASS: {reason}"),
            now_ms,
        )
    }

    /// Ask for a loosening. Returns the request's id.
    pub fn propose_change(
        &self,
        kind: &str,
        target: &str,
        params: &Value,
        reason: &str,
        proposer: &str,
        now_ms: i64,
    ) -> Result<String> {
        if !KINDS.contains(&kind) {
            return Err(RiskGuardError::InvalidArgument(format!(
                "kind must be one of {}",
                KINDS.join(", ")
            )));
        }
        person(proposer, "proposer")?;
        person(target, "target")?;
        person(reason, "reason")?;
        if reason.len() > 1000 {
            return Err(RiskGuardError::InvalidArgument("reason is too long".into()));
        }
        let built;
        let params = if kind == "policy_update" {
            match self.build_policy_update(target, params) {
                Ok(candidate) => {
                    built = candidate;
                    &built
                }
                Err(error) => {
                    // Keep the refusal and why, so the audit trail shows the attempt.
                    self.lock_conn()?.execute(
                        "INSERT INTO change_requests (id, kind, target, params_json, reason, proposer, proposed_at_ms, expires_at_ms, status, outcome)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'refused', ?8)",
                        params![
                            uuid::Uuid::new_v4().simple().to_string(),
                            kind,
                            target,
                            params.to_string(),
                            reason,
                            proposer,
                            now_ms,
                            format!("refused: {error}")
                        ],
                    )?;
                    return Err(error);
                }
            }
        } else {
            params
        };
        match kind {
            "release_quarantine" => {
                let held: bool = self.lock_read_conn()?.query_row(
                    "SELECT EXISTS(SELECT 1 FROM workload_quarantine WHERE agent_id = ?1)",
                    params![target],
                    |row| row.get(0),
                )?;
                if !held {
                    return Err(RiskGuardError::InvalidArgument(format!(
                        "'{target}' is not quarantined"
                    )));
                }
            }
            "clear_restriction" => {
                let scope = params["scope"].as_str().ok_or_else(|| {
                    RiskGuardError::InvalidArgument("clear_restriction needs params.scope".into())
                })?;
                let context = params["context_id"].as_str();
                let listed = self.list_restrictions(
                    RestrictionTarget::Agent {
                        agent_id: target,
                        context_id: context,
                    },
                    now_ms,
                )?;
                if !listed.to_string().contains(&serde_json::to_string(scope)?) {
                    return Err(RiskGuardError::InvalidArgument(
                        "no restriction with that exact scope for that workload".into(),
                    ));
                }
            }
            "policy_update" => {}
            "baseline_update" => {
                parse_baseline_change(params)?;
                if self.get_baseline(target)?.is_none() {
                    return Err(RiskGuardError::InvalidArgument(format!(
                        "there is no baseline for task profile '{target}'"
                    )));
                }
            }
            "update_guardrails" => {
                if !self.two_person_required()? {
                    return Err(RiskGuardError::InvalidArgument(
                        "two-person approval is not on".into(),
                    ));
                }
                let update: crate::guardrails::GuardrailsUpdate =
                    serde_json::from_value(params.clone()).map_err(|e| {
                        RiskGuardError::InvalidArgument(format!(
                            "update_guardrails needs valid GuardrailsUpdate params: {e}"
                        ))
                    })?;
                update.settings.validate()?;
                let exists: bool = self.lock_read_conn()?.query_row(
                    "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
                    params![target],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Err(RiskGuardError::InvalidArgument(
                        "agent does not exist".into(),
                    ));
                }
            }
            "demote_adaptive_model" => {
                if !self.two_person_required()? {
                    return Err(RiskGuardError::InvalidArgument(
                        "two-person approval is not on".into(),
                    ));
                }
                let model_id = params["model_id"].as_str().unwrap_or_default().trim();
                let mode = params["mode"].as_str().unwrap_or_default();
                if model_id.is_empty() || !matches!(mode, "shadow" | "off") {
                    return Err(RiskGuardError::InvalidArgument(
                        "demote_adaptive_model needs params.model_id and params.mode ('shadow' or 'off')".into(),
                    ));
                }
            }
            _ => {
                if !self.two_person_required()? {
                    return Err(RiskGuardError::InvalidArgument(
                        "two-person approval is not on".into(),
                    ));
                }
            }
        }
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending: Option<String> = tx
            .query_row(
                "SELECT id FROM change_requests WHERE kind = ?1 AND target = ?2 AND status = 'pending' AND expires_at_ms > ?3",
                params![kind, target, now_ms],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = pending {
            return Err(RiskGuardError::InvalidArgument(format!(
                "a request for the same change is already waiting: {id}"
            )));
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        tx.execute(
            "INSERT INTO change_requests (id, kind, target, params_json, reason, proposer, proposed_at_ms, expires_at_ms, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending')",
            params![id, kind, target, params.to_string(), reason, proposer, now_ms, now_ms + EXPIRY_MS],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Approve or reject a request. Approving someone else's request carries it out; approving your own is refused.
    pub fn decide_change(
        &self,
        id: &str,
        decider: &str,
        approve: bool,
        reason: &str,
        now_ms: i64,
    ) -> Result<Value> {
        person(decider, "decider")?;
        person(reason, "reason")?;
        let (kind, target, params_json, proposer, status, expires): (
            String,
            String,
            String,
            String,
            String,
            i64,
        ) = {
            let conn = self.lock_read_conn()?;
            conn.query_row(
                "SELECT kind, target, params_json, proposer, status, expires_at_ms FROM change_requests WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()?
            .ok_or_else(|| RiskGuardError::InvalidArgument("no such change request".into()))?
        };
        if status != "pending" {
            return Err(RiskGuardError::InvalidArgument(format!(
                "that request is already {status}"
            )));
        }
        if expires <= now_ms {
            self.lock_conn()?.execute(
                "UPDATE change_requests SET status = 'expired' WHERE id = ?1 AND status = 'pending'",
                params![id],
            )?;
            return Err(RiskGuardError::InvalidArgument(
                "that request expired (requests last 24 hours); propose it again".into(),
            ));
        }
        if approve && same_person(decider, &proposer) {
            return Err(RiskGuardError::PermissionDenied(
                "a change must be approved by someone other than the person who proposed it".into(),
            ));
        }
        // Decide first, atomically, so two deciders cannot both act on one request.
        let decided = self.lock_conn()?.execute(
            "UPDATE change_requests SET status = ?2, decided_by = ?3, decided_at_ms = ?4, decision_reason = ?5 WHERE id = ?1 AND status = 'pending'",
            params![id, if approve { "approved" } else { "rejected" }, decider, now_ms, reason],
        )?;
        if decided == 0 {
            return Err(RiskGuardError::InvalidArgument(
                "that request was decided by someone else a moment ago".into(),
            ));
        }
        let mut outcome = "rejected".to_string();
        if approve {
            let who = format!("{proposer}+{decider}");
            let why =
                format!("{reason} (proposed by {proposer}, approved by {decider}, change {id})");
            let params: Value = serde_json::from_str(&params_json)?;
            if kind == "policy_update" {
                // Approving records the decision and the command for a person to run. Risk Guard never writes OpenShell policy, so nothing is applied here.
                let outcome = policy_update_outcome(&params, id);
                self.lock_conn()?.execute(
                    "UPDATE change_requests SET outcome = ?2 WHERE id = ?1",
                    params![id, outcome],
                )?;
                return Ok(
                    serde_json::json!({"id": id, "kind": kind, "target": target, "proposer": proposer, "decided_by": decider, "approved": true, "outcome": outcome}),
                );
            }
            let result = match kind.as_str() {
                "release_quarantine" => self
                    .release_workload_unchecked(&target, &who, &why, now_ms)
                    .map(|was| {
                        if was {
                            "released".to_string()
                        } else {
                            "was not quarantined".to_string()
                        }
                    }),
                "clear_restriction" => self
                    .clear_restriction_unchecked(
                        RestrictionTarget::Agent {
                            agent_id: &target,
                            context_id: params["context_id"].as_str(),
                        },
                        params["scope"].as_str().unwrap_or_default(),
                        &who,
                        &why,
                        now_ms,
                    )
                    .map(|_| "cleared".to_string()),
                "baseline_update" => self.apply_baseline_update(&target, &params, &who, id),
                "update_guardrails" => serde_json::from_value::<crate::guardrails::GuardrailsUpdate>(params.clone())
                    .map_err(|e| RiskGuardError::InvalidArgument(format!("invalid GuardrailsUpdate: {e}")))
                    .and_then(|update| {
                        match self.save_agent_guardrails_approved(&target, &update, &who, now_ms)? {
                            crate::guardrails::GuardrailsSaveResult::Saved(view) => Ok(format!(
                                "guardrails saved (revision {})",
                                view["revision"].as_u64().unwrap_or(0)
                            )),
                            crate::guardrails::GuardrailsSaveResult::Conflict { current_revision } => {
                                Err(RiskGuardError::InvalidArgument(format!(
                                    "guardrail revision conflict (current revision is {current_revision})"
                                )))
                            }
                        }
                    }),
                "demote_adaptive_model" => self.demote_adaptive_model_approved(
                    &target,
                    params["model_id"].as_str().unwrap_or_default(),
                    params["mode"].as_str().unwrap_or_default(),
                    &who,
                    now_ms,
                ),
                _ => self
                    .lock_conn()?
                    .execute(
                        "DELETE FROM service_settings WHERE name = ?1",
                        params![TWO_PERSON],
                    )
                    .map(|_| "two-person approval turned off".to_string())
                    .map_err(RiskGuardError::from),
            };
            let (status, text) = match result {
                Ok(text) => ("executed", text),
                Err(error) => ("failed", error.to_string()),
            };
            // Home "openshell": the baseline now holds the new entries (so nothing is unprotected meanwhile); ask for the matching OpenShell policy candidate.
            let text = if kind == "baseline_update"
                && status == "executed"
                && parse_baseline_change(&params).is_ok_and(|c| c.home == Home::OpenShell)
            {
                format!(
                    "{text}. {}",
                    self.request_policy_candidate(&target, id, now_ms)
                )
            } else {
                text
            };
            self.lock_conn()?.execute(
                "UPDATE change_requests SET status = ?2, outcome = ?3 WHERE id = ?1",
                params![id, status, text],
            )?;
            outcome = format!("{status}: {text}");
        }
        Ok(
            serde_json::json!({"id": id, "kind": kind, "target": target, "proposer": proposer, "decided_by": decider, "approved": approve, "outcome": outcome}),
        )
    }

    /// After an approved baseline change that chose OpenShell as its home: propose a `policy_update` for the same profile, generated from the baseline as it now is and proven
    /// no wider than it. It is an ordinary request in the queue; nothing is applied by it, and it reaches only the next sandbox (or a network-rule hot reload). Returns the sentence
    /// added to the change's outcome: the new request's id, or why none could be built (the rule is then still enforced by Risk Guard).
    fn request_policy_candidate(&self, task_profile: &str, change_id: &str, now_ms: i64) -> String {
        let short = &change_id[..change_id.len().min(8)];
        match self.propose_change(
            "policy_update",
            task_profile,
            &serde_json::json!({"enforcement": "enforce", "linked_change": change_id}),
            &format!("move the routes and hosts approved in change {short} into OpenShell policy"),
            &format!("system (after change {short})"),
            now_ms,
        ) {
            Ok(request) => format!(
                "OpenShell policy candidate requested: {request} (review and approve it in Approvals, then create a new sandbox with it; until a sandbox runs it, Risk Guard still enforces these entries)"
            ),
            Err(error) => format!(
                "no OpenShell policy candidate could be built ({error}); these entries stay enforced by Risk Guard only"
            ),
        }
    }

    /// The newest stored policy of a sandbox that ran under `task_profile`: the named sandbox, or the latest snapshot of any sandbox for that profile.
    fn policy_source(
        &self,
        task_profile: &str,
        sandbox: Option<&str>,
    ) -> Result<Option<(String, String, String)>> {
        let conn = self.lock_read_conn()?;
        conn.query_row(
            "SELECT p.sandbox_id, p.policy_hash, p.policy_yaml
               FROM policy_snapshots p JOIN epochs e ON e.sandbox_id = p.sandbox_id
              WHERE e.task_profile = ?1 AND (?2 IS NULL OR p.sandbox_id = ?2)
              ORDER BY p.captured_at_ms DESC, p.id DESC LIMIT 1",
            params![task_profile, sandbox],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(Into::into)
    }

    /// Build the request parameters of a `policy_update`: the candidate policy and everything a reviewer needs to judge it. Refuses anything it cannot show is no wider.
    fn build_policy_update(&self, task_profile: &str, asked: &Value) -> Result<Value> {
        let enforcement = asked["enforcement"].as_str().unwrap_or_default();
        if !matches!(enforcement, "audit" | "enforce") {
            return Err(RiskGuardError::InvalidArgument(
                "params.enforcement must be audit or enforce".into(),
            ));
        }
        let sandbox = asked
            .get("sandbox")
            .filter(|v| !v.is_null())
            .map(|v| v.as_str().map(str::to_string))
            .map(|v| v.filter(|s| safe_name(s)));
        let sandbox = match sandbox {
            None => None,
            Some(Some(name)) => Some(name),
            Some(None) => {
                return Err(RiskGuardError::InvalidArgument(
                    "params.sandbox may use only letters, digits, '.', '_' and '-' (up to 128), so the command shown after approval is safe to paste".into(),
                ));
            }
        };
        let baseline = self.get_baseline(task_profile)?.ok_or_else(|| {
            RiskGuardError::InvalidArgument(format!(
                "there is no baseline for task profile '{task_profile}'"
            ))
        })?;
        if baseline.allowed_action_classes.is_empty() {
            return Err(RiskGuardError::InvalidArgument(format!(
                "the baseline for '{task_profile}' lists no approved routes, which means \"not specified\"; a policy written from it would allow nothing"
            )));
        }
        let (sandbox_id, policy_hash, source_yaml) = self
            .policy_source(task_profile, sandbox.as_deref())?
            .ok_or_else(|| {
                RiskGuardError::InvalidArgument(match &sandbox {
                    Some(name) => format!(
                        "no stored policy for sandbox '{name}' running task profile '{task_profile}'"
                    ),
                    None => format!("no stored policy for any sandbox running task profile '{task_profile}'"),
                })
            })?;
        if !safe_name(&sandbox_id) {
            return Err(RiskGuardError::InvalidArgument(
                "the sandbox id has characters that are not safe to put in a command; propose with a baseline export from the command line instead".into(),
            ));
        }
        let export = crate::policy_export::export_policy(&baseline, &source_yaml, enforcement)?;
        let proof = export.summary["proof"].clone();
        if proof["verified_no_wider"] != true {
            return Err(RiskGuardError::InvalidArgument(format!(
                "the prover did not certify the candidate as no wider than the current policy (verdict: {}); nothing was proposed",
                proof["step2_prover"]
            )));
        }
        let rule_diff = crate::policy_export::network_rules_diff(&source_yaml, &export.yaml)?;
        let changed = rule_diff.contains("\n@@ ");
        if !changed {
            return Err(RiskGuardError::InvalidArgument(
                "the sandbox's policy already matches the baseline in this mode; there is nothing to change".into(),
            ));
        }
        // export_policy writes only network rules, so this should always be false; it is checked, not assumed.
        let requires_new_sandbox =
            crate::policy_export::differs_outside_network_policies(&source_yaml, &export.yaml)?;
        Ok(serde_json::json!({
            "task_profile": task_profile,
            "enforcement": enforcement,
            "sandbox": sandbox_id,
            "source_policy_hash": policy_hash,
            "baseline_version": baseline.version,
            "candidate_yaml": export.yaml,
            "proof": proof,
            "rule_diff": rule_diff,
            "requires_new_sandbox": requires_new_sandbox,
            "notes": export.summary["notes"],
            "linked_change": asked.get("linked_change").cloned().unwrap_or(Value::Null),
            "applied": false,
        }))
    }

    /// The candidate policy of a `policy_update` that is waiting or approved, with a file name for it. Rejected, expired and unknown requests have none.
    pub fn change_policy(&self, id: &str, now_ms: i64) -> Result<Option<(String, String)>> {
        let row: Option<(String, String, String, i64, String)> = {
            let conn = self.lock_read_conn()?;
            conn.query_row(
                "SELECT kind, params_json, status, expires_at_ms, target FROM change_requests WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?
        };
        let Some((kind, params_json, status, expires, target)) = row else {
            return Ok(None);
        };
        let live = (status == "pending" && expires > now_ms) || status == "approved";
        if kind != "policy_update" || !live {
            return Ok(None);
        }
        let params: Value = serde_json::from_str(&params_json)?;
        Ok(params["candidate_yaml"]
            .as_str()
            .map(|yaml| (yaml.to_string(), policy_file_name(&target, id))))
    }

    /// Carry out an approved baseline change on the baseline as it is now (not as it was when the request was made), as a new version. Sandboxes already running keep the
    /// baseline they were started with; new ones use this one.
    fn apply_baseline_update(
        &self,
        task_profile: &str,
        params: &Value,
        approved_by: &str,
        change_id: &str,
    ) -> Result<String> {
        let change = parse_baseline_change(params)?;
        let mut baseline = self.get_baseline(task_profile)?.ok_or_else(|| {
            RiskGuardError::InvalidArgument(format!("there is no baseline for '{task_profile}'"))
        })?;
        let (mut routes, mut hosts, mut rates) = (0, 0, 0);
        for route in change.routes {
            routes += usize::from(baseline.allowed_action_classes.insert(route));
        }
        for host in change.hosts {
            hosts += usize::from(baseline.approved_egress_hosts.insert(host));
        }
        for (name, value) in change.rates {
            // Lowering only: a request that would raise a limit changes nothing.
            let slot = if name == "max_req_1m_p95" {
                &mut baseline.max_req_1m_p95
            } else {
                &mut baseline.max_req_1m_p99
            };
            if value < *slot {
                *slot = value;
                rates += 1;
            }
        }
        if routes + hosts + rates == 0 {
            return Err(RiskGuardError::InvalidArgument(
                "nothing to change: the baseline already has these entries and limits".into(),
            ));
        }
        baseline
            .validate_egress_hosts()
            .map_err(RiskGuardError::InvalidArgument)?;
        let base = baseline
            .version
            .split("+c")
            .next()
            .unwrap_or_default()
            .to_string();
        baseline.version = format!("{base}+c{}", &change_id[..change_id.len().min(8)]);
        baseline.approved_by = approved_by.to_string();
        let hash = self.store_baseline(&baseline)?;
        Ok(format!(
            "baseline {task_profile} stored as {}: {routes} route(s), {hosts} host(s), {rates} limit(s) changed (hash {})",
            baseline.version,
            &hash[..12]
        ))
    }

    /// Requests, newest first. Pending ones past their expiry are shown as expired.
    pub fn list_changes(&self, limit: u32, now_ms: i64) -> Result<Value> {
        // Read the setting before taking the connection: the lock is not re-entrant, and asking for it twice from one thread waits forever.
        let required = self.two_person_required()?;
        let conn = self.lock_read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, kind, target, params_json, reason, proposer, proposed_at_ms, expires_at_ms, status, decided_by, decided_at_ms, decision_reason, outcome
             FROM change_requests ORDER BY proposed_at_ms DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit.min(500)], |row| {
                let status: String = row.get(8)?;
                let expires: i64 = row.get(7)?;
                Ok(serde_json::json!({
                    "id": row.get::<_, String>(0)?, "kind": row.get::<_, String>(1)?, "target": row.get::<_, String>(2)?,
                    "params": serde_json::from_str::<Value>(&row.get::<_, String>(3)?).unwrap_or_default(),
                    "reason": row.get::<_, String>(4)?, "proposer": row.get::<_, String>(5)?,
                    "proposed_at_ms": row.get::<_, i64>(6)?, "expires_at_ms": expires,
                    "status": if status == "pending" && expires <= now_ms { "expired".to_string() } else { status },
                    "decided_by": row.get::<_, Option<String>>(9)?, "decided_at_ms": row.get::<_, Option<i64>>(10)?,
                    "decision_reason": row.get::<_, Option<String>>(11)?, "outcome": row.get::<_, Option<String>>(12)?,
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({ "changes": rows, "two_person_required": required }))
    }
}

/// What a route needs before Risk Guard suggests it: enough calls, spread over enough hours that it is a habit and not a burst.
const SUGGEST_MIN_CALLS: i64 = 20;
const SUGGEST_MIN_HOURS: i64 = 3;

/// `GET /repos/{owner}/{repo}` and `GET /repos/{org}/{name}` are the same route: compare with the placeholder names removed.
fn route_shape(action_class: &str) -> String {
    let mut out = String::with_capacity(action_class.len());
    let mut inside = false;
    for ch in action_class.trim().chars() {
        match ch {
            '{' => {
                inside = true;
                out.push_str("{}");
            }
            '}' => inside = false,
            _ if !inside => out.push(ch),
            _ => {}
        }
    }
    out
}

impl SqliteRiskStore {
    /// Routes each task profile has used steadily, never been refused on, and does not list in its baseline, from this service's own decision history. It never reads the SIEM, so
    /// it works when the SIEM is down. It suggests only; a person proposes the change and a second person approves it.
    pub fn suggest_baseline_changes(&self, since_ms: i64, now_ms: i64) -> Result<Value> {
        let profiles: Vec<String> = {
            let conn = self.lock_read_conn()?;
            let mut stmt =
                conn.prepare("SELECT DISTINCT task_profile FROM epochs ORDER BY task_profile")?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        let mut out = Vec::new();
        for profile in profiles {
            let Some(baseline) = self.get_baseline(&profile)? else {
                continue;
            };
            let known: BTreeSet<String> = baseline
                .allowed_action_classes
                .iter()
                .map(|c| route_shape(c))
                .collect();
            let rows: Vec<(String, String, i64, i64, i64, i64)> = {
                let conn = self.lock_read_conn()?;
                let mut stmt = conn.prepare(
                    "SELECT json_extract(d.normalized_request_json, '$.action_class'),
                            json_extract(d.normalized_request_json, '$.method'),
                            COUNT(*),
                            SUM(CASE WHEN d.outcome = 'deny' THEN 1 ELSE 0 END),
                            COUNT(DISTINCT d.created_at_ms / 3600000),
                            MAX(COALESCE(json_extract(d.normalized_request_json, '$.high_impact'), 0))
                       FROM decisions d JOIN epochs e ON e.epoch_id = d.epoch_id
                      WHERE e.task_profile = ?1 AND d.created_at_ms >= ?2
                      GROUP BY 1, 2",
                )?;
                stmt.query_map(params![profile, since_ms], |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })?
                .collect::<std::result::Result<_, _>>()?
            };
            let (mut add, mut skip) = (Vec::new(), Vec::new());
            for (action_class, method, calls, refused, hours, high_impact) in rows {
                if action_class.is_empty()
                    || action_class.ends_with(" unknown")
                    || known.contains(&route_shape(&action_class))
                {
                    continue;
                }
                let why = if refused > 0 {
                    Some(format!("refused {refused} time(s)"))
                } else if !matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
                    Some("not a read; add it deliberately by importing a baseline".to_string())
                } else if high_impact != 0 {
                    Some("marked high impact".to_string())
                } else if calls < SUGGEST_MIN_CALLS || hours < SUGGEST_MIN_HOURS {
                    Some(format!(
                        "not steady enough yet ({calls} calls in {hours} hour(s); needs {SUGGEST_MIN_CALLS} in {SUGGEST_MIN_HOURS})"
                    ))
                } else {
                    None
                };
                let entry = serde_json::json!({"action_class": action_class, "calls": calls, "hours": hours, "refused": refused});
                match why {
                    None => add.push(entry),
                    Some(why) => {
                        let mut entry = entry;
                        entry["why_not"] = Value::String(why);
                        skip.push(entry);
                    }
                }
            }
            out.push(serde_json::json!({
                "task_profile": profile, "baseline_version": baseline.version,
                "add_action_classes": add, "not_suggested": skip,
            }));
        }
        Ok(serde_json::json!({
            "profiles": out, "since_ms": since_ms, "generated_at_ms": now_ms,
            "needs": {"calls": SUGGEST_MIN_CALLS, "hours": SUGGEST_MIN_HOURS},
            "source": "this service's own decision history",
        }))
    }
}
