// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! One list of every control that can stop or advise on a call, with the same few words for each: where it comes from (OpenShell, a rule, learned behavior, the SIEM), what mode
//! it is in (enforcing, watching, off), what it did in the last day, and whether it has the data it needs. The console's Controls page is this list.
//!
//! The words are fixed on purpose. **Enforcing** blocks. **Watching** works out its answer, writes it down and lets the call through (called "shadow" elsewhere in the code).
//! **Off** does nothing. A control that needs history says so, with the numbers, instead of looking as if it were working.

use super::*;
use crate::detector::REASON_BASELINE_INSUFFICIENT;
use crate::types::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// The rules a baseline can turn on, in the order a reader meets them.
const RULES: [(&str, &str, &str); 5] = [
    (
        RULE_FORBIDDEN_ACTION,
        "Deny list",
        "Refuses any action the task profile lists as forbidden. Always enforcing when it has entries.",
    ),
    (
        RULE_UNFAMILIAR_HIGH_IMPACT,
        "High-impact on an unfamiliar resource",
        "Refuses a destructive or administrative action on a resource the task does not approve.",
    ),
    (
        RULE_UNAPPROVED_ACTION,
        "Approved routes",
        "Refuses a route the task profile's approved list does not contain.",
    ),
    (
        RULE_UNAPPROVED_RESOURCE,
        "Approved resources",
        "Refuses a resource the task profile's approved list does not contain.",
    ),
    (
        RULE_EGRESS_DESTINATION,
        "Approved egress hosts",
        "At the tunnel gate, refuses a connection to a host the task profile does not approve.",
    ),
];

fn rule_list_is_empty(baseline: &BaselineProfile, rule: &str) -> bool {
    match rule {
        RULE_FORBIDDEN_ACTION => baseline.forbidden_action_classes.is_empty(),
        RULE_UNAPPROVED_ACTION => baseline.allowed_action_classes.is_empty(),
        RULE_UNAPPROVED_RESOURCE => baseline.approved_resources.is_empty(),
        RULE_EGRESS_DESTINATION => baseline.approved_egress_hosts.is_empty(),
        _ => false,
    }
}

/// What a profile does with a rule: `enforcing`, `watching`, `off`, or `no_list` when the rule has nothing to match (an empty list means "not specified", never "block everything").
fn profile_state(baseline: &BaselineProfile, rule: &str) -> &'static str {
    if rule_list_is_empty(baseline, rule) {
        return "no_list";
    }
    match baseline.rule_mode(rule) {
        RuleMode::Enforce => "enforcing",
        RuleMode::Shadow => "watching",
        RuleMode::Off => "off",
    }
}

fn overall(states: &[&str]) -> &'static str {
    let count = |name: &str| states.iter().filter(|s| **s == name).count();
    let (enforcing, watching) = (count("enforcing"), count("watching"));
    match (enforcing, watching) {
        (0, 0) if count("no_list") > 0 && count("off") == 0 => "no_list",
        (0, 0) => "off",
        (_, 0) => "enforcing",
        (0, _) => "watching",
        _ => "mixed",
    }
}

impl SqliteRiskStore {
    /// Remember how this process was started (tunnel mode, whether the signals door is open and whether it is a dry run), so the console can say so. Written at start-up.
    pub fn record_runtime_facts(&self, facts: &[(&str, &str)], now_ms: i64) -> Result<()> {
        let conn = self.lock_conn()?;
        for (name, value) in facts {
            conn.execute(
                "INSERT OR REPLACE INTO service_settings (name, value, recorded_at_ms) VALUES (?1, ?2, ?3)",
                params![format!("runtime.{name}"), value, now_ms],
            )?;
        }
        Ok(())
    }

    fn runtime_fact(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .lock_read_conn()?
            .query_row(
                "SELECT value FROM service_settings WHERE name = ?1",
                params![format!("runtime.{name}")],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    fn count_by_text(&self, sql: &str, since_ms: i64) -> Result<Vec<(String, i64)>> {
        let conn = self.lock_read_conn()?;
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map(params![since_ms], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    row.get::<_, i64>(1)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every control, its mode, what it did in the last day, and whether it has the data it needs.
    pub fn controls_overview(&self, now_ms: i64) -> Result<Value> {
        let since = now_ms - DAY_MS;
        // The runtime facts are read before any connection is held: the read lock is not re-entrant.
        let tunnel_mode = self.runtime_fact("tunnel_restriction_mode")?;
        let tunnel_gate = self.runtime_fact("tunnel_gate")?;
        let signals_listening = self.runtime_fact("signals_listening")?;
        let signals_dry_run = self.runtime_fact("signals_dry_run")?;
        let names: Vec<String> = {
            let conn = self.lock_read_conn()?;
            let mut stmt = conn.prepare("SELECT DISTINCT name FROM artifacts WHERE artifact_type = 'baseline_profile' ORDER BY name")?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        let mut profiles = Vec::new();
        for name in names {
            if let Some(baseline) = self.get_baseline(&name)? {
                profiles.push(baseline);
            }
        }

        let total_24h: i64 = self.lock_read_conn()?.query_row(
            "SELECT COUNT(*) FROM decisions WHERE created_at_ms >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        // Watching rules write one "shadow_rule" signal per request they would have refused; enforcing ones appear in the task_constraint signal.
        let would_refuse = self.count_by_text(
            "SELECT json_extract(s.value, '$.baseline_summary'), COUNT(*) FROM decisions d, json_each(d.evaluation_json, '$.signals') s
              WHERE d.created_at_ms >= ?1 AND json_extract(s.value, '$.feature') = 'shadow_rule' GROUP BY 1",
            since,
        )?;
        let refused = self.count_by_text(
            "SELECT json_extract(s.value, '$.baseline_summary'), COUNT(*) FROM decisions d, json_each(d.evaluation_json, '$.signals') s
              WHERE d.created_at_ms >= ?1 AND json_extract(s.value, '$.feature') = 'task_constraint' GROUP BY 1",
            since,
        )?;
        let reasons = self.count_by_text("SELECT json_extract(evaluation_json, '$.reason_code'), COUNT(*) FROM decisions WHERE created_at_ms >= ?1 GROUP BY 1", since)?;
        let reason = |code: &str| {
            reasons
                .iter()
                .find(|(r, _)| r == code)
                .map_or(0, |(_, n)| *n)
        };
        let mut watching_by_rule: BTreeMap<String, i64> = BTreeMap::new();
        for (summary, n) in &would_refuse {
            if let Some(rule) = summary
                .strip_prefix("rule=")
                .and_then(|s| s.split(';').next())
            {
                *watching_by_rule.entry(rule.to_string()).or_default() += n;
            }
        }
        let mut refused_by_rule: BTreeMap<String, i64> = BTreeMap::new();
        for (summary, n) in &refused {
            if let Some(rules) = summary
                .strip_prefix("rules=")
                .and_then(|s| s.split(';').next())
            {
                for rule in rules.split(',').filter(|r| !r.is_empty()) {
                    *refused_by_rule.entry(rule.to_string()).or_default() += n;
                }
            }
        }
        let signal_counts = self.count_by_text(
            "SELECT outcome, COUNT(*) FROM siem_signals WHERE received_at_ms >= ?1 GROUP BY 1",
            since,
        )?;
        let silence_24h: i64 = self.lock_read_conn()?.query_row(
            "SELECT COUNT(*) FROM supervisor_silence_events WHERE at_ms >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        let quarantined_now = self.list_quarantined()?["quarantined"]
            .as_array()
            .map_or(0, Vec::len);

        // How the service was started is recorded by a running Risk Guard. A database nobody has served has no such record, and the controls that depend on it say so.
        let started_known = tunnel_gate.is_some() || signals_listening.is_some();
        let unknown_start = json!({"state": "not_applicable", "note": "No running Risk Guard has recorded how it was started against this database, so its mode here is not known."});
        let mut controls: Vec<Value> = Vec::new();
        controls.push(json!({
            "id": "openshell_network_policy", "source": "openshell", "name": "OpenShell network policy", "mode": "enforcing",
            "what": "Refuses hosts, methods and routes the sandbox's policy does not allow, endpoint by endpoint (enforce blocks; audit only logs). The policies deployed here set enforce. This is the floor and it does not depend on any learning.",
            "evidence": {"note": "OpenShell enforces this itself; its refusals are in the SIEM's OpenShell events."},
            "data": {"state": "ok", "note": "Needs no data."},
        }));
        controls.push(json!({
            "id": "openshell_filesystem", "source": "openshell", "name": "OpenShell filesystem and process confinement (Landlock)", "mode": "enforcing",
            "what": "Limits which files and programs a sandbox can touch. OpenShell requires Landlock: a sandbox on a kernel without it does not start, so there is no weaker mode to fall back on. Risk Guard does not see file access; it only shows the filesystem policy.",
            "evidence": {"note": "No file-access events appear in the SIEM today."},
            "data": {"state": "ok", "note": "Needs no data."},
        }));
        for (rule, name, what) in RULES {
            let states: Vec<&str> = profiles.iter().map(|p| profile_state(p, rule)).collect();
            let per_profile: Vec<Value> = profiles
                .iter()
                .map(|p| json!({"task_profile": p.task_profile, "state": profile_state(p, rule)}))
                .collect();
            let mode = overall(&states);
            let at_tunnel = rule == RULE_EGRESS_DESTINATION;
            let evidence = if at_tunnel {
                json!({"note": "Counted at the tunnel gate and shown in the SIEM (Egress and policy dashboard); not kept in this service's database."})
            } else {
                json!({"would_refuse_24h": watching_by_rule.get(rule).copied().unwrap_or(0), "refused_24h": refused_by_rule.get(rule).copied().unwrap_or(0), "calls_24h": total_24h})
            };
            let data = match mode {
                _ if at_tunnel && !started_known => unknown_start.clone(),
                "no_list" => {
                    json!({"state": "not_applicable", "note": "No task profile lists anything for this rule yet, so it has nothing to match."})
                }
                _ => {
                    json!({"state": "ok", "note": "Works from the lists a person approved; it does not learn."})
                }
            };
            let mode = if at_tunnel && !started_known {
                "unknown"
            } else if at_tunnel && tunnel_gate.as_deref() != Some("on") {
                "off"
            } else {
                mode
            };
            controls.push(json!({
                "id": rule, "source": "rule", "name": name, "mode": mode, "what": what, "profiles": per_profile, "evidence": evidence, "data": data,
            }));
        }
        {
            let tunnel_on = tunnel_gate.as_deref() == Some("on");
            let silent_states: Vec<&str> = profiles
                .iter()
                .map(|p| match p.rule_mode(RULE_SUPERVISOR_SILENT) {
                    RuleMode::Enforce => "enforcing",
                    RuleMode::Shadow => "watching",
                    RuleMode::Off => "off",
                })
                .collect();
            controls.push(json!({
                "id": RULE_SUPERVISOR_SILENT, "source": "rule", "name": "Silent supervisor", "mode": if !started_known { "unknown" } else if tunnel_on { overall(&silent_states) } else { "off" },
                "what": "At the tunnel gate, notices a sandbox that has been asking Risk Guard about requests and then stops while still opening tunnels, which is what a bypassed supervisor looks like.",
                "evidence": {"seen_24h": silence_24h}, "data": if started_known { json!({"state": "ok", "note": "Needs no history."}) } else { unknown_start.clone() },
            }));
            controls.push(json!({
                "id": "tunnel_restriction", "source": "rule", "name": "Latched restriction at the tunnel gate",
                "mode": if !started_known { "unknown" } else if !tunnel_on { "off" } else if tunnel_mode.as_deref() == Some("enforce") { "enforcing" } else { "watching" },
                "what": "After a refused action a workload is restricted. At the tunnel gate this either only records that it would cut the workload's connections (watching) or does cut them, including to the model (enforcing).",
                "evidence": {"note": "Counted in the SIEM as tunnel_would_refuse."}, "data": if started_known { json!({"state": "ok", "note": "Needs no history."}) } else { unknown_start.clone() },
            }));
        }
        // The deny list and the approved routes are method-and-path lists, which OpenShell's own policy can express (allow and deny rules per endpoint), reviewed and prover-checked.
        for control in &mut controls {
            if matches!(
                control["id"].as_str(),
                Some(RULE_FORBIDDEN_ACTION | RULE_UNAPPROVED_ACTION)
            ) {
                control["recommended_home"] = json!(
                    "OpenShell policy can hold this list too, and is the better home for it. It is kept here for now so it can run in watching mode and follow a workload between sandboxes."
                );
            }
        }
        let mature = profiles
            .iter()
            .filter(|p| p.maturity() == BaselineMaturity::Mature)
            .count();
        // Workloads whose maturity an operator backed with what the adaptive learner observed (who, when, which model).
        let credits = adaptive::counting_credits(&*self.lock_read_conn()?)?;
        let learning: Vec<Value> = profiles
            .iter()
            .map(|p| {
                let credited: Vec<Value> = credits
                    .iter()
                    .filter(|c| c.task_profile == p.task_profile)
                    .map(|c| json!({"workload": c.agent_id, "sessions": c.sessions, "requests": c.requests, "credited_by": c.granted_by, "credited_at_ms": c.granted_at_ms, "model_id": c.model_id}))
                    .collect();
                json!({"task_profile": p.task_profile, "sessions": p.training_sessions, "requests": p.training_requests, "enough": p.maturity() == BaselineMaturity::Mature, "credited_workloads": credited})
            })
            .collect();
        controls.push(json!({
            "id": "behavioral_score", "source": "learned", "name": "Behavioral score",
            "mode": if mature == 0 { "watching" } else if mature == profiles.len() { "enforcing" } else { "mixed" },
            "what": "Scores how unusual a call is for its workload (rate, new routes, new resources). It can only refuse once a task profile has learned enough; until then it records a score and never refuses on rarity alone.",
            "profiles": learning,
            "evidence": {"refused_24h": reason(REASON_BEHAVIORAL_RISK_DENIED), "scored_but_not_enforceable_24h": reason(REASON_BASELINE_INSUFFICIENT), "calls_24h": total_24h},
            "data": {"state": if mature == profiles.len() && !profiles.is_empty() { "ok" } else { "not_enough_data" },
                     "note": format!("{mature} of {} task profiles have learned enough (20 sessions and 200 requests each). Until a profile has, OpenShell policy and the approved lists above are what protect it.{}", profiles.len(), if credits.is_empty() { String::new() } else { format!(" {} workload(s) are mature through an operator-credited adaptive model instead of the hand-kept counters (see credited_workloads).", credits.len()) })},
        }));
        controls.push(json!({
            "id": "latched_restriction", "source": "rule", "name": "Latched restriction (after a refused action)", "mode": "enforcing",
            "what": "When a high-impact action is refused, that scope is locked for the workload: its later calls in the scope are refused until a person clears the lock (two people when two-person approval is on). It follows the workload into new sandboxes.",
            "evidence": {"refused_24h": reason(REASON_BEHAVIORAL_RISK_RESTRICTED), "calls_24h": total_24h},
            "data": {"state": "ok", "note": "Needs no history."},
        }));
        let (models, waiting_review, last_pass) = {
            let conn = self.lock_read_conn()?;
            (
                conn.query_row("SELECT COUNT(*) FROM adaptive_models", [], |r| r.get::<_, i64>(0))?,
                conn.query_row("SELECT COUNT(*) FROM adaptive_sessions WHERE status = 'pending_review'", [], |r| r.get::<_, i64>(0))?,
                conn.query_row("SELECT MAX(created_at_ms) FROM adaptive_audit WHERE actor = 'scheduled-trainer'", [], |r| r.get::<_, Option<i64>>(0))?,
            )
        };
        controls.push(json!({
            "id": "adaptive_learning", "source": "learned", "name": "Adaptive learning", "mode": "watching",
            "what": "Learns each workload's normal behavior from allowed traffic and offers a model for a person to review. It never refuses anything until a person promotes it.",
            "evidence": {"models": models, "sessions_waiting_for_a_person": waiting_review, "last_scheduled_training_ms": last_pass,
                         "note": "See the Adaptive tab on a workload."},
            "data": {"state": "ok", "note": format!("{models} model(s) in all. {waiting_review} captured session(s) wait for a person to approve or reject them; runs that end clean are approved and trained automatically, and a scheduled pass (--adaptive-schedule-minutes) trains any approved windows a model has not seen yet.")},
        }));
        controls.push(json!({
            "id": "quarantine", "source": "operator", "name": "Quarantine", "mode": "enforcing",
            "what": "A person (or the SIEM, see below) stops a workload. Both gates refuse it until it is released; release needs a second person when two-person approval is on.",
            "evidence": {"quarantined_now": quarantined_now}, "data": {"state": "ok", "note": "Needs no history."},
        }));
        let listening = signals_listening.as_deref() == Some("1");
        let count = |outcome: &str| {
            signal_counts
                .iter()
                .find(|(o, _)| o == outcome)
                .map_or(0, |(_, n)| *n)
        };
        controls.push(json!({
            "id": "siem_signals", "source": "siem", "name": "SIEM signals (quarantine)",
            "mode": if !started_known { "unknown" } else if !listening { "off" } else if signals_dry_run.as_deref() == Some("1") { "watching" } else { "enforcing" },
            "what": "An OpenSearch alert can ask Risk Guard to quarantine a workload for a limited time. It can only tighten. In watching mode a signal is recorded and nothing changes.",
            "evidence": {"received_24h": signal_counts.iter().map(|(_, n)| n).sum::<i64>(), "applied_24h": count("applied"), "dry_run_24h": count("dry_run")},
            "data": if started_known { json!({"state": "ok", "note": "Needs no history."}) } else { unknown_start.clone() },
        }));
        {
            // SIEM context: OpenShell denials and fleet counts published by the SIEM, which can add a bounded number of points to a score.
            let (any_batch, fresh_features, newest_age_ms) = self.siem_features_status(now_ms)?;
            let context_states: Vec<&str> = profiles
                .iter()
                .map(|p| match p.rule_mode(RULE_SIEM_CONTEXT) {
                    RuleMode::Enforce => "enforcing",
                    RuleMode::Shadow => "watching",
                    RuleMode::Off => "off",
                })
                .collect();
            let (mut would_change, mut changed, mut would_add_decisions) = (0i64, 0i64, 0i64);
            for (summary, n) in self.count_by_text(
                "SELECT json_extract(s.value, '$.baseline_summary'), COUNT(*) FROM decisions d, json_each(d.evaluation_json, '$.signals') s
                  WHERE d.created_at_ms >= ?1 AND json_extract(s.value, '$.feature') = 'siem_context' GROUP BY 1",
                since,
            )? {
                let changes = summary.contains("changes_outcome=1");
                if summary.contains("mode=enforce;") {
                    changed += if changes { n } else { 0 };
                } else {
                    would_add_decisions += n;
                    would_change += if changes { n } else { 0 };
                }
            }
            let mode = overall(&context_states);
            let (state, note) = if !any_batch {
                (
                    "not_enough_data",
                    "no features received: the SIEM has not published any batch to this service yet.".to_string(),
                )
            } else {
                (
                    "ok",
                    format!(
                        "{fresh_features} fresh features; the newest batch arrived {} s ago.",
                        newest_age_ms.unwrap_or(0) / 1000
                    ),
                )
            };
            controls.push(json!({
                "id": RULE_SIEM_CONTEXT, "source": "siem", "name": "SIEM context (risk features)", "mode": if profiles.is_empty() { "watching" } else { mode },
                "what": "The SIEM publishes how often OpenShell's policy refused each sandbox, how a workload's refusals compare with the fleet's, and whether several workloads are being refused at once. These can add a bounded number of points (15 by default, 30 at most) to a call's risk score and never subtract. Watching records the points it would have added; enforcing adds them. Missing or old features add nothing, and a call never waits on the SIEM.",
                "profiles": profiles.iter().map(|p| json!({"task_profile": p.task_profile, "state": match p.rule_mode(RULE_SIEM_CONTEXT) { RuleMode::Enforce => "enforcing", RuleMode::Shadow => "watching", RuleMode::Off => "off" }, "max_points": crate::detector::siem::effective_max(p.siem_context_max_points)})).collect::<Vec<_>>(),
                "evidence": {
                    "fresh_features": fresh_features, "newest_batch_age_seconds": newest_age_ms.map(|ms| ms / 1000),
                    "would_have_changed_24h": would_change, "changed_24h": changed, "scored_with_points_while_watching_24h": would_add_decisions,
                    "calls_24h": total_24h,
                },
                "data": {"state": state, "note": note},
            }));
        }
        Ok(json!({
            "generated_at_ms": now_ms, "window_hours": 24, "calls_24h": total_24h, "profiles": profiles.len(),
            "vocabulary": {
                "enforcing": "Blocks the call.",
                "watching": "Works out its answer and records it, but lets the call through (called shadow elsewhere).",
                "off": "Does nothing.",
                "mixed": "Enforcing for some task profiles and watching or off for others.",
                "no_list": "Has nothing to match yet, because no list was set.",
                "not_built": "Described in the design, not in the product.",
                "unknown": "No running Risk Guard has recorded how it was started, so the mode cannot be shown.",
            },
            "controls": controls,
        }))
    }
}
