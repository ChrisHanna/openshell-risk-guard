// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Turn a task profile's approved lists into OpenShell policy rules.
//!
//! The deny list and the approved routes are method-and-path rules, which OpenShell's own network policy can hold: allow rules, deny rules that beat them, and a per-endpoint mode
//! (`audit` logs a violation and allows the request; `enforce` blocks it). OpenShell reloads network rules on a running sandbox within seconds. This module writes those rules
//! from a baseline into a copy of a sandbox policy, and checks with OpenShell's prover that the result is **no wider** than the policy it started from. It never applies anything:
//! the output is a file for a person to review and apply (`openshell policy set <sandbox> --policy <file> --wait`).
//!
//! What it changes: for each endpoint of the policy that the task profile's `risk-guard` middleware covers, `rules`, `deny_rules` and `enforcement`. What it keeps: everything
//! else, including the middleware, so Risk Guard still sees every call OpenShell allows.

use std::collections::BTreeSet;
use std::time::Duration;

use openshell_policy_schema::{L7Allow, L7DenyRule, L7Rule, parse_policy};
use serde_json::{Value, json};

use crate::error::{Result, RiskGuardError};
use crate::hardening::ProverHardeningEngine;
use crate::types::{BaselineProfile, HardeningEngine};

/// The result of an export: the policy as YAML and a plain summary of what was done and proved.
#[derive(Debug, Clone)]
pub struct PolicyExport {
    pub yaml: String,
    pub summary: Value,
}

/// A baseline route template as an OpenShell path glob. `{name}` is one path segment (`*`); `**` as a whole segment matches across segments, as in OpenShell.
#[must_use]
pub fn route_glob(template: &str) -> String {
    let segments: Vec<String> = template
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "*".to_string()
            } else {
                segment
                    .chars()
                    .map(|c| {
                        if matches!(c, '?' | '[' | ']' | '\\' | '{' | '}') {
                            '*'
                        } else {
                            c
                        }
                    })
                    .collect()
            }
        })
        .collect();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// `GET /services/{svc}` as `("GET", "/services/*")`. A forbidden-action pattern ending in `*` becomes a prefix match (`/**`).
#[must_use]
pub fn action_class_rule(action_class: &str) -> Option<(String, String)> {
    let (method, path) = action_class.trim().split_once(' ')?;
    let method = method.trim().to_ascii_uppercase();
    let path = path.trim();
    if method.is_empty() || !path.starts_with('/') {
        return None;
    }
    let glob = match path.strip_suffix('*') {
        Some(prefix) if !prefix.ends_with("**") => {
            format!("{}/**", route_glob(prefix.trim_end_matches('/'))).replace("//", "/")
        }
        _ => route_glob(path),
    };
    Some((method, glob))
}

/// Whether an OpenShell path glob matches a concrete path: `*` within one segment, a whole `**` segment across segments. Used to test the rules written here, not to enforce.
#[must_use]
pub fn glob_matches(glob: &str, path: &str) -> bool {
    fn segs(s: &str) -> Vec<&str> {
        s.split('/').filter(|x| !x.is_empty()).collect()
    }
    fn seg_match(pattern: &str, text: &str) -> bool {
        let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
        fn go(p: &[char], t: &[char]) -> bool {
            match p.first() {
                None => t.is_empty(),
                Some('*') => go(&p[1..], t) || (!t.is_empty() && go(p, &t[1..])),
                Some(c) => t.first() == Some(c) && go(&p[1..], &t[1..]),
            }
        }
        go(&p, &t)
    }
    fn walk(p: &[&str], t: &[&str]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(&"**") => walk(&p[1..], t) || (!t.is_empty() && walk(p, &t[1..])),
            Some(seg) => !t.is_empty() && seg_match(seg, t[0]) && walk(&p[1..], &t[1..]),
        }
    }
    walk(&segs(glob), &segs(path))
}

fn make_allow(method: String, path: String) -> L7Rule {
    L7Rule {
        allow: L7Allow {
            method,
            path,
            command: String::new(),
            query: Default::default(),
            operation_type: String::new(),
            operation_name: String::new(),
            fields: Vec::new(),
            tool: None,
            params: Default::default(),
        },
    }
}

fn make_deny(method: String, path: String) -> L7DenyRule {
    L7DenyRule {
        method,
        path,
        command: String::new(),
        query: Default::default(),
        operation_type: String::new(),
        operation_name: String::new(),
        fields: Vec::new(),
        tool: None,
        params: Default::default(),
    }
}

/// One extra allow rule for a demonstration: a call the OpenShell policy lets through so that Risk Guard, not OpenShell, is the layer that refuses it. Each carries the reason
/// it is there. A set of these is reviewed like any other file (`deploy/aks/agents/<profile>/demo-exceptions.json`) and is applied only when asked for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DemoException {
    pub method: String,
    pub path: String,
    pub reason: String,
}

/// The reviewed file of demo exceptions for one task profile.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DemoExceptions {
    /// Which task profile the exceptions are for (`release-ops`); checked against the baseline so a file cannot be applied to the wrong profile.
    pub task_profile: String,
    pub exceptions: Vec<DemoException>,
}

/// At most this many: the point is a couple of examples, not a second policy.
pub const MAX_DEMO_EXCEPTIONS: usize = 3;

/// Marks a rule name as weakened for a demonstration. YAML comments do not survive serialization, so the name itself carries the disclosure.
#[must_use]
pub fn demo_rule_name(name: &str, count: usize) -> String {
    format!("{name} (DEMO EXCEPTIONS: {count})")
}

impl DemoExceptions {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|err| {
            RiskGuardError::InvalidArgument(format!(
                "failed to read demo exceptions '{}': {err}",
                path.display()
            ))
        })?;
        let parsed: Self = serde_json::from_str(&raw).map_err(|err| {
            RiskGuardError::InvalidArgument(format!(
                "demo exceptions '{}' are not valid: {err}",
                path.display()
            ))
        })?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Refuse a file that is empty, too long, or has an entry without a method, a rooted path or a reason.
    pub fn validate(&self) -> Result<()> {
        let bad = |message: String| Err(RiskGuardError::InvalidArgument(message));
        if self.exceptions.is_empty() {
            return bad("demo exceptions list no exceptions".into());
        }
        if self.exceptions.len() > MAX_DEMO_EXCEPTIONS {
            return bad(format!(
                "demo exceptions list {} entries; keep it to {MAX_DEMO_EXCEPTIONS} or fewer, they are examples and not a second policy",
                self.exceptions.len()
            ));
        }
        let mut seen = BTreeSet::new();
        for e in &self.exceptions {
            if !matches!(
                e.method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
            ) {
                return bad(format!(
                    "demo exception method '{}' must be one of GET, POST, PUT, PATCH, DELETE (upper case)",
                    e.method
                ));
            }
            if !e.path.starts_with('/') || e.path.contains(char::is_whitespace) {
                return bad(format!(
                    "demo exception path '{}' must start with / and hold no spaces",
                    e.path
                ));
            }
            if e.reason.trim().len() < 12 {
                return bad(format!(
                    "demo exception {} {} needs a reason of at least a sentence fragment",
                    e.method, e.path
                ));
            }
            if !seen.insert((e.method.clone(), e.path.clone())) {
                return bad(format!(
                    "demo exception {} {} is listed twice",
                    e.method, e.path
                ));
            }
        }
        Ok(())
    }
}

/// How long the prover may take. The proof is a satisfiability check whose cost grows with the number of rules and is noticeably slower on a small machine, and an inconclusive
/// answer (time ran out) is refused, never treated as a pass, so the budget errs long. `RISK_GUARD_PROOF_TIMEOUT_SECONDS` overrides it.
fn proof_timeout() -> Duration {
    let seconds = std::env::var("RISK_GUARD_PROOF_TIMEOUT_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| (1..=600).contains(s))
        .unwrap_or(60);
    Duration::from_secs(seconds)
}

/// Write `baseline`'s lists into `policy_yaml` as OpenShell rules, set the endpoints' mode to `enforcement` (`audit` or `enforce`), and prove the result is no wider.
pub fn export_policy(
    baseline: &BaselineProfile,
    policy_yaml: &str,
    enforcement: &str,
) -> Result<PolicyExport> {
    export_policy_with_demo_exceptions(baseline, policy_yaml, enforcement, None)
}

/// [`export_policy`] plus, when `demo` is given, the reviewed demo exceptions as extra allow rules. The result is deliberately **weaker** than the profile's baseline: the
/// endpoint's rule name says so (`<name> (DEMO EXCEPTIONS: n)`), the summary lists every exception with its reason, and the prover still checks the whole thing against the
/// original policy. Without `demo` the output is byte for byte what [`export_policy`] always wrote.
pub fn export_policy_with_demo_exceptions(
    baseline: &BaselineProfile,
    policy_yaml: &str,
    enforcement: &str,
    demo: Option<&DemoExceptions>,
) -> Result<PolicyExport> {
    if let Some(demo) = demo {
        demo.validate()?;
        if demo.task_profile != baseline.task_profile {
            return Err(RiskGuardError::InvalidArgument(format!(
                "the demo exceptions are for task profile '{}' but the baseline is '{}'",
                demo.task_profile, baseline.task_profile
            )));
        }
    }
    if !matches!(enforcement, "audit" | "enforce") {
        return Err(RiskGuardError::InvalidArgument(
            "enforcement must be audit or enforce".into(),
        ));
    }
    if baseline.allowed_action_classes.is_empty() {
        return Err(RiskGuardError::InvalidArgument(
            "the baseline lists no approved routes, which means \"not specified\"; writing it as a policy would allow nothing, so nothing was written".into(),
        ));
    }
    let mut document = parse_policy(policy_yaml)
        .map_err(|e| RiskGuardError::Policy(format!("failed to parse the policy: {e:#}")))?;
    let hosts: BTreeSet<String> = document
        .network_middlewares
        .values()
        .filter(|m| m.middleware == "risk-guard")
        .filter_map(|m| m.endpoints.as_ref())
        .flat_map(|selector| selector.include.iter().cloned())
        .collect();
    if hosts.is_empty() {
        return Err(RiskGuardError::InvalidArgument(
            "the policy has no risk-guard middleware with endpoints.include, so there is no way to say which hosts this task profile covers".into(),
        ));
    }
    let allows: Vec<(String, String)> = baseline
        .allowed_action_classes
        .iter()
        .filter_map(|c| action_class_rule(c))
        .collect();
    let denies: Vec<(String, String)> = baseline
        .forbidden_action_classes
        .iter()
        .filter_map(|c| action_class_rule(c))
        .collect();
    let mut changed = Vec::new();
    let mut weakened: BTreeSet<String> = BTreeSet::new();
    for (name, rule) in &mut document.network_policies {
        for endpoint in &mut rule.endpoints {
            if !hosts.contains(&endpoint.host) {
                continue;
            }
            if endpoint.protocol.is_empty() {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "endpoint {} in rule '{name}' has no protocol, so OpenShell does not inspect its requests and request rules would have no effect; set `protocol: rest` first",
                    endpoint.host
                )));
            }
            endpoint.rules = allows
                .iter()
                .map(|(m, p)| make_allow(m.clone(), p.clone()))
                .collect();
            if let Some(demo) = demo {
                for e in &demo.exceptions {
                    if allows.iter().any(|(m, p)| m == &e.method && p == &e.path) {
                        return Err(RiskGuardError::InvalidArgument(format!(
                            "demo exception {} {} is already an approved route; it would not be an exception",
                            e.method, e.path
                        )));
                    }
                    endpoint
                        .rules
                        .push(make_allow(e.method.clone(), e.path.clone()));
                }
                weakened.insert(name.clone());
            }
            endpoint.deny_rules = denies
                .iter()
                .map(|(m, p)| make_deny(m.clone(), p.clone()))
                .collect();
            endpoint.access = String::new();
            endpoint.enforcement = enforcement.to_string();
            changed.push(format!("{name}:{}", endpoint.host));
        }
    }
    if let Some(demo) = demo {
        for name in &weakened {
            if let Some(rule) = document.network_policies.get_mut(name) {
                let base = if rule.name.is_empty() {
                    name.clone()
                } else {
                    rule.name.clone()
                };
                rule.name = demo_rule_name(&base, demo.exceptions.len());
            }
        }
    }
    if changed.is_empty() {
        return Err(RiskGuardError::InvalidArgument(format!(
            "no network endpoint in the policy matches the covered hosts ({})",
            hosts.iter().cloned().collect::<Vec<_>>().join(", ")
        )));
    }
    let yaml = serde_yml::to_string(&document)
        .map_err(|e| RiskGuardError::Policy(format!("failed to write the policy: {e}")))?;
    // The prover can only certify rules that are enforced: in audit mode nothing is restricted, so there is nothing to prove. Prove the same rules in enforce form.
    let proof_yaml = if enforcement == "audit" {
        let mut enforced = document.clone();
        for rule in enforced.network_policies.values_mut() {
            for endpoint in &mut rule.endpoints {
                if hosts.contains(&endpoint.host) {
                    endpoint.enforcement = "enforce".to_string();
                }
            }
        }
        serde_yml::to_string(&enforced)
            .map_err(|e| RiskGuardError::Policy(format!("failed to write the policy: {e}")))?
    } else {
        yaml.clone()
    };
    let proof = ProverHardeningEngine::new().verify_two_step_containment(
        policy_yaml,
        &proof_yaml,
        proof_timeout(),
    )?;
    let mut notes = vec![
        "Network rules take effect on a running sandbox within seconds and close connections opened under the old rules; filesystem and process settings are unchanged.".to_string(),
        "Calls OpenShell refuses never reach Risk Guard, so it will not see those attempts; the SIEM does.".to_string(),
    ];
    if enforcement == "audit" {
        notes.push("audit mode logs a violation and allows the request: nothing is blocked until enforcement is set to enforce.".into());
    }
    if let Some(demo) = demo {
        notes.insert(
            0,
            format!(
                "DEMO ONLY - WEAKENED ON PURPOSE: this policy also allows {} so that those calls reach Risk Guard. It is wider than the profile's baseline. Do not use it for the fleet. The rule name ends in (DEMO EXCEPTIONS: {}).",
                demo.exceptions
                    .iter()
                    .map(|e| format!("{} {}", e.method, e.path))
                    .collect::<Vec<_>>()
                    .join(", "),
                demo.exceptions.len()
            ),
        );
    }
    let mut summary = json!({
            "task_profile": baseline.task_profile, "baseline_version": baseline.version, "enforcement": enforcement,
            "covered_hosts": hosts, "endpoints_changed": changed, "allow_rules": allows.len(), "deny_rules": denies.len(),
            "proof": {
                "proved_form": if enforcement == "audit" { "the same rules with enforcement: enforce (audit mode restricts nothing, so it cannot be proved)" } else { "as written" },
                "verified_no_wider": proof.verified_non_expanding, "step1_middleware_unchanged": proof.step1_middleware_invariant,
                "step2_prover": proof.step2_prover_verdict, "detail": proof.step2_counterexample_or_reason,
            },
            "notes": notes,
    });
    if let Some(d) = demo {
        summary["demo_exceptions"] = json!({
            "count": d.exceptions.len(), "weakened_rules": weakened, "proved_against": "the original policy given with --policy, including the exceptions",
            "exceptions": d.exceptions,
        });
    }
    Ok(PolicyExport { yaml, summary })
}

/// The network rules of a policy as readable lines, keyed by rule name and endpoint: the mode, the allow rules and the deny rules, in the order written.
fn network_rule_lines(
    document: &openshell_policy_schema::PolicyDocument,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out = std::collections::BTreeMap::new();
    for (name, rule) in &document.network_policies {
        for endpoint in &rule.endpoints {
            let ports = if endpoint.ports.is_empty() {
                endpoint.port.to_string()
            } else {
                endpoint
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let mut lines = Vec::new();
            if !endpoint.access.is_empty() {
                lines.push(format!("access: {}", endpoint.access));
            }
            lines.push(format!(
                "enforcement: {}",
                if endpoint.enforcement.is_empty() {
                    "(default)"
                } else {
                    &endpoint.enforcement
                }
            ));
            lines.extend(
                endpoint
                    .rules
                    .iter()
                    .map(|r| format!("allow {} {}", r.allow.method, r.allow.path)),
            );
            lines.extend(
                endpoint
                    .deny_rules
                    .iter()
                    .map(|r| format!("deny {} {}", r.method, r.path)),
            );
            out.insert(format!("{name} {}:{ports}", endpoint.host), lines);
        }
    }
    out
}

/// A readable, unified-style comparison of the network rules in two policies (`-` only in `old_yaml`, `+` only in `new_yaml`). Endpoints that did not change are left out.
/// Rules are compared as sets: reordering alone is not a difference.
pub fn network_rules_diff(old_yaml: &str, new_yaml: &str) -> Result<String> {
    let parse = |raw: &str| {
        parse_policy(raw)
            .map_err(|e| RiskGuardError::Policy(format!("failed to parse the policy: {e:#}")))
    };
    let (old, new) = (
        network_rule_lines(&parse(old_yaml)?),
        network_rule_lines(&parse(new_yaml)?),
    );
    let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    let mut out = String::from("--- current network rules\n+++ proposed network rules\n");
    let mut any = false;
    for key in keys {
        let (before, after) = (
            old.get(key).map(Vec::as_slice).unwrap_or_default(),
            new.get(key).map(Vec::as_slice).unwrap_or_default(),
        );
        if before.iter().collect::<BTreeSet<_>>() == after.iter().collect::<BTreeSet<_>>() {
            continue;
        }
        any = true;
        out.push_str(&format!("@@ {key} @@\n"));
        for line in before {
            let mark = if after.contains(line) { "  " } else { "- " };
            out.push_str(&format!("{mark}{line}\n"));
        }
        for line in after.iter().filter(|l| !before.contains(l)) {
            out.push_str(&format!("+ {line}\n"));
        }
    }
    if !any {
        out.push_str("(no change to the network rules)\n");
    }
    Ok(out)
}

/// Whether two policies differ in anything other than `network_policies` (filesystem, landlock, process, middleware). Filesystem and process settings cannot be changed on a
/// running sandbox, so a difference here means the new policy needs a new sandbox.
pub fn differs_outside_network_policies(old_yaml: &str, new_yaml: &str) -> Result<bool> {
    let strip = |raw: &str| -> Result<Value> {
        let document = parse_policy(raw)
            .map_err(|e| RiskGuardError::Policy(format!("failed to parse the policy: {e:#}")))?;
        let mut value = serde_json::to_value(&document)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("network_policies");
        }
        Ok(value)
    };
    Ok(strip(old_yaml)? != strip(new_yaml)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_becomes_a_glob_that_means_the_same_thing() {
        assert_eq!(route_glob("/services/{svc}"), "/services/*");
        assert_eq!(
            route_glob("/services/{svc}/deployments"),
            "/services/*/deployments"
        );
        assert_eq!(
            route_glob("/repos/{owner}/{repo}/issues/**"),
            "/repos/*/*/issues/**"
        );
        assert_eq!(route_glob("/services"), "/services");
        assert_eq!(route_glob("/"), "/");
    }

    #[test]
    fn an_action_class_becomes_a_method_and_a_path() {
        assert_eq!(
            action_class_rule("get /services/{svc}"),
            Some(("GET".into(), "/services/*".into()))
        );
        assert_eq!(
            action_class_rule("DELETE /buckets/*"),
            Some(("DELETE".into(), "/buckets/**".into()))
        );
        assert_eq!(action_class_rule("GET unknown"), None);
        assert_eq!(action_class_rule("nonsense"), None);
    }

    #[test]
    fn the_glob_matcher_follows_openshells_rules() {
        assert!(glob_matches("/services/*", "/services/worker"));
        assert!(
            !glob_matches("/services/*", "/services/worker/restart"),
            "one star is one segment"
        );
        assert!(glob_matches("/services/**", "/services/worker/restart"));
        assert!(!glob_matches("/services/*", "/services"));
        assert!(glob_matches(
            "/services/*/deployments",
            "/services/worker/deployments"
        ));
        assert!(!glob_matches(
            "/services/*",
            "//services/worker/../worker/x"
        ));
    }
}
