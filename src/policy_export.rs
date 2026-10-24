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

/// Write `baseline`'s lists into `policy_yaml` as OpenShell rules, set the endpoints' mode to `enforcement` (`audit` or `enforce`), and prove the result is no wider.
pub fn export_policy(
    baseline: &BaselineProfile,
    policy_yaml: &str,
    enforcement: &str,
) -> Result<PolicyExport> {
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
            endpoint.deny_rules = denies
                .iter()
                .map(|(m, p)| make_deny(m.clone(), p.clone()))
                .collect();
            endpoint.access = String::new();
            endpoint.enforcement = enforcement.to_string();
            changed.push(format!("{name}:{}", endpoint.host));
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
        Duration::from_secs(10),
    )?;
    let mut notes = vec![
        "Network rules take effect on a running sandbox within seconds and close connections opened under the old rules; filesystem and process settings are unchanged.".to_string(),
        "Calls OpenShell refuses never reach Risk Guard, so it will not see those attempts; the SIEM does.".to_string(),
    ];
    if enforcement == "audit" {
        notes.push("audit mode logs a violation and allows the request: nothing is blocked until enforcement is set to enforce.".into());
    }
    Ok(PolicyExport {
        yaml,
        summary: json!({
            "task_profile": baseline.task_profile, "baseline_version": baseline.version, "enforcement": enforcement,
            "covered_hosts": hosts, "endpoints_changed": changed, "allow_rules": allows.len(), "deny_rules": denies.len(),
            "proof": {
                "proved_form": if enforcement == "audit" { "the same rules with enforcement: enforce (audit mode restricts nothing, so it cannot be proved)" } else { "as written" },
                "verified_no_wider": proof.verified_non_expanding, "step1_middleware_unchanged": proof.step1_middleware_invariant,
                "step2_prover": proof.step2_prover_verdict, "detail": proof.step2_counterexample_or_reason,
            },
            "notes": notes,
        }),
    })
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
