// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The OpenShell policy written from each task profile's lists, checked against the red-team catalog.
//!
//! Three things must hold for the move of the static lists into OpenShell policy to be safe: the generated policy is no wider than the one it replaces (OpenShell's prover),
//! every routine call the catalog marks "allowed" is still allowed (no false blocks), and nothing destructive the catalog marks "refused" is allowed. What the policy alone
//! does not refuse (behavior, rate, resource-level) is reported, because that is what Risk Guard is still for.

use openshell_policy_schema::parse_policy;
use openshell_risk_guard::detector::load_baseline_profile;
use openshell_risk_guard::policy_export::{export_policy, glob_matches};
use serde_json::{Value, json};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const PROFILES: [&str; 4] = ["release", "support", "cloud", "redteam"];

struct Generated {
    allow: Vec<(String, String)>,
    proof_ok: bool,
    allowed_classes: Vec<String>,
}

fn generate(dir: &str) -> Generated {
    let baseline =
        load_baseline_profile(format!("{ROOT}/deploy/aks/agents/{dir}/baseline.json")).unwrap();
    let policy =
        std::fs::read_to_string(format!("{ROOT}/deploy/aks/agents/{dir}/policy.yaml")).unwrap();
    let export = export_policy(&baseline, &policy, "audit").unwrap();
    let document = parse_policy(&export.yaml).unwrap();
    let hosts: Vec<String> = export.summary["covered_hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect();
    let mut allow = Vec::new();
    for rule in document.network_policies.values() {
        for endpoint in rule.endpoints.iter().filter(|e| hosts.contains(&e.host)) {
            assert_eq!(endpoint.enforcement, "audit", "it starts in audit mode");
            allow.extend(
                endpoint
                    .rules
                    .iter()
                    .map(|r| (r.allow.method.clone(), r.allow.path.clone())),
            );
        }
    }
    Generated {
        allow,
        proof_ok: export.summary["proof"]["verified_no_wider"] == true,
        allowed_classes: baseline.allowed_action_classes.iter().cloned().collect(),
    }
}

fn allowed(rules: &[(String, String)], method: &str, path: &str) -> bool {
    let clean = path.split(['?', '#']).next().unwrap_or(path);
    rules
        .iter()
        .any(|(m, glob)| m.eq_ignore_ascii_case(method) && glob_matches(glob, clean))
}

/// A path OpenShell's own normalization decides about before any rule is consulted (encoded, dot segments, doubled slashes). This test does not claim to know that answer.
fn left_to_normalization(path: &str) -> bool {
    path.contains('%')
        || path.contains("..")
        || path.contains("//")
        || path.contains("/./")
        || path.contains('\\')
        || path.contains(';')
}

#[test]
fn every_generated_policy_is_proved_no_wider_than_the_one_it_replaces() {
    for dir in PROFILES {
        assert!(
            generate(dir).proof_ok,
            "{dir}: the prover did not certify the generated rules as within the original policy"
        );
    }
}

#[test]
fn the_routes_a_profile_approves_are_still_allowed() {
    for dir in PROFILES {
        let g = generate(dir);
        for class in &g.allowed_classes {
            let (method, template) = class.split_once(' ').unwrap();
            let concrete = template.replace("**", "x/y").replace(['{', '}'], "");
            let concrete = concrete
                .split('/')
                .map(|s| {
                    if s.chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-')
                        && template.contains(&format!("{{{s}}}"))
                    {
                        "item"
                    } else {
                        s
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            assert!(
                allowed(&g.allow, method, &concrete),
                "{dir}: '{class}' (as {concrete}) is approved by the baseline but the generated policy would block it"
            );
        }
    }
}

#[test]
fn the_catalog_agrees_and_what_policy_cannot_catch_is_reported() {
    let catalog: Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{ROOT}/conformance/red-team/catalog.json")).unwrap(),
    )
    .unwrap();
    let (mut refused_by_policy, mut only_risk_guard, mut left, mut routine_ok) =
        (Vec::new(), Vec::new(), Vec::new(), 0);
    for dir in PROFILES {
        let g = generate(dir);
        for attack in catalog["attacks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["profile"] == dir)
        {
            // An attack is a list of steps, or one request repeated (a rate attack, which no route list can express).
            let owned: Vec<(String, String)> = match attack["steps"].as_array() {
                Some(steps) => steps
                    .iter()
                    .map(|s| {
                        (
                            s["method"].as_str().unwrap().to_string(),
                            s["path"].as_str().unwrap().to_string(),
                        )
                    })
                    .collect(),
                None => {
                    let r = &attack["repeat"];
                    vec![(
                        r["method"].as_str().unwrap().to_string(),
                        r["path_template"].as_str().unwrap().replace("{n}", "1"),
                    )]
                }
            };
            let id = attack["id"].as_str().unwrap().to_string();
            let paths: Vec<(&str, &str)> = owned
                .iter()
                .map(|(m, p)| (m.as_str(), p.as_str()))
                .collect();
            match attack["expect"].as_str().unwrap() {
                "allowed" => {
                    for (m, p) in &paths {
                        assert!(
                            allowed(&g.allow, m, p),
                            "{id}: a routine call the catalog expects to be allowed ({m} {p}) would be blocked by the generated policy: a false block"
                        );
                    }
                    routine_ok += 1;
                }
                "refused" | "known_miss" => {
                    if paths.iter().any(|(_, p)| left_to_normalization(p)) {
                        left.push(id.clone());
                    } else if paths.iter().any(|(m, p)| !allowed(&g.allow, m, p)) {
                        refused_by_policy.push(id.clone());
                    } else {
                        // Every step is a route the profile approves: only behavior, rate or resource-level rules can catch it.
                        only_risk_guard.push(id.clone());
                    }
                    if attack["expect"] == "refused" {
                        for (m, p) in &paths {
                            if m.eq_ignore_ascii_case("DELETE") && !left_to_normalization(p) {
                                assert!(
                                    !allowed(&g.allow, m, p),
                                    "{id}: a DELETE the catalog expects to be refused is allowed by the generated policy"
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let report = json!({"refused_by_policy_alone": refused_by_policy, "only_risk_guard_can_catch": only_risk_guard, "left_to_openshell_normalization": left, "routine_calls_still_allowed": routine_ok});
    println!("{report}");
    let _ = std::fs::create_dir_all(format!("{ROOT}/target"));
    std::fs::write(
        format!("{ROOT}/target/policy-export-conformance.json"),
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
    assert!(
        !refused_by_policy.is_empty(),
        "the generated policies should refuse the destructive catalog attacks on their own"
    );
}
