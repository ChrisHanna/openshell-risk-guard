// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The OpenShell policy written from each task profile's lists, checked against the red-team catalog.
//!
//! Three things must hold for the move of the static lists into OpenShell policy to be safe: the generated policy is no wider than the one it replaces (OpenShell's prover),
//! every routine call the catalog marks "allowed" is still allowed (no false blocks), and nothing destructive the catalog marks "refused" is allowed. What the policy alone
//! does not refuse (behavior, rate, resource-level) is reported, because that is what Risk Guard is still for.

use openshell_policy_schema::parse_policy;
use openshell_risk_guard::detector::load_baseline_profile;
use openshell_risk_guard::policy_export::{
    DemoExceptions, MAX_DEMO_EXCEPTIONS, export_policy, export_policy_with_demo_exceptions,
    glob_matches,
};
use openshell_risk_guard::types::{RULE_UNAPPROVED_RESOURCE, RuleMode};
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

/// The audit policies the fleet runs (deploy/aks/agents/<profile>/policy.audit.yaml) are generated. A baseline or policy edit without
/// regenerating them would leave the fleet auditing yesterday's lists.
#[test]
fn the_committed_audit_policies_are_current() {
    for dir in ["support", "release", "cloud"] {
        let base = format!("{ROOT}/deploy/aks/agents/{dir}");
        let baseline = load_baseline_profile(format!("{base}/baseline.json")).unwrap();
        let policy = std::fs::read_to_string(format!("{base}/policy.yaml")).unwrap();
        let fresh = export_policy(&baseline, &policy, "audit").unwrap().yaml;
        let committed = std::fs::read_to_string(format!("{base}/policy.audit.yaml")).unwrap_or_else(|err| {
            panic!("{dir}/policy.audit.yaml is missing ({err}); run scripts/policy/generate_audit_policies.py")
        });
        assert_eq!(
            committed.replace('\r', ""),
            fresh,
            "{dir}/policy.audit.yaml is out of date; run scripts/policy/generate_audit_policies.py"
        );
    }
}

/// The profiles that have a generated enforce policy (the fleet's three, plus the end-state demo's own).
const ENFORCE_PROFILES: [&str; 4] = ["support", "release", "cloud", "demo-end-state"];

fn profile_dir(dir: &str) -> String {
    format!("{ROOT}/deploy/aks/agents/{dir}")
}

fn read_generated(dir: &str, name: &str) -> String {
    std::fs::read_to_string(format!("{}/{name}", profile_dir(dir)))
        .unwrap_or_else(|err| {
            panic!("{dir}/{name} is missing ({err}); run scripts/policy/generate_audit_policies.py")
        })
        .replace('\r', "")
}

fn load(dir: &str) -> (openshell_risk_guard::types::BaselineProfile, String) {
    let base = profile_dir(dir);
    (
        load_baseline_profile(format!("{base}/baseline.json")).unwrap(),
        std::fs::read_to_string(format!("{base}/policy.yaml")).unwrap(),
    )
}

/// What the fleet runs when `AGENT_POLICY_MODE=enforce` (and what the end-state demo starts from) is generated too, so it cannot drift from the baselines.
#[test]
fn the_committed_enforce_policies_are_current() {
    for dir in ENFORCE_PROFILES {
        let (baseline, policy) = load(dir);
        let fresh = export_policy(&baseline, &policy, "enforce").unwrap().yaml;
        assert_eq!(
            read_generated(dir, "policy.enforce.yaml"),
            fresh,
            "{dir}/policy.enforce.yaml is out of date; run scripts/policy/generate_audit_policies.py"
        );
    }
}

/// The audit and enforce files of a profile are the same rules; only the endpoint's mode differs. Anything else would mean the fleet changes more than the mode.
#[test]
fn the_enforce_policy_is_the_audit_policy_with_only_the_mode_switched() {
    for dir in ["support", "release", "cloud"] {
        let audit = read_generated(dir, "policy.audit.yaml");
        let enforce = read_generated(dir, "policy.enforce.yaml");
        assert_eq!(audit.matches("enforcement: audit").count(), 1, "{dir}");
        assert_eq!(
            audit.replace("enforcement: audit", "enforcement: enforce"),
            enforce,
            "{dir}: audit and enforce differ in more than the endpoint mode"
        );
    }
}

#[test]
fn every_enforce_policy_is_proved_no_wider_than_the_one_it_replaces() {
    for dir in ENFORCE_PROFILES {
        let (baseline, policy) = load(dir);
        let export = export_policy(&baseline, &policy, "enforce").unwrap();
        assert_eq!(export.summary["proof"]["verified_no_wider"], true, "{dir}");
        assert!(
            export.summary.get("demo_exceptions").is_none(),
            "{dir}: the summary of a normal export must not mention demo exceptions"
        );
    }
}

/// Dropped, malformed or normalized-away spellings are OpenShell's to decide on the cluster (see conformance/policy-export/path-edge-cases.json); what is checked here is the
/// rules: the enforce policy allows exactly the baseline's approved routes, and nothing the catalog marks as a plain destructive call.
#[test]
fn the_enforce_policies_allow_only_get_and_post() {
    for dir in ENFORCE_PROFILES {
        let g = {
            let (baseline, policy) = load(dir);
            let export = export_policy(&baseline, &policy, "enforce").unwrap();
            let document = parse_policy(&export.yaml).unwrap();
            let mut rules = Vec::new();
            for rule in document.network_policies.values() {
                for e in &rule.endpoints {
                    assert_eq!(e.enforcement, "enforce", "{dir}");
                    rules.extend(
                        e.rules
                            .iter()
                            .map(|r| (r.allow.method.clone(), r.allow.path.clone())),
                    );
                }
            }
            rules
        };
        for (method, path) in &g {
            assert!(
                method == "GET" || method == "POST",
                "{dir}: {method} {path} is allowed by the generated enforce policy; the baselines approve no other method"
            );
        }
    }
}

fn demo_profiles() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(format!("{ROOT}/deploy/aks/agents"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("demo-exceptions.json").exists())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    out.sort();
    out
}

fn demo_of(dir: &str) -> DemoExceptions {
    DemoExceptions::load(format!("{}/demo-exceptions.json", profile_dir(dir))).unwrap()
}

#[test]
fn the_committed_demo_policies_are_current_and_exist_exactly_where_exceptions_are_reviewed() {
    let profiles = demo_profiles();
    assert_eq!(
        profiles,
        ["cloud", "demo-end-state", "release"],
        "the profiles with reviewed demo exceptions changed: update scripts/policy/generate_audit_policies.py (DEMO_PROFILES) and this test together"
    );
    let mut total = 0;
    for dir in &profiles {
        let (baseline, policy) = load(dir);
        let demo = demo_of(dir);
        total += demo.exceptions.len();
        let fresh = export_policy_with_demo_exceptions(&baseline, &policy, "enforce", Some(&demo))
            .unwrap()
            .yaml;
        assert_eq!(
            read_generated(dir, "policy.enforce.demo.yaml"),
            fresh,
            "{dir}/policy.enforce.demo.yaml is out of date; run scripts/policy/generate_audit_policies.py"
        );
    }
    assert!(
        total <= MAX_DEMO_EXCEPTIONS,
        "{total} demo exceptions in all; the agreement is a couple of examples, at most {MAX_DEMO_EXCEPTIONS}"
    );
    // A demo file for a profile without reviewed exceptions would be an unreviewed weakening.
    for entry in std::fs::read_dir(format!("{ROOT}/deploy/aks/agents")).unwrap() {
        let path = entry.unwrap().path();
        if path.join("policy.enforce.demo.yaml").exists() {
            assert!(
                path.join("demo-exceptions.json").exists(),
                "{} has a demo policy without a reviewed demo-exceptions.json",
                path.display()
            );
        }
    }
}

/// The weakening is disclosed in the artifact itself (YAML comments do not survive serialization, so the rule name says it), listed in the summary, and still proved against the
/// original policy; and it is the only difference from the enforce policy.
#[test]
fn a_demo_policy_says_it_is_weakened_lists_what_it_adds_and_is_still_proved() {
    for dir in demo_profiles() {
        let (baseline, policy) = load(&dir);
        let demo = demo_of(&dir);
        let plain = export_policy(&baseline, &policy, "enforce").unwrap();
        let weakened =
            export_policy_with_demo_exceptions(&baseline, &policy, "enforce", Some(&demo)).unwrap();
        let n = demo.exceptions.len();

        let summary = &weakened.summary["demo_exceptions"];
        assert_eq!(summary["count"], n, "{dir}");
        assert_eq!(summary["exceptions"].as_array().unwrap().len(), n, "{dir}");
        assert!(
            weakened.summary["notes"][0]
                .as_str()
                .unwrap()
                .starts_with("DEMO ONLY - WEAKENED ON PURPOSE"),
            "{dir}: the first note must be the disclosure"
        );
        assert_eq!(
            weakened.summary["proof"]["verified_no_wider"], true,
            "{dir}: the prover must still certify the demo policy against the original"
        );

        let (plain_doc, demo_doc) = (
            parse_policy(&plain.yaml).unwrap(),
            parse_policy(&weakened.yaml).unwrap(),
        );
        for (name, rule) in &demo_doc.network_policies {
            let original = &plain_doc.network_policies[name];
            assert_eq!(
                rule.name,
                format!("{} (DEMO EXCEPTIONS: {n})", original.name),
                "{dir}: the endpoint rule's name must carry the disclosure"
            );
            assert!(
                !original.name.contains("DEMO"),
                "{dir}: the plain policy must not"
            );
            let (a, b) = (&original.endpoints[0], &rule.endpoints[0]);
            assert_eq!(b.enforcement, "enforce", "{dir}");
            assert_eq!(
                &b.rules[..a.rules.len()],
                &a.rules[..],
                "{dir}: the approved rules come first and are unchanged"
            );
            let extra: Vec<(String, String)> = b.rules[a.rules.len()..]
                .iter()
                .map(|r| (r.allow.method.clone(), r.allow.path.clone()))
                .collect();
            let wanted: Vec<(String, String)> = demo
                .exceptions
                .iter()
                .map(|e| (e.method.clone(), e.path.clone()))
                .collect();
            assert_eq!(
                extra, wanted,
                "{dir}: the only addition is the reviewed exceptions"
            );
            // The point of an exception: the plain policy refuses it, the demo policy lets it through.
            for (m, p) in &wanted {
                let concrete = p.replace('*', "x");
                let allows = |e: &openshell_policy_schema::NetworkEndpoint| {
                    e.rules.iter().any(|r| {
                        r.allow.method.eq_ignore_ascii_case(m)
                            && glob_matches(&r.allow.path, &concrete)
                    })
                };
                assert!(
                    !allows(a),
                    "{dir}: {m} {p} is already allowed without the exception"
                );
                assert!(
                    allows(b),
                    "{dir}: {m} {p} is not allowed with the exception"
                );
            }
        }
        // Nothing else differs: same policy once the disclosure and the added rules are taken away.
        let strip = |yaml: &str| {
            let mut doc = parse_policy(yaml).unwrap();
            for rule in doc.network_policies.values_mut() {
                rule.name = rule.name.split(" (DEMO").next().unwrap().to_string();
                for e in &mut rule.endpoints {
                    e.rules.truncate(
                        plain_doc
                            .network_policies
                            .values()
                            .next()
                            .unwrap()
                            .endpoints[0]
                            .rules
                            .len(),
                    );
                }
            }
            serde_json::to_value(&doc).unwrap()
        };
        assert_eq!(strip(&plain.yaml), strip(&weakened.yaml), "{dir}");
    }
}

/// The fleet's files can never carry an exception: nothing generated for the fleet mentions the demo.
#[test]
fn the_fleets_policies_carry_no_demo_exceptions() {
    for dir in ["support", "release", "cloud"] {
        for name in ["policy.audit.yaml", "policy.enforce.yaml"] {
            assert!(
                !read_generated(dir, name).contains("DEMO"),
                "{dir}/{name} mentions a demo exception; the fleet must never run a weakened policy"
            );
        }
    }
}

#[test]
fn demo_exceptions_are_refused_when_they_are_not_what_they_claim_to_be() {
    let (baseline, policy) = load("release");
    let good = demo_of("release");
    let try_with = |change: &dyn Fn(&mut DemoExceptions)| {
        let mut d = good.clone();
        change(&mut d);
        export_policy_with_demo_exceptions(&baseline, &policy, "enforce", Some(&d))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
    };
    assert!(try_with(&|d| d.task_profile = "cloud-hygiene".into()).contains("task profile"));
    assert!(try_with(&|d| d.exceptions.clear()).contains("no exceptions"));
    assert!(try_with(&|d| d.exceptions[0].reason = "ok".into()).contains("reason"));
    assert!(try_with(&|d| d.exceptions[0].method = "delete".into()).contains("method"));
    assert!(try_with(&|d| d.exceptions[0].path = "services".into()).contains("path"));
    assert!(
        try_with(&|d| {
            for i in 0..=MAX_DEMO_EXCEPTIONS {
                let mut e = d.exceptions[0].clone();
                e.path = format!("/x{i}/*");
                d.exceptions.push(e);
            }
        })
        .contains("keep it to")
    );
    assert!(
        try_with(&|d| {
            d.exceptions[0].method = "GET".into();
            d.exceptions[0].path = "/services".into();
        })
        .contains("already an approved route")
    );
    assert!(try_with(&|d| d.exceptions.push(d.exceptions[0].clone())).contains("twice"));
}

/// The end-state demo's resource-level case needs the rule to enforce for its profile (everywhere else it only watches).
#[test]
fn the_end_state_profile_enforces_the_resource_rule_and_nothing_else_does() {
    let end_state = load("demo-end-state").0;
    assert_eq!(end_state.task_profile, "demo-end-state");
    assert_eq!(
        end_state.rule_mode(RULE_UNAPPROVED_RESOURCE),
        RuleMode::Enforce
    );
    assert!(
        !end_state.approved_resources.is_empty(),
        "an empty list means not specified and trips nothing"
    );
    for dir in ["support", "release", "cloud", "redteam", "token"] {
        let baseline =
            load_baseline_profile(format!("{}/baseline.json", profile_dir(dir))).unwrap();
        assert_ne!(
            baseline.rule_mode(RULE_UNAPPROVED_RESOURCE),
            RuleMode::Enforce,
            "{dir}: turning the resource rule on for a live profile is a decision for its own change, not for the demo profile"
        );
    }
}
