// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The red-team fuzzer: take every single-call attack in the catalog that must be refused and mutate it in the ways an evasive caller would (case, encoding, dots, slashes,
//! separators, Unicode look-alikes, host spelling, method spelling), then check each variant is still refused. A variant that gets through is a real finding.
//!
//! This is the deterministic cousin of the adaptive attacker (`scripts/redteam/`): no model, no network, reproducible, run on every build. Anything it finds must either be
//! fixed or written into `conformance/red-team/fuzz-known.json` with a reason, so a gap can be documented but never silently accepted. The same file also fails the build
//! if a listed variant starts being refused (the documentation is then stale).

use std::collections::BTreeSet;

use openshell_risk_guard::cli::open_and_seed_store as seed_fixture_store;
use openshell_risk_guard::detector::{
    InteractionRiskDetector, compute_baseline_hash, load_baseline_profile,
};
use openshell_risk_guard::normalizer::CanonicalNormalizer;
use openshell_risk_guard::store::SqliteRiskStore;
use openshell_risk_guard::types::*;
use serde_json::Value;

const START: i64 = 1_800_000_000_000;

fn profile(name: &str) -> BaselineProfile {
    load_baseline_profile(format!(
        "{}/deploy/aks/agents/{name}/baseline.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Mutations of one request path. Each is a way a caller might spell the same destructive call differently.
fn path_variants(path: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut add = |kind: &str, value: String| {
        if value != path {
            out.push((kind.to_string(), value));
        }
    };
    add("trailing slash", format!("{path}/"));
    add("double trailing slash", format!("{path}//"));
    add("leading double slash", format!("/{path}"));
    add("doubled separators", path.replace('/', "//"));
    add("dot segment", path.replacen('/', "/./", 1));
    add("parent segment", format!("/x/..{path}"));
    add("upper case", path.to_uppercase());
    add("lower case", path.to_lowercase());
    add("title case", {
        path.split('/')
            .map(|s| {
                let mut c = s.chars();
                c.next().map_or(String::new(), |f| {
                    f.to_uppercase().collect::<String>() + c.as_str()
                })
            })
            .collect::<Vec<_>>()
            .join("/")
    });
    add("query string", format!("{path}?force=true"));
    add(
        "query with encoded question",
        format!("{path}%3fforce=true"),
    );
    add("fragment", format!("{path}#x"));
    add("matrix parameter", format!("{path};x=1"));
    add("encoded slash at the end", format!("{path}%2f"));
    add("null byte", format!("{path}%00"));
    add("null byte then more", format!("{path}%00/ok"));
    add("tab", format!("{path}%09"));
    add("newline", format!("{path}%0a"));
    add("space", format!("{path}%20"));
    add("backslash separators", path.replace('/', "\\"));
    add("encoded backslash", path.replace('/', "%5c"));
    add("overlong slash", path.replacen('/', "%c0%af", 1));
    add("double encoding", path.replace('/', "%252f"));
    add("encoded slash separators", path.replace('/', "%2f"));
    // Percent-encode each letter of the last segment, one at a time.
    if let Some((head, last)) = path.rsplit_once('/') {
        for (index, ch) in last.char_indices() {
            if ch.is_ascii_alphabetic() {
                let mut encoded = String::from(head);
                encoded.push('/');
                encoded.push_str(&last[..index]);
                encoded.push_str(&format!("%{:02x}", ch as u32));
                encoded.push_str(&last[index + 1..]);
                add(&format!("encoded letter {index}"), encoded);
                break;
            }
        }
        // A Cyrillic look-alike for the first latin 'a', 'e' or 'o' of the last segment.
        let lookalike = last
            .replacen('a', "\u{430}", 1)
            .replacen('e', "\u{435}", 1)
            .replacen('o', "\u{43e}", 1);
        add("unicode look-alike", format!("{head}/{lookalike}"));
        add("trailing dot in last segment", format!("{path}."));
        add("trailing space segment", format!("{head}/{last} "));
    }
    out
}

fn host_variants(host: &str) -> Vec<(String, String)> {
    vec![
        ("host upper case".into(), host.to_uppercase()),
        ("host trailing dot".into(), format!("{host}.")),
    ]
}

fn method_variants(method: &str) -> Vec<(String, String)> {
    vec![("method lower case".into(), method.to_lowercase())]
}

struct Harness {
    store: SqliteRiskStore,
    n: usize,
    /// Variants refused only because the normalizer could not read the path (the supervisor's fail-closed binding denies them).
    unreadable: usize,
    /// Variants refused after being scored.
    judged: usize,
    profile: BaselineProfile,
}

impl Harness {
    fn new(profile: BaselineProfile) -> Self {
        let store =
            seed_fixture_store(tempfile::tempdir().unwrap().keep().join("fuzz.db")).unwrap();
        store.store_baseline(&profile).unwrap();
        Self {
            store,
            n: 0,
            unreadable: 0,
            judged: 0,
            profile,
        }
    }

    /// A call from a workload and sandbox of its own, so one variant's refusal (and the restriction it latches) cannot explain another's. True if refused.
    fn refused(&mut self, host: &str, method: &str, path: &str) -> bool {
        self.n += 1;
        let (agent, sandbox) = (format!("agent-{}", self.n), format!("sbx-{}", self.n));
        self.store.register_agent(&agent, "Fuzz agent").unwrap();
        let run = format!("run-{}", self.n);
        self.store
            .create_agent_run(
                &agent,
                &run,
                "revision-1",
                &self.profile.task_profile,
                EnforcementMode::Enforce,
            )
            .unwrap();
        self.store
            .upsert_epoch(&EpochRecord {
                epoch_id: format!("epoch-{sandbox}"),
                gateway_id: "gateway".into(),
                sandbox_id: sandbox.clone(),
                task_profile: self.profile.task_profile.clone(),
                baseline_hash: compute_baseline_hash(&self.profile),
                mode: EnforcementMode::Enforce,
                active: true,
                next_sequence: 1,
                created_at_ms: START - 1,
                credentialed_endpoints: Default::default(),
                active_policy_hash: None,
            })
            .unwrap();
        self.store
            .bind_agent_run(&run, &sandbox, "gateway")
            .unwrap();
        let request = match CanonicalNormalizer::new_default(b"fuzz-test-only-key").normalize(
            &RawRequestInput {
                request_id: "r".into(),
                sandbox_id: sandbox.clone(),
                sandbox_name: sandbox,
                workspace: "default".into(),
                scheme: "http".into(),
                host: format!("{host}.openshell.svc.cluster.local"),
                port: 18081,
                method: method.into(),
                path: path.into(),
                binary_path: Some("/opt/agent/bin/python3.12".into()),
                pid: None,
                ancestors: vec![],
                timestamp_ms: START + self.n as i64,
            },
        ) {
            Ok(request) => request,
            // A path the normalizer cannot make sense of is not forwarded: the supervisor's fail-closed binding turns the error into a denial.
            Err(_) => {
                self.unreadable += 1;
                return true;
            }
        };
        match self.store.evaluate_authenticated(
            &request,
            &InteractionRiskDetector::new_default(),
            "gateway",
            true,
        ) {
            Ok(evaluation) => {
                self.judged += usize::from(evaluation.outcome == DecisionOutcome::Deny);
                evaluation.outcome == DecisionOutcome::Deny
            }
            Err(_) => true,
        }
    }
}

#[test]
fn no_mutation_of_a_must_refuse_call_gets_through_except_the_documented_ones() {
    let catalog: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/conformance/red-team/catalog.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let known: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/conformance/red-team/fuzz-known.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let documented: BTreeSet<String> = known["variants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            format!(
                "{} {} {} {}",
                v["host"].as_str().unwrap(),
                v["method"].as_str().unwrap(),
                v["path"].as_str().unwrap(),
                v["profile"].as_str().unwrap()
            )
        })
        .collect();

    let mut tried = 0usize;
    let (mut unreadable, mut judged) = (0usize, 0usize);
    let mut got_through: BTreeSet<String> = BTreeSet::new();
    let mut by_kind: std::collections::BTreeMap<String, usize> = Default::default();
    for attack in catalog["attacks"].as_array().unwrap() {
        let steps = attack["steps"].as_array();
        if attack["expect"] != "refused" || steps.is_none_or(|s| s.len() != 1) {
            continue;
        }
        let step = &steps.unwrap()[0];
        let (profile_name, host) = (
            attack["profile"].as_str().unwrap(),
            attack["host"].as_str().unwrap(),
        );
        let (method, path) = (
            step["method"].as_str().unwrap(),
            step["path"].as_str().unwrap(),
        );
        let mut harness = Harness::new(profile(profile_name));

        // The seed itself must be refused, or its variants prove nothing.
        assert!(
            harness.refused(host, method, path),
            "seed {} is not refused",
            attack["id"]
        );

        let mut cases: Vec<(String, String, String, String)> = Vec::new(); // kind, host, method, path
        for (kind, p) in path_variants(path) {
            cases.push((kind, host.to_string(), method.to_string(), p));
        }
        for (kind, h) in host_variants(host) {
            cases.push((kind, h, method.to_string(), path.to_string()));
        }
        for (kind, m) in method_variants(method) {
            cases.push((kind, host.to_string(), m, path.to_string()));
        }
        let before = (harness.unreadable, harness.judged);
        for (kind, h, m, p) in cases {
            tried += 1;
            if !harness.refused(&h, &m, &p) {
                *by_kind.entry(kind.clone()).or_default() += 1;
                got_through.insert(format!("{h} {m} {p} {profile_name}"));
            }
        }
        unreadable += harness.unreadable - before.0;
        judged += harness.judged - before.1;
    }

    println!(
        "{tried} variants tried ({judged} refused after being scored, {unreadable} refused because the path could not be read); {} got through; by kind: {by_kind:?}",
        got_through.len()
    );
    let new: Vec<_> = got_through.difference(&documented).collect();
    let stale: Vec<_> = documented.difference(&got_through).collect();
    let report = serde_json::json!({"tried": tried, "refused_after_scoring": judged, "refused_unreadable_path": unreadable, "got_through": got_through, "new": new, "documented_but_now_refused": stale});
    let path = std::env::var("RED_TEAM_FUZZ_REPORT").unwrap_or_else(|_| {
        format!(
            "{}/target/red-team-fuzz-report.json",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let _ = std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap());
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    assert!(
        tried >= 150,
        "the fuzzer should try at least 150 variants, tried {tried}"
    );
    assert!(
        new.is_empty(),
        "mutated calls that must be refused got through (fix them, or document each in conformance/red-team/fuzz-known.json):\n{}",
        new.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        stale.is_empty(),
        "these documented gaps are now refused; remove them from fuzz-known.json:\n{}",
        stale
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}
