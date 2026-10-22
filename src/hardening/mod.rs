// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Hardening recommender and Two-Step Containment Proof (Wave 1 - `t05-prover-hardening`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use openshell_policy::is_provider_rule_name;
use openshell_policy_schema::{
    AccessPreset, L7Allow, L7Rule, NetworkEndpoint, NetworkPolicyRule, PolicyDocument,
};
use openshell_prover::containment::{
    CheckOptions, CheckResult, check_within_boundary, parse_policy_str,
};
use sha2::{Digest, Sha256};

use crate::error::{Result, RiskGuardError};
use crate::types::{
    DecisionOutcome, HardeningCandidate, HardeningEngine, NormalizedRequest, TwoStepProofResult,
};

const DEFAULT_RECOMMENDATION_PROOF_TIMEOUT: Duration = Duration::from_secs(5);

/// Policy-hardening synthesis and Two-Step Containment Proof engine backed by `openshell-prover`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProverHardeningEngine;

impl ProverHardeningEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl HardeningEngine for ProverHardeningEngine {
    fn extract_credentialed_endpoints(&self, policy_yaml: &str) -> Result<BTreeSet<(String, u16)>> {
        let doc = openshell_policy_schema::parse_policy(policy_yaml)
            .map_err(|err| RiskGuardError::Policy(format!("failed to parse policy YAML: {err:#}")))?;

        let mut endpoints = BTreeSet::new();
        for (rule_key, rule) in &doc.network_policies {
            let is_provider =
                is_provider_rule_name(rule_key) || is_provider_rule_name(rule.effective_name(rule_key));
            for endpoint in &rule.endpoints {
                let is_credentialed = is_provider
                    || endpoint.credential_binding.is_some()
                    || !endpoint.credential_signing.is_empty();
                if !is_credentialed {
                    continue;
                }
                let host = endpoint.host.trim().to_ascii_lowercase();
                if host.is_empty() {
                    continue;
                }
                for port in endpoint.effective_ports() {
                    if port > 0 {
                        endpoints.insert((host.clone(), port));
                    }
                }
            }
        }

        Ok(endpoints)
    }

    fn verify_two_step_containment(
        &self,
        boundary_yaml: &str,
        candidate_yaml: &str,
        timeout: Duration,
    ) -> Result<TwoStepProofResult> {
        let boundary_doc = openshell_policy_schema::parse_policy(boundary_yaml).map_err(|err| {
            RiskGuardError::Policy(format!("failed to parse boundary policy YAML: {err:#}"))
        })?;
        let candidate_doc =
            openshell_policy_schema::parse_policy(candidate_yaml).map_err(|err| {
                RiskGuardError::Policy(format!("failed to parse candidate policy YAML: {err:#}"))
            })?;

        let raw_prover_status = if !boundary_doc.network_middlewares.is_empty()
            || !candidate_doc.network_middlewares.is_empty()
        {
            "unsupported: uses network middleware controls".to_string()
        } else if let (Ok(raw_boundary), Ok(raw_candidate)) = (
            parse_policy_str(boundary_yaml),
            parse_policy_str(candidate_yaml),
        ) {
            match check_within_boundary(&raw_boundary, &raw_candidate, CheckOptions::new(timeout)) {
                CheckResult::Within(_) => "within_boundary".to_string(),
                CheckResult::Exceeds(_) => "exceeds_boundary".to_string(),
                CheckResult::Unsupported(ev) => format!("unsupported: {}", ev.reason()),
                CheckResult::Inconclusive(ev) => format!("inconclusive: {}", ev.reason()),
            }
        } else {
            "unsupported: invalid policy".to_string()
        };

        // Step 1: Middleware Invariance Check
        if candidate_doc.network_middlewares != boundary_doc.network_middlewares {
            return Ok(TwoStepProofResult {
                raw_prover_status,
                step1_middleware_invariant: false,
                step1_detail:
                    "candidate network_middlewares differs from boundary network_middlewares"
                        .to_string(),
                step2_prover_verdict: "skipped".to_string(),
                step2_counterexample_or_reason: None,
                coverage_domains: Vec::new(),
                verified_non_expanding: false,
            });
        }

        if !boundary_doc.network_middlewares.is_empty()
            && !boundary_doc
                .network_middlewares
                .values()
                .any(|mw| mw.on_error == "fail_closed")
        {
            return Ok(TwoStepProofResult {
                raw_prover_status,
                step1_middleware_invariant: false,
                step1_detail:
                    "network_middlewares is non-empty but no entry specifies on_error == fail_closed"
                        .to_string(),
                step2_prover_verdict: "skipped".to_string(),
                step2_counterexample_or_reason: None,
                coverage_domains: Vec::new(),
                verified_non_expanding: false,
            });
        }

        let step1_detail = if boundary_doc.network_middlewares.is_empty() {
            "no network_middlewares configured; trivially invariant".to_string()
        } else {
            format!(
                "network_middlewares invariant ({} entries, fail_closed verified)",
                boundary_doc.network_middlewares.len()
            )
        };

        // Step 2: Projected Z3 Containment Check via openshell-prover
        let mut boundary_proj_doc = boundary_doc.clone();
        let mut candidate_proj_doc = candidate_doc.clone();
        boundary_proj_doc.network_middlewares.clear();
        candidate_proj_doc.network_middlewares.clear();

        if endpoint_extensions_invariant(&boundary_proj_doc, &candidate_proj_doc) {
            strip_invariant_endpoint_extensions(&mut boundary_proj_doc);
            strip_invariant_endpoint_extensions(&mut candidate_proj_doc);
        }

        let boundary_proj_yaml = openshell_policy_schema::serialize_policy(&boundary_proj_doc)
            .map_err(|err| {
                RiskGuardError::Policy(format!(
                    "failed to serialize projected boundary policy: {err:#}"
                ))
            })?;
        let candidate_proj_yaml = openshell_policy_schema::serialize_policy(&candidate_proj_doc)
            .map_err(|err| {
                RiskGuardError::Policy(format!(
                    "failed to serialize projected candidate policy: {err:#}"
                ))
            })?;

        let boundary_proj = parse_policy_str(&boundary_proj_yaml).map_err(|err| {
            RiskGuardError::Policy(format!(
                "failed to parse projected boundary policy for prover: {err}"
            ))
        })?;
        let candidate_proj = parse_policy_str(&candidate_proj_yaml).map_err(|err| {
            RiskGuardError::Policy(format!(
                "failed to parse projected candidate policy for prover: {err}"
            ))
        })?;

        let check_result =
            check_within_boundary(&boundary_proj, &candidate_proj, CheckOptions::new(timeout));

        let (step2_prover_verdict, step2_counterexample_or_reason, coverage_domains, verified) =
            match check_result {
                CheckResult::Within(ev) => (
                    "within_boundary".to_string(),
                    None,
                    ev.coverage()
                        .domains
                        .iter()
                        .map(|d| d.as_str().to_string())
                        .collect(),
                    true,
                ),
                CheckResult::Exceeds(ev) => (
                    "exceeds_boundary".to_string(),
                    Some(format!("{:?}", ev.counterexample())),
                    ev.coverage()
                        .domains
                        .iter()
                        .map(|d| d.as_str().to_string())
                        .collect(),
                    false,
                ),
                CheckResult::Unsupported(ev) => (
                    "unsupported".to_string(),
                    Some(format!("{}: {}", ev.reason_code().as_str(), ev.reason())),
                    ev.coverage()
                        .domains
                        .iter()
                        .map(|d| d.as_str().to_string())
                        .collect(),
                    false,
                ),
                CheckResult::Inconclusive(ev) => (
                    "inconclusive".to_string(),
                    Some(format!("{}: {}", ev.reason_code().as_str(), ev.reason())),
                    ev.coverage()
                        .domains
                        .iter()
                        .map(|d| d.as_str().to_string())
                        .collect(),
                    false,
                ),
            };

        Ok(TwoStepProofResult {
            raw_prover_status,
            step1_middleware_invariant: true,
            step1_detail,
            step2_prover_verdict,
            step2_counterexample_or_reason,
            coverage_domains,
            verified_non_expanding: verified,
        })
    }

    fn generate_recommendation(
        &self,
        sandbox_id: &str,
        epoch_id: &str,
        current_policy_yaml: &str,
        history: &[(NormalizedRequest, DecisionOutcome)],
        held_out_benign: &[NormalizedRequest],
        interval_start_ms: i64,
        interval_end_ms: i64,
        coverage_gaps: Vec<String>,
    ) -> Result<HardeningCandidate> {
        let mut candidate_doc =
            openshell_policy_schema::parse_policy(current_policy_yaml).map_err(|err| {
                RiskGuardError::Policy(format!("failed to parse current policy YAML: {err:#}"))
            })?;

        let allowed_requests: Vec<&NormalizedRequest> = history
            .iter()
            .filter_map(|(req, outcome)| {
                matches!(
                    outcome,
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithObservation
                )
                .then_some(req)
            })
            .collect();

        let mut diff_summary = Vec::new();

        for (rule_key, rule) in &mut candidate_doc.network_policies {
            if is_provider_rule_name(rule_key)
                || is_provider_rule_name(rule.effective_name(rule_key))
            {
                continue;
            }

            let rule_requests: Vec<&NormalizedRequest> = allowed_requests
                .iter()
                .copied()
                .filter(|req| request_matches_rule(req, rule))
                .collect();

            if rule.binaries.len() > 1 {
                let retained_binaries: Vec<_> = rule
                    .binaries
                    .iter()
                    .filter(|bin| {
                        rule_requests
                            .iter()
                            .any(|req| request_matches_binary_pattern(req, &bin.path))
                    })
                    .cloned()
                    .collect();

                if !retained_binaries.is_empty() && retained_binaries.len() < rule.binaries.len() {
                    diff_summary.push(format!(
                        "rule '{rule_key}': narrowed binaries from {} to {}",
                        rule.binaries.len(),
                        retained_binaries.len()
                    ));
                    rule.binaries = retained_binaries;
                }
            }

            let rule_binaries_snapshot = rule.binaries.clone();
            for endpoint in &mut rule.endpoints {
                if !endpoint.protocol.eq_ignore_ascii_case("rest") {
                    continue;
                }

                if is_broad_rest_endpoint(endpoint) {
                    let mut synthesized_pairs: BTreeSet<(String, String)> = BTreeSet::new();
                    for req in &allowed_requests {
                        if !rule_binaries_snapshot.is_empty()
                            && (req.binary_path.is_some() || !req.ancestors.is_empty())
                            && !rule_binaries_snapshot
                                .iter()
                                .any(|b| request_matches_binary_pattern(req, &b.path))
                        {
                            continue;
                        }
                        if !request_matches_endpoint_connection(req, endpoint) {
                            continue;
                        }
                        let method = req.method.trim().to_ascii_uppercase();
                        if method.is_empty() {
                            continue;
                        }
                        for path in synthesize_l7_paths(req) {
                            if endpoint_allows_method_and_path(endpoint, &method, &path) {
                                synthesized_pairs.insert((method.clone(), path));
                            }
                        }
                    }

                    if !synthesized_pairs.is_empty() {
                        let prev_desc = if !endpoint.access.is_empty() {
                            format!("access '{}'", endpoint.access)
                        } else {
                            format!("{} wildcard rules", endpoint.rules.len())
                        };
                        endpoint.access.clear();
                        endpoint.rules = synthesized_pairs
                            .into_iter()
                            .map(|(method, path)| make_l7_rule(method, path))
                            .collect();
                        diff_summary.push(format!(
                            "rule '{rule_key}' endpoint '{}': narrowed {prev_desc} to {} explicit REST rules",
                            endpoint.host,
                            endpoint.rules.len()
                        ));
                    }
                } else if endpoint.access.is_empty() && endpoint.rules.len() > 1 {
                    let endpoint_snapshot = endpoint.clone();
                    let retained_rules: Vec<L7Rule> = endpoint
                        .rules
                        .iter()
                        .filter(|l7_rule| {
                            allowed_requests.iter().any(|req| {
                                if !rule_binaries_snapshot.is_empty()
                                    && (req.binary_path.is_some() || !req.ancestors.is_empty())
                                    && !rule_binaries_snapshot
                                        .iter()
                                        .any(|b| request_matches_binary_pattern(req, &b.path))
                                {
                                    return false;
                                }
                                if !request_matches_endpoint_connection(req, &endpoint_snapshot) {
                                    return false;
                                }
                                let method = req.method.trim().to_ascii_uppercase();
                                if !method_pattern_allows(&l7_rule.allow.method, &method) {
                                    return false;
                                }
                                let concrete = concrete_path_for_request(req);
                                path_glob_matches(&l7_rule.allow.path, &concrete)
                                    || synthesize_l7_paths(req)
                                        .iter()
                                        .any(|p| path_glob_matches(&l7_rule.allow.path, p))
                            })
                        })
                        .cloned()
                        .collect();

                    if !retained_rules.is_empty() && retained_rules.len() < endpoint.rules.len() {
                        let prev_len = endpoint.rules.len();
                        endpoint.rules = retained_rules;
                        diff_summary.push(format!(
                            "rule '{rule_key}' endpoint '{}': pruned {} unexercised REST rules (retained {} of {} explicit rules)",
                            endpoint.host,
                            prev_len - endpoint.rules.len(),
                            endpoint.rules.len(),
                            prev_len
                        ));
                    }
                }
            }
        }

        let candidate_yaml = openshell_policy_schema::serialize_policy(&candidate_doc)
            .map_err(|err| {
                RiskGuardError::Policy(format!("failed to serialize candidate policy YAML: {err:#}"))
            })?;

        let source_policy_hash = sha256_hex(current_policy_yaml.as_bytes());
        let candidate_policy_hash = sha256_hex(candidate_yaml.as_bytes());

        let two_step_proof = self.verify_two_step_containment(
            current_policy_yaml,
            &candidate_yaml,
            DEFAULT_RECOMMENDATION_PROOF_TIMEOUT,
        )?;

        let replay_total_requests = held_out_benign.len();
        let replay_would_block = held_out_benign
            .iter()
            .filter(|req| !policy_allows_normalized_request(&candidate_doc, req))
            .count();

        let completeness_ok = coverage_gaps.is_empty();
        let status = if !completeness_ok {
            "incomplete_coverage".to_string()
        } else if !two_step_proof.verified_non_expanding {
            "rejected_containment".to_string()
        } else if replay_would_block > 0 {
            "blocked_on_replay".to_string()
        } else {
            "ready".to_string()
        };

        Ok(HardeningCandidate {
            recommendation_id: format!("rec-{sandbox_id}-{epoch_id}-{interval_end_ms}"),
            sandbox_id: sandbox_id.to_string(),
            epoch_id: epoch_id.to_string(),
            interval_start_ms,
            interval_end_ms,
            observed_requests: history.len(),
            completeness_ok,
            coverage_gaps,
            source_policy_hash,
            candidate_policy_hash,
            candidate_yaml,
            diff_summary,
            two_step_proof,
            replay_total_requests,
            replay_would_block,
            status,
        })
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn make_l7_rule(method: String, path: String) -> L7Rule {
    L7Rule {
        allow: L7Allow {
            method,
            path,
            command: String::new(),
            query: BTreeMap::new(),
            operation_type: String::new(),
            operation_name: String::new(),
            fields: Vec::new(),
            tool: None,
            params: BTreeMap::new(),
        },
    }
}

fn endpoint_has_credential_or_tls_ext(ep: &NetworkEndpoint) -> bool {
    ep.credential_binding.is_some()
        || !ep.credential_signing.is_empty()
        || !ep.signing_service.is_empty()
        || !ep.signing_region.is_empty()
        || !ep.tls.is_empty()
}

fn endpoint_extensions_invariant(boundary: &PolicyDocument, candidate: &PolicyDocument) -> bool {
    let any_ext = boundary
        .network_policies
        .values()
        .chain(candidate.network_policies.values())
        .flat_map(|r| &r.endpoints)
        .any(endpoint_has_credential_or_tls_ext);
    if !any_ext {
        return false;
    }

    for (rule_key, cand_rule) in &candidate.network_policies {
        for cand_ep in &cand_rule.endpoints {
            if !endpoint_has_credential_or_tls_ext(cand_ep) {
                continue;
            }
            let Some(bound_rule) = boundary.network_policies.get(rule_key) else {
                return false;
            };
            let matched = bound_rule.endpoints.iter().any(|bound_ep| {
                bound_ep.host.eq_ignore_ascii_case(&cand_ep.host)
                    && cand_ep
                        .effective_ports()
                        .iter()
                        .all(|p| bound_ep.effective_ports().contains(p))
                    && bound_ep.credential_binding == cand_ep.credential_binding
                    && bound_ep.credential_signing == cand_ep.credential_signing
                    && bound_ep.signing_service == cand_ep.signing_service
                    && bound_ep.signing_region == cand_ep.signing_region
                    && bound_ep.tls == cand_ep.tls
            });
            if !matched {
                return false;
            }
        }
    }
    true
}

fn strip_invariant_endpoint_extensions(doc: &mut PolicyDocument) {
    for rule in doc.network_policies.values_mut() {
        for ep in &mut rule.endpoints {
            ep.credential_binding = None;
            ep.credential_signing.clear();
            ep.signing_service.clear();
            ep.signing_region.clear();
            ep.tls.clear();
        }
    }
}

fn is_broad_rest_endpoint(endpoint: &NetworkEndpoint) -> bool {
    if matches!(
        endpoint.access.as_str(),
        "full" | "read-write" | "read_write"
    ) {
        return true;
    }
    endpoint.access.is_empty()
        && !endpoint.rules.is_empty()
        && endpoint.rules.iter().any(|r| {
            r.allow.method == "*"
                || matches!(r.allow.path.as_str(), "" | "*" | "**" | "/**" | "/*")
        })
}

fn request_matches_rule(req: &NormalizedRequest, rule: &NetworkPolicyRule) -> bool {
    let binary_ok = rule.binaries.is_empty()
        || (req.binary_path.is_none() && req.ancestors.is_empty())
        || rule
            .binaries
            .iter()
            .any(|b| request_matches_binary_pattern(req, &b.path));
    binary_ok
        && rule
            .endpoints
            .iter()
            .any(|ep| request_matches_endpoint_connection(req, ep))
}

fn request_matches_binary_pattern(req: &NormalizedRequest, pattern: &str) -> bool {
    req.binary_path
        .as_deref()
        .is_some_and(|bp| path_glob_matches(pattern, bp))
        || req
            .ancestors
            .iter()
            .any(|anc| path_glob_matches(pattern, anc))
}

fn request_matches_endpoint_connection(req: &NormalizedRequest, endpoint: &NetworkEndpoint) -> bool {
    let ports = endpoint.effective_ports();
    ports.contains(&req.port) && host_glob_matches(&endpoint.host, &req.host)
}

fn host_glob_matches(pattern: &str, host: &str) -> bool {
    let pat_lower = pattern.trim().to_ascii_lowercase();
    let host_lower = host.trim().to_ascii_lowercase();
    if pat_lower == host_lower || pat_lower == "*" || pat_lower == "**" {
        return true;
    }
    if let Some(suffix) = pat_lower.strip_prefix("*.") {
        return host_lower.ends_with(&format!(".{suffix}"))
            && !host_lower[..host_lower.len() - suffix.len() - 1].contains('.');
    }
    if let Some(suffix) = pat_lower.strip_prefix("**.") {
        return host_lower == suffix || host_lower.ends_with(&format!(".{suffix}"));
    }
    let pat_labels: Vec<&str> = pat_lower.split('.').collect();
    let host_labels: Vec<&str> = host_lower.split('.').collect();
    wildcard_segments_match(&pat_labels, &host_labels)
}

fn path_glob_matches(pattern: &str, path: &str) -> bool {
    if matches!(pattern, "" | "**" | "/**") || pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**")
        && (path == prefix || path.starts_with(&format!("{prefix}/"))) {
            return true;
        }
    let pat_segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    wildcard_segments_match(&pat_segs, &path_segs)
}

fn wildcard_segments_match(pat: &[&str], text: &[&str]) -> bool {
    if pat.is_empty() {
        return text.is_empty();
    }
    if pat[0] == "**" {
        return wildcard_segments_match(&pat[1..], text)
            || (!text.is_empty() && wildcard_segments_match(pat, &text[1..]));
    }
    if text.is_empty() {
        return false;
    }
    wildcard_str_match(pat[0].as_bytes(), text[0].as_bytes())
        && wildcard_segments_match(&pat[1..], &text[1..])
}

fn wildcard_str_match(pat: &[u8], text: &[u8]) -> bool {
    if pat.is_empty() {
        return text.is_empty();
    }
    if pat[0] == b'*' {
        return wildcard_str_match(&pat[1..], text)
            || (!text.is_empty() && wildcard_str_match(pat, &text[1..]));
    }
    !text.is_empty() && pat[0] == text[0] && wildcard_str_match(&pat[1..], &text[1..])
}

fn synthesize_l7_paths(req: &NormalizedRequest) -> Vec<String> {
    let route = req.route_template.trim();
    let resource = req.resource_id.trim().trim_matches('/');

    if route.is_empty() || route == "unknown" {
        if !resource.is_empty() && resource != "unknown" {
            let p = sanitize_l7_path(&format!("/{resource}"));
            return vec![p];
        }
        return vec!["/**".to_string()];
    }

    if route.contains("{owner}/{repo}") {
        let rep = if !resource.is_empty() && resource != "unknown" {
            resource
        } else {
            "*/*"
        };
        let replaced = route.replace("{owner}/{repo}", rep);
        let segments: Vec<&str> = replaced
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        // /repos/<owner>/<repo> has 3 segments
        if segments.len() <= 3 && !replaced.contains('{') {
            return vec![sanitize_l7_path(&format!("/{}", segments.join("/")))];
        }

        // Sub-resource under /repos/<owner>/<repo>/...
        // Keep concrete non-placeholder prefix up to the first placeholder segment
        let mut prefix_segments = Vec::new();
        let mut had_placeholder = false;
        for seg in &segments {
            if seg.starts_with('{') && seg.ends_with('}') {
                had_placeholder = true;
                break;
            }
            prefix_segments.push(*seg);
        }

        let base_path = sanitize_l7_path(&format!("/{}", prefix_segments.join("/")));
        if prefix_segments.len() > 3 {
            let wildcard_path = sanitize_l7_path(&format!("{base_path}/**"));
            if had_placeholder {
                return vec![base_path, wildcard_path];
            }
            return vec![base_path, wildcard_path];
        }
        return vec![ sanitize_l7_path(&format!("{base_path}/**")) ];
    }

    // Generic route template without {owner}/{repo}
    let mut out_segments = Vec::new();
    let raw_segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
    for (idx, seg) in raw_segments.iter().enumerate() {
        if seg.starts_with('{') && seg.ends_with('}') {
            if idx + 1 == raw_segments.len() {
                out_segments.push("**");
            } else {
                out_segments.push("*");
            }
        } else {
            out_segments.push(*seg);
        }
    }
    let path = sanitize_l7_path(&format!("/{}", out_segments.join("/")));
    vec![path]
}

fn sanitize_l7_path(raw: &str) -> String {
    let mut cleaned = String::with_capacity(raw.len() + 1);
    for ch in raw.chars() {
        if matches!(ch, '?' | '[' | ']' | '{' | '}' | '\\') {
            cleaned.push('*');
        } else {
            cleaned.push(ch);
        }
    }
    let segments: Vec<&str> = cleaned
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .collect();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn concrete_path_for_request(req: &NormalizedRequest) -> String {
    let route = req.route_template.trim();
    let resource = req.resource_id.trim().trim_matches('/');

    if route.is_empty() || route == "unknown" {
        if !resource.is_empty() && resource != "unknown" {
            return sanitize_l7_path(&format!("/{resource}"));
        }
        return "/".to_string();
    }

    let replaced = if route.contains("{owner}/{repo}") {
        let rep = if !resource.is_empty() && resource != "unknown" {
            resource
        } else {
            "owner/repo"
        };
        route.replace("{owner}/{repo}", rep)
    } else {
        route.to_string()
    };

    let segments: Vec<&str> = replaced
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            if seg.starts_with('{') && seg.ends_with('}') {
                "item"
            } else {
                seg
            }
        })
        .collect();

    if segments.is_empty() {
        "/".to_string()
    } else {
        sanitize_l7_path(&format!("/{}", segments.join("/")))
    }
}

fn method_pattern_allows(rule_method: &str, req_method: &str) -> bool {
    if rule_method.is_empty() {
        return false;
    }
    if rule_method == "*" || rule_method.eq_ignore_ascii_case(req_method) {
        return true;
    }
    rule_method.eq_ignore_ascii_case("GET") && req_method.eq_ignore_ascii_case("HEAD")
}

fn endpoint_allows_method_and_path(
    endpoint: &NetworkEndpoint,
    method: &str,
    path: &str,
) -> bool {
    if !endpoint.path.is_empty() && !path_glob_matches(&endpoint.path, path) {
        return false;
    }

    let denied = endpoint
        .deny_rules
        .iter()
        .any(|d| method_pattern_allows(&d.method, method) && path_glob_matches(&d.path, path));
    if denied {
        return false;
    }

    match endpoint.access.as_str() {
        "full" => true,
        "read-write" | "read_write" => AccessPreset::ReadWrite
            .methods("rest")
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method)),
        "read-only" | "read_only" => AccessPreset::ReadOnly
            .methods("rest")
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method)),
        "" => endpoint.rules.iter().any(|r| {
            method_pattern_allows(&r.allow.method, method)
                && path_glob_matches(&r.allow.path, path)
        }),
        _ => false,
    }
}

fn policy_allows_normalized_request(doc: &PolicyDocument, req: &NormalizedRequest) -> bool {
    let concrete_path = concrete_path_for_request(req);
    let method = req.method.trim().to_ascii_uppercase();

    for rule in doc.network_policies.values() {
        if !request_matches_rule(req, rule) {
            continue;
        }
        for endpoint in &rule.endpoints {
            if !request_matches_endpoint_connection(req, endpoint) {
                continue;
            }
            if endpoint.protocol.eq_ignore_ascii_case("rest") {
                let denied = endpoint.deny_rules.iter().any(|d| {
                    method_pattern_allows(&d.method, &method)
                        && path_glob_matches(&d.path, &concrete_path)
                });
                if denied {
                    return false;
                }
            }
        }
    }

    doc.network_policies.values().any(|rule| {
        request_matches_rule(req, rule)
            && rule.endpoints.iter().any(|endpoint| {
                request_matches_endpoint_connection(req, endpoint)
                    && (endpoint.is_l4()
                        || (endpoint.protocol.eq_ignore_ascii_case("rest")
                            && endpoint_allows_method_and_path(endpoint, &method, &concrete_path)))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(
        request_id: &str,
        method: &str,
        route_template: &str,
        resource_id: &str,
        binary_path: Option<&str>,
    ) -> NormalizedRequest {
        NormalizedRequest {
            request_id: request_id.to_string(),
            sandbox_id: "sb-1".to_string(),
            scheme: "https".to_string(),
            host: "api.github.com".to_string(),
            port: 443,
            method: method.to_string(),
            route_template: route_template.to_string(),
            resource_id: resource_id.to_string(),
            resource_key: format!("key-{resource_id}"),
            action_class: format!("{method} {route_template}"),
            restriction_scope: format!(
                "https://api.github.com:443 {method} {route_template} {resource_id}"
            ),
            high_impact: method != "GET",
            semantic_category: if method == "GET" {
                "read_only".to_string()
            } else {
                "write_mutation".to_string()
            },
            binary_path: binary_path.map(str::to_string),
            ancestors: Vec::new(),
            fingerprint: format!("fp-{request_id}"),
            timestamp_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn extract_credentialed_endpoints_detects_credential_binding_and_provider_rules() {
        let yaml = r#"
version: 1
network_policies:
  _provider_openai:
    endpoints:
      - host: API.OPENAI.COM
        port: 443
      - host: files.openai.com
        ports: [443, 8443]
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        credential_binding:
          provider: github-token
  aws_s3:
    endpoints:
      - host: s3.amazonaws.com
        port: 443
        credential_signing: sigv4
  public_docs:
    endpoints:
      - host: docs.rs
        port: 443
"#;

        let engine = ProverHardeningEngine::new();
        let creds = engine
            .extract_credentialed_endpoints(yaml)
            .expect("should parse and extract credentialed endpoints");

        let expected = BTreeSet::from([
            ("api.openai.com".to_string(), 443),
            ("files.openai.com".to_string(), 443),
            ("files.openai.com".to_string(), 8443),
            ("api.github.com".to_string(), 443),
            ("s3.amazonaws.com".to_string(), 443),
        ]);
        assert_eq!(creds, expected);
        assert!(!creds.contains(&("docs.rs".to_string(), 443)));
    }

    #[test]
    fn verify_two_step_containment_proves_within_boundary_with_middlewares() {
        let boundary_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/gh
"#;

        let candidate_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/org/docs-site
    binaries:
      - path: /usr/bin/gh
"#;

        let engine = ProverHardeningEngine::new();
        let proof = engine
            .verify_two_step_containment(boundary_yaml, candidate_yaml, Duration::from_secs(5))
            .expect("two-step containment proof should succeed");

        assert_eq!(
            proof.raw_prover_status,
            "unsupported: uses network middleware controls"
        );
        assert!(proof.step1_middleware_invariant);
        assert_eq!(proof.step2_prover_verdict, "within_boundary");
        assert!(proof.step2_counterexample_or_reason.is_none());
        assert!(proof.verified_non_expanding);
        assert!(proof.coverage_domains.contains(&"network_rest".to_string()));
    }

    #[test]
    fn verify_two_step_containment_rejects_modified_or_removed_middlewares() {
        let boundary_yaml = r#"
version: 1
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
"#;

        let removed_mw_yaml = r#"
version: 1
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/org/docs-site
"#;

        let weakened_mw_yaml = r#"
version: 1
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_open
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/org/docs-site
"#;

        let engine = ProverHardeningEngine::new();

        let proof_removed = engine
            .verify_two_step_containment(boundary_yaml, removed_mw_yaml, Duration::from_secs(5))
            .expect("should return proof result");
        assert!(!proof_removed.step1_middleware_invariant);
        assert_eq!(proof_removed.step2_prover_verdict, "skipped");
        assert!(!proof_removed.verified_non_expanding);

        let proof_weakened = engine
            .verify_two_step_containment(boundary_yaml, weakened_mw_yaml, Duration::from_secs(5))
            .expect("should return proof result");
        assert!(!proof_weakened.step1_middleware_invariant);
        assert_eq!(proof_weakened.step2_prover_verdict, "skipped");
        assert!(!proof_weakened.verified_non_expanding);
    }

    #[test]
    fn verify_two_step_containment_rejects_expanding_candidate_in_step2() {
        let boundary_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/org/docs-site
    binaries:
      - path: /usr/bin/gh
"#;

        let expanding_method_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/org/docs-site
          - allow:
              method: POST
              path: /admin
    binaries:
      - path: /usr/bin/gh
"#;

        let expanding_host_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: evil.example.com
        port: 8443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/org/docs-site
    binaries:
      - path: /usr/bin/gh
"#;

        let engine = ProverHardeningEngine::new();

        let proof_method = engine
            .verify_two_step_containment(
                boundary_yaml,
                expanding_method_yaml,
                Duration::from_secs(5),
            )
            .expect("should return proof result");
        assert!(proof_method.step1_middleware_invariant);
        assert_eq!(proof_method.step2_prover_verdict, "exceeds_boundary");
        assert!(!proof_method.verified_non_expanding);
        let ce = proof_method
            .step2_counterexample_or_reason
            .expect("should include counterexample");
        assert!(ce.contains("POST") || ce.contains("/admin"), "unexpected ce: {ce}");

        let proof_host = engine
            .verify_two_step_containment(boundary_yaml, expanding_host_yaml, Duration::from_secs(5))
            .expect("should return proof result");
        assert!(proof_host.step1_middleware_invariant);
        assert_eq!(proof_host.step2_prover_verdict, "exceeds_boundary");
        assert!(!proof_host.verified_non_expanding);
        assert!(proof_host.step2_counterexample_or_reason.is_some());
    }

    #[test]
    fn generate_recommendation_narrows_policy_and_verifies_containment_and_replay() {
        let current_policy_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  _provider_github:
    endpoints:
      - host: uploads.github.com
        port: 443
    binaries:
      - path: /usr/bin/gh
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        deny_rules:
          - method: DELETE
            path: /repos/**
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/gh
      - path: /usr/bin/git
"#;

        let history = vec![
            (
                sample_request(
                    "req-1",
                    "GET",
                    "/repos/{owner}/{repo}",
                    "org/docs-site",
                    Some("/usr/bin/gh"),
                ),
                DecisionOutcome::Allow,
            ),
            (
                sample_request(
                    "req-2",
                    "GET",
                    "/repos/{owner}/{repo}/issues",
                    "org/docs-site",
                    Some("/usr/bin/gh"),
                ),
                DecisionOutcome::AllowWithObservation,
            ),
            (
                sample_request(
                    "req-3",
                    "POST",
                    "/repos/{owner}/{repo}/hooks",
                    "org/untrusted-repo",
                    Some("/usr/bin/curl"),
                ),
                DecisionOutcome::Deny,
            ),
        ];

        let held_out_benign = vec![
            sample_request(
                "holdout-1",
                "GET",
                "/repos/{owner}/{repo}",
                "org/docs-site",
                Some("/usr/bin/gh"),
            ),
            sample_request(
                "holdout-2",
                "GET",
                "/repos/{owner}/{repo}/issues/{issue_number}",
                "org/docs-site",
                Some("/usr/bin/gh"),
            ),
        ];

        let engine = ProverHardeningEngine::new();
        let candidate = engine
            .generate_recommendation(
                "sb-1",
                "epoch-1",
                current_policy_yaml,
                &history,
                &held_out_benign,
                1_000,
                2_000,
                Vec::new(),
            )
            .expect("recommendation generation should succeed");

        assert!(candidate.completeness_ok);
        assert!(candidate.two_step_proof.verified_non_expanding);
        assert_eq!(
            candidate.two_step_proof.step2_prover_verdict,
            "within_boundary"
        );
        assert_eq!(candidate.replay_total_requests, 2);
        assert_eq!(candidate.replay_would_block, 0);
        assert_eq!(candidate.status, "ready");
        assert_ne!(candidate.source_policy_hash, candidate.candidate_policy_hash);

        let parsed_candidate = openshell_policy_schema::parse_policy(&candidate.candidate_yaml)
            .expect("candidate YAML must parse");
        assert!(parsed_candidate.network_policies.contains_key("_provider_github"));

        let gh_rule = &parsed_candidate.network_policies["github_api"];
        assert_eq!(gh_rule.binaries.len(), 1);
        assert_eq!(gh_rule.binaries[0].path, "/usr/bin/gh");

        let ep = &gh_rule.endpoints[0];
        assert!(ep.access.is_empty());
        assert_eq!(ep.deny_rules.len(), 1);
        let allowed_paths: BTreeSet<&str> =
            ep.rules.iter().map(|r| r.allow.path.as_str()).collect();
        assert!(allowed_paths.contains("/repos/org/docs-site"));
        assert!(allowed_paths.contains("/repos/org/docs-site/issues/**"));
    }

    #[test]
    fn generate_recommendation_reports_replay_block_and_coverage_gaps() {
        let current_policy_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
    binaries:
      - path: /usr/bin/gh
"#;

        let history = vec![(
            sample_request(
                "req-1",
                "GET",
                "/repos/{owner}/{repo}",
                "org/docs-site",
                Some("/usr/bin/gh"),
            ),
            DecisionOutcome::Allow,
        )];

        let held_out_benign = vec![
            sample_request(
                "holdout-ok",
                "GET",
                "/repos/{owner}/{repo}",
                "org/docs-site",
                Some("/usr/bin/gh"),
            ),
            sample_request(
                "holdout-unseen",
                "POST",
                "/repos/{owner}/{repo}/issues",
                "org/other-repo",
                Some("/usr/bin/gh"),
            ),
        ];

        let engine = ProverHardeningEngine::new();
        let candidate = engine
            .generate_recommendation(
                "sb-1",
                "epoch-1",
                current_policy_yaml,
                &history,
                &held_out_benign,
                1_000,
                2_000,
                Vec::new(),
            )
            .expect("should generate recommendation");

        assert!(candidate.two_step_proof.verified_non_expanding);
        assert_eq!(candidate.replay_total_requests, 2);
        assert_eq!(candidate.replay_would_block, 1);
        assert_eq!(candidate.status, "blocked_on_replay");

        let candidate_with_gap = engine
            .generate_recommendation(
                "sb-1",
                "epoch-1",
                current_policy_yaml,
                &history,
                &[],
                1_000,
                2_000,
                vec!["restart gap 1200..1300".to_string()],
            )
            .expect("should generate recommendation with gap");
        assert!(!candidate_with_gap.completeness_ok);
        assert_eq!(candidate_with_gap.status, "incomplete_coverage");
    }

    #[test]
    fn generate_recommendation_prunes_unexercised_explicit_rules_and_proves_containment() {
        let demo_policy_yaml = include_str!("../../deploy/rail-guard-demo/sandbox-policy.yaml");
        let allow_req = NormalizedRequest {
            request_id: "req-allow-1".to_string(),
            sandbox_id: "sb-demo".to_string(),
            scheme: "http".to_string(),
            host: "host.openshell.internal".to_string(),
            port: 18081,
            method: "GET".to_string(),
            route_template: "/repos/{owner}/{repo}/issues".to_string(),
            resource_id: "local/review".to_string(),
            resource_key: "rk-review".to_string(),
            action_class: "GET /repos/{owner}/{repo}/issues".to_string(),
            restriction_scope:
                "http://host.openshell.internal:18081 GET /repos/{owner}/{repo}/issues local/review"
                    .to_string(),
            high_impact: false,
            semantic_category: "read_only".to_string(),
            binary_path: None,
            ancestors: Vec::new(),
            fingerprint: "fp-allow".to_string(),
            timestamp_ms: 1_700_000_001_000,
        };
        let deny_req = NormalizedRequest {
            request_id: "req-deny-1".to_string(),
            sandbox_id: "sb-demo".to_string(),
            scheme: "http".to_string(),
            host: "host.openshell.internal".to_string(),
            port: 18081,
            method: "DELETE".to_string(),
            route_template: "/repos/{owner}/{repo}".to_string(),
            resource_id: "local/production".to_string(),
            resource_key: "rk-prod".to_string(),
            action_class: "DELETE /repos/{owner}/{repo}".to_string(),
            restriction_scope:
                "http://host.openshell.internal:18081 DELETE /repos/{owner}/{repo} local/production"
                    .to_string(),
            high_impact: true,
            semantic_category: "destructive_admin".to_string(),
            binary_path: None,
            ancestors: Vec::new(),
            fingerprint: "fp-deny".to_string(),
            timestamp_ms: 1_700_000_002_000,
        };

        let history = vec![
            (allow_req.clone(), DecisionOutcome::Allow),
            (deny_req, DecisionOutcome::Deny),
        ];
        let held_out = vec![allow_req];

        let engine = ProverHardeningEngine::new();
        let candidate = engine
            .generate_recommendation(
                "sb-demo",
                "ep-demo-1",
                demo_policy_yaml,
                &history,
                &held_out,
                1_700_000_001_000,
                1_700_000_002_000,
                Vec::new(),
            )
            .expect("should prune unexercised DELETE rule and verify containment");

        assert_eq!(candidate.status, "ready");
        assert!(candidate.two_step_proof.verified_non_expanding);
        assert_eq!(
            candidate.two_step_proof.step2_prover_verdict,
            "within_boundary"
        );
        assert_eq!(candidate.replay_would_block, 0);
        assert_eq!(candidate.diff_summary.len(), 1);
        assert!(candidate.diff_summary[0].contains("pruned 1 unexercised REST rules"));
        assert!(!candidate.candidate_yaml.contains("DELETE"));
        assert!(candidate.candidate_yaml.contains("/repos/local/review/issues"));
    }
}

