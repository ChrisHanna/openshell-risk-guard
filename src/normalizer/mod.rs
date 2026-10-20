// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Request target normalizer and API semantic map (Wave 1 - `t02-normalizer-semantics`).

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, RiskGuardError};
use crate::types::{NormalizedRequest, RawRequestInput, RequestNormalizer};

type HmacSha256 = Hmac<Sha256>;

/// Default embedded `config/api_semantics.yaml`.
pub const DEFAULT_API_SEMANTICS_YAML: &str = include_str!("../../config/api_semantics.yaml");

/// Default normalizer version when not explicitly specified in YAML.
pub const DEFAULT_NORMALIZER_VERSION: &str = "v1";

fn default_normalizer_version() -> String {
    DEFAULT_NORMALIZER_VERSION.to_string()
}

/// Top-level deserialized configuration for curated API route semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSemanticsConfig {
    #[serde(default = "default_normalizer_version", alias = "normalizer_version")]
    pub version: String,
    #[serde(default, alias = "rules")]
    pub routes: Vec<ApiRouteRule>,
}

/// Single curated API route classification rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRouteRule {
    /// Restrict the rule to one upstream host. Without it the rule applies to every
    /// host, so templates for different APIs should always name their host.
    #[serde(default)]
    pub host: Option<String>,
    pub method: String,
    #[serde(alias = "template", alias = "path", alias = "route")]
    pub route_template: String,
    #[serde(alias = "category", alias = "classification")]
    pub semantic_category: String,
    pub high_impact: bool,
    #[serde(default, alias = "resource")]
    pub resource_template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TemplateSegment {
    Literal(String),
    Param(String),
    SingleWildcard,
    MultiWildcard,
}

#[derive(Debug, Clone)]
struct CompiledRouteRule {
    host: Option<String>,
    method: String,
    route_template: String,
    segments: Vec<TemplateSegment>,
    semantic_category: String,
    high_impact: bool,
    resource_template: Option<String>,
}

impl CompiledRouteRule {
    fn compile(rule: ApiRouteRule) -> Result<Self> {
        let host = rule.host.as_deref().map(normalize_host).transpose()?;
        let method = normalize_method(&rule.method)?;
        let route_template = normalize_template_path(&rule.route_template)?;
        let segments = parse_template_segments(&route_template)?;

        if rule.semantic_category.trim().is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "semantic_category must not be empty".to_string(),
            ));
        }

        Ok(Self {
            host,
            method,
            route_template,
            segments,
            semantic_category: rule.semantic_category,
            high_impact: rule.high_impact,
            resource_template: rule.resource_template,
        })
    }

    fn matches<'a>(
        &self,
        host: &str,
        method: &str,
        path_segments: &[&'a str],
    ) -> Option<BTreeMap<String, &'a str>> {
        if self.method != method || self.host.as_deref().is_some_and(|rule| rule != host) {
            return None;
        }
        let mut captures = BTreeMap::new();
        if match_segments(&self.segments, path_segments, &mut captures) {
            Some(captures)
        } else {
            None
        }
    }

    fn extract_resource_id(&self, canonical_path: &str, captures: &BTreeMap<String, &str>) -> String {
        if let Some(ref tpl) = self.resource_template {
            return interpolate_resource_template(tpl, captures);
        }
        if let (Some(owner), Some(repo)) = (captures.get("owner"), captures.get("repo")) {
            return format!("{owner}/{repo}");
        }
        canonical_path.to_string()
    }
}

/// Canonical request normalizer and curated API semantic classifier.
#[derive(Debug, Clone)]
pub struct CanonicalNormalizer {
    version: String,
    hmac_key: Vec<u8>,
    rules: Vec<CompiledRouteRule>,
}

impl CanonicalNormalizer {
    /// Construct a `CanonicalNormalizer` loaded with the embedded default `config/api_semantics.yaml`.
    #[must_use]
    pub fn new_default(hmac_key: &[u8]) -> Self {
        Self::from_yaml_str(DEFAULT_API_SEMANTICS_YAML, hmac_key)
            .expect("embedded config/api_semantics.yaml must be valid")
    }

    /// Construct a `CanonicalNormalizer` from a YAML configuration string and HMAC key.
    pub fn from_yaml_str(yaml: &str, hmac_key: &[u8]) -> Result<Self> {
        let config: ApiSemanticsConfig = serde_yml::from_str(yaml).map_err(|err| {
            RiskGuardError::InvalidArgument(format!("invalid api_semantics yaml: {err}"))
        })?;

        if config.version.trim().is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "normalizer version must not be empty".to_string(),
            ));
        }

        let mut rules = Vec::with_capacity(config.routes.len());
        for rule in config.routes {
            rules.push(CompiledRouteRule::compile(rule)?);
        }
        // First match wins; a host-specific rule always beats a host-agnostic one.
        rules.sort_by_key(|rule| rule.host.is_none());

        Ok(Self {
            version: config.version,
            hmac_key: hmac_key.to_vec(),
            rules,
        })
    }

    /// Load an operator-mounted semantic map. Its `version` must equal the normalizer
    /// contract that approved baselines were built against, and it must define routes.
    pub fn from_file(path: &std::path::Path, hmac_key: &[u8]) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|err| {
            RiskGuardError::InvalidArgument(format!(
                "failed to read api semantics '{}': {err}",
                path.display()
            ))
        })?;
        let normalizer = Self::from_yaml_str(&raw, hmac_key)?;
        if normalizer.version != DEFAULT_NORMALIZER_VERSION {
            return Err(RiskGuardError::InvalidArgument(format!(
                "api semantics version '{}' does not match normalizer contract '{DEFAULT_NORMALIZER_VERSION}' used by approved baselines",
                normalizer.version
            )));
        }
        if normalizer.rules.is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "api semantics file defines no routes".into(),
            ));
        }
        Ok(normalizer)
    }

    /// Normalize a [`RawRequestInput`] into a [`NormalizedRequest`].
    pub fn normalize(&self, input: &RawRequestInput) -> Result<NormalizedRequest> {
        let scheme = normalize_scheme(&input.scheme)?;
        let host = normalize_host(&input.host)?;
        let port = validate_port(input.port)?;
        let method = normalize_method(&input.method)?;
        let path = normalize_request_path(&input.path)?;

        let binary_path = normalize_optional_process_path(input.binary_path.as_deref())?;
        let ancestors = normalize_ancestors(&input.ancestors)?;

        let path_segments = split_canonical_path(&path);

        let (route_template, resource_id, high_impact, semantic_category) =
            if let Some((rule, captures)) = self
                .rules
                .iter()
                .find_map(|r| r.matches(&host, &method, &path_segments).map(|c| (r, c)))
            {
                let resource_id = rule.extract_resource_id(&path, &captures);
                (
                    rule.route_template.clone(),
                    resource_id,
                    rule.high_impact,
                    rule.semantic_category.clone(),
                )
            } else {
                // Unknown semantics fail safe: only methods that cannot change state are
                // low-impact. POST, custom verbs and RPC-over-HTTP are assumed consequential.
                let high_impact = !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS");
                (
                    "unknown".to_string(),
                    format!("{host}:{port}{path}"),
                    high_impact,
                    "unknown".to_string(),
                )
            };

        let resource_key = compute_hmac_sha256_hex(&self.hmac_key, &resource_id);
        let action_class = format!("{method} {route_template}");
        let restriction_scope =
            format!("{scheme}://{host}:{port} {method} {route_template} {resource_id}");
        let fingerprint = compute_fingerprint(
            &input.sandbox_id,
            &scheme,
            &host,
            port,
            &method,
            &path,
            binary_path.as_deref(),
            &ancestors,
        );

        Ok(NormalizedRequest {
            request_id: input.request_id.clone(),
            sandbox_id: input.sandbox_id.clone(),
            scheme,
            host,
            port,
            method,
            route_template,
            resource_id,
            resource_key,
            action_class,
            restriction_scope,
            high_impact,
            semantic_category,
            binary_path,
            ancestors,
            fingerprint,
            timestamp_ms: input.timestamp_ms,
        })
    }

    /// Return the semantic normalizer version string.
    #[must_use]
    pub fn normalizer_version(&self) -> &str {
        &self.version
    }
}

impl RequestNormalizer for CanonicalNormalizer {
    fn normalize(&self, input: &RawRequestInput) -> Result<NormalizedRequest> {
        CanonicalNormalizer::normalize(self, input)
    }

    fn normalizer_version(&self) -> &str {
        CanonicalNormalizer::normalizer_version(self)
    }
}

fn normalize_scheme(raw: &str) -> Result<String> {
    if raw.is_empty()
        || !raw.is_ascii()
        || raw.chars().any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
    {
        return Err(RiskGuardError::InvalidArgument(format!(
            "invalid scheme '{raw}'"
        )));
    }
    let lower = raw.to_ascii_lowercase();
    match lower.as_str() {
        "http" | "https" | "ws" | "wss" => Ok(lower),
        _ => Err(RiskGuardError::InvalidArgument(format!(
            "unsupported scheme '{raw}'; expected http, https, ws, or wss"
        ))),
    }
}

fn normalize_host(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(RiskGuardError::InvalidArgument(
            "host must not be empty".to_string(),
        ));
    }
    if !raw.is_ascii()
        || raw.chars().any(|c| {
            c.is_ascii_control()
                || c.is_ascii_whitespace()
                || matches!(c, '/' | '\\' | '?' | '#' | '@')
        })
    {
        return Err(RiskGuardError::InvalidArgument(format!(
            "invalid characters in host '{raw}'"
        )));
    }
    let lower = raw.to_ascii_lowercase();
    if !lower.starts_with('[') && (lower.starts_with('.') || lower.contains("..")) {
        return Err(RiskGuardError::InvalidArgument(format!(
            "malformed DNS host '{raw}'"
        )));
    }
    Ok(lower)
}

fn validate_port(port: u16) -> Result<u16> {
    if port == 0 {
        return Err(RiskGuardError::InvalidArgument(
            "port must be in 1..=65535".to_string(),
        ));
    }
    Ok(port)
}

fn normalize_method(raw: &str) -> Result<String> {
    if raw.is_empty()
        || !raw.is_ascii()
        || raw.chars().any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
    {
        return Err(RiskGuardError::InvalidArgument(format!(
            "invalid HTTP method '{raw}'"
        )));
    }
    let upper = raw.to_ascii_uppercase();
    match upper.as_str() {
        "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE" => Ok(upper),
        _ => Err(RiskGuardError::InvalidArgument(format!(
            "unsupported HTTP method '{raw}'"
        ))),
    }
}

fn normalize_request_path(raw: &str) -> Result<String> {
    if raw.is_empty() || !raw.starts_with('/') {
        return Err(RiskGuardError::InvalidArgument(format!(
            "path must start with '/': '{raw}'"
        )));
    }
    if !raw.is_ascii()
        || raw
            .chars()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace() || c == '\\')
    {
        return Err(RiskGuardError::InvalidArgument(format!(
            "path contains invalid or non-ASCII characters: '{raw}'"
        )));
    }

    // Ignore raw query string or fragment if present in the input path
    let path_only = raw
        .split('?')
        .next()
        .unwrap_or(raw)
        .split('#')
        .next()
        .unwrap_or(raw);

    // Reject dot-segments (raw `.` or `..` as well as percent-encoded `%2e` traversal)
    // Do NOT decode `%2F` so OpenShell's canonical path semantics are preserved.
    for seg in path_only.split('/').skip(1) {
        if is_dot_traversal_segment(seg) {
            return Err(RiskGuardError::InvalidArgument(format!(
                "dot-segment path traversal is not allowed in path '{raw}'"
            )));
        }
    }

    // Trim trailing slash except on `/`
    let canonical = if path_only.len() > 1 {
        let trimmed = path_only.trim_end_matches('/');
        if trimmed.is_empty() {
            "/"
        } else {
            trimmed
        }
    } else {
        "/"
    };

    Ok(canonical.to_string())
}

fn is_dot_traversal_segment(seg: &str) -> bool {
    if seg == "." || seg == ".." {
        return true;
    }
    let lower = seg.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "%2e" | "%2e%2e" | ".%2e" | "%2e."
    ) || lower.contains("..%2f")
        || lower.contains("%2f..")
        || lower.contains("%2e%2e%2f")
        || lower.contains("%2f%2e%2e")
}

fn normalize_optional_process_path(raw: Option<&str>) -> Result<Option<String>> {
    let Some(s) = raw else {
        return Ok(None);
    };
    if !s.is_ascii() || s.chars().any(|c| c.is_ascii_control()) {
        return Err(RiskGuardError::InvalidArgument(
            "binary_path contains invalid non-ASCII or control characters".to_string(),
        ));
    }
    let trimmed = s.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn normalize_ancestors(ancestors: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(ancestors.len());
    for anc in ancestors {
        if !anc.is_ascii() || anc.chars().any(|c| c.is_ascii_control()) {
            return Err(RiskGuardError::InvalidArgument(
                "ancestor path contains invalid non-ASCII or control characters".to_string(),
            ));
        }
        let trimmed = anc.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn normalize_template_path(raw: &str) -> Result<String> {
    if raw.is_empty() || !raw.starts_with('/') || !raw.is_ascii() {
        return Err(RiskGuardError::InvalidArgument(format!(
            "invalid route_template '{raw}'"
        )));
    }
    if raw.chars().any(|c| c.is_ascii_control() || c.is_ascii_whitespace()) {
        return Err(RiskGuardError::InvalidArgument(format!(
            "route_template contains invalid whitespace or control chars: '{raw}'"
        )));
    }
    let canonical = if raw.len() > 1 {
        let trimmed = raw.trim_end_matches('/');
        if trimmed.is_empty() { "/" } else { trimmed }
    } else {
        "/"
    };
    Ok(canonical.to_string())
}

fn parse_template_segments(route_template: &str) -> Result<Vec<TemplateSegment>> {
    if route_template == "/" {
        return Ok(Vec::new());
    }
    let mut segments = Vec::new();
    for seg in route_template[1..].split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(RiskGuardError::InvalidArgument(format!(
                "invalid segment '{seg}' in route_template '{route_template}'"
            )));
        }
        if seg == "**" {
            segments.push(TemplateSegment::MultiWildcard);
        } else if seg == "*" {
            segments.push(TemplateSegment::SingleWildcard);
        } else if let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if inner.is_empty() {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "empty parameter placeholder in route_template '{route_template}'"
                )));
            }
            segments.push(TemplateSegment::Param(inner.to_string()));
        } else {
            segments.push(TemplateSegment::Literal(seg.to_string()));
        }
    }
    Ok(segments)
}

fn split_canonical_path(path: &str) -> Vec<&str> {
    if path == "/" {
        Vec::new()
    } else {
        path[1..].split('/').collect()
    }
}

fn match_segments<'a>(
    tpl: &[TemplateSegment],
    path: &[&'a str],
    captures: &mut BTreeMap<String, &'a str>,
) -> bool {
    match (tpl.first(), path.first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(TemplateSegment::MultiWildcard), _) => {
            if path.is_empty() || path.iter().any(|s| s.is_empty()) {
                return false;
            }
            if tpl.len() == 1 {
                return true;
            }
            for consume in 1..=path.len() {
                let mut sub_captures = captures.clone();
                if match_segments(&tpl[1..], &path[consume..], &mut sub_captures) {
                    *captures = sub_captures;
                    return true;
                }
            }
            false
        }
        (Some(_), None) => false,
        (Some(seg_tpl), Some(&seg_path)) => {
            if seg_path.is_empty() {
                return false;
            }
            match seg_tpl {
                TemplateSegment::Literal(lit) => {
                    if seg_path != lit {
                        return false;
                    }
                    match_segments(&tpl[1..], &path[1..], captures)
                }
                TemplateSegment::Param(name) => {
                    let prev = captures.insert(name.clone(), seg_path);
                    if match_segments(&tpl[1..], &path[1..], captures) {
                        true
                    } else {
                        if let Some(old) = prev {
                            captures.insert(name.clone(), old);
                        } else {
                            captures.remove(name);
                        }
                        false
                    }
                }
                TemplateSegment::SingleWildcard => match_segments(&tpl[1..], &path[1..], captures),
                TemplateSegment::MultiWildcard => unreachable!(),
            }
        }
    }
}

fn interpolate_resource_template(tpl: &str, captures: &BTreeMap<String, &str>) -> String {
    let mut out = String::with_capacity(tpl.len());
    let mut rest = tpl;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + 1..];
        if let Some(end) = after_start.find('}') {
            let key = &after_start[..end];
            if let Some(val) = captures.get(key) {
                out.push_str(val);
            } else {
                out.push('{');
                out.push_str(key);
                out.push('}');
            }
            rest = &after_start[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

fn compute_hmac_sha256_hex(hmac_key: &[u8], resource_id: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(hmac_key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(resource_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn compute_fingerprint(
    sandbox_id: &str,
    scheme: &str,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    binary_path: Option<&str>,
    ancestors: &[String],
) -> String {
    let canonical_tuple = (
        sandbox_id,
        scheme,
        host,
        port,
        method,
        path,
        binary_path,
        ancestors,
    );
    let payload =
        serde_json::to_vec(&canonical_tuple).expect("canonical fingerprint tuple is serializable");
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &[u8] = b"test-hmac-secret-key-0123456789";

    #[test]
    fn host_scoped_rules_win_and_do_not_leak_to_other_hosts() {
        let yaml = r#"
version: v1
routes:
  - method: DELETE
    route_template: /repos/{owner}/{repo}
    semantic_category: read_only
    high_impact: false
  - host: API.GitHub.com
    method: DELETE
    route_template: /repos/{owner}/{repo}
    semantic_category: destructive_admin
    high_impact: true
"#;
        let normalizer = CanonicalNormalizer::from_yaml_str(yaml, TEST_KEY).unwrap();
        let github = normalizer.normalize(&sample_input("DELETE", "/repos/org/app")).unwrap();
        assert!(github.high_impact, "host-specific rule takes precedence");
        assert_eq!(github.semantic_category, "destructive_admin");

        let mut other = sample_input("DELETE", "/repos/org/app");
        other.host = "billing.internal".into();
        let other = normalizer.normalize(&other).unwrap();
        assert_eq!(other.semantic_category, "read_only", "GitHub semantics stay on GitHub");
    }

    #[test]
    fn semantic_map_rejects_typos_and_mismatched_files() {
        let typo = "version: v1\nroutes:\n  - hosts: api.github.com\n    method: GET\n    route_template: /x\n    semantic_category: read_only\n    high_impact: false\n";
        assert!(
            CanonicalNormalizer::from_yaml_str(typo, TEST_KEY).is_err(),
            "a misspelled host must not silently become a global rule"
        );

        let dir = tempfile::tempdir().unwrap();
        let wrong_version = dir.path().join("v2.yaml");
        std::fs::write(&wrong_version, "version: v2\nroutes:\n  - method: GET\n    route_template: /x\n    semantic_category: read_only\n    high_impact: false\n").unwrap();
        assert!(CanonicalNormalizer::from_file(&wrong_version, TEST_KEY).is_err());
        let empty = dir.path().join("empty.yaml");
        std::fs::write(&empty, "version: v1\nroutes: []\n").unwrap();
        assert!(CanonicalNormalizer::from_file(&empty, TEST_KEY).is_err());
        let good = dir.path().join("good.yaml");
        std::fs::write(&good, "version: v1\nroutes:\n  - host: billing.internal\n    method: POST\n    route_template: /v1/refunds\n    semantic_category: write_mutation\n    high_impact: true\n").unwrap();
        let normalizer = CanonicalNormalizer::from_file(&good, TEST_KEY).unwrap();
        let mut refund = sample_input("POST", "/v1/refunds");
        refund.host = "billing.internal".into();
        assert_eq!(normalizer.normalize(&refund).unwrap().route_template, "/v1/refunds");
    }

    fn sample_input(method: &str, path: &str) -> RawRequestInput {
        RawRequestInput {
            request_id: "req-001".to_string(),
            sandbox_id: "sbx-alpha".to_string(),
            sandbox_name: "alpha".to_string(),
            workspace: "/workspace".to_string(),
            scheme: "HTTPS".to_string(),
            host: "API.GitHub.com".to_string(),
            port: 443,
            method: method.to_string(),
            path: path.to_string(),
            binary_path: Some("/usr/bin/curl".to_string()),
            pid: Some(1234),
            ancestors: vec!["/bin/bash".to_string(), "/usr/bin/python3".to_string()],
            timestamp_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn test_exact_route_template_and_resource_extraction() {
        let normalizer = CanonicalNormalizer::new_default(TEST_KEY);

        // 1. GET /repos/org/docs-site
        let r1 = normalizer
            .normalize(&sample_input("get", "/repos/org/docs-site/"))
            .expect("should normalize GET /repos/org/docs-site");
        assert_eq!(r1.scheme, "https");
        assert_eq!(r1.host, "api.github.com");
        assert_eq!(r1.port, 443);
        assert_eq!(r1.method, "GET");
        assert_eq!(r1.route_template, "/repos/{owner}/{repo}");
        assert_eq!(r1.resource_id, "org/docs-site");
        assert_eq!(r1.action_class, "GET /repos/{owner}/{repo}");
        assert_eq!(
            r1.restriction_scope,
            "https://api.github.com:443 GET /repos/{owner}/{repo} org/docs-site"
        );
        assert!(!r1.high_impact);
        assert_eq!(r1.semantic_category, "read_only");

        // 2. GET /repos/org/docs-site/issues/42
        let r2 = normalizer
            .normalize(&sample_input("GET", "/repos/org/docs-site/issues/42"))
            .expect("should normalize GET /repos/org/docs-site/issues/42");
        assert_eq!(r2.route_template, "/repos/{owner}/{repo}/issues/**");
        assert_eq!(r2.resource_id, "org/docs-site");
        assert_eq!(r2.action_class, "GET /repos/{owner}/{repo}/issues/**");
        assert!(!r2.high_impact);
        assert_eq!(r2.semantic_category, "read_only");

        // 3. DELETE /repos/org/payments-prod
        let r3 = normalizer
            .normalize(&sample_input("DELETE", "/repos/org/payments-prod"))
            .expect("should normalize DELETE /repos/org/payments-prod");
        assert_eq!(r3.route_template, "/repos/{owner}/{repo}");
        assert_eq!(r3.resource_id, "org/payments-prod");
        assert_eq!(r3.action_class, "DELETE /repos/{owner}/{repo}");
        assert_eq!(
            r3.restriction_scope,
            "https://api.github.com:443 DELETE /repos/{owner}/{repo} org/payments-prod"
        );
        assert!(r3.high_impact);
        assert_eq!(r3.semantic_category, "destructive_admin");

        // 4. PUT /repos/org/payments-prod/contents/src/main.rs
        let r4 = normalizer
            .normalize(&sample_input(
                "PUT",
                "/repos/org/payments-prod/contents/src/main.rs",
            ))
            .expect("should normalize PUT /repos/org/payments-prod/contents/src/main.rs");
        assert_eq!(r4.route_template, "/repos/{owner}/{repo}/contents/**");
        assert_eq!(r4.resource_id, "org/payments-prod");
        assert_eq!(r4.action_class, "PUT /repos/{owner}/{repo}/contents/**");
        assert!(r4.high_impact);
        assert_eq!(r4.semantic_category, "write_mutation");
    }

    #[test]
    fn test_read_only_post_and_fixture_routes() {
        let normalizer = CanonicalNormalizer::new_default(TEST_KEY);

        // Read-only POST /search/code has high_impact == false
        let search = normalizer
            .normalize(&sample_input("POST", "/search/code"))
            .expect("should normalize POST /search/code");
        assert_eq!(search.route_template, "/search/code");
        assert!(!search.high_impact);
        assert_eq!(search.semantic_category, "read_only_query");
        assert_eq!(search.action_class, "POST /search/code");

        // POST /graphql can carry a destructive mutation in its unread body.
        let graphql = normalizer
            .normalize(&sample_input("POST", "/graphql"))
            .expect("should normalize POST /graphql");
        assert_eq!(graphql.route_template, "/graphql");
        assert!(graphql.high_impact);
        assert_eq!(graphql.semantic_category, "opaque_rpc");

        // Unknown routes fail safe: only state-preserving methods are low-impact.
        for (method, expected) in [("GET", false), ("HEAD", false), ("OPTIONS", false),
            ("POST", true), ("PUT", true), ("PATCH", true), ("DELETE", true)] {
            let unknown = normalizer
                .normalize(&sample_input(method, "/v1/unmapped/endpoint"))
                .expect("should normalize unknown route");
            assert_eq!(unknown.route_template, "unknown");
            assert_eq!(unknown.high_impact, expected, "{method} on an unknown route");
        }

        // POST /repos/org/docs-site/issues is write_mutation with high_impact == false
        let post_issue = normalizer
            .normalize(&sample_input("POST", "/repos/org/docs-site/issues"))
            .expect("should normalize POST /repos/org/docs-site/issues");
        assert_eq!(post_issue.route_template, "/repos/{owner}/{repo}/issues");
        assert_eq!(post_issue.resource_id, "org/docs-site");
        assert!(!post_issue.high_impact);
        assert_eq!(post_issue.semantic_category, "write_mutation");

        // POST /repos/org/docs-site/hooks is destructive_admin with high_impact == true
        let post_hook = normalizer
            .normalize(&sample_input("POST", "/repos/org/docs-site/hooks"))
            .expect("should normalize POST /repos/org/docs-site/hooks");
        assert_eq!(post_hook.route_template, "/repos/{owner}/{repo}/hooks");
        assert_eq!(post_hook.resource_id, "org/docs-site");
        assert!(post_hook.high_impact);
        assert_eq!(post_hook.semantic_category, "destructive_admin");

        // Local fixture endpoints GET /clean and GET /sensitive
        let clean = normalizer
            .normalize(&sample_input("GET", "/clean"))
            .expect("should normalize GET /clean");
        assert_eq!(clean.route_template, "/clean");
        assert!(!clean.high_impact);
        assert_eq!(clean.semantic_category, "read_only");

        let sensitive = normalizer
            .normalize(&sample_input("GET", "/sensitive"))
            .expect("should normalize GET /sensitive");
        assert_eq!(sensitive.route_template, "/sensitive");
        assert!(!sensitive.high_impact);
        assert_eq!(sensitive.semantic_category, "read_only");
    }

    #[test]
    fn test_unknown_routes_and_percent_encoded_slash_preservation() {
        let normalizer = CanonicalNormalizer::new_default(TEST_KEY);

        // Unrecognized GET route -> route_template == "unknown", high_impact == false
        let unk_get = normalizer
            .normalize(&sample_input("GET", "/v1/custom/unmapped"))
            .expect("should normalize unknown GET route");
        assert_eq!(unk_get.route_template, "unknown");
        assert_eq!(unk_get.resource_id, "api.github.com:443/v1/custom/unmapped");
        assert_eq!(unk_get.semantic_category, "unknown");
        assert!(!unk_get.high_impact);
        assert_eq!(unk_get.action_class, "GET unknown");
        assert_eq!(
            unk_get.restriction_scope,
            "https://api.github.com:443 GET unknown api.github.com:443/v1/custom/unmapped"
        );

        // Unrecognized DELETE route -> route_template == "unknown", high_impact == true
        let unk_del = normalizer
            .normalize(&sample_input("DELETE", "/v1/custom/unmapped"))
            .expect("should normalize unknown DELETE route");
        assert_eq!(unk_del.route_template, "unknown");
        assert_eq!(unk_del.semantic_category, "unknown");
        assert!(unk_del.high_impact);

        // %2F must NOT be double-decoded into `/`
        let encoded_slash = normalizer
            .normalize(&sample_input("GET", "/repos/org%2Fdocs-site"))
            .expect("should preserve %2F without decoding into path separator");
        assert_eq!(encoded_slash.route_template, "unknown");
        assert_eq!(
            encoded_slash.resource_id,
            "api.github.com:443/repos/org%2Fdocs-site"
        );
    }

    #[test]
    fn test_rejection_of_invalid_inputs() {
        let normalizer = CanonicalNormalizer::new_default(TEST_KEY);

        // Path traversal `..` and `.`
        for bad_path in [
            "/repos/org/../payments-prod",
            "/repos/./org/docs-site",
            "/..",
            "/.",
            "/repos/org/%2e%2e/secret",
            "repos/org/docs-site",
            "/repos/org/docs site",
            "/repos/org/docs\0site",
            "/repos/org/λ",
        ] {
            let err = normalizer
                .normalize(&sample_input("GET", bad_path))
                .expect_err(&format!("expected path '{bad_path}' to be rejected"));
            assert!(matches!(err, RiskGuardError::InvalidArgument(_)));
        }

        // Empty host or non-ASCII / control host
        for bad_host in ["", "api.github.com/evil", "api.github.com\r\n", "exämple.com"] {
            let mut input = sample_input("GET", "/clean");
            input.host = bad_host.to_string();
            let err = normalizer
                .normalize(&input)
                .expect_err(&format!("expected host '{bad_host}' to be rejected"));
            assert!(matches!(err, RiskGuardError::InvalidArgument(_)));
        }

        // Invalid scheme
        for bad_scheme in ["", "ftp", "file", "javascript", "http\n"] {
            let mut input = sample_input("GET", "/clean");
            input.scheme = bad_scheme.to_string();
            let err = normalizer
                .normalize(&input)
                .expect_err(&format!("expected scheme '{bad_scheme}' to be rejected"));
            assert!(matches!(err, RiskGuardError::InvalidArgument(_)));
        }

        // Invalid port 0
        {
            let mut input = sample_input("GET", "/clean");
            input.port = 0;
            let err = normalizer
                .normalize(&input)
                .expect_err("expected port 0 to be rejected");
            assert!(matches!(err, RiskGuardError::InvalidArgument(_)));
        }

        // Invalid method
        for bad_method in ["", "CONNECT", "TRACE", "GET / HTTP/1.1"] {
            let err = normalizer
                .normalize(&sample_input(bad_method, "/clean"))
                .expect_err(&format!("expected method '{bad_method}' to be rejected"));
            assert!(matches!(err, RiskGuardError::InvalidArgument(_)));
        }
    }

    #[test]
    fn test_deterministic_fingerprint_and_keyed_resource_key() {
        let norm_key1 = CanonicalNormalizer::new_default(b"key-one");
        let norm_key2 = CanonicalNormalizer::new_default(b"key-two");

        let mut req_a = sample_input("GET", "/repos/org/docs-site");
        let mut req_b = sample_input("get", "/repos/org/docs-site/");
        // Different request_id and timestamp_ms should still produce identical canonical fingerprint
        req_a.request_id = "req-a".to_string();
        req_b.request_id = "req-b".to_string();
        req_a.timestamp_ms = 100;
        req_b.timestamp_ms = 200;

        let norm_a = norm_key1.normalize(&req_a).unwrap();
        let norm_b = norm_key1.normalize(&req_b).unwrap();
        assert_eq!(norm_a.fingerprint, norm_b.fingerprint);
        assert_eq!(norm_a.fingerprint.len(), 64);
        assert_eq!(norm_a.resource_key, norm_b.resource_key);
        assert_eq!(norm_a.resource_key.len(), 64);

        // Different HMAC key produces a different resource_key for the same resource_id
        let norm_other_key = norm_key2.normalize(&req_a).unwrap();
        assert_eq!(norm_a.resource_id, norm_other_key.resource_id);
        assert_ne!(norm_a.resource_key, norm_other_key.resource_key);

        // Changing binary_path or sandbox_id changes the canonical fingerprint
        let mut req_diff_bin = req_a.clone();
        req_diff_bin.binary_path = Some("/usr/bin/python3".to_string());
        let norm_diff_bin = norm_key1.normalize(&req_diff_bin).unwrap();
        assert_ne!(norm_a.fingerprint, norm_diff_bin.fingerprint);
    }
}

