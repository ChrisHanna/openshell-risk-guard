// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Derive a workload ID from the identity OpenShell authenticates at sandbox creation.
//!
//! In principal mode the workload is `(workspace, principal)`: both parts come from the
//! gateway, not from a label anyone typed, so nobody can forge or squat an ID, and the same
//! authenticated creator keeps one history across all of its sandboxes. The derived ID is a
//! readable slug plus a hash of the exact inputs, so distinct identities never collide even
//! when their slugs match.

use sha2::{Digest, Sha256};

use crate::error::RiskGuardError;

const MAX_SUBJECT_BYTES: usize = 256;
const MAX_WORKSPACE_BYTES: usize = 128;

/// A workload ID that is safe to store, and a human-readable name for the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedWorkload {
    pub agent_id: String,
    pub display_name: String,
}

/// Identity providers OpenShell reports for callers it actually authenticated.
const AUTHENTICATED_PROVIDERS: [&str; 4] = ["oidc", "cloudflare_access", "mtls", "spiffe"];
/// OpenShell's explicit unauthenticated local-development user. It proves nothing about who
/// is calling, so it only owns a workload when the operator opts in.
const LOCAL_DEV_PROVIDER: &str = "local_dev";

/// Callers the gateway authenticates as a person or operator can own a workload, and so can a workload that proved a SPIFFE ID.
/// Anonymous, unknown, peer and sandbox callers are refused because they name no durable actor.
///
/// `provider` is the identity provider the gateway reports for the caller. A subject is only
/// unique within its provider, so it is part of the identity and of the hash.
pub fn derive_workload(
    workspace: &str,
    provider: &str,
    kind: &str,
    subject: &str,
    allow_local_dev: bool,
) -> Result<DerivedWorkload, RiskGuardError> {
    let workspace = workspace.trim();
    let subject = subject.trim();
    if workspace.is_empty() {
        return Err(RiskGuardError::InvalidArgument(
            "the sandbox did not report its workspace, so no workload can be derived".into(),
        ));
    }
    if !matches!(kind, "operator" | "user" | "workload") {
        return Err(RiskGuardError::InvalidArgument(format!(
            "cannot derive a workload from a '{kind}' principal; only operator and user callers can own one"
        )));
    }
    let provider_ok = match (kind, provider) {
        // A client-certificate caller is a `user` unless its certificate carries the operator
        // role, in which case the gateway reports `operator`; both come from the `mtls` provider.
        ("user", "oidc" | "cloudflare_access" | "mtls") | ("operator", "mtls") => true,
        // A SPIFFE workload is identified by the SPIFFE ID in its verified X.509-SVID, and by nothing else.
        ("workload", "spiffe") => subject.starts_with("spiffe://"),
        ("user", LOCAL_DEV_PROVIDER) => allow_local_dev,
        _ => false,
    };
    if !provider_ok {
        let reason = if provider == LOCAL_DEV_PROVIDER {
            "the caller is OpenShell's unauthenticated local-development user; start serve with --allow-local-dev-principal to bind it, for local testing only".to_string()
        } else if AUTHENTICATED_PROVIDERS.contains(&provider) {
            format!("a '{kind}' principal cannot come from the '{provider}' identity provider")
        } else {
            "the principal reports no recognized identity provider".to_string()
        };
        return Err(RiskGuardError::InvalidArgument(format!(
            "cannot derive a workload: {reason}"
        )));
    }
    if subject.is_empty()
        || subject.len() > MAX_SUBJECT_BYTES
        || subject.chars().any(char::is_control)
    {
        return Err(RiskGuardError::InvalidArgument(
            "the principal subject must be 1..256 bytes without control characters".into(),
        ));
    }
    if workspace.len() > MAX_WORKSPACE_BYTES || workspace.chars().any(char::is_control) {
        return Err(RiskGuardError::InvalidArgument(
            "the workspace must be 1..128 bytes without control characters".into(),
        ));
    }

    let digest = Sha256::digest(format!("{workspace}\0{provider}\0{kind}\0{subject}").as_bytes());
    let hash = hex::encode(digest);
    let agent_id = format!(
        "{}.{kind}.{}-{}",
        slug(workspace, 24),
        slug(subject, 32),
        &hash[..16]
    );
    Ok(DerivedWorkload {
        agent_id,
        display_name: format!("{workspace} / {kind}:{subject} ({provider})"),
    })
}

/// Lowercase ASCII letters and digits, with every other run collapsed into one '-'.
fn slug(value: &str, max_len: usize) -> String {
    let mut out = String::new();
    for c in value.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= max_len {
            break;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "x".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(workspace: &str, kind: &str, subject: &str) -> String {
        let provider = if kind == "operator" { "mtls" } else { "oidc" };
        derive_workload(workspace, provider, kind, subject, false)
            .unwrap()
            .agent_id
    }

    #[test]
    fn the_same_identity_always_gets_the_same_workload() {
        assert_eq!(id("team-a", "user", "alice"), id("team-a", "user", "alice"));
    }

    #[test]
    fn workspace_and_principal_both_separate_workloads() {
        let base = id("team-a", "user", "alice");
        assert_ne!(
            base,
            id("team-b", "user", "alice"),
            "workspace must scope the workload"
        );
        assert_ne!(base, id("team-a", "user", "bob"));
        assert_ne!(
            base,
            id("team-a", "operator", "alice"),
            "kind must be part of the identity"
        );
    }

    #[test]
    fn the_identity_provider_is_part_of_the_identity() {
        let oidc = derive_workload("w", "oidc", "user", "alice", false)
            .unwrap()
            .agent_id;
        let cloudflare = derive_workload("w", "cloudflare_access", "user", "alice", false)
            .unwrap()
            .agent_id;
        assert_ne!(
            oidc, cloudflare,
            "the same subject from two providers is two people"
        );
    }

    #[test]
    fn subjects_that_slug_alike_do_not_collide() {
        assert_ne!(
            id("w", "user", "a.b@example.com"),
            id("w", "user", "a-b@example.com")
        );
        assert_ne!(id("w", "user", "auth0|123"), id("w", "user", "auth0-123"));
    }

    #[test]
    fn derived_ids_are_valid_stored_identifiers() {
        for (workspace, subject) in [
            ("default", "alice@example.com"),
            ("Team A/Prod", "auth0|abc 123"),
            ("w", "\u{e9}l\u{e8}ve"),
            ("w", "!!!"),
        ] {
            let derived = id(workspace, "user", subject);
            assert!(
                !derived.is_empty()
                    && derived.len() <= 128
                    && derived
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "{derived}"
            );
        }
    }

    #[test]
    fn a_missing_workspace_is_refused_not_assumed() {
        for workspace in ["", "  "] {
            assert!(derive_workload(workspace, "oidc", "user", "alice", false).is_err());
        }
    }

    #[test]
    fn callers_that_name_no_durable_actor_are_refused() {
        for kind in ["anonymous", "unknown", "peer", "sandbox", ""] {
            assert!(
                derive_workload("default", "oidc", kind, "x", false).is_err(),
                "{kind}"
            );
        }
        assert!(derive_workload("default", "oidc", "user", "  ", false).is_err());
        assert!(derive_workload("default", "oidc", "user", "a\nb", false).is_err());
    }

    #[test]
    fn unrecognized_or_mismatched_providers_are_refused() {
        assert!(derive_workload("w", "", "user", "alice", false).is_err());
        assert!(derive_workload("w", "saml", "user", "alice", false).is_err());
        assert!(derive_workload("w", "oidc", "operator", "ops", false).is_err());
    }

    #[test]
    fn a_client_certificate_user_and_operator_both_own_a_workload() {
        // Observed on a real gateway: whoami reports provider=mtls, role=openshell-user.
        let user = derive_workload("default", "mtls", "user", "openshell-client", false).unwrap();
        let operator =
            derive_workload("default", "mtls", "operator", "openshell-client", false).unwrap();
        assert_ne!(user.agent_id, operator.agent_id, "kind keeps them apart");
    }

    #[test]
    fn the_unauthenticated_local_dev_user_needs_an_explicit_opt_in() {
        let refused = derive_workload(
            "default",
            "local_dev",
            "user",
            "unauthenticated-local-dev",
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains("--allow-local-dev-principal"), "{refused}");
        assert!(
            derive_workload(
                "default",
                "local_dev",
                "user",
                "unauthenticated-local-dev",
                true
            )
            .is_ok()
        );
        assert!(derive_workload("default", "local_dev", "operator", "x", true).is_err());
    }

    #[test]
    fn a_spiffe_workload_owns_a_workload_only_through_a_spiffe_id() {
        let a = derive_workload(
            "spiffe",
            "spiffe",
            "workload",
            "spiffe://example.org/ns/p/sa/a",
            false,
        )
        .unwrap();
        let b = derive_workload(
            "spiffe",
            "spiffe",
            "workload",
            "spiffe://example.org/ns/p/sa/b",
            false,
        )
        .unwrap();
        assert_ne!(a.agent_id, b.agent_id);
        assert_eq!(
            a.agent_id,
            derive_workload(
                "spiffe",
                "spiffe",
                "workload",
                "spiffe://example.org/ns/p/sa/a",
                false
            )
            .unwrap()
            .agent_id
        );
        // The same string from another provider, or a non-SPIFFE subject, never becomes a SPIFFE workload.
        assert!(
            derive_workload(
                "spiffe",
                "oidc",
                "workload",
                "spiffe://example.org/x",
                false
            )
            .is_err()
        );
        assert!(derive_workload("spiffe", "spiffe", "workload", "alice", false).is_err());
        assert!(
            derive_workload("spiffe", "spiffe", "user", "spiffe://example.org/x", false).is_err()
        );
    }

    #[test]
    fn display_name_is_readable() {
        let derived =
            derive_workload("team-a", "oidc", "user", "alice@example.com", false).unwrap();
        assert_eq!(
            derived.display_name,
            "team-a / user:alice@example.com (oidc)"
        );
    }
}
