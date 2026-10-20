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

/// Only callers the gateway authenticates as a person or operator can own a workload.
/// Anonymous, unknown, peer and sandbox callers are refused because they name no durable actor.
pub fn derive_workload(
    workspace: &str,
    kind: &str,
    subject: &str,
) -> Result<DerivedWorkload, RiskGuardError> {
    let workspace = match workspace.trim() {
        "" => "default",
        trimmed => trimmed,
    };
    let subject = subject.trim();
    if !matches!(kind, "operator" | "user") {
        return Err(RiskGuardError::InvalidArgument(format!(
            "cannot derive a workload from a '{kind}' principal; only operator and user callers can own one"
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

    let digest = Sha256::digest(format!("{workspace}\0{kind}\0{subject}").as_bytes());
    let hash = hex::encode(digest);
    let agent_id = format!(
        "{}.{kind}.{}-{}",
        slug(workspace, 24),
        slug(subject, 32),
        &hash[..16]
    );
    Ok(DerivedWorkload {
        agent_id,
        display_name: format!("{workspace} / {kind}:{subject}"),
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
    if trimmed.is_empty() { "x".to_string() } else { trimmed.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(workspace: &str, kind: &str, subject: &str) -> String {
        derive_workload(workspace, kind, subject).unwrap().agent_id
    }

    #[test]
    fn the_same_identity_always_gets_the_same_workload() {
        assert_eq!(id("team-a", "user", "alice"), id("team-a", "user", "alice"));
    }

    #[test]
    fn workspace_and_principal_both_separate_workloads() {
        let base = id("team-a", "user", "alice");
        assert_ne!(base, id("team-b", "user", "alice"), "workspace must scope the workload");
        assert_ne!(base, id("team-a", "user", "bob"));
        assert_ne!(base, id("team-a", "operator", "alice"), "kind must be part of the identity");
    }

    #[test]
    fn subjects_that_slug_alike_do_not_collide() {
        assert_ne!(id("w", "user", "a.b@example.com"), id("w", "user", "a-b@example.com"));
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
                    && derived.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "{derived}"
            );
        }
    }

    #[test]
    fn an_empty_workspace_means_default() {
        assert_eq!(id("", "user", "alice"), id("default", "user", "alice"));
    }

    #[test]
    fn callers_that_name_no_durable_actor_are_refused() {
        for kind in ["anonymous", "unknown", "peer", "sandbox", ""] {
            assert!(derive_workload("default", kind, "x").is_err(), "{kind}");
        }
        assert!(derive_workload("default", "user", "  ").is_err());
        assert!(derive_workload("default", "user", "a\nb").is_err());
    }

    #[test]
    fn display_name_is_readable() {
        let derived = derive_workload("team-a", "user", "alice@example.com").unwrap();
        assert_eq!(derived.display_name, "team-a / user:alice@example.com");
    }
}
