// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! SPIFFE workload identity as a second way to say who is calling.
//!
//! A caller that presents an X.509-SVID over mutual TLS is identified by the SPIFFE ID in its certificate, such as
//! `spiffe://example.org/ns/prod/sa/release-bot`. The TLS handshake proves the certificate chains to the trust bundle the operator
//! configured; this module then checks that the certificate really is an SVID, that its trust domain is one the operator allows,
//! and turns the ID into a Risk Guard workload.
//!
//! The ID is never taken from a request field or header a caller can set. The listener removes any inbound copy of
//! [`PEER_SPIFFE_HEADER`] and writes it only from the verified certificate.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Request, Status};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::{Result, RiskGuardError};
use crate::types::{
    AuthVerifier, AuthenticatedCaller, BaselineProfile, EnforcementMode, EpochRecord, RiskStore,
    SandboxBinding,
};
use crate::workload_identity::derive_workload;

/// Set by the SVID listener from the verified certificate, and read by [`SvidAuthVerifier`]. Any value a client sends is discarded.
pub const PEER_SPIFFE_HEADER: &str = "x-risk-guard-peer-spiffe-id";

const SCHEME: &str = "spiffe://";
const MAX_ID_BYTES: usize = 256;
/// The workspace SPIFFE workloads are scoped to. They have no OpenShell workspace, so this one is fixed.
const SPIFFE_WORKSPACE: &str = "spiffe";

/// A syntactically valid SPIFFE ID: a trust domain and an optional path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId {
    trust_domain: String,
    path: String,
}

impl SpiffeId {
    /// Parse and validate `spiffe://<trust-domain>[/<path>]` as the SPIFFE ID specification defines it. No userinfo, port,
    /// query or fragment; path segments are never empty, `.` or `..`; characters are limited to the ranges the specification allows.
    pub fn parse(uri: &str) -> Result<Self> {
        let invalid = |reason: &str| {
            RiskGuardError::InvalidArgument(format!("not a valid SPIFFE ID ({reason})"))
        };
        if uri.len() > MAX_ID_BYTES {
            return Err(invalid("longer than 256 bytes"));
        }
        let rest = uri
            .strip_prefix(SCHEME)
            .ok_or_else(|| invalid("must start with spiffe://"))?;
        let (trust_domain, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        if trust_domain.is_empty() {
            return Err(invalid("empty trust domain"));
        }
        if !trust_domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
        {
            return Err(invalid(
                "trust domain may contain only lowercase letters, digits, '-', '.' and '_'",
            ));
        }
        if !path.is_empty() {
            for segment in path[1..].split('/') {
                if segment.is_empty() || segment == "." || segment == ".." {
                    return Err(invalid("path segments must not be empty, '.' or '..'"));
                }
                if !segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
                {
                    return Err(invalid(
                        "path segments may contain only letters, digits, '-', '.' and '_'",
                    ));
                }
            }
        }
        Ok(Self {
            trust_domain: trust_domain.to_string(),
            path: path.to_string(),
        })
    }

    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn uri(&self) -> String {
        format!("{SCHEME}{}{}", self.trust_domain, self.path)
    }

    /// The sandbox identifier this SPIFFE ID owns on the SVID listener: readable, and unique because it carries a hash of the
    /// whole ID. A caller may evaluate requests only for this sandbox, never for another caller's.
    #[must_use]
    pub fn sandbox_id(&self) -> String {
        let digest = Sha256::digest(self.uri().as_bytes());
        let hash = hex::encode(digest);
        let readable: String = self
            .path
            .trim_start_matches('/')
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .take(40)
            .collect();
        let readable = readable.trim_matches('-');
        if readable.is_empty() {
            format!("svid-{}", &hash[..16])
        } else {
            format!("svid-{readable}-{}", &hash[..16])
        }
    }
}

/// Which SPIFFE IDs may call. Only the trust domains the operator lists are accepted.
#[derive(Debug, Clone)]
pub struct SvidPolicy {
    trust_domains: BTreeSet<String>,
}

impl SvidPolicy {
    pub fn new<I, S>(trust_domains: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = BTreeSet::new();
        for domain in trust_domains {
            let domain = domain.as_ref().trim();
            // Parsing a bare ID validates the trust domain with the same rules as an ID's.
            let parsed = SpiffeId::parse(&format!("{SCHEME}{domain}"))?;
            set.insert(parsed.trust_domain);
        }
        if set.is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "the SVID listener needs at least one trusted trust domain (--svid-trust-domain)"
                    .into(),
            ));
        }
        Ok(Self { trust_domains: set })
    }

    pub fn authorize(&self, id: &SpiffeId) -> Result<()> {
        if self.trust_domains.contains(id.trust_domain()) {
            Ok(())
        } else {
            Err(RiskGuardError::PermissionDenied(format!(
                "trust domain '{}' is not accepted",
                id.trust_domain()
            )))
        }
    }
}

/// Read the SPIFFE ID from a DER certificate that the TLS handshake has already verified against the trust bundle.
///
/// An X-509 SVID has exactly one URI subject alternative name, which is a SPIFFE ID, and is a leaf: not a certificate
/// authority, and not usable to sign certificates or revocation lists.
pub fn spiffe_id_from_certificate(der: &[u8]) -> Result<SpiffeId> {
    let denied =
        |reason: &str| RiskGuardError::Unauthenticated(format!("not an X.509-SVID ({reason})"));
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| denied("unreadable certificate"))?;

    let mut uris = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    uris.push((*uri).to_string());
                }
            }
        }
    }
    let [uri] = uris.as_slice() else {
        return Err(denied(
            "it must have exactly one URI subject alternative name",
        ));
    };
    let id = SpiffeId::parse(uri).map_err(|_| denied("its URI SAN is not a SPIFFE ID"))?;

    if cert.is_ca() {
        return Err(denied("a leaf certificate must not be a CA"));
    }
    if let Ok(Some(usage)) = cert.key_usage() {
        let flags = usage.value;
        if flags.key_cert_sign() || flags.crl_sign() {
            return Err(denied(
                "a leaf certificate must not sign certificates or CRLs",
            ));
        }
        if !flags.digital_signature() {
            return Err(denied("a leaf certificate must allow digital signatures"));
        }
    }
    Ok(id)
}

/// Replace whatever the client sent with the verified identity, or refuse the call. Runs for every request on the SVID listener.
pub fn attach_peer_identity(
    policy: &SvidPolicy,
    mut request: Request<()>,
) -> std::result::Result<Request<()>, Status> {
    request.metadata_mut().remove(PEER_SPIFFE_HEADER);
    let certificates = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("a client certificate (X.509-SVID) is required"))?;
    let leaf = certificates
        .first()
        .ok_or_else(|| Status::unauthenticated("a client certificate (X.509-SVID) is required"))?;
    let id = spiffe_id_from_certificate(leaf.as_ref())
        .map_err(|error| Status::unauthenticated(error.to_string()))?;
    policy
        .authorize(&id)
        .map_err(|error| Status::permission_denied(error.to_string()))?;
    let value = MetadataValue::try_from(id.uri())
        .map_err(|_| Status::unauthenticated("the SPIFFE ID is not a valid header value"))?;
    request.metadata_mut().insert(PEER_SPIFFE_HEADER, value);
    Ok(request)
}

/// Authenticates calls on the SVID listener. The caller is the SPIFFE ID the listener verified; it may evaluate requests for
/// the one sandbox its ID owns, which is enrolled (workload, epoch and run) the first time it appears.
pub struct SvidAuthVerifier {
    policy: SvidPolicy,
    store: Arc<dyn RiskStore>,
    gateway_id: String,
    default_task_profile: String,
    enrolled: Mutex<HashSet<String>>,
}

impl SvidAuthVerifier {
    pub fn new(
        policy: SvidPolicy,
        store: Arc<dyn RiskStore>,
        gateway_id: impl Into<String>,
        default_task_profile: impl Into<String>,
    ) -> Self {
        Self {
            policy,
            store,
            gateway_id: gateway_id.into(),
            default_task_profile: default_task_profile.into(),
            enrolled: Mutex::new(HashSet::new()),
        }
    }

    fn peer(&self, metadata: &MetadataMap) -> Result<SpiffeId> {
        let value = metadata
            .get(PEER_SPIFFE_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                RiskGuardError::Unauthenticated("no verified SPIFFE ID on the call".into())
            })?;
        let id = SpiffeId::parse(value)?;
        self.policy.authorize(&id)?;
        Ok(id)
    }

    /// Give a SPIFFE ID's sandbox an active epoch bound to a workload derived from the ID, once.
    fn enroll(&self, id: &SpiffeId, sandbox_id: &str, now_ms: i64) -> Result<()> {
        if self
            .enrolled
            .lock()
            .map_err(|_| RiskGuardError::Internal("enrollment lock poisoned".into()))?
            .contains(sandbox_id)
        {
            return Ok(());
        }
        if self.store.get_active_epoch(sandbox_id)?.is_none() {
            let baseline: BaselineProfile = self
                .store
                .get_baseline(&self.default_task_profile)?
                .ok_or_else(|| {
                    RiskGuardError::InvalidArgument(format!(
                        "baseline '{}' is not provisioned; use baseline-import",
                        self.default_task_profile
                    ))
                })?;
            self.store.upsert_epoch(&EpochRecord {
                epoch_id: format!("ep_{sandbox_id}_1"),
                gateway_id: self.gateway_id.clone(),
                sandbox_id: sandbox_id.to_string(),
                task_profile: baseline.task_profile.clone(),
                baseline_hash: crate::detector::compute_baseline_hash(&baseline),
                mode: EnforcementMode::Enforce,
                active: true,
                next_sequence: 1,
                created_at_ms: now_ms,
                credentialed_endpoints: Default::default(),
                active_policy_hash: None,
            })?;
        }
        let uri = id.uri();
        let derived = derive_workload(SPIFFE_WORKSPACE, "spiffe", "workload", &uri, false)?;
        let run_id = format!("run-{sandbox_id}");
        self.store.auto_bind_sandbox_epoch(&SandboxBinding {
            sandbox_id,
            gateway_id: &self.gateway_id,
            agent_id: &derived.agent_id,
            agent_revision: "svid",
            run_id: &run_id,
            auto_register: true,
            display_name: Some(&derived.display_name),
            workspace: SPIFFE_WORKSPACE,
            claim_workspace: true,
        })?;
        self.enrolled
            .lock()
            .map_err(|_| RiskGuardError::Internal("enrollment lock poisoned".into()))?
            .insert(sandbox_id.to_string());
        Ok(())
    }
}

impl AuthVerifier for SvidAuthVerifier {
    fn verify_supervisor_call(
        &self,
        metadata: &MetadataMap,
        expected_sandbox_id: &str,
    ) -> Result<AuthenticatedCaller> {
        let id = self.peer(metadata)?;
        let sandbox_id = id.sandbox_id();
        if expected_sandbox_id != sandbox_id {
            return Err(RiskGuardError::PermissionDenied(format!(
                "{} may evaluate requests only for its own sandbox '{sandbox_id}', not '{expected_sandbox_id}'",
                id.uri()
            )));
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
            });
        self.enroll(&id, &sandbox_id, now_ms)?;
        Ok(AuthenticatedCaller::Supervisor {
            gateway_id: self.gateway_id.clone(),
            sandbox_id,
            jti: format!("svid:{}", id.uri()),
            exp: i64::MAX,
        })
    }

    fn verify_gateway_call(&self, _metadata: &MetadataMap) -> Result<AuthenticatedCaller> {
        Err(RiskGuardError::PermissionDenied(
            "the SVID listener never accepts gateway calls".into(),
        ))
    }
}

/// Serve the middleware on a second, mutual-TLS listener that identifies callers by their X.509-SVID.
///
/// The listener trusts only the certificate authorities in `bundle` for client certificates. SPIRE rotates its signing keys, so the
/// bundle file is re-read every `BUNDLE_POLL` and the listener restarts with the new roots when it changes (open connections are
/// closed; the caller reconnects). `shutdown` ends it for good.
pub async fn serve_svid_listener<F>(
    addr: std::net::SocketAddr,
    server_tls: tonic::transport::ServerTlsConfig,
    bundle: std::path::PathBuf,
    policy: SvidPolicy,
    service: crate::middleware_service::RiskGuardMiddlewareService,
    shutdown: impl Fn() -> F,
) -> Result<()>
where
    F: std::future::Future<Output = ()>,
{
    const BUNDLE_POLL: std::time::Duration = std::time::Duration::from_secs(30);
    let policy = Arc::new(policy);
    loop {
        let pem = std::fs::read(&bundle).map_err(|error| {
            RiskGuardError::InvalidArgument(format!(
                "cannot read the SVID trust bundle '{}': {error}",
                bundle.display()
            ))
        })?;
        let tls = server_tls
            .clone()
            .client_ca_root(tonic::transport::Certificate::from_pem(&pem))
            .client_auth_optional(false);
        let for_calls = Arc::clone(&policy);
        let guarded = tonic::service::interceptor::InterceptedService::new(
            service.clone().into_server(),
            move |request: Request<()>| attach_peer_identity(&for_calls, request),
        );
        let watched = bundle.clone();
        let changed = async move {
            loop {
                tokio::time::sleep(BUNDLE_POLL).await;
                if std::fs::read(&watched).ok().as_deref() != Some(pem.as_slice()) {
                    return;
                }
            }
        };
        tracing::info!(%addr, bundle = %bundle.display(), "starting the SVID (SPIFFE mutual-TLS) listener");
        let stopped_for_good = std::sync::atomic::AtomicBool::new(false);
        let wait = async {
            tokio::select! {
                () = changed => tracing::info!("the SVID trust bundle changed; reloading the listener"),
                () = shutdown() => stopped_for_good.store(true, std::sync::atomic::Ordering::SeqCst),
            }
        };
        tonic::transport::Server::builder()
            .tls_config(tls)
            .map_err(|error| {
                RiskGuardError::InvalidArgument(format!("invalid SVID listener TLS: {error}"))
            })?
            .add_service(guarded)
            .serve_with_shutdown(addr, wait)
            .await
            .map_err(|error| RiskGuardError::Internal(format!("SVID listener error: {error}")))?;
        if stopped_for_good.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_ids_parse_and_round_trip() {
        for uri in [
            "spiffe://example.org",
            "spiffe://example.org/ns/prod/sa/release-bot",
            "spiffe://a.b-c_d/x.y/z_1",
        ] {
            assert_eq!(SpiffeId::parse(uri).unwrap().uri(), uri);
        }
    }

    #[test]
    fn malformed_ids_are_refused() {
        for uri in [
            "",
            "https://example.org/x",
            "spiffe:/example.org/x",
            "spiffe:///x",
            "spiffe://Example.org/x",
            "spiffe://example.org:8080/x",
            "spiffe://user@example.org/x",
            "spiffe://example.org/x?y=1",
            "spiffe://example.org/x#f",
            "spiffe://example.org/",
            "spiffe://example.org//x",
            "spiffe://example.org/x/",
            "spiffe://example.org/./x",
            "spiffe://example.org/../x",
            "spiffe://example.org/x y",
            "spiffe://example.org/x%2fy",
            "spiffe://exa mple.org",
        ] {
            assert!(SpiffeId::parse(uri).is_err(), "{uri:?} must be refused");
        }
        let long = format!("spiffe://example.org/{}", "a".repeat(300));
        assert!(SpiffeId::parse(&long).is_err());
    }

    #[test]
    fn a_sandbox_id_is_stable_distinct_and_a_valid_identifier() {
        let a = SpiffeId::parse("spiffe://example.org/ns/prod/sa/bot").unwrap();
        let b = SpiffeId::parse("spiffe://example.org/ns/prod/sa/bot2").unwrap();
        let other_domain = SpiffeId::parse("spiffe://other.org/ns/prod/sa/bot").unwrap();
        assert_eq!(a.sandbox_id(), a.sandbox_id());
        assert_ne!(a.sandbox_id(), b.sandbox_id());
        assert_ne!(a.sandbox_id(), other_domain.sandbox_id());
        for id in [
            &a,
            &b,
            &other_domain,
            &SpiffeId::parse("spiffe://example.org").unwrap(),
        ] {
            let sandbox = id.sandbox_id();
            assert!(
                sandbox.len() <= 128
                    && sandbox
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "{sandbox}"
            );
        }
    }

    #[test]
    fn only_listed_trust_domains_are_accepted() {
        let policy = SvidPolicy::new(["example.org"]).unwrap();
        assert!(
            policy
                .authorize(&SpiffeId::parse("spiffe://example.org/x").unwrap())
                .is_ok()
        );
        assert!(
            policy
                .authorize(&SpiffeId::parse("spiffe://evil.org/x").unwrap())
                .is_err()
        );
        assert!(SvidPolicy::new(Vec::<String>::new()).is_err());
        assert!(SvidPolicy::new(["Not A Domain"]).is_err());
    }
}
