// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Inbound `openshell-ext+jwt` authentication verifier (Wave 1 - `t01-auth-verifier`).

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
pub use openshell_extension_core::{
    EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims, MAX_EXTENSION_TOKEN_TTL,
};
use rcgen::{KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};
use tonic::metadata::{AsciiMetadataValue, MetadataMap};
use uuid::Uuid;

use crate::error::{Result, RiskGuardError};
use crate::types::{AuthVerifier, AuthenticatedCaller};

const GATEWAY_ISSUER_PREFIX: &str = "openshell-gateway:";
const SPIFFE_SANDBOX_PREFIX: &str = "spiffe://openshell/sandbox/";
/// Default clock-skew tolerance in seconds for production `openshell-ext+jwt` verification.
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 5;

pub(crate) fn install_crypto_provider() {
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Verifies inbound `openshell-ext+jwt` Ed25519-signed bearer tokens for both
/// gateway interceptor calls and supervisor middleware calls.
#[derive(Clone)]
pub struct JwtAuthVerifier {
    pub expected_gateway_id: String,
    pub expected_audience: String,
    pub decoding_key: Option<DecodingKey>,
    pub allow_insecure_local_test: bool,
    pub clock_skew_secs: u64,
}

impl fmt::Debug for JwtAuthVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtAuthVerifier")
            .field("expected_gateway_id", &self.expected_gateway_id)
            .field("expected_audience", &self.expected_audience)
            .field("has_decoding_key", &self.decoding_key.is_some())
            .field("allow_insecure_local_test", &self.allow_insecure_local_test)
            .field("clock_skew_secs", &self.clock_skew_secs)
            .finish()
    }
}

impl JwtAuthVerifier {
    /// Construct a strict `EdDSA` (`Ed25519`) verifier from a PEM-encoded public key.
    pub fn from_ed25519_pem(
        expected_gateway_id: impl Into<String>,
        expected_audience: impl Into<String>,
        public_key_pem: &[u8],
    ) -> Result<Self> {
        install_crypto_provider();

        let expected_gateway_id = expected_gateway_id.into();
        let expected_audience = expected_audience.into();

        if expected_gateway_id.trim().is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "expected_gateway_id must not be empty".to_string(),
            ));
        }
        if expected_audience.trim().is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "expected_audience must not be empty".to_string(),
            ));
        }
        if public_key_pem.is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "public_key_pem must not be empty".to_string(),
            ));
        }

        let decoding_key = DecodingKey::from_ed_pem(public_key_pem).map_err(|err| {
            RiskGuardError::InvalidArgument(format!("invalid Ed25519 public key PEM: {err}"))
        })?;

        Ok(Self {
            expected_gateway_id,
            expected_audience,
            decoding_key: Some(decoding_key),
            allow_insecure_local_test: false,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
        })
    }

    /// Construct a local-test verifier that permits unauthenticated calls when the
    /// `authorization` metadata header is absent.
    #[must_use]
    pub fn insecure_for_local_test(
        expected_gateway_id: impl Into<String>,
        expected_audience: impl Into<String>,
    ) -> Self {
        install_crypto_provider();
        Self {
            expected_gateway_id: expected_gateway_id.into(),
            expected_audience: expected_audience.into(),
            decoding_key: None,
            allow_insecure_local_test: true,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
        }
    }

    /// Configure maximum allowed clock skew in seconds.
    #[must_use]
    pub const fn with_clock_skew_secs(mut self, clock_skew_secs: u64) -> Self {
        self.clock_skew_secs = clock_skew_secs;
        self
    }

    /// Configure whether missing `authorization` headers are allowed for local testing.
    #[must_use]
    pub const fn with_allow_insecure_local_test(mut self, allow: bool) -> Self {
        self.allow_insecure_local_test = allow;
        self
    }

    /// A missing token is accepted only by the explicit local-test verifier that has no
    /// gateway key. Once a public key is configured, every call must carry a valid JWT,
    /// even if the local-test flag is also set; the flag cannot downgrade authentication.
    fn unauthenticated_fallback_allowed(&self) -> bool {
        self.allow_insecure_local_test && self.decoding_key.is_none()
    }

    /// Return the expected `iss` claim (`openshell-gateway:<expected_gateway_id>`).
    #[must_use]
    pub fn expected_issuer(&self) -> String {
        format!("{GATEWAY_ISSUER_PREFIX}{}", self.expected_gateway_id)
    }

    fn extract_bearer_token<'a>(metadata: &'a MetadataMap) -> Result<Option<&'a str>> {
        let Some(raw_value) = metadata.get("authorization") else {
            return Ok(None);
        };
        let header_str = raw_value.to_str().map_err(|_| {
            RiskGuardError::Unauthenticated(
                "authorization metadata header is not valid ASCII".to_string(),
            )
        })?;
        let token = openshell_core::auth::strip_bearer_scheme(header_str).ok_or_else(|| {
            RiskGuardError::Unauthenticated(
                "authorization metadata header must use Bearer scheme".to_string(),
            )
        })?;
        if token.is_empty() || token.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(RiskGuardError::Unauthenticated(
                "bearer token is empty or contains whitespace".to_string(),
            ));
        }
        Ok(Some(token))
    }

    fn verify_token(&self, token: &str, now: i64) -> Result<ExtensionJwtClaims> {
        install_crypto_provider();

        let decoding_key = self.decoding_key.as_ref().ok_or_else(|| {
            RiskGuardError::Unauthenticated(
                "no Ed25519 decoding key configured on verifier".to_string(),
            )
        })?;

        let header = decode_header(token).map_err(|err| {
            RiskGuardError::Unauthenticated(format!("malformed JWT header: {err}"))
        })?;

        if header.alg != Algorithm::EdDSA {
            return Err(RiskGuardError::Unauthenticated(format!(
                "unsupported JWT algorithm {:?}; expected EdDSA",
                header.alg
            )));
        }

        if header.typ.as_deref() != Some(EXTENSION_JWT_TYP) {
            return Err(RiskGuardError::Unauthenticated(format!(
                "invalid JWT typ {:?}; expected {:?}",
                header.typ, EXTENSION_JWT_TYP
            )));
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp", "jti"]);

        let token_data = decode::<ExtensionJwtClaims>(token, decoding_key, &validation).map_err(
            |err| RiskGuardError::Unauthenticated(format!("JWT verification failed: {err}")),
        )?;
        let claims = token_data.claims;

        let expected_issuer = self.expected_issuer();
        if claims.iss != expected_issuer {
            return Err(RiskGuardError::Unauthenticated(format!(
                "JWT issuer '{}' does not match expected '{expected_issuer}'",
                claims.iss
            )));
        }

        if claims.aud != self.expected_audience {
            return Err(RiskGuardError::Unauthenticated(format!(
                "JWT audience '{}' does not match expected '{}'",
                claims.aud, self.expected_audience
            )));
        }

        if claims.sub.trim().is_empty() {
            return Err(RiskGuardError::Unauthenticated(
                "JWT sub claim must not be empty".to_string(),
            ));
        }

        if claims.jti.trim().is_empty() {
            return Err(RiskGuardError::Unauthenticated(
                "JWT jti claim must not be empty".to_string(),
            ));
        }

        if claims.iat > claims.exp {
            return Err(RiskGuardError::Unauthenticated(
                "JWT iat must be less than or equal to exp".to_string(),
            ));
        }

        if claims.iat > now.saturating_add(i64::try_from(self.clock_skew_secs).unwrap_or(0)) {
            return Err(RiskGuardError::Unauthenticated(
                "JWT iat is in the future".to_string(),
            ));
        }

        let max_ttl_secs = i64::try_from(MAX_EXTENSION_TOKEN_TTL.as_secs()).unwrap_or(3_600);
        let ttl = claims.exp.saturating_sub(claims.iat);
        if ttl > max_ttl_secs {
            return Err(RiskGuardError::Unauthenticated(format!(
                "JWT TTL ({ttl}s) exceeds maximum allowed ({max_ttl_secs}s)"
            )));
        }

        let skew = i64::try_from(self.clock_skew_secs).unwrap_or(0);
        if claims.exp.saturating_add(skew) <= now {
            return Err(RiskGuardError::Unauthenticated(
                "JWT token has expired".to_string(),
            ));
        }

        Ok(claims)
    }
}

impl AuthVerifier for JwtAuthVerifier {
    fn verify_supervisor_call(
        &self,
        metadata: &MetadataMap,
        expected_sandbox_id: &str,
    ) -> Result<AuthenticatedCaller> {
        let Some(token) = Self::extract_bearer_token(metadata)? else {
            if self.unauthenticated_fallback_allowed() {
                if expected_sandbox_id.trim().is_empty() {
                    return Err(RiskGuardError::PermissionDenied(
                        "expected_sandbox_id must not be empty".to_string(),
                    ));
                }
                return Ok(AuthenticatedCaller::Supervisor {
                    gateway_id: self.expected_gateway_id.clone(),
                    sandbox_id: expected_sandbox_id.to_string(),
                    jti: "insecure-local-test".to_string(),
                    exp: i64::MAX,
                });
            }
            return Err(RiskGuardError::Unauthenticated(
                "missing authorization metadata header".to_string(),
            ));
        };

        let claims = self.verify_token(token, now_unix_secs())?;

        if claims.caller_kind != ExtensionCallerKind::Supervisor {
            return Err(RiskGuardError::PermissionDenied(format!(
                "supervisor call requires caller_kind=supervisor, got {:?}",
                claims.caller_kind
            )));
        }

        if expected_sandbox_id.trim().is_empty() {
            return Err(RiskGuardError::PermissionDenied(
                "expected_sandbox_id must not be empty".to_string(),
            ));
        }

        let Some(token_sandbox_id) = claims.sandbox_id else {
            return Err(RiskGuardError::PermissionDenied(
                "supervisor token is missing sandbox_id claim".to_string(),
            ));
        };

        if token_sandbox_id != expected_sandbox_id {
            return Err(RiskGuardError::PermissionDenied(format!(
                "token sandbox_id '{token_sandbox_id}' does not match request context sandbox_id '{expected_sandbox_id}'"
            )));
        }

        Ok(AuthenticatedCaller::Supervisor {
            gateway_id: self.expected_gateway_id.clone(),
            sandbox_id: token_sandbox_id,
            jti: claims.jti,
            exp: claims.exp,
        })
    }

    fn verify_gateway_call(&self, metadata: &MetadataMap) -> Result<AuthenticatedCaller> {
        let Some(token) = Self::extract_bearer_token(metadata)? else {
            if self.unauthenticated_fallback_allowed() {
                return Ok(AuthenticatedCaller::Gateway {
                    gateway_id: self.expected_gateway_id.clone(),
                    jti: "insecure-local-test".to_string(),
                    exp: i64::MAX,
                });
            }
            return Err(RiskGuardError::Unauthenticated(
                "missing authorization metadata header".to_string(),
            ));
        };

        let claims = self.verify_token(token, now_unix_secs())?;

        if claims.caller_kind != ExtensionCallerKind::Gateway {
            return Err(RiskGuardError::PermissionDenied(format!(
                "gateway call requires caller_kind=gateway, got {:?}",
                claims.caller_kind
            )));
        }

        if claims.sandbox_id.is_some() {
            return Err(RiskGuardError::PermissionDenied(
                "gateway token must not include a sandbox_id claim".to_string(),
            ));
        }

        Ok(AuthenticatedCaller::Gateway {
            gateway_id: self.expected_gateway_id.clone(),
            jti: claims.jti,
            exp: claims.exp,
        })
    }
}

/// Test and demo helper that generates an Ed25519 keypair and mints real
/// `openshell-ext+jwt` bearer tokens for `Gateway` and `Supervisor` callers.
#[derive(Clone)]
pub struct JwtTestIssuer {
    pub gateway_id: String,
    pub kid: String,
    pub signing_key_pem: String,
    pub public_key_pem: String,
    encoding_key: EncodingKey,
}

impl fmt::Debug for JwtTestIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtTestIssuer")
            .field("gateway_id", &self.gateway_id)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl JwtTestIssuer {
    /// Generate a fresh Ed25519 keypair for `gateway_id`.
    pub fn generate(gateway_id: impl Into<String>) -> Result<Self> {
        install_crypto_provider();

        let gateway_id = gateway_id.into();
        if gateway_id.trim().is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "gateway_id must not be empty".to_string(),
            ));
        }

        let keypair = KeyPair::generate_for(&PKCS_ED25519).map_err(|err| {
            RiskGuardError::Internal(format!("failed to generate Ed25519 keypair: {err}"))
        })?;
        let signing_key_pem = keypair.serialize_pem();
        let public_key_pem = keypair.public_key_pem();
        let digest = Sha256::digest(keypair.public_key_der());
        let kid = hex::encode(&digest[..16]);

        let encoding_key = EncodingKey::from_ed_pem(signing_key_pem.as_bytes()).map_err(|err| {
            RiskGuardError::Internal(format!("failed to parse generated Ed25519 key: {err}"))
        })?;

        Ok(Self {
            gateway_id,
            kid,
            signing_key_pem,
            public_key_pem,
            encoding_key,
        })
    }

    /// Infallible convenience constructor for unit and integration tests.
    #[must_use]
    pub fn new(gateway_id: impl Into<String>) -> Self {
        Self::generate(gateway_id).expect("failed to generate Ed25519 test issuer")
    }

    /// Construct from existing Ed25519 private and public key PEM material.
    pub fn from_ed25519_pem(
        gateway_id: impl Into<String>,
        signing_key_pem: &[u8],
        public_key_pem: &[u8],
        kid: impl Into<String>,
    ) -> Result<Self> {
        install_crypto_provider();

        let gateway_id = gateway_id.into();
        if gateway_id.trim().is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "gateway_id must not be empty".to_string(),
            ));
        }
        let signing_key_str = std::str::from_utf8(signing_key_pem).map_err(|err| {
            RiskGuardError::InvalidArgument(format!("signing_key_pem is not UTF-8: {err}"))
        })?;
        let public_key_str = std::str::from_utf8(public_key_pem).map_err(|err| {
            RiskGuardError::InvalidArgument(format!("public_key_pem is not UTF-8: {err}"))
        })?;
        let encoding_key = EncodingKey::from_ed_pem(signing_key_pem).map_err(|err| {
            RiskGuardError::InvalidArgument(format!("invalid Ed25519 signing key PEM: {err}"))
        })?;

        Ok(Self {
            gateway_id,
            kid: kid.into(),
            signing_key_pem: signing_key_str.to_string(),
            public_key_pem: public_key_str.to_string(),
            encoding_key,
        })
    }

    /// Return the gateway ID.
    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    /// Return the formatted issuer string (`openshell-gateway:<gateway_id>`).
    #[must_use]
    pub fn issuer(&self) -> String {
        format!("{GATEWAY_ISSUER_PREFIX}{}", self.gateway_id)
    }

    /// Return the key ID (`kid`).
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Return the Ed25519 public key PEM bytes.
    #[must_use]
    pub fn public_key_pem(&self) -> &[u8] {
        self.public_key_pem.as_bytes()
    }

    /// Return the Ed25519 private signing key PEM bytes.
    #[must_use]
    pub fn signing_key_pem(&self) -> &[u8] {
        self.signing_key_pem.as_bytes()
    }

    /// Build a matching [`JwtAuthVerifier`] configured with this issuer's public key.
    pub fn verifier(&self, expected_audience: impl Into<String>) -> Result<JwtAuthVerifier> {
        JwtAuthVerifier::from_ed25519_pem(
            &self.gateway_id,
            expected_audience,
            self.public_key_pem.as_bytes(),
        )
    }

    /// Mint a valid `openshell-ext+jwt` token for `ExtensionCallerKind::Supervisor`.
    pub fn mint_supervisor_token(
        &self,
        audience: &str,
        sandbox_id: &str,
        ttl_secs: u64,
    ) -> Result<String> {
        self.mint_token(
            audience,
            ExtensionCallerKind::Supervisor,
            Some(sandbox_id),
            Duration::from_secs(ttl_secs),
        )
    }

    /// Mint a valid `openshell-ext+jwt` token for `ExtensionCallerKind::Gateway`.
    pub fn mint_gateway_token(&self, audience: &str, ttl_secs: u64) -> Result<String> {
        self.mint_token(
            audience,
            ExtensionCallerKind::Gateway,
            None,
            Duration::from_secs(ttl_secs),
        )
    }

    /// Mint an `openshell-ext+jwt` token for either `Gateway` or `Supervisor`.
    pub fn mint_token(
        &self,
        audience: &str,
        caller_kind: ExtensionCallerKind,
        sandbox_id: Option<&str>,
        ttl: Duration,
    ) -> Result<String> {
        if ttl.is_zero() || ttl > MAX_EXTENSION_TOKEN_TTL {
            return Err(RiskGuardError::InvalidArgument(format!(
                "extension token TTL must be between 1 and {} seconds",
                MAX_EXTENSION_TOKEN_TTL.as_secs()
            )));
        }

        let (sub, sandbox_claim) = match (caller_kind, sandbox_id) {
            (ExtensionCallerKind::Gateway, None) => (self.issuer(), None),
            (ExtensionCallerKind::Gateway, Some(_)) => {
                return Err(RiskGuardError::InvalidArgument(
                    "gateway extension token must not specify sandbox_id".to_string(),
                ));
            }
            (ExtensionCallerKind::Supervisor, Some(sb)) if !sb.trim().is_empty() => (
                format!("{SPIFFE_SANDBOX_PREFIX}{sb}"),
                Some(sb.to_string()),
            ),
            (ExtensionCallerKind::Supervisor, _) => {
                return Err(RiskGuardError::InvalidArgument(
                    "supervisor extension token requires non-empty sandbox_id".to_string(),
                ));
            }
        };

        let iat = now_unix_secs();
        let exp = iat.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(3_600));
        let claims = ExtensionJwtClaims {
            iss: self.issuer(),
            aud: audience.to_string(),
            sub,
            iat,
            exp,
            jti: Uuid::new_v4().to_string(),
            caller_kind,
            sandbox_id: sandbox_claim,
        };

        self.mint_with_claims(Some(EXTENSION_JWT_TYP), &claims)
    }

    /// Mint an EdDSA-signed token with custom JOSE `typ` and custom claims.
    pub fn mint_with_claims(
        &self,
        typ: Option<&str>,
        claims: &ExtensionJwtClaims,
    ) -> Result<String> {
        install_crypto_provider();

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        header.typ = typ.map(ToOwned::to_owned);

        encode(&header, claims, &self.encoding_key).map_err(|err| {
            RiskGuardError::Internal(format!("failed to encode extension JWT: {err}"))
        })
    }

    /// Construct a tonic [`MetadataMap`] containing `authorization: Bearer <token>`.
    pub fn bearer_metadata(token: &str) -> Result<MetadataMap> {
        let mut metadata = MetadataMap::new();
        let header_val = AsciiMetadataValue::try_from(format!("Bearer {token}")).map_err(|err| {
            RiskGuardError::InvalidArgument(format!("invalid bearer token metadata: {err}"))
        })?;
        metadata.insert("authorization", header_val);
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GATEWAY_ID: &str = "gw-prod-01";
    const TEST_AUDIENCE: &str = "urn:openshell:extension:middleware:risk-guard";

    #[test]
    fn valid_supervisor_token_matching_expected_sandbox_id_succeeds() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");

        let token = issuer
            .mint_supervisor_token(TEST_AUDIENCE, "sandbox-alpha", 300)
            .expect("mint supervisor token");
        let metadata = JwtTestIssuer::bearer_metadata(&token).expect("metadata");

        let caller = verifier
            .verify_supervisor_call(&metadata, "sandbox-alpha")
            .expect("supervisor verification should succeed");

        match caller {
            AuthenticatedCaller::Supervisor {
                gateway_id,
                sandbox_id,
                jti,
                exp,
            } => {
                assert_eq!(gateway_id, TEST_GATEWAY_ID);
                assert_eq!(sandbox_id, "sandbox-alpha");
                assert!(!jti.is_empty());
                assert!(exp > now_unix_secs());
            }
            other => panic!("expected Supervisor caller, got {other:?}"),
        }
    }

    #[test]
    fn valid_gateway_token_succeeds() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");

        let token = issuer
            .mint_gateway_token(TEST_AUDIENCE, 300)
            .expect("mint gateway token");
        let metadata = JwtTestIssuer::bearer_metadata(&token).expect("metadata");

        let caller = verifier
            .verify_gateway_call(&metadata)
            .expect("gateway verification should succeed");

        match caller {
            AuthenticatedCaller::Gateway {
                gateway_id,
                jti,
                exp,
            } => {
                assert_eq!(gateway_id, TEST_GATEWAY_ID);
                assert!(!jti.is_empty());
                assert!(exp > now_unix_secs());
            }
            other => panic!("expected Gateway caller, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_id_mismatch_between_jwt_and_request_context_returns_permission_denied() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");

        let token = issuer
            .mint_supervisor_token(TEST_AUDIENCE, "sandbox-alpha", 300)
            .expect("mint supervisor token");
        let metadata = JwtTestIssuer::bearer_metadata(&token).expect("metadata");

        let err = verifier
            .verify_supervisor_call(&metadata, "sandbox-bravo")
            .expect_err("mismatched sandbox_id must fail");

        assert!(
            matches!(err, RiskGuardError::PermissionDenied(_)),
            "expected PermissionDenied, got {err:?}"
        );
    }

    #[test]
    fn wrong_typ_header_returns_unauthenticated() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");

        let now = now_unix_secs();
        let claims = ExtensionJwtClaims {
            iss: issuer.issuer(),
            aud: TEST_AUDIENCE.to_string(),
            sub: format!("{SPIFFE_SANDBOX_PREFIX}sandbox-alpha"),
            iat: now,
            exp: now + 300,
            jti: Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some("sandbox-alpha".to_string()),
        };

        let token = issuer
            .mint_with_claims(Some("JWT"), &claims)
            .expect("mint token with wrong typ");
        let metadata = JwtTestIssuer::bearer_metadata(&token).expect("metadata");

        let err = verifier
            .verify_supervisor_call(&metadata, "sandbox-alpha")
            .expect_err("wrong typ must fail");

        assert!(
            matches!(err, RiskGuardError::Unauthenticated(_)),
            "expected Unauthenticated, got {err:?}"
        );
    }

    #[test]
    fn wrong_audience_or_wrong_issuer_returns_unauthenticated() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");

        // Wrong audience
        let wrong_aud_token = issuer
            .mint_supervisor_token(
                "urn:openshell:extension:middleware:other-service",
                "sandbox-alpha",
                300,
            )
            .expect("mint wrong aud token");
        let wrong_aud_meta = JwtTestIssuer::bearer_metadata(&wrong_aud_token).expect("metadata");
        let err = verifier
            .verify_supervisor_call(&wrong_aud_meta, "sandbox-alpha")
            .expect_err("wrong audience must fail");
        assert!(
            matches!(err, RiskGuardError::Unauthenticated(_)),
            "expected Unauthenticated for wrong aud, got {err:?}"
        );

        // Wrong issuer (same keypair, different gateway_id)
        let wrong_issuer = JwtTestIssuer::from_ed25519_pem(
            "gw-other-99",
            issuer.signing_key_pem(),
            issuer.public_key_pem(),
            issuer.kid(),
        )
        .expect("wrong issuer with same key");
        let wrong_iss_token = wrong_issuer
            .mint_supervisor_token(TEST_AUDIENCE, "sandbox-alpha", 300)
            .expect("mint wrong iss token");
        let wrong_iss_meta = JwtTestIssuer::bearer_metadata(&wrong_iss_token).expect("metadata");
        let err = verifier
            .verify_supervisor_call(&wrong_iss_meta, "sandbox-alpha")
            .expect_err("wrong issuer must fail");
        assert!(
            matches!(err, RiskGuardError::Unauthenticated(_)),
            "expected Unauthenticated for wrong iss, got {err:?}"
        );
    }

    #[test]
    fn local_test_flag_cannot_downgrade_a_keyed_verifier() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer
            .verifier(TEST_AUDIENCE)
            .expect("verifier")
            .with_allow_insecure_local_test(true);
        let empty_meta = MetadataMap::new();
        assert!(matches!(
            verifier.verify_supervisor_call(&empty_meta, "sandbox-alpha"),
            Err(RiskGuardError::Unauthenticated(_))
        ));
        assert!(matches!(
            verifier.verify_gateway_call(&empty_meta),
            Err(RiskGuardError::Unauthenticated(_))
        ));
    }

    #[test]
    fn token_issued_in_the_future_is_rejected() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");
        let now = now_unix_secs();
        let claims = ExtensionJwtClaims {
            iss: issuer.issuer(),
            aud: TEST_AUDIENCE.to_string(),
            sub: format!("{SPIFFE_SANDBOX_PREFIX}sandbox-alpha"),
            iat: now + 600,
            exp: now + 900,
            jti: Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some("sandbox-alpha".to_string()),
        };
        let token = issuer
            .mint_with_claims(Some(EXTENSION_JWT_TYP), &claims)
            .expect("mint future token");
        let meta = JwtTestIssuer::bearer_metadata(&token).expect("metadata");
        assert!(matches!(
            verifier.verify_supervisor_call(&meta, "sandbox-alpha"),
            Err(RiskGuardError::Unauthenticated(_))
        ));
    }

    #[test]
    fn expired_token_or_ttl_exceeding_one_hour_returns_unauthenticated() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");
        let now = now_unix_secs();

        // Expired token
        let expired_claims = ExtensionJwtClaims {
            iss: issuer.issuer(),
            aud: TEST_AUDIENCE.to_string(),
            sub: format!("{SPIFFE_SANDBOX_PREFIX}sandbox-alpha"),
            iat: now - 600,
            exp: now - 10,
            jti: Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some("sandbox-alpha".to_string()),
        };
        let expired_token = issuer
            .mint_with_claims(Some(EXTENSION_JWT_TYP), &expired_claims)
            .expect("mint expired token");
        let expired_meta = JwtTestIssuer::bearer_metadata(&expired_token).expect("metadata");
        let err = verifier
            .verify_supervisor_call(&expired_meta, "sandbox-alpha")
            .expect_err("expired token must fail");
        assert!(
            matches!(err, RiskGuardError::Unauthenticated(_)),
            "expected Unauthenticated for expired token, got {err:?}"
        );

        // TTL > 1 hour (3601 seconds)
        let long_ttl_claims = ExtensionJwtClaims {
            iss: issuer.issuer(),
            aud: TEST_AUDIENCE.to_string(),
            sub: format!("{SPIFFE_SANDBOX_PREFIX}sandbox-alpha"),
            iat: now,
            exp: now + 3_601,
            jti: Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some("sandbox-alpha".to_string()),
        };
        let long_ttl_token = issuer
            .mint_with_claims(Some(EXTENSION_JWT_TYP), &long_ttl_claims)
            .expect("mint long ttl token");
        let long_ttl_meta = JwtTestIssuer::bearer_metadata(&long_ttl_token).expect("metadata");
        let err = verifier
            .verify_supervisor_call(&long_ttl_meta, "sandbox-alpha")
            .expect_err("token with TTL > 3600s must fail");
        assert!(
            matches!(err, RiskGuardError::Unauthenticated(_)),
            "expected Unauthenticated for TTL > 3600s, got {err:?}"
        );
    }

    #[test]
    fn gateway_token_on_supervisor_call_and_vice_versa_returns_permission_denied() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");

        // Gateway token presented to supervisor endpoint
        let gw_token = issuer
            .mint_gateway_token(TEST_AUDIENCE, 300)
            .expect("mint gateway token");
        let gw_meta = JwtTestIssuer::bearer_metadata(&gw_token).expect("metadata");
        let err = verifier
            .verify_supervisor_call(&gw_meta, "sandbox-alpha")
            .expect_err("gateway token on supervisor call must fail");
        assert!(
            matches!(err, RiskGuardError::PermissionDenied(_)),
            "expected PermissionDenied when gateway token is used on supervisor call, got {err:?}"
        );

        // Supervisor token presented to gateway endpoint
        let sup_token = issuer
            .mint_supervisor_token(TEST_AUDIENCE, "sandbox-alpha", 300)
            .expect("mint supervisor token");
        let sup_meta = JwtTestIssuer::bearer_metadata(&sup_token).expect("metadata");
        let err = verifier
            .verify_gateway_call(&sup_meta)
            .expect_err("supervisor token on gateway call must fail");
        assert!(
            matches!(err, RiskGuardError::PermissionDenied(_)),
            "expected PermissionDenied when supervisor token is used on gateway call, got {err:?}"
        );
    }

    #[test]
    fn missing_header_respects_allow_insecure_local_test_flag() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let strict_verifier = issuer.verifier(TEST_AUDIENCE).expect("strict verifier");
        let empty_meta = MetadataMap::new();

        assert!(matches!(
            strict_verifier.verify_supervisor_call(&empty_meta, "sandbox-alpha"),
            Err(RiskGuardError::Unauthenticated(_))
        ));
        assert!(matches!(
            strict_verifier.verify_gateway_call(&empty_meta),
            Err(RiskGuardError::Unauthenticated(_))
        ));

        let insecure_verifier =
            JwtAuthVerifier::insecure_for_local_test(TEST_GATEWAY_ID, TEST_AUDIENCE);
        let sup_caller = insecure_verifier
            .verify_supervisor_call(&empty_meta, "sandbox-alpha")
            .expect("insecure supervisor fallback");
        assert_eq!(
            sup_caller,
            AuthenticatedCaller::Supervisor {
                gateway_id: TEST_GATEWAY_ID.to_string(),
                sandbox_id: "sandbox-alpha".to_string(),
                jti: "insecure-local-test".to_string(),
                exp: i64::MAX,
            }
        );

        let gw_caller = insecure_verifier
            .verify_gateway_call(&empty_meta)
            .expect("insecure gateway fallback");
        assert_eq!(
            gw_caller,
            AuthenticatedCaller::Gateway {
                gateway_id: TEST_GATEWAY_ID.to_string(),
                jti: "insecure-local-test".to_string(),
                exp: i64::MAX,
            }
        );
    }

    #[test]
    fn wrong_signature_and_iat_after_exp_return_unauthenticated() {
        let trusted_issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let untrusted_issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = trusted_issuer.verifier(TEST_AUDIENCE).expect("verifier");

        // Token signed by a different Ed25519 keypair
        let forged_token = untrusted_issuer
            .mint_supervisor_token(TEST_AUDIENCE, "sandbox-alpha", 300)
            .expect("forged token");
        let forged_meta = JwtTestIssuer::bearer_metadata(&forged_token).expect("metadata");
        assert!(matches!(
            verifier.verify_supervisor_call(&forged_meta, "sandbox-alpha"),
            Err(RiskGuardError::Unauthenticated(_))
        ));

        // Token with iat > exp
        let now = now_unix_secs();
        let inverted_claims = ExtensionJwtClaims {
            iss: trusted_issuer.issuer(),
            aud: TEST_AUDIENCE.to_string(),
            sub: format!("{SPIFFE_SANDBOX_PREFIX}sandbox-alpha"),
            iat: now + 500,
            exp: now + 300,
            jti: Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some("sandbox-alpha".to_string()),
        };
        let inverted_token = trusted_issuer
            .mint_with_claims(Some(EXTENSION_JWT_TYP), &inverted_claims)
            .expect("inverted token");
        let inverted_meta = JwtTestIssuer::bearer_metadata(&inverted_token).expect("metadata");
        assert!(matches!(
            verifier.verify_supervisor_call(&inverted_meta, "sandbox-alpha"),
            Err(RiskGuardError::Unauthenticated(_))
        ));
    }

    #[test]
    fn default_clock_skew_tolerates_minor_drift_and_rejects_beyond_skew() {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let verifier = issuer.verifier(TEST_AUDIENCE).expect("verifier");
        assert_eq!(verifier.clock_skew_secs, DEFAULT_CLOCK_SKEW_SECS);

        let now = 1_700_000_000_i64;
        let slight_future_claims = ExtensionJwtClaims {
            iss: issuer.issuer(),
            aud: TEST_AUDIENCE.to_string(),
            sub: format!("{SPIFFE_SANDBOX_PREFIX}sandbox-alpha"),
            iat: now + 3,
            exp: now + 300,
            jti: Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some("sandbox-alpha".to_string()),
        };
        let slight_future_token = issuer
            .mint_with_claims(Some(EXTENSION_JWT_TYP), &slight_future_claims)
            .expect("mint slight future token");
        verifier
            .verify_token(&slight_future_token, now)
            .expect("slight future iat within 5s default skew should be accepted");

        let slight_expired_claims = ExtensionJwtClaims {
            iss: issuer.issuer(),
            aud: TEST_AUDIENCE.to_string(),
            sub: format!("{SPIFFE_SANDBOX_PREFIX}sandbox-alpha"),
            iat: now - 300,
            exp: now - 3,
            jti: Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some("sandbox-alpha".to_string()),
        };
        let slight_expired_token = issuer
            .mint_with_claims(Some(EXTENSION_JWT_TYP), &slight_expired_claims)
            .expect("mint slight expired token");
        verifier
            .verify_token(&slight_expired_token, now)
            .expect("slight past exp within 5s default skew should be accepted");

        let zero_skew_verifier = verifier.with_clock_skew_secs(0);
        assert!(matches!(
            zero_skew_verifier.verify_token(&slight_expired_token, now),
            Err(RiskGuardError::Unauthenticated(_))
        ));
    }
}

