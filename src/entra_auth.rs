// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Microsoft Entra ID sign-in for the operator console.
//!
//! The console accepts an Entra v2 access token for its own API and checks everything itself: the RS256
//! signature against the tenant's published signing keys, issuer, tenant, audience, expiry, and a delegated
//! scope. Who may do what is decided by object ID (`oid`), which Entra assigns and never reuses; email
//! addresses are shown to people but never trusted for access. An unlisted caller gets nothing.
//!
//! Failure is closed. Without a usable signing key the answer is "no", and nothing here ever downgrades to
//! "unauthenticated is fine".

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{Result, RiskGuardError};

const LOGIN_HOST: &str = "https://login.microsoftonline.com";
/// Unknown signing key IDs trigger a refetch, at most this often, so a forged `kid` cannot make us hammer Entra.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const CLOCK_LEEWAY_SECS: u64 = 60;
/// The delegated scope the console asks for. App-only tokens carry no `scp`, so they never qualify.
pub const REQUIRED_SCOPE: &str = "access";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// May read evidence.
    Viewer,
    /// May read and change settings, and clear locks.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Admin => "admin",
        }
    }
}

/// A verified caller. `display` is for people to read; `oid` is what access was decided on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub oid: String,
    pub display: String,
    pub role: Role,
}

impl Identity {
    /// The text recorded as the actor in audit rows: readable, and tied to the immutable object ID.
    pub fn actor(&self) -> String {
        format!("{} [entra:{}]", self.display, self.oid)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// Missing, malformed, expired, or otherwise not a token we accept. Maps to 401.
    Invalid(&'static str),
    /// A genuine token from our tenant, for someone who is not on the list. Maps to 403.
    NotAuthorized,
}

#[derive(Clone, Debug)]
pub struct EntraConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub admins: Vec<String>,
    pub viewers: Vec<String>,
}

fn normalized_guid(label: &str, value: &str) -> Result<String> {
    Uuid::parse_str(value.trim())
        .map(|id| id.hyphenated().to_string())
        .map_err(|_| RiskGuardError::InvalidArgument(format!("{label} must be a GUID")))
}

impl EntraConfig {
    pub fn new(
        tenant_id: &str,
        client_id: &str,
        admins: &[String],
        viewers: &[String],
    ) -> Result<Self> {
        let admins = admins
            .iter()
            .filter(|oid| !oid.trim().is_empty())
            .map(|oid| normalized_guid("admin object ID", oid))
            .collect::<Result<Vec<_>>>()?;
        if admins.is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "Entra sign-in needs at least one admin object ID".into(),
            ));
        }
        let viewers = viewers
            .iter()
            .filter(|oid| !oid.trim().is_empty())
            .map(|oid| normalized_guid("viewer object ID", oid))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            tenant_id: normalized_guid("tenant ID", tenant_id)?,
            client_id: normalized_guid("client ID", client_id)?,
            admins,
            viewers,
        })
    }

    pub fn issuer(&self) -> String {
        format!("{LOGIN_HOST}/{}/v2.0", self.tenant_id)
    }

    pub fn scope(&self) -> String {
        format!("api://{}/{REQUIRED_SCOPE}", self.client_id)
    }

    fn jwks_url(&self) -> String {
        format!("{LOGIN_HOST}/{}/discovery/v2.0/keys", self.tenant_id)
    }

    fn role_of(&self, oid: &str) -> Option<Role> {
        // Admin wins if an ID is listed twice.
        if self.admins.iter().any(|a| a == oid) {
            Some(Role::Admin)
        } else if self.viewers.iter().any(|v| v == oid) {
            Some(Role::Viewer)
        } else {
            None
        }
    }
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    last_attempt: Option<Instant>,
}

pub struct EntraVerifier {
    config: EntraConfig,
    cache: RwLock<KeyCache>,
    /// `None` means the keys were supplied up front (tests) and are never refetched.
    jwks_url: Option<String>,
    http: Option<reqwest::Client>,
}

#[derive(Deserialize)]
struct Claims {
    oid: Option<String>,
    tid: Option<String>,
    scp: Option<String>,
    ver: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
    name: Option<String>,
}

fn keys_from_set(set: &JwkSet) -> HashMap<String, DecodingKey> {
    set.keys
        .iter()
        .filter_map(|jwk| {
            let kid = jwk.common.key_id.clone()?;
            // Only RSA signing keys. An encryption key or another type can never verify one of our tokens.
            if !matches!(jwk.algorithm, jsonwebtoken::jwk::AlgorithmParameters::RSA(_)) {
                return None;
            }
            DecodingKey::from_jwk(jwk).ok().map(|key| (kid, key))
        })
        .collect()
}

fn clean_display(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    cleaned.trim().to_string()
}

impl EntraVerifier {
    /// Production: signing keys are fetched from the tenant's published endpoint when first needed.
    pub fn new(config: EntraConfig) -> Result<Self> {
        crate::auth::install_crypto_provider();
        // reqwest is built without a bundled TLS provider; give rustls one before the first client exists.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let jwks_url = config.jwks_url();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| RiskGuardError::Internal(format!("Entra HTTP client: {e}")))?;
        Ok(Self {
            config,
            cache: RwLock::new(KeyCache::default()),
            jwks_url: Some(jwks_url),
            http: Some(http),
        })
    }

    #[cfg(test)]
    fn with_static_keys(config: EntraConfig, set: &JwkSet) -> Self {
        Self {
            config,
            cache: RwLock::new(KeyCache {
                keys: keys_from_set(set),
                last_attempt: None,
            }),
            jwks_url: None,
            http: None,
        }
    }

    pub fn config(&self) -> &EntraConfig {
        &self.config
    }

    fn cached_key(&self, kid: &str) -> Option<DecodingKey> {
        self.cache.read().ok()?.keys.get(kid).cloned()
    }

    async fn refresh_keys(&self) {
        let (Some(url), Some(http)) = (&self.jwks_url, &self.http) else { return };
        {
            let Ok(mut cache) = self.cache.write() else { return };
            if cache
                .last_attempt
                .is_some_and(|t| t.elapsed() < MIN_REFRESH_INTERVAL)
            {
                return;
            }
            cache.last_attempt = Some(Instant::now());
        }
        let fetched = async {
            let response = http.get(url).send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            let body = response.bytes().await.ok()?;
            if body.len() > MAX_JWKS_BYTES {
                return None;
            }
            serde_json::from_slice::<JwkSet>(&body).ok()
        }
        .await;
        match fetched.map(|set| keys_from_set(&set)) {
            // An empty or unreadable answer never replaces keys we already trust.
            Some(keys) if !keys.is_empty() => {
                if let Ok(mut cache) = self.cache.write() {
                    cache.keys = keys;
                }
            }
            _ => tracing::warn!("could not refresh Entra signing keys; keeping what is cached"),
        }
    }

    pub async fn verify(&self, token: &str) -> std::result::Result<Identity, AuthError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(AuthError::Invalid("malformed token"));
        }
        let header = decode_header(token).map_err(|_| AuthError::Invalid("malformed token"))?;
        // Pin the algorithm: never let the token choose, and never accept `none` or an HMAC keyed by a public value.
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::Invalid("unsupported algorithm"));
        }
        let kid = header.kid.ok_or(AuthError::Invalid("token has no key id"))?;
        let key = match self.cached_key(&kid) {
            Some(key) => key,
            None => {
                self.refresh_keys().await;
                self.cached_key(&kid)
                    .ok_or(AuthError::Invalid("unknown signing key"))?
            }
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.config.issuer()]);
        validation.set_audience(&[
            self.config.client_id.clone(),
            format!("api://{}", self.config.client_id),
        ]);
        validation.leeway = CLOCK_LEEWAY_SECS;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud"]);
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|error| {
                tracing::debug!(%error, "Entra token rejected");
                AuthError::Invalid("token not accepted")
            })?
            .claims;

        if claims.tid.as_deref() != Some(self.config.tenant_id.as_str()) {
            return Err(AuthError::Invalid("wrong tenant"));
        }
        if claims.ver.as_deref() != Some("2.0") {
            return Err(AuthError::Invalid("not a v2 token"));
        }
        let has_scope = claims
            .scp
            .as_deref()
            .is_some_and(|scp| scp.split_whitespace().any(|s| s == REQUIRED_SCOPE));
        if !has_scope {
            return Err(AuthError::Invalid("token lacks the console scope"));
        }
        let oid = claims
            .oid
            .as_deref()
            .and_then(|oid| Uuid::parse_str(oid).ok())
            .map(|id| id.hyphenated().to_string())
            .ok_or(AuthError::Invalid("token has no object ID"))?;
        let role = self
            .config
            .role_of(&oid)
            .ok_or(AuthError::NotAuthorized)?;
        let display = [&claims.preferred_username, &claims.email, &claims.name]
            .into_iter()
            .flatten()
            .map(|value| clean_display(value))
            .find(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        Ok(Identity { oid, display, role })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
    use aws_lc_rs::signature::KeyPair as _;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TENANT: &str = "aaaaaaaa-1111-2222-3333-444444444444";
    const CLIENT: &str = "11111111-2222-3333-4444-555555555555";
    pub(crate) const ADMIN: &str = "bbbbbbbb-1111-2222-3333-444444444444";
    pub(crate) const VIEWER: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    pub(crate) const STRANGER: &str = "99999999-8888-7777-6666-555555555555";

    /// A verifier that trusts a throwaway key, for tests of the routes that sit behind it.
    pub(crate) fn test_verifier() -> std::sync::Arc<EntraVerifier> {
        std::sync::Arc::new(verifier())
    }

    /// A valid console token for the given object ID, signed by the throwaway key.
    pub(crate) fn test_token(oid: &str) -> String {
        sign(&keys().0, "good", &with(claims(), "oid", json!(oid)))
    }

    struct TestKey {
        encoding: EncodingKey,
        jwk: serde_json::Value,
    }

    fn make_key(kid: &str) -> TestKey {
        let pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA key");
        let der = pair.as_der().expect("private DER");
        let body = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            body.as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
        let components = aws_lc_rs::rsa::PublicKeyComponents::<Vec<u8>>::from(pair.public_key());
        TestKey {
            encoding: EncodingKey::from_rsa_pem(pem.as_bytes()).expect("test key PEM"),
            jwk: json!({
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                "n": URL_SAFE_NO_PAD.encode(&components.n),
                "e": URL_SAFE_NO_PAD.encode(&components.e),
            }),
        }
    }

    fn keys() -> &'static (TestKey, TestKey) {
        static KEYS: OnceLock<(TestKey, TestKey)> = OnceLock::new();
        KEYS.get_or_init(|| (make_key("good"), make_key("other")))
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn claims() -> serde_json::Value {
        json!({
            "iss": format!("https://login.microsoftonline.com/{TENANT}/v2.0"),
            "aud": CLIENT, "tid": TENANT, "ver": "2.0", "oid": ADMIN,
            "scp": "access", "preferred_username": "admin@example.com",
            "nbf": now() - 10, "exp": now() + 3600,
        })
    }

    fn sign(key: &TestKey, kid: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &key.encoding).unwrap()
    }

    fn verifier() -> EntraVerifier {
        crate::auth::install_crypto_provider();
        let config = EntraConfig::new(TENANT, CLIENT, &[ADMIN.into()], &[VIEWER.into()]).unwrap();
        let set: JwkSet = serde_json::from_value(json!({ "keys": [keys().0.jwk.clone()] })).unwrap();
        EntraVerifier::with_static_keys(config, &set)
    }

    fn with(mut base: serde_json::Value, key: &str, value: serde_json::Value) -> serde_json::Value {
        base[key] = value;
        base
    }

    fn without(mut base: serde_json::Value, key: &str) -> serde_json::Value {
        base.as_object_mut().unwrap().remove(key);
        base
    }

    #[tokio::test]
    async fn the_admin_signs_in_and_is_recorded_by_object_id() {
        let who = verifier().verify(&sign(&keys().0, "good", &claims())).await.unwrap();
        assert_eq!(who.role, Role::Admin);
        assert_eq!(who.oid, ADMIN);
        assert_eq!(who.actor(), format!("admin@example.com [entra:{ADMIN}]"));
    }

    #[tokio::test]
    async fn a_listed_viewer_reads_but_is_not_an_admin() {
        let token = sign(&keys().0, "good", &with(claims(), "oid", json!(VIEWER)));
        assert_eq!(verifier().verify(&token).await.unwrap().role, Role::Viewer);
    }

    #[tokio::test]
    async fn a_real_tenant_user_who_is_not_listed_gets_nothing() {
        let token = sign(&keys().0, "good", &with(claims(), "oid", json!(STRANGER)));
        assert_eq!(verifier().verify(&token).await, Err(AuthError::NotAuthorized));
    }

    #[tokio::test]
    async fn access_follows_the_object_id_not_the_email() {
        // Someone else claiming the admin's email address is still a stranger.
        let forged = with(with(claims(), "oid", json!(STRANGER)), "preferred_username", json!("admin@example.com"));
        assert_eq!(
            verifier().verify(&sign(&keys().0, "good", &forged)).await,
            Err(AuthError::NotAuthorized)
        );
    }

    #[tokio::test]
    async fn bad_tokens_are_all_rejected() {
        let v = verifier();
        let good = &keys().0;
        let cases: Vec<(&str, String)> = vec![
            ("expired", sign(good, "good", &with(claims(), "exp", json!(now() - 3600)))),
            ("not yet valid", sign(good, "good", &with(claims(), "nbf", json!(now() + 3600)))),
            ("wrong audience", sign(good, "good", &with(claims(), "aud", json!("someone-else")))),
            ("wrong issuer", sign(good, "good", &with(claims(), "iss", json!("https://evil.example/v2.0")))),
            ("other tenant issuer", sign(good, "good", &with(claims(), "iss", json!("https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0")))),
            ("wrong tenant claim", sign(good, "good", &with(claims(), "tid", json!("00000000-0000-0000-0000-000000000000")))),
            ("v1 token", sign(good, "good", &with(claims(), "ver", json!("1.0")))),
            ("no scope", sign(good, "good", &without(claims(), "scp"))),
            ("wrong scope", sign(good, "good", &with(claims(), "scp", json!("read")))),
            ("no object id", sign(good, "good", &without(claims(), "oid"))),
            ("no expiry", sign(good, "good", &without(claims(), "exp"))),
            ("signed by another key", sign(&keys().1, "good", &claims())),
            ("unknown key id", sign(good, "nobody", &claims())),
        ];
        for (name, token) in cases {
            assert!(
                matches!(v.verify(&token).await, Err(AuthError::Invalid(_))),
                "{name} must be rejected"
            );
        }
        for junk in ["", "abc", "a.b.c", "Bearer x"] {
            assert!(matches!(v.verify(junk).await, Err(AuthError::Invalid(_))), "junk {junk:?}");
        }
    }

    #[tokio::test]
    async fn tokens_with_another_algorithm_are_rejected() {
        // An unsigned token, and an HMAC token keyed with the public modulus, must not get through.
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT","kid":"good"}"#);
        let body = URL_SAFE_NO_PAD.encode(claims().to_string());
        assert!(matches!(
            verifier().verify(&format!("{header}.{body}.")).await,
            Err(AuthError::Invalid(_))
        ));
        let mut hs = Header::new(Algorithm::HS256);
        hs.kid = Some("good".into());
        let hmac = encode(&hs, &claims(), &EncodingKey::from_secret(b"anything")).unwrap();
        assert!(matches!(verifier().verify(&hmac).await, Err(AuthError::Invalid(_))));
    }

    #[test]
    fn configuration_is_checked_and_normalised() {
        assert!(EntraConfig::new("not-a-guid", CLIENT, &[ADMIN.into()], &[]).is_err());
        assert!(EntraConfig::new(TENANT, "x", &[ADMIN.into()], &[]).is_err());
        assert!(EntraConfig::new(TENANT, CLIENT, &[], &[]).is_err(), "an admin is required");
        assert!(EntraConfig::new(TENANT, CLIENT, &["nope".into()], &[]).is_err());
        let upper = EntraConfig::new(&TENANT.to_uppercase(), CLIENT, &[ADMIN.to_uppercase()], &[]).unwrap();
        assert_eq!(upper.admins[0], ADMIN, "object IDs compare case-insensitively");
        assert_eq!(upper.scope(), format!("api://{CLIENT}/access"));
    }

    #[test]
    fn display_text_is_cleaned_before_it_reaches_the_audit_log() {
        assert_eq!(clean_display("a\nb\u{0}c"), "abc");
        assert_eq!(clean_display(&"x".repeat(500)).len(), 120);
    }
}
