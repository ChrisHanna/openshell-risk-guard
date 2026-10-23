// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Identity threat tests and the key-rotation drill for the gateway-signed (TLS plus JWT) path, which stays as it is.
//!
//! Three identity sources are kept apart in Risk Guard, and these tests cover the first; the others are covered where they live:
//!
//! 1. the sandbox identity the gateway signs into a JWT (here);
//! 2. a SPIFFE identity read from a verified X.509 certificate (`svid_listener`);
//! 3. a sandbox found from a connection's source address (`pod_resolver` tests and `svid_listener`).
//!
//! A token only ever answers "which sandbox is speaking over this call"; a certificate only answers "which workload is this proxy
//! speaking for"; an address only answers "which sandbox's tunnel is this". No source stands in for another.

use openshell_risk_guard::auth::{
    EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims, JwtAuthVerifier, JwtTestIssuer,
};
use openshell_risk_guard::types::AuthVerifier;
use tonic::metadata::MetadataMap;

const GATEWAY: &str = "gw-prod";
const AUDIENCE: &str = "urn:openshell:extension:risk-guard";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn bearer(token: &str) -> MetadataMap {
    JwtTestIssuer::bearer_metadata(token).unwrap()
}

fn supervisor_token(issuer: &JwtTestIssuer, sandbox: &str) -> String {
    issuer
        .mint_supervisor_token(AUDIENCE, sandbox, 300)
        .unwrap()
}

fn claims(
    issuer: &JwtTestIssuer,
    sandbox: Option<&str>,
    kind: ExtensionCallerKind,
) -> ExtensionJwtClaims {
    ExtensionJwtClaims {
        iss: format!("openshell-gateway:{GATEWAY}"),
        aud: AUDIENCE.to_string(),
        sub: format!("spiffe://openshell/sandbox/{}", sandbox.unwrap_or("x")),
        iat: now(),
        exp: now() + 300,
        jti: format!("jti-{}", issuer.kid),
        caller_kind: kind,
        sandbox_id: sandbox.map(ToOwned::to_owned),
    }
}

fn verifier_for(pems: &[&JwtTestIssuer]) -> openshell_risk_guard::error::Result<JwtAuthVerifier> {
    let bundle: String = pems
        .iter()
        .map(|i| i.public_key_pem.clone())
        .collect::<Vec<_>>()
        .join("\n");
    JwtAuthVerifier::from_ed25519_pem(GATEWAY, AUDIENCE, bundle.as_bytes())
}

#[test]
fn a_token_for_one_sandbox_cannot_speak_for_another_and_headers_do_not_matter() {
    let issuer = JwtTestIssuer::generate(GATEWAY).unwrap();
    let verifier = verifier_for(&[&issuer]).unwrap();
    let token = supervisor_token(&issuer, "sbx-a");

    assert!(
        verifier
            .verify_supervisor_call(&bearer(&token), "sbx-a")
            .is_ok()
    );
    // The sandbox named in the call decides whose authority is checked; the token must be for that same sandbox.
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&token), "sbx-b")
            .is_err()
    );

    // Anything else a caller adds to the metadata (a claimed sandbox, an address, a forwarded identity) is not read.
    let mut spoofed = bearer(&token);
    spoofed.insert("x-sandbox-id", "sbx-b".parse().unwrap());
    spoofed.insert("x-forwarded-for", "10.0.0.2".parse().unwrap());
    spoofed.insert(
        "x-spiffe-id",
        "spiffe://risk-guard.demo/ns/openshell/sa/egress-proxy"
            .parse()
            .unwrap(),
    );
    assert!(
        verifier.verify_supervisor_call(&spoofed, "sbx-b").is_err(),
        "claimed headers cannot move a token to another sandbox"
    );
    assert!(verifier.verify_supervisor_call(&spoofed, "sbx-a").is_ok());
}

#[test]
fn unknown_missing_malformed_and_wrongly_scoped_tokens_obtain_nothing() {
    let issuer = JwtTestIssuer::generate(GATEWAY).unwrap();
    let verifier = verifier_for(&[&issuer]).unwrap();
    let stranger = JwtTestIssuer::generate(GATEWAY).unwrap();

    let no_token = MetadataMap::new();
    assert!(verifier.verify_supervisor_call(&no_token, "sbx-a").is_err());
    assert!(verifier.verify_gateway_call(&no_token).is_err());
    for garbage in ["", "x", "a.b.c", "Bearer", "eyJhbGciOiJub25lIn0.e30."] {
        let mut meta = MetadataMap::new();
        meta.insert(
            "authorization",
            format!("Bearer {garbage}").parse().unwrap(),
        );
        assert!(
            verifier.verify_supervisor_call(&meta, "sbx-a").is_err(),
            "{garbage:?}"
        );
    }
    // Signed by a key Risk Guard was never given.
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&supervisor_token(&stranger, "sbx-a")), "sbx-a")
            .is_err()
    );
    // A gateway token is not a supervisor token, and the reverse.
    let gateway = issuer.mint_gateway_token(AUDIENCE, 300).unwrap();
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&gateway), "sbx-a")
            .is_err()
    );
    assert!(
        verifier
            .verify_gateway_call(&bearer(&supervisor_token(&issuer, "sbx-a")))
            .is_err()
    );
    // A supervisor token with no sandbox in it, or with the wrong audience or issuer.
    let no_sandbox = issuer
        .mint_with_claims(
            Some(EXTENSION_JWT_TYP),
            &claims(&issuer, None, ExtensionCallerKind::Supervisor),
        )
        .unwrap();
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&no_sandbox), "sbx-a")
            .is_err()
    );
    let mut wrong_aud = claims(&issuer, Some("sbx-a"), ExtensionCallerKind::Supervisor);
    wrong_aud.aud = "urn:someone:else".into();
    let token = issuer
        .mint_with_claims(Some(EXTENSION_JWT_TYP), &wrong_aud)
        .unwrap();
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&token), "sbx-a")
            .is_err()
    );
    let mut wrong_iss = claims(&issuer, Some("sbx-a"), ExtensionCallerKind::Supervisor);
    wrong_iss.iss = "openshell-gateway:other".into();
    let token = issuer
        .mint_with_claims(Some(EXTENSION_JWT_TYP), &wrong_iss)
        .unwrap();
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&token), "sbx-a")
            .is_err()
    );
    // An expired token, and one whose lifetime is longer than the maximum.
    let mut expired = claims(&issuer, Some("sbx-a"), ExtensionCallerKind::Supervisor);
    expired.iat = now() - 600;
    expired.exp = now() - 300;
    let token = issuer
        .mint_with_claims(Some(EXTENSION_JWT_TYP), &expired)
        .unwrap();
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&token), "sbx-a")
            .is_err()
    );
    let mut long = claims(&issuer, Some("sbx-a"), ExtensionCallerKind::Supervisor);
    long.exp = now() + 10 * 24 * 3600;
    let token = issuer
        .mint_with_claims(Some(EXTENSION_JWT_TYP), &long)
        .unwrap();
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&token), "sbx-a")
            .is_err()
    );
    // A token with the wrong JOSE type.
    let token = issuer
        .mint_with_claims(
            Some("JWT"),
            &claims(&issuer, Some("sbx-a"), ExtensionCallerKind::Supervisor),
        )
        .unwrap();
    assert!(
        verifier
            .verify_supervisor_call(&bearer(&token), "sbx-a")
            .is_err()
    );
}

/// The rotation drill, phase by phase. The gateway's signing key is replaced without ever accepting an unverified token:
///
/// 1. before: only the old key is known, and the old key's tokens work;
/// 2. overlap: Risk Guard is given the new key first and the old one after it; tokens from either verify, from nobody else;
/// 3. after: the old key is removed from the file and Risk Guard restarts; the old key's tokens stop working, the new key's keep working.
#[test]
fn gateway_key_rotation_overlaps_then_retires_the_old_key_with_no_unverified_fallback() {
    let old = JwtTestIssuer::generate(GATEWAY).unwrap();
    let new = JwtTestIssuer::generate(GATEWAY).unwrap();
    let stranger = JwtTestIssuer::generate(GATEWAY).unwrap();
    let check = |verifier: &JwtAuthVerifier, issuer: &JwtTestIssuer| {
        verifier
            .verify_supervisor_call(&bearer(&supervisor_token(issuer, "sbx-a")), "sbx-a")
            .is_ok()
    };

    // 1. before
    let before = verifier_for(&[&old]).unwrap();
    assert!(check(&before, &old));
    assert!(
        !check(&before, &new),
        "the new key is not trusted before it is distributed"
    );

    // 2. overlap: the file lists the new key first, then the old one
    let overlap = verifier_for(&[&new, &old]).unwrap();
    assert!(check(&overlap, &new) && check(&overlap, &old));
    assert!(
        !check(&overlap, &stranger),
        "a key that was never listed is refused during the overlap"
    );
    // The other order is the same set of keys.
    let reversed = verifier_for(&[&old, &new]).unwrap();
    assert!(check(&reversed, &new) && check(&reversed, &old));
    // Retired keys are held to the same rules as the current one: an expired token from the old key is still expired.
    let mut stale = claims(&old, Some("sbx-a"), ExtensionCallerKind::Supervisor);
    stale.iat = now() - 600;
    stale.exp = now() - 300;
    let token = old
        .mint_with_claims(Some(EXTENSION_JWT_TYP), &stale)
        .unwrap();
    assert!(
        overlap
            .verify_supervisor_call(&bearer(&token), "sbx-a")
            .is_err()
    );

    // 3. after
    let after = verifier_for(&[&new]).unwrap();
    assert!(check(&after, &new));
    assert!(
        !check(&after, &old),
        "the retired key stops working once it is removed"
    );

    // A bad file never leaves a verifier that skips verification: an unreadable block is an error, not a dropped key.
    let broken = format!(
        "{}\n-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n",
        new.public_key_pem
    );
    assert!(JwtAuthVerifier::from_ed25519_pem(GATEWAY, AUDIENCE, broken.as_bytes()).is_err());
    assert!(JwtAuthVerifier::from_ed25519_pem(GATEWAY, AUDIENCE, b"").is_err());
    assert!(JwtAuthVerifier::from_ed25519_pem(GATEWAY, AUDIENCE, b"no key here").is_err());

    // Supplying keys does not switch on the local-test fallback: with keys, a call without a token is refused.
    let lenient = verifier_for(&[&new, &old])
        .unwrap()
        .with_allow_insecure_local_test(true);
    assert!(
        lenient
            .verify_supervisor_call(&MetadataMap::new(), "sbx-a")
            .is_err()
    );
    assert!(lenient.verify_gateway_call(&MetadataMap::new()).is_err());
}
