# Workload attribution and key rotation

Risk Guard learns "who is this?" from three different places. They are kept apart on purpose, and none stands in for another.

| Source | Answers | Where it is checked | Used for |
|---|---|---|---|
| **Gateway-signed sandbox identity** (TLS plus an Ed25519 JWT) | Which sandbox is making this call | `src/auth/mod.rs` | OpenShell's supervisor middleware and gateway interceptor calls (gates 1 and 2) |
| **Verified SPIFFE identity** (an X.509-SVID over mutual TLS) | Which workload a proxy is speaking for, or which proxy is asking | `src/spiffe.rs`, `src/ext_authz.rs` | The per-request egress proxy; the proxies' own right to ask |
| **Network source address** | Which sandbox's tunnel this is | `src/pod_resolver.rs` | The tunnel gate (gate 3) |

The existing TLS-plus-JWT path is kept. It is what OpenShell's extension protocol defines, and replacing it with mutual TLS would add
nothing to the checks below.

## Source-address attribution: what happens when the information is wrong

| Situation | Behaviour | Test |
|---|---|---|
| The pod list is out of date | A mapping is trusted for 5 s, then the list is read again. A refresh replaces the whole table | `a_mapping_is_not_trusted_past_its_lifetime…` |
| An address is reused by another pod | After at most 5 s it maps to the new pod, or to nothing. In that window the old mapping is served; that is the one stale case, and it only matters to a pod the proxy's network policy already admits (supervisors) | same |
| A pod is terminating | It is not mapped (its address may be handed on) | `terminating_pods_and_addresses_claimed_by_two_sandboxes…` |
| Two sandboxes claim one address | Mapped to neither: the tunnel is refused as coming from an unknown sandbox | same |
| A pod has no sandbox label or no address | Not mapped: refused as unknown | `only_running_supervisor_pods_with_a_sandbox_label…` |
| The pod list cannot be read | An error, so the proxy's check fails and the tunnel is refused. Nothing from before is served: the cache is emptied | `a_failed_refresh_is_an_error…` |
| An address that is no sandbox | Refused. A lookup that finds nothing re-reads the list at most every 2 s | `an_unknown_address_triggers_a_refresh…`, `a_sandbox_tunnel_is_carried_unless…` |
| The caller claims an identity (the `principal` field, headers, a sandbox name) | Ignored on the tunnel path: only the source address counts. A quarantine cannot be lifted by claiming another identity | `a_claimed_identity_cannot_change_whose_tunnel_it_is…` |
| A workload (not a listed proxy) asks about a tunnel | `PermissionDenied`, whatever its certificate says about itself | same |

## Token threats (gateway-signed path)

`tests/identity_threats.rs` shows that none of these obtains another workload's authorization: a token for sandbox A used for B; claimed
headers (`x-sandbox-id`, `x-forwarded-for`, `x-spiffe-id`); no token, malformed or `alg=none` tokens; a stranger's signature; a gateway
token on a supervisor call and the reverse; a missing sandbox claim; wrong audience, issuer or JOSE type; an expired token; a lifetime past
the maximum. `sidecar_transport` adds the transport-level cases (no TLS, untrusted CA).

## Key rotation

The gateway signs tokens with one Ed25519 key; Risk Guard holds the public key (`--public-key-pem`, the Secret `openshell-jwt-keys`).

The key file may hold **several public keys**: the current one first, then any being retired. Every key is held to the same rules
(signature, issuer, audience, lifetime, expiry); there is no relaxed mode for the old one.

1. **Before.** Only the old key is known.
2. **Overlap.** Put the new public key first and keep the old one after it. Restart Risk Guard. Tokens signed by either verify; by anyone else, never.
3. **Switch.** Have the gateway sign with the new key (restart it). Tokens now come from the new key; the old one still verifies, so nothing in flight is dropped.
4. **Retire.** Remove the old key from the file and restart Risk Guard. The old key's tokens are refused.

A file with an unreadable block, or none, is an error at start: Risk Guard does not start with fewer keys than it was given, and giving it
keys never enables the local-test fallback (a call without a token is refused).

**Drill.** `gateway_key_rotation_overlaps_then_retires_the_old_key_with_no_unverified_fallback` runs the four phases and checks each side of
each. It runs in CI. **It has not been run against the live cluster**: that would restart the gateway, and the deployed image predates the
multi-key support, so a live drill needs an image build and a Risk Guard redeploy first.

Not covered here: SPIRE's own rotation. SPIRE rotates SVIDs automatically and republishes its trust bundle (`spire-bundle`), which Risk
Guard polls; that was observed working but not forced as part of this drill.
