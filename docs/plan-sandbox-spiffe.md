# Plan: SPIFFE identity per sandbox, and a full-request gate on the network path

Status (22 October 2026, end of day): **phases 1, 2 and 3 done and verified live. Phase 4 was built as a smaller, different thing (approved egress hosts
at the tunnel gate; the intercepting proxy was designed and not built, with reasons below). Phase 5 partly done** (fail-closed drill for the egress proxy,
fleet rate-limit fix, first-offence measurement started at 20:24 UTC with a small first result: 5 of 5 first offences refused, none carried over, far too
few to quote). **Phase 6 partly done** (How it works page, architecture and identity docs). Still open: a longer first-offence run, drills for the sandbox
tunnel gate and SPIRE outages, the demo runbook and slides. Written 22 October 2026 against OpenShell `main` (`ea13dfc`, after v0.1.5) and the commit this repository
pins (`55bf786`). Everything marked **verified** was read in OpenShell's documentation, chart or source; nothing here has been run on
the cluster yet.

## 1. Goal, and what "done" means

Today each OpenShell sandbox is identified to Risk Guard by the gateway (a token bound to the sandbox's Kubernetes UID and pod UID) and,
at the network gate, by its pod address. The goal is to:

1. give **every sandbox its own SPIFFE identity**, issued by SPIRE through OpenShell's own support, and show it doing real work;
2. make Risk Guard **record and display that identity** for every sandbox, honestly labelled;
3. (stretch) give real sandboxes a **full-request gate** on the network path, so a method and path are visible to Risk Guard outside
   the supervisor;
4. leave the project **robust enough to present**: every claim backed by a test, a measurement or a clearly stated limit.

"Done" is the acceptance criteria in section 4, not the code.

## 2. What is known, and what is not

| Fact | Status |
|---|---|
| OpenShell mounts a SPIFFE Workload API socket into gateway and sandbox pods (`provider_spiffe_workload_api_socket_path`) | verified (docs, chart `ci/values-spire.yaml`) |
| The supervisor fetches a JWT-SVID and exchanges it for short-lived upstream tokens (provider token grants) | verified (docs `kubernetes/access-control`, `providers/profiles`; source `token_grant.rs`) |
| OpenShell ships a SPIRE overlay that names sandbox pods by `openshell.ai/sandbox-id` | verified (docs) |
| Supervisor-to-gateway auth stays on projected ServiceAccount tokens and gateway-minted sandbox JWTs, bound to the sandbox and pod UIDs | verified (docs) |
| `upstreamProxy` supports `http://` and `https://` proxies, Basic authentication, and a CA bundle for a **TLS-intercepting proxy** | verified (chart values, docs) |
| The proxy hop presents no client certificate and no SPIFFE identity | **inferred** from the available options (URL, Basic auth, CA bundle); source not read line by line |
| SPIFFE X.509-SVID trust for extension services (Risk Guard) | "future" per `openshell-extension-core` README |
| The supervisor pods mount the SPIRE socket in our Kata setup | **unknown** (step 1 settles it) |
| The CONNECT target is an IP address, not a hostname, unless `connectByHostname` is set | verified (docs); matters for a proxy that decides on host |
| A TLS-intercepting proxy sees credentials the supervisor injected after Risk Guard's check | **reasoned**, not tested; treat as true |

## 3. Phases

Each phase ends in something that works and can be shown, so the project can stop after any of them. Effort is a rough estimate for
one person; the live cluster work is the slow part.

### Phase 1 — Spike: does the mechanism work here? (0.5 day)

* Add `provider_spiffe_workload_api_socket_path` to the gateway through a values overlay; restart the gateway.
* Confirm the supervisor and sandbox pods mount the socket (`kubectl describe pod`), and that Kata sandboxes still start.
* Add one `ClusterSPIFFEID` for supervisor pods (class `openshell-spire`, selector on `openshell.ai/component=supervisor`,
  template `spiffe://<domain>/ns/openshell/sandbox/{{ index .PodMeta.Labels "openshell.ai/sandbox-id" }}`) and confirm SPIRE creates one
  entry per supervisor pod.
* **Exit:** entries exist per sandbox; no fleet run fails. **Stop and re-plan if** the socket cannot be mounted, the fleet breaks, or
  the entry cannot be derived from the label.
* **Rollback:** helm upgrade with the value removed; delete the ClusterSPIFFEID.

### Phase 2 — The identity does real work (1–1.5 days)

* Deploy a token issuer that validates JWT-SVIDs against the SPIRE bundle and returns a short-lived token for a demo API (adapt
  OpenShell's `examples/spiffe-token-grant-demo`).
* Add a provider profile with a `token_grant` for that API and attach it to a fleet agent.
* The agent calls the API with no stored secret; the supervisor injects the token.
* **Exit:** a fleet run calls the API successfully through the grant; a sandbox without the profile cannot; the issuer logs the SPIFFE
  ID it accepted. Risk Guard scores the calls like any others.
* **Risk:** the grant needs a provider profile format we have not used; budget time for it. If it fights back, show the SVID being
  issued and fall back to Phase 3 alone.

### Phase 3 — Risk Guard records and shows the identity (1 day)

* Derive each sandbox's SPIFFE ID from the same convention and store it with the sandbox record (a nullable column, migrated in place).
* Show it in the console (sandbox and workload detail), in `/api/state`, and in the tunnel-gate log line.
* Label it **"assigned by SPIRE"**. Do not show it as "verified" or "presented": Risk Guard does not receive the certificate.
* Optional hardening: cross-check at the tunnel gate that the source pod carries the expected label *and* that a SPIRE entry exists
  for it. Needs read access to SPIRE entries; only do it if that access is cheap and least-privilege (decide after phase 1).
* **Exit:** every live sandbox shows its SPIFFE ID; a test covers the derivation and the migration.

### Phase 4 — outcome (22 October 2026): built a different, smaller thing

**What was built:** approved egress hosts per task, enforced at the tunnel gate (`approved_egress_hosts`, rule `egress_destination`, shadow by
default), with OpenShell sending hostnames (`connectByHostname`) and a network policy that keeps the proxy off the cluster network.
**What was not built, and why:** the TLS-intercepting proxy below. Designing it showed that it would see only the calls to the hosted model
(the task APIs are plain HTTP inside the cluster and never go through the upstream proxy), and that it would hold the model API key.
See "Why not a TLS-intercepting proxy" in `workload-identity.md`. The original plan text follows.

### Phase 4 (as planned) — A full-request gate for sandboxes (stretch; 3–4 days)

* Replace the Envoy tunnel gate for sandboxes with a TLS-intercepting proxy (mitmproxy, or squid ssl-bump) whose CA is staged through
  `upstreamProxy.caBundle`. Envoy cannot mint certificates for arbitrary hosts, so it stays only for the SPIFFE demo workloads.
* The proxy asks Risk Guard per request (method, host, path), through a small addition to the SVID listener, and returns 403 on deny.
  Reuse `Check`; the proxy needs a gRPC client or a thin HTTP shim in front of it.
* Keep the quarantine and unknown-sandbox rules from the tunnel gate; add the per-request decision on top.
* **Security work that is part of the phase, not an extra:**
  * The proxy sees real credentials the supervisor injected. Run it in its own namespace with no logging of headers, no body capture,
    a read-only filesystem, and a network policy that lets only the gateway-chained supervisors reach it. Document the exposure.
  * Fail closed, and test it.
  * The CA private key is a high-value secret: store it as a Kubernetes Secret with narrow access, and plan rotation.
* **Exit:** a destructive request from a real fleet sandbox is refused by the proxy with the path visible in the decision; routine
  traffic still flows; latency overhead measured; the exposure is written down.
* **Cut line:** if phases 1–3 take longer than planned, skip this and present it as the designed next step.

### Phase 5 — Make it robust (1–1.5 days, partly overlapping)

* Failure tests, each automated where possible and otherwise a scripted drill: proxy down, Risk Guard down, SPIRE server down, SVID
  expiry and rotation mid-run, trust-bundle rotation, a sandbox with no entry, an address reused by a new pod.
* Measure: decision time through the new gate, and the end-to-end overhead on a fleet run.
* Detection: re-run the live measurement with **first-offence and repeat attempts reported separately**, since most "blocked" calls were
  restriction carry-over.
* A rollback runbook per phase; `-Remove` paths for every script.
* CI: add the new tests and the manifest checks (YAML parses, scripts parse).

### Phase 6 — Meeting readiness (1 day)

* A timed demo runbook with a fallback for each step, and a short recorded run as a backup.
* Slides built from the architecture page and this plan.
* Updated screenshots; the "How it works" page rewritten (section 6).
* A list of questions for NVIDIA (section 7).
* A fresh-machine walk-through of the getting-started guide by someone else.

## 4. Acceptance criteria

1. Every live sandbox has a SPIRE entry, and Risk Guard shows its SPIFFE ID labelled "assigned".
2. At least one fleet agent uses a SPIFFE-backed token grant with no stored secret, and the issuer logs the accepted identity.
3. Turning each new feature off restores the previous behaviour, and the fleet keeps running through the change.
4. If phase 4 is built: a destructive sandbox request is refused at the proxy with its path in the evidence; routine traffic is unaffected;
   added latency is measured and stated; the credential exposure is documented.
5. No claim in the docs or slides lacks a test, a measurement, or an explicit "not verified" next to it.
6. CI is green; the tests for new code pass without relying on the live cluster.

## 5. What it means for the solution

| | Now | After phases 1–3 | After phase 4 |
|---|---|---|---|
| Sandbox identity at Risk Guard | Gateway token bound to the sandbox's pod; address at the tunnel | The same, plus a SPIFFE ID per sandbox, recorded and shown | The same |
| Credentials in the sandbox | Provider credentials injected by the supervisor | Can be replaced by SPIFFE-backed short-lived grants for chosen APIs | The same |
| Enforcement visible to Risk Guard | Per-request in the supervisor; destination only at the tunnel | The same | Per-request on the network path as well |
| If the supervisor is compromised | Gate 3 stops only quarantined workloads | The same | Gate 3 sees and can refuse each request |
| Trust placed in Risk Guard's side | Never sees secrets | Never sees secrets | **The proxy sees injected secrets**, a new trust boundary |
| What we can say to NVIDIA | A reference integration beside OpenShell | It uses OpenShell's SPIFFE support end to end | It shows what a request-level network gate adds, and the exposure it costs |

What does not change: Risk Guard still only adds denials, never permits; scoring is still rule-based over learned statistics; there is
still one SQLite writer; detection is still measured on the author's own agents; and none of this is the hardware isolation Sentry
provides.

The main thing to be honest about in the meeting is the gap that remains in every column: **the proxy hop cannot yet authenticate
the sandbox cryptographically.** The project works around it (pod address) and says so; closing it needs OpenShell to present the
supervisor's SVID (or a token) to the upstream proxy.

## 6. Documentation changes

| Document | Change |
|---|---|
| `docs/workload-identity.md` | Reorganise around **Issued / Used / Presented**; add the SPIRE registration, the token-grant demo, the "assigned, not presented" wording, and the remaining gap |
| `docs/architecture.md` | Add SPIRE issuing to supervisors and the token-grant path; if phase 4 is built, replace gate 3 with the intercepting proxy and add the credential-exposure boundary and failure modes |
| `docs/positioning.md` | Update the workload-identity row and the "what would close the gap" paragraph; compare honestly with Sentry's SPIFFE integration |
| `README.md` | Limits: per-sandbox SPIFFE is issued by OpenShell's own support and recorded, not verified, by Risk Guard |
| Console **How it works** page | Add the tunnel/network gate step and the SPIFFE path, extend "Who is the workload?" with the three identity sources, add the new limits and live proof badges |
| `docs/detection-results.md` | First-offence versus repeat split; path-level results for sandboxes if phase 4 is built |
| `docs/aks.md` and `scripts/aks` | New scripts (SPIFFE for sandboxes, token-grant demo, intercepting proxy) with `-Remove` paths |
| `SECURITY.md` | The proxy's credential exposure and the CA key, if phase 4 is built |
| New: demo runbook | Timed script, fallbacks, expected output |

## 7. Questions to raise with NVIDIA

1. Will the supervisor present its SVID (or a token) to an upstream proxy, so a proxy can authenticate a sandbox rather than infer it
   from an address?
2. When will SPIFFE X.509-SVID trust be available for extension services such as Risk Guard?
3. For a TLS-intercepting upstream proxy, is there a way to keep injected credentials out of the proxy's view?
4. Is there interest in a standard per-request decision hook on the network path, beside the supervisor middleware?

## 8. Risks and decisions

| Risk | Mitigation | Decision needed |
|---|---|---|
| Enabling the SPIRE socket restarts the gateway and briefly breaks the fleet | Do it once, in a quiet moment; rollback ready | When to schedule |
| The grant needs a provider-profile format not yet used | Time-box; fall back to showing issuance only | — |
| The intercepting proxy exposes credentials | Dedicated, locked-down proxy; document it; keep it optional | **Whether to build phase 4 at all** |
| Running out of time | Phases are independent; phase 4 is the cut | The cut line |
| Cost of running the cluster | Teardown script kept ready | How long to keep it up |
| The claims drift from what is true | Section 4, item 5: no claim without evidence | — |
