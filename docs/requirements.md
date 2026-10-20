# OpenShell Behavioral Risk Guard: Requirements

Status: implemented and running against a real OpenShell gateway, supervisor and sandbox in the local demo; see the [README](../README.md).
Detection results come from synthetic corpora, so accuracy on real traffic remains to be validated.
Audience: OpenShell maintainers and implementers.
Reference checkout: `55bf786453395f3fe1858a187152537b457de77d`.

Companion documents:

- [System design](design.md)
- [Anomaly detection and evaluation](anomaly-detection.md)
- [Sidecar implementation & presenter README](../README.md)

## 1. Purpose and value hypothesis

OpenShell authorizes agent activity using declared policy. An authorized request
can still be inappropriate in its current context: for example, an agent that
normally reads repository metadata attempts a destructive action against an
unfamiliar repository.

The proposed operator-run service adds behavioral risk evaluation at OpenShell's
existing HTTP middleware boundary. It does not replace OpenShell authorization,
forward traffic itself, or introduce another policy language for network access.

The value hypothesis is falsifiable:

> Contextual, explainable behavioral signals can identify useful cases of
> suspicious-but-authorized activity, with acceptably low false-denial rates and
> bounded overhead, beyond what the configured static policy already blocks.

This is an application of established conditional-access principles, not a claim
of inventing anomaly detection or a new security category. "Best in class" is an
aspiration requiring comparative evidence, not a product claim.

## 2. Users and primary workflow

### Operational truthfulness requirements

- Workload ID MUST be durable across runs and sandbox instances and MUST be issued
  by the trusted operator path, not a claim made by the sandboxed process.
- Comparable runs for the same agent/revision/task/baseline/detector/mode MUST
  share temporal scoring and restriction state. Sandbox rotation or a new run
  MUST NOT reset that state.
- Different workload IDs and incompatible contexts MUST remain isolated.
  Context changes MUST NOT alter historical decision attribution.
- Each run-to-sandbox binding MUST be explicit and immutable. Binding an epoch
  with prior decisions MUST be rejected rather than rewriting its history.
- Operational middleware MUST require a trusted binding by default. An explicit
  legacy compatibility mode MUST NOT permit previously bound sandboxes to evade
  attribution by rotating their execution epoch.
- The primary UI MUST follow workload ID across run and sandbox history, while
  preserving sandbox-level policy/coverage provenance and unknown outcomes.

- Operational startup MUST NOT seed fixture baselines or silently assign a
  fabricated baseline hash to an unknown task profile.
- The operator MUST provision approved baseline artifacts explicitly. Imported
  approver metadata is local-operator attestation, not a cryptographic signature.
- The operational dashboard MUST be read-only and independent of scenario
  generation, test token issuers and proxy-generated workload identities.
- Inventory MUST identify governed epochs without equating them to running
  sandboxes. Native lifecycle and gateway connectivity remain unknown until
  separately collected and reconciled.
- Request scores MUST NOT be presented as sandbox compromise probabilities.
  Scoped request restrictions MUST NOT be presented as whole-sandbox quarantine.
- Evidence MUST preserve missing context and unknown upstream outcomes. The
  current schema does not attest whether persisted evaluations originated from
  native supervisors, the offline CLI or the synthetic harness.
- A native deployment acceptance test MUST create actual OpenShell sandboxes,
  execute workload traffic through their supervisors, correlate decisions with
  authenticated sandbox identity, and verify denied application effects at a
  controlled upstream. Docker container names and direct gRPC tests are not
  substitutes.

Primary user: an operator responsible for agents running in OpenShell sandboxes.

1. The operator defines a task profile, approved resources, and initial policy.
2. OpenShell admits a supported request to a selected middleware binding.
3. The service compares available request context with a trusted baseline.
4. The service allows, alerts, or denies according to configured risk policy.
5. The operator receives a correlated explanation without credentials or bodies.
6. After a configured observation interval, the service recommends narrower
   policies with evidence, limitations, and containment-check results.
7. No recommendation changes OpenShell policy automatically.

Task descriptions or authorization claims supplied by an in-sandbox agent are
untrusted. An agent cannot approve its own baseline, exceptions, or training data.

## 3. Explicit scope

### Demo and first implementation

- One pinned OpenShell revision and a tested Linux runtime configuration.
- Single Rust sidecar binary exposing `SupervisorMiddleware` (`PRE_CREDENTIALS` data-plane gate) and optional `GatewayInterceptor` (control-plane policy/epoch guard).
- REST requests on explicitly selected, inspectable HTTP/S endpoints.
- Destination, method, path-derived resource, available executable identity, velocity/fan-out, and policy-derived credential-bearing endpoint status (`credential_binding` / `_provider_*` scope).
- Deterministic risk rules plus interpretable behavioral statistics with interaction terms.
- Frozen, operator-approved task baselines and a Two-Tier Monotonic Ratchet.
- Allow-with-observation and deny (`behavioral_risk_denied`) outcomes; observe and enforce deployments; quarantined denial records for operator review.
- Durable, versioned decisions and hardening recommendations verified via a Two-Step Containment Proof (`network_middlewares` invariance + `openshell-prover` Z3 check).
- Controlled local upstream fixtures rather than destructive real services.

### Explicit non-claims and trust boundaries

- Not a replacement for OpenShell's kernel/proxy enforcement or a claim of universal mediation across non-HTTP protocols (raw TCP, SSH, opaque tunnels, local filesystem, or stdio MCP).
- Does not inspect raw secret values at `PRE_CREDENTIALS`; credential risk uses policy-level credential-binding metadata only.
- Does not pause in-flight HTTP requests for synchronous human prompts (which would violate middleware sub-second timeouts); human review operates via immediate fail-closed denial (`behavioral_risk_denied`) into an operator review queue.
- Does not auto-train on unreviewed live traffic or auto-apply policy recommendations.

## 4. Safety invariants and monotonic ratchet semantics

Two formal properties govern the sidecar:

**1. Data-Plane Authorization Attenuation:** for all inspected requests $a$, the risk gate cannot override an OpenShell denial:

$$\text{FinalAllow}(a) = \text{OpenShellAllow}(a) \land \text{RiskPermit}(a)$$

Configuration forbids request body/header mutations (FR-01) and binds the middleware with `on_error: fail_closed` on protected endpoints.

**2. Two-Tier Monotonic Ratchet (Resolved Decision D-01):** let $E_t$ be the set of effectively permitted actions in policy epoch $e$ at step $t$. To guarantee monotonic tightening on consequential risks without permanently bricking an agent on a transient read burst, enforcement uses a deterministic two-tier ratchet:

- **Tier 1 — High-Impact & Task-Constraint Denials ($I = 1$ or `task_constraint`):** **Strict Epoch Ratchet.** When an action $a$ involving a high-impact operation or explicit task-constraint violation is denied in enforce mode, its normalized `(host, port, method, resource_scope)` is durably inserted into the epoch's immutable `restrictions` ledger ($R_{t+1} = R_t \cup \{\text{scope}(a)\}$). It cannot be cleared by retries, cooldowns, or service restarts for the remainder of the epoch. Restoring or broadening access requires terminating the epoch and explicitly authorizing a new epoch.
- **Tier 2 — Pure Velocity / Fan-Out Anomalies ($I = 0$, triggered by rate $V$ or enumeration fan-out $F$):** **Bounded Cooldown Window.** Denies requests during a configurable cooldown window (`cooldown_until_ms`) without permanently latching read paths, *unless* repeated cooldown triggers reach the epoch strike limit (default: 3 cooldown episodes), which escalates the scope into the Tier 1 permanent `restrictions` ledger.
- **Control-Plane Monotonicity (when `GatewayInterceptor` is enabled):** Intercepts `CreateSandbox`, `UpdateConfig`, `ApproveDraftChunk`, `ApproveAllDraftChunks`, and `SubmitPolicyAnalysis` in `VALIDATE` phase to ensure the `risk-guard` middleware binding is never removed, `proposal_approval_mode=auto` is blocked on governed sandboxes, and any in-epoch policy update satisfies the Two-Step Containment Proof ($E_{\text{new}} \subseteq E_{\text{current}}$).

## 5. Functional requirements

| ID | Requirement | Acceptance evidence |
|---|---|---|
| FR-01 | Use the existing middleware interface and return no body/header mutations. | Contract tests assert empty mutations and no replacement body. |
| FR-02 | Evaluate only authenticated supervisor requests; bind state to configured gateway identity and authenticated sandbox ID. | Cross-sandbox, wrong-audience, and context/token mismatch tests reject requests. |
| FR-03 | Use immutable sandbox IDs, not reusable sandbox names or PIDs, for durable identity. | Name reuse and PID reuse tests show no baseline inheritance. |
| FR-04 | Record normalized features, signal contributions, decision, and baseline/detector/config versions. | A recorded case can be deterministically replayed to the same result. |
| FR-05 | Treat unknown process identity, unknown resource semantics, and immature baselines explicitly. | Dedicated unknown/cold-start cases never silently become trusted history. |
| FR-06 | Support observe and enforce modes with the selected mode in every decision. | Observe alerts but allows; enforce blocks the designated high-risk fixture. |
| FR-07 | Distinguish static high-impact safeguards from learned behavioral evidence. | Explanations identify which rule supplied each contribution. |
| FR-08 | Use frozen approved baselines; quarantine new observations for later review. | Attack traffic and repeated retries cannot promote themselves into normal behavior. |
| FR-09 | Handle duplicates and concurrent requests without double-counting evidence. | Duplicate and parallel replay tests; documented bounded deduplication window. |
| FR-10 | Generate recommendations after a configurable observation interval. | Report includes interval, data completeness, support counts, and affected resources. |
| FR-11 | Recommendations remain unapplied and include a candidate diff and review status. | Before/after effective-policy hashes remain unchanged during report generation. |
| FR-12 | Verify hardening recommendations with the Two-Step Containment Proof (`network_middlewares` invariance + `openshell-prover` Z3 check on the middleware-stripped projection). | `Within` requires both steps to pass; exceeds, unsupported, inconclusive, and error never appear as verified-safe. |
| FR-13 | Explain decisions in service-owned audit records correlated with OpenShell request IDs. | Demo joins supervisor event, service decision, and fixture observation. |
| FR-14 | Durably commit Tier 1 epoch restrictions and Tier 2 cooldown state before returning the corresponding deny. | Crash/restart tests retain restrictions and strike counts; persistence failure fails closed. |
| FR-15 | Use service-owned SQLite for risk state; access OpenShell context through authorized APIs or `GatewayInterceptor`, never its internal database. | Deployment has no gateway database mount or connection; API permissions are tested separately from extension authentication. |
| FR-16 | Track active policy revisions synchronously via `GatewayInterceptor` (`POST_COMMIT`) when enabled, or label SDK-polled policy snapshots as asynchronous context in middleware-only mode. | Decision records distinguish interceptor-synchronized policy revisions from asynchronously polled snapshots. |
| FR-17 | Track observation coverage and source gaps explicitly. | Watch lag, expired cursors, service outages, and unsupported routes appear in recommendation evidence. |
| FR-18 | Reuse OpenShell `SupervisorMiddleware`, `GatewayInterceptor`, generated contracts, SDK, policy helpers, and prover where their documented semantics apply. | Integration tests establish each reused surface; unsupported hardening operations are not disguised as addition-oriented draft chunks. |

## 6. Operational and privacy requirements

| ID | Requirement |
|---|---|
| NFR-01 | Bound concurrency, input sizes, state cardinality, queues, and retention. Exhaustion is visible and cannot cause unbounded allocation. |
| NFR-02 | Use authenticated TLS for the team-facing integration. Plaintext is allowed only for isolated local contract tests and labeled as such. |
| NFR-03 | Validate signature, issuer, audience, token type, lifetime, caller kind, and sandbox binding using provisioned trust. |
| NFR-04 | Do not persist request bodies, raw queries, headers, tokens, or credential values. Scrub errors and test diagnostic output for leakage. |
| NFR-05 | Protect resource identifiers as potentially sensitive; use approved templates, keyed identifiers, or access-controlled redacted displays. |
| NFR-06 | Configure `fail_closed` for the protected enforce-mode binding. Test timeout, crash, oversized body, malformed response, and registration mismatch. |
| NFR-07 | Report readiness only after configuration, trust, state schema, and baseline artifacts are valid. No permissive empty baseline on corruption. |
| NFR-08 | Use a monotonic clock for windows/deadlines and UTC timestamps for audit. Reject future or inconsistent training timestamps. |
| NFR-09 | Do not put request IDs, raw paths, sandbox IDs, or resource names in unbounded metric labels. |
| NFR-10 | Document unsupported policy shapes and middleware coverage gaps before deployment; no hidden "protected" status. |
| NFR-11 | Store state and decision evidence on persistent storage with migrations, integrity checks, access controls, and explicit retention. |
| NFR-12 | Use SQLite WAL and `synchronous=FULL` for acknowledged decision/restriction transactions; enable foreign keys on each connection. |
| NFR-13 | Keep decision, deduplication, window updates, sequence, and strict restrictions atomic. A failed commit must not return a successful evaluation. |
| NFR-14 | Bound writer queues and lock waits within the request deadline; benchmark actual durable commits, not memory-only scoring. |
| NFR-15 | Protect the database, WAL files, backups, and identifier keys. Hashing alone does not establish authenticity or prevent administrative rollback. |
| NFR-16 | Test consistent backup/restore and migrations. Do not reopen an existing strict epoch from a stale backup without trusted freshness evidence. |
| NFR-17 | Preserve explicit window uncertainty after restart or clock discontinuity; never reset persistent restrictions to recover availability. |

An observe deployment may deliberately continue on middleware errors, but must
be labeled detection-only. It is not evidence that enforcement is fail-closed.
Failure denial is an availability tradeoff, not a successful anomaly detection.

### Data ownership and retention

OpenShell remains the system of record for sandbox identity, declared/effective
authorization, credentials, policy revisions, and load status. Our service owns
approved behavioral artifacts, risk decisions, temporal features, restrictions,
coverage evidence, and recommendation records.

Follow the [storage design](design.md#71-storage-decision-independent-sqlite-not-the-gateway-database)
for schema, constraints, durability, and retention. Initial defaults are 30 days
for detailed decisions/deduplication, 90 days for coverage/usage aggregates, and
the active lifetime plus 90 days for epochs, restrictions, and linked artifacts.
Never expire referenced evidence while a live restriction or retained report
depends on it. Recommendation intervals cannot exceed available evidence
without explicitly declaring the missing coverage.

Anonymous activity counters are not behavioral training data. Endpoint status
is a latest-result observation, not ordered action history. Log-watch replay is
bounded and can be lost; only committed service decisions form our primary
evaluation history, and those still do not prove upstream action success.

## 7. Measurable release gates

These are proposed predeclared targets, not measured results. Change them only
through a recorded review before unblinding the final evaluation set.

| Gate | Initial target and measurement |
|---|---|
| G-01 Enforcement | Every designated denied request has zero corresponding application requests at the fixture upstream. Test allows and baseline denials too. |
| G-02 Benign impact | One-sided 95% upper bound on false-denied benign sessions <= 1%, using at least 300 held-out independent session groups. Publish actual counts and clustering limitations. |
| G-03 Detection | >= 90% episode recall on the predeclared supported misuse suite, at least 100 episodes, with per-scenario breakdown and confidence intervals. No universal detection claim. |
| G-04 Useful alerts | >= 80% precision on the explicitly declared evaluation mixture. Also report false alerts per 1,000 benign requests and per benign session; precision depends on prevalence. |
| G-05 Incremental value | Compare static-only, novelty-only, and contextual detection at matched benign false-denial budgets. Publish null or negative improvements. |
| G-06 Latency | Added end-to-end p95 <= 25 ms and p99 <= 75 ms at 100 requests/s, 20 concurrent clients, warm state, <= 16 KiB bodies. Report hardware, TLS, durability, errors, and saturation curves. |
| G-07 Deadline | Configure a tested middleware timeout, initially 200 ms subject to OpenShell validation; service deadline budget <= 100 ms including queue and durable state work. |
| G-08 Replay | Identical versioned inputs and initial state yield identical decisions; parallel execution preserves documented serialization semantics. |
| G-09 Hardening | Every report declares completeness and proof status; no automatic policy writes; known task tests remain replayable. |
| G-10 Reliability | Fault suite has explicit outcomes for restarts, duplicates, state corruption, full disk, stale baselines, and service disconnection. |
| G-11 Storage | Tests verify configured WAL/FULL/foreign-key settings, transaction atomicity, retention references, bounded contention, migrations, and consistent restore. No stale restore resumes a strict epoch without freshness validation. |
| G-12 Evidence & Proof | Gap injection and delayed policy polling never produce a complete-history claim. Unprojected middleware policies return `unsupported` as expected, while the Two-Step Containment Proof (`network_middlewares` invariance + projected `openshell-prover` check) proves `within_boundary` on narrowed policies. |

*Note on synthetic evaluation:* Synthetic fixtures verify functional and regression gates (G-01, G-06..G-12); statistical detection claims (G-02..G-05) report exact sample sizes, clustering assumptions, and confidence intervals.

## 8. Demo acceptance sequence

1. Show the deliberately broad static policy and why each test action is allowed by OpenShell alone.
2. Create a governed sandbox; show `GatewayInterceptor` binding the initial epoch and verifying the `risk-guard` middleware attachment.
3. Run a benign task against an instrumented local API and inspect the approved baseline artifact.
4. Run legitimate novelty (new harmless read resource, normal task transition) and verify `DECISION_ALLOW` with explainable low score ($S < 70$).
5. Run the flagship suspicious-but-authorized attack (expected binary performing a destructive `DELETE`/`POST` on an unfamiliar credentialed repo) and show `DECISION_DENY` ($S = 85 \ge 70$) with zero upstream hit.
6. Retry the denied scope and show it is permanently latched in the Tier 1 `restrictions` ledger, even after restarting the sidecar process.
7. Show an OpenShell-denied action cannot be rescued by middleware allow.
8. Kill or delay the sidecar and verify `on_error: fail_closed` blocks protected traffic.
9. Attempt an unauthorized policy broadening via `openshell policy update` and show `GatewayInterceptor` rejecting it in `VALIDATE` phase.
10. Generate a periodic hardening report with a narrowed YAML diff and a passing Two-Step Containment Proof (`within_boundary`), while verifying live policy remains unchanged until operator authorization.

## 9. Delivery boundaries

Phase A: contract integration, authentication, controlled upstream, replayable
decisions, and failure tests.

Phase B: contextual detection, approved baselines, held-out evaluation, and
performance tests.

Phase C: recommendation-only hardening, coverage reporting, reproducible demo,
and maintainer-facing limitations.

Do not prioritize a dashboard, learned embedding model, or broad protocol support
before these gates are met. There is no code-completion claim until the evidence
above exists.

## 10. Code-grounded references

- [Middleware protocol and request context](https://github.com/NVIDIA/OpenShell/blob/main/proto/supervisor_middleware.proto)
- [Gateway interceptor protocol](https://github.com/NVIDIA/OpenShell/blob/main/proto/gateway_interceptor.proto)
- [Interceptable control-plane routes](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-gateway-interceptors/src/routes.rs)
- [REST relay policy-to-middleware path](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-supervisor-network/src/l7/relay.rs)
- [Middleware buffering and failure handling](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-supervisor-network/src/l7/middleware.rs)
- [Research-preview middleware example](https://github.com/NVIDIA/OpenShell/blob/main/examples/supervisor-middleware-content-guard/README.md)
- [Governance interceptor example](https://github.com/NVIDIA/OpenShell/blob/main/examples/governance-interceptor/README.md)
- [Extension authentication contract](https://github.com/NVIDIA/OpenShell/blob/main/rfc/0009-supervisor-middleware/appendices/extension-authentication.md)
- [Policy advisor scope](https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/policies/advisor.mdx)
- [Policy prover and coverage](https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/policies/prover.mdx)
