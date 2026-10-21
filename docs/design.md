# OpenShell Behavioral Risk Guard: System Design

Status: implemented and running against a real OpenShell gateway in the local demo; see the [README](../README.md).
Reference checkout: `55bf786453395f3fe1858a187152537b457de77d`.

See [requirements](requirements.md) for scope, decisions, and release gates, and
[anomaly detection](anomaly-detection.md) for scoring and evidence standards.

## 1. Architectural decision and container sidecar topology

Implement a single operator-run Rust sidecar binary ([`openshell-risk-guard`](../README.md)) packaged as a non-root container image ([`Dockerfile`](../Dockerfile)) that exposes two native OpenShell gRPC extension services over a shared local SQLite state store:

1. **`SupervisorMiddleware` (`openshell.middleware.v1.SupervisorMiddleware`):** inline data-plane risk gate at `PRE_CREDENTIALS` for inspected HTTP/S requests.
2. **`GatewayInterceptor` (`openshell.gateway_interceptor.v1.GatewayInterceptor`, optional/modular):** control-plane lifecycle and policy-monotonicity guard across `CreateSandbox`, `DeleteSandbox`, `UpdateConfig`, `SubmitPolicyAnalysis`, `ApproveDraftChunk`, and `ApproveAllDraftChunks`.

OpenShell's [RFC 0009 Deployment Options](https://github.com/NVIDIA/OpenShell/blob/main/rfc/0009-supervisor-middleware/appendices/deployment-options.md)
supports externally managed endpoints; it does not require gateway co-location.
Co-location is our optional packaging choice. Both gateway and sandbox
supervisors must reach the actual endpoint, with trusted extension authentication.
Container names, shared networks and deployment templates alone do not prove
reachability, registration or enforcement.

### Operational view versus synthetic harness

`dashboard --db <existing-service-db>` serves a loopback-only, read-only view.
It reads persisted epochs and request evidence with bounded results and explicit
unknowns for gateway connectivity, sandbox lifecycle, event transport provenance
and upstream outcome. It cannot reset evidence, generate requests, or apply
native sandbox policies. Optional authenticated operator controls can save
versioned per-agent Risk Guard settings.
Queries use a SQLite read transaction for a consistent inventory or detail
snapshot. The current inventory is limited to active governed epochs, not the
OpenShell fleet; missing sandboxes and terminated-epoch history need separate
lifecycle reconciliation and historical views.

`demo-dashboard` retains the synthetic scenario harness for component exercises.
Its identity headers, test-issued tokens and proxy are not native supervisor
evidence. Operational commands do not call its fixture-seeding startup helper.
Approved baseline import is explicit and checked for normalizer compatibility.
Existing demo databases are not automatically converted into operational stores.

Behavior is represented at three levels: an individual request score, current
epoch's scoped restrictions, and baseline/coverage context. A score is neither
a calibrated compromise probability nor proof of malicious intent. Current
unknowns must not be replaced with invented route, process or lifecycle data.

### Operator console presentation

The embedded, offline console separates environment-level **Fleet overview** and
**Agents** from the selected agent's **Activity**, **Detections**,
**Recommendations**, **Runs**, and **Guardrails** tabs. Fleet overview is the
default entry point. Global headers do not inherit an agent's posture; time and
boundary controls appear only on the activity/detection views they filter.
Inventory totals remain bounded recorded totals, not a time-windowed fleet
analytics service.

The Graphite design uses neutral surfaces and selection states, system
sans-serif typography, and technical-content-only monospace. Muted red denotes
blocked decisions, amber denotes policy exposure, and desaturated green denotes
evidenced allow/verification states. Text and labels accompany color. Normal
text targets 4.5:1 contrast; map labels remain at least 12 rendered CSS pixels
at the default zoom. Tables, code, and the map scroll within their regions on
narrow layouts. Tabs, graph filters, and audit evidence support keyboard focus;
the audit modal returns focus to its opener.

Graph edges and counts derive from recorded network decisions. A permitted
request is not proof of upstream execution. Filesystem links visualize parsed
policy snapshots and never animate as file requests. Missing snapshots remain
unknown rather than acquiring example mounts. Gate counts cover loaded
decisions; the visible sandbox sample is labeled separately. Replay is
single-shot and explicitly historical, and new-evidence pulses are keyed by
request ID rather than a possibly capped list's length. Reduced motion disables
packets.

The existing filesystem posture heuristic is display-only guidance, not a
server-issued request score. Recommendations distinguish stored candidate and
proof records from illustrative filesystem guidance; missing proof is not a
successful verdict. Guardrail inputs load a SQLite-backed configuration, retain
unsaved drafts, and require explicit authenticated Save & apply. The visual
design itself does not change detector formulas, proof generation, or deployment
qualifications.

### Versioned operator guardrails

`agent_guardrail_revisions` is an append-only settings/audit ledger, with a
transactionally updated `agent_guardrail_heads` pointer. Saves validate the
complete typed document and use an expected revision for optimistic concurrency.
`decision_guardrail_revisions` links every affected decision to the exact
committed settings. Settings contain no operator authentication secret.

For authenticated agent-bound requests, the evaluator validates the original
immutable run binding and request idempotency first. It then loads a single
committed guardrail revision in the same SQLite decision transaction. Live
operator overrides select mode, thresholds, cooldown, expected resources/action
classes, the unfamiliar-high-impact constraint and statistical envelopes.
The original state owner, windows, restrictions and binding are not replaced.
The effective baseline artifact and a zero-contribution revision-provenance
signal make the decision reproducible without rewriting history.

Existing strict/cooldown restrictions are checked before new scoring and are not
cleared by configuration changes. Statistical maturity rules and explicit
forbidden-action constraints are preserved. Live task-profile reattribution is
not allowed: approved profile selection and filesystem settings are desired
configuration for new runs/sandboxes. A trusted new binding must match the saved
approved profile artifact, mode, and managed filesystem policy. Exported
next-run YAML retains `fail_closed`; sandbox creation resolves its approved
profile artifact and mode from the native middleware configuration.

Application status distinguishes saved Risk Guard configuration from observed
decision usage and recorded native policy matches. Filesystem mismatches require
a new sandbox; missing or invalid recorded policies are explicit unknowns, not
healthy/applied fallbacks. Runtime policy-load state remains uncollected.

The dashboard stays read-only by default. `--operator-token-file` explicitly
enables writes using a persistent private local token. Mutation requests require
a constant-time verified Bearer capability and exact same-origin headers;
ordinary page reads never disclose the token. The browser retains the unlocked
capability only in tab memory. When unlocked, operators can also clear active
restrictions from the UI (`POST /api/agents/{id}/restrictions/clear`), which
records the operator and reason in `restriction_clearances`. In addition, the
dashboard listener exposes `GET /metrics` in Prometheus text exposition format
(`openshell_risk_guard_*` gauges and counters for store health, agents, active
epochs, decision outcomes, active restrictions by tier, clearances, and adaptive
models). This is local-operator authorization rather than
production RBAC/SSO, and does not relax native gateway/supervisor authentication.

## 2. Verified integration surface and boundaries

### Curated adaptive detection

Migration `0004_adaptive_learning.sql` adds native provenance, opt-in capture
windows, frozen models and dataset membership, separate shadow/enforced heads,
per-decision assessments and an operator audit ledger. It shares the existing
SQLite transaction and trusted binding, without replacing scoring-context owners
or bypassing idempotency and pre-existing restrictions. Every successful new
native RPC evaluation records verified-vs-local-test provenance; historical and
CLI evidence stays explicitly unrecorded rather than becoming native training.

The optional authenticated Adaptive console and lifecycle API reuse the private
operator capability. Under **Automated Shadow Learning** (on by default for every
agent, pausable per agent), pristine single-sandbox runs enroll on their first native
request and auto-approve on run/epoch end only when every observation is a plain
allow and strictly read-only (`reviewed_by = "auto-clean-policy"`,
excluding `write_mutation` routes and `POST /graphql` because request bodies are
not inspected at `PRE_CREDENTIALS`), and automatically fit/update the active
shadow model (`shadow_model_id`). Flagged windows and manual captures wait for
human review. Operators pause or resume it per agent (`set_auto_learning`),
while **Enforce promotion** remains strictly
manual behind the 20-train / 5-holdout / 5-shadow gates. Models cannot grant
permissions; updates and rollback preserve existing containment. Exact guardrails
revision and authentication scope are part of model compatibility. Sparse
candidates remain shadow-only; algorithm support, chronological held-out replay
and fresh native shadow gates must pass.
See [adaptive detection](anomaly-detection.md#implemented-adaptive-network-layer-phase-1)
for qualification limits, source isolation and poisoning controls.

| Checkout evidence | Design consequence |
|---|---|
| `SupervisorMiddleware` has `Describe`, `ValidateConfig`, and `EvaluateHttpRequest`. | Implement manifest negotiation and strict config validation, not only the scoring endpoint. |
| `GatewayInterceptor` intercepts `CreateSandbox`, `UpdateConfig`, `SubmitPolicyAnalysis`, `ApproveDraftChunk`, and `ApproveAllDraftChunks` in `MODIFY_OPERATION`, `VALIDATE`, and `POST_COMMIT`. | Synchronize sandbox epochs and active policy snapshots at commit time and block control-plane policy broadening or removal of the risk middleware. |
| Request context contains sandbox ID, request ID, and optional process details. | Key identity on authenticated IDs; process context can be unknown. |
| Request target contains host, port, method, path, and query. | Use target metadata; ignore raw queries and bodies for v1 scoring/storage. |
| Evaluation occurs at `PRE_CREDENTIALS`. | Never inspect raw secret values; derive whether an endpoint is credential-bearing (`C = 1`) from the policy's `credential_binding` and `_provider_*` rules. |
| Result supports allow/deny, mutations, findings, metadata, and reason code. | Return only decision, `reason_code`, bounded diagnostics, and non-secret metadata; never mutate traffic. |
| External finding text is sanitized in platform audit output. | Own a detailed private audit stream; correlate rather than depend on custom platform-rendered text. |
| `openshell-prover` rejects policies with non-empty `network_middlewares`. | Use a Two-Step Containment Proof: verify `network_middlewares` invariance first, then run `check_within_boundary` on the middleware-stripped projection. |

The inspected REST relay evaluates L7 policy before the middleware chain for
that path. Integration tests verify both CONNECT/TLS and forward-HTTP paths.

## 3. Logical flow

```text
Control Plane (GatewayInterceptor):
  CreateSandbox / UpdateConfig / ApproveDraftChunk
      |--> VALIDATE: verify risk-guard middleware attached + Two-Step Containment Proof
      +--> POST_COMMIT: bind epoch + store exact policy_snapshot + credential-bearing endpoints

Data Plane (SupervisorMiddleware at PRE_CREDENTIALS):
  Workload HTTP/S request
      |
      v
  OpenShell L4 + L7 Rego authorization
      | deny -> existing OpenShell 403 policy_denied
      | allow on selected route
      v
  OpenShell PRE_CREDENTIALS middleware adapter
      |
      | authenticated gRPC (openshell-ext+jwt), bounded deadline
      v
  Risk Guard Sidecar
      | authenticate -> normalize -> check Tier 1/2 ratchet -> score -> commit SQLite tx
      |
      +-- deny (reason_code="behavioral_risk_denied") -> OpenShell rejects request (403)
      |                                               -> quarantined for operator review
      +-- allow -> OpenShell injects credentials (if any) and forwards upstream

Periodic Hardening Loop (Offline Reporter):
  Approved baseline + SQLite decisions + policy_snapshot
      -> synthesize narrower NetworkPolicyRule candidate
      -> Two-Step Containment Proof (middleware invariance + openshell-prover Z3 Within)
      -> operator review report (never auto-applied)
```

A transport connection reaching an upstream is not the same as the HTTP action
being executed. Denial tests must count application requests and effects at the
fixture, not merely TCP connections.

## 4. Trust and identity

### Workload ID (implemented ownership model)

For attributed operation, the workload ID is the durable behavioral key. It is either
derived from the authenticated `(workspace, principal)` of the creating call
(`--workload-from-principal`; operator and user callers only) or an operator label, which is an
assertion by an allowlisted principal. A workload is scoped to one workspace once derived,
auto-registered or registered with `--workspace`, and every binding attempt is audited with its
principal and workspace. A run
pins its agent, operator-declared revision, task profile, immutable baseline,
detector configuration and enforcement mode. Each sandbox execution epoch can
be bound to one run either through the trusted operator CLI (`run-create` ->
`CreateSandbox` -> `run-bind`) before any decisions, or, when explicitly enabled,
via `GatewayInterceptor` (`POST_COMMIT`) from the `openshell.nvidia.com/agent-id`
annotation (plus optional `openshell.nvidia.com/agent-revision` and
`openshell.nvidia.com/run-id`). The annotation is honored only for an allowlisted
`operator`/`user` principal, never auto-registers an unknown agent unless
`--auto-register-agents` is set, and cannot attach a sandbox to a run owned by a
different workload or revision; creating a sandbox with these annotations as anyone else
is refused in `VALIDATE`. When
`DeleteSandbox` commits (`POST_COMMIT`), `GatewayInterceptor` automatically
closes the sandbox epoch and ends the bound run, triggering automatic read-only
capture approval and shadow model fitting without manual CLI intervention.
One run may span multiple sandboxes, and successive runs reuse the same scoring
context when all pinned dimensions match.

The additive [agent migration](../migrations/0002_agent_identity.sql)
introduces `agents`, `scoring_contexts`, `agent_runs`, `epoch_bindings`,
`identity_required_sandboxes`, `decision_identity`, `agent_window_buckets` and
`agent_restrictions` and `agent_restriction_origins`. Restriction origins record
both request and execution epoch so equal request IDs in different sandboxes
cannot make the triggering evidence ambiguous.
Legacy decision JSON and epoch-owned state are not rewritten.
Identity is joined through immutable bindings, not inferred from names or
retroactively attached to existing traffic.

The state-owner resolver selects exactly one owner per evaluation:

- Bound traffic: agent scoring context owns temporal windows, fan-out sets,
  cooldown strikes and restrictions across runs and sandbox replacements.
- Legacy traffic: the original epoch owns its state and is explicitly unattributed.
- Both: the execution epoch retains request identity, deduplication, sequencing,
  policy/credential context and coverage provenance.

The SQLite immediate transaction resolves the binding, checks authenticated
gateway ownership, rejects ended runs/configuration drift, checks deduplication,
scores using the shared pre-event window, and commits state plus decision
attribution together. Concurrent sandboxes cannot independently reset counters.
The service does not average request scores into a lifetime compromise probability.

`serve` requires agent attribution by default; `--allow-unattributed` is a
deliberate compatibility mode. A previously bound sandbox cannot silently fall
back to legacy state after an epoch rotation, even in compatibility mode.
Policy-only updates preserve shared history. Ending a run rejects new actions
but does not clear its agent context. Strict restrictions persist across run
boundaries; revision/profile/baseline/configuration changes create separate
operator-authorized contexts. Restrictions never expire or clear automatically;
`restriction-clear` is the explicit, audited operator exception and is copied to
`restriction_clearances` with operator, reason and the original trigger.

The UI is agent-first, with run history and sandbox bindings as execution
evidence. Its sandbox view remains an enforcement diagnostic, not the identity
root. Hardening recommendations remain scoped to their original sandbox policy.
The current release trusts local operator database access and does not provide
tenant RBAC, agent attestation, delegated task grants or cross-gateway federation.

This ownership model supersedes the per-epoch behavioral-state descriptions
below for agent-bound requests; those descriptions remain accurate for legacy
unattributed traffic.

Trust anchors:

- Operator-provisioned gateway identity, verification key/JWKS, service audience,
  and service TLS trust configuration.
- Operator-approved detector configuration, task/resource mappings, baselines,
  and baseline versions.
- Supervisor-generated identity context, bound to an authenticated caller.

Untrusted:

- Workload traffic, query/header/body content, agent-authored task labels.
- Claims that an action is "approved" embedded in request data.
- Arbitrary client-supplied sandbox IDs or names.
- Observed activity as training truth.

Follow OpenShell's extension authentication contract: verify EdDSA signature,
`typ`, issuer, exact audience, bounded lifetime, and caller kind. Evaluation must
require a supervisor token whose sandbox ID matches the request context. Authorize
gateway-only and supervisor-only RPCs deliberately; do not treat any valid token
as permission to call any method.

Provision first-contact verification keys through the trusted deployment path.
Do not bootstrap trust from an unauthenticated discovery response. Token `jti`
is not a per-request nonce: the OpenShell contract permits token reuse. Request
deduplication does not by itself provide cryptographic replay resistance.

Use authenticated gateway/sandbox identity to resolve the operator-owned run
binding. Agent context owns attributed behavioral state; execution epochs retain
policy and request provenance. Sandbox/workspace names are display labels.
PIDs are transient. Multi-agent attribution inside one sandbox is unsupported.

## 5. Service components

1. **Contract adapter:** negotiate protocol, validate registration/configuration,
   authenticate calls, impose input and deadline limits.
2. **Normalizer:** parse targets using explicit canonicalization rules; extract
   bounded features without retaining request content.
3. **Baseline registry:** load approved immutable artifacts and detect mismatched,
   stale, missing, or corrupt state.
4. **Detector:** deterministic feature evaluation against a versioned snapshot.
5. **Decision policy:** map evidence to observe/allow/deny using configured mode
   and the Two-Tier Monotonic Ratchet.
6. **Transactional state/audit store:** deduplicate, update temporal counters,
   persist Tier 1 restrictions and Tier 2 cooldowns, and append versioned decision evidence.
7. **Control-plane interceptor & offline reporter:** synchronize policy snapshots
   via `GatewayInterceptor`, enforce control-plane non-expansion, and generate
   prover-verified hardening candidates.

These can be modules in one executable. Do not create a microservice per module.

## 6. Evaluation algorithm

1. Authenticate and authorize the caller before accepting identity fields.
2. Reject invalid configuration, missing required context, or oversized input
   with a typed RPC failure; let the configured platform error policy apply.
3. Resolve the operator-owned epoch and feature/detector/baseline versions.
4. Normalize target/process fields. Preserve unknowns; do not invent defaults
   that look like successful identification.
5. Obtain a consistent per-identity state snapshot.
6. If a known request ID has the same fingerprint, return its committed result.
   If the ID is reused for a different fingerprint, reject and audit the conflict.
7. Evaluate persistent restrictions, hard safeguards, and behavioral evidence.
8. In one serialized transaction, commit decision evidence, dedup record, window
   updates, and new restrictions if strict mode requires them.
9. Return a bounded allow/deny result with no body or header mutations.

Score temporal features using history before this event, then update counters.
Retries with new request IDs remain new attempts; identical authenticated
evaluation retries within the configured deduplication window do not.

Do not hold a global database lock during network calls or model downloads.
No network calls, external LLM, or prover invocation are required to score a
request. Expensive offline work is isolated from request admission.

## 7. Data model and durability

| Record | Essential fields |
|---|---|
| Epoch | Gateway/sandbox ID, epoch ID, task profile, mode, creation time, active/terminated state |
| Baseline artifact | Version/hash, source sessions, approved-by identity, normalization version, support counts, validity interval |
| Decision | Request ID, identity, sequence, timestamp, normalized features, reason codes/contributions, score, threshold, outcome, all versions |
| Window state | Identity/feature key, bucket start, counts, cardinality summary, state sequence |
| Restriction | Epoch, normalized scope, triggering decision, created sequence, immutable status in strict mode |
| Recommendation | Input policy hashes, interval/completeness, candidate diff, replay evidence, proof result/coverage, pending review |

For the demo, use one writer authority and durable local transactions; configure
and benchmark the actual persistence settings. Acknowledge no allow/deny result
as durably recorded before the corresponding transaction commits.

On restart, restore epochs, restrictions, dedup records, and window state before
readiness. Corrupt or unavailable state fails closed in enforce mode; no empty
state reset. Bound storage and dedup retention explicitly. Beyond the retention
window, at-most-once evaluation cannot be promised.

Multi-replica deployment is deferred until shared state/ownership and linearized
per-identity updates are designed and tested. Sticky routing alone is not a
correct failover or concurrency protocol.

### 7.1 Storage decision: independent SQLite, not the gateway database

Use one service-owned SQLite database on persistent local storage for v1, with
SQLx migrations and typed queries following the Rust ecosystem already used by
OpenShell. No Redis, vector database, time-series service, or message broker is
required by the initial detector.

The inspected gateway supports SQLite and PostgreSQL. Its SQLite implementation
uses WAL and `synchronous=FULL` for authorization-sensitive durable writes,
including an explicit warning that `NORMAL` can lose acknowledged transactions
after a power/kernel failure. Adopt that reasoning for our decision/restriction
transactions; do not copy the relaxed pool without a separately justified use.

This is reuse of engineering patterns, not shared database ownership. The gateway
stores versioned protobuf objects and exposes public APIs; its durable storage
protocol explicitly says it is internal and not part of the SDK. Although its
Rust `Store` is exported, using it as an external database interface couples our
service to gateway schema, migrations, and authorization state unnecessarily.

Never mount, query, migrate, or write the gateway database from the risk service.
Do not fetch provider secrets merely to obtain metadata. Offline context reads
use separately authorized SDK/API credentials, not extension bearer tokens:
credentials that authenticate OpenShell to middleware are not general gateway
client credentials.

Deployment settings to verify in tests:

- WAL mode initialized before accepting work; `synchronous=FULL` on every
  authorization-sensitive writer connection, paired with a dedicated
  `PRAGMA query_only = ON` SQLite `WAL` read connection so dashboard, `/api/state`,
  and `/metrics` reads never block or contend with inline decision writes.
- Foreign keys enabled on every connection; prepared/bound SQL only.
- A bounded writer queue, explicit lock/deadline budgets, and short transactions,
  plus bounded `10,000`-decision retention pruning that preserves any decision rows
  referenced by adaptive training windows or active restriction triggers.
- Local durable volume, owner-only database/backup access, and protection for
  WAL/shared-memory files too. SQLite is not encrypted by default; use encrypted
  storage and keep key material outside the database.
- One owning service instance; no SQLite file shared across hosts/network storage.
- Monitored disk/WAL size, checkpoints, busy time, and commit latency. No slow
  report query may hold a read transaction indefinitely and grow the WAL.

At the measured single-writer capacity limit, first optimize bounded batching
and reporting isolation. Move to PostgreSQL only with a tested multi-replica
ownership/transaction model and evidence that the operational cost is justified.
OpenShell's PostgreSQL backend is useful prior art, not a reason to implement
two backends before the demo.

### 7.2 Proposed logical tables and constraints

These are design-level records, not a committed migration. Use relational keys
for identity/versioning and bounded schema-versioned JSON for explainable signal
payloads; do not hide queryable ownership/status in an opaque generic blob.

| Table | Key / role |
|---|---|
| `epochs` | Unique gateway/sandbox/epoch tuple; lifecycle, task profile, active baseline/config references, next sequence. One active epoch per governed sandbox in v1. |
| `artifacts` | Immutable content-addressed baseline, normalizer, detector, and decision-config payloads; type/version, approval provenance, integrity hash. |
| `decisions` | Unique epoch/request ID; input fingerprint, per-epoch sequence, action features, contributions, outcome, mode, artifact hashes, timestamps. This row is also the durable evaluation dedup record while retained. |
| `window_buckets` | Epoch/feature/window bucket key; bounded counts and exact bounded resource sets for v1. Cardinality overflow is explicit degraded evidence, not silently lost data. |
| `restrictions` | Epoch/scope key; tier (`strict_epoch` vs `cooldown`), `cooldown_until_ms`, `strike_count`, originating decision and sequence. Tier 1 rows are immutable for the active epoch. |
| `policy_snapshots` | Captured via `GatewayInterceptor` (`POST_COMMIT`) or SDK poll: source API, capture time, sandbox identity, base/effective classification, policy hash, extracted credential-bearing `(host, port)` set, and redacted payload. |
| `coverage_intervals` | Identity/source/time interval; service/route configuration, gap reason, optional watch cursor and stream-instance association. |
| `recommendations` | Immutable evidence/candidate versions, snapshot references, observation range, proof coverage/result, replay summary, review status. |

Indexes: unique `(epoch_id, request_id)` and `(epoch_id, sequence)`; chronological
decision paging by epoch; restriction lookup by epoch/scope; bucket expiry;
recommendation status and creation time. Foreign keys prevent orphan restrictions
and proof reports. Audit explanation templates must resolve to retained versions.

In a write transaction, lock/serialize the epoch state, resolve duplicate IDs,
read the pre-event window, compute a bounded deterministic score, then write
decision, counters, sequence, and any restriction atomically. No unbounded scans,
policy fetching, or filesystem artifact downloads occur inside this transaction.
An in-memory cache is optional and invalidated by committed versions; it is not
the authority for strict restrictions.

### 7.3 Evidence freshness and coverage

Although `SupervisorMiddleware.RequestContext` does not carry an effective policy hash, enabling `GatewayInterceptor` (`POST_COMMIT` on `CreateSandbox`, `UpdateConfig`, `ApproveDraftChunk`, and `ApproveAllDraftChunks`) lets the sidecar record every committed policy revision and extract its credential-bearing `(host, port)` set synchronously. When running in middleware-only mode without the gateway interceptor, policy snapshots are fetched via the SDK and tagged as asynchronous context rather than exact per-request authorization snapshots.

Use OpenShell policy status/history and sandbox status to distinguish persisted,
pending, failed, and loaded configuration. Historical policy revision content is
not automatically a complete provider-composed effective policy. Verify the
specific API projection before using a snapshot for hardening.

The SDK log watcher already supports reconnect and cursor resume. Reuse it for
operator correlation, but handle lag warnings and `OUT_OF_RANGE` as gaps.
Gateway log buffers are memory-backed; restarting or changing replica can
invalidate a cursor. Commit imported evidence and cursor progress together;
cursor resume does not transform the source into an infinite durable log.

Middleware decisions are the primary observation stream for the selected
requests. They are attempted evaluations, not proof of upstream execution.
OpenShell logs and endpoint status supplement them; neither can prove complete
coverage of every agent action. An outage or missing interval must invalidate
claims of complete usage during the affected recommendation interval.

### 7.4 Retention, restart, and recovery

Initial deployment defaults, to be validated against storage measurements:

- Detailed redacted decisions/dedup results: 30 days; documented duplicate
  protection ends at expiry. Never prune evidence still referenced by a live
  restriction or retained recommendation.
- Bounded rate/fan-out buckets: at least the longest configured window plus
  restart grace, initially 1 hour for 1-minute/15-minute windows.
- Coverage/usage aggregates: 90 days, without treating aggregation as training
  approval. Longer recommendation windows require matching retained evidence.
- Epochs, baseline/config versions, restrictions, and linked evidence: entire
  active lifetime, then 90 days after termination unless governance requires
  longer. Retention changes are reviewed and recorded.

Do not persist process-monotonic clock values as portable timestamps. Store UTC
bucket anchors plus boot/clock health metadata; use monotonic time in-process.
On restart or clock discontinuity, restore only trustworthy buckets or mark rate
features warming/unknown. Never clear restrictions or manufacture a zero-risk
rate estimate to recover availability.

Back up with SQLite's consistent backup mechanism or a verified quiesced
procedure, not a blind copy of the live main database without its WAL. Test
migration failure and restore before promoting a release. Database integrity
checks and hashes detect some corruption, not malicious administrative rollback.
An old backup can omit newer restrictions: do not resume the same strict epoch
unless a trusted external checkpoint establishes freshness. Otherwise keep it
closed and require a new authorized lifetime.

### 7.5 OpenShell leverage map

| Existing capability | Reuse / boundary |
|---|---|
| `SupervisorMiddleware` | Inline HTTP/S metadata and allow/deny at `PRE_CREDENTIALS`; no second traffic proxy. |
| `GatewayInterceptor` | Intercept `CreateSandbox`, `UpdateConfig`, `SubmitPolicyAnalysis`, `ApproveDraftChunk`, and `ApproveAllDraftChunks` to bind epochs, enforce control-plane non-expansion, and keep `risk-guard` attached. |
| Extension protocol/auth types | Share generated contracts, capability negotiation, identity/claim types (`openshell-ext+jwt`). |
| Kernel/proxy authorization and credential handling | Leave with OpenShell; derive credential-bearing endpoint booleans (`C = 1`) from policy metadata without touching secret values. |
| Rust SDK and authenticated raw gRPC | Inventory, read-only policy evidence, log watch, pagination, token refresh; verify each RPC's authorization and projection. |
| Policy schema/serializer/merge helpers | Reuse `openshell-policy-schema` and `openshell-policy` to parse/build candidate policies and compose provider rules. |
| Containment prover (`openshell-prover`) | Execute the Two-Step Containment Proof (`network_middlewares` invariance + Z3 `check_within_boundary` on the middleware-stripped projection). |
| Policy revision and load status | OpenShell remains the system of record; retain evidence snapshots only. |
| Draft proposal inbox | Reuse only for semantics it supports. Existing addition-oriented chunks are not a safe representation of rule removal or full hardening review. |
| OCSF and log correlation | Use for interoperability/correlation without expecting custom findings text to survive sanitization. |
| Anonymous activity summaries & endpoint observations | Supplementary health signals only; not an ordered behavioral request history. |

## 8. Two-Tier Monotonic Ratchet semantics

To enforce monotonic tightening on consequential risks without permanently bricking read access on a transient burst, the sidecar implements the **Two-Tier Monotonic Ratchet** (resolving Decision D-01):

$$\text{RiskPermit}_t(a) = \bigl(\text{scope}(a) \notin R_t^{\text{strict}}\bigr) \land \bigl(t_{\text{now}} \ge \text{CooldownUntil}_t(\text{scope}(a))\bigr) \land \text{CurrentScorePermits}_t(a)$$

1. **Tier 1 — Strict Epoch Ratchet ($R_t^{\text{strict}}$):**
   - Triggered when an enforced denial involves a high-impact operation ($I = 1$), a `task_constraint` safeguard, or a scope that exceeds the Tier 2 cooldown strike limit (default: 3 cooldown episodes in the same epoch).
   - Inserts `scope(a) = (host, port, method, resource_scope)` into the SQLite `restrictions` table with `tier = 'strict_epoch'`.
   - Monotonic invariant: $R_{t+1}^{\text{strict}} = R_t^{\text{strict}} \cup \text{NewStrictRestrictions}_t$. Rows are never deleted or expired during epoch $e$.
   - Restoring or broadening access requires terminating epoch $e$ and explicitly authorizing a new epoch $e'$.
2. **Tier 2 — Bounded Cooldown Window (`cooldown`):**
   - Triggered when an enforced denial is caused solely by velocity/fan-out ($I = 0$ with $V \ge 1$ or $F \ge 1$).
   - Records `cooldown_until_ms` (default: 300 seconds) and increments `strike_count` in SQLite. If `strike_count >= max_strikes`, the row atomically promotes to `tier = 'strict_epoch'`.
3. **Operational Errors vs. Risk Restrictions:**
   - Service errors, timeouts, or DB lock failures fail closed for the current request (`on_error: fail_closed`) but are **not** behavioral evidence and do not insert rows into `restrictions`.
4. **Control-Plane Enforcement (`GatewayInterceptor`):**
   - When the gateway interceptor binding is active, any `UpdateConfig` or `ApproveDraftChunk` call on a governed sandbox is validated against the epoch's current policy via the Two-Step Containment Proof. Attempts to widen network/filesystem permissions in place or set `proposal_approval_mode=auto` are rejected in `VALIDATE` phase unless a new epoch is explicitly authorized.

## 9. Failure behavior

| Condition | Protected enforce-mode behavior |
|---|---|
| Invalid/expired JWT or identity mismatch | Reject evaluation; platform error handling blocks; audit authentication failure without token. |
| Deadline or service unavailable | Selected binding's `fail_closed` applies; verify actual response and upstream effects. |
| Saturated queue | Reject bounded admission rather than buffer indefinitely; count operational failure separately from detections. |
| Missing optional process | Mark unknown; do not claim binary-specific detection. Apply explicit context policy. |
| Missing baseline | Cold-start rules and observation only unless an independent configured safeguard justifies denial. |
| Corrupt configuration/state | Not ready; no permissive fallback. |
| Oversized/unbufferable request | OpenShell middleware error policy applies; count coverage/availability impact. |
| Uninspectable route | Reject deployment for protected scope or verify OpenShell refuses it; never advertise protection based only on registration. |
| Stale epoch/config | Reject or enter an explicitly configured degraded state; never silently select a different identity. |
| Disk full / commit failure | Fail evaluation closed; do not acknowledge unpersisted strict restrictions. |

Use stable short reason codes such as `behavioral_risk_denied` and
`risk_state_unavailable`. Platform handling of RPC errors is distinct from
returning `DECISION_DENY`; tests document both. Free-form service reasons are
not guaranteed to reach users through OpenShell.

## 10. Privacy and observability

Use the minimum metadata needed. Ignore headers, body, and raw query for v1;
although the contract supplies them, that does not make them safe to log.
Canonical paths can contain secrets and resource names can be sensitive.
Record approved route templates and keyed resource identifiers when possible.
Detailed displays require redaction, access control, and retention limits.

Service audit records contain the full explanation structure; OpenShell logs
carry platform-owned fields. Correlate by request ID and authenticated sandbox
identity. Do not depend on arbitrary custom finding text appearing in platform
security logs.

Metrics: evaluation counts by bounded outcome/reason, histogram of queue/scoring/
commit/total latency, failure counts, baseline maturity, and backlog/storage
health. No high-cardinality request/resource identity labels.

## 11. Hardening recommendation flow and Two-Step Containment Proof

1. Capture observation interval and completeness, identity, baseline versions,
   and the current base/effective policy identities.
2. Generate conservative proposals using `openshell-policy-schema`: remove an
   unused named rule, replace broad `access: read-write` or `access: full` presets
   with explicit observed `rules:`, or narrow wildcard paths to observed route
   templates.
3. Never remove a `deny_rules` entry as though it were unused permission. Never
   assume removing one allow removes access when overlapping or `_provider_*`
   rules remain.
4. Recompute the candidate's effective authority, including provider-owned rules
   (`compose_effective_policy`).
5. **Execute the Two-Step Containment Proof:**
   - Because `openshell-prover` (`validate_supported_common_policy` in
     `crates/openshell-prover/src/containment.rs`) rejects any policy with a
     non-empty `network_middlewares` map, running the prover on the raw policy
     returns `Unsupported(unsupported_policy_shape: "uses network middleware controls")`.
   - **Step 1 (Middleware Invariance Check):** Verify deterministically that
     `candidate.network_middlewares == boundary.network_middlewares`, that our
     `risk-guard` binding keeps `on_error: fail_closed`, and that its endpoint
     `include` set covers every REST endpoint in `candidate.network_policies`.
   - **Step 2 (Projected Z3 Containment Check):** Construct `boundary_proj` and
     `candidate_proj` by clearing only the identical `network_middlewares` map,
     and invoke `openshell_prover::containment::check_within_boundary(&boundary_proj, &candidate_proj, options)`.
   - **Soundness:** Since a non-mutating `PRE_CREDENTIALS` middleware only
     intersects permissions ($\text{Allow}_{\text{OpenShell}} \land \text{Permit}_{\text{MW}}$),
     $\text{MW}(C) = \text{MW}(B)$ and $\text{Auth}(C_{\text{proj}}) \subseteq \text{Auth}(B_{\text{proj}})$
     implies $\text{Effective}(C) \subseteq \text{Effective}(B)$ across all five
     modeled domains (`filesystem, network_l4, network_rest, process, landlock`).
   - Record both the raw prover status (`unsupported_middleware`) and the
     Two-Step Proof verdict (`within_boundary` + coverage) in the recommendation
     artifact. Any non-`Within` result in Step 2 fails the proof.
6. Replay held-out task traffic against the candidate policy and report any
   would-block cases.
7. Save a pending-review report. The sidecar never auto-applies policy writes.

### 12.1 Concrete end-to-end artifact walkthrough

**1. Gateway registration (`gateway.toml`):**

> **Note on TLS:** `openshell-risk-guard serve --tls-cert --tls-key` terminates TLS itself. Register `https://` endpoints with `tls_ca_cert_path` for the signing CA; the gateway's EdDSA extension JWT remains the caller authentication. Plaintext is accepted only on loopback or with `--allow-insecure-local-test`.

```toml
[[openshell.supervisor.middleware]]
name = "risk-guard"
grpc_endpoint = "https://host.openshell.internal:50061"
timeout = "500ms"
max_payload_bytes = 4194304

[[openshell.gateway.interceptors]]
name = "risk-guard-governance"
grpc_endpoint = "https://host.openshell.internal:50061"
order = 10
failure_policy = "fail_closed"
binding_policy = "allowlist"
timeout = "500ms"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["validate", "post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateConfig"
phases = ["validate", "post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/ApproveDraftChunk"
phases = ["validate", "post_commit"]
```

**2. Initial sandbox policy (`policy.yaml`) — deliberately broad static L7 access:**

```yaml
version: 1

network_middlewares:
  behavioral-risk-guard:
    name: Behavioral Risk Guard
    middleware: risk-guard
    order: 10
    on_error: fail_closed
    config:
      task_profile: "repo-triage-readonly"
      mode: "enforce"
    endpoints:
      include:
        - api.github.local

network_policies:
  github_api:
    name: github_api
    endpoints:
      - host: api.github.local
        port: 18443
        protocol: rest
        enforcement: enforce
        access: full
        credential_binding:
          provider: github-work
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/gh
```

**3. Recorded SQLite `decisions` explanation when the agent attempts `DELETE /repos/org/payments-prod`:**

```json
{
  "request_id": "9f8c2b10-4d3a-4c9e-8a11-7e55d2c0a111",
  "sandbox_id": "sbx_01j8x9k2m4",
  "epoch_id": "ep_01",
  "mode": "enforce",
  "decision": "DECISION_DENY",
  "reason_code": "behavioral_risk_denied",
  "risk_score": 85,
  "threshold": 70,
  "ratchet_action": "latched_tier1_strict_epoch",
  "restricted_scope": "https://api.github.local:18443 DELETE /repos/{owner}/{repo}",
  "signals": [
    {"feature": "N_r", "observed": "org/payments-prod", "baseline": ["org/docs-site"], "contribution": 15},
    {"feature": "N_a", "observed": "DELETE repo_admin", "baseline": ["GET repo_meta", "GET issues"], "contribution": 15},
    {"feature": "T", "observed": "/usr/bin/curl", "baseline": ["/usr/bin/curl", "/usr/bin/gh"], "contribution": 0},
    {"feature": "I", "observed": "high_impact_destructive", "baseline": "read_only_profile", "contribution": 30},
    {"feature": "J_Nr_I", "observed": "unfamiliar_resource_x_destructive", "baseline": "none", "contribution": 15},
    {"feature": "C", "observed": "credential_binding:github-work", "baseline": "credentialed", "contribution": 10}
  ]
}
```

**4. Periodic hardening recommendation diff (verified `within_boundary` via Two-Step Proof):**

```diff
   github_api:
     name: github_api
     endpoints:
       - host: api.github.local
         port: 18443
         protocol: rest
         enforcement: enforce
-        access: full
+        rules:
+          - allow:
+              method: GET
+              path: /repos/org/docs-site
+          - allow:
+              method: GET
+              path: /repos/org/docs-site/issues/**
         credential_binding:
           provider: github-work
     binaries:
       - path: /usr/bin/curl
-      - path: /usr/bin/gh
```

## 12. Deployment and demo

Use the pinned checkout and an isolated Linux Docker/Podman or supported Linux
environment. Native Windows operation is not assumed from this Windows source
workspace. Do not run destructive fixtures against real external APIs.

The gateway and each supervisor must reach the configured middleware endpoint.
Use authenticated TLS and provisioned keys in the team-facing setup. Build a
scripted local fixture with independent application-level request/effect counts.

Startup sequence: provision trust/config -> migrate state -> load approved
baseline -> start service -> authenticate `Describe`/`ValidateConfig` -> create
the protected sandbox -> verify route selection and negative coverage tests.

The demo records OpenShell commit, service commit/build, fixture/dataset hashes,
configuration, environment, and test results. Explicitly clean up only resources
created by the demo. No "demo passed" banner without assertion results.

## 13. Validation plan and design risks

- Unit: normalization, scoring, config bounds, state transitions, privacy.
- Contract: manifest/version negotiation, authentication, result shape.
- Integration: baseline deny cannot be overridden; middleware deny prevents
  application action; allow preserves body/headers and normal task behavior.
- Fault: queue saturation, timeout, invalid response, disk full, crash/restart,
  token expiry, missing context, coverage mismatch.
- Concurrency: duplicate IDs, inconsistent duplicate fingerprints, parallel
  windows/restrictions, no cross-identity contamination.
- Evaluation: held-out metrics and comparisons from the detection document.
- Performance: end-to-end overhead including OpenShell buffering and persistence,
  not just an in-process scoring timer.

Primary risks: false positives, poisoned baselines, task attribution ambiguity,
preview API changes, incomplete mediation, and fail-closed availability impact.
No anomaly model eliminates these; contain them through scope, evidence, and
clear operational contracts.

## 14. Code references

- [Protocol](https://github.com/NVIDIA/OpenShell/blob/main/proto/supervisor_middleware.proto)
- [Gateway interceptor protocol](https://github.com/NVIDIA/OpenShell/blob/main/proto/gateway_interceptor.proto)
- [Interceptable gateway RPC list](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-gateway-interceptors/src/routes.rs)
- [Governance interceptor example](https://github.com/NVIDIA/OpenShell/blob/main/examples/governance-interceptor/README.md)
- [L7 call path](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-supervisor-network/src/l7/relay.rs)
- [Middleware runner integration](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-supervisor-network/src/l7/middleware.rs)
- [Example registration and smoke test](https://github.com/NVIDIA/OpenShell/blob/main/examples/supervisor-middleware-content-guard/README.md)
- [Extension authentication](https://github.com/NVIDIA/OpenShell/blob/main/rfc/0009-supervisor-middleware/appendices/extension-authentication.md)
- [Provider policy composition](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-policy/src/compose.rs)
- [Policy mutation and approval](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-server/src/grpc/policy.rs)
- [Gateway SQLite durability](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-server/src/persistence/sqlite.rs)
- [Gateway persistence API](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-server/src/persistence/mod.rs)
- [Internal gateway durable formats](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-server/proto/storage.proto)
- [Public history, activity, endpoint, and watch contracts](https://github.com/NVIDIA/OpenShell/blob/main/proto/openshell.proto)
- [Rust SDK watch and raw client](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-sdk/src/client.rs)
- [Memory-backed gateway log bus](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-server/src/tracing_bus.rs)
- [Anonymous activity channel](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-core/src/activity.rs)
- [Extension claim types](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-extension-core/src/jwt.rs)
- [Containment implementation](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-prover/src/containment.rs)
- [Containment coverage and limitations](https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/policies/prover.mdx)
