# OpenShell Behavioral Risk Guard: Detection and Evaluation Design

Status: implemented, with synthetic-corpus benchmarks and a live demo against a real OpenShell gateway; see the [README](../README.md).
Fixture accuracy and latency are not production guarantees; validate on your own traffic before enforcing broadly.
Reference checkout: `55bf786453395f3fe1858a187152537b457de77d`.

See [requirements](requirements.md) for acceptance gates and
[system design](design.md) for identity, persistence, enforcement, and trust.

## 1. Objective and non-claims

Detect consequential deviations in otherwise-authorized inspected HTTP actions,
while preserving legitimate novelty and task changes.

Anomaly is evidence of unfamiliarity, not proof of compromise. High-impact API
semantics require curated, versioned domain knowledge; HTTP methods alone do
not prove read/write/destructive intent. POST may be a read-only query; GET can
be unsafe on poorly designed APIs.

The detector cannot know the agent's true intent, whether a credential was
injected later, whether an upstream accepted the operation, or whether an
uninspected local tool performed a harmful action.

"Best in class" requires independent, representative comparisons. Until then,
describe this as an explainable detector with published evaluation results and stated limits.

### Real-time payment-fraud inspirations (`p50 ≤ 10 ms`, `p99 ≤ 250 ms` inline SLA)

Because an AI agent cannot wait seconds on a SIEM query before every tool call, Risk Guard's scoring architecture directly adapts patterns from **real-time payment card fraud engines** (FICO Falcon, Stripe Radar, Visa Advanced Authorization):

1. **Pre-Auth Gate (`PRE_CREDENTIALS`)**: Evaluates requests *after* OpenShell's deny-by-default static YAML passes, *before* credentials are injected into the outbound call.
2. **Split-Speed Fast Path + Asynchronous Feature Store (`SiemFeatureCache`)**: Inline evaluation never queries OpenSearch; out-of-band OpenStream aggregations (`R1`–`R6`, including OpenSearch Random Cut Forest `anomaly_grade_15m_permille`) are pushed over SPIFFE mTLS into an in-memory `RwLock<SiemFeatureCache>` and read in nanoseconds.
3. **Non-Linear Interaction Terms ($N_r \cdot I$ & Low-and-Slow $B_{\text{slow}}$)**: Combines *Unfamiliar Resource* $\times$ *High-Impact Action* ($N_r \cdot I = +15$) and *Low 1m Velocity* $\times$ *High 15m Fan-Out* ($B_{\text{slow}} = +15$) so single benign novelties pass while dangerous combinations cross the $\ge 70$ block line.
4. **Empirical Bayes Cold-Start Shrinkage (`src/adaptive/v2.rs`)**: Shrinks a new workload's sparse observations toward its task profile and fleet prior (`PRIOR_REQUEST_STRENGTH = 200`, `PRIOR_WINDOW_STRENGTH = 600`) until sufficient workload history is observed.
5. **Two-Tier Step-Down Cooldown vs. Hard Lock**: Pure read bursts ($I=0$) trigger a 5-minute Tier-2 cooldown (`cooldown_until_ms`), whereas destructive violations ($I=1$) or 3 cooldown strikes latch a Tier-1 permanent cross-sandbox lock (`strict_epoch`).
6. **Champion/Challenger Shadow Mode & Adverse-Action Replay**: New rules and learned models run in `shadow` mode behind a promotion gate, and every decision records its full `SignalContribution` waterfall and SIEM feature snapshot for bit-for-bit audit replay.

## 2. Threat and benign behavior model

### Supported misuse hypotheses

- A read-oriented agent attempts a known destructive operation on an unfamiliar
  resource that its broad static policy permits.
- An unexpected executable makes a high-impact request inconsistent with the
  trusted task profile.
- A session rapidly enumerates distinct resources outside its approved scope.
- Activity evolves from ordinary reads to consequential cross-resource changes.
- An agent repeats unusual activity to try to normalize it through training.

### Mandatory benign counterexamples

- First legitimate call to a new read-only resource.
- Approved maintenance task performing expected destructive actions.
- Retry storms caused by a local test outage, not compromise.
- A legitimate batch job with high request rate and broad resource access.
- A new tool version, missing process identity, or new sandbox identity.
- Read-only POST endpoints and domain-specific method semantics.
- Legitimate staged workflows requiring a new host.

Static policy should deny inherently forbidden actions. Behavioral detection is
not a replacement for configuring a known prohibition.

## 3. Signal inventory

| Signal | Source / treatment | Limitation |
|---|---|---|
| Identity | Authenticated gateway/sandbox/epoch | Middleware does not supply a workload ID. |
| Host/port/scheme | Admitted request target | Host novelty is not destination reputation. |
| Method | Request target, normalized per contract | Method alone is not semantic impact. |
| Route/resource | Curated parser for approved API family | Unknown route means unknown semantics; no guessed repository boundaries. |
| Binary/ancestry | Optional originating process | Path is not a cryptographic measurement of trusted software. |
| Count/rate | Service-observed evaluation events | Selected routes only; not all sandbox activity. |
| Distinct resources | Bounded per-identity window | Enumeration may be legitimate; require task/context evidence. |
| Action sequence | Bounded previous-event summaries | Do not claim causal proof or infer unseen intermediate actions. |
| Baseline support | Approved artifact and source provenance | Sparse data cannot establish normality confidently. |
| Credential-bearing endpoint ($C$) | Policy snapshot (`credential_binding` or `_provider_*` rules in `compose.rs`) | Indicates the endpoint carries managed credentials (`C = 1`), without exposing raw secret values at `PRE_CREDENTIALS`. |
| Response status/bytes | Optional future `HttpResponsePreReturn` integration | Not available from request evaluation alone. Not a v1 feature. |

Ignore raw body/query/header values. Request byte counts are not transferred
data volume and cannot substantiate an exfiltration claim.

### Observation sources and persistence

The primary detector input is authenticated middleware evaluation, not a log
scraper. Store redacted normalized decisions and bounded temporal state in the
service-owned SQLite database described in the
[storage design](design.md#71-storage-decision-independent-sqlite-not-the-gateway-database).
OpenShell's gateway database is neither a training source nor an extension
storage API.

Supplementary sources have narrower meanings:

- Anonymous activity summaries omit destination/path/process details and cannot
  train action/resource baselines.
- Endpoint status records the latest accepted result for a configured endpoint,
  not the sequence of actions or proof of tool success.
- SDK log-watch events support correlation, but bounded replay, lag warnings,
  and invalidated cursors require explicit coverage-gap records.
- Read-only policy snapshots support recommendation context and credential-bearing endpoint extraction ($C$). When `GatewayInterceptor` (`POST_COMMIT`) is enabled, policy revisions are captured synchronously; in middleware-only mode, SDK-polled snapshots are labeled as asynchronous context.

Keep exact local baseline/detector/config versions separate from asynchronously
observed OpenShell context. A committed evaluation means the service made a
decision; it does not establish that OpenShell subsequently forwarded the
request or that the upstream operation succeeded.

## 4. Feature normalization

Version the normalizer with the detector; changing normalization requires
reevaluation of the baseline and held-out corpus.

- Accept only supported schemes, methods, and valid ports within configured
  bounds. Preserve significant method distinctions rather than coercing invalid
  values into a common valid method.
- Normalize DNS case using the contract's admitted target; preserve IPv6/IP
  semantics and explicitly reject unsupported shapes.
- Use OpenShell's provided path representation. Do not repeatedly decode `%`
  sequences, collapse encoded separators, or otherwise disagree with upstream
  resource selection.
- Match resources using anchored, tested route templates, not substring tests.
- Test trailing slashes, dot segments, percent encoding, Unicode, empty
  components, and ambiguous targets. An unrecognized shape is `unknown`.
- Resource identifiers are keyed/hardened for persistent aggregation; keep
  human-readable displays redacted and access-controlled.
- Keep optional process fields as `unknown`, not an empty "trusted" executable.
- Bound route templates, feature values, and distinct-resource state to resist
  high-cardinality input.

Every API-semantic classifier ships with positive and negative examples. A
DELETE route for a repository fixture may be labeled destructive; that label
must not generalize to every DELETE endpoint without validation.

## 5. Baseline design

### Ownership and population

Baseline artifacts remain operator-approved task profiles. Attributed online
windows and ratchets belong to a context keyed by workload ID, revision,
task profile, baseline hash, detector configuration and enforcement mode.
They are shared across that agent's comparable runs and sandboxes, not reset
at every launch. Different contexts never share counters or restrictions.
Legacy unattributed traffic retains per-epoch windows.

An operator registers an agent, creates a run pinned to a context, and binds
decision-free execution epochs to that run. Middleware resolves this association
from authenticated sandbox identity; self-declared agent/task claims cannot
establish it. Missing required bindings, ended runs and detector configuration
drift fail closed. A new sandbox is not a new behavioral identity.

Baseline imports do not rewrite historical attribution, rescore decisions or
increase maturity from observed traffic. Agent history is investigation context,
not an implicit permission grant. Request scores remain action scores, not
calibrated agent compromise probabilities. The legacy `strict_epoch` restriction
name denotes shared-context persistence for attributed traffic.

A profile artifact includes:

- Trusted provenance and approving identity.
- API semantic map and normalizer/detector versions.
- Allowed task resources, expected tools, and high-impact operations.
- Training-session manifest and hashes.
- Counts of action classes and distinct resources.
- Rate/window distributions and uncertainty.
- Validity interval and minimum support requirements.

### Cold start and sparse data

Require at least 20 trusted training sessions and 200 relevant requests for a
mature behavioral profile in the initial release. These are provisional
engineering thresholds, not scientific guarantees; evaluate sensitivity.

Before maturity:

- Do not deny on novelty/statistical rarity alone.
- Independent operator-defined high-impact safeguards remain active.
- Emit bounded `baseline_insufficient` observations.
- Do not use an unrestricted global fallback profile to authorize behavior.

### Poisoning and drift

- Enforced traffic cannot immediately train the active baseline.
- Denied and high-risk observations go to quarantine.
- Even low-risk production observations require review before promotion.
- Weight/cap contributions by session so a high-volume actor cannot dominate.
- Keep candidate baseline versions and evaluate on a separate promotion set.
- Drift can trigger review or observe-only evaluation of a candidate; it cannot
  silently clear strict-mode restrictions or expand OpenShell policy.
- Train and evaluate by chronological session groups, not random request rows.

### Implemented adaptive network layer (phase 1)

`src/adaptive.rs` implements empirical category frequencies and temporal envelopes;
`src/store/adaptive.rs` owns curated native windows, immutable dataset membership,
model versions, shadow evaluation and explicitly approved model heads. This layer
does not synthesize permissions, and it does not change imported baseline maturity
counts on its own: an operator can **explicitly credit** an enforced model's observed
training counts to a workload's maturity (see
[adaptive-v2.md](adaptive-v2.md), "Honest maturity"); nothing credits automatically.

**Version 2** (`network-metadata-empirical-v2`) adds, on top of the same collection and
review rules: shrinkage toward a pooled prior from other workloads of the same task
profile (cold start), deterministic recent-activity features (burst peak, gap regularity,
route entropy, write share, a never-seen method, never-seen resources in the last hour),
optional bounded SIEM context, and a promotion gate that blocks a candidate that would
block more benign holdout traffic, or catch fewer injected probes, than the model it
replaces. Models fitted under v1 keep scoring as before. On scripted traffic it caught
82% of injected attack episodes at the shadow-alert line against 29% for v1, with no false
would-blocks; that is a regression check on named shapes by the same author, not
accuracy against an unseen attacker. Method, numbers, what did not help and the limits
are in [adaptive-v2.md](adaptive-v2.md).

The supervisor RPC assigns transport provenance only after its authentication
step. Explicit insecure local-test calls are isolated from verified supervisor
evidence. Historical records without this provenance and direct CLI evaluations
are ineligible. Collection starts from a trusted run binding and records new
decision identities transactionally, after idempotency checks. No retrospective
enrollment or request-row random split is supported.

A recording window must be finished and reviewed as benign (either via
**Automated Shadow Learning** on clean read-only run/epoch closure with
`reviewed_by = "auto-clean-policy"` or via explicit operator review). Under
Automated Shadow Learning (on by default for every agent; paused per agent via
`set_auto_learning`), pristine single-sandbox runs enroll on their first native
request and auto-approve on run/epoch end only when every observation is strictly
read-only and a plain allow. Flagged windows and manually started captures wait
for human review. Approved windows fit or update the active shadow model
(`shadow_model_id`). Routes classified as `write_mutation` and `POST /graphql`
are excluded from clean read-only auto-approval because request bodies are not
inspected at `PRE_CREDENTIALS`. Any denial, high-impact action, non-read-only or
unknown semantic route, task constraint, source or revision mismatch quarantines
the entire window. Limits are 500 observations and one hour per window, with at
most 100 windows per training operation. Withdrawing approval revokes all derived
models and clears their active pointers, but not existing ratchets, rolling state
or history.

Whole-run grouping keeps repeated windows from inflating independent support.
Operational phase-1 collection is stricter: one capture per pristine,
single-sandbox run, begun on or before its first request. The run's sandbox binding
then freezes. Mid-run and repeated windows are rejected explicitly instead of
training capture-local envelopes against incompatible full-run history.
Later nonoverlapping run groups form the held-out partition where possible.
One-window demo examples can produce provisional shadow candidates, never
enforcement-ready models. While shadow candidates fit and update automatically on
clean run closure, **Enforce promotion** remains strictly manual behind the
20-train / 5-holdout / 5-shadow gates: 20 training runs/200 requests, 5 later
held-out runs/50 requests, zero held-out would-blocks, plus 50 fresh clean native
shadow observations from 5 independent runs and explicit operator review.
The statistical module can impose additional sparse-tail gates. These are minimum
engineering gates, not a confidence bound or measured production detection rate.

Empirical p95/p99 values include observed quiet intervals and remain estimates.
Missing binary identity is a coverage gap, not an invented expected executable.
Rate/fan-out features honor temporal warming; scoring never subtracts risk or
widens a native boundary. Learned scores remain separate from deterministic
scores in shadow. An explicitly enforced, qualified model can add a high-confidence
denial and scoped cooldown; it cannot override a deterministic denial or clear
earlier containment. Single-category read novelty cannot alone justify a learned
block.

Models are pinned to immutable scoring context, saved guardrails revision and
source scope. New settings cannot silently reuse an incompatible model.
Temporal training and inference both use per-sandbox/run native windows, so simultaneous
runs are not incorrectly compared against a single-run learned rate envelope.
Deterministic context counters and all restrictions remain shared across runs.
New training selects a shadow head while preserving any previously enforced head;
promotion/rollback use an expected active-model ID. Each native assessment records
the frozen model hash and counterfactual result. Recent anomaly frequency raises
a drift-review cue, not an automatic relearning or permission expansion action.
Unlabeled shadow traffic does not establish a false-positive rate. Promotion
support excludes training and held-out run IDs. Demoting an enforced model to
shadow atomically stops new model denials without clearing existing ratchets.

This is network metadata learning only. There is no filesystem-access training
stream, model-weight optimization, automatic retraining schedule, production
qualification, SSO or multi-operator RBAC in this phase.

### Replay, restart, and retained evidence

Persist decision evidence, deduplication, pre-event sequence updates, temporal
buckets, and strict-mode restrictions atomically before acknowledging evaluation.
Duplicates with the same authenticated request identity and fingerprint reuse
the committed decision within the retention window; conflicting fingerprints
are errors. New-ID retries are separate attempts, not automatically duplicates.

Replay requires the original ordered feature inputs, starting window state,
artifact versions, and restriction state. An aggregate count is insufficient
to reproduce a sequence-sensitive decision. Pin replay evidence needed by
retained evaluations/recommendations; never imply that an expired raw history
is reproducible from summary statistics alone.

Monotonic process clocks cannot be restored across boots. After a restart or
clock discontinuity, reconstruct only trustworthy buckets and mark other rate
features warming/unknown. Frozen approved baselines remain intact; persistent
restrictions are not cleared. Test stale-backup recovery separately from ordinary
restart because missing newer restrictions can violate strict-mode semantics.

## 6. Detector composition

### Layer A: operator-owned safeguards

Examples: known destructive action outside approved task resources, or a task
that explicitly prohibits cross-resource mutation.

These can deny without historical data because they encode explicit operator
intent. Label them `task_constraint`, not an anomaly-model discovery.

Layer A is a set of named rules, and each runs in a mode:

| Rule | Trips when | Default |
|---|---|---|
| `forbidden_action` | The action is on the explicit deny list (or matches a `prefix*` pattern). | Always enforces |
| `unfamiliar_high_impact` | A high-impact action targets a resource the task does not approve. | Enforce while `forbid_unfamiliar_high_impact` is on; an override can soften it to shadow |
| `unapproved_action` | The action class is not in the task's allowed-action list. | Shadow |
| `unapproved_resource` | The resource is not in the task's approved-resource list. | Shadow |

A **shadow** rule is evaluated and recorded but never changes the outcome: the decision gets a zero-point `shadow_rule`
signal (`rule=<id>; mode=shadow`, support `would_block`) so an operator can see what promoting the rule would block. An
**enforce** rule denies with `task_constraint_denied` and names the rule in the `task_constraint` signal (`rules=<ids>`).
An `off` rule is skipped. The two approved-list rules apply from the first request, because they encode the operator's
declared task rather than learned behavior, and an empty list means "not specified": it trips nothing and never blocks
everything. A denial from the deny list or the high-impact rule scores at least 85 and latches Tier 1. A denial from an
approved-list rule scores at least the block line and latches Tier 1 only when the request is high impact; otherwise it
denies that request and nothing more, so it cannot cool down the approved resources and actions that share the route.

### Layer B: interpretable behavioral features

Initial candidates:

1. Novel action/resource pair relative to the frozen task profile.
2. Unexpected originating executable when identity is available.
3. Transition from supported read patterns to a known high-impact operation.
4. Rate exceeding the profile's trusted envelope.
5. Unusual distinct-resource fan-out over short and long windows.

Use bounded windows initially at 1 minute and 15 minutes. Learn rate envelopes
from trusted session distributions with conservative uncertainty margins. Do not
use z-scores without checking skew, small sample sizes, and heavy tails.

Categorical rarity may be estimated using:

`p(x) = (count(x) + alpha) / (N + alpha * K)`

where `K` includes an explicit unknown category over a defined bounded
vocabulary. Set and version `alpha` on development data. Frequency is descriptive;
rare does not mean malicious and the value is not attack probability.

### Layer C: transparent decision policy and interaction-aware score

Initial score for reproducible experiments (not a calibrated probability):

$$S = \min\bigl(100,\ 15N_r + 15N_a + 20T + 30I + 15(N_r \cdot I) + 10C + 15V + 15F\bigr)$$

Feature definitions:

- $N_r \in \{0, 1\}$: **Resource novelty** — normalized resource identifier is unseen in the mature trusted task profile.
- $N_a \in \{0, 1\}$: **Action-class novelty** — `(method, route_template)` class is unseen in the mature trusted task profile.
- $T \in \{0, 1\}$: **Tool deviation** — known originating executable (or ancestor chain) differs from the task profile's expected executable set.
- $I \in \{0, 1\}$: **High-impact operation** — curated API semantic map classifies `(method, route_template)` as destructive or privilege/state-mutating.
- $N_r \cdot I \in \{0, 1\}$: **Cross-resource impact interaction** — amplifies a high-impact operation when it targets an unfamiliar resource, ensuring attacks that reuse the expected binary ($T = 0$) are caught.
- $C \in \{0, 1\}$: **Credential-bearing endpoint** — target `(host, port)` has an active `credential_binding` or `_provider_*` rule in the sandbox's policy snapshot.
- $V \in \{0, 1, 2\}$: **Tiered velocity** — `0` within envelope; `1` elevated ($> \text{p95}$ and $\ge 2\times$ baseline rate); `2` severe burst ($> \text{p99}$ and $\ge 5\times$ baseline rate).
- $F \in \{0, 1, 2\}$: **Tiered distinct-resource fan-out** — `0` within envelope; `1` elevated ($\ge 2\times$ baseline distinct resources in window); `2` severe enumeration ($\ge 5\times$ baseline distinct resources and $\ge 10$ distinct resources in window).

Thresholds:
- **Observation (`DECISION_ALLOW` + audit alert):** $S \ge 20$.
- **Enforcement (`DECISION_DENY`, `reason_code = "behavioral_risk_denied"`):** $S \ge 70$ (or an explicit Layer A `task_constraint` violation).

#### Scenario verification matrix

| Scenario | Active signals | Score $S$ | Outcome & Ratchet tier |
|---|---|---|---|
| **1. Benign novel read** (`GET /repos/org/new-docs` on credentialed host, expected `curl`) | $N_r=1, C=1$ | $15 + 10 = \mathbf{25}$ | **Allow** (logged as observation $\ge 20$; not blocked) |
| **2. Flagship demo attack** (Expected `curl` $T=0$ runs `DELETE /repos/org/payments-prod` on credentialed host) | $N_r=1, N_a=1, I=1, N_r\cdot I=1, C=1$ | $15 + 15 + 30 + 15 + 10 = \mathbf{85}$ | **Deny ($\ge 70$)** + **Tier 1 Strict Epoch Latch** (even if $C=0$, $S=75 \ge 70$) |
| **3. Unexpected binary + mutation** (`python3` $T=1$ runs unfamiliar write $N_a=1, I=1$ on known credentialed repo $N_r=0, C=1$) | $N_a=1, T=1, I=1, C=1$ | $15 + 20 + 30 + 10 = \mathbf{75}$ | **Deny ($\ge 70$)** + **Tier 1 Strict Epoch Latch** |
| **4. Rapid cross-repo enumeration** (Expected `gh` $T=0$ runs `GET` across 30 unfamiliar repos on credentialed host) | $N_r=1, C=1, V=2, F=2$ | $15 + 10 + 30 + 30 = \mathbf{85}$ | **Deny ($\ge 70$)** + **Tier 2 Cooldown** (escalates to Tier 1 on 3rd strike) |
| **5. Approved maintenance task** (Profile includes destructive cleanup on approved repo set) | $I=1, C=1$ ($N_r=0, N_a=0, T=0$) | $30 + 10 = \mathbf{40}$ | **Allow** ($< 70$, expected for maintenance profile) |

Unknown features do not receive invented reassuring values; a separate `missing_context` indicator is recorded and governed by explicit policy. Lock weights and thresholds before unblinding the final evaluation set.

### Two-Tier Monotonic Ratchet semantics

Scoring and temporal persistence are coupled through the resolved Two-Tier Monotonic Ratchet (see [System Design Section 8](design.md#8-two-tier-monotonic-ratchet-semantics)):
- **Tier 1 (`strict_epoch`):** Any enforced denial with $I = 1$, a Layer A `task_constraint`, or $\ge 3$ Tier 2 cooldown strikes permanently latches `(host, port, method, resource_scope)` in SQLite for the remainder of the epoch.
- **Tier 2 (`cooldown`):** Pure velocity/fan-out denials ($I = 0$) enforce a bounded cooldown window (`cooldown_until_ms`) and increment `strike_count`, preventing transient read bursts from bricking the sandbox while still stopping sustained enumeration.

## 7. Explanation contract

Every decision stores:

```text
request_id, authenticated identity, epoch
normalizer_version, baseline_hash, detector_version, config_hash
mode, decision, reason_code, risk_score, threshold
signals: feature, observed_summary, baseline_summary, contribution, support
missing_context, baseline_maturity
state_sequence, restriction_reference, decision_timestamp
```

Example human explanation:

> Denied: a known destructive repository operation targeted an unfamiliar
> resource from an unexpected executable. The approved task profile contains
> read-only operations from the expected tool. This is a risk decision, not a
> conclusion that the agent is compromised.

Do not claim "credentials exfiltrated" or "attack prevented" based only on this
request. Do not serialize raw paths/tokens into public error messages.
Counterfactual explanations must be recomputed, not guessed from one feature:
removing a signal may still leave another safeguard denying the request.

## 8. Dataset and experiment protocol

### Corpus structure

Each episode contains a task profile, isolated starting state, ordered
requests, labels, expected policy coverage, and fixture outcomes. Include
multiple benign task families and malicious/misuse variants.

Keep four separate roles:

1. Training sessions for approved baselines.
2. Development sessions for feature and threshold iteration.
3. Validation sessions for operating-point selection.
4. Locked final test sessions for reported results.

Split by task/session group, time, and where feasible resource family so near
duplicates cannot cross splits. Generate unseen parameter variations after
freezing detection rules. Report shared generators and resulting dependence.

Labels must record rationale and provenance. For realistic traces, use two
independent reviewers with adjudication; reviewers should not see detector
scores when labeling. Synthetic labels describe intended fixture scenarios,
not established ground truth about real attacks.

### Mandatory test matrix

| Family | Examples |
|---|---|
| Ordinary behavior | Reads, expected writes, scheduled batch, approved cleanup |
| Benign novelty | New read resource, new approved host, task transition |
| Suspicious context | New-resource destructive action, unexpected tool plus impact |
| Enumeration | Burst and low-rate fan-out; compare legitimate inventory jobs |
| Cold start | No profile, insufficient support, newly created sandbox |
| Evasion | Encoding variants, known-tool reuse, slow requests, mimicry |
| Poisoning | Repeated risky requests, long benign warm-up, agent-provided approval claims |
| Missing context | No binary, unknown route, stale profile, partial coverage |
| Identity | Reused sandbox name/PID, token/context mismatch, cross-sandbox access |
| Operations | Retry storm, duplicate ID, restart, saturation, state loss |

At least some attacks must reuse expected tools and common destinations.
Otherwise the evaluation measures novelty detection rather than useful
behavioral risk discrimination.

## 9. Metrics and comparative evidence

Use the release gates in [requirements](requirements.md); do not report invented
results or tune on the final set.

Report:

- Episode recall: detected/blockable misuse episodes divided by supported
  labeled misuse episodes; separate alert from pre-action block.
- False-denied benign sessions and requests, with denominators.
- False alerts per 1,000 benign requests and per benign session.
- Precision and precision-recall curves on a declared prevalence mixture.
- Time/requests to detection and actions already executed before detection.
- Coverage: evaluated protected requests versus the intended protected surface.
- Cold-start, missing-context, and unknown-route outcome rates.
- Operational denials separately from risk denials.
- Latency p50/p95/p99, throughput, failures, state size, and CPU/memory.

Provide 95% confidence intervals and session/task-clustered uncertainty where
appropriate. With zero false-denied independent sessions out of 300, a one-sided
95% exact upper bound is approximately 1%; this is not proof of zero risk.
Correlated generated sessions do not justify the independence assumption.

Comparators:

1. The deliberately broad static policy alone.
2. A tighter practical static policy, to test whether the sidecar is necessary.
3. An operator task-constraint rule set without behavioral history.
4. Novelty-only detection.
5. Full contextual detector and ablations removing each signal family.

Compare at matched false-denial budgets and report scenarios where static
least privilege solves the problem more simply. If context adds no measurable
benefit, narrow the product claim rather than inflate the model.

For credible real-world claims, obtain consented representative agent traces or
an external evaluation beyond the controlled fixture corpus. Never transmit
private workload traces to third parties as part of evaluation.

## 10. Hardening recommendations

After an operator-selected observation interval:

- Report access observed, not access necessarily required.
- Include total task sessions, relevant traffic, missing intervals, selected
  routes, detector versions, and log/evaluation completeness.
- Bind reports to retained evidence and explicitly sourced base/effective
  policy snapshots. Pending persisted revisions are not proof of loaded policy,
  and historical base policies may omit provider-composed access.
- Suggest removal/narrowing only with supporting evidence and explicit
  exception cases, including scheduled or rarely used tasks.
- Preserve deny semantics and inspect overlaps/provider contributions.
- Execute the **Two-Step Containment Proof** ([System Design Section 11](design.md#11-hardening-recommendation-flow-and-two-step-containment-proof)): verify `network_middlewares` invariance first, then run `openshell-prover` (`check_within_boundary`) on the middleware-stripped projection. Record both the raw prover status and the two-step proof verdict (`within_boundary` + domain coverage). Never turn an `exceeds`, `unsupported`, or `inconclusive` step into a passing status.
- Replay held-out task cases and list would-block operations.
- Leave every proposal pending review.
- Keep hardening reports separate from OpenShell's addition-oriented draft
  chunks until an appropriate restrictive-change review integration is verified.

No observation period alone makes a policy safe. A seven-day run missing a
monthly task is not evidence that the task's access is unnecessary.

## 11. Promotion, rollback, and stop conditions

Promote to enforce only after contract, failure, identity-isolation, privacy,
quality, and performance gates pass. Threshold/config updates are versioned,
reviewed, and shadow-evaluated against the locked regression corpus.

Roll back a detector by deploying a previous tested artifact; in strict mode
this does not clear persistent restrictions. If an incident requires broader
access, terminate the governed lifetime and authorize a replacement according
to the selected product semantics.

Stop enforcement promotion if:

- Benign false-denial bounds exceed the gate.
- Unknown/unsupported coverage is being represented as protection.
- Rate/fan-out signals primarily detect legitimate workload intensity.
- Baseline promotion admits adversarial observations without review.
- The implementation cannot prove pre-forwarding denial for the demo paths.
- Availability costs exceed the declared operating budget.
- Source gaps or stale policy snapshots are being presented as complete or
  precisely request-correlated evidence.
- Retention or backup recovery makes decision replay or strict restrictions
  unverifiable while the deployment still advertises those guarantees.

The final report must contain failures, confidence limits, tested environment,
coverage exclusions, and incremental-value comparisons. Engineering quality
means making these limitations visible, not hiding them behind a risk score.

## 12. References

- [Middleware context and decision contract](https://github.com/NVIDIA/OpenShell/blob/main/proto/supervisor_middleware.proto)
- [Gateway interceptor contract](https://github.com/NVIDIA/OpenShell/blob/main/proto/gateway_interceptor.proto)
- [Provider policy composition](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-policy/src/compose.rs)
- [OpenShell containment prover implementation](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-prover/src/containment.rs)
- [OpenShell containment coverage](https://github.com/NVIDIA/OpenShell/blob/main/docs/how-it-works/policies/prover.mdx)
- [Microsoft Entra agent risk precedent](https://learn.microsoft.com/en-us/entra/id-protection/concept-risky-agents)
