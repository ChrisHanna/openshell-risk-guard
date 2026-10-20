# Security model and design rationale

How Risk Guard sits next to OpenShell, what it scores, who is trusted, and the measured release gates. Start with the [README](../README.md) for the overview.

## Workload ID and scoring continuity

A workload ID is the durable identity of a logical agent workload that persists across
runs and sandboxes. It is not a credential, model name, process path, user-supplied header
or sandbox display name. It is established in one of two ways. With
`--workload-from-principal` it is derived from the **workspace** a sandbox was created in and
the **principal** the gateway authenticated for that call, so nothing in the request can choose
or forge it. Otherwise it is an operator label, which is an assertion made by an allowlisted
principal. Either way a workload is scoped to one workspace once it has been derived,
auto-registered or registered with `--workspace`, and a sandbox from another workspace is
refused. A workload registered without a workspace is unscoped by design.
The binding is resolved from authenticated gateway/sandbox context on the server.
`serve` requires a binding by default. `--allow-unattributed` explicitly permits
legacy sandbox-only operation, but cannot bypass a missing binding for a sandbox
that has previously been workload-bound. Authentication bypass and unattributed
operation are separate flags.

Scoring uses the same explainable request formula, with rolling counters,
fan-out sets, cooldown strikes and persistent restrictions shared by
`(agent_id, agent_revision, task_profile, baseline_hash, detector_configuration, mode)`.
Creating another run or moving to another sandbox within this context does not
reset risk state. Different agents, revisions, profiles, baseline artifacts and
modes do not contaminate one another. A context is resumed when its exact
identity/configuration is reused. There is no averaged lifetime "agent score"
and no automatic baseline training.

`run-create` pins the current approved baseline and the built-in detector
configuration. Run IDs are unique, immutable and cannot be reassigned.
Revision is trusted operator metadata, not code attestation. Context changes
are operator actions, never workload-driven escape hatches. Restrictions are never
cleared automatically. After review, `restriction-clear` removes one restriction
and records the operator, reason and original trigger (see *Recovering from a
false positive*). The legacy `strict_epoch` tier
name means shared-context persistence for attributed decisions.

`run-bind` only accepts an active, decision-free epoch whose gateway, task,
baseline and mode match the run. Bindings cannot rewrite old evidence.
One run can use multiple sandboxes; a sandbox supports one active bound run.
If manually creating an epoch, use `epoch-create --gateway-id ...` to match the
authenticated gateway. Policy-only updates retain the binding.
`run-end --db ... --run-id ...` rejects subsequent evaluations on that run
without clearing the agent context's restrictions or counters.
This includes replay attempts after run closure or detector-configuration drift;
previously committed evidence remains available through read-only history.

The additive migration leaves legacy decisions unattributed and unchanged.
Agent detail joins immutable bindings, showing up to 100 contexts, runs and
decisions, up to 100 sandbox bindings per run, 20 policy-scoped recommendations
and 100 recorded coverage gaps. Policy recommendations retain their sandbox
and source-policy scope; they are not agent-wide permissions.
Agent-level task authorization tokens, automatic launcher provisioning,
multi-agent attribution within a shared sandbox, delegation graphs and
cross-gateway federation are not implemented.

For the historical synthetic walkthrough, explicitly use
`cargo run -- demo-dashboard --db ./synthetic-demo.db`. Never expose that
unauthenticated, state-changing harness publicly or treat it as deployment proof.

# Why a Gateway-Co-Located Sidecar? (OpenShell Topology)

OpenShell's [RFC 0009 Deployment Options](https://github.com/NVIDIA/OpenShell/blob/main/rfc/0009-supervisor-middleware/appendices/deployment-options.md) supports operator-managed external services. Our combined middleware/interceptor endpoint must be reachable by **both**:
1. **`openshell-gateway`** (which calls `Describe` and `ValidateConfig` at startup, and invokes `GatewayInterceptor.Evaluate` on `CreateSandbox`, `UpdateConfig`, and `ApproveDraftChunk` *before* a sandbox container even exists), and
2. **`openshell-supervisor` inside each sandbox** (which calls `SupervisorMiddleware.EvaluateHttpRequest` at `PRE_CREDENTIALS` for every inspected HTTP/S request).

Gateway co-location is a deployment option, not an OpenShell requirement.
`openshell-risk-guard` is packaged as a non-root container image ([`Dockerfile`](../Dockerfile)).
Deployment assets require actual gateway configuration, trusted keys and supervisor
reachability; a Risk Guard-only container is not a complete OpenShell deployment.

```text
+-------------------------------------------------------------------------+
| Gateway Pod / Host                                                      |
|                                                                         |
|  +-----------------------+  127.0.0.1:50061  +-----------------------+  |
|  |   openshell-gateway   | ----------------> | openshell-risk-guard  |  |
|  | (Control Plane RPCs)  | GatewayInterceptor|  Sidecar Container    |  |
|  +-----------------------+  (openshell-ext   |                       |  |
|                             +jwt: gateway)   | - Dual gRPC Services  |  |
|                                       ^      | - SQLite (WAL + FULL) |  |
+---------------------------------------|------+ - Z3 Prover Bridge    |  |
                                        |      +-----------------------+  |
                                        | ClusterIP / Bridge :50061       |
+---------------------------------------|---------------------------------+
| Sandbox Container / MicroVM           | (openshell-ext+jwt: supervisor) |
|                                       |                                 |
|  [Agent Process] -> [openshell-supervisor L4/L7 Rego]                   |
|                           | (if allowed by static policy)               |
|                           +--> SupervisorMiddleware (PRE_CREDENTIALS) --+
+-------------------------------------------------------------------------+
```

---

# Core Capabilities

1. **Dual OpenShell Extension Surface in One Binary:**
   - **`SupervisorMiddleware` (`PRE_CREDENTIALS`):** Evaluates otherwise-authorized HTTP/S requests before OpenShell injects credentials. Never mutates headers or bodies (`has_body: false`, `header_mutations: []`).
   - **`GatewayInterceptor` (`VALIDATE` & `POST_COMMIT`):** Intercepts `CreateSandbox`, `UpdateConfig`, `ApproveDraftChunk`, `ApproveAllDraftChunks`, and `SubmitPolicyAnalysis`. Blocks `proposal_approval_mode=auto`, prevents stripping the `risk-guard` middleware, enforces control-plane non-expansion, and binds sandbox epochs synchronously.
2. **Interaction-Aware Behavioral Risk Scoring:**
   $$S = \min\bigl(100,\ 15N_r + 15N_a + 20T + 30I + 15(N_r \cdot I) + 10C + 15V + 15F\bigr)$$
   - Distinguishes harmless novelty (`GET /repos/org/new-docs` $\to S = 25 < 70$, allowed with observation) from consequential attacks (`curl` executing `DELETE /repos/org/payments-prod` $\to S = 85 \ge 70$, denied with `reason_code = "behavioral_risk_denied"`).
   - Uses policy-derived credential-bearing status ($C \in \{0, 1\}$ from `credential_binding` and `_provider_*` rules) without ever exposing raw secret values.
3. **Two-Tier Monotonic Ratchet (SQLite `WAL` + `synchronous=FULL`):**
   - **Tier 1 (`strict_epoch`):** High-impact ($I=1$) or `task_constraint` denials permanently latch `(host, port, method, resource_scope)` in SQLite for the remainder of the epoch—even across sidecar restarts.
   - **Tier 2 (`cooldown`):** Velocity/enumeration bursts ($I=0$) trigger a bounded cooldown window (`cooldown_until_ms`) and promote to Tier 1 on the 3rd strike.
4. **Periodic Policy Hardening & Two-Step Formal Containment Proof:**
   - Generates least-privilege YAML candidates from observed allowed traffic.
   - Resolves `openshell-prover`'s `network_middlewares` limitation ([`containment.rs`](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-prover/src/containment.rs)) via a **Two-Step Proof**:
     1. **Step 1:** Deterministic `network_middlewares` invariance and `fail_closed` verification.
     2. **Step 2:** Z3 SMT containment check (`openshell_prover::containment::check_within_boundary`) on the middleware-stripped projection across `filesystem, network_l4, network_rest, process, landlock`.

# Measured Release Gate Summary (Gates G-01 – G-12)

| Gate | Target | Measured Result |
|---|---|---|
| **G-01 Enforcement** | 0 upstream hits on denied requests | `0` upstream hits across all denied requests & retries |
| **G-02 Benign Impact** | 95% Clopper-Pearson upper bound $\le 1.0\%$ | `0 / 310` false denials ($\text{UB}_{95\%} = \mathbf{0.9617\%}$) |
| **G-03 Misuse Recall** | $\ge 90\%$ episode recall ($\ge 100$ episodes) | `105 / 105` ($\mathbf{100.0\%}$ across all 5 misuse families) |
| **G-04 Precision** | $\ge 80\%$ precision | $\mathbf{100.0\%}$ enforce precision; $\mathbf{85.4\%}$ alert episode precision |
| **G-05 Ablation Gain** | Beat static-only, novelty-only, and no-interaction | `FullContextual` $\mathbf{100.0\%}$ vs. `WithoutInteractionTerm` $\mathbf{60.0\%}$ |
| **G-06 Latency** | p95 $\le 25\text{ ms}$, p99 $\le 75\text{ ms}$ (20 workers, `WAL`+`FULL`) | `p50 = 2.60 ms`, `p95 = 3.21 ms`, `p99 = 3.56 ms` |
| **G-08 Replay** | Bit-for-bit deterministic replay | `1,694 / 1,694` requests identical across 415 episodes |
| **G-09 / G-12 Hardening** | Two-Step Z3 `within_boundary` proof + `0` replay blocks | `step1_invariant = true`, `step2_verdict = "within_boundary"`, `0/3` blocks |
| **G-10 / G-11 Reliability** | `WAL`+`FULL` (`2`)+`FK` (`1`) + crash/restart ratchet persistence | Verified `("wal", 2, 1)` and post-restart `behavioral_risk_restricted` |
