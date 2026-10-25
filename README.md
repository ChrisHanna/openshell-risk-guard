<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell Behavioral Risk Guard (`openshell-risk-guard`)

[![CI](https://github.com/ChrisHanna/openshell-risk-guard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ChrisHanna/openshell-risk-guard/actions/workflows/ci.yml)

## Status

Risk Guard runs end to end with a real OpenShell gateway, supervisor and sandbox.
It scores every inspected request, enforces denials before credentials are injected,
carries restrictions across sandboxes for the same workload, learns each workload's
normal behavior automatically in shadow mode, and records an explainable decision
for everything it evaluates. The gateway-to-sidecar channel is TLS with
gateway-signed JWTs, and the restriction state survives restarts. It is ready to
evaluate against your own OpenShell deployment and to extend.

What remains is validation on real traffic. Detection results so far come from
synthetic episodes, and the local demo uses scripted traffic, so tune thresholds
from your own captures before enforcing broadly. Details are in
[Evidence and limits](#evidence-and-limits).

## The story in one picture

Three open systems form one loop. **OpenShell** (NVIDIA) *permits*: it sandboxes each agent and decides what it may reach.
**Risk Guard** (this project) *judges*: it can only narrow what OpenShell allows, for this agent, right now. **OpenSearch** (the SIEM)
*remembers and reacts*: it holds the evidence from both, finds the unusual, and can ask Risk Guard to tighten, over an authenticated
door that only tightens. Red-team tests and promotion gates keep the whole thing honest.

```
agent -> OpenShell policy (permit) -> Risk Guard (judge) -> target
              |                            |
              +----- events (OCSF) --------+--> OpenSearch (remember: dashboards, anomaly detection)
                                                     |
        Risk Guard <---- mTLS, tighten only ---- signal forwarder <---- alert (react)
```

Start with [the story](docs/the-story.md) (the loop, why each piece exists, and a map of the repository), then
[how it works](docs/how-it-works.md) for the detail.

## See it work

The operator console, captured from a live run against a real OpenShell gateway and sandbox
(the upstream is a harmless local fixture).

![Fleet overview: workloads, active restrictions and blocked actions](docs/images/console-overview.png)

**Activity** follows one workload across its sandboxes to each destination. The risky `DELETE` is
stopped inline while the allowed `GET`s pass.

![Activity map: one workload, three sandboxes, a blocked DELETE and passing GETs](docs/images/console-activity.png)

**Detections** explain every score: the signals behind it, the thresholds, and the persisted
cross-sandbox lock that carried the restriction to a new sandbox. An operator can clear a lock with an
audited reason.

![Detections: score 100, signal breakdown and active restriction with audited recovery](docs/images/console-detections.png)

**Adaptive** learns each workload's normal behavior automatically in shadow mode. It never blocks
until an operator reviews and promotes a model. How it is measured, what it catches on scripted
traffic and what that does and does not show: [docs/adaptive-v2.md](docs/adaptive-v2.md).

![Adaptive: learning automatically, shadow model, deterministic guardrails only](docs/images/console-adaptive.png)

## At a glance

Risk Guard is a **sidecar** to the OpenShell gateway. OpenShell decides what an
agent is *permitted* to do; Risk Guard decides whether a permitted request is
*reasonable for this agent right now*, and can only narrow OpenShell's answer:
`FinalAllow = OpenShellAllow ∧ RiskPermit`. It plugs into OpenShell's own
extension points (`SupervisorMiddleware` before credentials are injected,
`GatewayInterceptor` on policy changes) and keeps its own SQLite state. It never
proxies traffic, stores secrets, or writes OpenShell policy.

## Where this fits: OpenShell and NVIDIA Sentry

Risk Guard is a **reference integration built to learn how to integrate with OpenShell**'s extension points and to show what
request-level evidence can add. It is a prototype, not a threat-protection product. **For threat-level protection of agents, the
recommended approach is OpenShell plus NVIDIA Sentry**, NVIDIA's out-of-band layer on BlueField-4 hardware (NVIDIA lists Sentry as
planned). Risk Guard is useful alongside it for visibility (why a request was allowed or blocked, per workload) and for improving
policies (learned behavior and prover-checked tighter policy candidates), and as a software stand-in where the hardware is not
available, as on this project's Azure deployment. Its checks run next to the workload, so it assumes an uncompromised supervisor and
node, which the hardware layer does not. See [Where Risk Guard fits](docs/positioning.md).

## Why Risk Guard for OpenShell Users: Closing the Authorized-Endpoint Gap

- **The OpenShell Foundation:** Kernel Landlock filesystem confinement, process isolation, static L4/L7 Rego network policies, credential injection only for approved endpoints, and Z3 formal verification (`openshell-prover`) on policy changes.
- **The Authorized-Endpoint Gap:** An AI agent needs real API permissions (e.g., `api.github.com`, internal billing, cloud APIs) to do its job—or starts with a broader Day-1 policy while a team discovers what routes it needs. Within those permitted endpoints, an agent can still perform a destructive action outside its task (`DELETE /repos/org/payments-prod`), rapidly enumerate 50+ resources in 60 seconds, or retry a blocked action when an orchestrator spins up a fresh sandbox container.
- **How Risk Guard Complements OpenShell:**

| Layer | NVIDIA OpenShell (Governed Runtime) | OpenShell Risk Guard (Behavioral & Task-Aware Sidecar) | How They Work Together |
|---|---|---|---|
| **Enforcement Boundary** | Kernel Landlock, process rules, static L4/L7 network policy, and credential injection. | Inline `SupervisorMiddleware` (`PRE_CREDENTIALS`) + `GatewayInterceptor` (`VALIDATE` / `POST_COMMIT`). | **Strictly attenuating (`FinalAllow = OpenShellAllow ∧ RiskPermit`):** Evaluates requests *after* static policy allows them and *before* credentials are injected. Never widens OpenShell's boundary. |
| **Workload Continuity & State** | Per-sandbox container/microVM isolation (`sandbox_id`), plus external IAM/Entra credential injection. | Durable **Agent Workload ID** (`agent_id` / `openshell.nvidia.com/agent-id`) and scoring context persisted in SQLite (`WAL + FULL`). | **Cross-sandbox continuity (distinct from IAM/Entra identity):** While OpenShell isolates individual containers and injects external credentials at the boundary, Risk Guard maps ephemeral sandboxes back to the same logical **Agent Workload**. If a workload triggers a Tier-1 lock or Tier-2 cooldown in Sandbox A, spinning up Sandbox B for the same workload inherits the restriction immediately. |
| **Day-1 to Day-N Policy Lifecycle** | Enforces active YAML policy and runs `openshell-prover` on proposed edits. | Observes allowed traffic, learns normal rate/fan-out envelopes in **Auto-Shadow** mode, and synthesizes least-privilege YAML candidates with a **Two-Step Z3 Containment Proof**. | **Safe progressive hardening:** Teams can start with a broader policy, catch task deviations inline, and export a prover-verified tightened OpenShell policy once behavior stabilizes. |
| **Operator Experience** | CLI (`openshell`), SDKs, and gateway control plane. | Operator console (default `http://127.0.0.1:8791`), live SQLite Guardrail tuning, audited UI/CLI lock recovery, and Prometheus `/metrics`. | Gives security/platform teams fleet-wide visibility into *why* agents make requests, instant threshold/mode tuning, and audited false-positive recovery. |

## Terminology

| Term | Meaning |
|---|---|
| **Workload ID** | The durable identity of a logical agent workload across runs and ephemeral sandboxes. It selects which restrictions, baseline and learning history apply. It carries no credentials, and a sandboxed process can neither assert nor change it. It is established one of two ways: **derived** from the creating workspace and the principal the gateway authenticated (`--workload-from-principal`, so it cannot be forged), or an **operator label** (`--agent-id` or the `openshell.nvidia.com/agent-id` annotation), which is an assertion. Stored as `agent_id`. |
| **Principal** | The authenticated operator or user OpenShell reports for a call, with the identity provider that vouched for it (`oidc`, `cloudflare_access`, `mtls`, or the unauthenticated `local_dev`). Allowlisted principals decide which sandboxes are bound to which workload ID. With `--workload-from-principal`, the workload is derived from the creating workspace and principal instead. |
| **Workspace** | OpenShell's isolation boundary for sandboxes, providers and policies. Derived workloads, auto-registered labels and `agent-register --workspace` workloads are scoped to one, so a sandbox from another workspace cannot bind to them. Not to be confused with a workload, or with the `/sandbox` directory. |
| **Sandbox**, **epoch** | An ephemeral OpenShell sandbox and the policy epoch it runs under. |
| **Run** | One execution of a workload, bound to its sandboxes. Many runs share one workload ID. |

"Workload" is the user-facing term. Machine names keep `agent` (the `agent_id` column,
`--agent-id`, `agent-register`, `/api/agents/...`) so existing data and tooling keep working.
Where this document says "the sandboxed process", it means the program running inside a sandbox.

## Evidence and limits

- **Detection is measured, but only on the author's own data.** The scoring logic is checked on 415 synthetic episodes. On the
  live fleet (three scripted agents, real gateway and sandboxes) 193 routine calls had no false denials (95% interval 0 to 2.0%)
  and 38 of 42 tempting calls were blocked; the four misses were a `v1` profile that did not enforce its approved-action list,
  fixed in `v2`. A red-team set covers path and encoding variants, and records what is *not* caught (slow enumeration and bursts
  on a cold-start profile, anything in bodies, headers or query strings). The labels and agents are the author's, so this is a
  regression check, not accuracy against an unseen attacker. See [Detection results](docs/detection-results.md).
- **Decision time is measured on the live path.** Each decision's server-side time goes into a histogram shown on the console and in
  `/metrics` (p50/p95/p99 upper bounds, slowest, calls over the 500 ms OpenShell timeout). It excludes network transit.
- **Sandbox lifecycle is derived, not guaranteed.** The gateway's delete event is best-effort, so a missed one is never retried.
  Sandboxes not seen for 6 hours are shown as "presumed gone" rather than deleted from the record, and return to open if traffic resumes.
- **CI** builds from a clean clone with the pinned toolchain, runs the tests, clippy and dependency checks (`cargo-deny`).
- **One gateway, one writer.** A single SQLite writer is what makes the ratchet
  durable and linearizable. Move to a shared store only when you need several
  gateway replicas or exceed measured single-writer throughput.
- **Rules run in shadow or enforce.** The approved-action and approved-resource rules default to shadow: they record what
  they would have blocked without blocking it, and an operator promotes one to enforce once its record looks right. The deny
  list and the high-impact rule enforce. See [Operating Risk Guard](docs/operations.md#rule-modes-shadow-first-then-enforce).
- **Workload identity beyond OpenShell's gateway (demonstration).** Callers can instead prove who they are with a SPIFFE X.509-SVID
  (SPIRE) over mutual TLS, and an Envoy egress proxy can enforce Risk Guard's decision on the network path, outside the workload.
  Verified on AKS for demo workloads (plain HTTP inside the cluster). OpenShell's own sandboxes get a weaker gate on the network path:
  their TLS tunnels go through an Envoy proxy that refuses operator-quarantined workloads. See [Workload identity](docs/workload-identity.md)
  and the [architecture](docs/architecture.md). Each OpenShell sandbox also has a SPIFFE identity issued by SPIRE through OpenShell's own
  support, used for credential-less token grants and shown in the console; Risk Guard does not verify it. A task profile can also list
  the hostnames its sandboxes may open an encrypted connection to (`approved_egress_hosts`), checked at the tunnel gate outside the supervisor
  (shadow by default).
- **Containment is tested, not assumed.** `scripts/conformance/` holds runners that produce machine-readable reports in `conformance/`: whether a sandbox or a compromised supervisor can bypass the proxy (and the Cilium fence that closes most routes), how long an open tunnel survives a quarantine (at most 120 s), how the system behaves when Risk Guard, its database or its credentials fail, and where the security services run and what the sandbox service accounts may change. The threat model, with the gaps stated, is in [Deployment security](docs/deployment-security.md); the placement decision is [ADR 0001](docs/adr/0001-security-placement.md). The Kubernetes baseline and its documented exceptions are in [Hardening](docs/hardening.md); identity attribution, token threats and the key-rotation drill are in [Identity hardening](docs/identity-hardening.md). Measured cost and capacity of the enforcement path (about 5.5 ms median for the gate, a ceiling near 100 decisions/s that fails closed) are in [Benchmark](docs/benchmark.md). Recorded decisions can be exported and replayed from nothing to check they reproduce: [Decision replay](docs/replay.md). The supported hardened install, the release gate (SBOMs, scans, digest pinning) and an upgrade/rollback drill are in [Release](docs/release.md). For a meeting: the [partner demonstration](docs/partner-demo.md) (a 90-second scripted run against the live deployment), the [results sheet](docs/results-sheet.md), [sizing and cost](docs/sizing-and-cost.md), the [production gaps](docs/production-gaps.md) and a design-only note on [confidential computing](docs/confidential-computing-design.md). For security vendors: how Risk Guard's decisions reach a SIEM through OpenShell's own OCSF export, verified on the cluster, is in [SIEM integration](docs/siem-integration.md).
- **Network only.** Risk Guard scores HTTP/S requests that OpenShell inspects.
  Filesystem and process behavior are enforced statically by OpenShell
  (Landlock and policy), not scored.
- **Bodies and headers are received but never used.** OpenShell's middleware call
  delivers the request body, headers and query (up to the registered
  `max_payload_bytes`). Risk Guard discards them unread and never stores or logs
  them. Routes whose effect depends on the body (GraphQL, unknown POSTs) are treated
  as high-impact by default. OpenShell treats an oversized payload as a middleware
  failure, so Risk Guard advertises and is registered for the 4 MiB platform maximum;
  a large body is never denied just for its size.
- **Operators.** On the AKS deployment the console is public to read, and an administrator signs in with Microsoft Entra
  at `/admin` to change settings; changes are recorded against the verified account (object ID). A local console
  without sign-in uses one private capability token, and its audit records the capability, not a person.
- **Raw resource names** (for example `org/payments-prod`) are stored for operator
  explanations. The database is owner-only (`0600`). Put it on an encrypted volume.

## Quickstart

See the operator console with sample data in about ten minutes. It needs Rust, a C++ toolchain and internet access, and no
OpenShell checkout, cluster or Docker ([full prerequisites and troubleshooting](docs/getting-started.md)):

```bash
git clone https://github.com/ChrisHanna/openshell-risk-guard.git && cd openshell-risk-guard
cargo build --locked --release                     # about 5 minutes the first time
scripts/seed-sample-data.sh                        # a sample database, in about a second
target/release/openshell-risk-guard dashboard --db /tmp/risk-guard-sample.db
# then open http://127.0.0.1:8787/
```

Other ways in: run the tests, run it against a real OpenShell gateway locally ([Demo and local deployment](docs/demo.md)), or
deploy it on Azure with live agents ([Running on AKS](docs/aks.md)). [Getting started](docs/getting-started.md) compares them.

`./scripts/demo.sh` runs the synthetic evaluation, latency benchmark and 10-step end-to-end suite (`--interactive` pauses between
stages).

### Operator CLI commands

```bash
# 1. Start the unified gRPC sidecar (SupervisorMiddleware + GatewayInterceptor).
#    TLS, the HMAC key and the gateway's JWT public key are required; see
#    docs/operations.md. For a single-user loopback test only, replace the three
#    secret flags with --allow-insecure-local-test.
cargo run -- serve \
  --listen 127.0.0.1:50061 \
  --db /tmp/risk-guard.db \
  --gateway-id local-gateway \
  --audience urn:openshell:extension:risk-guard \
  --public-key-pem /path/to/gateway-public.pem \
  --tls-cert /path/to/tls.crt --tls-key /path/to/tls.key \
  --hmac-key-file /path/to/hmac.key

# 2. Create/bind a governed policy epoch for a sandbox
cargo run -- epoch-create \
  --db /tmp/risk-guard.db \
  --sandbox-id sbx-demo-01 \
  --task-profile repo-triage-readonly \
  --mode enforce \
  --policy ./policy.yaml

# 3. Inspect recorded explainable risk decisions for a sandbox
cargo run -- decision-inspect \
  --db /tmp/risk-guard.db \
  --sandbox-id sbx-demo-01 \
  --limit 10

# 4. Generate a prover-verified least-privilege hardening recommendation
cargo run -- hardening-report \
  --db /tmp/risk-guard.db \
  --sandbox-id sbx-demo-01 \
  --policy ./policy.yaml \
  --out /tmp/hardening-recommendation.json
```

## Documentation

| Read | For |
|---|---|
| [Demo runbook](docs/demo-runbook.md) | Ten minutes in order: what to open, what to run, what to say, the questions to expect, and the rough edges to avoid. `scripts/demo/preflight.py` checks the deployment first |
| [Who blocks, who recommends](docs/who-does-what.md) | One page: what can stop a call, what only advises, who decides what loosens, and the flow of one call |
| [The story](docs/the-story.md) | How OpenShell, Risk Guard and OpenSearch fit together, why each is there, and where things live in the repository |
| [How it works](docs/how-it-works.md) | The whole system on one page: decision path, state, identity, SIEM events and dashboards, signals back from the SIEM, two-person approval, promotion gate, red-team tests, deployment, and current limits |
| [Getting started](docs/getting-started.md) | Four ways to run it, from ten minutes with sample data to a live Azure deployment; prerequisites and troubleshooting |
| [Operating Risk Guard](docs/operations.md) | TLS and secrets, bootstrap order, protecting a new API, recovering from a false positive, metrics, rollout |
| [Security model](docs/security-model.md) | How the sidecar sits next to OpenShell, workload ID continuity, trust boundaries, measured release gates |
| [Where Risk Guard fits](docs/positioning.md) | What this project is for, why OpenShell plus NVIDIA Sentry is the recommended approach for threat-level protection, and what Risk Guard adds beside it |
| [Running on AKS](docs/aks.md) | Deploy OpenShell and Risk Guard on Azure Kubernetes Service with scripts: Kata VM sandboxes, Key Vault credentials, Entra agent identities, a protected public console, and what a real cluster showed |
| [Demo and local deployment](docs/demo.md) | Running the local demo stack and its traffic generator |
| [Requirements](docs/requirements.md), [Design](docs/design.md), [Anomaly detection](docs/anomaly-detection.md) | Specifications and the scoring model |
| [Architecture and security review](docs/architecture-review.md) | A critical review of how the three systems fit, what the SIEM really adds, and the gaps |

## Building

`openshell-risk-guard` builds on its own. The few [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) crates it uses
are fetched from NVIDIA's public repository, pinned to one commit in `Cargo.toml`, so the build needs network access to
github.com and nothing else:

```bash
git clone https://github.com/ChrisHanna/openshell-risk-guard.git
cd openshell-risk-guard && cargo build --locked
```

To move to another OpenShell commit, change `rev` on the seven `openshell-*` lines together and run
`cargo update -p openshell-core`. No OpenShell checkout is needed for anything, including running it: the AKS scripts install
OpenShell from NVIDIA's published Helm chart and images at the pinned commit, and `scripts/install-openshell-cli.sh` builds the
matching `openshell` CLI (add `--all` for the gateway, supervisor and sandbox the local demo runs).

## License

Apache-2.0. See [LICENSE](LICENSE). This is an independent project and is not affiliated with or endorsed by NVIDIA.
