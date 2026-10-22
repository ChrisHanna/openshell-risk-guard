# Rail-guard demo and local deployment

The local OpenShell + Risk Guard demo stack (scripted traffic, not a production deployment), plus native deployment prerequisites. Overview: [README](../README.md).

## Start the demo stack

From the workspace root in PowerShell:

```powershell
.\scripts\rail-guard-demo.ps1 -Action start -AllowInsecureLocalTest
```

See [demo launcher operations](../deploy/rail-guard-demo/README.md) for preparation, persistence
and shutdown. Matching binaries, checksummed images and an offline image archive
are prepared separately; startup does not build, install or download anything.
The launcher opens the dashboard only after real sandbox traffic passes its
effects checks. Keep its terminal open; Ctrl-C stops its owned services.
If the demo stack is already running, open <http://127.0.0.1:8791/> rather
than launching a second owner.

Verified on Ubuntu 24.04 WSL2 with an isolated rootful Docker 29.8.1 daemon:
native gateway/supervisor/sandbox startup, permitted GET reaching the harmless
fixture, Risk Guard-denied DELETE with zero upstream DELETE hits, and a second
run/sandbox inheriting the same workload ID's restriction. Windows launcher warm
restart and restart from a stopped isolated Docker daemon preserve evidence.
A full Windows/WSL reboot has not been tested because this WSL distribution
also hosts unrelated work.

This uses explicit **insecure local-test transport**. The example baseline has
zero training sessions/requests: its denial demonstrates an operator task
constraint and persisted restriction, not learned statistical anomaly detection.
The API target is a harmless local fixture; the sandbox traffic, supervisor
middleware calls, decisions and enforcement are real.

The default `dashboard` command is a separate, read-only operator interface.
It reads an existing database and opens on **Fleet overview**, followed by a
searchable **Agents** directory and a selected agent's investigation workspace.
It shows persisted request evidence, baseline context, scoped restrictions and
recommendations.
It never launches workloads, resets evidence, or silently learns from history. Optional
operator controls use a private local capability token; they are disabled unless
`--operator-token-file` is supplied.
Gateway connectivity, runtime lifecycle, upstream outcome and transport provenance
are explicitly unknown until collected. An active epoch is not proof of a running
sandbox; a request score is not a probability of compromise.

### Operator console workflow

- **Activity** connects a workload ID to its sandboxes, network enforcement
  decisions, and destinations. Time and boundary controls apply to this view
  and **Detections**, not to fleet totals or saved recommendations. The map
  labels its sandbox sample; full loaded run bindings remain in **Runs**.
  `pass` means a recorded allow decision, not proven upstream delivery.
- **Detections** groups request scores and contributing signals. The filesystem
  policy posture heuristic is explicitly separate from request scores; saved
  policy snapshots are not runtime file-operation telemetry.
- **Recommendations** shows the latest stored candidate, its recorded proof
  and replay details, and the candidate YAML. Filesystem examples are labeled
  manual guidance, not additional prover-verified candidates. No policies are
  applied by the console.
- **Runs** connects execution bindings to contextual agent/sandbox **Audit
  evidence**. **Enforcement** (formerly "Guardrails") loads actual recorded settings. After **Unlock
  editing**, **Save & apply** validates and commits a new per-agent SQLite
  revision. Reloads and process restarts retain saved values; unsaved drafts
  remain local and are not confused with successful saves.
- **Adaptive** learns **automatically for every workload ID** (shadow only); an
  operator can pause it per agent (`set_auto_learning`). The tab opens on a status
  card (learning, shadow model, blocking, next step) with manual controls under
  **Advanced**. Pristine single-sandbox runs enroll on their first native request and
  auto-approve on run/epoch end only when every observation is strictly read-only
  *and* a plain allow (`reviewed_by = "auto-clean-policy"`); anything flagged, and
  every manually started capture, waits for human review. Approved windows fit/update the active
  shadow model (`shadow_model_id`), while **Enforce promotion** remains manual
  behind the 20-train / 5-holdout / 5-shadow gates, and the promotion dialog shows
  how many training windows were auto-approved. Models never grant broader native
  permissions.

The offline Graphite theme uses system fonts, restrained semantic colors,
keyboard-visible focus, and monospace only for technical content. Narrow views
keep tables and the readable-size map locally scrollable rather than shrinking
labels. Auto-refresh starts disabled; when enabled it polls every ten seconds.
New request IDs can trigger a single visual pulse, while **Replay flow** is
explicitly historical. Idle views, denied gate-to-destination paths, and static
filesystem links do not emit packets. Reduced-motion preferences suppress
packets without changing evidence.

### Saved guardrails and application timing

Mode, score thresholds, cooldown duration, approved resources, expected action
classes, the unfamiliar-high-impact task constraint, and request-rate/fan-out
envelopes affect **subsequent new requests** for the bound workload ID. The evaluator
reads committed settings in its decision transaction, including when the
dashboard and middleware are separate processes. Other agents are unaffected.

Edits do not clear existing strict/cooldown restrictions, rolling windows, or
request-idempotency records. Historical decisions remain pinned to their original
settings revision. Immutable run/context bindings remain the workload provenance;
versioned agent-wide operator overrides are recorded separately, including an
effective baseline snapshot. Existing explicit forbidden-action constraints are
not removed by editing the expected-action list.

The p95/p99 fields are **detector envelopes, not hard quotas**. Statistical
enforcement still requires a mature baseline. In enforce mode, Layer A task
constraints deny independently of the statistical block threshold. In observe
mode they are recorded as observations and the request is allowed; only
existing strict/cooldown restrictions still deny. Observe mode never relaxes the
control plane: draft-chunk approvals and policy-expansion proposals stay guarded
for every active governed epoch.

Task-profile selection and filesystem policy are saved desired configuration for
a **new run/sandbox**. OpenShell cannot hot-change activated filesystem, Landlock,
or process policies. The console reports pending/new-sandbox-required status
rather than claiming a database save changed kernel enforcement. A recorded
policy match is not runtime-load telemetry. No running workload is automatically
stopped, replaced, or granted broader native permissions.

The selected task profile must already have been imported and approved.
New trusted run bindings validate the saved profile, mode, and any managed
filesystem settings. Export the next-run policy before creating a replacement:

```bash
openshell-risk-guard guardrails-show --db ./risk-guard.db --agent-id repository-reviewer
openshell-risk-guard guardrails-export --db ./risk-guard.db \
  --agent-id repository-reviewer --out ./next-sandbox-policy.yaml
```

The exported policy retains the native `fail_closed` Risk Guard binding and
uses the exact approved profile artifact. It is not an automatic live update.
Create the new sandbox through the normal trusted provisioning path, then bind
its pristine epoch to a run using the saved profile and mode.

To enable editing on a standalone loopback dashboard, supply an absolute token
path in a private runtime directory:

```bash
mkdir -p "$HOME/.local/state/openshell-risk-guard"
chmod 700 "$HOME/.local/state/openshell-risk-guard"
openshell-risk-guard dashboard --db ./risk-guard.db --listen 127.0.0.1:8787 \
  --operator-token-file "$HOME/.local/state/openshell-risk-guard/operator-token"
```

The token is generated once as an owner-only file on Unix and is never returned
by the API or logged. Read it only in your local terminal and paste it into
**Unlock editing**; do not paste it into chat or commit it. The browser holds it
only in the current tab's memory, not cookies, URLs or browser storage. Reloading
the page locks editing again without losing saved settings. Operator writes
require Unix file-privacy validation; use WSL on Windows. Native non-Unix builds
reject the control option rather than accepting an unverified token-file ACL.

Writes require both the token and the exact dashboard Origin. This is a
single-local-operator capability, not SSO, multi-tenant RBAC, or production
identity attestation. Stale revisions are rejected with HTTP 409; invalid edits
are rejected without changing the saved head. The revision history records the
local-operator capability identity, settings hash, and server timestamp.

Operational startup requires explicit baseline provisioning:

```bash
# Import an artifact reviewed by the operator, with normalizer_version: v1.
# The CLI trusts the local operator; approved_by is not a verified signature.
cargo run -- baseline-import --db ./risk-guard.db --profile ./approved-baseline.json

# Register the workload once, then create a run for an approved task.
cargo run -- agent-register --db ./risk-guard.db \
  --agent-id repository-reviewer --display-name "Repository reviewer"
cargo run -- run-create --db ./risk-guard.db \
  --agent-id repository-reviewer --run-id review-001 \
  --agent-revision revision-1 --task-profile repo-triage-readonly

# Start the native gRPC extension endpoint using the gateway's trusted public key.
cargo run -- serve --db ./risk-guard.db \
  --default-task-profile repo-triage-readonly \
  --gateway-id local-gateway --public-key-pem ./gateway-public.pem

# After OpenShell provisions the sandbox epoch, bind its actual sandbox ID
# BEFORE the sandboxed process sends traffic. No workload ID is accepted from traffic.
cargo run -- run-bind --db ./risk-guard.db --run-id review-001 \
  --sandbox-id ACTUAL_SANDBOX_ID --gateway-id local-gateway

# In a separate terminal, inspect the SAME service-owned database.
cargo run -- dashboard --db ./risk-guard.db --listen 127.0.0.1:8787
```

`serve`, `epoch-create`, inspection and reporting no longer seed fixture
baselines. Unknown task profiles are errors, not fabricated baseline hashes.
`--allow-insecure-local-test` is an explicit test-only authentication bypass.
Existing databases are not scrubbed: previously seeded fixture artifacts remain,
so use a new database and explicitly reviewed artifacts for operational use.
Do not point the operational interface at an old demo database and infer that
its events came from native sandboxes.

### Adaptive anomaly detection & Automated Shadow Learning

The adaptive layer is separate from the imported operator baseline. Its empirical
destination/resource/action frequencies and request-rate/fan-out envelopes derive
from recorded observations, not editable `training_sessions` assertions. Neither
training nor promotion rewrites the original task constraints or permissions.
Interpretation weights remain fixed and transparent; this is statistical learning,
not a trained neural classifier or a calibrated probability of compromise.

**Automated Shadow Learning** is **on by default for every workload ID** and can be
paused per agent with `set_auto_learning`. Automating it is safe because learning
can never block: only unflagged read-only windows auto-approve, models only reach
shadow, and enforcement needs an explicit, evidence-bound promotion that shows how
many training windows no human reviewed:

1. **Automatic enrollment on first native request:** When a pristine, trusted-bound,
   single-sandbox run emits its first native supervisor HTTP evaluation, it
   automatically enrolls a capture window (freezing the run's sandbox binding so
   training and live temporal history remain comparable). Historical demo runs,
   CLI evaluations, idempotent replays, mid-run/multi-sandbox enrollments and
   self-declared workload identities are rejected.
2. **Strict read-only auto-approval (`reviewed_by = "auto-clean-policy"`):** When
   the run or epoch ends, an auto-enrolled window is automatically approved only if
   every recorded observation was a plain allow (none merely allowed with an
   observation) and strictly read-only (`semantic_category == "read_only"`
   with zero denials, high-impact actions, task-constraint violations, unknown
   routes, source mismatches, guardrails changes, or budget overflows). Routes
   classified as `write_mutation` as well as `POST /graphql` are excluded from
   clean read-only training because request bodies are not inspected at
   `PRE_CREDENTIALS`. Any non-clean observation quarantines the entire window;
   the trainer never silently extracts a clean subset. Operators can also
   manually start, finish, approve, or withdraw windows in the **Adaptive** tab.
3. **Automatic shadow model fitting (`shadow_model_id`):** Cleanly closed runs
   automatically fit or update the active shadow candidate (`shadow_model_id`),
   grouping approved windows by **whole independent run** with later
   nonoverlapping runs held out chronologically where available. A sparse
   candidate remains provisional in shadow. Its frozen membership, model hash,
   algorithm version and empirical replay results survive restart.
4. **Manual Enforce promotion behind strict gates:** Shadow evaluation never
   changes the actual allow/deny decision or its deterministic risk score.
   Promoting a shadow candidate to **Enforce** remains strictly manual and is
   gated behind the 20-train / 5-holdout / 5-shadow thresholds.

Phase-1 minimum gates are 20 training runs / 200 training requests, 5 later
holdout runs / 50 holdout requests, no held-out model would-blocks, and 50 fresh
clean native shadow observations across 5 runs. Sparse-tail and other algorithm
gates can require more evidence. These are engineering safeguards, **not**
production accuracy, p99 confidence or false-positive guarantees. Live shadow
traffic is unlabeled: its anomaly/would-block frequency is not a measured
false-positive rate. A lone unfamiliar read is not sufficient for a learned block.

Learning is scoped to the original agent/revision/task/configuration context,
exact saved guardrails revision, and authentication scope. **Local demo** evidence
is explicitly unverified and cannot train or enforce a verified-transport model.
Changing guardrails makes previous models incompatible. Retraining starts a new
shadow candidate without silently replacing an enforced model. Turning a model
off or withdrawing a window's approval never clears restrictions or decision
history; withdrawal revokes derived models. Enforcement can add scoped cooldown
denials only, never relax OpenShell's boundaries.

Capture is bounded to 500 requests and one hour per window; phase-1 datasets
contain at most 100 windows. Shadow promotion support excludes all training and
holdout run IDs; continuing a dataset run is not independent validation.
Metadata privacy rules still exclude bodies, headers and queries.
Filesystem policy snapshots are **not** file-access telemetry; filesystem learning
is not implemented.

Inspect state using `adaptive-show --db ./risk-guard.db --agent-id AGENT`.
For scripted local operation, `adaptive-apply --db ./risk-guard.db --agent-id AGENT
--request ./operation.json` accepts the same strictly typed operation document as
the console API. Direct CLI access requires trusted local database access.

Run `node tests/adaptive_ui_contract.cjs` to check the console's native run
binding-count response contract without installing browser dependencies.

The API is local-only. Default evidence routes are `GET /api/state`,
`GET /api/agents/{agent_id}`, `GET /api/sandboxes/{sandbox_id}`, and Prometheus
`GET /metrics`.
`GET /api/agents/{agent_id}/guardrails` exposes saved settings/application status;
`GET .../guardrails/policy` exports the saved next-run policy.
With operator controls explicitly enabled, authenticated same-origin
`PUT .../guardrails` saves a validated revision, and authenticated
`POST /api/agents/{agent_id}/restrictions/clear` clears an active restriction scope
with an audited operator reason in `restriction_clearances`. Operator capability status and
verification use `/api/operator/status` and `/api/operator/verify`.
`GET /api/agents/{agent_id}/adaptive` reports curated learning state;
authenticated same-origin `POST` to that route accepts `start_capture`,
`review_capture`, `train`, `set_model`, and `set_auto_learning` operations. Writes share the existing
private operator capability and 64 KiB limit; stale revisions/active heads return
409, and insufficient-evidence promotion fails explicitly.
There are still no scenario, evidence-reset, or arbitrary command-execution APIs.
Inventory is capped at 200 agents and 200 sandboxes; sandbox detail
shows the current epoch's newest 100 decisions, up to 100 active restrictions,
20 recommendations and 100 recorded coverage gaps. Restrictions exclude expired
cooldowns. Agent context restrictions survive inactive execution epochs.
This is a single-gateway-per-database design.
Use an authenticated tunnel for remote access; public binding is rejected.

## Native local deployment prerequisites

See [local deployment operations](../deploy/local/OPERATIONS.md) and run
`bash scripts/deploy-local-risk-guard.sh --check` from the workspace root
in Linux before attempting startup. The flow uses actual gateway configuration,
supervisor middleware registration and a paired workload/supervisor topology;
it requires a matching gateway built from the pinned OpenShell commit (`scripts/install-openshell-cli.sh --all`) and a qualified
rootful, same-host Docker environment. Test-only startup requires explicit
`--allow-insecure-local-test` consent.

Native qualification is verified via the isolated rootful Docker daemon
(`/run/openshell-risk-guard-demo/docker.sock`) and pinned `0.1.5-dev` binaries
staged in `~/openshell-demo` (see [demo launcher operations](../deploy/rail-guard-demo/README.md)),
while the default user-session rootless Docker socket (`/run/user/1000/docker.sock`)
remains intentionally unqualified. Do not deploy the old Azure polling harness as
an OpenShell demo.

`openshell-risk-guard` is a containerized sidecar extension for [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell/blob/main/README.md) that adds **behavioral risk-based conditional access** and **formally verified policy hardening** for autonomous AI agents.

Unlike a standalone proxy or an approval system that can grant new permissions, `openshell-risk-guard` is **strictly attenuating on the data plane** and **monotonically non-expanding on the control plane**:

$$\text{FinalAllow}(a) = \text{OpenShellAllow}(a) \land \text{RiskPermit}_t(a)$$

## Workload binding in the demo

By default the launcher starts the sidecar with `--workload-from-principal`: each sandbox binds itself to a
workload derived from its workspace and the principal that created it, and the Runs tab shows both. Local
OpenShell reports every caller as its unauthenticated local-development user (`user:unauthenticated-local-dev`,
provider `local_dev`), which only binds because the demo starts the sidecar with the explicit, local-only
`--allow-local-dev-principal`. All local sandboxes therefore share one workload. Set
`RAIL_GUARD_DEMO_WORKLOAD_FROM_PRINCIPAL=0` for explicit `run-create` / `run-bind` binding with the
`demo-reviewer` workload and the fixed allow/deny rehearsal.

## Live traffic generator

`scripts/rail-guard-demo-traffic.sh` (PowerShell wrapper: `scripts/rail-guard-demo-traffic.ps1`) keeps one sandbox
under a dedicated `live-traffic` workload and, every 60-120 seconds, runs one scripted action inside it so the
console always has fresh traffic:

| Action | Expected result |
|---|---|
| `GET /repos/local/review/issues` | 200, allowed by OpenShell and Risk Guard |
| `DELETE /repos/local/production` | 403, OpenShell allows it, Risk Guard denies it |
| `GET /repos/local/production/secrets` | 403, blocked by OpenShell's static policy before Risk Guard |
| Filesystem checks | `/tmp` and `/sandbox` writable; `/etc` and `/usr` blocked by Landlock (not scored by Risk Guard) |

Commands: `start [min_seconds] [max_seconds]`, `stop`, `status`, `once`, `reset`. The traffic is scripted `curl`
and shell, with no LLM, against a local GitHub-like fixture, not github.com.

## Real agent: NVIDIA NeMo Agent Toolkit

`scripts/rail-guard-demo-agent.sh` runs a real [NeMo Agent Toolkit](https://docs.nvidia.com/nemo/agent-toolkit/latest/index.html)
ReAct agent on a hosted Nemotron model inside an OpenShell sandbox. The model chooses which tool to
call, and each tool makes a real HTTP request to the local fixture, so the traffic Risk Guard scores is
traffic the model decided to send. Inference goes to `integrate.api.nvidia.com` using a key held by OpenShell
(provider `nvidia-nat`); the sandbox never sees it.

Files are in `deploy/rail-guard-demo/agent/` (image, tools, workflow, provider profile and sandbox policy).

```bash
# one-time: build the image (needs network) and save your key to a 0600 file
docker build --network host -t risk-guard-demo/nat-agent:2 deploy/rail-guard-demo/agent
echo 'NVIDIA_API_KEY=...' > ~/.config/rail-guard-demo/nvidia.env && chmod 600 ~/.config/rail-guard-demo/nvidia.env

scripts/rail-guard-demo-agent.sh setup              # import the profile, create the provider
scripts/rail-guard-demo-agent.sh probe              # no model or key: checks sandbox, policy and scoring
scripts/rail-guard-demo-agent.sh run triage         # benign task
scripts/rail-guard-demo-agent.sh run overreach      # task nudges the agent to delete the production repo
GUARDRAILS=on scripts/rail-guard-demo-agent.sh run overreach   # NeMo Guardrails input rail screens the task first
scripts/rail-guard-demo-agent.sh export             # decisions for the last run as JSON lines
```

Each run is a fresh run and sandbox under the workload `nat-agent`, so a denial in one run restricts the
next, which is the cross-sandbox behavior the console shows. Transcripts and exported decisions are saved in
`$HOME/.local/state/openshell-risk-guard-demo/agent-runs/`. Free hosted models can be slow or rate-limited;
what the agent does is up to the model, so runs differ.

### Layers

With `GUARDRAILS=on`, [NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/latest/about-nemo-guardrails-library/overview)
screens the task with an input rail (`deploy/rail-guard-demo/agent/guardrails/`) before the agent starts. If the
rail cannot run, the runner fails closed. The three layers are independent, so each one can be demonstrated:

| Layer | Decides | Example |
|---|---|---|
| NeMo Guardrails (model) | Should the agent take this request at all? | "Delete the production repo" is blocked before the agent starts |
| OpenShell policy (runtime) | May this process reach this endpoint and path? | `/production/secrets` is blocked by the static policy |
| Risk Guard (behavior) | Is this permitted call reasonable for this workload now? | `DELETE /production` is allowed by policy and denied by score |

Run `overreach` with guardrails off to see Risk Guard catch it, and on to see the rail stop it first.
