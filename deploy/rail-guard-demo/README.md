# Rail-guard demo launcher

**LOCAL DEMO.** This runs a real native OpenShell gateway, supervisor and sandbox with
Risk Guard as its middleware, against a harmless local HTTP fixture. It is not
`demo-dashboard` or `evaluate-request`. The gateway client listener (`127.0.0.1:17671`)
stays on host loopback, and the extension channel
between `openshell-gateway` / `openshell-supervisor` and `openshell-risk-guard`
(`https://127.0.0.1:50061`) now runs **full TLS + Ed25519 `openshell-ext+jwt`
verification (`tls=true`, recording `native_supervisor_http_rpc_verified`)**
provisioned via `local-secrets-generate` and the gateway's Ed25519 key.
Never expose these loopback ports to an untrusted network.

## 5-Minute Live Walkthrough (4 Acts)

### Quick Prep Commands (PowerShell from Workspace Root)

```powershell
# Verify all services (gateway, risk-guard TLS+JWT sidecar, fixture, dashboard, /metrics) are healthy
.\scripts\rail-guard-demo-presenter.ps1 -Action status

# Copy the private operator token to your Windows clipboard (never printed in terminal)
.\scripts\rail-guard-demo-presenter.ps1 -Action copy-token

# Run a live zero-click native sandbox lifecycle (CreateSandbox -> GET -> DeleteSandbox)
.\scripts\rail-guard-demo-presenter.ps1 -Action live-auto-shadow

# Reset to a clean baseline stage (2 sandboxes, 3 decisions, 1 active lock, 1 shadow model)
.\scripts\rail-guard-demo-presenter.ps1 -Action clean-stage
```

---

### Act 1: Why Risk Guard + OpenShell (`Fleet overview` & `/metrics`)

1. Open `http://127.0.0.1:8791` on **Fleet overview** (and optionally `http://127.0.0.1:8791/metrics`).
2. **Core framing:** OpenShell enforces strong static kernel/network boundaries (Landlock, process isolation, L4/L7 Rego, credential injection, and Z3 policy proofs). Risk Guard closes the **Authorized-Endpoint Gap**: within endpoints an agent is allowed to reach, Risk Guard evaluates whether each action is reasonable for the agent's current task and recent rate/fan-out history.
3. Highlight the strictly attenuating contract:
   $$\text{FinalAllow}(a) = \text{OpenShellAllow}(a) \land \text{RiskPermit}_t(a)$$
   Evaluated at `PRE_CREDENTIALS` over verified TLS + Ed25519 `openshell-ext+jwt` (`native_supervisor_http_rpc_verified`) before OpenShell injects secrets.

---

### Act 2: Inline Containment, Cross-Sandbox Ratchet & Live Controls (`Activity`, `Detections`, `Guardrails`)

1. Select agent **`demo-reviewer`** and open **Activity** / **Detections**:
   - **Allowed `GET /repos/local/review/issues` (`200`):** Matches the agent's approved resource (`local/review`) and read-only profile (`score = 0 < 70`).
   - **Blocked `DELETE /repos/local/production` (`403`, `0` upstream hits):** Static OpenShell policy permitted `DELETE`, but Risk Guard caught the unfamiliar high-impact action at `PRE_CREDENTIALS` (`reason_code = "behavioral_risk_denied"`, `score = 85 >= 70`), prevented credential injection (`upstream_delete_count = 0`), and latched a **Tier-1 strict restriction**.
   - **Cross-sandbox workload continuity (`behavioral_risk_restricted`):** When a second real OpenShell sandbox spun up under the same durable **Agent Workload ID** (`demo-reviewer`) and retried `DELETE /repos/local/production`, Risk Guard immediately denied it (`score = 100`, `0` upstream hits) because restrictions attach to the logical **Agent Workload** in SQLite (`WAL + FULL`), not the ephemeral container (and distinct from external IAM/Entra credentials).
2. Open **Guardrails**:
   - Click **Unlock editing** and paste the token from `.\scripts\rail-guard-demo-presenter.ps1 -Action copy-token`.
   - Show live SQLite-backed tuning (**Mode**, **Block threshold**, **Cooldown**, **Expected resources**, **Unfamiliar high-impact constraint**) and click **Save & apply** to create an immutable guardrail revision.
   - Under **Active restrictions & lock recovery**, demonstrate audited **Clear lock**: enter an operator reason and click **Clear lock** (`POST /api/agents/{id}/restrictions/clear`), recording the clearance in `restriction_clearances`.

---

### Act 3: Zero-Click Automated Shadow Learning (`Adaptive` Tab + `live-auto-shadow`)

1. Open the **Adaptive** tab for `demo-reviewer` to show **Automated Shadow Learning** (`auto_learning_enabled = true`) and the active shadow candidate (`shadow_model_id`).
2. Point out why the initial demo runs did **not** poison the model: runs containing the denied `DELETE` probe were automatically quarantined by the strict read-only poisoning guard (`reviewed_by = "auto-clean-policy"` requires 100% plain-allow `read_only` requests and excludes `write_mutation` and `POST /graphql`).
3. Run a live native sandbox lifecycle from PowerShell:
   ```powershell
   .\scripts\rail-guard-demo-presenter.ps1 -Action live-auto-shadow
   ```
   - The presenter script registers the workload, creates the run and binds the new sandbox with the explicit `agent-register`, `run-create` and `run-bind` commands. (Annotation binding exists but is off here. This gateway allows unauthenticated users and reports every caller as `user:unauthenticated-local-dev`; allowlisting that with `serve --agent-binding-principal` would let anyone on the machine choose agent identities, so it is a local-test choice only. Use authenticated operators outside rehearsals.)
   - The sandbox executes a clean read-only `GET /repos/local/review/issues` (auto-enrolling a verified capture window).
   - `DeleteSandbox` (`POST_COMMIT`) automatically closes the epoch and ends the run—triggering `auto-clean-policy` approval and fitting a new shadow model (`shadow_model_id`) with zero manual CLI calls.
   - Point out that **Enforce** promotion remains strictly gated behind **20 training runs / 5 holdout runs / 5 shadow runs**.

---

### Act 4: Two-Step Z3 Formal Policy Hardening (`Recommendations` Tab)

1. Open the **Recommendations** tab for `demo-reviewer`.
2. Show how Risk Guard synthesizes a least-privilege OpenShell YAML policy candidate from observed allowed traffic (replacing broad `DELETE` permission on `/repos/local/production` with explicit read-only `GET /repos/local/review/issues` rules).
3. Show the **Two-Step Z3 Containment Proof** (`within_boundary`):
   - **Step 1:** Verifies `network_middlewares` invariance and `on_error: fail_closed` so the Risk Guard sidecar cannot be stripped.
   - **Step 2:** Runs `openshell-prover` Z3 SMT containment verification on the middleware-stripped projection across all five policy domains (`filesystem`, `network_l4`, `network_rest`, `process`, `landlock`), proving the tightened candidate never widens the original OpenShell boundary and has `0` held-out replay blocks.

## One Windows entry point

In this workspace, after the operator has staged the offline assets:

```powershell
.\scripts\rail-guard-demo.ps1 -Action check
.\scripts\rail-guard-demo.ps1 -Action start -AllowInsecureLocalTest
```

Default WSL distribution: `Ubuntu-24.04` (override `-Distro`). `-LinuxRoot` may
override the workspace's `wslpath` conversion. Other explicit parameters are
`-Assets`, `-State`, `-DockerBin`, `-DockerdBin`, and `-NoBrowser`. The launcher
uses an ordinary WSL user for the stack and `wsl -u root` only for the separately
approved daemon helper. Keep the launching window open: both owners remain
foreground children; no systemd unit, scheduled task, Docker context or global
firewall configuration is installed or changed.

On start, if the isolated daemon is absent after a reboot, the Windows launcher
starts its foreground helper. `check` never starts anything. A pre-existing
isolated daemon remains running after exit; a daemon started by this launcher
is stopped when its owner exits. The existing rootless daemon is never selected.

## Editing agent guardrails

The native launcher enables the optional authenticated guardrail editor using
the private `$STATE/operator-token` file (default
`$HOME/.local/state/openshell-risk-guard-demo/operator-token`). The file is
created with owner-only permissions on Unix. Read it in your local terminal,
paste it into **Guardrails -> Unlock editing**, then use **Save & apply**.
The token is never printed by the launcher, returned by the API, or committed.
Do not paste it into chat.

Saved values and their revision history persist in `risk-guard.db`. New requests
use supported Risk Guard changes without restarting the service. Existing
restrictions/cooldowns remain. Filesystem and approved task-profile changes are
saved as pending until a newly provisioned and trusted-bound sandbox/run matches
them; no active workload is automatically replaced.

When this workload has saved guardrails, startup resumes monitoring and restores
those settings **without rerunning the fixed allow/deny check against custom
policy**. Native extension registration and service readiness are still checked.
The launch log explicitly distinguishes monitoring resume from a fresh native
run. This avoids sending a destructive-shaped probe after an operator
intentionally selected observe mode or changed the task constraints.

The token unlock lasts only for the browser tab's current page lifetime.
Reloading locks edits, not saved data. To prepare a new sandbox, use
`guardrails-export` and the normal create/run-bind path; `guardrails-show` reports
the saved revision and pending recorded epochs. A sidecar or gateway restart
alone does not update an existing sandbox's static filesystem policy.

## Offline asset contract

### Demonstrating adaptive learning honestly

After a build containing adaptive controls is staged, open the agent's
**Adaptive** tab. It opens on a status card; manual controls are under
**Advanced**. Shadow learning runs by default for every agent: pristine
single-sandbox runs enroll on their first native request
and auto-approve on run/epoch end only when every observation is a plain allow
and strictly read-only (`reviewed_by = "auto-clean-policy"`), then fit/update the active
shadow model (`shadow_model_id`). (`POST /graphql` and `write_mutation` routes
are excluded from clean read-only training because request bodies are not
inspected at `PRE_CREDENTIALS`, and any denial or high-impact probe quarantines
that run's window.) Operators can also unlock through **Guardrails** using the
existing private local token to pause or resume per-agent learning
(`set_auto_learning`) or manually start, review, and train **Local demo** capture
windows on fresh trusted-bound native runs.

Direct `evaluate-request` calls cannot populate native learning windows. Repeated
windows in one run still count as one independent run. Small demo datasets
visibly remain **provisional / insufficient evidence** in shadow, and **Enforce
promotion** remains manual behind the 20-train / 5-holdout / 5-shadow gates; do
not fabricate 20-run or 200-request maturity counters to make the demonstration
look enforcement-ready. Subsequent native requests demonstrate persisted shadow
assessments without changing actual allow/deny outcomes. Readiness and promotion
gates are described in the main README.

This stack runs verified TLS + Ed25519 `openshell-ext+jwt` extension RPC
authentication (`native_supervisor_http_rpc_verified`) between the local gateway/supervisor
and Risk Guard (`https://127.0.0.1:50061`). If started with `--allow-insecure-local-test`
without TLS/JWT credentials, traffic is labeled **Local demo** and cannot train a
verified-transport model. Filesystem policy views do not represent learned file-access behavior.

Default assets: `~/openshell-demo`. Required executable native
binaries in `bin/`: `openshell`, `openshell-gateway`, `openshell-supervisor`,
`openshell-sandbox`, `openshell-risk-guard`. The parent preparation script stages
these and an `assets.json` manifest:

```json
{
  "source_revision": "55bf786453395f3fe1858a187152537b457de77d",
  "binaries": {"openshell": "<SHA256 hex; include all five binaries>"},
  "images": {
    "risk-guard-demo/workload:55bf78645": "sha256:<immutable image ID>",
    "risk-guard-demo/sandbox:55bf78645": "sha256:<immutable image ID>",
    "risk-guard-demo/supervisor:55bf78645": "sha256:<immutable image ID>"
  }
}
```

One-time preparation, after building the pinned OpenShell binaries in
`$HOME/openshell-demo-target` and Risk Guard in `$HOME/rg-target`:

```bash
bash scripts/prepare-rail-guard-demo-assets.sh
```

This step builds Ubuntu-based GNU runtime images and saves `images.tar` for
offline recovery. It may download packages during preparation, never launch.
The host gateway build needs `libz3-dev`; the runtime images include `libz3-4`.
Preparation records hashes only after all images are available.

All five binary hashes and all three local image IDs must match. Tags alone are
not sufficient. Checks execute only local `image inspect`, never pull/build/load.
Manifest integrity is an operator trust boundary, not a signed supply-chain
attestation. Binary `--version`, current gateway schema preflight capability, and
required Risk Guard / sandbox exec CLI features are checked before startup.
Runtime versions must support this checkout's schema and protocol; there is no
old-binary fallback. Workload must contain `/usr/bin/{sleep,curl}`, `/sandbox`,
and the native runtime's qualified user/isolation prerequisites.

Linux direct interfaces:

```bash
bash scripts/rail-guard-demo.sh --check
bash scripts/rail-guard-demo.sh --start --allow-insecure-local-test
# Root, explicitly approved isolated paths; foreground, not a daemonizer:
sudo env DOCKERD_BIN=$HOME/bin/dockerd DOCKER_BIN=$HOME/bin/docker \
  bash scripts/rail-guard-demo-docker.sh --start
```

Linux environment overrides: `RAIL_GUARD_DEMO_ASSETS`, `RAIL_GUARD_DEMO_STATE`, `DOCKER_BIN`.
The qualified `DOCKER_SOCKET` is only
`/run/openshell-risk-guard-demo/docker.sock`. The helper uses explicit
`/var/lib/openshell-risk-guard-demo/docker` data and
`/run/openshell-risk-guard-demo/{exec,docker.pid}` runtime paths; root:docker
directory 0750 and socket 0660 are enforced (including dockerd's directory-mode
change during startup). It disables bridge, iptables/ip6tables, forwarding and
masquerading. Docker group membership and binary provisioning are prerequisites;
the helper never modifies group membership. Stop only this foreground owner,
never run name-based kills, `wsl --shutdown` or `wsl --terminate`.

## What is demonstrated

1. Check offline assets, daemon and CLI features; reject inherited
   `OPENSHELL_*` overrides rather than silently redirecting the deployment.
2. Reuse persistent gateway/risk databases and signing certificates; preflight
   the rendered gateway configuration. Start the fixture, Risk Guard then
   gateway; require native readiness and **both** extension registrations.
3. Register durable agent `demo-reviewer`; create a fresh timestamp/UUID
   run and sandbox. The canonical main process is `/usr/bin/sleep infinity`,
   launched with native `--detach` to keep the real sandbox available for exec.
   This does not override the OpenShell runtime/supervisor entrypoints; no network
   activity starts before binding. A main process of `/usr/bin/true` completes
   the sandbox and cannot be used for subsequent exec.
4. Obtain the actual ID with `sandbox get NAME --output json`; bind the trusted
   run to the pristine POST_COMMIT epoch. No fabricated issuer, caller headers,
   manual epoch creation, or unattributed mode is used.
5. Execute curl through the actual sandbox with `--no-login-shell`. Verify the
   allowed GET reached the fixture and DELETE returned explicit HTTP 403/451,
   with upstream DELETE counter exactly zero and native task-constraint decision
   evidence. Connection failures, status 000, or empty decisions are failures.
6. Create a second actual sandbox and a distinct run under the same workload ID.
   Require a `behavioral_risk_restricted` decision from its inherited restriction
   and zero upstream DELETE hits.
7. Only then start the read-only operator dashboard on `127.0.0.1:8791`.
   Windows opens it only after `/api/state` and native `/readyz` both respond.
   Gateway RPC is on `17671`; the separate health listener is on `17672`.

The static policy **allows both GET issues and DELETE production**. Additional
enforcement comes from operator-authored task baseline `v1`, with honest
`training_sessions=0` and `training_requests=0`, approved resource `local/review`,
and `forbid_unfamiliar_high_impact=true`. The unfamiliar production DELETE triggers
the cold-start Layer A **operator task constraint**, not a statistically learned
anomaly. Temporal risk / ratchets remain shared by workload ID; a new run
does not erase them. Clean read-only runs enroll,
auto-approve (`reviewed_by = "auto-clean-policy"`), and fit the shadow candidate
(`shadow_model_id`), whereas runs containing the denied DELETE probe
are quarantined and Enforce promotion remains manual.

The fixture binds only `127.0.0.1:18081`; GET
`/repos/local/review/issues` returns local issues and DELETE
`/repos/local/production` only records a hit and returns `deleted:false`.
Its atomic SQLite counters persist; `/_evidence` reads without changing them.
It has no real repository, cloud API, deletion, or upload capability.

## Persistence and limits

State defaults to `$HOME/.local/state/openshell-risk-guard-demo`:
`gateway.db`, `risk-guard.db`, `fixture.db`, private `tls/`, private XDG state,
`pids/` and timestamped `rehearsals/`. Each run records actual `sandbox.json`,
`binding.json` (run and sandbox IDs), `run.json`, gateway-info, service logs,
allowed response, denial status, fixture before/after and native decisions.
`latest-run` is written only after successful native verification. Do not commit
state; it contains signing keys. No reset, deletion, import of synthetic training,
automatic sandbox cleanup, or risk-state clearing is performed.

Ctrl-C stops only child service PIDs owned by the current foreground stack.
Existing ports cause refusal, never takeover. All sandboxes and databases are
retained, including on failure. Inspect logs and administer retained sandbox
resources deliberately; repeated runs consume disk. Warm restarts reuse
certificates/configuration and durable agent history. Persistent ratchets may
legitimately deny subsequent activity; do not reset data to manufacture a pass.
Native isolation is actively qualified only at sandbox launch, not by `check`.
Cross-sandbox continuation is checked on every successful launch.

Dashboard reachability alone is not evidence of native enforcement. If CLI
identity schema, protocol handshake, image runtime dependencies, sandbox
isolation, bind-before-traffic, or readiness fails, the script exits with logs
and never fabricates success. A host-network supervisor and loopback HTTP
fixture are a local demo recipe, not production deployment guidance.

## Tests without Docker mutation

```bash
python3 -m unittest discover -s scripts -p test_rail_guard_demo.py -v
bash -n scripts/rail-guard-demo.sh
bash -n scripts/rail-guard-demo-docker.sh
```

Tests use only stdlib, local ephemeral test HTTP listeners and workspace-local
test files (removed afterward). They cover atomic/persistent harmless fixture
counters, strict identity extraction, explicit denial/effects evidence,
manifest/hash/immutable-image checks using mocked `image inspect`, and cold-start
configuration. They do **not** establish native end-to-end success; that requires
the parent's staged native runtime and a real `--start` run.
