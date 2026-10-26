<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# The fleet's OpenShell policy modes: hand-written, audit, enforce

The agent fleet's sandboxes (support, release, cloud) can run one of three policies, chosen by **one setting**, `AGENT_POLICY_MODE`, on the `agent-fleet` Deployment (`deploy/aks/fleet.yaml`, read by `scripts/aks/run-agent.sh`):

| `AGENT_POLICY_MODE` | File used (`deploy/aks/agents/<profile>/`) | What OpenShell does | Who refuses a destructive call |
|---|---|---|---|
| *(unset)* | `policy.yaml`, hand-written | Allows the dangerous calls on purpose ("so Risk Guard decides") | Risk Guard |
| `audit` | `policy.audit.yaml`, generated | Logs `L7_REQUEST audit ... not permitted by policy` for what it would block, and allows it | Risk Guard |
| `enforce` **(today, since 2026-10-24)** | `policy.enforce.yaml`, generated | Refuses what the profile's baseline does not approve (`policy_denied`) | OpenShell; Risk Guard never sees the call |

The generated files are `policy-export` output (`src/policy_export.rs`): the profile's approved routes and deny list written as OpenShell rules, plus a deny of an encoded backslash (`%5C`) in any path for every allowed method, proved no wider than `policy.yaml` by OpenShell's prover. The audit and enforce files differ in exactly one thing, the endpoint's `enforcement:` line (`tests/policy_export.rs` checks that). The inference endpoint (`integrate.api.nvidia.com`) is not in these files; the provider adds it, in enforce mode, in every mode.

`deploy/aks/fleet.yaml` says `enforce`: the fleet was switched on 2026-10-24 after the gate below was met (24 hours of audit data, 118 of 120 would-blocks also refused by Risk Guard, none that only OpenShell would have blocked, the other 2 refused either way because Risk Guard errored during a restart). Only sandboxes created afterwards are affected (the fleet creates a fresh sandbox per run and deletes it). First hour in enforce: 65 routine calls allowed, 3 overreach calls refused by OpenShell, and every agent run completed.

- Regenerate: `RG_BIN=<built openshell-risk-guard> python3 scripts/policy/generate_audit_policies.py` (`--check` only verifies). It writes `policy.audit.yaml`, `policy.enforce.yaml`, and the demo-only `policy.enforce.demo.yaml` (see [the end-state demo](end-state-demo.md)). `tests/policy_export.rs` and the CI step "Generated policies are current" fail when a committed file is stale.
- `run-agent.sh` fails loudly (exit 2) when the mode is set and the profile has no generated file of that kind. It never falls back silently.
- The weakened demo policy is not selectable by `run-agent.sh`, and `16-deploy-fleet.ps1` leaves it (and `demo-exceptions.json` and the `demo-end-state` profile) out of the fleet image.

## Before enforcing: the gate

All of these, on the cluster you are about to change:

1. **Agreement.** `python scripts/policy/agreement.py --hours 24` (or longer) shows **`openshell only: 0`**. That line counts calls OpenShell would have refused that Risk Guard did not, i.e. what enforcing would newly block. The tool leaves out the throwaway probe sandboxes (`epprobe-*`, `auditprobe-*`).
   - A separate line, `openshell only, risk guard failed closed`, counts calls OpenShell would refuse where Risk Guard *errored* (`middleware_failed`) and the middleware refused because it fails closed. They are refused either way, so enforcing changes nothing about their outcome, but they are not agreement: look at why Risk Guard errored before relying on it (a 24 h window on 2026-10-24 showed 63 `middleware_failed: external_service_error` events from token and fleet sandboxes, including routine `GET`s; one of them was a fleet `DELETE /buckets/tmp-scratch`). Reasons were not investigated here.
   - Run it after the fleet has been in audit mode long enough to have exercised every agent (support, release, cloud) including their overreach tasks. It has been in audit mode since about 23:15 Friday US Eastern.
2. **Generated files are current:** `python3 scripts/policy/generate_audit_policies.py --check` and `cargo test --test policy_export` pass.
3. **Path edge cases are understood.** [policy-path-edge-cases.md](policy-path-edge-cases.md): on the real OpenShell every catalog evasion is stopped in enforce mode. The one spelling OpenShell passed, an encoded backslash inside a segment (`/services/..%5ccustomers`), is now denied by a `deny_rules` entry that `policy-export` adds to every generated file (audit, enforce, demo); it was verified on a throwaway sandbox. Re-run `scripts/policy/path_probe.py` after upgrading OpenShell.
4. **Understand the shift in enforcement attribution.** In enforce mode, unapproved static routes (such as a fleet `DELETE`) are refused directly by OpenShell at the sandbox floor (`policy_denied`) and streamed to Risk Guard via OpenStream OCSF (`openshell_denials_5m` / `openshell_denials_1h`), while Risk Guard continues to score and latch locks on calls that pass OpenShell's static YAML (`scripts/demo/run_demo.py` and `end_state.py` remain unaffected).

## How the switch to enforce was done (and how to repeat it)

The fleet image bakes the policies in, so the **image must be rebuilt**: the image deployed today has no `policy.enforce.yaml`, and setting the variable alone would make every run exit 2 with "needs a profile with a generated policy.enforce.yaml" (a visible failure, not a silent audit).

1. Edit `deploy/aks/fleet.yaml`: `AGENT_POLICY_MODE` value `"enforce"`. Commit.
2. Rebuild and deploy the fleet. **Keep the token agent**, which the current fleet runs (`FLEET_TOKEN_AGENT=1`); omitting `-TokenAgent` would turn it off:
   ```powershell
   pwsh scripts/aks/16-deploy-fleet.ps1 -TokenAgent
   ```
   (Add `-AcrBuild` to build in Azure instead of local Docker. The script builds, pushes, applies `fleet.yaml` and restarts the Deployment.)
3. Wait one run per agent (about ten minutes). New sandboxes log `policy: generated enforce policy (<profile>)`: `kubectl -n openshell logs deploy/agent-fleet --tail=200 | grep "generated enforce"`.
4. Watch: `python scripts/policy/agreement.py --hours 1` is now about *audit* events and will be quiet. Look instead for `L7_REQUEST deny` events in the SIEM (the dashboard panel and the watch-only alert for repeated OpenShell denials are in `scripts/siem`), and confirm routine calls still succeed (agents complete their tasks; no `policy_denied` on approved routes).

## Roll back

One setting, then wait one run per agent. After step 2 above the image holds all three file kinds, so either of these works without a rebuild:

1. Back to audit: `kubectl -n openshell set env deploy/agent-fleet AGENT_POLICY_MODE=audit` (the pod restarts). Back to the hand-written policy: `kubectl -n openshell set env deploy/agent-fleet AGENT_POLICY_MODE-`.
2. Redeploy the previous image: `kubectl -n openshell set image deploy/agent-fleet fleet=<previous image>`. The image before the audit change was `fleet:a7ce1a1-20261022-160926` in the cluster's registry.

Re-running `16-deploy-fleet.ps1` re-applies `fleet.yaml`, so also change the value there, or the redeploy undoes the rollback.
