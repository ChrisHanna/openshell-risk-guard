<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# The end-state demo: OpenShell enforces the routes, Risk Guard decides the rest

`scripts/demo/end_state.py` shows the system as it will look once the fleet is enforcing: OpenShell's policy refuses what a path rule can refuse, and Risk Guard is the layer for what it cannot (a route that is approved but on a resource that is not, locks that follow a workload). Like `run_demo.py`, every line it prints comes from the running system.

> **Disclosure, which the script repeats before the run and again in act C.** The demo sandbox runs `deploy/aks/agents/<profile>/policy.enforce.demo.yaml`. That policy is **deliberately weaker than the profile's baseline**: it also allows the calls listed in `deploy/aks/agents/<profile>/demo-exceptions.json` (one each for release, cloud and demo-end-state: `DELETE /services/*`, `GET /secrets/*`, `DELETE /services/*`) so that those calls reach Risk Guard and Risk Guard is seen refusing them. Everything else in the policy is the baseline's. The weakening is written into the policy itself (the rule is named `... (DEMO EXCEPTIONS: n)`; YAML comments would not survive serialization), is listed with its reasons in the `policy-export` summary, is read back from the gateway by the script, and the fleet never runs it. The prover still certifies the weakened policy against the original `policy.yaml`.

## Acts

| Act | What it does | What it observes |
|---|---|---|
| A | `GET /services`, an approved route | OpenShell's `L7_REQUEST allow` and Risk Guard's `decision=Allow`; the service answers 200 |
| B | `POST /services/payments/rollback`: destructive, not an exception | `403 policy_denied` from OpenShell; the supervisor's OCSF `L7_REQUEST deny` record; **no** `MIDDLEWARE` record, so Risk Guard never saw it; the same event found in the SIEM |
| C | `DELETE /services/worker`: the reviewed exception | OpenShell allows it; Risk Guard answers `middleware_denied`, `task_constraint_denied`, and its own decision record names the rule (`unapproved_action`) and the lock it latched (`latch_tier1_strict_epoch` on that route and resource); the destination's own DELETE counter does not move; repeating the call is refused as `behavioral_risk_restricted`, while a routine `GET /services` still passes. An operator step then clears the restriction (break-glass, recorded) so act D is judged alone |
| D | `GET /services/payments`: an approved route shape on a resource the profile does not approve | In `demo-end-state` Risk Guard's `unapproved_resource` rule (enforcing there) refuses it. In a profile where the rule only watches (every other profile today) the script says so and shows Risk Guard allowing it with the rule listed as shadow |
| E | The agreement tool's numbers for the fleet's audit-mode run | Both layers refused / OpenShell only / OpenShell only with Risk Guard errored / Risk Guard only. The evidence for enforcing the fleet ([fleet-policy-modes.md](fleet-policy-modes.md)) |
| F | The same `GET /services` as act A, repeated until Risk Guard's decision carries the `siem_context` signal | Act B sent three denials in all. OpenSearch counts them (`openshell_denials_5m`), the feature publisher (every 30 s) hands the count to Risk Guard, and the next routine call's score rises by the rule's points (+4 for 3 to 9 denials, +8 for 10 or more), with the rule and `changes_outcome` printed. The rule is **enforcing in this profile only**; in the fleet it only watches. Nothing is injected: the path is OpenShell's event, the collector, OpenSearch, the publisher, `/features`. It takes one to three minutes after act B, so act F waits (up to `--feature-wait`, default 300 s) and says so honestly if the features have not arrived. Run again within ten minutes and act A already carries the features, which the script reports |

At the end the script polls OpenSearch until the calls' events appear (usually seconds; it waits up to 150 s) and prints them.

## The `demo-end-state` profile

`deploy/aks/agents/demo-end-state/`: `baseline.json` (task profile `demo-end-state`; approves `GET /services`, `GET /services/{svc}`, `GET /services/{svc}/deployments`; approved resources `services`, `web`, `api`; `rule_modes`: `unapproved_action` and `unapproved_resource` **enforce**), `policy.yaml` (the hand-written starting policy), and the generated `policy.enforce.yaml`, `policy.enforce.demo.yaml`, plus `demo-exceptions.json`. `tests/policy_export.rs` keeps the generated files current, proves them no wider than `policy.yaml`, and fails if any other profile enforces the resource rule or if more than three exceptions exist in all.

Importing it is part of the Risk Guard deployment: `deploy/aks/risk-guard.yaml` has a `baseline-import-demo-end-state` init container and `scripts/aks/04-deploy-risk-guard.ps1` adds the file to the `risk-guard-baseline` ConfigMap. **Neither was run** (that is a Risk Guard redeploy). The fleet image excludes this profile and the demo files (`16-deploy-fleet.ps1`).

## Running it

1. Import the baseline (a Risk Guard redeploy; do it away from a live demo): `pwsh scripts/aks/04-deploy-risk-guard.ps1` with the usual options. Until this is done Risk Guard is expected to fail the first call (`middleware_failed`; that behaviour for an unknown profile was not observed), and `--prepare` then removes the sandbox and says why.
2. `python scripts/demo/end_state.py --prepare` (about a minute: registers the workload `demo-end-state`, creates the sandbox `demo-endstate` from the `nat-agent` image with the demo policy).
3. `python scripts/demo/end_state.py [--pause]` (about two minutes, plus the SIEM wait; `--no-siem` skips it).
4. `python scripts/demo/end_state.py --cleanup`.

`--profile release` runs the same acts against the live `release-ops` profile with its own throwaway workload; it needs nothing imported. Names the script creates: sandbox `demo-endstate`, workloads `demo-end-state` and `endstate-release` (registered in Risk Guard, which has no command to remove a workload).

## What has and has not been verified on the cluster

Run on 2026-10-24 with `--profile release` ([a real output](end-state-demo-output-sample.txt)):

- **Verified:** the policy loads and the gateway reports the rule name `release-api (DEMO EXCEPTIONS: 1)`; act A passes both layers; act B is `policy_denied` with OpenShell's event and **no** Risk Guard record, both in the supervisor log and in OpenSearch; act C passes OpenShell, is refused by Risk Guard with `unapproved_action` named, latches the lock, leaves the destination counter unchanged, and is refused again as `behavioral_risk_restricted` while a routine `GET` passes; act D runs and reports the rule in shadow; act E prints the agreement numbers; the OpenSearch check finds every call; `--cleanup` leaves nothing behind.
- **Not verified:** act D **refusing** (needs the `demo-end-state` baseline imported; the baseline and the resource rule are tested in Rust, not on the cluster); `--prepare` and the run with the default profile; the `04-deploy-risk-guard.ps1` and `risk-guard.yaml` changes (run only through `scripts/check-risk-guard-deployment.py`, which passes); the `16-deploy-fleet.ps1` exclusion; act C's cloud variant (`GET /secrets/*`) and the `demo-end-state` variant of act C.
