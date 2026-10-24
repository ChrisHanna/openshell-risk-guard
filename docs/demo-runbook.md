<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Demo runbook: ten minutes, in order

For presenting. It wraps the 90-second scripted core in [partner demo](partner-demo.md) with the rest of the story. Every number on screen comes from the running system; the limits are said out loud.

**The sentence to open and close with:** OpenShell permits, Risk Guard judges, OpenSearch remembers. Only the first two can stop a call. OpenSearch can only watch, and ask Risk Guard to tighten. Nothing loosens without two people.

## Before (Saturday or Sunday, then Monday morning)

```bash
python scripts/demo/preflight.py          # everything the demo needs, ok / warn / FAIL, with the fix
python scripts/demo/run_demo.py --prepare # the standing sandbox for the quarantine act (about a minute)
python scripts/demo/run_demo.py --pause   # rehearse once end to end
python scripts/demo/run_demo.py --cleanup # then reset, and run the preflight again
```

Print the two addresses (they are in `.aks/state.json`, not in the repository): `consoleHost` is the Risk Guard console, `siemHost` is OpenSearch Dashboards. Copy the OpenSearch admin password without printing it with the command at the end of `scripts/aks/24-expose-siem.ps1`. Sign in at `<consoleHost>/admin` before you start so the Approvals buttons are live.

Open these tabs in this order, so you only ever move right:

1. `docs/the-story.md` rendered (the loop diagram), or the slide of it
2. Console: **Fleet overview**
3. Console: **Controls**
4. A terminal in the repository, font large, running `run_demo.py --pause`
5. OpenSearch Dashboards: **0. Start here**, then **One agent**, then **Risk Guard: quarantine and signals**
6. Console: **Approvals**
7. `docs/red-team-agent.md` (the results table)

## Run of show

| Min | Open | Do | Say | What it proves |
|---|---|---|---|---|
| 0:00 | The story | Point at the four boxes | "Agents act inside OpenShell sandboxes. OpenShell permits. Risk Guard judges whether this call is normal for this workload. OpenSearch remembers, and can ask Risk Guard to tighten. That is the whole system." | One mental model |
| 1:00 | Console, Fleet overview | Let the page load | "These are live agents on AKS in Kata micro-VMs. This is not a recording." | Real and running |
| 1:45 | **Controls** | Read the top box, then the badges | "Every control, same words: enforcing blocks, watching only records. And look at the box at the top: until a workload has learned enough, OpenShell's policy and the lists a person approved are what protect it. Learned behavior says 'not enough data yet' and only watches." | Honesty about learning; no confusing mechanisms |
| 3:00 | Terminal, acts 1 and 2 | Enter, Enter | "A routine read returns 200 in a few milliseconds. The same agent tries a DELETE: refused with a reason, and the destination's own counter shows it never arrived." | Enforcement, not a log line |
| 4:15 | Terminal, act 3 | Enter | "An operator quarantines the workload. A connection that worked a moment ago now times out." | Containment |
| 5:15 | OpenSearch: **0. Start here**, then One agent | On Start here, point at the three lanes and the "who stopped calls" chart; then pick the agent with refusals on One agent and open the "One call, both layers" search | "Same events, in the SIEM: what each agent did and what was refused. OpenShell's record and Risk Guard's refusal side by side. They share the sandbox, method, host and path; an exact call id would need a small OpenShell change." | Evidence and correlation, stated honestly |
| 6:30 | OpenSearch: quarantine and signals | Run `python scripts/siem/signal_demo.py --list` | "An OpenSearch alert can ask Risk Guard to quarantine. It goes through a forwarder with its own identity over mutual TLS, and can only tighten. It is in dry-run today: recorded, nothing changes." | Feedback loop, bounded |
| 7:30 | Console, **Approvals** | Tick the suggested route, give a reason, Propose. Then try to approve it | "Risk Guard suggests from its own history: this agent reads `pulls` steadily and was never refused. Proposing is one person. Approving takes a different person; watch it refuse me approving my own." | Two-person rule, working |
| 8:45 | `red-team-agent.md` | Point at the results | "We attack it continuously: 387 mutations of the must-refuse calls, none got through, and an adaptive agent made 17 more attempts, none got through. Garak did not produce a result: the hosted model was rate limiting. Anything that does get through becomes a failing test." | Evidence, and a stated gap |
| 9:30 | Controls, bottom rows | Scroll to "Not built" and the promotion gate line | "What is not done: SIEM context as a risk hint is designed, not built. Shadow-to-enforce is gated, and the gate says HOLD today, because traffic is thin and some workloads hold locks. That is the honest state." | Credibility |

### Three-minute cut

Story (0:45) → Controls (1:00) → act 2 only (0:45) → Approvals self-approval refusal (0:30).

## Questions to expect

| Question | Answer |
|---|---|
| Why does Risk Guard have its own approved-route list when OpenShell has policy? | Honest answer: partly overlap. Method-and-path lists belong in OpenShell policy, which is reviewed and prover-checked. Risk Guard needs its own state for what policy cannot hold: resource-level rules, locks that follow a workload across sandboxes, and behavior over time. The plan is to generate the static lists as OpenShell policy from Risk Guard's recommendations. |
| What is "watching"? | A control that works out its answer, records it, and lets the call through. It is how you measure a rule before enforcing it. |
| Why is almost everything watching? | We would rather measure before blocking. The Controls page shows what each would have refused, and the promotion gate decides when to switch. |
| Why 4,000-plus refusals in a day? | Mostly latched restrictions on workloads used for the red-team and demo exercises: after a refused destructive action the workload's scope is locked. It is the lock working, not new attacks. |
| Why not feed OpenSearch's anomaly detection into scoring? | It is the right direction and it is on the page as "not built". Today it has too little real data (two workloads have enough). A hint would only add risk, start in watching mode, and enforcement would never wait on OpenSearch. |
| Is a compromised supervisor a problem? | It can stop calling Risk Guard. The tunnel gate and the network fence still limit it, one in-cluster route stays open, and this is in the threat model. |
| Where does NVIDIA hardware fit? | Design only. Sentry is the out-of-band layer this software cannot replace; nothing here claims a BlueField, DOCA or Sentry integration. |
| Is it production-ready? | No. [Production gaps](production-gaps.md) lists what is missing, in order. |

## Rough edges: do not improvise around these

* **Approvals needs two administrators.** The console has one administrator in its allow-list, so you can show proposing and the refusal of self-approval, but not a completed approval, unless a second administrator is added first. Say so.
* **Do not run the red-team agent live.** It takes many minutes and the hosted model returns 429 under load. Show the recorded results.
* **Signals are in dry-run.** `applied` stays 0 by design. Do not say the SIEM quarantined anything.
* **The "quiet sandbox" alert fires when a sandbox simply finishes.** Do not present it as an incident.
* **Garak has no result yet.** Say it was run as an agent tool and the model rate-limited it.
* **Two-person approval is tested with the token path and in the store, not with two real Entra accounts.**
* **Deploys can fail on network resets.** Do not redeploy on Monday. If a change is needed, build with `-LocalDocker` and stop on a failed build.
* **An approved baseline change applies to new sandboxes only, not running ones** (each sandbox keeps the baseline it started with). Say so if asked. OpenShell's own network policy, by contrast, hot-reloads on a running sandbox.
* **Act 4 (replay) picks a workload whose recorded history is complete**, since retention prunes old decisions; it names the workload it used. If none qualifies it says so and skips.
* **A policy proposal can take up to a minute** while the prover runs (the budget is 60 s, `RISK_GUARD_PROOF_TIMEOUT_SECONDS` changes it); a proof that runs out of time is refused, never treated as a pass.
* **Counts move.** Numbers on the Controls page change every refresh; say "about".

## If something breaks

| Symptom | Do |
|---|---|
| Console or SIEM will not load | Play the captured output ([`demo-output-sample.txt`](demo-output-sample.txt)) and use the [results sheet](results-sheet.md). Say it is a recording. |
| Act 3 is slow or the sandbox is missing | The script skips it and says so; narrate `conformance/quarantine-tunnel-bounded.json`. |
| OpenSearch dashboards are empty | Check the fleet is running: `kubectl -n openshell scale deploy/agent-fleet --replicas=1`, wait three minutes. |
| Approvals buttons are greyed out | You are not signed in as an administrator: sign in at `/admin`. |
| A workload is quarantined from a rehearsal | `python scripts/demo/run_demo.py --cleanup`. |

## After

```bash
python scripts/demo/run_demo.py --cleanup
```

The demo OpenSearch is public and costs about $0.19 an hour. When you are done: `scripts/aks/24-expose-siem.ps1 -Remove`, then `scripts/aks/22-deploy-siem.ps1 -Remove`.
