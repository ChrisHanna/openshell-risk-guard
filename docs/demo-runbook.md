<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Demo runbook: ten minutes, in order

For presenting. It wraps the 90-second scripted core in [partner demo](partner-demo.md) with the rest of the story. Every number on screen comes from the running system; the limits are said out loud.

**The sentence to open and close with:** OpenShell permits, Risk Guard judges, OpenSearch remembers. Only the first two can stop a call. OpenSearch can only watch, and ask Risk Guard to tighten. Nothing loosens without two people.

## Before (Saturday or Sunday, then Monday morning)

```bash
python scripts/demo/preflight.py              # everything the demo needs, ok / warn / FAIL, with the fix
python scripts/demo/run_demo.py --prepare     # the standing sandbox for the quarantine act (about a minute)
python scripts/demo/end_state.py --prepare    # the end-state demo's sandbox (about a minute)
python scripts/demo/smoke.py --end-state      # runs both demos and checks what a presenter would look for; must say SMOKE PASSED
python scripts/demo/run_demo.py --pause       # rehearse once end to end
python scripts/demo/run_demo.py --cleanup     # then reset, and run the preflight again
```

Print the two addresses (they are in `.aks/state.json`, not in the repository): `consoleHost` is the Risk Guard console, `siemHost` is OpenSearch Dashboards. Copy the OpenSearch admin password without printing it with the command at the end of `scripts/aks/24-expose-siem.ps1`. Sign in at `<consoleHost>/admin` before you start so the Approvals buttons are live.

Open these tabs in this order, so you only ever move right:

1. `docs/the-story.md` rendered (the loop diagram), or the slide of it
2. Console: **Fleet overview**
3. Console: **Controls**
4. A terminal in the repository, font large: `run_demo.py --pause`, then `end_state.py --pause`
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
| 9:30 | Controls, bottom rows | Scroll to "Not built" and the promotion gate line | "What is not done: SIEM features are flowing into Risk Guard (look at the Controls row: fresh features, newest batch seconds old) but they only watch; they add nothing to a score until a profile promotes the rule. Shadow-to-enforce is gated, and the gate says HOLD until the review items are cleared. That is the honest state." | Credibility |

### The end state (about five minutes; use it after the partner acts, or instead of acts 2 to 4)

`python scripts/demo/end_state.py --pause`. **Say the disclosure out loud first:** the demo sandbox's OpenShell policy is deliberately weaker than the profile's baseline: it also allows `DELETE /services/*`, so that call reaches Risk Guard on purpose. The weakening is in the rule's name on the gateway and is printed by the script. The fleet does not run it.

| Act | What you show | Say |
|---|---|---|
| A | `GET /services` returns 200; OpenShell's `L7_REQUEST allow` and Risk Guard's `decision=Allow` | "Both layers allow routine work." |
| B | `POST /services/payments/rollback` returns `403 policy_denied`; OpenShell's own event; "Risk Guard was not consulted" | "A fixed rule lives in OpenShell's policy, which is reviewed and takes effect on running sandboxes. Risk Guard never even saw this call." |
| C | `DELETE /services/worker` passes OpenShell (the disclosed exception); Risk Guard refuses it, names the rules, and locks that route for the workload; the destination's counter does not move; the next call is refused by the lock while a routine `GET` still works | "What reaches Risk Guard gets judged against this workload's task, and a refusal follows the workload." |
| D | `GET /services/payments`: an approved route on a resource the profile does not approve is refused by Risk Guard's resource rule | "A path rule cannot say which repository or service. This can. That is what Risk Guard is for once the fixed rules live in OpenShell." |
| E | The agreement numbers: what OpenShell would have refused across the fleet in 24 hours, and how many of those Risk Guard also refused (and zero that only OpenShell would) | "This is the evidence we use before switching the fleet from audit to enforce." |
| F | `GET /services` again; the score is higher than in act A and the decision shows the `siem_context` rule: "openshell_denials_5m=3 (+4)". | "OpenSearch saw OpenShell deny three calls. It handed Risk Guard the count, and Risk Guard raised this workload's score because of it. Three systems, one story: OpenShell permits, Risk Guard judges, OpenSearch remembers." Say that this rule enforces in this profile only (the fleet's copy watches), that it only ever adds points and is capped, and that it did not cross the threshold here (`changes_outcome`). |

Act B now sends the denied call three times, so the SIEM has three denials to count. Act F waits for the features to travel (measured: the denial is in OpenSearch after 5 to 8 s and scored by Risk Guard after 20 to 34 s, so usually under a minute; it waits up to five) and says so if they have not arrived; **run the demo once earlier in the day**, and do not run it twice within ten minutes (act A would then already show the features). The script then finds all the calls in the SIEM. Run `end_state.py --cleanup` afterwards.

### Three-minute cut

Story (0:45) → Controls (1:00) → act 2 only (0:45) → Approvals self-approval refusal (0:30).

## Questions to expect

| Question | Answer |
|---|---|
| Why does Risk Guard have its own approved-route list when OpenShell has policy? | Honest answer: partly overlap. Method-and-path lists belong in OpenShell policy, which is reviewed and prover-checked. Risk Guard needs its own state for what policy cannot hold: resource-level rules, locks that follow a workload across sandboxes, and behavior over time. The plan is to generate the static lists as OpenShell policy from Risk Guard's recommendations. |
| What is "watching"? | A control that works out its answer, records it, and lets the call through. It is how you measure a rule before enforcing it. |
| Why is almost everything watching? | We would rather measure before blocking. The Controls page shows what each would have refused, and the promotion gate decides when to switch. |
| Why 4,000-plus refusals in a day? | Mostly latched restrictions on workloads used for the red-team and demo exercises: after a refused destructive action the workload's scope is locked. It is the lock working, not new attacks. |
| Does OpenSearch feed Risk Guard's scoring? | Yes, as bounded features (OpenShell denials per sandbox, refusal ratios, fleet aggregates), sent every 30 seconds over mutual TLS and stored locally. They can only add risk, are capped at 15 points, start in watching mode, and enforcement never waits on OpenSearch. OpenSearch's anomaly-detection scores are not used yet: there is too little real data. |
| Does the adaptive learner use those features? | It receives the same counts as bounded context since 2026-10-24 (tested; no live model has used them yet, because the demo profile has none). It can only add points when its own evidence is already high, it is trained on allowed traffic, scored in shadow, and promoted by a person. |
| How fast does OpenSearch reach Risk Guard? | Measured on the live system, two samples: an OpenShell denial is searchable in OpenSearch after 5 to 8 s and scored by Risk Guard after 20 to 34 s, mostly the publisher's 30 s cycle. That is context for slow patterns, not a defense against a fast burst; Risk Guard's own rate windows and locks handle those. |
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
* **A policy proposal can take up to a minute** while the prover runs (the budget is 180 s, since the encoded-backslash deny rules made the proof slower: about a minute on a laptop; `RISK_GUARD_PROOF_TIMEOUT_SECONDS` changes it); a proof that runs out of time is refused, never treated as a pass.
* **The fleet is in enforce mode** (since 2026-10-24): OpenShell refuses what each profile's baseline does not approve, so the fleet's destructive attempts show up in the SIEM as OpenShell denials and Risk Guard does not see or lock them. Risk Guard's own refusals now come from calls that reach it (demo exceptions, resource rules, behavior). Confirm with `deploy/aks/fleet.yaml` (`AGENT_POLICY_MODE`) before you say which.
* **SIEM features watch only.** On the Controls page "SIEM context" says watching; do not claim it changed a decision unless "would have changed" or "changed" is above zero.
* **Run `smoke.py` after any redeploy, not just the API checks.** A deploy once left the demo returning 403 while every API check passed.
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
