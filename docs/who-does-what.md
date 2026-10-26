<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Who blocks, who recommends, who decides

Three systems and some people. This page answers four questions about them and nothing else. For the loop they form, see [the story](the-story.md); for detail, [how it works](how-it-works.md).

**The console has one page for this: Controls.** It lists every control below in the same words, with what each did in the last 24 hours, and says plainly when a control does not have the data it needs. Until Risk Guard has learned enough, OpenShell's policy and the lists people approved are what protect an agent, and the page says so.

The words used everywhere (the code and older pages say "shadow" for what the console now calls **watching**):

| Word | Meaning |
|---|---|
| **Enforcing** | Blocks the call. |
| **Watching** | Works out its answer, records it, lets the call through. |
| **Off** | Does nothing. |
| **Mixed** | Enforcing for some task profiles, watching or off for others. |
| **No list set** | A rule with nothing to match yet, because no list was approved. An empty list never means "block everything". |
| **Not built** | In the design, not in the product. |
| **Unknown** | No running Risk Guard has recorded how it was started, so the mode cannot be shown. |

A learned control needs history before it can enforce: a task profile counts as having learned enough after 20 sessions and 200 requests. Before that, the behavioral score is recorded and never refuses on rarity alone.

The rule to hold on to: **only OpenShell, Risk Guard and the network fence can stop a call. OpenSearch can only watch, alert, and ask Risk Guard to tighten. Nothing loosens without two people.**

## 1. What can block a call?

| What | Blocks | Looks at | State on the demo cluster |
|---|---|---|---|
| **OpenShell policy** | A file, process, network destination, or HTTP method and path the policy does not allow; credentials are injected only for approved endpoints | Static rules (Landlock, L4/L7 Rego) | Enforcing |
| **Risk Guard, gate 1** (supervisor middleware, before credentials are injected) | A call OpenShell allowed but that is unreasonable for this workload now: the deny list, high-impact calls on unfamiliar resources, a route outside the approved list, a high behavioral score, a quarantined or latched workload, or anything it cannot score (fails closed) | Method, host, route, workload history, task profile | Deny list and high-impact rule enforce. The approved-action rule is set per profile in its baseline (`rule_modes`); egress is shadow |
| **Risk Guard, gate 3** (tunnel check on encrypted connections) | A tunnel from a quarantined workload; with `enforce` also a latched restriction (host-specific: only hosts the task does not explicitly approve; the model host stays open), a host not approved for the task, or a silent supervisor | Destination host only (not the path) | Quarantine enforces. Restriction, egress-host and silent-supervisor checks are **shadow** (they record what they would refuse) |
| **Cilium network fence** | Direct routes around the proxy | Network flows | Enforcing; closes most routes, not all (see [deployment security](deployment-security.md)) |
| **OpenSearch** | **Nothing, directly.** An alert can send a signal that makes Risk Guard quarantine a workload for 1 to 60 minutes | Events from both layers | Signals are **dry-run**: recorded, nothing changes |

"Shadow" means the control works out its answer, writes it down, and lets the call through. That is why the promotion gate exists.

## 2. What recommends?

Nothing in this project changes a rule by itself. Recommendations are advice for a person.

| Source | Recommends | Where you see it |
|---|---|---|
| **Risk Guard, Approvals page** | Routes a workload uses steadily and was never refused on, that its baseline lacks (reads only) | Console, Approvals, "Suggested baseline changes" |
| **Risk Guard, hardening** | A tighter OpenShell policy, with a proof it still covers what the workload did | Console, Recommendations tab; `hardening` command |
| **Risk Guard, adaptive learning** | A model of normal behavior, learned in shadow; it never blocks until a person promotes it | Console, Adaptive tab |
| **Promotion gate** | PROMOTE or HOLD before switching a shadow control to enforce, with what is missing | `scripts/promotion_gate.py`; checked by script 18 |
| **OpenShell** | Destination names an agent asked for that no policy approves yet (staged for a decision) | OpenSearch, "Egress and policy" dashboard |
| **OpenSearch** | Anomalies and unusual patterns (detectors, three watch-only monitors); egress hosts and rate limits that look wrong (`suggest_baselines.py`) | Dashboards, Alerting |

## 3. What loosens, and who decides?

Only people decide, and loosening needs two. See [two-person approval](two-person.md).

| Change | Who proposes | Who approves | Where |
|---|---|---|---|
| Release a quarantine, clear a restriction | An operator | A **different** operator | Console Approvals, API, CLI |
| Add routes, hosts, or lower a limit in a baseline | An operator, usually from a suggestion | A **different** operator (always, even if two-person is otherwise off) | Console Approvals |
| Shadow to enforce | An operator runs script 18 | The promotion gate must say PROMOTE, or the override reason is recorded | Script 18 |
| Anything tightening (quarantine, a SIEM signal) | Anyone with access, or the SIEM | Nobody; tightening is immediate | CLI, signals |

## 4. The flow of one call, step by step

1. The agent makes a call. **OpenShell** checks policy. If it says no, the call stops here.
2. **Risk Guard gate 1** scores it. Allow or refuse. A refusal can latch a restriction on the workload, which then applies to its other sandboxes.
3. For an encrypted connection, **gate 3** also checks the destination, mostly in shadow today.
4. Both layers write events. **OpenSearch** stores them and draws the dashboards.
5. If an alert rule matches, OpenSearch can send a signal. It goes through the forwarder to Risk Guard, which may quarantine (dry-run today, so it only records).
6. People read the dashboards and the Approvals page, and decide what to loosen or promote. Two of them, for loosening.

## Where the lists should live

The deny list and approved routes are method-and-path rules that OpenShell policy can hold, and OpenShell's network rules take effect on running sandboxes within seconds, while a Risk Guard baseline change applies only to new sandboxes. How generated OpenShell policies are verified and rolled out across the fleet is documented in [fleet policy modes](fleet-policy-modes.md).

**Each approved route change chooses its home.** When a baseline change is proposed (Approvals page, "Where the approved routes are kept"), it is either *kept in Risk Guard* (the default: it can run in watching mode and follows a workload between sandboxes) or *also pushed to OpenShell*. A pushed change is enforced by Risk Guard the moment it is approved, so nothing is unprotected meanwhile; Risk Guard then requests a policy candidate for the same profile, generated from the baseline as it now is and proved no wider than the sandbox's current policy. That candidate is an ordinary request in the queue for a person to approve; approving applies nothing (a person runs the command), and it reaches only the next sandbox created with it. If the candidate cannot be built or proved, the change's outcome says so and the entries stay enforced by Risk Guard alone. Rate limits always stay in Risk Guard. Controls shows how many changes chose OpenShell and how many candidates were approved; it cannot see that a sandbox is running one.

## Where the confusion usually comes from

- **A "would refuse" in the SIEM is not a block.** It is a shadow decision. Today most of the 400 or so in the last hours say a workload holds a latched restriction; enforcing that would also cut the workload's calls to the model.
- **A suggestion is not a change.** It becomes one only after a proposal and a second person's approval.
- **An alert is not a block.** OpenSearch alerts only reach Risk Guard through the signal path, and that path can only tighten.
- **Risk Guard's quarantine is a block; OpenShell's policy is a different block.** A call can be allowed by one and refused by the other. Both must allow it (`FinalAllow = OpenShellAllow AND RiskPermit`).
