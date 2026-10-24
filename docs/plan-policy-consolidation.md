<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Plan: move the static route lists into OpenShell policy

**Status (phases 0 and 1 are built; nothing is enforced and no live sandbox was changed).**

| Built | What it is |
|---|---|
| `openshell-risk-guard policy-export --baseline B --policy P [--enforcement audit\|enforce] [--out F]` | Writes the baseline's approved routes and deny list into a copy of the sandbox policy as OpenShell rules, and has OpenShell's prover check the result is no wider. Applies nothing. The proof is run on the `enforce` form of the rules, because the prover cannot certify a mode that only logs. |
| `tests/policy_export.rs` | For the four agent profiles: the proof holds, every routine call the catalog expects to be allowed still is (no false blocks), and nothing destructive the catalog expects to be refused is allowed. Result: 13 attacks are refused by the generated policy alone; 5 path-evasion variants are left to OpenShell's own normalization; 2 rate attacks only behavior can catch. |
| `scripts/policy/audit_probe.py` | Creates one throwaway sandbox with a generated policy in audit mode on the cluster, makes an allowed and a violating call, and prints what OpenShell recorded. Verified: OpenShell logs `L7_REQUEST audit ... not permitted by policy` and lets the request through; Risk Guard then refused the same call. |
| `scripts/policy/agreement.py` | Compares OpenShell's would-block events with Risk Guard's refusals, per sandbox, method and path. Exit status 1 if OpenShell would block something Risk Guard did not. This is the gate before enforcing. |
| A dashboard panel | "Requests OpenShell would block (audit mode)" on the Start here dashboard. |

**Not done:** rolling a generated policy out to the live agents (the fleet bakes its policies into its image, so it needs a fleet rebuild), enforcing, retiring Risk Guard's copy, the Approvals proposal type, and the SIEM hint. Left until after Monday on purpose: enforcing would change the demo, where Risk Guard refuses the `DELETE`.

The original plan follows. It answers one question: should the deny list and the approved-route list live in OpenShell's policy instead of in Risk Guard's baselines, generated from Risk Guard's recommendations?

Short answer: yes for those two lists, but it is not free, and one side effect needs a decision first (see "The catch").

## What OpenShell actually does (from its own docs, pinned commit)

| Fact | Consequence |
|---|---|
| **Network rules hot-reload.** `openshell policy update` or `policy set` changes allow rules, deny rules and enforcement on a **running** sandbox within seconds. Connections opened under the old rules are closed. | The route lists do **not** have to wait for the next sandbox. |
| **Startup sections do not.** Added filesystem paths do not reach a running workload; removed paths, `include_workdir`, Landlock and process settings are rejected after start. | Filesystem changes need a new sandbox. A proposal must say so. |
| **`enforcement: audit`** logs a violation and allows the request (it is the default); **`enforce`** blocks it. Deny rules beat allow rules. | OpenShell already has a "watching" mode. We can measure before blocking. |
| **A global policy** applies to every sandbox on the gateway within about ten seconds. | Useful, but too blunt for per-task lists. |
| **A Policy Advisor** lets denied requests become proposals that an operator approves. Our gateway interceptor already validates those calls. | OpenShell has its own recommendation flow; ours should feed it, not run beside it. |
| **Risk Guard baselines are different:** an approved baseline change applies to **new** sandboxes only, because each epoch pins the baseline it started with. | Today's route lists in Risk Guard are *slower* to change than OpenShell's. Moving them improves that. |

So "a policy can only be applied to the next sandbox" is true for the filesystem and process sections and for Risk Guard's baselines, and false for OpenShell's network rules.

## What moves and what stays

| Control | Where it should live | Why |
|---|---|---|
| Deny list (`forbidden_action_classes`) | OpenShell `deny_rules` | A method and path pattern; deny wins over allow; reviewed and prover-checked |
| Approved routes (`allowed_action_classes`) | OpenShell `rules` (allow) | Same |
| Approved egress hosts | OpenShell network endpoints | OpenShell already decides destinations; Risk Guard's egress rule duplicates it |
| Approved resources (which repo, which bucket) | **Stays in Risk Guard** | Needs resource identity, not just a path (a path glob covers some cases, not all) |
| High-impact on an unfamiliar resource | Stays | Semantic classification |
| Behavioral score, latched restriction, quarantine, adaptive learning | Stays | Needs history and the workload's memory across sandboxes |

## The catch: Risk Guard stops seeing the attempts

OpenShell checks its policy **before** Risk Guard's middleware. If OpenShell refuses a destructive call, Risk Guard never sees it. Today a refused `DELETE` latches a restriction on the workload and follows it to new sandboxes. After the move, that latch would not fire for calls OpenShell refuses first.

Options, to decide before building:

1. **Restore it through the SIEM.** An alert on repeated OpenShell denials from one sandbox sends a signal that restricts or quarantines the workload. The path exists (tighten-only, mutual TLS). It adds a delay and depends on OpenSearch.
2. **Keep the deny list in both places.** OpenShell stops it; Risk Guard also sees nothing, so this does not fix the latch. Not recommended.
3. **Accept the loss** for calls the policy already refuses, because they never reached anything, and keep the latch for calls that reached the policy's allowed set. Simple, and loses evidence of intent.

Recommendation: option 1, with option 3 as the fallback.

The demo narrative also changes. The sample policies deliberately permit the dangerous calls "so Risk Guard, not the static policy, decides". After the move, OpenShell refuses the `DELETE`, and Risk Guard's role in that act becomes what policy cannot do: resource-level rules, rate and fan-out, locks across sandboxes. Keep a Risk Guard-only demo profile for the demonstration.

## Design

1. **Generator.** A command, `policy-export --task-profile <name> --policy <base.yaml>`, writes a policy that adds the baseline's lists as OpenShell rules on the endpoints named in the profile's middleware `endpoints.include`. Route templates map to path globs (the hardening code already does this: `{owner}/{repo}` to `*` and `**`). The existing hardening engine and prover supply the synthesis and the containment proof.
2. **Proof.** Run the containment check that the new policy is no wider than the old one before it is offered.
3. **Conformance.** For every attack in the red-team catalog and every fuzz variant, the decision under the new OpenShell policy must match what Risk Guard decided. The two systems normalize paths differently, so this test is the real work.
4. **Audit first.** Apply with `enforcement: audit`, live, with `--wait`. Run normal traffic. Compare OpenShell's audit violations with Risk Guard's would-refuse for the same calls. The promotion gate gains a check: no disagreement over N hours.
5. **Enforce.** Switch the endpoint to `enforce`, live. Roll back with `policy set` of the previous file.
6. **Retire the copy.** Set Risk Guard's copy of the list to watching, then remove it. The Controls row changes from "better home: OpenShell policy" to "moved".
7. **Approvals gets a `policy_update` proposal.** It shows the diff, the proof, and whether a new sandbox is needed. A second person approves. Risk Guard still does not write OpenShell policy: the page produces the exact command and file, and an operator or pipeline applies it.
8. **Open question: the Policy Advisor.** Whether Risk Guard's suggestions should be submitted as advisor proposals instead of a parallel list. Needs a read of the advisor API.

## Order

| Phase | Work | Done when |
|---|---|---|
| 0 | Confirm OpenShell's audit-mode violations appear as events in the SIEM; decide the catch (option 1 or 3) | Violations visible in a dashboard |
| 1 | Generator, proof, conformance test, for one profile (`release-ops`) | Test passes on the catalog and the 387 fuzz variants |
| 2 | Audit-mode rollout on the cluster for that profile; agreement metric | Zero disagreements over a day |
| 3 | Enforce; Risk Guard's copy to watching; SIEM restriction signal if option 1 | One profile moved, red-team gate still green |
| 4 | `policy_update` proposals on the Approvals page; the other profiles | All task profiles moved |
| 5 | Update the Controls page, the how-it-works page, the demo and these docs | No page says the list lives in Risk Guard |

## Not part of this

* **Filesystem.** OpenShell requires Landlock and fails closed without it, so there is no weaker mode for Risk Guard to cover. Risk Guard sees no file access today. If runtime file visibility is wanted, that is a separate sensor in the guest (for example eBPF or audit), feeding the SIEM; it is not designed here.
* **SIEM hints into scoring.** Separate; see [the story](the-story.md).
