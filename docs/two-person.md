# Two-person approval for loosening

**Automation can only tighten. People can loosen, but not alone.** A SIEM signal, a rule or one person can quarantine a workload at once. Releasing it, or clearing a restriction, removes protection, so with
two-person approval on it takes a proposer and a **different** approver.

```
openshell-risk-guard two-person-enable --db …                          # turn the rule on (one-way for one person)
openshell-risk-guard change-propose --db … --kind release_quarantine --agent-id A --proposer alice --reason "…"
openshell-risk-guard change-decide  --db … --id <id> --decider bob --approve --reason "…"     # or --reject
openshell-risk-guard change-list    --db …
```

Console API (operator-authenticated, same as other changes): `GET /api/changes`, `POST /api/changes`, `POST /api/changes/{id}/decide`.

## The rules (enforced in the store, so every door is behind them)

| Rule | Test |
|---|---|
| With the rule on, `release_workload` and `clear_restriction` are refused for one person; the quarantine/restriction stays | `with_the_rule_on_tightening_is_still_one_persons_call_and_loosening_is_not` |
| The proposer cannot approve their own request, in any capitalisation | `a_quarantine_is_released_only_when_someone_else_approves` |
| A different approver carries it out; the audit rows name both people and the request | same |
| A rejected, expired (24 h) or already-decided request changes nothing; no duplicates while one waits | `a_rejected_or_expired_request_changes_nothing` |
| A latched restriction is cleared the same way; a proposal for a restriction that is not there is refused up front | `a_latched_restriction_is_cleared_only_by_a_second_person_too` |
| Turning the rule off is itself a request needing a second person | `the_rule_cannot_be_switched_off_by_one_person` |
| Tightening is unaffected | first test above |
| Console: a direct clear is refused, and the single operator token cannot approve what it proposed | `the_console_refuses_a_direct_release_and_one_token_approving_its_own_request` |

## The Approvals screen and baseline changes

The console has an **Approvals** page (left menu, with a count of what is waiting). It lists proposals waiting for a decision, recent decisions, and **suggested baseline changes**. An administrator signed in with Entra can approve or reject with a reason, or propose a suggested change; everyone else sees the page read-only.

A fourth kind of change, `baseline_update`, is for widening what a task profile may do. It is deliberately narrow: it can add routes that only read (`GET` or `HEAD`), add egress hosts, and **lower** the two request-rate limits. It cannot add a write, remove a deny-list entry, or raise a limit (a request to raise one changes nothing and is recorded as failed). It **always** needs a second person, even when the rule above is off. On approval a new baseline version is stored (`<version>+c<change id>`) with both names in `approved_by`; sandboxes already running keep their baseline, new ones use the new one.

Suggestions are computed inside Risk Guard from its own decision history (`GET /api/baseline-suggestions`): a route not in the baseline, used at least 20 times over at least 3 different hours, never refused, a read, not marked high impact. It does not read the SIEM, so it works when the SIEM is down. Routes it left out are listed with the reason. Egress hosts and rate limits are not suggested here; `scripts/siem/suggest_baselines.py` reads those from the SIEM, and its output can be proposed through the API (`POST /api/changes` with `kind: baseline_update`, `task_profile`, `reason`, `params`).

A redeploy re-imports the baselines in the repository, which would replace an approved change. To keep one, download the baseline from the executed request (`GET /api/baselines/<task profile>`) and commit it.

## Break-glass

`--break-glass` on `workload-release` and `restriction-clear` bypasses the rule. It needs a shell on the pod (cluster access), writes `(BREAK-GLASS)` into the operator and reason of the audit row and logs a warning.
A control with no emergency exit gets bypassed in a way nobody recorded; this one is allowed and visible.

## Limits (honest)

* **Identity.** On the console, who is "a different person" is whoever Entra says signed in (the account in the token). With only the local break-glass token there is a single identity, so approval from the console needs the Entra
  sign-in. The Entra path is not covered by an automated test (the token path is). On the command line the names are typed, so the rule there is a process control, not an authenticated one.
* **UI limits.** The Approvals screen covers listing, deciding and proposing suggested routes. Other proposals (release a quarantine, clear a restriction) are still made from the API or the CLI, and the screen has been checked in a browser against a local console with the token path, not with two real Entra accounts.
* **Four kinds of change.** Releasing a quarantine, clearing a restriction, disabling the rule itself, and widening a baseline (reads, hosts, lower limits only). Loosening an agent's guardrails (raising a threshold, moving a rule from enforce to shadow)
  already creates a new revision with an audit trail, but is **not** behind this rule yet. Importing a whole baseline from a file (`baseline-import`) is also outside it.
* Someone who can edit the database file directly is outside any of this; see production-gaps.md.
