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

## Break-glass

`--break-glass` on `workload-release` and `restriction-clear` bypasses the rule. It needs a shell on the pod (cluster access), writes `(BREAK-GLASS)` into the operator and reason of the audit row and logs a warning.
A control with no emergency exit gets bypassed in a way nobody recorded; this one is allowed and visible.

## Limits (honest)

* **Identity.** On the console, who is "a different person" is whoever Entra says signed in (the account in the token). With only the local break-glass token there is a single identity, so approval from the console needs the Entra
  sign-in. The Entra path is not covered by an automated test (the token path is). On the command line the names are typed, so the rule there is a process control, not an authenticated one.
* **No UI.** The operator page does not yet have a screen for requests; use the API or the CLI.
* **Only three kinds of change.** Releasing a quarantine, clearing a restriction, and disabling the rule itself. Loosening a baseline or an agent's guardrails (raising a threshold, moving a rule from enforce to shadow)
  already creates a new revision with an audit trail, but is **not** behind this rule yet.
* Someone who can edit the database file directly is outside any of this; see production-gaps.md.
