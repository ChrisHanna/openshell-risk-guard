# The promotion gate: shadow to enforce

A control that only watches (shadow) records what it **would** refuse. Turning it on (enforce) makes every one of those refusals real. The gate decides, from evidence, whether that is safe now.

```
python scripts/promotion_gate.py            # reads the SIEM, decides, exits 0 (promote) or 1 (hold)
```

`scripts/aks/18-enable-sandbox-egress.ps1 -RestrictionMode enforce` runs it first and stops on `hold`. The policy is `deploy/aks/promotion-policy.json`; the decision logic is a pure function with tests
(`scripts/test_promotion_gate.py`).

## What has to be true

| Check | Meaning | Why |
|---|---|---|
| enough observed | Every agent seen has at least 20 tunnels in the last 24 h, and the observation spans 24 h | A quiet agent proves nothing |
| no unreviewed would-refuse | Every (agent, destination, reason) shadow mode would have refused is covered by a reviewed entry with a **named reviewer, a date and a note** | Each is something enforcement starts blocking; a person says it should be |
| control healthy | Risk Guard has reported recently and failed to answer at most 3 times | Do not tighten a control that is itself struggling |
| can be undone | A verified backup within 24 h | Rollback needs something to roll back to |
| attack catalog passes | The red-team gate report says `pass` and is recent | Enforce on a build that still refuses what it should |

`hold` lists exactly what is missing. The revert command is printed with the decision.

An override is possible and visible: `-OverrideGate "<reason, at least 20 characters>"` records the reason and the time in the state file and prints it in yellow. It exists because a real
incident may justify enforcing before the evidence is complete; it should never be silent.

## What it said on the demo cluster (2026-10-23)

**HOLD**, for four real reasons:

* Observed 0.1 h of traffic, not 24 h; two agents had under 20 tunnels.
* **Four kinds of would-refuse, none reviewed. All four are the same thing: agents holding a latched restriction whose model calls to `integrate.api.nvidia.com:443` enforcement would cut** (110, 103, 62 and 29 times). This is
  the reason the tunnel gate runs in shadow: a restriction is scoped to one kind of request, and enforcing it at the tunnel would cut an agent off from its model. Seeing it as a number is the point of the gate.
* Risk Guard had failed to answer 14 times in the window (the limit is 3).
* No verified backup was recorded in the last 24 hours.

## Limits

* It covers the tunnel gate's restriction mode. Per-profile rule modes (`egress_destination`, `supervisor_silent`) go from shadow to enforce by changing a profile, which is a new profile version; the same evidence applies but
  this gate does not yet read it or block that change.
* "Reviewed" is a claim by a named person in a file in this repository. There is no second-person check on the policy file itself (that is the next section of work: two-person approval).
* The evidence is only as good as the SIEM's. If the collector drops events, the gate sees fewer would-refuse than happened. The control-health check reads Risk Guard's own events to notice silence, but it cannot see drops.
