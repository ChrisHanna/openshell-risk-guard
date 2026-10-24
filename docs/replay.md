# Decision replay

A decision depends on more than the request and a version number. It depends on what came before: counts in time windows, restrictions
latched earlier (including by a previous run of the same agent), the guardrail settings in force at that moment, and the order things
happened in. Replay rebuilds that state from nothing and checks that the same decisions and reason codes come out.

```bash
# on the host that has the database
openshell-risk-guard replay-export --db risk-guard.db --agent-id <agent> --out bundle.json
# anywhere, with no database and no cluster
openshell-risk-guard replay-verify --bundle bundle.json
```

`replay-verify` exits non-zero and prints each difference (request, field, recorded value, replayed value) if anything diverges.

## The unit: one scoring context

State lives in a **scoring context**: an agent's revision, task profile, baseline, detector configuration and mode. Runs and sandboxes come
and go; the context keeps the windows and restrictions. A bundle is one context.

## What a bundle holds

| Needed to replay | Where it comes from |
|---|---|
| Effective policy and detector configuration | the detector version and configuration id, checked against the build doing the replay; each epoch's credentialed endpoints and policy hash |
| Baseline | the context's baseline profile, checked against its hash, plus every profile a guardrail revision names |
| Guardrail settings in force | each revision the context's decisions ran under, and which revision each decision used |
| Workload binding | the agent, its runs, and the epoch bound to each run |
| Prior restriction and counter state | rebuilt by replaying the context's whole history in order, including carry-over between runs |
| Operator actions | restriction clearances, placed where they happened (scope, tier and time only) |
| Time inputs | each request's own timestamp; the detector reads nothing from the clock |
| Event ordering | the order decisions were committed (SQLite's row id) |
| Build | crate version, detector version, configuration id |

**Not included:** bodies, headers and query strings (never stored), tokens, signing keys, the resource-hashing key, operator names and
reasons, and network policy text. The bundle does contain resource names (for example `org/payments-prod`), binary paths and host names, because
decisions depend on them. A `content_hash` detects damage or editing; it does not say who made the bundle.

## When it refuses, and why

A bundle is marked incomplete, and replay refuses it unless you pass `--allow-incomplete`, when:

* an epoch's decisions do not run 1, 2, 3… with no gaps (retention pruning or loss means the starting state is unknown);
* decisions in those epochs were made without an agent run (they are not part of any context);
* a decision was scored by an enforced adaptive model (the model is not in the bundle);
* a decision was scored under baseline maturity that an operator credited from an adaptive model (the credit is not in the bundle; such decisions carry a `maturity_credit` signal).

A bundle whose content hash does not match, whose baseline does not match its hash, or of an unknown format version is always refused.
A different detector configuration is replayed but reported (`configuration_matches: false`), since the differences may come from it.

## Tested

`tests/replay.rs`, on a real database file: windowed counts; a destructive call that latches a restriction; a guardrail revision saved
part-way through; a second run in another sandbox that meets the carried restriction; an operator clearance; then export, a trip through
JSON, and replay in a fresh store. Every decision and reason code matches. Editing a bundle is refused, and an edit that is resealed shows up as divergences. Missing
history is reported and refused. The bundle contains none of the test's keys.

## Limits

* **Order is the commit order of rows.** If a database was vacuumed or copied by something that renumbers rows, the order can change. A
  restore from a backup file keeps it.
* **Retention** (30 days by default) deletes old decisions; a context older than that is incomplete.
* **Not yet run on the live cluster's data.** The deployed image predates this command; the first export from real data may report
  incomplete history for reasons the tests do not cover.
* Adaptive (shadow) scoring is not replayed; it changes a decision only when a model was enforced, which is checked.
