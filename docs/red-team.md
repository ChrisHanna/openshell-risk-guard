# The red-team gate

Every build replays an attack catalog against Risk Guard's real decision path and **fails if the answer changes in the wrong direction**.

* Catalog: [`conformance/red-team/catalog.json`](../conformance/red-team/catalog.json) (data, so adding an attack is a JSON edit).
* Gate: `tests/red_team_gate.rs`, run by `cargo test` and again as its own CI step, which keeps `red-team-report.json` as a build artifact.
* Each attack is a short sequence of calls on one of the fleet's task profiles (`release-ops`, `cloud-hygiene`, `support-triage`) and carries what Risk Guard must do:

| Expectation | Meaning | The build fails when |
|---|---|---|
| `refused` | The last call must be refused | it is allowed (a regression) |
| `allowed` | A benign control | any call is refused (a false positive) |
| `known_miss` | A documented gap | the call is refused (the documentation is stale; update it with the change) |

The gate also fails if the catalog shrinks below 15 must-refuse attacks, 3 controls or 8 categories, so deleting an inconvenient attack cannot turn it green.

## What is in it today

24 entries: destructive actions, secrets access, data destruction, path and encoding evasion (doubled slash, dot segments, case, percent-encoding, null byte, query smuggling),
persistence (immediate retry, a different method, a fresh sandbox for the same workload), confused-deputy cases (an injected instruction makes a read-only agent write or
export), four benign controls, and two known misses (slow enumeration and a burst of approved calls on a cold-start profile). Each is tagged with the OWASP Top 10 for
LLM applications entry whose call-level effect it exercises.

The report says **why** each call was refused. Nearly all are judged (`task_constraint_denied`, or `behavioral_risk_restricted` for a carried restriction). One is not:
dot segments (`/services/web/../worker`) are refused because the normalizer rejects the path, not because the call was scored. That is a safe outcome, but it is a different
claim, and the report keeps them apart.

## More than the catalog

* **Fuzzer** (`tests/red_team_fuzz.rs`): every single-call must-refuse attack is mutated 387 ways; a variant that gets through fails the build unless it is written in `conformance/red-team/fuzz-known.json` with a reason.
* **Adaptive attacker** (`conformance/red-team/discovered.json`): attacks an LLM agent found are replayed with the catalog. See [red-team-agent.md](red-team-agent.md).

## What it does not cover, on purpose

* **Anything only in a body, header or query string** (a method-override header, a destructive query parameter, a mutation inside a GraphQL body). Risk Guard never reads
  them. They are listed in the catalog as `out_of_scope` so they are not mistaken for tested.
* **Model-level attacks** (jailbreaks, prompt leakage, toxic output). Risk Guard governs actions, not text.
* **Unseen attackers.** This is the author's own list. It is a regression gate, not a measure of accuracy.

## Relation to Garak and NeMo Guardrails

They test and shape the *model*; this gate tests the control that must hold **even when the model is fooled**.

* **Garak** probes a model for susceptibility (prompt injection, leakage, encoding tricks). A Garak finding says the model can be made to want something. The question for this
  project is whether the resulting *call* still gets through. The `confused-deputy` entries are that second half, written by hand.
* **NeMo Guardrails** constrains what the model says and which tools it may call, inside the application. Risk Guard sits outside it, at the network and supervisor boundary, so a
  bypassed rail still meets a policy the application cannot edit.
* **Not done:** this repository does not run Garak or NeMo Guardrails. A useful next step is to run Garak against a sandboxed agent's model endpoint and feed any prompt that
  makes the agent attempt a call into this catalog as a new entry, so a model-level finding becomes a permanent call-level regression test.
