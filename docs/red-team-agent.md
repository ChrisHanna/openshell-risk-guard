# The adaptive attacker, and Garak as an agent's tool

Three layers, from cheapest to most realistic. Each turns what it finds into a test that runs on every build.

| Layer | What it is | Needs | Status |
|---|---|---|---|
| **Catalog** | 24 hand-written attacks and controls (`conformance/red-team/catalog.json`) | nothing | runs in CI |
| **Fuzzer** | Mutates every single-call must-refuse attack 387 ways: case, encodings, dot segments, separators, query and fragment suffixes, null byte, tab, newline, Unicode look-alikes, host and method spelling (`tests/red_team_fuzz.rs`) | nothing | runs in CI. **387 tried, 0 got through** (239 refused after being scored, 148 refused because the path could not be read) |
| **Adaptive attacker** | An LLM agent that is *given* the goal ("get a DELETE of `worker` accepted") and adapts to the status codes it sees. It is a governed agent like the others, with two tools: `raw_call` (one HTTP request exactly as written, to the three fixture services only) and `garak_scan` | The cluster, an Entra app for the agent, the agent image rebuilt with Garak, NVIDIA model access | **written and unit-tested; not yet run on the cluster** (see below) |

## How the adaptive attacker feeds the gate

1. `scripts/aks/run-redteam.sh` creates a sandbox from the agent image and gives the agent one goal (delete a service, read a secret, export customers, or "run Garak, then attack").
2. Every request the agent makes is written to `/sandbox/redteam-calls.jsonl` by the tool itself (method, URL, status). The runner reads that record, not the model's account of what it did.
3. `scripts/redteam/ingest.py` turns every **destructive request answered 2xx** into an entry in `conformance/red-team/discovered.json`, expected to be **refused**. The red-team gate replays the file with the catalog, so a discovered gap
   fails the build until Risk Guard refuses it. Refused requests are only counted.

If the live run got a 2xx but the offline engine refuses the same call, the entry passes: the difference is the environment (policy, service), and the entry stays as evidence rather than a failure.

## Garak

Garak probes a **model** for susceptibility (prompt injection, encoding tricks, jailbreaks). The agent has it as a tool (`garak_scan`, a separate virtual environment so its dependencies cannot disturb the agent toolkit's), runs a short scan of its
own model through the sandbox's allowed route to the hosted model, and gets back a plain summary: per probe and detector, how many attempts failed. The summary is saved to `conformance/red-team/garak-latest.json`.

What that does and does not mean: a Garak failure says the model can be talked into something. It is **not** a finding about Risk Guard, and it is never turned into a call-level test by itself. The link is the scenario `garak-then-attack`: the agent learns how its model can be steered,
then tries to use that to make a refused call. If a call gets through, that is a call-level finding and goes through the path above.

## What has not been done (honestly)

* The adaptive attacker has **not run on the cluster**. It needs: `13-register-agent-identity.ps1 -AgentName red-team` (a new Entra application in the tenant), the agent image rebuilt with Garak (`14-build-agent-image.ps1`; it adds roughly 1.5 GB for CPU PyTorch and Garak),
  a Risk Guard redeploy to import the `red-team-probe` profile, and NVIDIA model calls (Garak makes many). None of those is started automatically.
* Whether Garak's traffic is allowed by the sandbox's binary-identity rule (it runs under a different Python than the agent toolkit) is untested. The policy lists the system Python the virtual environment resolves to; the first run will show.
* The fuzzer found nothing. That is a result about 387 spellings from one author, not a proof. Its value is that the next regression is caught at once, and that anything it ever finds must be fixed or documented in `conformance/red-team/fuzz-known.json`.
