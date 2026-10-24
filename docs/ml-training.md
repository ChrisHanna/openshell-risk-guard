# Training models on the sample agents

The four fleet agents (`release`, `cloud`, `support`, `token`) are scripted workflows, so their routine behaviour is known well enough to simulate. That makes it possible to
**build, test and demonstrate the learning pipeline before there is months of real traffic**. This page says what was built, what the numbers are, and what they do not mean.

> **Everything here is synthetic.** A model trained on generated traffic learns the generator. These results show that the pipeline works and how each method behaves on named
> attack shapes. They are not evidence about real attackers or real agents.

## What is there

| Piece | Where | What it does |
|---|---|---|
| Agent and attack models | `scripts/ml/agents.py` | Each agent's routes, mix, pace (log-normal think-time) and session lengths; five attack shapes |
| Trace generator | `scripts/ml/generate.py` | Seeded and reproducible. 72 h by default. Attacks land only in the last 30 % of the time, as in real use |
| Offline training and evaluation | `scripts/ml/train.py` | Per-minute windows, one model per agent, fit on benign training time, scored on later time. Also proposes baseline limits |
| OpenSearch anomaly detection on the same traces | `scripts/ml/opensearch_ad.py` | Loads them into a separate index, trains OpenSearch's detector with **one baseline per agent**, scores it |
| Tests | `scripts/ml/test_ml.py` | Determinism, labelling, no attack leaking into training, the models on shapes where the answer is certain |

```
python scripts/ml/generate.py --out data/synthetic --hours 72 --seed 7
python scripts/ml/train.py --data data/synthetic --report data/synthetic/report.json
python scripts/ml/opensearch_ad.py --data data/synthetic        # needs the demo SIEM; --cleanup removes it
python -m unittest scripts/ml/test_ml.py
```

Needs `numpy`, `pandas` and `scikit-learn` for training (not for the rest of the repository). The generated `data/` is not committed.

## The attack shapes

| Shape | What it is | Why it is in |
|---|---|---|
| `tempting_call` | One off-task, often destructive call | The case the rule engine is built for |
| `enumeration` | 25 to 40 different resources in about 15 s | A scanning agent |
| `burst` | The agent's own approved call, 60 to 120 times in under 30 s | Looks harmless call by call |
| `slow_and_low` | A new resource every 20 minutes | Below every rate window |
| `subtle_write` | One off-task write at the agent's normal pace | A window's statistics hardly move |

## Results (seed 7, 72 h, 4 agents, 48 attack episodes)

Window features per agent per minute: calls in the minute, distinct paths, distinct routes, write share and never-seen-before paths over fifteen minutes, mean gap. The
alert line is set so about 0.5 % of benign training windows would cross it. Minutes that still carry an attack's mark (the fifteen minutes after) are counted as neither benign nor attack.

| | Envelope (per-feature benign spread) | Isolation Forest | OpenSearch anomaly detection (requests per minute, per agent) |
|---|---|---|---|
| Benign minutes flagged | 2 of 232 (0.9 %) | 1 of 232 (0.4 %) | 1 flagged benign interval |
| `tempting_call` | 11 / 12 | 3 / 12 | **0 / 12** |
| `enumeration` | 12 / 12 | 1 / 12 | 4 / 12 |
| `burst` | 8 / 8 | 2 / 8 | 5 / 8 |
| `slow_and_low` | 8 / 8 | 2 / 8 | 3 / 8 |
| `subtle_write` | 6 / 8 | 2 / 8 | **0 / 8** |

How to read it:

* **The simple envelope beat the forest** on these features, and is easy to explain: how far the worst feature sits beyond what benign time looked like. That matches Risk Guard's
  own p95/p99 limits, learned per feature. A tree ensemble needs more data and more careful features than 72 hours of four agents give it.
* **The envelope's strong numbers are flattered.** The attack shapes were written by the same person as the generator, and the envelope has a "never seen this path" feature that fires on
  almost anything an attacker invents. A real agent meets new paths for ordinary reasons.
* **OpenSearch's detector, given only a request count, cannot see a single bad call** (0 of 12) or a write at normal pace (0 of 8). That is not a flaw in it; a count is the wrong feature for those.
  It is exactly why the **rules stay** (`task_constraint_denied` refuses the tempting call outright; the red-team gate holds that) and statistical detection **adds** the rate and variety shapes.
  The two are complementary, not competitors.
* `slow_and_low` caught 3 of 8 by OpenSearch is probably chance (a single request in an otherwise silent minute), not a real ability to see a 20-minute drip.
* Small numbers: 8 to 12 episodes per shape. Treat differences of one or two as noise.

## What it suggests for Risk Guard

`train.py` also proposes baseline limits from benign training time. For all four agents the 99th percentile of requests per minute is about 14 to 17; the shipped profiles say 120 (and 60 for p95).
**That limit is several times looser than these agents behave, which is why a burst of 60 approved calls goes unnoticed (red-team entry RT-024, a documented known miss).**

Two cautions before acting on it: (1) these numbers come from the generator, so they only say *what to look for* in real traffic, not what to set; (2) the synthetic "distinct paths" is not Risk Guard's unit
(it counts keyed resource names per window), so the distinct-resource proposals must be recomputed with the engine's definition. Nothing in this pipeline changes a baseline: a person reviews the
proposal, and a changed baseline is a new version.

## The in-product learner has its own evaluation

Risk Guard's adaptive learner (`src/adaptive.rs`, shadow by default) is measured by a separate, Rust-only harness that reuses these agent models: `cargo run --release --example adaptive_eval -- --suite headline --seeds 101-110`. It needs no cluster, reports detection on the injected attacks and false-block rate on benign traffic per workload with Wilson 95% intervals, and reads the real summaries below for the workloads that have enough of them. The fleet it reads is `testdata/adaptive-eval/fleet.json`, written by `python scripts/ml/agents.py --dump` and checked by `test_ml.py`. Results, what changed in version 2 and what did not help are in [adaptive-v2.md](adaptive-v2.md). The same caveats apply: scripted, small, ours.

## Using it with real traffic

Risk Guard now sends the real equivalent: a once-a-minute **activity summary** per workload (decisions, refused, share refused, highest score, distinct paths) with the workload's identity.
`python scripts/ml/summaries.py --export data/real` pulls them out of the SIEM and `--train data/real` fits one envelope per workload, using the same method as above. It refuses to train
a workload with fewer than 120 active minutes and says so, instead of printing numbers that look like a result. On 2026-10-23 there were 13 summaries in total, so the real-data report
is empty until the agents have run for a while. OpenSearch's own detector, `workload-activity-by-agent`, uses the same events with one baseline per workload (decisions, refused, paths).

Older note, before the summaries existed:

The same pipeline takes real events: export Risk Guard's decisions (or the SIEM's `ocsf-openshell-*` documents) in the `events.jsonl` shape, and `train.py` produces the same report with no
synthetic caveat. The honest path to a model worth trusting is the one the repository already follows: shadow first, measure false denials on real traffic, then enforce.

## Limits

* No online learning, no automatic baseline changes, and no model decides anything in production. The output is a report for a person.
* No labelled real attacks. Recall on real attackers is unknown.
* One feature set, one window length, small samples. Not tuned, on purpose; tuning on the generator that wrote the attacks would only make the table look better.
