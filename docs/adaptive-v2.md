<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Adaptive learning, version 2

Algorithm version `network-metadata-empirical-v2` (the first learner, `-v1`, still scores every model that was fitted under it).

> **Read this first.** Every number below comes from scripted traffic of four sample agents, ten generator seeds, and attacks written by the same hands as the generator. The two agents in `data/real` are also scripted and ours. These are regression checks on named attack shapes, **not accuracy against an unseen attacker**. Intervals are Wilson 95% intervals. Benign calls inside one session are correlated, so the false-flag intervals are narrower than the truth. Nothing was tuned on the seeds used here: the v2 weights were fixed before the first run, and the only change made after seeing results was to drop a component that did not help (the fleet prior, below).

## 1. How it is measured

`src/adaptive_eval.rs`, run by `examples/adaptive_eval.rs` and gated by `tests/adaptive_eval.rs`, needs no cluster and no clock.

```
cargo run --release --example adaptive_eval -- --suite headline --seeds 101-110
# suites: headline, cold, ablation, context, real, all
```

* **Traffic.** A Rust port of `scripts/ml/agents.py` and `generate.py`. The four agent models are read from `testdata/adaptive-eval/fleet.json`, which `python scripts/ml/agents.py --dump` writes and `scripts/ml/test_ml.py` checks, so the two generators cannot drift apart. The random draws are not Python's, so a seed gives different (statistically equivalent) traffic. 72 hours per workload, 12 attack episodes per workload (the five shapes in `generate.py`: tempting call, enumeration, burst, slow-and-low, subtle write), all in the last 30%.
* **Learning.** Benign hours are cut into hour-long captures (one run each), as the store does. A workload trains on its first 40 hours; hours 41 to 50 are the promotion holdout; the rest is the test period. Evaluation replays the test period one call at a time with causal windows, exactly as `score_stream` does for a run.
* **Metrics.** Detection is per attack episode: caught at the *alert* line (score 40, a shadow alert) or at the *would-block* line (score 70 with confidence, the only thing enforcement acts on). False flags are per benign call. Benign calls within 15 minutes after an attack call are excluded, because the attack is still in their window.
* **Two worlds.** *Closed* is what `scripts/ml` generates: benign traffic never touches a resource that is not in the training set. *Open* makes 1 in 100 benign calls to a route with a variable touch a never-seen record (a new ticket, a new bucket). Closed flatters any novelty signal; open is the fairer test of false alerts.
* **Real data.** `python scripts/ml/summaries.py --export data/real` writes per-minute summaries. They hold counts, not requests, and carry no attack labels, so the only thing they can answer is how often the learned rate and fan-out limits would alert on minutes with no refusal. See section 5.

## 2. Before: the first learner

v1, seeds 101 to 110, 40 training hours, 40 models (4 workloads x 10 seeds), all of them ready for promotion. Detection counts are episodes (480 in all, 120 per workload).

| | closed world | open world |
|---|---|---|
| benign calls scored | 15,937 | 15,346 |
| false alerts | 0 (0.0%, [0.0, 0.0]) | 0 (0.0%, [0.0, 0.0]) |
| false would-blocks | 0 | 0 |
| attacks caught, alert line | 141/480 = 29.4% [25.5, 33.6] | 141/480 = 29.4% [25.5, 33.6] |
| attacks caught, would-block line | 49/480 = 10.2% [7.8, 13.2] | 63/480 = 13.1% [10.4, 16.4] |

| shape (closed world) | alert | would-block |
|---|---|---|
| burst | 27/80 = 33.8% [24.3, 44.6] | 27/80 = 33.8% [24.3, 44.6] |
| enumeration | 85/120 = 70.8% [62.2, 78.2] | 22/120 = 18.3% [12.4, 26.2] |
| slow-and-low | 20/80 = 25.0% [16.8, 35.5] | 0/80 = 0.0% [0.0, 4.6] |
| subtle write | 3/80 = 3.8% [1.3, 10.5] | 0/80 = 0.0% [0.0, 4.6] |
| tempting call | 6/120 = 5.0% [2.3, 10.5] | 0/120 = 0.0% [0.0, 3.1] |

By workload the alert line catches 18% (support) to 35% (token). The first learner is silent on benign traffic and also nearly silent on everything else. Why: a single unseen category is worth at most 15 to 25 points; the rate rule only fires above `max(2x max, 3x p99, 20)` and is severe only at 100 calls in a minute, so a burst of 60 approved calls scores 35 and never alerts (the documented known miss RT-024); nothing watches how many new resources turn up over an hour; and a method that was never used is not special.

## 3. What changed

All of it is in `src/adaptive.rs`, `src/adaptive/v2.rs` and `src/store/adaptive.rs`. `ALGORITHM_VERSION` is now `-v2`.

**(b) Richer deterministic features.** Each is computed by one function (`shape_values`, `Tracker`) used identically when fitting and when scoring, from the run's last hour of calls (bounded to 600). Learned ranges (min, p01, median, p99, max over every training call) are stored in the model.

| feature | what it is | scored as |
|---|---|---|
| burst peak | most calls in any 10-second slice of the last minute | beyond the learned range: +8, +15 when far beyond |
| route entropy | Shannon entropy of the action mix over 15 minutes | either side of the range |
| write share | share of the 15 minutes' calls that were writes | above the range |
| gap regularity | median absolute deviation of inter-arrival gaps over their median (near 0 is machine-regular) | below the range |
| method mix | a method this workload (or its task profile) never used: +20; under 1% of traffic: +10 | |
| novelty | distinct never-seen resources in the last hour: 2 add 15, 3 or more add 30 | fan-out in the sense that matters for a slow probe |

The four shape features together are capped at 30, so they never reach the alert line alone; they only add to other evidence. Rate and fan-out over 1 and 15 minutes are unchanged.

**(a) Cold start by shrinkage.** A model can carry a `prior` pooled from other workloads' models of the same task profile (counts summed, rate and fan-out envelopes weighted by window count, shape ranges by sample count). A category's effective frequency is `(own + 200 x prior_share) / (own_total + 200)`, so the prior counts for at most 200 pseudo-requests and fades as the workload's own history grows. A category nobody has seen is still *unseen* at full weight; one seen only by siblings is judged by its pooled frequency. The prior is stored inside the model (with the ids of the models it came from), so the model's hash covers it and an auditor can see where it came from. The store pools the newest usable model of each other workload with the same task profile.

**(c) Optional context.** `ContextInputs` is a plain struct, every field `Option`, accepted by `assess_in_context`. It mirrors the vocabulary in `docs/design-siem-features.md` (OpenShell denials per sandbox, refusal ratios, fleet aggregates). The learner works with none. Values are clamped, and context can only add at most 12 points and only when the other evidence already scores 15 or more, so it can start nothing and loosen nothing. The store passes `None` today (the `siem_features` table is another branch's work); wiring it is one argument at the call in `load_and_assess`. Training does not use context.

**(d) Per workload, per task profile, fleet.** Each workload has its own model; the task-profile prior links it to siblings. A fleet-wide prior across profiles was built and measured (section 4) and is **not** used.

**Compatibility.** `assess` dispatches on a model's own version; a v1 model scores exactly as before and its stored JSON is unchanged (every new field is absent when empty). `model()` accepts both versions. Replay is unchanged for them: shadow scoring is not replayed, an enforced adaptive model still marks a bundle incomplete. Shadow remains the default, and memory stays bounded by the existing `MAX_*` limits (500 samples per session, 1,024 sessions, 100,000 windows) plus 600 activity events, 2,048 keys per prior map, 32 pooled models.

## 4. After, and what each part earned

v2 with every component on, same seeds and worlds:

| | closed world | open world |
|---|---|---|
| false alerts | 0/15,937 (0.0%, [0.0, 0.0]) | 8/15,346 (0.1%, [0.0, 0.1]) |
| false would-blocks | 0 | 0 |
| attacks caught, alert line | 394/480 = 82.1% [78.4, 85.3] | 390/480 = 81.2% [77.5, 84.5] |
| attacks caught, would-block line | 202/480 = 42.1% [37.7, 46.5] | 205/480 = 42.7% [38.4, 47.2] |

| shape (closed world) | v1 alert | v2 alert | v1 would-block | v2 would-block |
|---|---|---|---|---|
| burst | 33.8% | 100.0% [95.4, 100.0] | 33.8% | 53.8% [42.9, 64.3] |
| enumeration | 70.8% | 100.0% [96.9, 100.0] | 18.3% | 92.5% [86.4, 96.0] |
| slow-and-low | 25.0% | 100.0% [95.4, 100.0] | 0.0% | 30.0% [21.1, 40.8] |
| subtle write | 3.8% | 52.5% [41.7, 63.1] | 0.0% | 6.2% [2.7, 13.8] |
| tempting call | 5.0% | 60.0% [51.1, 68.3] | 0.0% | 15.8% [10.4, 23.4] |

Ablation (all alert-line, would-block in brackets; episodes of 480):

| | closed | open | |
|---|---|---|---|
| all components | 394 (202) | 390 (205) | |
| without novelty | 286 (122) | 266 (129) | **kept**: -108 and -124 alert detections. Open-world false alerts fall from 8 to 0 without it, which is its price (about 1 per 2,000 benign calls) |
| without method mix | 353 (188) | 359 (185) | **kept**: the tempting and subtle writes, which use a method the agent never uses; no false-alert cost |
| without shape features | 348 (155) | 357 (163) | **kept, but only burst peak is shown to matter**: removing the four shape features costs 37 (closed) and 32 (open) burst detections at the alert line, 16 and 20 at would-block, and a few subtle-write and tempting-call detections in the closed world only (3 and 6). Which of the four features does the work was not separated; the burst is the case burst peak is built for, and the others are the first candidates to drop if they keep not showing a gain |

**Cold start** (all workloads, alert line / would-block line of 480 episodes, false alerts of about 15,900 benign calls; with 2 to 8 training hours no model reaches the 20-run promotion floor, which is correct):

| training hours | v1 | v2, no prior | v2 + task-profile prior | v2 + fleet prior |
|---|---|---|---|---|
| 2 (closed) | 171 / 92, 0 FA | 205 / 102, 4 FA | **394 / 205, 2 FA** | 189 / 93, 0 FA |
| 4 (closed) | 161 / 87, 0 FA | 308 / 172, 22 FA | **394 / 205, 2 FA** | 299 / 138, 19 FA |
| 8 (closed) | 154 / 73, 0 FA | 394 / 213, 11 FA | **394 / 207, 2 FA** | 388 / 180, 2 FA |
| 4 (open) | 166 / 94, 0 FA | 302 / 170, 9 FA | **393 / 207, 8 FA** | 288 / 131, 19 FA |

* The task-profile prior does what shrinkage should: a workload with 2 hours of history scores like one with 40, and a v2 model without a prior at 4 hours raises 22 false alerts that the prior cuts to 2. **Caveat that matters:** in this harness the sibling is a second draw from the *same* agent model, so the prior is the right answer by construction. It shows the mechanism works when siblings really are alike; it does not show how much a prior costs when siblings differ. A divergent sibling was not tested.
* **The fleet-wide prior did not help and is not used.** Pooled across other task profiles (rates and shape only), it caught fewer attacks than no prior at 4 and 8 hours (138 against 172, 180 against 213 at the would-block line) and did not reduce false alerts. Different agents have different rates, so pooling them blurs the limit the workload needed.
* v2 with no prior and little history is not better than v1 on false alerts (22 against 0 at 4 hours): v1 stays quiet partly because it detects almost nothing. This is why the store attaches the prior whenever a sibling exists.

**Context (synthetic, mechanism only).** With context correlated with the attacks *by construction* detection rises from 390 to 464 (alert) and 205 to 291 (would-block) with no new false alerts; with context unrelated to the attacks (1 call in 20 carries 4 denials) alert detection is unchanged and would-block rises by 6 with 0 false blocks. Because the context here is invented, the first number says the plumbing and the cap work and nothing about whether real denials track real attackers.

## 5. Real data

Run on `data/real/summaries.jsonl` as exported on 2026-10-23 and 24 (1,003 rows; workloads are labelled by rank of history, not by identity). 82 rows had no workload name and were left out, because they cannot be placed in any workload's history. A workload needs 120 active minutes; the first 70% trains the rate and fan-out limits with the learner's own rule, the last 30% is tested.

| workload | active minutes | result |
|---|---|---|
| 1 | 424 | evaluated. 0 of 110 minutes with no refusal alerted (Wilson 95%: 0.0% to 3.4%); 0 of 18 minutes that had a refusal alerted |
| 2 | 416 | evaluated. 0 of 110 quiet minutes alerted (0.0% to 3.4%); 0 of 15 refusal minutes alerted |
| 3 to 8 | 22, 17, 16, 13, 10, 3 | **not evaluated**: far under the 120 minutes needed |

What this can and cannot show:

* It can show the rate and fan-out limits do not fire on these two scripted workloads' ordinary minutes. It cannot show they would catch anything: the busiest minute in the data has 5 calls, so the learned limits sit at the learner's floors (20 calls a minute), and no minute came near them.
* The minutes with a refusal are **not** labelled attacks. They are Risk Guard refusals (for example the red-team acts), and the rate rule did not alert on any, which says the refusals were not rate or fan-out events, not that the learner missed them.
* Only the temporal part of the learner can run on this data. Destination, resource, action, method, binary, burst shape and novelty need individual requests, which the per-minute summaries do not hold, so none of the v2 improvements is evaluated on real data. The result is the same under v1 and v2, because this path uses the one rule they share.
* Six of eight workloads had too little history to say anything; that is the true state of the real data today, not a gap in the harness. Re-run `scripts/ml/summaries.py --export` and the example as history accumulates.

## 6. Honest maturity (task 3)

**The problem.** `BaselineProfile::maturity` reads two hand-edited counters (`training_sessions`, `training_requests`; 20 and 200). Every fleet baseline has 0, so the behavioral score can never enforce, and nothing ties the counters to anything observed.

**What was built.** A maturity *credit*: an auditable row in the new `adaptive_maturity_credits` table (created by `migrations/0008_adaptive_maturity_credits.sql`). It is written only by the operator action `credit_maturity`, and only when:

1. the model is the one **enforced now**, so an operator promoted it, and so it passed every promotion gate (holdout floors, no holdout would-blocks, shadow evidence from independent runs, not worse than the model it replaced);
2. the model was trained on at least 20 independent runs and 200 requests (the same thresholds as `maturity()`, kept in step by a test);
3. the operator ticks `acknowledge_behavioral_enforcement`: crediting lets the behavioral score refuse on rarity for that workload;
4. the baseline's approved action list and expected binaries do not leave out traffic that was at least 1% of what the model observed (a mature profile scores calls off those lists as new, so a list that contradicts the traffic must be fixed first).

The row records who, when, the model id and hash, the independent runs and requests, the holdout numbers, and how many training captures a person approved against how many the automatic clean-run policy approved. Rows are never deleted: `revoke_maturity_credit` stamps who, when and why.

**How it is read.** When a decision loads its baseline, a credit that *counts right now* raises the effective counters to the credited numbers (never above what was observed). It counts while the credit is not revoked, its model is not revoked, the model was trained under the guardrails revision now in force, **and the model is still the enforced one**: demoting or turning off the model withdraws the effect, promoting it again restores it. The hand-kept counters are not touched. Nothing changes for a workload without a credit, and the cold-start rule is untouched: below the thresholds a profile is still `Insufficient` and never denies on rarity alone. Each decision made under a credit carries a `maturity_credit` signal, the raised profile is stored as an artifact of its own type (so Controls does not list it as another task profile), and a replay bundle that contains such a decision is marked incomplete, the same treatment as an enforced adaptive model.

**Controls page.** The "Behavioral score" row lists, per task profile, `credited_workloads` (workload, sessions, requests, who credited it, when, which model), and its note says how many workloads are mature through a credit instead of the hand-kept counters. The workload's adaptive view lists every credit with whether it counts now.

**Decisions that were the user's to make, with the safe default taken.**

* *Should promotion raise maturity automatically?* Default: **no**, explicit operator action only. Promotion decides whether a model's anomalies may refuse a call; maturity decides whether the classic behavioral rules (approved lists, hand-set envelopes) may refuse a call on rarity. They are different permissions. The alternative is to credit at promotion time with a single combined confirmation; it is a small change in `set_model` and is safe only once the baseline lists are known to match the traffic.
* *Count human-approved windows only?* Default: count every window the model trained on, and **record** how many a person approved. Most captures here are auto-approved by the clean-run policy, so counting only people would leave nearly every workload immature. The alternative is a gate on the recorded person count.
* *Demotion withdraws the credit's effect* (above). The alternative, keeping maturity after demotion because the observations were real, is simpler but lets a demoted model's operator-reviewed trust linger.

## 7. Promotion gates (task 4)

When a candidate is trained the store compares it with the model it would replace (the enforced one, else the current shadow, else the newest earlier model), on the **same inputs**: the candidate's holdout, replayed through both, and up to fourteen reference attack probes built from the candidate's own most common traffic (bursts of 40 to 150 calls, enumerations of 20 to 40, slow drips of 5 to 10, a never-used write on each of the top routes, an unseen destination). The result, with both models' numbers, is stored in the candidate (`profile.comparison`, shown to the operator in the model view). The candidate is **blocked from promotion** if it would block more of the benign holdout than the previous model, or catches fewer probes at either line. The blocker text carries the numbers, e.g. `Candidate: holdout would-blocks 0/150 (0.0%), ... injected probes alerted 9/12 (75.0%), blocked 4/12 (33.3%). Previous: ...`. When an operator promotes, the comparison is recomputed against whatever is enforced at that moment if it differs from the one stored. A first model has nothing to be compared with, and a v1 model has no comparison and is promoted under the gates it always had. Limits: the probes are the generator's shapes, so a candidate can pass them and still be worse against an attack nobody thought of; and with a holdout of 50 requests a difference of one call is noise, so the rule is strict by design and an operator who sees a one-call difference retrains.

## 8. Limits

* The data is small, scripted and ours: ten seeds of four agents, 480 attack episodes, attacks written by the generator's author. Differences of a few episodes are noise; the large gaps (burst, enumeration, slow-and-low, cold start) are not.
* The closed world flatters novelty; the open world at 1% is one guess at how often real agents meet new records. The novelty signal's false-alert cost grows with that rate.
* The prior experiment used a perfectly alike sibling.
* The real summaries support only rate and fan-out, and they are unlabeled.
* Shape features other than burst peak are unproven. Context is a mechanism test.
* Alert-line detection is a shadow alert, not a block. At the would-block line v2 catches 42%; the rules (`task_constraint_denied`, the approved lists) are still what stop a tempting call.
* Nothing here is calibrated probability or false-positive-rate certification; the learner's own `phase1_only` caveat stands.
