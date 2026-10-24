<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Design: OpenSearch features that improve Risk Guard's scoring

Status: design. It is the contract for three pieces of work (Risk Guard's side, the publisher on the SIEM side, and the adaptive learner), written so they can be built in parallel.

## Goal

OpenSearch holds what both OpenShell and Risk Guard saw, across every sandbox and over time. Risk Guard sees one workload's calls at the moment they happen. The SIEM can say things Risk Guard cannot: "this sandbox has been refused by OpenShell's policy ten times in five minutes", "this workload's refusal rate is unlike the fleet's", "three workloads started probing at once". Those become **features** that Risk Guard's scoring may use, per sandbox (and so per SPIFFE identity), per workload, and across the fleet.

## Principles

1. **Never in the hot path.** Scoring reads a local table. If OpenSearch, the publisher or the network is down, features go stale and stop mattering; enforcement and fail-closed behavior are unchanged.
2. **Tighten only.** A feature can add risk. It can never subtract it, and it can never turn a refusal into an allow.
3. **Bounded.** Total effect is capped (default 15 points of a 100-point score, configurable up to 30 per task profile). A feature alone cannot cause a denial at the default threshold.
4. **Watching first.** A new rule starts in watching mode: Risk Guard works out what it would have added, records it, and adds nothing. A person promotes it per task profile, with the same evidence discipline as other rules.
5. **Recorded and replayable.** Each decision stores the exact features it used. Replay feeds them back in, so decisions still reproduce from a bundle.
6. **Closed vocabulary.** Only the feature names below are accepted. Unknown names, out-of-range values and stale batches are rejected and counted.
7. **Explainable.** The decision breakdown names each feature, its value, and the points it added (or would have added).

## The contract

**Transport.** `POST /features` on Risk Guard's signals listener (the existing mutual-TLS port). Allowed callers are the SPIFFE IDs already allowed for signals (the signal forwarder). The caller's verified identity is recorded as the source; the body cannot override it. Rate limit: one batch per 10 seconds per source, maximum 2,000 subjects, 64 KiB.

**Body (schema 1).**

```json
{
  "schema": 1,
  "generated_at_ms": 1792800000000,
  "window_seconds": 300,
  "subjects": [
    {"kind": "sandbox",  "id": "<OpenShell sandbox id, the OCSF container.uid>", "features": {"openshell_denials_5m": 3}},
    {"kind": "spiffe",   "id": "spiffe://<trust domain>/ns/<ns>/sa/<sa>",         "features": {"openshell_denials_5m": 3}},
    {"kind": "workload", "id": "<Risk Guard agent_id>",                           "features": {"refusal_ratio_15m_permille": 420}},
    {"kind": "fleet",    "id": "fleet",                                           "features": {"fleet_workloads_with_denials_5m": 4}}
  ]
}
```

**Features (the whole vocabulary).** Counts are integers 0 to 100,000; "permille" values are 0 to 1,000.

| Name | Kinds | Meaning | Where OpenSearch gets it |
|---|---|---|---|
| `openshell_denials_5m` | sandbox, spiffe | OpenShell policy denials (enforced L7 denials and denied connections) in the last 5 minutes | OpenShell events: `firewall_rule.type:"l7" and action:"Denied"`, or class Network Activity with action Denied, by `container.uid` |
| `openshell_denials_1h` | sandbox, spiffe | The same over an hour | same |
| `openshell_would_block_5m` | sandbox, spiffe | Requests an audit-mode policy logged as violations (`message:"L7_REQUEST audit"`) | same |
| `refusal_ratio_15m_permille` | workload | Risk Guard's refusals over its decisions, 15 minutes, times 1,000 | Risk Guard per-minute summary events (`unmapped.risk_guard.gate:"summary"`), by `unmapped.risk_guard.agent_id` |
| `new_routes_1h` | workload | Distinct (host, route) pairs seen in the last hour that this workload did not use in the previous 7 days | Risk Guard route events (`gate:"route"`) |
| `routes_unique_to_workload_permille` | workload | Share of this workload's routes in the last 24 hours that no other workload used | same; the across-workloads part |
| `fleet_openshell_denials_5m` | fleet | Denials across all sandboxes in 5 minutes | OpenShell events |
| `fleet_workloads_with_denials_5m` | fleet | Distinct sandboxes with at least one denial in 5 minutes | OpenShell events |
| `fleet_refusal_ratio_15m_permille` | fleet | Risk Guard's refusals over decisions across all workloads | summary events |
| `fleet_active_workloads_15m` | fleet | Workloads that made any call in 15 minutes | summary events |

**What Risk Guard does with a batch.** For `sandbox` and `spiffe` subjects it resolves the sandbox to its workload (its epoch and run tables already say which workload a sandbox belongs to; a SPIFFE ID for a sandbox is derived from the sandbox id and trust domain, which Risk Guard knows). It stores the latest value per (kind, id, name) with `expires_at = generated_at + 2 × window_seconds`. Anything older than `generated_at - 10 minutes` is rejected as stale. Every batch (source, size, accepted, rejected and why) is kept in an audit table.

## Scoring

A new rule, `siem_context`, in a task profile's `rule_modes` (default `shadow`; `enforce` applies it). It computes an adjustment from fresh features with fixed, documented rules, capped at the profile's maximum (default 15):

| Rule | Adds | Condition |
|---|---|---|
| R1 probing the policy | +4, or +8 | the sandbox's `openshell_denials_5m` is 3 or more, or 10 or more |
| R2 unlike the fleet | +3 | the workload's `refusal_ratio_15m_permille` is 300 or more while the fleet's is 100 or less |
| R3 unusual routes | +3 | `new_routes_1h` is 3 or more and `routes_unique_to_workload_permille` is 500 or more |
| R4 a campaign | +4 | `fleet_workloads_with_denials_5m` is 3 or more and this sandbox has at least one denial |

In watching mode the decision carries a `siem_context` signal with contribution 0 and the points it would have added. In enforce mode the points are added to the score before the outcome is chosen. Missing or stale features add nothing.

## Recording and replay

The features used (name, value, subject, age) are stored with the decision and included in the replay bundle. Replay supplies them to the scorer at the same point. The detector's configuration hash and `detector_version` change when these rules do, so an old bundle is still replayed under the rules it was recorded with.

## Controls page

One row, "SIEM context (risk features)", with its mode, the number of fresh features, the age of the newest batch, and how many decisions it would have changed (watching) or did change (enforcing). If no batch has ever arrived it says "no features received".

## Security

Only the forwarder's SPIFFE ID may post. The publisher reads OpenSearch with a dedicated read-only user limited to the `ocsf-openshell*` indexes, not the admin account. Values are clamped and names are an allow-list. Nothing in a batch is used as free text.

## Out of scope for the first version

OpenSearch anomaly-detection scores as a feature (there is too little real data; the vocabulary can grow later), any effect that can loosen, and applying features to training data (the adaptive learner may read the same table, see the adaptive v2 note).
