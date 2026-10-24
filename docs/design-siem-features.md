<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Design: OpenSearch features that improve Risk Guard's scoring

Status: Risk Guard's side is built (see "What was built on Risk Guard's side" at the end); it has not been deployed. The publisher on the SIEM side is separate work. This document was the contract for three pieces of work (Risk Guard's side, the publisher, and the adaptive learner), written so they could be built in parallel.

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

## What was built on Risk Guard's side

Built and tested; **not deployed**, and nothing here has been run against a live OpenSearch or the live cluster. The publisher (`src/signal_forwarder.rs`) is separate work, so nothing has yet sent a real batch to this endpoint; the tests post batches themselves.

**Ingest.** `POST /features` on the signals listener (`src/signals.rs`, `src/store/siem_features.rs`). Same mutual TLS and SPIFFE allow-list as signals; the source recorded is the verified SPIFFE ID (a bearer-token listener records `bearer-token`). The body is schema 1 exactly as above and **refuses unknown fields**, so a body that tries to carry a `source` is a 400, not a quiet ignore. Limits: 64 KiB body (413 over it, before the body is read), at most 2,000 subjects, one batch per source per 10 seconds (429), `window_seconds` 60 to 3,600, a batch generated more than 10 minutes ago is refused as stale (422), one generated more than 5 minutes ahead is refused (400). Features are checked one by one against the closed vocabulary (`src/detector/siem.rs`): an unknown name, a name for the wrong kind of subject (for example a fleet name on a sandbox), a non-integer or negative value, or a value over its range (counts 0 to 100,000, permille 0 to 1,000) is rejected and counted by reason, and the rest of the batch is still stored. The answer says how many were accepted and rejected, why, and how many sandbox and SPIFFE subjects resolved to a workload.

**Tables** (created by `ensure_siem_feature_tables`, the way the change-request tables are): `siem_features` holds the latest value per (kind, subject, name) with `expires_at_ms = generated_at + 2 x window_seconds`, the source, when it was received, and the sandbox and workload it resolved to; an older batch arriving late does not replace a newer value. `siem_feature_batches` is the audit of every batch (source, size, subjects, accepted, rejected, resolved, unresolved, outcome and reasons), including refused and malformed ones except bodies over 64 KiB, which are refused by the HTTP layer before Risk Guard sees them. Expired features are deleted an hour after they expire and batch rows after seven days. A `siem_features_json` column on `decisions` holds the features a decision used.

**Resolution.** A `sandbox` subject resolves through its latest epoch, run binding and scoring context to the workload. A `spiffe` subject names a sandbox as `spiffe://<domain>/openshell/sandbox/<id>` (the reverse of the derivation in `src/ocsf.rs`; if this store knows its own trust domain, another domain is refused) or, for any other SPIFFE ID, as the SVID-listener sandbox derived from the ID. A sandbox Risk Guard has not met is stored by sandbox only and counted as unresolved. At scoring time a request reads the features stored for its sandbox (sandbox and SPIFFE subjects, the larger value if both give one), for its workload, and the fleet's.

**Scoring.** Rule `siem_context` (`RULE_SIEM_CONTEXT`), set in a profile's `rule_modes`, default shadow, with `siem_context_max_points` (default 15, never more than 30). R1 to R4 are exactly the table above and live in `src/detector/siem.rs`; the detector stays pure, taking a bounded `ContextFeatures` in `DetectorContext` (empty by default). Watching adds a `siem_context` signal with contribution 0 and the points it would have added (and whether they would have crossed the observe or enforce threshold); enforcing adds the points before the outcome is chosen. Nothing is added when a feature is missing, expired, or the rule is off, and a decision with no features is unchanged: the same signals, the same score, the same JSON. The score can only go up, so an outcome can only get stricter; this is checked over 1,500 generated cases in `tests/siem_features.rs`. The lookup happens inside the decision's own transaction and reads two indexed tables; a missing or empty table adds nothing. Under a saved per-workload guardrail revision the profile's `rule_modes` come from that revision (as for the other rules), so `siem_context` runs in its default, shadow, for such a workload until the revision names it.

**Recording and replay.** The features used (scope, name, value, subject, age) are stored on the decision and included in the replay bundle as `features` on each decision event (left out when there were none, so a bundle without them has the same bytes and hash as before). Replay scores each decision with exactly its recorded features. `detector_version` is now `interaction-v2` and the configuration hash includes the rule set, so decisions bound to the old configuration identifier are not accepted under the new build: a run started before an upgrade must be started again after it. An older bundle replays with a note that the configuration differs; its decisions, which had no features, come out the same.

**Controls.** One row, "SIEM context (risk features)" (it replaces the earlier "not built" placeholder): mode per task profile, fresh features, age of the newest accepted batch, decisions that would have changed (watching) or did change (enforcing) in the last day, and "no features received" until a batch has been accepted.

**Not done.** The publisher; any use of the features by the adaptive learner; a console page for the batch audit (the tables are there, `list_siem_feature_batches` reads them); promotion of the rule through the two-person change flow (a profile's `rule_modes` is set the way other rules' modes are); an end-to-end run against OpenSearch.
