<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# The SIEM feature publisher

The publisher is the SIEM's half of [design-siem-features.md](design-siem-features.md). Every 30 seconds it asks OpenSearch what OpenShell and Risk Guard recorded, works out the ten features the design names, and posts one batch to Risk Guard's `POST /features`. Risk Guard's side (storing the features and the `siem_context` scoring rule) is a separate piece of work; this document covers only what the publisher does.

It is a mode of the existing binary, `openshell-risk-guard feature-publisher`, and runs as a second container in the **signal-forwarder pod**, so it speaks to Risk Guard as the identity Risk Guard already allows (`spiffe://<trust domain>/ns/siem/sa/signal-forwarder`) over the same mutual TLS, with the same SVID files that `spiffe-helper` keeps current. No new identity and no new secret on Risk Guard's side.

## What it computes

Everything below is a read-only `_search` against `ocsf-openshell*`. The exact request bodies are built in [src/feature_publisher.rs](../src/feature_publisher.rs), each next to the feature it produces, and are unit tested against canned OpenSearch responses.

| Feature | Subject | How it is computed |
|---|---|---|
| `openshell_denials_1h`, `openshell_denials_5m` | sandbox, spiffe | Denial events of the last hour, `terms` on `container.uid.keyword` (up to 2,000 sandboxes), with a nested `filter` aggregation for the last five minutes. |
| `openshell_would_block_5m` | sandbox, spiffe | Events in the last five minutes whose `message` contains the phrase `L7_REQUEST audit`, `terms` on `container.uid.keyword`. |
| `fleet_openshell_denials_5m` | fleet | `hits.total` of the denial events of the last five minutes (all sandboxes). |
| `fleet_workloads_with_denials_5m` | fleet | `cardinality` of `container.uid.keyword` over the same events. |
| `refusal_ratio_15m_permille` | workload | Risk Guard's per-minute `summary` events (`unmapped.risk_guard.gate:"summary"`) of the last 15 minutes: `sum(refused_calls)` over `sum(total)` per `unmapped.risk_guard.agent_id`, times 1,000. A workload with no decisions has no ratio (not zero). |
| `fleet_refusal_ratio_15m_permille` | fleet | The same two sums over all summaries. |
| `fleet_active_workloads_15m` | fleet | `cardinality` of `agent_id` among summaries with `total > 0`. |
| `new_routes_1h`, `routes_unique_to_workload_permille` | workload | One paged `composite` aggregation over route events (`gate:"route"`) from seven days and one hour ago until now, one entry per (workload, host, route) with its first and last time seen. A route is *new* when its first sighting is in the last hour (so the workload did not use it in the seven days before). The *unique* share is, of a workload's routes seen in the last 24 hours, the fraction no other workload used in those 24 hours. |

What counts as an **OpenShell denial**: an event from a sandbox (it has `container.uid`) with `action:"Denied"` that is an enforced L7 decision (`firewall_rule.type:"l7"`) or a Network Activity event (a denied connection, a refused DNS name), and is not `firewall_rule.type:"middleware"`. That last exclusion matters: the supervisor echoes **Risk Guard's own refusals** as middleware events with `action:"Denied"`, and those are not OpenShell policy denials. The gateway's `Authentication` denials have no `container.uid` and fall out for the same reason.

**Subjects.** Sandbox features are sent under `kind:"sandbox"` (the OCSF `container.uid`) and, when the SPIFFE ID can be derived, again under `kind:"spiffe"` with the same values. The ID is derived exactly as `src/ocsf.rs` does: `spiffe://<trust domain>/openshell/sandbox/<id>`, and none for ids that start with `svid-` (those sandboxes already are SVID-named). The trust domain comes from `--trust-domain`, or with `--trust-domain-from-svid` (what the manifest uses) from the publisher's own SVID, on the assumption that SPIRE issues the publisher and the sandboxes in one trust domain; with neither, no `spiffe` subjects are sent. Workload features go under `kind:"workload"` with the Risk Guard `agent_id`. The fleet subject (`kind:"fleet"`, id `fleet`) is always sent when any fleet feature was computed.

**What is left out.** Only subjects with at least one non-zero feature are sent, except the fleet subject. A subject whose features all fall back to zero is therefore *not* sent, and Risk Guard keeps its previous value until that value expires (twice the 300-second window, so at most 10 minutes). That is the contract's rule; it means a recovered sandbox can look slightly worse than it is for a few minutes, never better.

**Limits.** At most 2,000 subjects and 60,000 bytes (Risk Guard's cap is 64 KiB). If a batch would be larger, the quietest subjects are left out first, the fleet subject never, and the log says how many. Values are clamped (counts 0 to 100,000; permille 0 to 1,000).

## Failure behavior

The publisher never blocks or slows Risk Guard, and keeps no state between intervals: no queue, no retry, no backlog.

* **OpenSearch unreachable, or one query failing** (non-200, a timeout, any failed shard, an unparsable answer, or a list too large to read whole): each of the five queries is independent. The features of the failed query are left out of that batch and the log names the query and the reason (`feature-publisher: query failed; its features are left out of this batch`). Nothing is estimated and nothing is substituted. If every query failed, nothing was learned and no batch is sent.
* **Risk Guard refusing** (any non-2xx, including the 429 rate limit), or **unreachable**: logged, counted, and the batch is dropped. The next interval sends fresh values, not the old ones.
* **A list cut off by a size limit** (more than 2,000 sandboxes or workloads in one aggregation): the log says so; the quietest subjects are not reported, and nothing is mislabeled.
* **Credentials or SVID not readable** (Secret not yet created, SVID not yet issued): logged on every interval until they appear. The files are read each interval, so rotation and late arrival need no restart.

Counters appear in every log line that ends a tick (`counters=Counters { ticks, batches_accepted, batches_refused, batches_rate_limited, risk_guard_unreachable, ticks_without_batch, query_failures, subjects_dropped }`). They are cumulative since the container started.

## OpenSearch credentials

`scripts/siem/install_publisher_user.py` creates, idempotently:

* a role `rg_feature_publisher` with **read on `ocsf-openshell*` only** (no cluster permissions, no write, no other index, no security API),
* an internal user `rg-feature-publisher` mapped to that role only,
* the Secret `opensearch-feature-publisher` in the `siem` namespace with the keys `username` and `password`.

The password is generated by the script and goes only into the Secret and into OpenSearch's user API through stdin; it is never printed, never in the repository, never on a command line. Like `install_content.py` the script reaches OpenSearch through the Dashboards pod, so the admin password is never handled either. Run it without arguments for a dry run that changes nothing; `--apply` creates what is missing, reuses the Secret's password if there is one, and then proves the account: it can search `ocsf-openshell*`, and gets HTTP 403 for another index, for a write, and for the security API. To rotate the password: delete the Secret, run with `--apply`.

The publisher reads the Secret from the mounted files `/etc/opensearch-publisher/username` and `/password` (flags `--opensearch-user-file`, `--opensearch-password-file`).

OpenSearch's certificate in the demo is self-signed (the collector also skips verification). The manifest passes `--opensearch-insecure` for that; the hop is inside the `siem` namespace and fenced by NetworkPolicy. With a real CA, pass `--opensearch-ca` instead.

## Deployment

Nothing here is applied by merging. [deploy/aks/siem/signal-forwarder.yaml](../deploy/aks/siem/signal-forwarder.yaml) adds, to the existing forwarder pod:

* the container `feature-publisher` (same image as the forwarder, `__IMAGE__` filled by `scripts/aks/25-enable-signals.ps1` as before, same hardening: non-root, read-only root filesystem, no capabilities, resource limits),
* the Secret volume `opensearch-publisher` (`optional: true`, so the forwarder pod still starts if the Secret has not been created yet),
* an egress rule in `forwarder-egress` to OpenSearch on 9200, and a new policy `opensearch-from-publisher` that lets the forwarder pod reach OpenSearch on 9200 (`opensearch-ingress` lists only the collector and the dashboards; NetworkPolicies add up). `25-enable-signals.ps1 -Remove` deletes that policy too.

Order: run `scripts/siem/install_publisher_user.py --apply`, then `scripts/aks/25-enable-signals.ps1` (which re-applies the manifest). Risk Guard's `/features` endpoint must exist on the signals listener (the other half of this work) or every post will be refused with a 404, which the publisher logs and counts.

## Seeing it work

```bash
# every interval, one line with the counters; "batch accepted" carries Risk Guard's answer
kubectl logs -n siem deploy/signal-forwarder -c feature-publisher --tail=20

# the batch it would send right now, without sending anything (run in the pod; needs the mounted Secret)
kubectl exec -n siem deploy/signal-forwarder -c feature-publisher -- \
  openshell-risk-guard feature-publisher --dry-run \
  --opensearch-user-file=/etc/opensearch-publisher/username \
  --opensearch-password-file=/etc/opensearch-publisher/password --opensearch-insecure --trust-domain-from-svid
```

`--dry-run` runs the five queries once, prints the batch (and any query that failed) and exits; it posts nothing and needs no SVID.

Healthy looks like `batches_accepted` rising by one per interval and `query_failures` flat. A rising `batches_rate_limited` means more than one batch per 10 seconds per sender: another publisher, or `--interval` set below 10 (the command refuses that).

## What is not verified

* The five queries were run read-only against the live demo index and their real answers parsed by the publisher's own code (no shard failures; the denial count matched an independently written query exactly), but not against a production-scale index. The user script's `--apply`, the manifest and the end-to-end post were not run against the cluster. The route query reads seven days of route events whole; it refuses (and omits the two route features) beyond 30,000 distinct workload/host/route combinations.
* Risk Guard's `/features` handler was not available to test against; the integration test uses a fake mutual-TLS listener that records the verified SPIFFE ID and the body, so the contract is tested from the publisher's side only.
* `fleet_workloads_with_denials_5m` counts sandboxes (the contract's own table says "distinct sandboxes"), not workloads; a workload that ran several sandboxes counts once per sandbox.
