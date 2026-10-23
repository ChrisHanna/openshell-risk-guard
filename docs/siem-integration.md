# Integrating with a SIEM or security platform

Risk Guard does not ship its own security-event format. OpenShell already exports its security events in **OCSF** (the Open Cybersecurity Schema
Framework), and Risk Guard's decisions flow through that same pipeline. A vendor integrates with OpenShell once and sees Risk Guard's decisions
with everything else. This page records what was verified on the running cluster, what is not yet covered, and what is next.

## What OpenShell offers (from its own documentation)

| Signal | Where it goes |
|---|---|
| OCSF events | the gateway console and `openshell logs`; JSONL files; OTLP logs to a collector |
| Traces | an OTLP collector |
| Metrics | a Prometheus scrape of the gateway |

OpenShell's documentation names Splunk, CrowdStrike and AWS Security Lake as targets for the JSON export and describes a schema-version setting for older
SIEMs. None of those products was tested here.

Turning the JSON export on (reversible, takes effect within about ten seconds, no restart):

```bash
openshell settings set --global --key ocsf_json_enabled --value true --yes
```

## What a SIEM sees today for a Risk Guard decision (verified)

From a real sandbox on the cluster, one refused call (`DELETE /customers/1`) produced these records
([`evidence/ocsf-risk-guard-sample.jsonl`](evidence/ocsf-risk-guard-sample.jsonl)):

| OCSF class | What it says |
|---|---|
| HTTP Activity (4002), `firewall_rule.type: l7` | OpenShell's own policy allowed the request |
| HTTP Activity (4002), `firewall_rule.type: middleware`, action **Denied**, disposition Blocked | Risk Guard refused it; `status_detail` is `middleware_denied:risk-guard:<reason code>` |
| Detection Finding (2004), severity **High** | "External middleware finding" for the `risk-guard` middleware |

Allowed requests are recorded too (an HTTP Activity "MIDDLEWARE risk-guard decision=Allow"). Failure is visible as well: when a required middleware
fails, OpenShell writes a High Detection Finding "Required supervisor middleware failed closed" (seen on the cluster during a sandbox start).

Each record carries the sandbox name and ID, the URL, the method, and the OpenShell product version.

## What a SIEM does not get today

* **Our detail.** OpenShell normalises a middleware finding to a generic type and title (`risk-guard.finding`). The score, threshold, workload and
  restriction tier we put in the finding are not in the OCSF record. The reason code survives only in the HTTP Activity's `status_detail`.
* **Anything that does not go through OpenShell's middleware:** tunnel-gate refusals, operator quarantines and releases, restriction clearances, and
  silent-supervisor flags exist only in Risk Guard (`supervisor-silence-list`, the quarantine audit table, the console).
* **Workload identity.** The record names the sandbox, not the durable workload it belongs to.

## What is next

1. Emit our own OCSF events for those Risk Guard-only actions, as Detection Findings and API Activity, using OpenShell's OCSF builders if the crate can be
   depended on (not yet confirmed), with the workload and sandbox IDs so a SIEM can join them to OpenShell's records.
2. Send OTLP to a collector and fan out to open-source consumers to show more than one tool reading the same stream.
3. A short guide for vendors in both directions: *consume* the OCSF and OTLP output, and *extend* OpenShell by implementing the middleware or interceptor
   contract (Risk Guard is the worked example).

## Reference SIEM for the demo (deployed and receiving real events)

`deploy/aks/siem/` and scripts `22-deploy-siem.ps1` and `23-enable-ocsf-export.ps1` build a demonstration pipeline: the gateway and supervisors send OCSF as OTLP to
an OpenTelemetry Collector, which writes documents to a single-node OpenSearch, viewed in OpenSearch Dashboards. Placement and controls:

* its own namespace and a tainted node pool, away from Risk Guard and the sandboxes; default-deny network policies; Dashboards reachable only by port-forward;
* the collector accepts OTLP only from the OpenShell gateway and supervisor pods. A compromised supervisor could still send forged events, so a rule that decides
  something must treat supervisor-origin records as untrusted; the agent pods cannot reach it at all;
* events contain attacker-influenced text (URLs, paths), so Dashboards must stay patched and its access restricted;
* the OpenSearch admin password is generated into a Secret by the script and is never printed or committed;
* **demo only:** a cluster administrator can delete it, so it is not the tamper-resistant audit store a production deployment needs (that is a separate cluster,
  subscription or managed service). It uses a self-signed certificate and one node.

Validated offline: the Helm values render against the real charts, the collector configuration passes `otelcol-contrib validate` (and a deliberately bad value
is rejected), and the network policies match the rendered pod labels.

Deployed and checked on the cluster: the three pods run on the dedicated node, OpenSearch reports green, and three synthetic OCSF-shaped records sent to the collector from a
short-lived test pod arrived in the `ocsf-openshell` index as parsed documents (then deleted). Problems found and fixed on the way: the chart's root init container
conflicted with running as non-root (disabled; the volume is writable through `fsGroup`), and Dashboards' default CPU limit was below its request.
Still to do: index settings (a single node cannot hold a replica, so the index shows yellow; `time` is stored as a number, not a date), and switching the gateway export on
(`23-enable-ocsf-export.ps1`).

### Verified end to end (real events)

After `23-enable-ocsf-export.ps1 -Apply` (the gateway restarted in about a minute and logged that OTLP export was enabled) and a new sandbox, a refused call arrived in
the `ocsf-openshell` index within seconds. Within minutes the index held 63 documents across OCSF classes (Device Config State Change, Authentication, Network Activity, SSH
Activity, HTTP Activity, Detection Finding). The ones for the refusal, from [`evidence/ocsf-in-opensearch-sample.jsonl`](evidence/ocsf-in-opensearch-sample.jsonl):

| Time (UTC) | OCSF class | What it says |
|---|---|---|
| 07:07:55 | HTTP Activity, `firewall_rule.type: l7`, Allowed | `DELETE /customers/1` passed OpenShell's own policy |
| 07:07:55 | HTTP Activity, `firewall_rule.type: middleware`, **Denied**, Medium | `status_detail: middleware_denied:risk-guard:behavioral_risk_restricted` |
| 07:07:55 | Detection Finding, **High** | "External middleware finding" for the same sandbox |

Events from other sandboxes (for example a fleet agent's `POST /v1/chat/completions`) arrive in the same index, so one query covers the whole fleet.

Known rough edges, to fix next: the single-node index shows yellow (no replica is possible), `time` and `class_uid` are stored as floating-point numbers (parsed from JSON) rather than as a date
and integers, and the field `status_detail` is analysed as text, so exact-match queries need its `.keyword` form. These matter before a Security Analytics rule is written on top.

### Public access for the demo (`24-expose-siem.ps1`)

For the interview the Dashboards can be published on the internet: nginx terminating HTTPS with a Let's Encrypt certificate (the same pattern as the Risk Guard console),
a rate-limited sign-in (six attempts a minute per address after a small burst), and two accounts. The hostname is not recorded in this repository.

| Account | What it can do | Checked from outside |
|---|---|---|
| `admin` | everything | logs in |
| `viewer` (for interviewers) | read the `ocsf-*` indices and use Discover and dashboards | logs in; reading works; writing an index, reading the security API and listing other indices are refused; a wrong password gets 401 |

Both passwords are generated into Secrets and never printed or committed. **This is a deliberate demo exposure, accepted by the owner of this subscription:**

* The address is public from the moment the certificate is issued (certificate-transparency logs advertise it). Internet scanners probed it within a minute, and every probe was
  answered with 401, which is the only protection besides the passwords and the rate limit.
* The data includes sandbox names, URLs and resource names from the demo agents.
* There is no second factor and no source-address restriction. Do not leave it up after the demo: `scripts/aks/24-expose-siem.ps1 -Remove` takes the address down,
  and `scripts/aks/22-deploy-siem.ps1 -Remove` deletes the whole SIEM.

Two problems found and fixed while enabling it: a helper that sent request bodies to OpenSearch through a PowerShell pipe silently failed (the script now stops if the read-only account does
not exist, before anything is made public), and OpenSearch refused the OCSF `time` as a date because JSON numbers arrive as floating point (the collector now converts `time` and the id
fields to integers, and an index template maps `time` as a date and sets no replica).

## What this does not claim

No commercial SIEM has been tested. The statement is: the OCSF output of a real sandbox contains Risk Guard's refusals, verified on this cluster.

## Risk Guard's own events

OpenShell reduces what a middleware says to a generic `risk-guard` finding: the score, the threshold and the workload do not survive. So Risk Guard sends its own OCSF events
(`src/ocsf.rs`) to the same collector, over OTLP/HTTP (`--ocsf-otlp-endpoint`), into the same index. They carry:

| Field | Meaning |
|---|---|
| `class_uid` 2004 (Detection Finding) | A refusal at the supervisor middleware, a tunnel refusal, a "would refuse in enforce mode" note, or a silent supervisor |
| `class_uid` 6003 (API Activity) | A signal received from a SIEM, with its outcome |
| `actor.user.name` | The workload (agent) |
| `actor.user.uid` | The sandbox's SPIFFE ID, when a trust domain is configured (otherwise null) |
| `actor.session.uid` | The run |
| `risk_score`, `unmapped.risk_guard.threshold` | The score and the line it crossed |
| `unmapped.risk_guard.reason_code`, `.signals[]` | Why, and which signals contributed |
| `unmapped.risk_guard.task_profile` | The task the workload was approved for |
| `unmapped.risk_guard.gate` | `middleware`, `tunnel` or `signal` |
| `container.uid` | The sandbox |
| `status_detail` | `risk_guard_denied:<reason>`, `risk_guard_tunnel:<kind>` or `risk_guard_signal:<outcome>` |

* **Activity summaries.** Once a minute, for each workload that did anything, Risk Guard sends one event (`unmapped.risk_guard.gate: summary`) with every decision counted: `total`,
  `allowed_calls`, `refused_calls`, `refusal_ratio`, `max_score`, `distinct_paths`, over `window_seconds`. This is the per-workload denominator and the feature source for per-agent anomaly
  detection and model training. Counting costs about 70 ns per decision (in memory, no I/O); a workload that does nothing sends nothing, so a missing summary is itself a signal. Paths are
  counted up to 512 per workload per minute, then the count saturates.
* **One field name, one type.** OpenSearch fixes a field's type on first sight. The first version of the summary reused `refused` (a flag on tunnel events) as a count, and the collector dropped
  every summary. A unit test now fails if any key has different JSON types across the event kinds.
* Individual allowed requests are not sent; OpenShell already records them and they would drown the rest.
* Sending never slows a decision: events go through a bounded queue to a background task; when the queue is full or the collector is down they are dropped and counted.
* Operator actions taken with the command line (quarantine, release, clear) run in a separate process and are **not** sent; they are in the quarantine audit table.
* The events follow OCSF 1.8's shape but are **not validated against the schema**.
* Enable on the demo cluster with `scripts/aks/25-enable-signals.ps1` (it turns on the export and the signals listener together).
