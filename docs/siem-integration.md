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

Because OpenShell's own middleware event normalises a middleware finding to a generic title (`risk-guard.finding`) without the numerical risk score, signal breakdown, or durable workload ID, **Risk Guard also emits its own enriched OCSF events (`src/ocsf.rs`)** directly to the same OTLP collector (`--ocsf-otlp-endpoint`), described in [Risk Guard's own events](#risk-guards-own-events) below.

## Reference SIEM deployment (`deploy/aks/siem/`)

`deploy/aks/siem/` and scripts `22-deploy-siem.ps1` and `23-enable-ocsf-export.ps1` deploy the reference pipeline: the OpenShell gateway, sandbox supervisors, and Risk Guard send OCSF over OTLP to an OpenTelemetry Collector, which writes structured documents to OpenSearch, viewed in OpenSearch Dashboards. Placement and controls:

* Dedicated `siem` namespace and tainted node pool, isolated from Risk Guard and sandbox pods; default-deny NetworkPolicies;
* The collector accepts OTLP only from the OpenShell gateway, supervisor pods, and Risk Guard; agent containers cannot reach it directly;
* Events contain untrusted request metadata (URLs, paths), so Dashboards access is authenticated and rate-limited;
* The OpenSearch admin password is generated into a Kubernetes Secret by the deployment script and never printed or committed;
* **Demo posture:** single-node OpenSearch in the same cluster. A production deployment should ship OTLP to an external, append-only SIEM cluster or managed service.

### Verified end to end (real events)

With OTLP export enabled (`23-enable-ocsf-export.ps1 -Apply`), refused calls arrive in the `ocsf-openshell` index within seconds across OCSF classes (Device Config State Change, Authentication, Network Activity, SSH Activity, HTTP Activity, Detection Finding). Sample records from [`evidence/ocsf-in-opensearch-sample.jsonl`](evidence/ocsf-in-opensearch-sample.jsonl):

| Time (UTC) | OCSF class | What it says |
|---|---|---|
| 07:07:55 | HTTP Activity, `firewall_rule.type: l7`, Allowed | `DELETE /customers/1` passed OpenShell's own policy |
| 07:07:55 | HTTP Activity, `firewall_rule.type: middleware`, **Denied**, Medium | `status_detail: middleware_denied:risk-guard:behavioral_risk_restricted` |
| 07:07:55 | Detection Finding, **High** | "External middleware finding" for the same sandbox |

Events from all sandboxes arrive in the same index, enabling fleet-wide correlation across both OpenShell and Risk Guard.

### Optional HTTPS ingress (`24-expose-siem.ps1`)

For external review, OpenSearch Dashboards can be published over HTTPS: nginx terminating TLS with a Let's Encrypt certificate (the same pattern as the Risk Guard console),
a rate-limited sign-in (six attempts a minute per address after a small burst), and two accounts. The hostname is not recorded in this repository.

| Account | What it can do | Checked from outside |
|---|---|---|
| `admin` | everything | logs in |
| `viewer` (read-only reviewer) | read the `ocsf-*` indices and use Discover and dashboards | logs in; reading works; writing an index, reading the security API and listing other indices are refused; a wrong password gets 401 |

Both passwords are generated into Secrets and never printed or committed. To tear down the public endpoint after a review session, run `scripts/aks/24-expose-siem.ps1 -Remove` (or `scripts/aks/22-deploy-siem.ps1 -Remove` to remove the SIEM namespace).

## Scope

No commercial third-party SIEM product has been tested directly against this cluster; the verification confirms that OpenShell and Risk Guard OCSF 1.8 streams are ingested, indexed, and correlated end to end over standard OTLP/HTTP.

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
* **Per route and per destination.** The same minute also produces one row per route a workload called (`gate: route`: host, method, route template, `allowed_calls`, `refused_calls`, `max_score`) and one row per
  destination it opened tunnels to (`gate: egress`: destination, `allowed_calls`, `refused_calls`, `shadow_calls`, where shadow means "would be refused in enforce mode"). Routes and destinations are capped at 64
  per workload per minute; the rest are counted together as `other`. These give a per-agent view of what it calls and where it connects, which OpenShell's own events cannot (they know the sandbox, not the agent).
* Events carry `actor.user.full_name`, the name an operator gave the agent (`agent-rename`); `actor.user.name` stays the agent_id that decisions are keyed on.
* **One field name, one type.** OpenSearch fixes a field's type on first sight. The first version of the summary reused `refused` (a flag on tunnel events) as a count, and the collector dropped
  every summary. A unit test now fails if any key has different JSON types across the event kinds.
* Individual allowed requests are not sent; OpenShell already records them and they would drown the rest.
* Sending never slows a decision: events go through a bounded queue to a background task; when the queue is full or the collector is down they are dropped and counted.
* Operator actions taken with the command line (quarantine, release, clear) run in a separate process and are **not** sent; they are in the quarantine audit table.
* The events follow OCSF 1.8's shape but are **not validated against the schema**.
* Enable on the demo cluster with `scripts/aks/25-enable-signals.ps1` (it turns on the export and the signals listener together).
