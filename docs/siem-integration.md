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

## Reference SIEM for the demo (prepared, not yet deployed)

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
is rejected), and the network policies match the rendered pod labels. Not yet run on the cluster.

## What this does not claim

No commercial SIEM has been tested. The statement is: the OCSF output of a real sandbox contains Risk Guard's refusals, verified on this cluster.
