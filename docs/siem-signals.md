# Signals: letting a SIEM ask Risk Guard to tighten

The SIEM sees patterns across sandboxes and over time; Risk Guard decides inline. A **signal** is how the first can ask the second to act, within strict limits.
It is a small HTTP listener on its own port, separate from the operator console and from the gateway's gRPC port.

## What a signal can and cannot do

| Rule | How it is enforced | Test |
|---|---|---|
| **Tighten only.** The one action is `quarantine`. There is no way to release, loosen, clear or change a baseline. | Validation in `src/store/signals.rs`; unknown fields and any other action are refused (400) | `only_a_tightening_action_...`, `the_listener_wants_its_own_token_...` |
| **Expires.** 60 s to 3600 s; the quarantine ends by itself. | `expires_at_ms` on the quarantine row, checked at every gate | `a_signal_quarantines_for_its_time_...` |
| **Cannot override a person.** An operator's quarantine has no end and is never replaced or shortened by a signal. | `already_quarantined` outcome | `a_signal_never_overrides_...` |
| **Limited.** At most 10 applied per minute and 5 workloads held by signals at once (both settable), so a wrong or hijacked sender cannot sweep the fleet. | `rate_limited`, `too_many_active` outcomes (HTTP 429) | `limits_stop_a_flood_...` |
| **Dry run.** `--signals-dry-run` (or `"dry_run": true` per request) records and answers but quarantines nothing. | `dry_run` outcome | `a_dry_run_records_...` |
| **Idempotent.** A repeated `signal_id` is answered with the stored result, never applied twice. | `duplicate: true` | `a_repeated_signal_is_answered_...` |
| **Audited.** Every signal that passes validation is in `siem_signals` with its outcome; every applied one is also in the quarantine audit with `signal:<source>` as the operator. | `GET /v1/signals` | same tests |

Gate coverage: a quarantined workload is refused at the middleware (gate 1, reason `workload_quarantined`) and at the tunnel gate (gate 3). Tunnels already open end
within the proxy's maximum lifetime (see [architecture](architecture.md)).

## The request

```
POST /v1/signals          Authorization: Bearer <64 hex characters>
{
  "signal_id": "opensearch-<alert id>",      // unique per alert firing
  "source": "opensearch-alerting",
  "alert_id": "<alert id>",                  // optional, for the trail
  "sandbox_id": "<container.uid>",           // or "agent_id": "<workload>"; exactly one
  "action": "quarantine",
  "ttl_seconds": 600,
  "reason": "three or more Risk Guard refusals for one sandbox in five minutes"
}
```

Answers: 200 `applied` / `dry_run` / `already_quarantined`; 404 `unknown_target`; 429 `rate_limited` / `too_many_active`; 400 invalid; 401 no or wrong token.
`GET /v1/signals?limit=50` lists recent signals (same token). `GET /healthz` needs no token.

## Running it

```
openshell-risk-guard serve ... --signals-listen=0.0.0.0:50063 --signals-allow-plaintext [--signals-dry-run]
```

The token comes from `--signals-token-file` (private file) or the `RISK_GUARD_SIGNALS_TOKEN` environment variable (how a Kubernetes Secret reaches the pod). It is **not** the
operator token, and it cannot do anything the operator token can.

On the demo cluster, `scripts/aks/25-enable-signals.ps1 -Apply` creates the Secret, opens the port, fences it so only the SIEM's OpenSearch pod can reach it
(`deploy/aks/siem/signals-egress.yaml`), and creates the webhook channel and the alert in OpenSearch. It starts in **dry run**; `-Enforce` makes it act.

## Honest limits

* **Plain HTTP with a bearer token** is demonstration-grade. In-cluster it is fenced by a network policy, but a token on the wire can be replayed by anything that can see
  the traffic. The production design puts mTLS in front, with the sender identified by a SPIFFE ID (as the SVID listener already does for workloads).
* **The token sits in OpenSearch's notification settings** (readable by its administrators) and in a Kubernetes Secret.
* **A compromised SIEM can still deny service to a few workloads for up to an hour** (within the limits above). It cannot loosen anything or touch more than the cap.
* **Quarantine is blunt.** It stops the workload entirely. Finer actions (raise the risk score, tighten one route) are not offered, deliberately.
* **Detection quality is the SIEM's.** The demo alert (three refusals for one sandbox in five minutes) is a rule, not a model.
