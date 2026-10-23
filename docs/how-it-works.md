# How it works, end to end

This is the technical detail behind [the story](the-story.md), which explains why the parts exist and where they live in the repository.

One page that ties the parts together. Each section names the page with the detail. What is measured and what is only designed is stated in each place; the limits are collected at the end.

## 1. The decision path

An agent in an OpenShell sandbox makes a call. Risk Guard can only narrow OpenShell's answer: `FinalAllow = OpenShellAllow ∧ RiskPermit`.

| Gate | Where | What it sees | Detail |
|---|---|---|---|
| 1 | OpenShell supervisor middleware (gRPC), before credentials are injected | Method, host, path, workload, run | [architecture](architecture.md) |
| 3 | Envoy `ext_authz` on the tunnel (egress) | Destination host and port, sandbox | [architecture](architecture.md) |

Both gates fail closed: if Risk Guard cannot answer, the call is refused. Both also refuse a **quarantined** workload (`workload_quarantined`). The scorer is deterministic: rules and weights over the normalised request, a per-workload baseline, and a restriction that latches across sandboxes of the same workload. The score and the signals behind it are stored with every decision ([design](design.md), [anomaly detection](anomaly-detection.md)).

## 2. State

One SQLite database, one writer (WAL, `synchronous=FULL`), a separate read connection for probes and the console. It holds baselines, decisions, restrictions, the quarantine list and its audit, SIEM signals received, and change requests. Probes: startup (readiness command, 150 s), readiness (read connection), liveness (no database). Backup is `VACUUM INTO` from a read-only connection with a SHA-256 sidecar; restore keeps `<db>.before-restore`. Measured on the demo cluster: 2.4 s backup, 56 s restore, restriction preserved. See [recovery](recovery.md).

## 3. Identity

Agents are workloads (`openshell.nvidia.com/agent-id`), bound to a principal by `RISK_GUARD_AGENT_BINDING_PRINCIPALS` (kept in the deployment state as `agentBindingPrincipal`; losing it makes agent sandboxes refuse). Sandboxes can carry SPIFFE identities from SPIRE ([workload identity](workload-identity.md)). Services talk to each other over mTLS.

## 4. What Risk Guard tells the SIEM

Risk Guard emits OCSF events over OTLP/HTTP to the collector (`--ocsf-otlp-endpoint`):

- Detection Finding (2004): each refusal at either gate.
- API Activity (6003): each signal received.
- Per-minute **summaries** per workload (`gate: summary | route | egress`): allowed and refused counts, refusal ratio, max score, distinct routes, with the agent id, display name (`agent-rename`), SPIFFE id and task profile. Counted in memory (about 69 ns per decision).

OpenSearch needs one JSON type per key across all event kinds, so the summary fields are named `allowed_calls`, `refused_calls`, `total`, and so on; a test (`a_key_has_the_same_type_in_every_kind_of_event`) holds that. Events are rolled over by an ISM policy and kept 14 days. OpenShell's own events arrive through the same collector. See [SIEM guide](siem-guide.md) and [SIEM integration](siem-integration.md).

**Dashboards** (installed by `scripts/siem/install_content.py`, verified by `check_dashboards.py`): Fleet, One agent, Incidents, Control health, Sandbox activity and egress, Workloads, and a model-training view on synthetic data.

## 5. The SIEM talks back (signals)

OpenSearch can ask Risk Guard to tighten, never loosen.

```
OpenSearch alert (query monitor, throttled 10 min)
  -> webhook (bearer token, inside the siem namespace, NetworkPolicy)
  -> signal-forwarder pod (its own SPIFFE SVID)
  -> Risk Guard signals listener (mTLS, SPIFFE allow-list)
```

The only action is `quarantine` with a ttl of 60–3600 s. Limits: 10 per minute, at most 5 active, idempotent by `signal_id`, a **dry-run** mode, and the source is overwritten with the verified SPIFFE ID. Every signal is stored (`siem_signals`, `workload_quarantine`). Direct OpenSearch-to-Risk-Guard traffic is blocked. Current deployment: dry-run. See [SIEM signals](siem-signals.md).

## 6. People changing the rules

Loosening needs two people. Release of a quarantine, clearing a restriction, or turning the rule off is a **change request**: proposed by one operator, approved by a different one, expiring after 24 hours. A `--break-glass` path exists and is labelled in the record. CLI and `/api/changes`; there is no UI. See [two-person approval](two-person.md).

## 7. Shadow to enforce

`scripts/promotion_gate.py` reads evidence from the SIEM against `deploy/aks/promotion-policy.json` and answers PROMOTE or HOLD. `scripts/aks/18-enable-sandbox-egress.ps1 -RestrictionMode enforce` refuses on HOLD unless `-OverrideGate "reason (20+ characters)"` is given, and the override is recorded. **Today the answer is HOLD**: thin traffic, four unreviewed would-refuse decisions (the agents' own calls to the hosted model), 14 middleware failures, no recent backup. See [promotion gate](promotion-gate.md).

## 8. Attacking it, and keeping the results

- **Catalog** (24 attacks) and **fuzzer** (387 mutations of the must-refuse calls: case, encoding, dots, slashes, separators, look-alikes, host and method spelling). Result: 239 judged and refused, 148 refused because the path could not be read, none through. Both run in CI (`red_team_gate`, `red_team_fuzz`); a gap must be fixed or written into `fuzz-known.json` with a reason.
- **Adaptive attacker**: a governed agent (workload `red-team-agent`) that tries spellings against the three fixture services and records every call. A destructive call answered 2xx becomes an entry in `discovered.json`, expected to be refused, so the build fails until it is. Cluster run: 17 requests, none through (OpenShell's L7 layer also refused lower-case methods and dropped some encoded paths).
- **Garak** is a tool of that agent (allow-listed small DAN probes). It tests the model, not Risk Guard. The run produced no result: the hosted model answered 429.

See [red team](red-team.md) and [red-team agent](red-team-agent.md).

## 9. Models and anomaly detection

Synthetic traces (`scripts/ml`) compare a per-agent envelope, Isolation Forest and OpenSearch anomaly detection per agent. The real-data path (`summaries.py`) needs at least 120 active minutes per workload, which the demo does not have yet. See [ML training](ml-training.md).

## 10. Deploying it

Scripts `01`–`26` in `scripts/aks/` build the cluster (Kata pool, Cilium, SPIRE), OpenShell, Risk Guard (`04`), the SIEM (`22`–`24`), signals (`25`) and backup (`26`). `deploy/aks/risk-guard.yaml` carries `__PLACEHOLDERS__` that `04` fills; `scripts/check-risk-guard-deployment.py` fails if one is lost. See [AKS](aks.md), [hardening](hardening.md).

## What it does not do yet

See [production gaps](production-gaps.md) for the full list. The ones most relevant to this page:

- The model-call would-refuse decisions and thin traffic keep the promotion gate at HOLD; nothing has been enforced broadly.
- The signals path is in dry-run; it has been shown end to end, not run in anger.
- Two-person approval has no UI and its Entra path is untested; quarantine and release by CLI sit outside authenticated identity.
- Scheduled backups and an Azure disk snapshot are not built.
- Garak has not produced a result; the exercise covers three fixture services only.
- The webhook hop into the forwarder is a shared token inside the SIEM namespace.
- The demo SIEM is public and costs about $0.19/h; remove it with `22-deploy-siem.ps1 -Remove` and `24-expose-siem.ps1 -Remove`.
