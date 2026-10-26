# How it works, end to end

This is the technical detail behind [the story](the-story.md), which explains why the parts exist and where they live in the repository.

One page that ties the parts together. Each section names the page with the detail. What is measured and what is only designed is stated in each place; the limits are collected at the end.

The console's **Controls** page lists every control with its mode (enforcing, watching, off), what it did in the last 24 hours and whether it has the data it needs; see [who blocks, who recommends](who-does-what.md).

## 1. The decision path

An agent in an OpenShell sandbox makes a call. Risk Guard can only narrow OpenShell's answer: `FinalAllow = OpenShellAllow ∧ RiskPermit`.

| Gate | Where | What it sees | Detail |
|---|---|---|---|
| 1 | OpenShell supervisor middleware (gRPC), before credentials are injected | Method, host, path, workload, run | [architecture](architecture.md) |
| 3 | Envoy `ext_authz` on the tunnel (egress) | Destination host and port, sandbox | [architecture](architecture.md) |

When Risk Guard evaluates a request, it can only narrow OpenShell's answer (`FinalAllow = OpenShellAllow ∧ RiskPermit`), refusing calls that cross the workload's risk threshold or hit a latched lock or quarantine (`workload_quarantined`). Because **OpenShell (System 1) is deny-by-default**—meaning any request that reaches Risk Guard has already passed OpenShell's static Landlock, host, and L7 route rules—if Risk Guard's store or admission queue cannot answer in time (`eval_timeout`), `evaluate_http_request` returns a degraded allow (`degraded_fail_open_openshell_permitted`) and records the event in OCSF telemetry so legitimate work permitted by OpenShell continues without interruption. The scorer is deterministic: rules and weights over the normalised request, a per-workload baseline, and a restriction that latches across sandboxes of the same workload. The score and the signals behind it are stored with every decision ([design](design.md), [anomaly detection](anomaly-detection.md)).

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

**Following one call across both layers.** The supervisor does create a per-call id (`request_id`, a UUID) and sends it to Risk Guard, which stores it with every decision and logs it on refusals (`finding_info.uid`). But the supervisor does not write it into its own OCSF events (their `metadata.uid` is a different, random id; checked in the pinned OpenShell source and in the stored events), so OpenSearch has nothing exact to join on. Until OpenShell logs it, a call is found in both layers by the sandbox (`container.uid`), method, host and path within a few seconds. Risk Guard's refusal events carry those fields in OpenShell's own shape (`http_request`, `dst_endpoint`) beside its own request id (`finding_info.uid`), and the "One call, both layers" search on the Agent activity dashboard shows both. The new fields appear once the image with this change is deployed; older events lack them.

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

**Watch-only monitors.** Besides the signal monitor, three monitors have no action, so they only raise an alert in OpenSearch Alerting for a person to read: an agent's refusal ratio jumps (half or more of 10+ calls in 5 minutes), an agent reaches a destination it had not used in the last day, and a sandbox that was making calls goes quiet for 10 minutes. Installed by `scripts/siem/install_content.py` (or `--watch`) and checked with a dry run. The quiet-sandbox monitor also fires when a sandbox simply finishes.

## 6. People changing the rules

Loosening needs two people. Release of a quarantine, clearing a restriction, or turning the rule off is a **change request**: proposed by one operator, approved by a different one, expiring after 24 hours. A `--break-glass` path exists and is labelled in the record. The console's **Approvals** page lists what is waiting, lets an Entra administrator approve or reject, and shows **suggested baseline changes** computed from Risk Guard's own history (steady, never-refused reads), which can be proposed from the page. A baseline change always needs a second person, can only add reads, hosts or lower limits, and is stored as a new baseline version with both names on it. See [two-person approval](two-person.md).

**Baseline suggestions from history.** `scripts/siem/suggest_baselines.py` reads a week of route and tunnel summaries and, per task profile, proposes steady, never-refused GET/HEAD routes and egress hosts missing from the baseline, and rate limits far above what was observed. It never proposes a destructive method, anything refused even once, or a higher limit. It writes a proposed baseline with a blank `approved_by`, which `baseline-import` rejects, so a person must read the evidence, sign it and import it. On the current data it proposes no additions (the baselines already cover what is steady) and flags only the demo profile's rate limit as loose.

## 7. Shadow to enforce

`scripts/promotion_gate.py` reads evidence from the SIEM against `deploy/aks/promotion-policy.json` and answers PROMOTE or HOLD. `scripts/aks/18-enable-sandbox-egress.ps1 -RestrictionMode enforce` refuses on HOLD unless `-OverrideGate "reason (20+ characters)"` is given, and the override is recorded. **Today the answer is HOLD**: thin traffic, four unreviewed would-refuse groups (agents whose workloads hold a latched restriction, so enforcement would cut even their calls to the hosted model; the model host itself is approved), 14 middleware failures, no recent backup. See [promotion gate](promotion-gate.md).

## 8. Attacking it, and keeping the results

- **Catalog** (24 attacks) and **fuzzer** (387 mutations of the must-refuse calls: case, encoding, dots, slashes, separators, look-alikes, host and method spelling). Result: 239 judged and refused, 148 refused because the path could not be read, none through. Both run in CI (`red_team_gate`, `red_team_fuzz`); a gap must be fixed or written into `fuzz-known.json` with a reason.
- **Adaptive attacker**: a governed agent (workload `red-team-agent`) that tries spellings against the three fixture services and records every call. A destructive call answered 2xx becomes an entry in `discovered.json`, expected to be refused, so the build fails until it is. Cluster run: 17 requests, none through (OpenShell's L7 layer also refused lower-case methods and dropped some encoded paths).
- **Garak** is a tool of that agent (allow-listed small DAN probes). It tests the model, not Risk Guard. The run produced no result: the hosted model answered 429.

See [red team](red-team.md) and [red-team agent](red-team-agent.md).

## 9. Models and anomaly detection

Synthetic traces (`scripts/ml`) compare a per-agent envelope, Isolation Forest and OpenSearch anomaly detection per agent. The real-data path (`summaries.py`) needs at least 120 active minutes per workload. Two workloads (the repo-review demo pair) have that now and train on real summaries, flagging about 1 in 128 held-out minutes; the sporadic fleet agents have 10–22 minutes each and need longer runs. See [ML training](ml-training.md).

## 10. Deploying it

Scripts `01`–`26` in `scripts/aks/` build the cluster (Kata pool, Cilium, SPIRE), OpenShell, Risk Guard (`04`), the SIEM (`22`–`24`), signals (`25`) and backup (`26`). `deploy/aks/risk-guard.yaml` carries `__PLACEHOLDERS__` that `04` fills; `scripts/check-risk-guard-deployment.py` fails if one is lost. See [AKS](aks.md), [hardening](hardening.md).

## What it does not do yet

See [production gaps](production-gaps.md) for the full list. The ones most relevant to this page:

- The model-call would-refuse decisions and thin traffic keep the promotion gate at HOLD; nothing has been enforced broadly.
- The signals path is in dry-run; it has been shown end to end, not run in anger.
- Two-person approval has an Approvals page, but a completed approval by two real accounts has not been shown, and its Entra path is untested; quarantine and release by CLI sit outside authenticated identity.
- Scheduled backups and an Azure disk snapshot are not built.
- Garak has not produced a result; the exercise covers three fixture services only.
- The webhook hop into the forwarder is a shared token inside the SIEM namespace.
- The demo SIEM is public and costs about $0.19/h; remove it with `22-deploy-siem.ps1 -Remove` and `24-expose-siem.ps1 -Remove`.
