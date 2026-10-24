# Production-readiness gaps

For how the parts work today, see [how it works](how-it-works.md).

What stands between this demonstration and a production deployment, in the order I would close them. Each item says what is missing, why it matters, and
what is already in place. Nothing here is hidden elsewhere: this is the list.

## Must close before trusting it with real work

| # | Gap | Why it matters | What exists |
|---|---|---|---|
| 1 | **Backup and restore proven once, not scheduled** | The database holds restrictions and history; losing it forgets which workloads were locked | `backup`/`restore` with checksum; measured 2.4 s backup, 56 s restore, restriction preserved ([recovery](recovery.md)). Not scheduled; no Azure disk snapshot drill |
| 2 | **No high availability** | One writer, one pod: a restart is an 80–110 s outage during which requests fail closed | Fail-closed behaviour, tested; a Recreate rollout that never runs two writers |
| 3 | **Throughput ceiling of about 100 decisions/s** | Past about 8 concurrent callers requests are refused | Measured, fails closed, explicit thresholds; faster disk and batched commits are the planned fixes |
| 4 | **Probes and shutdown not tested under load** | Slow startup, database contention or termination under load could cause unsafe behaviour or restart loops | Separate startup, readiness (read connection) and liveness (no database) probes; no load test yet |
| 5 | **Evidence is deletable by a database administrator** | An attacker who reaches the volume can erase the record of what happened | Refusals, signals and per-minute summaries are exported as OCSF to OpenSearch (14-day retention); a short window is unexported and the SIEM is not append-only |
| 6 | **Second-person approval has no UI; policy is not signed** | Loosening needs two people by CLI/API, but break-glass exists and the Entra path is untested | Change requests, proposer ≠ approver, 24 h expiry ([two-person](two-person.md)); a promotion gate before enforce ([promotion gate](promotion-gate.md)) |

## Limits of what it can see or stop

| # | Gap | Detail |
|---|---|---|
| 7 | A compromised supervisor can stop calling Risk Guard | Per-request scoring then does not happen. The tunnel gate flags a sandbox that goes quiet (shadow by default; an attacker who keeps sending harmless requests is not caught), the network fence still limits it, but it can reach in-cluster HTTP services directly |
| 8 | The tunnel gate sees a destination, not a path | A TLS-intercepting proxy would show paths but would hold the credentials; designed, not built |
| 9 | Kubernetes administrators are out of scope | They can change anything; only the organisation can address that (RBAC, just-in-time access, audit logs) |
| 10 | Node pools are not separate trust domains | Security services run on their own nodes, but share one control plane with the sandboxes |
| 11 | No hardware-backed trust | No confidential computing, no attestation, no DPU-based enforcement; see the [design note](confidential-computing-design.md) |

| 20 | Route lists exist in two places | The deny list and approved routes are in Risk Guard baselines and could be OpenShell policy; see [the plan](plan-policy-consolidation.md) |

## Evidence and operations

| # | Gap | Detail |
|---|---|---|
| 12 | Detection evidence is small and scripted | A few hundred decisions on the author's own agents; no held-out set; scores are not probabilities |
| 13 | No clean-install proof by a second person | Install scripts and an offline checker exist; nobody else has run them end to end, and teardown was not exercised |
| 14 | No image signing or provenance attestation | SBOMs, a vulnerability gate and digest pinning exist; no admission check |
| 18 | Quarantine by CLI is outside authenticated identity | Signals arrive over mTLS with a verified SPIFFE source; an operator using the CLI on the pod is not identified |
| 19 | Red-team coverage is narrow | Catalog, fuzzer and an adaptive agent cover three fixture services; Garak has not yet produced a result (model rate limit) |
| 15 | SPIRE's own chart hardening is deferred | Privileged node daemons and unhardened server pods are documented exceptions; Pod Security Admission only warns |
| 16 | Single tenant | No tenant isolation of caches, configuration or authorisation |
| 17 | Sizing beyond one instance is a design, not a build | Sharding scoring contexts across several writers |

## The order I would take

1. Schedule backups and drill an Azure disk snapshot (a restore into a clean deployment has been shown once).
2. Raise and prove throughput (measure the real ceiling, faster disk, batched commits), with explicit overload refusals.
3. Test probes, startup and shutdown under load.
4. Export decisions to an append-only store outside the cluster, with a stated window of unexported evidence.
5. Add signed policy bundles and a UI for two-person approval; sign images and check them at admission.
6. Have a second engineer install it from a clean subscription and record what they had to ask.
