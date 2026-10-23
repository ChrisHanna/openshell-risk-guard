# Production-readiness gaps

What stands between this demonstration and a production deployment, in the order I would close them. Each item says what is missing, why it matters, and
what is already in place. Nothing here is hidden elsewhere: this is the list.

## Must close before trusting it with real work

| # | Gap | Why it matters | What exists |
|---|---|---|---|
| 1 | **No proven backup and restore** | The database holds restrictions and history; losing it forgets which workloads were locked | Retention and WAL durability; the upgrade drill showed state surviving a redeploy, not a restore |
| 2 | **No high availability** | One writer, one pod: a restart is an 80–110 s outage during which requests fail closed | Fail-closed behaviour, tested; a Recreate rollout that never runs two writers |
| 3 | **Throughput ceiling of about 100 decisions/s** | Past about 8 concurrent callers requests are refused | Measured, fails closed, explicit thresholds; faster disk and batched commits are the planned fixes |
| 4 | **Probes and shutdown not tested under load** | Slow startup, database contention or termination under load could cause unsafe behaviour or restart loops | TLS-aware health checks and readiness; no dedicated test yet |
| 5 | **Evidence is deletable by a database administrator** | An attacker who reaches the volume can erase the record of what happened | An audit table for quarantine and clearances; no external, append-only export |
| 6 | **No second-person approval or signed policy** | One operator can loosen a baseline or switch a rule from enforce to shadow | Revisioned guardrails, an audited quarantine, Entra-gated `/admin` |

## Limits of what it can see or stop

| # | Gap | Detail |
|---|---|---|
| 7 | A compromised supervisor can stop calling Risk Guard | Per-request scoring then does not happen. The tunnel gate and network fence still limit it, but it can reach in-cluster HTTP services directly |
| 8 | The tunnel gate sees a destination, not a path | A TLS-intercepting proxy would show paths but would hold the credentials; designed, not built |
| 9 | Kubernetes administrators are out of scope | They can change anything; only the organisation can address that (RBAC, just-in-time access, audit logs) |
| 10 | Node pools are not separate trust domains | Security services run on their own nodes, but share one control plane with the sandboxes |
| 11 | No hardware-backed trust | No confidential computing, no attestation, no DPU-based enforcement; see the [design note](confidential-computing-design.md) |

## Evidence and operations

| # | Gap | Detail |
|---|---|---|
| 12 | Detection evidence is small and scripted | A few hundred decisions on the author's own agents; no held-out set; scores are not probabilities |
| 13 | No clean-install proof by a second person | Install scripts and an offline checker exist; nobody else has run them end to end, and teardown was not exercised |
| 14 | No image signing or provenance attestation | SBOMs, a vulnerability gate and digest pinning exist |
| 15 | SPIRE's own chart hardening is deferred | Privileged node daemons and unhardened server pods are documented exceptions; Pod Security Admission only warns |
| 16 | Single tenant | No tenant isolation of caches, configuration or authorisation |
| 17 | Sizing beyond one instance is a design, not a build | Sharding scoring contexts across several writers |

## The order I would take

1. Prove backup and restore (a restricted workload stays restricted after restoring into a clean deployment).
2. Raise and prove throughput (measure the real ceiling, faster disk, batched commits), with explicit overload refusals.
3. Test probes, startup and shutdown under load.
4. Export decisions to an append-only store outside the cluster, with a stated window of unexported evidence.
5. Add signed policy bundles and a two-person rule for loosening changes.
6. Have a second engineer install it from a clean subscription and record what they had to ask.
