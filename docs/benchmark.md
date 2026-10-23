# Performance of the deployed enforcement path

Raw results: [`conformance/benchmark-path.json`](../conformance/benchmark-path.json), produced by
[`scripts/conformance/bench_path.py`](../scripts/conformance/bench_path.py). Run it again to reproduce; it needs only `kubectl` access.

## What was measured

The same small request sent from pods inside the cluster, each cell a closed loop (N workers, each sending as soon as the last reply arrives) for 20 s:

| Path | What it is |
|---|---|
| `direct` | straight to the fixture API from a throwaway pod: the destination's own cost plus the network |
| `proxied` | an allowed read through the Envoy egress proxy, which authenticates the caller by its SPIFFE X.509-SVID and asks Risk Guard on every request |
| `denied` | a destructive call the policy refuses, so it never reaches the destination: the cost of the proxy plus the decision, with the fixture out of the way |

**Environment:** AKS (Kubernetes 1.36); the proxy, the load generator and the fixture on `Standard_D2s_v5` nodes (2 vCPU); Risk Guard on its own
`Standard_D2s_v5` node with a 100 m / 500 m CPU request/limit; storage class `default` (Azure managed disk); SQLite in WAL mode with
`synchronous=FULL`. Image `openshell-risk-guard:d35b248`.

## Results

| Path | Workers | Requests/s | p50 ms | p95 ms | p99 ms | Refused for no reason given¹ |
|---|---|---|---|---|---|---|
| direct | 1 | 50 | 18 | 35 | 46 | 0 |
| proxied | 1 | 39 | 19 | 35 | 215 | 3 of 777 |
| denied | 1 | 90 | 5.5 | 9.7 | 246 | 4 of 1799 |
| proxied | 4 | 69 | 24 | 249 | 343 | 8 of 1374 |
| denied | 4 | 94 | 20 | 266 | 304 | 16 of 1904 |
| proxied | 16 | 83 | 129 | 496 | 796 | 64 of 1696 (4 %) |
| denied | 16 | 97 | 88 | 399 | 427 | 32 of 1959 |
| proxied | 32 | 78 | 368 | 670 | 845 | 420 of 1586 (26 %) |
| proxied | 64 | 111 | 379 | 592 | 627 | 2116 of 2286 (93 %) |
| proxied, new connection each time | 4 | 62 | 39 | 253 | 298 | 12 of 1242 |

¹ An HTTP 403 with an empty body: the proxy's authorization call to Risk Guard timed out (its limit is 1 s) or failed, so the proxy refused
the request. These are failures to decide, which fail closed, and are different from policy denials.

## What this shows

* **Cost of the gate for one caller.** The `denied` path, which has no destination, took a median of 5.5 ms (p95 9.7 ms) at one worker. That
  is the proxy hop, mutual TLS, scoring and the decision, and it is the better figure for "what enforcement adds". The difference between
  `proxied` and `direct` at one worker is only about 1 ms, but that comparison is not a clean floor: the fixture's own time varies, and the two
  pods are on different nodes.
* **The decision rate tops out at about 100 per second.** Every decision is committed to SQLite with `synchronous=FULL`, one fsync on a managed
  disk each. The `denied` path, which does no destination work, flattens at 90–115 requests/s whatever the concurrency. Risk Guard's CPU
  stayed below about 100 m of its 500 m limit, so it is not CPU-bound. Disk commit latency fits those numbers, but **this was not isolated**
  (no direct fsync measurement was taken), so treat it as the likely cause, not a finding.
* **Past 8 concurrent callers it fails closed, visibly.** Latency climbs because requests queue for the single writer, then the proxy's 1 s
  authorization limit is hit and requests are refused. At 16 workers 4 % were refused; at 64, 93 %. No request was allowed without a
  decision. One `risk_state_unavailable` error was also seen from a separate demo workload during the heavy cells.
* **The destination limits the allowed path too.** The fixture itself tops out near 110 requests/s, so the `proxied` throughput is not a
  statement about a real destination.

## Release thresholds (for this deployment size)

These are chosen from the data above, not from a requirement, and apply to one Risk Guard on the node above:

| Threshold | Value | Why |
|---|---|---|
| Gate cost, one caller (`denied` p50) | ≤ 10 ms | measured 5.5 ms; leaves headroom without being meaningless |
| End-to-end p99 at ≤ 4 workers | ≤ 500 ms | measured 304–343 ms; the supervisor's own budget for Risk Guard is 500 ms |
| Refusals with no reason at ≤ 4 workers | ≤ 1 % | measured 0.4–0.8 % |
| Supported load | ≤ 8 concurrent callers, ≤ 80 decisions/s sustained | where the numbers stay inside the above |
| Behaviour past that | refuse, never allow | observed |

A build that regresses a measured figure by more than 25 % at the same load should not be released without an explanation.

## What is not measured, and limits

* **The supervisor path** that OpenShell sandboxes use (gRPC middleware) is not in this benchmark. Risk Guard records its own processing time for
  that path (console, "decision latency", with a 500 ms timeout); read it there.
* **Quarantine delay** is measured separately: an open tunnel survives at most 120 s (81–112 s observed). See [architecture](architecture.md).
* **Detection quality** (false denials and misses) is not repeated here. It is in [detection results](detection-results.md), which keeps the
  scripted-live runs and the synthetic red-team tests apart. There is no independently held-out set, and no coverage percentage is claimed.
* All requests are routine allowed reads or one refused call from a single identity. This measures cost, not detection.
* The load generator is Python threads in one small pod (25 m CPU request), the fixture is a small Python server, and the nodes have two vCPUs.
  Per-pod CPU came from `kubectl top`, which lags by tens of seconds, so it was read as "no sample above about 100 m", not per cell.
* One run of 20 s per cell: no confidence intervals. Tail figures (p99) from about 1000–2500 requests are rough.
* A larger disk class, a larger node, or relaxing `synchronous=FULL` could move the ceiling. None was tried, and relaxing it would trade away
  the durability of restrictions across a crash, which is why it is on.
