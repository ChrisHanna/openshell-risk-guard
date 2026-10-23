# Sizing and cost

What the demonstration deployment costs, how much load one Risk Guard carries, and how to size for more. Prices are Azure's public retail list
prices for Linux pay-as-you-go in East US 2, read from the Azure Retail Prices API on 2026-10-23. They change, ignore discounts and
reservations, and cover compute only.

## What runs where, and what it costs

| Node pool | Size | Count | Hourly each | Per month (730 h) | What runs there |
|---|---|---|---|---|---|
| `kata` | Standard_D4s_v5 (4 vCPU) | 1 | $0.192 | $140 | OpenShell sandboxes as Kata micro-VMs, supervisors, the gateway, the fleet |
| `security` | Standard_D2s_v5 (2 vCPU) | 1 | $0.096 | $70 | Risk Guard, both proxies, the SPIRE server |
| `nodepool1` | Standard_D2s_v5 (2 vCPU) | 2 | $0.096 | $140 | Demo workloads, SPIRE agents, the token-grant demo |
| **Compute total** | | 4 | | **about $350** | |

Not included: managed disks (a few GB), the public IP and load balancer, the container registry, Key Vault, bandwidth, and the model API.
Stopping the cluster (`az aks stop`) ends the VM charges; the disks and IP keep a small charge. `scripts/aks/99-teardown.ps1` removes everything.

The Kata node needs a VM size with nested virtualization, which is why it is the largest. The `nodepool1` pair exists for the demo
workloads and could be one node for a smaller demonstration.

## What Risk Guard itself needs

| | Measured | Configured |
|---|---|---|
| Risk Guard memory | about 20–50 MiB in use | request 128 MiB, limit 512 MiB |
| Risk Guard CPU | about 15–100 millicores during the benchmark | request 100 m, limit 500 m |
| Proxies (each) | about 16–17 MiB, under 40 m | request 50 m / 64 MiB, limit 256 MiB |
| Disk | not measured | a 2 GiB volume; 30-day decision retention by default |

The security services together fit on a single 2-vCPU node with room to spare. Throughput appears to be limited by the database's commit rate rather than CPU or memory
([benchmark](benchmark.md)); that cause is likely but was not isolated.

## How many agents one Risk Guard carries

The rated load for this size is **80 decisions/s sustained, up to about 8 concurrent callers**; past that it refuses requests rather than allow without a decision.
Every inspected request is one decision. The agent's request rate depends on how it works; an agent that calls a model between actions rarely
exceeds 1 request/s.

| Average requests per second per agent | Agents per Risk Guard at 80 decisions/s |
|---|---|
| 1 | 80 |
| 0.5 | 160 |
| 0.1 | 800 |

Instances needed = peak decisions per second ÷ 80, rounded up. These are assumptions about agent behaviour, not measurements of a
production fleet, and there is no concurrency data above 64 callers or for sandbox density on the Kata node (not measured).

## Cost per decision, in perspective

If one security node ($70/month) ran flat out at 80 decisions/s it would make about 200 million decisions a month, roughly **$0.35 per million**
in compute. Real utilisation is far lower, and the other pools dominate the bill, so this only shows the control plane is not the
expensive part: the micro-VM sandboxes are.

## Scaling beyond one instance

One instance has one SQLite writer by design, so replicas and autoscaling are not an option for it. Beyond roughly 80 decisions/s the
paths are, in order: a faster disk, batching commits (to be built and tested against the replay harness), and finally sharding scoring contexts across several
independent Risk Guards. See [production gaps](production-gaps.md).
