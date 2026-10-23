# ADR 0001: Where the security services run

**Status:** accepted and **applied** to the demo cluster. Before: [`placement-before-hardening.json`](../../conformance/placement-before-hardening.json)
(0 of 5 placement checks). After: [`placement-after-hardening.json`](../../conformance/placement-after-hardening.json) (5 of 5, and 56 of 56
permission checks). The live containment cases still passed afterwards (7 of 7).

## Context

Risk Guard, the tunnel proxy (`sandbox-egress`), the per-request proxy (`egress-proxy`) and the SPIRE server decide what sandboxes may do.
Sandboxes run untrusted agent code. Today they all share one cluster, and Risk Guard and the SPIRE server share the Kata node with the
sandboxes' supervisors and workload pods. The proxies run on the ordinary pool next to the demo workloads.

That matters for one reason: a node is a trust boundary in Kubernetes. A process that escapes onto a node can read what that node's pods
mount (Risk Guard's database volume, its TLS keys, the SPIRE server's data) and act as that node's kubelet. It cannot, by itself, read
secrets for pods scheduled elsewhere (the node authorizer limits a kubelet to its own pods' secrets).

## Decision

Offer a **hardened placement profile** ([`deploy/aks/placement-profile.json`](../../deploy/aks/placement-profile.json),
[`scripts/aks/21-harden-placement.ps1`](../../scripts/aks/21-harden-placement.ps1)):

* a node pool `security`, labelled `workload-class=security` and tainted `workload-class=security:NoSchedule`;
* Risk Guard, `sandbox-egress`, `egress-proxy` and the SPIRE server get the matching `nodeSelector` and toleration, so nothing else lands there;
* the two per-node SPIRE daemons tolerate the taint, because the proxies need the SPIRE agent's socket;
* sandboxes and demos stay on their own pools.

`scripts/conformance/placement.py` checks the result on the live cluster rather than trusting the manifests: where each service runs, that
no sandbox or demo pod shares a security node, and (separately) that the service accounts sandboxes and demos run as cannot read secrets,
change or delete the security services or their network policies, or exec into their pods. It reports before and after.

## What this does not give you

A node pool is **not a separate trust domain**. Both pools share the Kubernetes API server and its administrators; anyone who can patch
deployments or exec into pods in the namespace can still do so to Risk Guard. Nor is it hardware isolation of the kind a DPU provides.
The profile reduces what a compromised sandbox node yields. It does not remove the cluster administrator from the trust base.

The permission checks also show two honest exceptions, both belonging to the platform and not to sandboxes: the gateway's service account
can exec into pods, and the SPIRE server can update the trust-bundle ConfigMap (it publishes it). The install-time certificate job
(`openshell-certgen`) can read secrets; no sandbox or demo pod runs as it.

## Alternatives considered

| Option | Why not (here) |
|---|---|
| Separate cluster for the security services | Real separation of control plane and admins, and the right answer for production. Doubles the demo's fixed cost and the operational work; every call from the gateway then crosses clusters. Recommended as the next step, not built. |
| Separate subscription / tenant | Strongest administrative separation; out of proportion for a demonstration. |
| Dedicated node pool (chosen) | Cheap, quick, verifiable, and removes the shared-node exposure that exists today. |
| Do nothing | The demo works, but a node escape from a sandbox would land next to Risk Guard's data and the SPIRE server. Worth stating plainly in a security review. |

## Consequences

* **Cost:** one more small VM (the script defaults to `Standard_D2s_v5`; check current pricing for your region).
* **Availability:** moving Risk Guard detaches and re-attaches its disk. Risk Guard is single-writer, so there is a short outage during
  which new requests fail closed. Do it when nothing is being shown.
* **Operations:** `sandbox-egress.yaml` and `egress-proxy.yaml` pin the ordinary pool, and scripts 17 and 18 re-apply them, which moves the
  proxies back; re-run `21-harden-placement.ps1 -Apply` afterwards (it replaces the selector, and the checks will fail until you do). The taint means a new security workload must be added to the profile, or it will not schedule.
* **Verification:** run `scripts/conformance/placement.py`; it lists the failed checks, and the report records the date and cluster context.
