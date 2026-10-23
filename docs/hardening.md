# Kubernetes hardening baseline

Every container (init containers included) and every pod in the `openshell` namespace is held to the same checks, taken from the Pod
Security **Restricted** standard plus a few of our own. Restricted is a useful baseline, not a substitute for reviewing each component.

| Check | Meaning |
|---|---|
| `non_root` | runs as a non-root user |
| `no_privilege_escalation` | `allowPrivilegeEscalation: false` |
| `drop_all_capabilities` | drops `ALL` |
| `seccomp` | `RuntimeDefault` or `Localhost`, pod- or container-level |
| `read_only_root` | read-only root filesystem |
| `requests`, `memory_limit` | CPU and memory requests; a memory limit (no CPU limit is required, to avoid throttling) |
| `dedicated_service_account` | not the namespace's `default` account |
| `no_api_token_unless_needed` | `automountServiceAccountToken: false` |
| `no_host_access`, `no_privileged` | no host network, PID, IPC or hostPath; not privileged |
| `secret_mounts_restricted` | secret files no wider than `0440`, mounted read-only |

## How it is checked

`scripts/conformance/hardening.py` (report: [`conformance/hardening.json`](../conformance/hardening.json)):

* **Static:** the manifests under `deploy/aks`, as rendered. `risk-guard.yaml` is rendered the way script 04 does it with every optional
  feature on, and the console proxy patch is merged in, so the init containers and the proxy containers are checked. The OpenShell chart
  and the SPIRE chart are not rendered here.
* **Live:** the pods the cluster actually admitted, so defaults and admission changes are included.
* **Exceptions** are listed in [`deploy/aks/hardening-baseline.json`](../deploy/aks/hardening-baseline.json), per workload and check, each with
  a reason. An exception that no longer matches anything is reported, so the list cannot go stale.

Result on the demo cluster: **no unexplained failures** in 10 static and 17 live workloads. Everything we write meets the baseline except
one named exception: Risk Guard keeps its API token because the tunnel gate reads supervisor pods with a read-only role.

## The exceptions, and why

* **SPIRE's node daemons** are the genuinely privileged part: the CSI driver is privileged (it mounts into other pods), and the agent shares the
  host PID namespace and uses hostPath sockets to identify workloads.
* **SPIRE's server, controller manager and OIDC provider** do not need that. They fail the baseline because the chart's own hardening
  (`global.spire.recommendations`) is switched off here; enabling it requires setting the CA subject, which changes the CA, so it is deferred
  until SPIRE can be re-issued on purpose. That is a gap, not a necessity.
* **The OpenShell gateway** (chart-owned) has a writable root, default secret modes, no resource requests, and the API token it needs to manage sandboxes.
* **Sandbox pods** are created by OpenShell's driver: no container requests (the micro-VM is sized by the runtime class), and the agent's
  filesystem is writable by design, confined by Landlock inside the VM.

## Pod Security Admission

The namespace is labelled `pod-security.kubernetes.io/warn=restricted` and `audit=restricted` (by script 04). It is **not enforced**: the
SPIRE CSI driver and agent, and the OpenShell gateway, would not be admitted under an enforcing label, and they share the namespace. The
way to enforce it is to move the privileged SPIRE node daemons to a namespace of their own with a narrower label; SPIRE was kept here so the
trust-bundle ConfigMap can be mounted by Risk Guard and the proxies, so that is a design change, not a switch.

## Changes made for this baseline

Resource requests and limits on every container we write, including the baseline-import init containers; `automountServiceAccountToken: false`
on all but one workload; dedicated service accounts for Risk Guard, the fixture, the fleet and the token-grant demo services; a seccomp profile
on Risk Guard and the fixture; a read-only root for the fixture; `0440` secret modes for the gateway public key and the fleet's client
certificate. A stray test pod (`curltest`, which ran as root) was deleted.
