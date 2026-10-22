# Workload identity with SPIFFE, and enforcement on the network path

Risk Guard normally learns who a request comes from through OpenShell: the supervisor inside the sandbox asks, and the gateway says
which authenticated person created the sandbox. This page describes a second path that does not rely on the supervisor: callers
prove who they are with a **SPIFFE X.509-SVID** over mutual TLS, and an **egress proxy** on the network path enforces Risk Guard's
decision.

It is built and has been run on the AKS demo cluster. Read [What this does and does not protect](#what-this-does-and-does-not-protect)
before relying on it.

## The pieces

```
 workload ──(mTLS, its SVID)──▶ Envoy egress proxy ──(allowed)──▶ backend
                                   │      ▲
                      Check (gRPC, mTLS, the proxy's own SVID)
                                   ▼      │ allow / deny
                                  Risk Guard  (SVID listener :50062)
```

| Piece | What it is | Where |
|---|---|---|
| **SPIRE** | Issues each pod a short-lived X.509-SVID, `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`, from its Kubernetes attributes. No stored secret. | Helm chart, `deploy/aks/spire-values.yaml` |
| **SVID listener** | A second mutual-TLS gRPC listener (`--svid-listen`) that trusts only certificates chaining to the SPIRE bundle, for the trust domains you list (`--svid-trust-domain`). | `src/spiffe.rs` |
| **Identity → workload** | The SPIFFE ID in the verified certificate becomes a Risk Guard workload (provider `spiffe`) with its own sandbox, scored like any other. | `src/spiffe.rs`, `src/workload_identity.rs` |
| **External authorization** | Risk Guard serves Envoy's `envoy.service.auth.v3.Authorization/Check`. A proxy it trusts (`--svid-proxy-id`) names the downstream workload it verified; Risk Guard answers allow or 403. | `src/ext_authz.rs` |
| **Egress proxy** | Envoy: verifies the workload's SVID, calls `Check` for every request, forwards allowed ones and answers 403 itself for denied ones. Fails closed. | `deploy/aks/egress-proxy.yaml` |

## How the identity is established

* The TLS handshake proves the certificate chains to the trust bundle the operator configured. Risk Guard then checks it is a real
  SVID (a leaf, exactly one URI SAN, a well-formed SPIFFE ID, allowed trust domain) and nothing else.
* The identity is **never** read from a request field or header a caller can set. The listener deletes any inbound copy of
  `x-risk-guard-peer-spiffe-id` and writes it only from the verified certificate. A test sends a forged one and it is ignored.
* A caller on the SVID listener may only evaluate requests for the sandbox its own ID owns.
* The trust bundle is a file (`spire-bundle`, published by SPIRE as PEM). Risk Guard re-reads it every 30 seconds and restarts the
  listener when it changes, so SPIRE's key rotation needs no restart of Risk Guard.
* For the proxy path there are two identities and they are kept apart: the **proxy** authenticates with its own SVID and must be
  listed in `--svid-proxy-id`; the **workload** is the caller the proxy verified, passed as `source.principal`. A workload cannot
  call `Check` itself, because it is not a listed proxy.

## Running it

```powershell
# SPIRE, the SPIFFE listener and a demo workload that is scored as its SPIFFE identity
scripts/aks/17-deploy-spire.ps1

# ...and the Envoy egress proxy, with a workload that can reach its backend only through it
scripts/aks/17-deploy-spire.ps1 -EgressProxy
```

Then:

```bash
# a routine request goes through to the backend
kubectl exec -n openshell deploy/egress-demo -c caller -- python /etc/demo/call.py GET /repos/org/docs-site/issues
# a destructive one is refused by the proxy
kubectl exec -n openshell deploy/egress-demo -c caller -- python /etc/demo/call.py DELETE /repos/org/payments-prod
#   -> 403 denied by Risk Guard: task_constraint_denied
```

Both workloads appear in the console as `spiffe / workload:spiffe://<trust-domain>/ns/openshell/sa/<name> (spiffe)`.

The demo workload's network policy (Cilium, which the cluster enforces) lets it reach only the proxy and DNS. Direct calls to the backend
time out, so the proxy is its only route. Without a policy like that, a compromised workload could simply connect to the backend
itself and the proxy would enforce nothing.

## OpenShell's own sandboxes: the tunnel gate

OpenShell can chain a sandbox's policy-approved TLS egress through an operator-owned proxy (the chart's `upstreamProxy`, HTTP `CONNECT`).
`scripts/aks/18-enable-sandbox-egress.ps1` points it at a second Envoy, `sandbox-egress` (`deploy/aks/sandbox-egress.yaml`), which asks
Risk Guard about every tunnel. OpenShell still applies its own policy, SSRF checks and Risk Guard's per-request check first.

What the proxy can know is much less than the request-level gate: a `CONNECT` carries only a destination address and port, and the
connection carries no certificate. So the question it answers is "may this sandbox have the network at all":

* **Which sandbox?** Risk Guard maps the connection's source address to the supervisor pod, whose `openshell.ai/sandbox-id` label names
  the sandbox it already tracks. This is read-only Kubernetes access (`pods`, one namespace). An address that is no supervisor, or a
  sandbox Risk Guard has no record of, gets no tunnel.
* **Quarantine.** An operator can quarantine a workload (`workload-quarantine`, audited; `workload-release` ends it). Its sandboxes get
  no tunnels, whatever the scoring says and whatever the supervisor does. This is always enforced.
* **Latched restrictions** (a strict-epoch restriction on some scope) are *recorded* as what would have been refused, and enforced only
  with `-RestrictionMode enforce`. They are scoped to one kind of request and stay until an operator clears them, so cutting a whole
  sandbox's network on one is blunt: enforcing them on the demo fleet cut off every agent, which is why shadow is the default.
* **Fails closed.** If the proxy or Risk Guard cannot answer, no new TLS tunnel is opened.

Limits: sandboxes are identified by pod address, not by a certificate (OpenShell's proxy chaining sends none), so this is as strong as
the network's refusal to forge source addresses. Plain HTTP is not chained through the proxy. OpenShell's own pods are not otherwise
fenced by network policy, so a sandbox that could reach the internet some other way is not stopped by this gate.

## What was verified

On the AKS demo cluster (SPIRE 1.15, Envoy 1.36):

* A pod received a SPIRE-issued SVID, called the SVID listener with it, and was scored as `spiffe://…/sa/svid-demo`.
* Through the proxy, a routine `GET` reached the backend and a `DELETE` of a repository was answered `403` by the proxy.
* The network policy blocked a direct connection from the workload to the backend.
* With the tunnel gate on, the live fleet's model calls went through `sandbox-egress` after OpenShell's checks, and Risk Guard logged each
  tunnel with the sandbox it belonged to. Quarantining one fleet workload made its next run's tunnels fail (`the sandbox's workload is
  quarantined`); releasing it restored it. Enforcing latched restrictions was tried and cut off every fleet agent, so it is off by default.
* In the automated tests (`tests/svid_listener.rs`, real mutual TLS): a forged identity header, a certificate from another authority,
  an untrusted trust domain, no certificate, a CA used as a leaf, two URI SANs, a cross-sandbox call, a workload posing as a proxy,
  and a missing or foreign downstream identity are all refused.

## What this does and does not protect

* **Protects:** the identity of the caller (it comes from a certificate SPIRE issued, not from the workload's own claim) and the
  enforcement point (the proxy is outside the workload and its supervisor). A compromised workload cannot skip the check on this
  path, and cannot pretend to be another workload.
* **Does not protect:**
  * Traffic that does not go through the proxy. Forcing it through is the job of network policy or routing; the demo does it with a
    Cilium policy for one pod. It is not applied to OpenShell's sandbox pods.
  * Request-level enforcement for OpenShell's sandboxes. The tunnel gate sees only a destination. OpenShell's upstream proxy setting does
    support a TLS-intercepting proxy: the chart's `upstreamProxy.caBundle` stages the CA that proxy re-signs with into each sandbox's
    supervisor, so a proxy such as squid (ssl-bump) or mitmproxy could see every method and path and ask Risk Guard about it. That is
    the route to the full-request gate for real sandboxes. It is not built here: Envoy, which this deployment uses, cannot mint
    certificates for arbitrary hosts, so it would need a different proxy.
  * The demo's backend is plain HTTP inside the cluster, so `egress-demo` needs no TLS interception.
  * OpenShell's sandboxes *can* have SPIFFE identities (checked against OpenShell `main` of 22 October 2026 and the pinned commit): with a
    SPIFFE Workload API socket mounted (`provider_spiffe_workload_api_socket_path`) the supervisor fetches a JWT-SVID from SPIRE, and OpenShell
    ships a SPIRE overlay that names sandbox pods by their `openshell.ai/sandbox-id`. OpenShell uses it for dynamic provider token grants
    (the JWT-SVID is the OAuth2 client assertion). Nothing in its upstream proxy settings presents that identity to the proxy, though
    (the options are a URL, Basic authentication and a CA bundle), so the tunnel gate still identifies a sandbox by pod address. This
    deployment does not turn the OpenShell SPIFFE support on.
  * Risk Guard and SPIRE share the cluster. A compromise of the cluster itself is out of scope.
* **Not the same as NVIDIA Sentry.** Sentry puts the enforcement layer in a separate hardware trust domain (a BlueField DPU). This
  puts it on the network path in software. It improves on enforcement inside the workload's own host, and it is not equivalent to
  hardware isolation. See [positioning](positioning.md).

## Operating notes

* The trust domain is a name, not a DNS name (default `risk-guard.demo`). Changing it changes every workload's identity.
* SPIRE is installed into the `openshell` namespace so that the trust bundle it publishes can be mounted (a ConfigMap cannot cross
  namespaces). Its own `ClusterSPIFFEID` resources must carry the controller's class (`openshell-spire`), or the controller ignores them.
* `-Remove` uninstalls SPIRE and the demo workloads; re-run `04-deploy-risk-guard.ps1` to switch the listener off.
* SVIDs are short-lived. Envoy and `spiffe-helper` pick up renewals from the SPIRE agent; nothing is stored.
* The Risk Guard server certificate on this listener is the same one the gateway uses, from the local certificate authority, not an
  SVID of its own. Giving Risk Guard its own SVID would let callers verify it by SPIFFE ID too.
