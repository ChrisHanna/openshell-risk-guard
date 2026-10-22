<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Where Risk Guard fits: OpenShell, NVIDIA Sentry, and what this project is for

Statements about NVIDIA and Red Hat products on this page come from their published material (linked at the end). They are vendor
claims and have not been verified by this project.

## What this project is

Risk Guard was built to learn how to integrate with OpenShell: its extension points (`SupervisorMiddleware` and `GatewayInterceptor`),
its identity and policy model, and what a request-level behavioral layer can add on top of them. It is a **reference integration and
research prototype**. It is not a threat-protection product, its detection numbers come from synthetic fixtures, and it has had no
independent security review.

## The recommended approach for protecting agents

For threat-level protection of AI agents, the recommended approach is **OpenShell plus NVIDIA Sentry**. NVIDIA's recent releases (the
Open Agent Safety Platform, announced 28 September 2026) describe it this way:

1. **OpenShell**, the open-source runtime: a sandbox per agent, policy for files, network and credentials, a supervisor that checks
   outbound requests and holds credentials, and a prover that keeps policies inside a ceiling.
2. **NVIDIA Sentry**, an out-of-band layer on BlueField-4 DPUs built on DOCA. As described, it sits in a separate hardware trust domain
   and combines a layer-4 firewall, a layer-7 proxy (DOCA Tower) with Open Policy Agent rules on the requested API and action, workload
   identity (SPIFFE/SPIRE), behavioral checks against a predefined profile, and quarantine that does not depend on the agent or the
   host. **DOCA Argus** supplies host runtime evidence by reading host memory from a BlueField DPU. Red Hat's design runs this on
   OpenShift with BlueField-3 DPUs.

The reason is isolation: the hardware layer keeps observing and enforcing when the host or the supervisor is compromised, which software
running next to the workload cannot do. NVIDIA's own deep dive lists Sentry as planned for early next year, with some DOCA components
available now for experimentation.

## What Risk Guard is useful for alongside it

- **Visibility.** Every decision is recorded with its reason: what was asked, which workload asked, what its task allows, what it
  normally does, and what happened. The console shows the fleet, the evidence behind each block, and audited recovery.
- **Improving policies.** Risk Guard observes allowed traffic, learns each workload's normal envelope in shadow mode, and synthesizes
  least-privilege policy candidates with a prover-checked containment proof, so a team can start broad and tighten safely.
- **A software stand-in where the hardware is not available.** This project's reference deployment runs on Azure Kubernetes Service,
  where we have no access to BlueField. There, Risk Guard narrows OpenShell's answer in software. That is useful for development,
  demos and learning, and it is not a substitute for threat-level protection.
- **Possible input to the hardware layer.** Decision records and per-workload baselines are the kind of context a policy or telemetry
  pipeline can use. This has not been built or discussed with NVIDIA.

## What each layer gives you

| | OpenShell | Risk Guard (this project) | NVIDIA Sentry / DOCA Argus (as described) |
|---|---|---|---|
| Runs on | Laptops, VMs, any Kubernetes | Any Kubernetes that runs OpenShell; tested on AKS with Kata | BlueField DPUs (Sentry: BlueField-4; Argus: BlueField-3 or later) |
| Available | Now (open source) | Now (prototype) | Sentry planned; some DOCA parts available |
| Static policy, credentials, filesystem | Yes | No: it only narrows what OpenShell allows | Enforces OpenShell policy in hardware |
| Is this request reasonable for this agent's job? | No | Yes: task profile, learned baseline, reason codes, restrictions that follow the workload across sandboxes | Claimed: Rego policy and drift against a predefined profile; details not specified |
| Request content (PII, secrets, MCP and agent-to-agent traffic) | Supervisor checks requests | No: scores request metadata, never uses bodies or headers | Claimed for the layer-7 proxy |
| Workload identity | Gateway-attested principals | Binds sandboxes to workloads from gateway identity and Entra; **also** accepts SPIFFE X.509-SVIDs (SPIRE) on a separate mutual-TLS listener, see [workload identity](workload-identity.md). OpenShell's own sandboxes do not use it yet | SPIFFE/SPIRE |
| Survives a compromised host or supervisor | No | **No** | Yes: separate hardware domain |
| Host runtime evidence (processes, memory, kernel modules) | Supervisor process identity | No | Argus |
| Operator evidence and console | CLI, SDKs, TUI | Console, decisions with reasons, audited recovery | Telemetry to SIEM and XDR |

## What Risk Guard assumes

Its checks run in software next to the workload they judge. It therefore assumes an **uncompromised OpenShell supervisor and node**. An
agent that escapes its sandbox, or compromises the supervisor, could skip a middleware call or feed it false data. Kata Containers makes
that harder (the agent must escape its guest kernel and the hypervisor) but does not remove the possibility. The hardware layer exists for
the case where the host itself is hostile, and Risk Guard does not cover it.

## If you must run without the hardware (ideas, not built)

Without DPUs, the same architectural idea (enforcement and evidence in a trust domain the agent cannot reach) can be approximated, more
weakly, with Azure-native parts:

1. **Separate trust domains:** gateway, Risk Guard and its evidence database on their own node pool, apart from the sandbox nodes, with
   network policies and separate identities between them.
2. **Egress outside the node:** sandbox traffic forced through a proxy the node and the agent cannot reconfigure, as a second,
   destination-level check beside the supervisor middleware.
3. **Host signals:** a software sensor such as Defender for Containers, Falco or Tetragon as the weaker analogue of Argus. It runs on the
   host, so a kernel-level compromise can blind it.

These reduce risk. They do not provide the guarantee of a separate hardware domain.

### What running Risk Guard on a separate host does and does not buy

Putting Risk Guard on its own host (or node pool) protects the **decision and the record**, not the **gate**:

* **Protected:** the scoring logic, the baselines, the restrictions and the evidence database are out of reach of a compromised
  workload host. It cannot rewrite its own history or clear its own locks. (Today they already run in a different pod from the
  Kata sandboxes.)
* **Not protected:** the enforcement point. The check is made by OpenShell's supervisor, which runs on the workload side. A
  compromised supervisor can skip the call to Risk Guard or send it false context, and "fail closed" only applies when the call is
  attempted.
* **What would close that gap:** an enforcement point on the network path outside the host, such as an egress proxy or firewall that
  sandbox traffic is forced through by Azure routing and network rules, which then asks Risk Guard. It is harder than it sounds: the
  proxy needs the HTTP method and path (so it must terminate TLS for the sandboxes), and it must learn which workload a request came
  from by network identity instead of from the supervisor, which is what Sentry's SPIFFE integration is for.
  **Built as a demonstration:** an Envoy egress proxy that identifies workloads by their SPIFFE SVID and asks Risk Guard (Envoy
  external authorization) about each request, with a network policy that leaves the demo workload no other route. It works end to end on
  AKS for plain-HTTP traffic inside the cluster. For OpenShell's own sandboxes there is a weaker gate on the network path: their TLS
  tunnels pass through an Envoy proxy that refuses quarantined workloads and sandboxes Risk Guard does not know; it cannot see paths
  inside the tunnel. OpenShell supports a TLS-intercepting upstream proxy (a CA bundle the supervisor trusts), which is how a full-request
  gate for its sandboxes could be built; that is not built here. Details and limits: [workload identity](workload-identity.md).
* **Never reproduced in software on the same host:** host-memory introspection of the kind DOCA Argus does from the DPU.

So a separate host gives tamper-resistant decisions and evidence, not a tamper-proof gate. That is a useful property, and it is
not the same guarantee as Sentry's.

## One-line positioning

For threat-level protection of agents, use OpenShell with NVIDIA Sentry. Risk Guard is a reference integration that shows what
request-level evidence can add: visibility into why requests are allowed or blocked, and data for tightening policies.

## Sources

- NVIDIA developer blog, [Inside NVIDIA Sentry: Secure AI Agents at Runtime](https://developer.nvidia.com/blog/inside-nvidia-sentry-secure-ai-agents-at-runtime)
- NVIDIA developer blog, [Open Agent Safety Platform reference design](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)
- NVIDIA developer blog, [OpenShell Reference Architecture](https://developer.nvidia.com/blog/how-nvidia-openshell-reference-architecture-secures-and-governs-ai-agent-workloads-at-scale/)
- NVIDIA, [DOCA Argus service guide](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-argus-service-guide)
- Red Hat, [Securing AI agents with NVIDIA BlueField, DOCA Argus and OpenShift](https://www.redhat.com/en/blog/securing-ai-agents-enterprise-ai-factory-nvidia-bluefield-doca-argus-red-hat-openshift)
