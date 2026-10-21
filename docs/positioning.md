<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Where Risk Guard fits: OpenShell, NVIDIA Sentry, and clouds without the hardware

This page says what Risk Guard is for, what it is not, and how it relates to NVIDIA's hardware-based approach. Statements about
NVIDIA and Red Hat products come from their published material (linked at the end), are vendor claims, and have not been
verified by this project.

## The recommended shape, and the gap on Azure

NVIDIA's recent releases (the Open Agent Safety Platform, announced 28 September 2026) describe a layered way to govern AI agents:

1. **OpenShell**, the open-source runtime: a sandbox per agent, policy for files, network and credentials, a supervisor that
   checks outbound requests and holds credentials, and a prover that keeps policies inside a ceiling.
2. **NVIDIA Sentry**, an out-of-band layer on BlueField-4 DPUs built on DOCA. As described, it sits in a separate hardware
   trust domain and combines a layer-4 firewall, a layer-7 proxy (DOCA Tower) with Open Policy Agent rules on the requested
   API and action, workload identity (SPIFFE/SPIRE), behavioral checks against a predefined profile, and quarantine that
   does not depend on the agent or the host. **DOCA Argus** supplies host runtime evidence by reading host memory from a
   BlueField DPU. Red Hat's design runs this on OpenShift with BlueField-3 DPUs.

That combination is the recommended approach where the hardware exists. NVIDIA's own deep dive lists Sentry as planned for early
next year, with some DOCA components available now for experimentation, and it needs BlueField hardware.

**This project's reference deployment runs on Azure Kubernetes Service, where we have no access to that hardware.** So Risk
Guard is a software layer for the same job: task-aware, behavior-aware enforcement and an evidence trail for OpenShell
sandboxes. It is built on OpenShell's own extension points (`SupervisorMiddleware` and `GatewayInterceptor`), needs no
special hardware, and runs on any Kubernetes cluster that runs OpenShell. It is not equivalent to the hardware layer, and it does
not claim to be.

## What each layer gives you

| | OpenShell | Risk Guard (this project) | NVIDIA Sentry / DOCA Argus (as described) |
|---|---|---|---|
| Runs on | Laptops, VMs, any Kubernetes | Any Kubernetes that runs OpenShell; tested on AKS with Kata | BlueField DPUs (Sentry: BlueField-4; Argus: BlueField-3 or later) |
| Available | Now (open source) | Now | Sentry planned; some DOCA parts available |
| Static policy, credentials, filesystem | Yes | No: it only narrows what OpenShell allows | Enforces OpenShell policy in hardware |
| Is this request reasonable for this agent's job? | No | Yes: task profile, learned baseline, reason codes, restrictions that follow the workload across sandboxes | Claimed: Rego policy and drift against a predefined profile; details not specified |
| Request content (PII, secrets, MCP and agent-to-agent traffic) | Supervisor checks requests | No: scores request metadata, never uses bodies or headers | Claimed for the layer-7 proxy |
| Workload identity | Gateway-attested principals | Binds sandboxes to workloads from gateway identity and Entra; not SPIFFE/SPIRE | SPIFFE/SPIRE |
| Survives a compromised host or supervisor | No | **No** | Yes: separate hardware domain |
| Host runtime evidence (processes, memory, kernel modules) | Supervisor process identity | No | Argus |
| Operator evidence and console | CLI, SDKs, TUI | Console, decisions with reasons, audited recovery | Telemetry to SIEM and XDR |

## What Risk Guard assumes

Risk Guard's checks run in software next to the workload they judge. It therefore assumes an **uncompromised OpenShell
supervisor and node**. An agent that escapes its sandbox, or compromises the supervisor, could skip a middleware call or feed it
false data. Kata Containers makes that harder (the agent must escape its guest kernel and the hypervisor), but it does not remove
the possibility. What the hardware layer adds is the case where the host itself is hostile, and Risk Guard does not cover it.

## Closing the gap in software on Azure

Without DPUs, the same architectural idea (enforcement and evidence in a trust domain the agent cannot reach) can be approximated
with Azure-native parts. These are weaker than hardware isolation and are described as a software analogue, not parity.

1. **Separate trust domains.** Gateway, Risk Guard and its evidence database run on their own node pool, apart from the sandbox
   nodes, with network policies and separate identities between them.
2. **Network enforcement outside the node.** Sandbox egress is forced through a proxy outside the sandbox node that the node and
   the agent cannot reconfigure. A compromised supervisor then still cannot reach destinations the proxy does not allow. This is a
   second, destination-level enforcement point, in addition to the supervisor middleware, not a replacement for it.
3. **Host signals.** A software sensor such as Defender for Containers, Falco or Tetragon is the weaker analogue of Argus. It runs on
   the host, so a kernel-level compromise can blind it.

Status: these are planned. See [docs/aks.md](aks.md) for what is deployed today.

## One-line positioning

Risk Guard is the request-level, task-aware enforcement layer for OpenShell, available today on any cluster. It complements OpenShell's
policy and NVIDIA's hardware layer. It does not replace either, and where BlueField hardware exists the layers stack.

## Sources

- NVIDIA developer blog, [Inside NVIDIA Sentry: Secure AI Agents at Runtime](https://developer.nvidia.com/blog/inside-nvidia-sentry-secure-ai-agents-at-runtime)
- NVIDIA developer blog, [Open Agent Safety Platform reference design](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)
- NVIDIA developer blog, [OpenShell Reference Architecture](https://developer.nvidia.com/blog/how-nvidia-openshell-reference-architecture-secures-and-governs-ai-agent-workloads-at-scale/)
- NVIDIA, [DOCA Argus service guide](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-argus-service-guide)
- Red Hat, [Securing AI agents with NVIDIA BlueField, DOCA Argus and OpenShift](https://www.redhat.com/en/blog/securing-ai-agents-enterprise-ai-factory-nvidia-bluefield-doca-argus-red-hat-openshift)
