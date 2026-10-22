<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Security

## What this project is

`openshell-risk-guard` is a **reference integration and research prototype** for [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell).
It is not a production security product, its detection results come from synthetic fixtures, and it has had no independent
security review. See [Where Risk Guard fits](docs/positioning.md) for what it assumes (an uncompromised OpenShell supervisor and
node) and what it does not cover. For threat-level protection of agents, use OpenShell with NVIDIA Sentry.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue:

* Use GitHub's **private vulnerability reporting**: the *Security* tab of this repository, then *Report a vulnerability*.
* Include the version or commit, what you did, what you expected and what happened. A minimal reproduction helps.

There is no service-level agreement; this is a one-person project. I aim to acknowledge a report within a week.

Vulnerabilities in OpenShell itself belong with NVIDIA: see the security policy in
[NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell).

## Supported versions

Only the latest commit on `main` is supported.

## What is in scope

* The sidecar and its gRPC services (`SupervisorMiddleware`, `GatewayInterceptor`), including the authentication of its callers.
* The operator console and its API, including the Microsoft Entra sign-in and the read-only/administrator split.
* The deployment scripts and manifests in `deploy/` and `scripts/`.

Out of scope: findings that require a compromised OpenShell supervisor, node or gateway (documented as an assumption), and the
synthetic demo harness (`demo-dashboard`), which is explicitly not a native deployment.

## Handling of secrets

The repository holds no secrets. The AKS scripts keep credentials in Key Vault or Kubernetes Secrets, take API keys through a
hidden prompt (never a command line or a chat), and keep local state (`.aks/`) out of git. If you find a secret in the history,
please report it privately.
