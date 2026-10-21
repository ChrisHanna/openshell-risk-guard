# Running OpenShell with Risk Guard on Azure Kubernetes Service

This guide deploys an OpenShell gateway on AKS from its Helm chart and runs Risk Guard beside it as an
operator-run extension (gateway interceptor and supervisor middleware). Sandboxes can run in Kata VMs. Everything
here was run on a real cluster; the [Findings](#findings) section records what worked and what did not.

The scripts live in [`scripts/aks/`](../scripts/aks) and the manifests in [`deploy/aks/`](../deploy/aks).

> **Cost.** The defaults (two `Standard_D2s_v5` nodes and a Basic registry) cost roughly 10 USD per day. The Kata
> pool (one `Standard_D4s_v5`) adds roughly 5 USD per day, and the public console adds a small load-balancer charge.
> These are estimates, not quotes. Run `scripts/aks/99-teardown.ps1 -Yes` when you are done: it deletes the resource group.

## What you get

This is a reference deployment for learning how to integrate with OpenShell. For threat-level protection of agents, the recommended
approach is OpenShell plus NVIDIA Sentry, which needs BlueField hardware that Azure does not give us. Here Risk Guard adds visibility
and policy-improvement data and acts as a software stand-in; [Where Risk Guard fits](positioning.md) explains what it assumes and what
the hardware layer adds.

```mermaid
flowchart LR
  CLI[openshell CLI] -- mTLS --> GW[OpenShell gateway]
  GW -- interceptor, TLS + JWT --> RG[Risk Guard]
  SB[Sandbox in a Kata VM] -- middleware, TLS + JWT --> RG
  RG --- DB[(SQLite on a managed disk)]
  KV[Key Vault] -. sync .-> GW
  ME[You] -- HTTPS, admin: Entra sign-in --> RG
```

* **OpenShell** is installed from the chart in your OpenShell checkout, with images from `ghcr.io/nvidia/openshell` at the
  checkout's commit.
* **Risk Guard** runs as its own Deployment (one replica, `Recreate` rollout, because it is a single-writer SQLite store)
  with a read-only console on the pod's loopback. It binds each sandbox to a workload derived from the workspace and the
  principal the gateway authenticated, or to a workload named by an allowlisted label such as an agent's Entra application ID.
* **Kata** sandboxes run in their own VM with an upstream guest kernel that provides the Landlock OpenShell requires.

## Prerequisites

* An Azure subscription where you can create AKS clusters, and the Azure CLI signed in (`az login`).
* `kubectl` and Helm 3.14+ (or 4). PowerShell 5.1 or 7+ (the scripts also run on Linux and macOS with `pwsh`).
* A checkout of [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) next to this repository, or pass `-OpenShellPath`.
  Risk Guard builds against it, so use the same commit you deploy.
* For the Kata pool: quota for a Gen2 VM size with nested virtualization (for example `Standard_D4s_v5`).
* The `openshell` CLI (Linux or macOS; on Windows use WSL) to create sandboxes.

## Steps

Run from the repository root. Each script is idempotent, saves resource names to `.aks/state.json` (git-ignored, never
secrets), and prints the next step. Windows PowerShell 5.1 and PowerShell 7 are both supported.

| Step | Script | What it does |
|---|---|---|
| 1 | `01-create-environment.ps1` | Resource group, container registry and AKS cluster (Azure Linux, Cilium so NetworkPolicy is enforced, OIDC issuer and workload identity). Re-attaches the registry every run. |
| 2 | `02-build-image.ps1` | Builds the Risk Guard image **in Azure** with `az acr build`; no local Docker needed. Queues, then polls. |
| 3 | `03-install-openshell.ps1` | Pinned Agent Sandbox controller, then the OpenShell chart. Keeps earlier values on upgrade. `-RuntimeClass kata-qemu` runs every sandbox in Kata. |
| 4 | `04-deploy-risk-guard.ps1` | Generates TLS and HMAC secrets inside the cluster, writes them straight to Kubernetes Secrets, deploys Risk Guard. |
| 5 | `05-register-extension.ps1` | Registers Risk Guard with the gateway (Helm values overlay). The gateway restarts. |
| 6 | `06-add-kata-pool.ps1` | Kata node pool. Default mode installs **upstream Kata** with kata-deploy and approves the RuntimeClass for OpenShell. |
| – | `connect-gateway.sh` | Registers the gateway with the `openshell` CLI over mTLS (untested as a script; see below). |
| 8 | `08-deploy-fixture.ps1` | Harmless test fixture and a small workload image with curl. |
| 7 | `07-verify.ps1` | Prints workloads, who bound each sandbox, and recent decisions. |
| 9 | `09-expose-console.ps1` | Publishes the console on the internet behind a Let's Encrypt certificate and, until step 15 is done, an IP allowlist. |
| 15 | `15-setup-console-signin.ps1` | Lets anyone view the console and requires Microsoft Entra sign-in (at `/admin`) to change it (see Security notes). Re-run 04 and 09 afterwards. |
| 10 | `10-create-key-vault.ps1` | Key Vault (RBAC, purge protection, firewalled to your address). |
| 11 | `11-set-secret.ps1` | Stores a secret from a hidden prompt, through a protected temp file that is overwritten and deleted. |
| 12 | `12-sync-credentials.ps1` | Copies a Key Vault secret into an OpenShell provider over stdin. |
| 13 | `13-register-agent-identity.ps1` | Registers an Entra application for an agent; its client secret goes only to Key Vault; its application ID becomes a workload. |
| 14 | `14-build-agent-image.ps1` | Builds the NeMo Agent Toolkit agent image in the registry. |
| – | `99-teardown.ps1 -Yes` | Deletes the resource group. |

The gateway validates every registered extension when it starts, so Risk Guard (step 4) must be running before step 5.
After redeploying Risk Guard with step 4, re-run steps 9 and 13: they patch the deployment, and a fresh apply resets
those fields.

## Try it

```bash
openshell sandbox create --name try1 --from <acr>.azurecr.io/openshell-demo/workload:1 \
  --policy deploy/aks/sandbox-policy.yaml --no-auto-providers --no-tty --detach -- /usr/bin/sleep infinity
openshell sandbox exec --name try1 --no-tty -- /usr/bin/curl -s -o /dev/null -w '%{http_code}\n' \
  http://risk-guard-fixture.openshell.svc.cluster.local:18081/repos/local/review/issues        # 200
openshell sandbox exec --name try1 --no-tty -- /usr/bin/curl -s -o /dev/null -w '%{http_code}\n' -X DELETE \
  http://risk-guard-fixture.openshell.svc.cluster.local:18081/repos/local/production            # 403, denied by Risk Guard
pwsh scripts/aks/07-verify.ps1
```

To give an agent its own workload from its Entra identity, add
`--annotation openshell.nvidia.com/agent-id=<application id>` (step 13 prints it).

## Credentials

* **Where they live.** Agent credentials are stored in OpenShell's provider store, encrypted with a key held in a cluster
  Secret. A sandbox receives an opaque placeholder; OpenShell substitutes the real value only on requests to the hosts,
  paths and binaries the provider profile allows.
* **Key Vault is the system of record.** Set and rotate a secret there (`11-set-secret.ps1`), then copy it into the
  provider with `12-sync-credentials.ps1`. OpenShell cannot use Key Vault as its credential backend (it supports its own
  store, Kubernetes Secrets and HashiCorp Vault's API), so the value is copied; Key Vault keeps the access control, audit
  log and versions. The Secrets Store CSI driver is not an option for Kata pods in AKS Pod Sandboxing.
* **Never type a secret into chat or a command line.** Both scripts read hidden input or stdin.

## Security notes

* Risk Guard gets only the gateway's **public** extension-signing key (a projected `public.pem`); the signing key in the same
  Secret is never mounted into it.
* TLS keys and the HMAC key are generated in-cluster and stored only as Kubernetes Secrets. Treat the Secret store as the
  trust boundary (enable AKS encryption at rest and restrict `get secret` in `openshell`).
* **Console sign-in.** With `15-setup-console-signin.ps1`, **anyone can view the console** and only a listed Microsoft Entra
  administrator, signing in at **`/admin`**, can change anything. Every write route answers 401 (no valid sign-in) or 403 (a
  real tenant account that is not an administrator). Add `-RequireSignInToRead` to make the whole console members-only instead
  (then unlisted visitors see only a sign-in screen and every data route refuses them).
  * The public page is the evidence the console always showed (workloads, routes, principals, decisions): publishing it with
    sign-in on removes the IP allowlist, so only do so when that is meant to be public.
  * `/admin` signs in with the authorization-code flow and PKCE against a single-tenant app registration (no client secret
    exists) and holds the token in the tab's session storage. The console verifies every token itself: RS256 signature against
    the tenant's published keys, issuer, tenant, audience, expiry, v2 token and the delegated `access` scope. If it cannot get a
    signing key it refuses; it never falls back to open access.
  * Access follows the account's **object ID** (Entra assigns it and never reuses it), not the email address, which is only
    shown. Administrators (`-AdminObjectId`, by default the account you are signed in to `az` with) may change settings.
    Settings changes are recorded against the verified account (`name [entra:<object id>]`) instead of a typed name.
  * Scripts need no token on the public console. On a members-only one (`-RequireSignInToRead`) they read it as you with
    `az account get-access-token --scope api://<app id>/access`, which works where the tenant lets the script pre-authorize the
    Azure CLI for the scope (it is best effort). `07-verify.ps1` does this.
  * The local operator token (`--operator-token-file`) is not set on AKS. If you enable it, treat it as break-glass: it can
    change settings but never reads data while sign-in is required to read.
  * The page is served with a Content-Security-Policy that lets it talk only to itself and `login.microsoftonline.com`.
  * Sign-in does not limit which tenant accounts can request a token for the app, only which of them can change anything. To
    also stop unlisted accounts at Entra, set "Assignment required" on the enterprise application and assign the administrators.
* Until sign-in is configured, the console is exposed only through the proxy in step 9 behind a source-IP allowlist (default:
  this machine's address) and GET/HEAD only; `-RequirePassword` adds a generated password (stored only as a hash in the
  cluster) but cannot be combined with sign-in. With sign-in on, the allowlist is dropped unless you pass `-AllowedIp`. Pages
  are GET/HEAD only; settings changes (PUT/POST) reach `/api/` only. Port 80 is open to the internet so Let's Encrypt can
  validate the name; it serves only the challenge and redirects to HTTPS. Because one Service cannot restrict ports
  separately, nginx enforces any allowlist on 443 (the Service keeps the client address with `externalTrafficPolicy: Local`).
  The hostname appears in public certificate-transparency logs. Use `-AcmeStaging` to test without using the real limits.
* Every script that restarts the Risk Guard pod (04, 09 and 13) waits for the console to present a trusted Let's Encrypt
  certificate and fails with the certificate client's log if it does not (`scripts/aks/verify-console-cert.ps1` runs the same
  check). The console is unreachable for roughly half a minute to a minute during a redeploy (one replica, `Recreate`); that
  shows as a connection error, not a certificate warning. Measured across a full 04, 09 and 13 redeploy: the certificate was
  trusted every time the server answered.
* The chart's default client certificate is a single shared identity (`openshell-client`, provider `mtls`), so everyone
  using it shares one derived workload and can label sandboxes. For real per-person identity, configure OIDC (Microsoft Entra
  ID works) on the chart.
* OpenShell's unauthenticated local-development user is refused by Risk Guard unless you pass the local-testing-only
  `--allow-local-dev-principal`. These manifests do not.
* `kata-deploy` is a privileged installer. It is limited to nodes labeled `openshell.ai/kata=true` and pinned to a release.
* The Agent Sandbox controller is a cluster-wide CRD and controller from kubernetes-sigs, pinned to `v1.0.7`.

## Findings

What running this on a real AKS cluster showed (Kubernetes 1.36, OpenShell `0.1.5-dev.63`, Risk Guard from this repository).

**It works.** A sandbox was Ready in about 35 seconds. The allowed `GET` returned 200; the destructive `DELETE` returned
403 from Risk Guard although the static policy permits it. The sandbox was bound by the real mTLS principal, and a
second sandbox labeled with an agent's Entra application ID became its own workload.

**Kata: AKS Pod Sandboxing does not work with OpenShell; upstream Kata does.**

| | Guest kernel | Landlock | OpenShell |
|---|---|---|---|
| AKS Pod Sandboxing (`kata-vm-isolation`) | 6.6 (`mshv`) | not implemented (ENOSYS) | fails closed: *"Landlock ABI v3 or newer is required, but Landlock is not implemented (kernel lacks CONFIG_SECURITY_LANDLOCK)"* |
| Upstream Kata via kata-deploy (`kata-qemu`) | 6.18 | available | sandbox runs; allow and deny both enforced |

A normal (runc) AKS node reports Landlock ABI 3, which satisfies OpenShell, so Kata is optional hardening, not a requirement.
OpenShell also only schedules onto operator-approved RuntimeClasses: label the class `openshell.ai/sandbox-attachable=true`
or `CreateSandbox` fails with `FAILED_PRECONDITION` (step 6 does this).

**Bugs found and fixed by running it for real**

* The sidecar image failed to link on Debian 12: OpenShell's prebuilt Z3 needs glibc 2.38+ and libstdc++ 13+. The image now
  builds and runs on Debian 13.
* Kubernetes' built-in gRPC probe cannot speak TLS, so a TLS-only listener was killed by its own liveness probe. The sidecar
  has a `health-check` subcommand that does the call over TLS and is used as an exec probe.
* A client-certificate caller is a `user` principal from the `mtls` provider; the workload derivation now accepts it.
* A cluster create interrupted after the cluster existed left the registry unattached (401 on image pull). The script now
  re-attaches every run.
* Windows PowerShell 5.1 specifics: no `$IsLinux`, native-argument quote stripping, strict-mode property access, and flaky
  connection resets that the scripts retry.

**Also verified on the cluster**

* The sidecar's TLS health check: SERVING with the right certificate name, an error exit with a wrong one, and the pod stays up
  past its liveness window with no restarts.
* The NeMo Agent Toolkit agent image, running in a Kata VM as the workload named by the agent's Entra application ID: its
  interpreter's `GET` returned 200 and its `DELETE` returned 403, and the NeMo Agent Toolkit and NeMo Guardrails import cleanly.
* Key Vault to OpenShell provider sync (with a dummy secret), and an Entra application registration with its secret kept only in
  Key Vault.

**Not verified**

* `connect-gateway.sh` as a script. Its steps were done by hand. On Windows the CLI runs in WSL while kubectl runs on Windows,
  so the port-forward must be relayed to WSL's localhost.
* `11-set-secret.ps1` needs an interactive hidden prompt, so it was not run unattended. `12-sync-credentials.ps1` was verified
  with a dummy secret.
* The Entra provider profile minting tokens for a real protected API.
* Real OIDC principals: only the shared client-certificate identity was exercised on the cluster.

**Also verified later:** the agent makes live Nemotron calls through OpenShell with the key injected from Key Vault; three
agents, each with its own Entra application, run on a schedule and each shows in the console with its name next to its
application ID; the console serves a Let's Encrypt certificate that browsers trust.

**Operational lessons**

* A small Kata node fills up. Each sandbox is a VM, so leftover sandboxes make new ones sit in `Provisioning`. The fleet deletes
  each sandbox after its run and sweeps `agent-*` sandboxes older than 3 hours.
* The gateway connection from WSL is a `kubectl port-forward` and it drops now and then. A dropped `sandbox create` may still
  have created the sandbox, so `run-agent.sh` checks for it and retries before giving up.
* In a script with `set -e` and `pipefail`, a `grep` that finds nothing ends the script silently. Polling a sandbox's phase while
* A long `openshell sandbox exec` (the NeMo Guardrails check waits on a model call) can die with `h2 protocol error ... broken
  pipe` when the CLI's connection runs through the `kubectl port-forward`. That is a transport failure, not a verdict, so
  `run-agent.sh` retries the check up to three times. An exit of 3 (the rail blocked the task) is final and is never
  retried, and a check that still cannot run fails closed, so the agent is not started.
  it is still being scheduled hit this, so that line ends with `|| true`.
* Some networks reset the `az` client's connections to the ACR build service (`az acr build` fails with error 10054) while
  `curl` works. `02-build-image.ps1 -LocalDocker` builds with Docker and pushes to the registry instead.
* Docker Desktop can fail to start on stale unix-socket files (`sailor-ingest.sock`, `docker-secrets-engine\engine.sock`) left by
  an unclean shutdown. They cannot be deleted, but moving their folders aside lets Docker recreate them.
* A reasoning model needs a larger `max_tokens` and native tool calling, otherwise the ReAct reply is empty or fails to parse.
* The fleet runs from the machine that starts it, so it stops when that machine sleeps (the gateway port-forward and WSL both
  pause). For an unattended demo, run it somewhere that stays awake.
* A restart of an unapproved production resource (`POST /services/payments/restart`) was allowed at score 0 while the agent's
  baseline was still `insufficient` (no behavioral history), even though a rollback of the same service was denied. A low-impact
  action on an unapproved resource is not penalized until the baseline matures; widening the approved-resource check for
  production names is a possible follow-up.

## Running a fleet of agents

`scripts/aks/agent-fleet.sh` runs three agents on a schedule so the console always has fresh, varied behavior to
score. Register each identity first (`13-register-agent-identity.ps1 -AgentName nat-agent`, then `release-bot` and
`ops-cleaner`; add `-SkipRiskGuardUpdate` after the first run).

| Agent | Role and service | Does | Risk Guard should |
| --- | --- | --- | --- |
| `nat-agent` | Support analyst · `support-api` | reads tickets, customer records and the knowledge base; once is asked to export every customer's email | allow the routine work; block the bulk export |
| `release-bot` | Release engineer · `deploy-api` | lists services and deployments, restarts a staging service; twice is asked to roll back or delete production | allow the checks; deny the rollback and the delete |
| `ops-cleaner` | Cloud cost agent · `cloud-api` | reviews costs and buckets; otherwise tries to delete buckets and read secrets | allow the review; deny the deletes and the secret reads, then lock |

Each agent has its own folder in `deploy/aks/agents/<support|release|cloud>/` with a workflow (its tools), a static sandbox
policy (the one hostname it may reach) and a Risk Guard baseline (its approved task profile). The three services are served
by the same harmless fixture pod under different hostnames, so the console shows three different destinations. POST and
DELETE calls only record themselves; nothing is changed anywhere.

Every 3 to 5 minutes (`MIN_WAIT` and `MAX_WAIT` seconds) one agent runs one randomly chosen task. Every third run of
an agent is screened by the NeMo Guardrails input rail first (`--guardrails-every N`), so some requests are stopped
before they reach Risk Guard and others are stopped by it. Use `--once` for a single pass. Each sandbox is deleted
after its run, and every 3 hours (`SWEEP_EVERY` seconds) the fleet also removes any `agent-*` sandbox older than that, such as one left behind by a dropped connection, so the Kata node stays small.

```bash
export OPENSHELL_BIN=... ACR_SERVER=<registry>.azurecr.io
scripts/aks/agent-fleet.sh
```
