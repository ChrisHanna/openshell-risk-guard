<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Getting started

Pick the path that matches what you want to see. The first one needs nothing but a Rust toolchain and takes about ten minutes,
most of it the first build.

| I want to | Needs | Time | Go to |
|---|---|---|---|
| **See the console and a few decisions, with no setup** | Rust, a C++ toolchain, internet | ~10 min | [Path A](#path-a-see-it-in-ten-minutes) |
| **Run the tests** | the same | 1 to 10 min | [Path B](#path-b-run-the-tests) |
| **Run it against a real OpenShell gateway on my machine** | Docker or Podman, an OpenShell checkout | 30+ min | [Path C](#path-c-a-real-openshell-gateway-locally) |
| **Deploy it on Azure with live agents** | an Azure subscription, about $15 a day | 1 to 2 hours | [Path D](#path-d-azure-kubernetes-service) |

## What you need

* **Linux, macOS, or Windows with WSL.** The scripts are bash. On Windows, use WSL with Ubuntu 24.04; the repository's PowerShell
  scripts (Path D) run from Windows and call into WSL.
* **Rust 1.94 or newer** (edition 2024): `curl https://sh.rustup.rs -sSf | sh`.
* **A C++ toolchain, CMake and pkg-config:** on Ubuntu or Debian, `sudo apt install build-essential cmake pkg-config`.
* **glibc 2.38 or newer** (Ubuntu 24.04, Debian 13 or later). OpenShell's prebuilt Z3 prover needs it. On an older system, build in
  Docker instead (`docker build -t openshell-risk-guard:local .`).
* **Internet access to github.com.** The OpenShell crates Risk Guard uses are fetched from NVIDIA's public repository at the
  commit pinned in `Cargo.toml`, and the prover downloads a prebuilt Z3. **You do not need an OpenShell checkout to build.**
* **Python 3** for the optional demo scripts.

## Path A: see it in ten minutes

```bash
git clone https://github.com/ChrisHanna/openshell-risk-guard.git
cd openshell-risk-guard

cargo build --locked --release          # about 5 minutes the first time
scripts/seed-sample-data.sh             # builds /tmp/risk-guard-sample.db in about a second
target/release/openshell-risk-guard dashboard --db /tmp/risk-guard-sample.db
```

Open **http://127.0.0.1:8787/**. The console is read-only and listens on loopback only.

**What the sample data is.** The script registers the three agents from the Azure deployment (a support analyst, a release
engineer and a cloud-cost agent), imports their approved task profiles from `deploy/aks/agents/*/baseline.json`, and sends each
one its routine calls plus the two calls it is tempted by. It uses the same normalizer, detector and SQLite store as the real
sidecar. The traffic is synthetic: nothing here talks to a gateway, a model or a network.

**A short tour**

1. **Fleet overview.** Three workloads. Each has two blocked requests and a lock that stays in force until an operator clears it.
2. **Open `release-bot`, then Detections.** `POST /services/{svc}/rollback` is denied at score 85 against a block line of 70, and the
   page explains why: outside the approved task, and a high-impact call.
3. **Enforcement.** The task rules, each in a mode. The deny list, the high-impact rule and the approved-action rule *enforce*. The
   approved-resource rule is in *shadow*: it records what it would have blocked without blocking anything, which is the evidence you
   would use before promoting it.
4. **How it works.** The path of a request through OpenShell and Risk Guard, with a real blocked request from this database
   walked through all six steps.

**Try your own request.** This is the same pipeline the sidecar runs for each request OpenShell sends it:

```bash
target/release/openshell-risk-guard evaluate-request \
  --db /tmp/risk-guard-sample.db --sandbox-id sbx-release-bot-1 --request-id try-1 \
  --scheme http --host deploy-api.openshell.svc.cluster.local --port 18081 \
  --method GET --path /services/web --binary /opt/agent/bin/python3.12 --allow-insecure-local-test

target/release/openshell-risk-guard decision-inspect \
  --db /tmp/risk-guard-sample.db --sandbox-id sbx-release-bot-1 --limit 5
```

Change `--method GET` to `DELETE` and run it again: the action is not in the approved list, so it is denied and the workload is
locked. Reload the console to see it.

**Changing settings from the console** (promoting a shadow rule, clearing a lock) needs an operator token. For a local run, start
the console with a token file; it is created on first use, readable only by you:

```bash
target/release/openshell-risk-guard dashboard --db /tmp/risk-guard-sample.db \
  --operator-token-file "$HOME/.risk-guard-operator-token"
cat "$HOME/.risk-guard-operator-token"      # paste this into "Unlock" on the Enforcement tab
```

The Azure deployment replaces this token with Microsoft Entra sign-in; see [Running on AKS](aks.md).

## Path B: run the tests

Run the tests for the area you changed; the full suite is large.

```bash
cargo test --locked --lib detector::            # the scoring rules and their modes (seconds)
cargo test --locked --lib guardrails::          # saved settings and validation
cargo test --locked --test fleet_profiles       # each fleet agent's routine calls pass, the tempting ones are refused
cargo test --locked --test agent_guardrails     # promoting a rule takes effect on the next request
cargo test --locked --test standalone_build     # no dependency points outside the repository
```

`./scripts/demo.sh` runs the whole statistical evaluation, latency benchmark and 10-step end-to-end suite (several minutes); add
`--interactive` for a narrated walkthrough with a pause between stages. The detection numbers come from 415 synthetic fixtures
written for this project; they show the scoring logic does what it was designed to do, not real-world accuracy.

## Path C: a real OpenShell gateway locally

This runs Risk Guard beside a real OpenShell gateway and sandbox on your machine, with a traffic generator and, optionally, a real
NVIDIA NeMo Agent Toolkit agent. It needs Docker or Podman and **a checkout of OpenShell at the commit pinned in `Cargo.toml`**
(the gateway must match). Follow [Demo and local deployment](demo.md).

## Path D: Azure Kubernetes Service

This deploys OpenShell and Risk Guard on AKS with Kata VM sandboxes, a Let's Encrypt certificate, a public read-only console with
Microsoft Entra sign-in for administrators, and three agents running on a schedule. It costs about $15 a day while it runs;
`scripts/aks/99-teardown.ps1 -Yes` deletes everything.

You need an Azure subscription, the Azure CLI signed in, `kubectl`, Helm, PowerShell, Docker Desktop (for builds), a checkout of
OpenShell (for its Helm chart) and the `openshell` CLI built from the same commit as the gateway. [Running on AKS](aks.md) has the
numbered scripts in order, the prerequisites in full, and what a real cluster showed.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `cmake`, `g++` or `pkg-config` not found | Install a C++ toolchain: `sudo apt install build-essential cmake pkg-config`. |
| `GLIBC_2.38 not found`, or a Z3 link error | The system is too old for OpenShell's prebuilt Z3. Use Ubuntu 24.04 or Debian 13, or build with Docker. |
| `failed to fetch ... github.com/NVIDIA/OpenShell` | The build needs access to github.com, including through a proxy or VPN. Retry; the first fetch is large. |
| `dashboard requires an existing Risk Guard database` | Run `scripts/seed-sample-data.sh` first. The console never invents data. |
| `operator dashboard ... must bind to loopback` | The console only listens on 127.0.0.1. For remote access use an SSH tunnel or `kubectl port-forward`. |
| `Address already in use` | Another console is running. Pass `--listen 127.0.0.1:8790` to use a different port. |
| The console is empty | It reads one database file. Check that `--db` is the file you seeded. |
| Windows: `bash\r: No such file` | Git converted the scripts to CRLF. Clone inside WSL, or `git config core.autocrlf false` before cloning. |

## Where things are

| Path | What is there |
|---|---|
| `src/detector/` | The scoring and the task rules, with their modes |
| `src/store/` | The SQLite state, restrictions, settings and audit |
| `src/middleware_service.rs`, `src/interceptor_service.rs` | The two OpenShell hooks Risk Guard serves |
| `src/operator_dashboard.rs`, `src/operator_ui.html` | The operator console (one embedded page, no external assets) |
| `src/entra_auth.rs` | Microsoft Entra sign-in for administrators |
| `deploy/aks/`, `scripts/aks/` | The Azure deployment: manifests and the numbered scripts |
| `docs/` | Operations, security model, design, requirements, where Risk Guard fits |
