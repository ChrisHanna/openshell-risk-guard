# Bounded local OpenShell integration

This is a **native Linux, single-user, explicitly insecure local-test recipe**,
not a cloud deployment or proof of a working sandbox on this workstation.
Risk Guard is a standalone gRPC process. The real gateway calls its
`GatewayInterceptor` service; real host-networked sandbox supervisors call its
`SupervisorMiddleware` service. Dashboard polling is neither of these.

## Mandatory prerequisites

- Run from Linux/WSL with a **same-host rootful Docker API socket**, Docker 28+,
  Bash 4.3+, curl and coreutils `timeout`. Rootless Docker, remote Docker and
  Docker Desktop cross-VM host-loopback forwarding are outside this recipe.
- Supply `openshell` and `openshell-gateway` matching the local OpenShell source
  and its **schema version 2**, including `config preflight`. The installed WSL
  binaries observed on 2026-10-19 are **0.0.116**; that gateway rejects `config
  preflight` and cannot be substituted silently.
- Build Risk Guard locally with the operational `baseline-import --db --profile`
  command. Set `GATEWAY_BIN`, `CLI_BIN`, `RISK_GUARD_BIN` if not on PATH.
- Preload compatible, explicitly versioned/digest-pinned images in the selected
  Docker daemon. Supply `WORKLOAD_IMAGE` (with `/usr/bin/curl`),
  `SANDBOX_RUNTIME_IMAGE` and `SUPERVISOR_IMAGE` from the same OpenShell build.
  The script does not download, build, push or upload images.
- Supply `BASELINE_PROFILE`, an **operator-approved JSON baseline artifact** with
  `task_profile: "local-repo-review"`, `normalizer_version: "v1"`, nonempty
  `approved_by` and `version`, expected
  binary `/usr/bin/curl`, resource `local/review` and action
  `GET /repos/{owner}/{repo}/issues`. Do not label invented training observations
  as a mature baseline. No fixture baseline is seeded automatically.
- Provide a harmless HTTP service on the Linux host at `127.0.0.1:18081` serving
  `GET /repos/local/review/issues`. It is a test destination, not a dashboard
  proxy, GitHub credential provider or third-party API.
- The sandbox boundary requires Landlock ABI 3+ (upstream Linux 6.2+), nested
  seccomp user-notification filters and atomic ADDFD/SEND. OpenShell actively
  qualifies these at launch. Kernel version checks alone cannot certify them.
  Linux gateway GNU builds need glibc 2.28+. Windows/WSL support is experimental.

From a Linux shell in this checkout, set the inputs above, then:

```sh
bash scripts/deploy-local-risk-guard.sh --check
bash scripts/deploy-local-risk-guard.sh --start --allow-insecure-local-test
```

`--check` never starts services or modifies files. `--start` creates a private,
fresh `openshell-risk-guard/deploy/local/state` directory (or fresh `STATE_DIR`
below the checkout),
generates local signing material without Kubernetes/cloud access, imports the
explicit baseline, preflights the rendered TOML, then starts Risk Guard **before**
the gateway. An existing state directory is never overwritten. Logs, signing
keys and both SQLite databases persist. Keep this directory private and out of
source control; it contains private keys. No process is daemonized.

## Actual sandbox traffic and acceptance evidence

In another Linux shell, using the same binaries and workload image:

```sh
openshell --gateway-endpoint http://127.0.0.1:17671 gateway info
openshell --gateway-endpoint http://127.0.0.1:17671 sandbox create \
  --name risk-guard-local-check --from "$WORKLOAD_IMAGE" \
  --policy openshell-risk-guard/deploy/local/sandbox-policy.yaml \
  --no-auto-providers --no-tty -- /usr/bin/true
```

Do not use `--no-keep`: this recipe never automatically deletes sandboxes.
Use a new name if it already exists. Obtain the actual sandbox ID from CLI
output/list, then inspect it, not a fixture ID:

```sh
openshell-risk-guard agent-register \
  --db openshell-risk-guard/deploy/local/state/risk-guard.db \
  --agent-id local-reviewer --display-name "Local reviewer"
openshell-risk-guard run-create \
  --db openshell-risk-guard/deploy/local/state/risk-guard.db \
  --agent-id local-reviewer --run-id local-review-001 \
  --agent-revision revision-1 --task-profile local-repo-review
openshell-risk-guard run-bind \
  --db openshell-risk-guard/deploy/local/state/risk-guard.db \
  --run-id local-review-001 --sandbox-id ACTUAL_SANDBOX_ID \
  --gateway-id risk-guard-local

openshell --gateway-endpoint http://127.0.0.1:17671 sandbox exec \
  --name risk-guard-local-check --no-tty --no-login-shell -- \
  /usr/bin/curl --fail --max-time 15 \
  http://host.openshell.internal:18081/repos/local/review/issues

openshell-risk-guard decision-inspect \
  --db openshell-risk-guard/deploy/local/state/risk-guard.db \
  --sandbox-id ACTUAL_SANDBOX_ID
openshell-risk-guard dashboard \
  --db openshell-risk-guard/deploy/local/state/risk-guard.db
```

Use the gateway ID rendered by the script if it differs from `risk-guard-local`.
Register the workload once; subsequent runs reuse its workload ID. Initial
creation deliberately executes a no-network command so the operator can bind
the pristine epoch before sending requests. The workload image must contain
`/usr/bin/true`. If creation or startup unexpectedly emits inspected traffic
before binding, investigate it: do not bypass binding requirements or attach
a workload retroactively to its decisions. `serve` rejects unattributed traffic
by default; missing bindings cannot be supplied by HTTP headers.

Acceptance requires: gateway info lists **both** `risk-guard-governance`
interceptor and `risk-guard` middleware, sandbox launch passes active isolation
qualification, a request traverses the supervisor, and decision inspection for
that sandbox contains the matching HTTP evaluation. A ready socket, dashboard
screen, preflight success or local evaluator invocation is insufficient.
Inspect service logs on failure; fail-closed denials must not be bypassed with
manual epoch creation or permissive fallback policies.

## Verified wiring and limits

The authoritative local sources are OpenShell `AGENTS.md`,
`crates/openshell-server/src/{cli,config_file}.rs`,
`crates/openshell-core/src/config.rs`, `crates/openshell-policy-schema/src/lib.rs`
and `docs/how-it-works/gateways/configuration.mdx`.
Gateway bootstrap is a **separate binary**, not `openshell gateway start`.
`openshell gateway add <endpoint> --name <alias>` only registers a CLI endpoint;
it does not start the gateway or install extensions. This recipe uses
`--gateway-endpoint` and a private XDG configuration instead of changing the
user's active gateway. Registration is static TOML and requires restart.

The service-reported middleware name is in the reserved `openshell/` namespace,
but operator registrations cannot claim that namespace. Policy
`middleware: risk-guard` references the operator name. Both registrations share
the explicit audience `urn:openshell:extension:risk-guard`; the 4 MiB (4194304-byte) payload
limit matches Risk Guard's manifest. The `network_middlewares` policy attachment
uses `on_error: fail_closed`; the interceptor uses `failure_policy: fail_closed`.

With gateway JWT signing enabled, OpenShell requires HTTPS extension endpoints and
mints bearer tokens; `allow_insecure_transport = true` explicitly sends **no token**.
This loopback recipe therefore uses `--allow-insecure-local-test` at both its
entrypoint and Risk Guard invocation. Loopback is not an authentication boundary
against other local users. **Do not expose these ports to untrusted clients.**

For an authenticated deployment, serve with `--tls-cert`, `--tls-key`,
`--hmac-key-file` and `--public-key-pem`, and register both extensions with
`grpc_endpoint = "https://<host>:50061"` plus `tls_ca_cert_path` for the CA that
signed the certificate (its SAN must match `<host>`). Risk Guard refuses plaintext
on any non-loopback listener unless `--allow-insecure-local-test` is set.

Offline asset checks are available with Python 3.11+ and PyYAML:
`python scripts/check-risk-guard-deployment.py`. Shell syntax can be checked with
`bash -n scripts/deploy-local-risk-guard.sh`. These validate syntax and shared
configuration assertions, **not** native gateway schema acceptance or runtime
connectivity. Compose's service-only example additionally requires
`BASELINE_PROFILE` and `TASK_PROFILE` for `docker compose ... config --quiet`.

Current workstation evidence: the default user-session WSL Docker socket
(`/run/user/1000/docker.sock`) is **rootless** and intentionally remains
unqualified (and any global `0.0.116` binary on PATH lacks current `config
preflight`), so `deploy-local-risk-guard.sh` refuses to start against the default
rootless socket. Full native gateway + supervisor + sandbox qualification on this
workstation is verified through the isolated rootful Docker daemon
(`/run/openshell-risk-guard-demo/docker.sock`) and the pinned `0.1.5-dev`
binaries staged in `~/openshell-demo`; see the verified isolated
rootful demo stack in [`deploy/rail-guard-demo/README.md`](../rail-guard-demo/README.md).
