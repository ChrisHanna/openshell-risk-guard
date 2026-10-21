# Operating Risk Guard

Running the sidecar securely, bootstrapping workloads, protecting new APIs, recovering from a false positive, metrics, and rollout. Overview: [README](../README.md).

## Running the sidecar securely

```bash
openshell-risk-guard serve --listen 0.0.0.0:50061 --db /var/lib/openshell-risk-guard/risk-guard.db \
  --public-key-pem /etc/openshell/ext-jwt/public.pem \
  --tls-cert /etc/openshell-risk-guard/tls/tls.crt --tls-key /etc/openshell-risk-guard/tls/tls.key \
  --hmac-key-file /etc/openshell-risk-guard/hmac/key \
  --gateway-id <gateway-id> --default-task-profile <imported-profile>
```

| Input | Why | Without it |
|---|---|---|
| `--tls-cert`/`--tls-key` (`RISK_GUARD_TLS_CERT`/`_KEY`) | Sandbox supervisors reach the sidecar over the network; OpenShell only sends extension JWTs over HTTPS. | Refused off loopback. |
| `--public-key-pem` (`RISK_GUARD_PUBLIC_KEY_PEM`) | Verifies the gateway-minted EdDSA JWT on every call. | Refused. |
| `--hmac-key-file` (`RISK_GUARD_HMAC_KEY_FILE`) | Keys resource identifiers for rolling windows. The database records the key's fingerprint and refuses a different key later. | Refused. |
| `--api-semantics` (`RISK_GUARD_API_SEMANTICS`) | Route templates and impact classes for the APIs you protect, as a mounted file. | Built-in GitHub-style demo map, with a startup warning. |
| Durable volume for `--db` | Restrictions and evidence must survive restarts. | An ephemeral volume silently resets every restriction. |

`--allow-insecure-local-test` is the only way to skip the first three, and is for
single-user loopback tests. Register the extensions with
`grpc_endpoint = "https://…:50061"` and `tls_ca_cert_path`. Probes use the standard
`grpc.health.v1.Health/Check` on the same port; it reports `NOT_SERVING` when the
decision store is unavailable (evaluations already fail closed then). SIGTERM drains
in-flight requests. See [`deploy/k8s-gateway-sidecar.yaml`](../deploy/k8s-gateway-sidecar.yaml).
Run **one** sidecar per gateway, with `replicas: 1` and a `Recreate` rollout. A
rolling update would briefly run two writers on one SQLite file. Use node-local
block storage, never a network filesystem. Scaling to several gateway replicas
means porting the store to a shared database with per-agent serialized
transactions, not just swapping the `RiskStore` trait: the decision transaction
is what keeps the restriction ratchet linearizable.

## Bootstrap order

1. Mount secrets: TLS cert/key, HMAC key, the gateway's extension-JWT public key
   (or generate a local trust bundle for single-host deployments via `local-secrets-generate`).
   The first start records the HMAC key's fingerprint; a different key is refused later.
2. `baseline-import` the operator-approved profile (an initContainer in Kubernetes).
   It is idempotent, and `serve` refuses to start until the default profile exists.
3. **Provisioning & Lifecycle (three paths):**
   - **Explicit CLI binding (default):** `agent-register` once per durable agent
     identity; then per sandbox in the provisioning path: `run-create` ->
     `CreateSandbox` (the gateway interceptor creates the epoch) -> `run-bind`
     **before the workload sends traffic**. Unbound traffic fails closed.
   - **Annotation binding (opt-in):** start `serve` with
     `--agent-binding-principal operator:<subject>` (repeatable; `user:<subject>`
     also works), then create sandboxes with `openshell.nvidia.com/agent-id`
     (optional `agent-revision` and `run-id`) in their annotations or labels. The
     workload ID chooses which restrictions, baseline and learning history a sandbox
     inherits, so it is an operator decision and is guarded:
     - Only allowlisted `operator`/`user` callers are honored. Sandbox, peer and
       anonymous callers never qualify, wildcards are rejected, and with no
       allowlist the annotations are ignored. Anyone else sending them is refused at
       creation; if a refusal happens after the fact the sandbox stays unbound, so its
       traffic fails closed.
     - An unregistered workload ID is refused unless `--auto-register-agents` is set.
     - `openshell.nvidia.com/agent-name` (optional) gives a labeled workload a readable name that the console shows next to its
       ID, for example an Entra application's display name. It is display text only (at most 256 bytes, no control
       characters; anything else is ignored). It replaces an auto-generated name once and never overwrites a name an
       operator chose.
     - A `run-id` that already exists must belong to the named agent and revision.
     - A workload is scoped to the workspace that created it. Auto-registered labels and
       `agent-register --workspace <name>` workloads refuse sandboxes created in any other
       workspace, which also stops a label from capturing another workspace's derived
       workload. A workload registered without `--workspace` is unscoped and any workspace's
       sandbox can use it, so scope it when teams share a gateway.
     - Only the exact `openshell.nvidia.com/...` keys are read, from labels and
       annotations only. Bare names such as `agent_id` are ignored.
     - A new `agent-revision` starts a fresh scoring context, so keep the allowlist
       to people and systems you would let reset an agent's history.

     On `DeleteSandbox` or `StopSandbox` the interceptor closes the epoch and ends the
     bound run, which finalizes any learning window.
   - **Principal-derived binding (opt-in):** start `serve` with
     `--workload-from-principal`. A sandbox created without a workload label is bound to a
     workload derived from the **workspace** it was created in and the **principal** the
     gateway authenticated for the creating call, for example
     `team-a.user.alice-example-com-<hash>`. Both parts come from OpenShell, so nobody can
     choose, forge or squat the ID, and the same authenticated creator keeps one history
     and one set of restrictions across all of its sandboxes. Use it when each agent has its
     own service identity, or when one person launches one kind of agent.
     - Only `operator` and `user` callers can own a workload. Anonymous, unknown, peer and
       sandbox callers stay unbound, so their traffic fails closed.
     - The identity provider the gateway reports (`oidc`, `cloudflare_access` or `mtls`) is part of
       the identity, because a subject is only unique within its provider. A principal with no
       recognized provider is refused.
     - OpenShell's unauthenticated local-development user (`provider=local_dev`) proves nothing about
       who is calling, so it owns no workload and passes no allowlist unless you start `serve` with
       `--allow-local-dev-principal`. Use that for local testing only.
     - The sandbox must report its workspace in the committed response. A response without one is
       refused, never assumed to be `default`.
     - The workload is registered on first use. Different workspaces never share a workload.
     - An explicit label still wins and still needs an allowlisted principal; derivation
       never rescues a refused label.
     - One principal that launches several different agents shares one workload across them,
       so use a label (or separate service identities) when behavior differs.
     - Every attempt, accepted or refused, is recorded in `workload_binding_audit` with the
       workspace, principal and whether the workload came from the principal or a label.

## Protecting a new API

Route semantics come from a mounted YAML map. Name the `host` on every rule so one
API's templates never classify another's traffic; host-specific rules win over
host-agnostic ones, and unknown fields are rejected so a typo cannot widen a rule.

```yaml
version: v1                      # must match the baselines' normalizer contract
routes:
  - host: billing.internal
    method: POST
    route_template: /v1/refunds
    semantic_category: write_mutation
    high_impact: true
    resource_template: "/v1/refunds"
```

Unmapped routes still work, conservatively: any method other than GET/HEAD/OPTIONS
is high-impact (denied as unfamiliar when that constraint is on), reads use the
full path as the resource, and adaptive learning never trains on them. Review map
changes like policy changes, and re-import baselines whose resources change.

## Recovering from a false positive

Restrictions never expire or clear on their own. After reviewing the evidence,
operators can clear a restriction via either the CLI or the web console:

- **Web Console (`Guardrails` or `Detections` tab):** Unlock operator controls with
  the local operator token, then use **Active restrictions & lock recovery -> Clear lock**
  (which calls authenticated `POST /api/agents/{id}/restrictions/clear` and records
  the operator and reason in `restriction_clearances`).
- **Operator CLI:**

```bash
openshell-risk-guard restriction-list  --db risk-guard.db --agent-id repository-reviewer
openshell-risk-guard restriction-clear --db risk-guard.db --agent-id repository-reviewer \
  --scope '<exact scope from restriction-list>' --operator alice --reason 'approved maintenance task'
```

The cleared row is copied to `restriction_clearances` with the operator, reason and
triggering request. New requests in that scope are scored again from scratch.
OpenShell policy, baselines and decision history are unchanged. If the behavior is
legitimate and recurring, add the resource or action to the agent's guardrails
rather than clearing it repeatedly.

## Prometheus `/metrics`, WAL read concurrency & bounded retention

- **Prometheus `/metrics` (`GET /metrics`):** The dashboard HTTP listener exposes
  Prometheus text exposition format (`text/plain; version=0.0.4`) reporting store
  health (`openshell_risk_guard_store_up`), registered agents, active epochs,
  recorded decisions by outcome (`allow`, `allow_with_observation`, `deny`,
  `observe_would_deny`), active restrictions by tier (`strict_epoch`, `cooldown`),
  audited restriction clearances, and adaptive models by status.
- **Dedicated SQLite `WAL` Read Connection:** `SqliteRiskStore` maintains a
  dedicated `PRAGMA query_only = ON` SQLite `WAL` read connection alongside the
  serialized `synchronous = FULL` writer connection so dashboard, `/api/state`,
  and `/metrics` queries never contend with inline `EvaluateHttpRequest`
  decision transactions.
- **Decision retention (two bounds):** Detailed decisions are kept for
  `--decision-retention-days` (default `30`, env `RISK_GUARD_DECISION_RETENTION_DAYS`; `0`
  keeps everything). An hourly job prunes older decisions in small batches. Separately, each
  epoch keeps at most `10,000` decisions, pruning the oldest first. Neither bound removes a
  decision that something still needs: an adaptive training window
  (`adaptive_observations`), a restriction origin, or the request that triggered a lock
  (`restrictions.trigger_request_id` / `agent_restrictions.trigger_request_id`). Epochs,
  restrictions and the audit of cleared locks are never pruned. The console's request counts
  cover the decisions still retained, so with the default they describe the last 30 days.
- **Sandbox lifecycle is inferred, not polled.** Risk Guard learns of sandboxes only from
  gateway interceptor events and supervisor requests, and OpenShell makes `POST_COMMIT`
  fail-open, so a delete event missed during a restart is never retried. `/api/state`
  therefore classifies each active epoch by its last activity (`recently_active` within 15
  minutes, `idle` within 6 hours, otherwise `not_seen_recently`, most likely a deleted
  sandbox) and reports `gateway_connectivity` from the calls it has received. It does not
  probe the gateway.
- **`/metrics` is operator-only.** The console's public proxy answers `404` for it; read it
  with `kubectl port-forward` or `kubectl exec` against the pod's loopback listener.

## Rolling it out

1. **Observe.** Bind agents in `observe` mode. Every decision is recorded and
   nothing is denied. The control plane is still guarded.
2. **Review.** Look at what *would* have been denied in the console. Tune approved
   resources, action classes and thresholds until the would-deny list is
   behavior you actually want blocked.
3. **Enforce** one agent at a time. Keep `restriction-clear` and the rollback
   (switch back to `observe`) in the runbook.
4. **Learned models** build themselves in shadow for every agent; promoting one to
   enforce is an explicit, evidence-bound decision. They are a second opinion, never
   the only control.
