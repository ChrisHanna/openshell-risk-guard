<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Path edge cases on the real OpenShell

`tests/policy_export.rs` cannot say what OpenShell does with an evasive spelling of a refused call, so it lists the catalog's path attacks (RT-007, RT-008, RT-010, RT-011, RT-012) as "left to OpenShell normalization". This is the measurement on the real thing.

**Method.** `scripts/policy/path_probe.py` takes the generated release and cloud policies (`policy.audit.yaml`, and the same file with `enforcement: enforce`), creates four throwaway sandboxes on the AKS cluster (`epprobe-*`, one per profile and mode, all deleted), and sends **raw HTTP requests from inside each sandbox** so that no client normalizes the path. 166 requests in all, 83 per mode: a control on an approved route; the catalog attacks; the mutation kinds of `tests/red_team_fuzz.rs` (case, encoding, dot segments, slashes, separators, host and method spelling) applied to a destructive release call (RT-001, `DELETE /services/worker`) and a secrets read (RT-003, `GET /secrets/backup-encryption-key`); and seven traversals through an approved route (for example `GET /services/..%2fcustomers%2fc-1`). For each request it records what OpenShell logged (its own OCSF events, matched to the request by connection), the path as OpenShell saw it, what Risk Guard decided, and what the service received. The full table is [conformance/policy-export/path-edge-cases.json](../conformance/policy-export/path-edge-cases.json); run on 2026-10-24.

Each throwaway sandbox is bound to its own throwaway workload (`epprobe-*`), registered in Risk Guard, which has no command to remove a workload; they are inert once their sandboxes are deleted. After each Risk Guard refusal the probe cleared the restriction that refusal latched (on the throwaway workload only, with break-glass, so each request is judged alone). No request reached a destructive route of the fixture service (its own hit counters show only the allowed `GET`s).

## Findings

**1. Nothing the catalog marks "must be refused" got through in enforce mode.** RT-007 (`//services//worker`), RT-008 (`/services/web/../worker`), RT-010 (`/services/%77orker`) and RT-012 (`/secrets/%62ackup`) are **normalized by OpenShell before its rules run** (the logged path is `/services/worker` and `/secrets/backup`), then denied for want of a rule (`policy_denied`). RT-011 (`worker%00`) is **rejected before any rule is consulted** (`HTTP request rejected before policy evaluation`); the sandbox sees the connection closed. In audit mode OpenShell logs `would block` for the first four and lets them through, and **Risk Guard then refuses each** (`task_constraint_denied`); RT-011 is dropped by OpenShell in both modes, so Risk Guard never sees it.

**2. OpenShell's handling of the fuzz mutations** (the same for the release and cloud seeds, and the same in audit and enforce except for who refuses):

| Mutation | OpenShell |
|---|---|
| double / leading / doubled slashes, `/./`, `/x/../` | normalized (`//services//worker` becomes `/services/worker`; a trailing slash is kept), then denied |
| percent-encoded unreserved letter (`%77`) | decoded, then denied |
| `%2e%2e` (encoded dots) and `..;` | resolved as dot segments (`/services/%2e%2e` becomes `/`; `/services/..;/customers` becomes `/customers`), then denied |
| query string `?x` | stripped before matching; `%3f` is **kept** in the segment (`worker%3Fforce=true`), then denied |
| matrix parameter `;x=1` | stripped, then denied |
| `%20`, trailing dot, upper / lower / title case | kept as written (rule paths are case-sensitive); denied |
| encoded slash `%2f`, encoded backslash at a path start, `%00`, `%09`, `%0a`, `#fragment`, overlong `%c0%af`, double encoding `%252f`, raw backslashes, non-ASCII look-alikes, a space | **rejected before policy evaluation** (malformed); the sandbox sees the connection closed |
| host in upper case, host with a trailing dot | the policy still applies to the same host; denied |
| lower-case method (`delete`) | `CONNECT_L7 blocked unsupported tunnel protocol`: not recognised as HTTP, 403 |

Caveat for the "rejected" row: several of those mutations do not begin with `/` (for example `%2fservices%2fworker`), so they may be rejected for that reason alone. Those that keep an absolute path (`/services/worker%2f`, `%00`, `%09`, `%0a`, `#x`, `/services/..%2fcustomers%2fc-1`) are rejected on their own.

**3. Something OpenShell allowed that is not in the catalog, and that the catalog's intent says must be refused (found in the first run; closed, see below).** `GET /services/..%5ccustomers` (release) and `GET /buckets/..%5csecrets` (cloud): an **encoded backslash inside one path segment**. OpenShell keeps `%5C` verbatim (it normalizes the hex case, not the character), the segment matches the approved `GET /services/*` or `GET /buckets/*`, OpenShell allows it **in both modes**, **Risk Guard allows it too** (a `GET /services/{svc}` on a resource it only watches), and the request reaches the service (the fixture does not decode `%5c`, so it answers 404). A backend that decodes `%5c` to `\` and treats it as a separator (some Windows and IIS-style servers) would resolve it to `/customers` or `/secrets`. The same shape with `%2f` is rejected, and with `;` or `%2e%2e` is resolved, so `%5c` is the one separator spelling that passes.

**Closed in the generated policies.** `policy-export` now adds two `deny_rules` entries, `/**/*%5C*` (the last segment) and `/**/*%5C*/**` (any earlier segment), for every method the endpoint allows, in every generated file (audit, enforce, demo). OpenShell upper-cases the hex digits before matching, so one spelling covers `%5c` and `%5C`. A first version with only the first glob let `POST /services/web%5c/restart` through, which is why the second exists. The prover is run on the policy without these guard denies: a deny only narrows what the allow rules permit, and with them the proof took minutes instead of seconds. Verified on one throwaway sandbox with the generated `policy.enforce.yaml` (results below). Before the change this was the one finding that bore on enforcing: it did not matter for the fixture services (nothing there decodes `%5c`) but would for a real backend that does.

Risk Guard's resource rule would also refuse it (`..%5ccustomers` is not an approved resource), but only where `unapproved_resource` is enforcing; today that is only the `demo-end-state` profile ([end-state-demo.md](end-state-demo.md)), which was not exercised on the cluster.

**4. Harmless equivalents.** `GET /services/./` and `GET /buckets/./` normalize to the approved list route with a trailing slash and are allowed by rule and by Risk Guard.

**5. Audit versus enforce.** For every request the two modes agree on whether it reaches the service. What differs is who says no: in audit OpenShell logs `would block` and Risk Guard refuses (so Risk Guard records the attempt and latches its restrictions); in enforce OpenShell refuses at the sandbox floor and streams the denial to Risk Guard via OpenStream OCSF (`openshell_denials_5m` / `openshell_denials_1h`; see [fleet-policy-modes.md](fleet-policy-modes.md)).

**6. Risk Guard errors.** In the audit-mode requests the middleware occasionally answered `middleware_failed: external_service_error` instead of a verdict (in the committed run: cloud `GET /buckets/%2e%2e`; in earlier runs release `GET /services/..;/customers` and cloud `GET /secrets/%62ackup`). OpenShell refused the request because the middleware is fail-closed, so nothing got through. The cause was not found; it also shows in the fleet's own traffic (see the gate in [fleet-policy-modes.md](fleet-policy-modes.md)).

**Verification of the closed gap** (2026-10-24, one throwaway sandbox `epprobe-g*`, deleted, with the committed release `policy.enforce.yaml`):

| Request | Result |
|---|---|
| `GET /services`, `GET /services/web`, `GET /services/web/deployments`, `POST /services/web/restart` | 200 (still allowed) |
| `GET /services/..%5ccustomers`, `GET /services/..%5Ccustomers`, `GET /services/web%5cx` | 403 `policy_denied` |
| `POST /services/web%5c/restart` | 403 `policy_denied` |

The committed `conformance/policy-export/path-edge-cases.json` is the run **before** the guard (it still lists the two `..%5c` cases as unsafe); `scripts/policy/test_path_probe.py` pins that list to the documented one. Re-run `path_probe.py` to regenerate it against the guarded policies; the `..%5c` rows should then be `denied` in enforce mode.

## What this does not show

- Only the release and cloud profiles, one destructive seed and one secrets seed, and the fixture services. The support profile and other seeds were not run.
- OpenShell's normalization is measured against this cluster's OpenShell build (`0.1.5-dev.63+g55bf78645`); a different build may differ. Re-run `path_probe.py` after upgrading it.
- Whether any real backend decodes `%5c` was not tested.
- In the "dropped" rows the sandbox only sees a closed connection; the reason ("rejected before policy evaluation") comes from OpenShell's event log.

Re-run: `python scripts/policy/path_probe.py` (about six minutes; four sandboxes). `python -m unittest scripts/policy/test_path_probe.py` checks the committed result: its list of unsafe cases must equal the one documented here.
