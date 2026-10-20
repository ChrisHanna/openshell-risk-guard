#!/usr/bin/env bash
# Offline, foreground native demo. All data and sandbox resources persist.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -d "$ROOT/deploy/rail-guard-demo" ]]; then
  CONFIG="$ROOT/deploy/rail-guard-demo"
else
  CONFIG="$ROOT/openshell-risk-guard/deploy/rail-guard-demo"
fi
ACTION="${1:---check}"
fail() { printf 'BLOCKED: %s\n' "$*" >&2; exit 1; }
case "$ACTION" in
  --help)
    printf '%s\n' 'Usage: bash scripts/rail-guard-demo.sh --check' \
      '       bash scripts/rail-guard-demo.sh --start --allow-insecure-local-test' \
      'Environment: RAIL_GUARD_DEMO_ASSETS, RAIL_GUARD_DEMO_STATE, DOCKER_BIN, DOCKER_SOCKET.' \
      'Foreground only. Ctrl-C stops owned services, never deletes data/sandboxes.'
    exit 0 ;;
  --check) [[ $# -le 1 ]] || fail 'Unexpected arguments.' ;;
  --start) [[ $# = 2 && "$2" = --allow-insecure-local-test ]] ||
    fail 'Start requires explicit --allow-insecure-local-test.' ;;
  *) fail 'Use --help.' ;;
esac
[[ "$(uname -s)" = Linux && "$EUID" != 0 ]] || fail 'Run as the ordinary Linux user (not root).'
ASSETS="${RAIL_GUARD_DEMO_ASSETS:-$HOME/openshell-demo}"
STATE="${RAIL_GUARD_DEMO_STATE:-$HOME/.local/state/openshell-risk-guard-demo}"
DOCKER_SOCKET="${DOCKER_SOCKET:-/run/openshell-risk-guard-demo/docker.sock}"
DOCKER_BIN="${DOCKER_BIN:-$HOME/bin/docker}"
REVISION=55bf78645
WORKLOAD_IMAGE="risk-guard-demo/workload:$REVISION"
SANDBOX_RUNTIME_IMAGE="risk-guard-demo/sandbox:$REVISION"
SUPERVISOR_IMAGE="risk-guard-demo/supervisor:$REVISION"
for path in "$ASSETS" "$STATE" "$DOCKER_SOCKET"; do
  [[ "$path" =~ ^/[a-zA-Z0-9_./-]+$ && "$path" != *'/../'* && "$path" != */.. ]] ||
    fail "Unsupported absolute path: $path"
done
[[ "$DOCKER_SOCKET" = /run/openshell-risk-guard-demo/docker.sock ]] ||
  fail 'Only the explicitly isolated daemon socket is qualified.'
for name in python3 curl timeout flock realpath; do
  command -v "$name" >/dev/null || fail "Missing prerequisite: $name"
done
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
[[ -x "$DOCKER_BIN" && -S "$DOCKER_SOCKET" ]] || fail 'Missing isolated Docker binary/socket.'
python3 "$ROOT/scripts/rail-guard-demo-fixture.py" check-assets --assets "$ASSETS" \
  --docker "$DOCKER_BIN" --socket "$DOCKER_SOCKET"
for name in openshell openshell-gateway openshell-supervisor openshell-sandbox openshell-risk-guard; do
  [[ -x "$ASSETS/bin/$name" ]] || fail "Missing staged native binary: $ASSETS/bin/$name"
  "$ASSETS/bin/$name" --version || fail "Native binary cannot run: $name"
done
CLI="$ASSETS/bin/openshell"
GATEWAY="$ASSETS/bin/openshell-gateway"
GUARD="$ASSETS/bin/openshell-risk-guard"
"$GATEWAY" config preflight --help >/dev/null || fail 'Gateway is not current schema v2.'
"$CLI" sandbox exec --help | grep -q -- '--no-login-shell' ||
  fail 'CLI lacks deterministic --no-login-shell execution.'
for subcommand in agent-register run-create run-bind baseline-import dashboard guardrails-show guardrails-export; do
  "$GUARD" "$subcommand" --help >/dev/null || fail "Missing native command: $subcommand"
done
for file in baseline.json sandbox-policy.yaml gateway.toml.in; do
  [[ -r "$CONFIG/$file" ]] || fail "Missing configuration: $file"
done
[[ -x "$DOCKER_BIN" && -S "$DOCKER_SOCKET" ]] || fail 'Missing isolated Docker binary/socket.'
[[ "$(stat -c '%U:%G:%a' "${DOCKER_SOCKET%/*}")" = root:docker:750 &&
   "$(stat -c '%U:%G:%a' "$DOCKER_SOCKET")" = root:docker:660 ]] ||
  fail 'Isolated Docker requires root:docker directory 0750 and socket 0660.'
DOCKER=("$DOCKER_BIN" --host "unix://$DOCKER_SOCKET")
INFO="$("${DOCKER[@]}" info --format '{{.OSType}} {{json .SecurityOptions}}')" ||
  fail 'Selected isolated daemon inaccessible; check Linux docker group membership.'
[[ "$INFO" = linux* && "$INFO" != *rootless* ]] || fail 'Rootful Linux daemon required.'
for image in "$WORKLOAD_IMAGE" "$SANDBOX_RUNTIME_IMAGE" "$SUPERVISOR_IMAGE"; do
  "${DOCKER[@]}" image inspect "$image" >/dev/null || fail "Offline image missing: $image"
done
while IFS= read -r name; do
  [[ "$name" != OPENSHELL_* ]] || fail "Unset inherited override $name."
done < <(compgen -e)
printf '%s\n' 'Offline assets/CLI features/rootful daemon checked. No builds, pulls or downloads.'
if [[ "$ACTION" = --check ]]; then
  printf '%s\n' 'Read-only check passed; native isolation and full traffic still require --start.'
  exit 0
fi
umask 077
mkdir -p "$STATE"/{logs,pids,rehearsals}
STATE="$(realpath "$STATE")"
exec 9>"$STATE/pids/owner.lock"
flock -n 9 || fail 'Another demo owner holds this state directory.'
LAUNCH_TOKEN="${RAIL_GUARD_DEMO_LAUNCH_TOKEN:-$(cat /proc/sys/kernel/random/uuid)}"
[[ "$LAUNCH_TOKEN" =~ ^[a-zA-Z0-9-]+$ ]] || fail 'Invalid launcher ownership token.'
printf '%s\n' "$$" >"$STATE/pids/owner.pid"
printf '%s\n' "$LAUNCH_TOKEN" >"$STATE/pids/owner-token"
export OPENSHELL_DB_URL="sqlite://$STATE/gateway.db"
export OPENSHELL_LOCAL_TLS_DIR="$STATE/tls"
export XDG_STATE_HOME="$STATE/xdg-state" XDG_CONFIG_HOME="$STATE/xdg-config"
PIDS=()
cleanup() {
  trap - EXIT INT TERM
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  rm -f "$STATE/pids/owner.pid"
  rm -f "$STATE/pids/owner-token" "$STATE/pids/ready-token"
  for name in fixture risk-guard gateway dashboard; do rm -f "$STATE/pids/$name.pid"; done
  printf '%s\n' 'Owned services stopped; databases, logs, certificates and sandboxes retained.'
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for port in 18081 50061 17671 17672 8791; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    fail "Loopback port $port occupied; no existing process will be stopped."
  fi
done
if [[ ! -d "$STATE/tls" ]]; then
  "$GATEWAY" generate-certs --output-dir "$STATE/tls" >"$STATE/logs/certgen.log" 2>&1
fi
for file in signing.pem public.pem kid; do
  [[ -s "$STATE/tls/jwt/$file" ]] || fail 'Persistent JWT material incomplete; inspect, do not reset.'
done
# The gateway<->Risk Guard extension channel is authenticated even in this local
# rehearsal: TLS (local test CA) plus gateway-signed EdDSA JWTs on every call.
RG_TLS="$STATE/risk-guard-tls"
if [[ ! -d "$RG_TLS" ]]; then
  "$GUARD" local-secrets-generate --out-dir "$RG_TLS" --san 127.0.0.1 --san localhost \
    >"$STATE/logs/risk-guard-secrets.json" 2>&1 ||
    fail 'Risk Guard TLS/HMAC generation failed; see logs/risk-guard-secrets.json.'
fi
for file in ca.crt tls.crt tls.key hmac.key; do
  [[ -s "$RG_TLS/$file" ]] || fail 'Risk Guard TLS/HMAC material incomplete; inspect, do not reset.'
done
RENDERED="$(<"$CONFIG/gateway.toml.in")"
STATE_DIR="$STATE"
for name in STATE_DIR DOCKER_SOCKET WORKLOAD_IMAGE SANDBOX_RUNTIME_IMAGE SUPERVISOR_IMAGE; do
  token="@$name@"; RENDERED="${RENDERED//$token/${!name}}"
done
printf '%s\n' "$RENDERED" >"$STATE/gateway.toml"
"$GATEWAY" config preflight --path "$STATE/gateway.toml"
DB="$STATE/risk-guard.db"
"$GUARD" baseline-import --db "$DB" --profile "$CONFIG/baseline.json" >"$STATE/logs/baseline-import.json"
RUN_ID="review-$(date -u +%Y%m%dT%H%M%S)-$(cat /proc/sys/kernel/random/uuid)"
SANDBOX_NAME="rg-$(cat /proc/sys/kernel/random/uuid | cut -c1-16)"
RUN="$STATE/rehearsals/$RUN_ID"
mkdir "$RUN"
start() {
  local name="$1"; shift
  "$@" >"$RUN/$name.log" 2>&1 9>&- &
  local pid=$!
  PIDS+=("$pid")
  printf '%s\n' "$pid" >"$STATE/pids/$name.pid"
}
alive() {
  for pid in "${PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null || fail "Owned service $pid exited; inspect $RUN"
  done
}
wait_http() {
  local url="$1"
  for ((i=0; i<90; i++)); do
    alive
    if curl --noproxy '*' --silent --fail --max-time 2 "$url" >/dev/null; then return; fi
    sleep 1
  done
  fail "Readiness deadline: $url; inspect $RUN"
}
start fixture python3 "$ROOT/scripts/rail-guard-demo-fixture.py" serve --db "$STATE/fixture.db"
wait_http http://127.0.0.1:18081/_evidence
# Default: bind sandboxes to a workload derived from the creating workspace and principal.
# Sandboxes then bind themselves, so the fixed rehearsal below is skipped.
# Set RAIL_GUARD_DEMO_WORKLOAD_FROM_PRINCIPAL=0 for explicit run-bind with the demo-reviewer workload.
PRINCIPAL_MODE="${RAIL_GUARD_DEMO_WORKLOAD_FROM_PRINCIPAL:-1}"
[[ "$PRINCIPAL_MODE" == 1 ]] && export RISK_GUARD_WORKLOAD_FROM_PRINCIPAL=true
start risk-guard "$GUARD" serve --listen 127.0.0.1:50061 --db "$DB" \
  --gateway-id risk-guard-demo --audience urn:openshell:extension:risk-guard \
  --default-task-profile demo-repo-review \
  --public-key-pem "$STATE/tls/jwt/public.pem" \
  --tls-cert "$RG_TLS/tls.crt" --tls-key "$RG_TLS/tls.key" --hmac-key-file "$RG_TLS/hmac.key"
for ((i=0; i<30; i++)); do
  alive
  if (exec 3<>/dev/tcp/127.0.0.1/50061) 2>/dev/null; then break; fi
  sleep 1
done
((i < 30)) || fail 'Risk Guard did not bind.'
start gateway "$GATEWAY" --config "$STATE/gateway.toml"
wait_http http://127.0.0.1:17672/readyz
CLI_CMD=("$CLI" --gateway-endpoint http://127.0.0.1:17671)
timeout 30 "${CLI_CMD[@]}" gateway info >"$RUN/gateway-info.txt"
grep -Fq 'risk-guard-governance (gateway-interceptor)' "$RUN/gateway-info.txt" ||
  fail 'Native interceptor registration not reported.'
grep -Fq 'risk-guard (supervisor-middleware)' "$RUN/gateway-info.txt" ||
  fail 'Native middleware registration not reported.'
REGISTERED="$(python3 "$ROOT/scripts/rail-guard-demo-fixture.py" agent-registered \
  --db "$DB" --agent-id demo-reviewer)"
case "$REGISTERED" in
  no) "$GUARD" agent-register --db "$DB" --agent-id demo-reviewer \
    --display-name 'Demo reviewer (local insecure)' >"$RUN/agent.json" ;;
  yes) printf '%s\n' '{"agent_id":"demo-reviewer","status":"reused"}' >"$RUN/agent.json" ;;
  *) fail 'Unexpected identity query result.' ;;
esac
"$GUARD" guardrails-show --db "$DB" --agent-id demo-reviewer >"$RUN/guardrails.json"
HAS_SAVED_GUARDRAILS="$(python3 -c 'import json,sys; print("yes" if json.load(open(sys.argv[1]))["has_saved_settings"] else "no")' "$RUN/guardrails.json")"
if [[ "$HAS_SAVED_GUARDRAILS" = yes || "$PRINCIPAL_MODE" == 1 ]]; then
  start dashboard "$GUARD" dashboard --listen 127.0.0.1:8791 --db "$DB" \
    --operator-token-file "$STATE/operator-token"
  wait_http http://127.0.0.1:8791/api/state
  printf '%s\n' "$LAUNCH_TOKEN" >"$STATE/pids/ready-token"
  printf '%s\n' \
    "SAVED_GUARDRAILS_READY http://127.0.0.1:8791/ evidence=$RUN" \
    "$([[ "$PRINCIPAL_MODE" == 1 ]] && echo 'Sandboxes bind themselves to a workload derived from their workspace and creating principal; the fixed rehearsal is skipped.' || echo 'Saved guardrails restored. Monitoring resumed; fixed allow/deny rehearsal was not rerun against custom settings.')" \
    'Operator editing requires the private operator-token file. The token is never printed.'
  wait -n "${PIDS[@]}"
  fail "A native service exited; inspect $RUN"
fi
[[ "$HAS_SAVED_GUARDRAILS" = no ]] || fail 'Unexpected saved guardrail state.'
"$GUARD" run-create --db "$DB" --agent-id demo-reviewer --run-id "$RUN_ID" \
  --agent-revision "$REVISION" --task-profile demo-repo-review >"$RUN/run.json"
timeout 180 "${CLI_CMD[@]}" sandbox create --name "$SANDBOX_NAME" --from "$WORKLOAD_IMAGE" \
  --policy "$CONFIG/sandbox-policy.yaml" --no-auto-providers --no-tty --detach \
  -- /usr/bin/sleep infinity >"$RUN/create.txt" 2>"$RUN/create.stderr"
timeout 30 "${CLI_CMD[@]}" sandbox get "$SANDBOX_NAME" --output json >"$RUN/sandbox.json"
SANDBOX_ID="$(python3 "$ROOT/scripts/rail-guard-demo-fixture.py" sandbox-id "$RUN/sandbox.json")"
"$GUARD" run-bind --db "$DB" --run-id "$RUN_ID" --sandbox-id "$SANDBOX_ID" \
  --gateway-id risk-guard-demo >"$RUN/binding.json"
curl --noproxy '*' --silent --fail http://127.0.0.1:18081/_evidence >"$RUN/before.json"
EXEC=(timeout 45 "${CLI_CMD[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty --no-login-shell --)
"${EXEC[@]}" /usr/bin/curl --noproxy '*' --fail --max-time 20 \
  http://host.openshell.internal:18081/repos/local/review/issues >"$RUN/allowed.json"
# Do not use --fail: capture the actual HTTP status, not just a nonzero CLI exit.
"${EXEC[@]}" /usr/bin/curl --noproxy '*' --silent --show-error --max-time 20 \
  --request DELETE --output /dev/null --write-out '%{http_code}' \
  http://host.openshell.internal:18081/repos/local/production >"$RUN/denied-status.txt"
STATUS="$(tr -d '\r\n' <"$RUN/denied-status.txt")"
curl --noproxy '*' --silent --fail http://127.0.0.1:18081/_evidence >"$RUN/after.json"
for ((attempt=0; attempt<25; attempt++)); do
  "$GUARD" decision-inspect --db "$DB" --sandbox-id "$SANDBOX_ID" >"$RUN/decisions.json"
  if python3 "$ROOT/scripts/rail-guard-demo-fixture.py" verify --before "$RUN/before.json" \
    --after "$RUN/after.json" --status "$STATUS" --decisions "$RUN/decisions.json" 2>/dev/null; then
    break
  fi
  sleep 0.2
done
python3 "$ROOT/scripts/rail-guard-demo-fixture.py" verify --before "$RUN/before.json" \
  --after "$RUN/after.json" --status "$STATUS" --decisions "$RUN/decisions.json"
"$GUARD" hardening-report --db "$DB" --sandbox-id "$SANDBOX_ID" \
  --policy "$CONFIG/sandbox-policy.yaml" --out "$RUN/hardening-report.json" >/dev/null
CONTINUATION_RUN="$RUN_ID-continuation"
CONTINUATION_NAME="rg-$(cat /proc/sys/kernel/random/uuid | cut -c1-16)"
"$GUARD" run-create --db "$DB" --agent-id demo-reviewer --run-id "$CONTINUATION_RUN" \
  --agent-revision "$REVISION" --task-profile demo-repo-review >"$RUN/continuation-run.json"
timeout 180 "${CLI_CMD[@]}" sandbox create --name "$CONTINUATION_NAME" --from "$WORKLOAD_IMAGE" \
  --policy "$CONFIG/sandbox-policy.yaml" --no-auto-providers --no-tty --detach \
  -- /usr/bin/sleep infinity >"$RUN/continuation-create.txt" 2>"$RUN/continuation-create.stderr"
timeout 30 "${CLI_CMD[@]}" sandbox get "$CONTINUATION_NAME" --output json >"$RUN/continuation-sandbox.json"
CONTINUATION_ID="$(python3 "$ROOT/scripts/rail-guard-demo-fixture.py" sandbox-id "$RUN/continuation-sandbox.json")"
"$GUARD" run-bind --db "$DB" --run-id "$CONTINUATION_RUN" --sandbox-id "$CONTINUATION_ID" \
  --gateway-id risk-guard-demo >"$RUN/continuation-binding.json"
timeout 45 "${CLI_CMD[@]}" sandbox exec --name "$CONTINUATION_NAME" --no-tty --no-login-shell -- \
  /usr/bin/curl --noproxy '*' --silent --show-error --max-time 20 \
  --request DELETE --output /dev/null --write-out '%{http_code}' \
  http://host.openshell.internal:18081/repos/local/production >"$RUN/continuation-status.txt"
for ((attempt=0; attempt<25; attempt++)); do
  "$GUARD" decision-inspect --db "$DB" --sandbox-id "$CONTINUATION_ID" >"$RUN/continuation-decisions.json"
  if grep -Fq '"behavioral_risk_restricted"' "$RUN/continuation-decisions.json"; then
    break
  fi
  sleep 0.2
done
curl --noproxy '*' --silent --fail http://127.0.0.1:18081/_evidence >"$RUN/continuation-after.json"
python3 - "$RUN" <<'PY'
import json
from pathlib import Path
import sys

run = Path(sys.argv[1])
decisions = json.loads((run / "continuation-decisions.json").read_text())
assert (run / "continuation-status.txt").read_text().strip() in ("403", "451")
assert any(d["outcome"] == "deny" and d["reason_code"] == "behavioral_risk_restricted"
           for d in decisions), "new sandbox must inherit the original agent restriction"
assert json.loads((run / "continuation-after.json").read_text())["DELETE"] == 0
first = json.loads((run / "sandbox.json").read_text())["id"]
second = json.loads((run / "continuation-sandbox.json").read_text())["id"]
assert first != second, "continuation must use a distinct actual sandbox"
print("Same workload ID, distinct run and sandbox: persisted restriction verified.")
PY
start dashboard "$GUARD" dashboard --listen 127.0.0.1:8791 --db "$DB" \
  --operator-token-file "$STATE/operator-token"
wait_http http://127.0.0.1:8791/api/state
printf '%s\n' "$RUN_ID" >"$STATE/latest-run"
printf '%s\n' "$LAUNCH_TOKEN" >"$STATE/pids/ready-token"
printf '%s\n' 'LOCAL INSECURE TEST ONLY — cold-start task constraint, not learned anomaly.' \
  "NATIVE_REHEARSAL_READY http://127.0.0.1:8791/ evidence=$RUN" \
  'Ctrl-C stops owned services only. Persistent shared agent risk state is not reset.'
wait -n "${PIDS[@]}"
fail "A native service exited; inspect $RUN"
