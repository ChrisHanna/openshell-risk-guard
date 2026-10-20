#!/usr/bin/env bash
# Periodic traffic for the rail-guard demo, so the console has something to show.
#
# A dedicated workload (default ID: live-traffic) gets its own long-lived sandbox. Every
# 1-2 minutes a scripted `curl` or shell command runs INSIDE that sandbox through
# `openshell sandbox exec`. There is no LLM: the point is real traffic through the real
# gateway, supervisor and Risk Guard sidecar.
#
#   allowed read   GET    .../review/issues      -> Risk Guard allows            (console)
#   risky delete   DELETE .../production         -> OpenShell allows, Risk Guard
#                                                   denies                       (console)
#   static block   GET    .../production/secrets -> blocked by OpenShell's static
#                                                   policy, never reaches Risk Guard
#   filesystem     /tmp and /sandbox writable; /etc and /usr blocked by Landlock.
#                  Filesystem activity is enforced by OpenShell, not scored.
#
# The upstream is the harmless local fixture, not github.com.
#
# Usage: rail-guard-demo-traffic.sh start [min_seconds] [max_seconds]
#        rail-guard-demo-traffic.sh stop | status | once | reset
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS="${RAIL_GUARD_DEMO_ASSETS:-$HOME/openshell-demo}"
STATE="${RAIL_GUARD_DEMO_STATE:-$HOME/.local/state/openshell-risk-guard-demo}"
GUARD="$ASSETS/bin/openshell-risk-guard"
CLI="$ASSETS/bin/openshell"
DB="$STATE/risk-guard.db"
FIXTURE_PY="$ROOT/scripts/rail-guard-demo-fixture.py"
POLICY="$ROOT/deploy/rail-guard-demo/sandbox-policy.yaml"
IMAGE="${WORKLOAD_IMAGE:-risk-guard-demo/workload:55bf78645}"
GATEWAY_ID="${GATEWAY_ID:-risk-guard-demo}"
ENDPOINT="${GATEWAY_ENDPOINT:-http://127.0.0.1:17671}"
TARGET="http://host.openshell.internal:18081"
WORKLOAD_ID="${TRAFFIC_WORKLOAD_ID:-live-traffic}"
TASK_PROFILE="${TRAFFIC_TASK_PROFILE:-demo-repo-review}"
MIN_SECONDS="${TRAFFIC_MIN_SECONDS:-60}"
MAX_SECONDS="${TRAFFIC_MAX_SECONDS:-120}"
LOG="$STATE/logs/live-traffic.log"
PIDFILE="$STATE/pids/live-traffic.pid"
ENVFILE="$STATE/live-traffic.env"

# shellcheck source=lib/binding.sh
. "$ROOT/scripts/lib/binding.sh"

SANDBOX_NAME=""; RUN_ID=""; SANDBOX_ID=""

log() { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*"; }
gw() { timeout 120 "$CLI" --gateway-endpoint "$ENDPOINT" "$@"; }
stack_ready() { curl -s -o /dev/null --max-time 3 --noproxy '*' http://127.0.0.1:17672/readyz; }
running_pid() { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null && cat "$PIDFILE"; }

sandbox_phase() {
  gw sandbox get "$1" --output json 2>/dev/null | grep -o '"phase": *"[A-Za-z]*"' | head -1 | sed 's/.*: *"//; s/"//'
}

wait_ready() {
  local name="$1" waited=0 phase=""
  while (( waited < 300 )); do
    phase="$(sandbox_phase "$name")"
    [[ "$phase" == Ready ]] && return 0
    (( waited % 30 == 0 )) && log "waiting for sandbox $name (phase: ${phase:-unknown}); it needs about two minutes after a stack restart"
    sleep 5; waited=$((waited + 5))
  done
  return 1
}

bound_in_db() {
  # True while the sandbox still has an active epoch bound to a run in the evidence database.
  python3 - "$DB" "$1" <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    row = c.execute("""SELECT 1 FROM epoch_bindings b JOIN epochs e ON e.epoch_id = b.epoch_id
                       WHERE e.sandbox_id = ? AND e.active != 0 LIMIT 1""", (sys.argv[2],)).fetchone()
    sys.exit(0 if row else 1)
except Exception:
    sys.exit(1)
PY
}

create_workload() {
  local stamp name tmp registered
  stamp="$(date -u +%Y%m%dT%H%M%S)"
  RUN_ID="live-traffic-$stamp"
  name="rg-live-${stamp:9:6}"
  if ! rg_principal_mode; then
    registered="$(python3 "$FIXTURE_PY" agent-registered --db "$DB" --agent-id "$WORKLOAD_ID")"
    if [[ "$registered" == no ]]; then
      "$GUARD" agent-register --db "$DB" --agent-id "$WORKLOAD_ID" \
        --display-name "Live traffic generator" >/dev/null || return 1
    fi
    "$GUARD" run-create --db "$DB" --agent-id "$WORKLOAD_ID" --run-id "$RUN_ID" \
      --agent-revision "live-1" --task-profile "$TASK_PROFILE" >/dev/null || return 1
  fi
  gw sandbox create --name "$name" --from "$IMAGE" --policy "$POLICY" \
    --no-auto-providers --no-tty --detach -- /usr/bin/sleep infinity >/dev/null 2>&1 || return 1
  tmp="$(mktemp)"
  gw sandbox get "$name" --output json >"$tmp" || return 1
  SANDBOX_ID="$(python3 "$FIXTURE_PY" sandbox-id "$tmp")"; rm -f "$tmp"
  [[ -n "$SANDBOX_ID" ]] || return 1
  # Bind before any traffic; unbound traffic fails closed.
  if rg_principal_mode; then
    # The sidecar binds the sandbox itself, from its workspace and creating principal.
    WORKLOAD_ID="$(rg_wait_bound "$DB" "$SANDBOX_ID")" || return 1
    RUN_ID="run-$SANDBOX_ID"
  else
    "$GUARD" run-bind --db "$DB" --run-id "$RUN_ID" --sandbox-id "$SANDBOX_ID" \
      --gateway-id "$GATEWAY_ID" >/dev/null || return 1
  fi
  SANDBOX_NAME="$name"
  printf 'SANDBOX_NAME=%s\nRUN_ID=%s\nSANDBOX_ID=%s\n' "$SANDBOX_NAME" "$RUN_ID" "$SANDBOX_ID" >"$ENVFILE"
  log "created workload '$WORKLOAD_ID': run $RUN_ID, sandbox $SANDBOX_NAME"
}

ensure_workload() {
  if [[ -f "$ENVFILE" ]]; then
    # shellcheck disable=SC1090
    . "$ENVFILE"
    if [[ -n "$SANDBOX_ID" ]] && bound_in_db "$SANDBOX_ID" && [[ -n "$(sandbox_phase "$SANDBOX_NAME")" ]]; then
      wait_ready "$SANDBOX_NAME" && return 0
    fi
    log "previous sandbox is gone or no longer bound (evidence reset?); creating a new one"
    rm -f "$ENVFILE"
  fi
  create_workload || { log "could not create the workload sandbox"; return 1; }
  wait_ready "$SANDBOX_NAME"
}

sx() { timeout 90 "$CLI" --gateway-endpoint "$ENDPOINT" sandbox exec --name "$SANDBOX_NAME" --no-tty --no-login-shell -- "$@"; }

http_code() { sx /usr/bin/curl --noproxy '*' --silent --max-time 20 --output /dev/null --write-out '%{http_code}' "$@" 2>/dev/null | tail -1; }

act_read() {
  local code; code="$(http_code "$TARGET/repos/local/review/issues")"
  log "READ    GET    /repos/local/review/issues        -> HTTP ${code:-none}  (expected 200: allowed by OpenShell and Risk Guard)"
}
act_delete() {
  local code; code="$(http_code --request DELETE "$TARGET/repos/local/production")"
  log "DELETE  DELETE /repos/local/production           -> HTTP ${code:-none}  (expected 403: OpenShell allows it, Risk Guard denies it)"
}
act_static() {
  local code; code="$(http_code "$TARGET/repos/local/production/secrets")"
  log "BLOCKED GET    /repos/local/production/secrets   -> HTTP ${code:-none}  (expected 403: OpenShell's static policy; Risk Guard never sees it)"
}
act_fs() {
  local out
  out="$(sx /bin/bash -c '
t() { if "$@" >/dev/null 2>&1; then echo allowed; else echo blocked; fi; }
echo "write /tmp      $(t sh -c "echo ok > /tmp/live-traffic.txt")"
echo "write /sandbox  $(t sh -c "echo ok > /sandbox/live-traffic.txt")"
echo "read  /etc      $(t cat /etc/hostname)"
echo "write /etc      $(t sh -c "echo x > /etc/rail-guard-demo")"
echo "write /usr      $(t sh -c "echo x > /usr/rail-guard-demo")"
' 2>&1)"
  log "FILES   sandbox filesystem (enforced by Landlock; not scored by Risk Guard):"
  printf '%s\n' "$out" | sed 's/^/                 /'
}

cycle_once() { act_read; act_delete; act_static; act_fs; }

pick_action() {
  # 6 reads, 1 delete, 1 blocked route, 2 filesystem checks per 10 cycles.
  local n=$((RANDOM % 10))
  if   (( n < 6 )); then act_read
  elif (( n == 6 )); then act_delete
  elif (( n == 7 )); then act_static
  else act_fs
  fi
}

run_loop() {
  printf '%s\n' "$$" >"$PIDFILE"
  trap 'rm -f "$PIDFILE"; log "traffic generator stopped"; exit 0' TERM INT
  log "traffic generator started for workload '$WORKLOAD_ID' (one action every ${MIN_SECONDS}-${MAX_SECONDS}s)"
  local first=1 wait_s
  while true; do
    if ! stack_ready; then log "demo stack is not ready; waiting"; sleep 15; continue; fi
    if ensure_workload; then
      if (( first )); then act_read; first=0; else pick_action; fi
    else
      log "workload sandbox is not ready; will retry"
    fi
    wait_s=$(( MIN_SECONDS + RANDOM % (MAX_SECONDS - MIN_SECONDS + 1) ))
    sleep "$wait_s" &
    wait $!
  done
}

status() {
  local pid; pid="$(running_pid || true)"
  if [[ -n "$pid" ]]; then echo "generator: running (pid $pid)"; else echo "generator: not running"; fi
  [[ -f "$ENVFILE" ]] && sed 's/^/  /' "$ENVFILE"
  if [[ -f "$ENVFILE" ]]; then
    # shellcheck disable=SC1090
    . "$ENVFILE"
    python3 - "$DB" "$SANDBOX_ID" <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    rows = c.execute("""SELECT outcome, COUNT(*) FROM decisions
                        WHERE sandbox_id = ? GROUP BY 1 ORDER BY 1""", (sys.argv[2],)).fetchall()
    print("  decisions recorded by Risk Guard:", dict(rows) if rows else "none yet")
except Exception as error:
    print("  decisions: unavailable (%s)" % error)
PY
  fi
  echo "--- last log lines ---"; tail -n 8 "$LOG" 2>/dev/null || echo "(no log yet)"
}

mkdir -p "$STATE/logs" "$STATE/pids"
case "${1:-status}" in
  run)   run_loop ;;
  start)
    [[ -x "$CLI" && -x "$GUARD" ]] || { echo "missing demo binaries in $ASSETS" >&2; exit 1; }
    stack_ready || { echo "the demo stack is not running; start it first (rail-guard-demo --start)" >&2; exit 1; }
    if pid="$(running_pid)"; then echo "already running (pid $pid); log: $LOG"; exit 0; fi
    [[ "${2:-}" =~ ^[0-9]+$ ]] && MIN_SECONDS="$2"
    [[ "${3:-}" =~ ^[0-9]+$ ]] && MAX_SECONDS="$3"
    (( MAX_SECONDS >= MIN_SECONDS && MIN_SECONDS >= 5 )) || { echo "need 5 <= min <= max seconds" >&2; exit 1; }
    TRAFFIC_MIN_SECONDS="$MIN_SECONDS" TRAFFIC_MAX_SECONDS="$MAX_SECONDS" \
      nohup setsid bash "${BASH_SOURCE[0]}" run >>"$LOG" 2>&1 </dev/null &
    sleep 2
    if pid="$(running_pid)"; then echo "started (pid $pid): one action every ${MIN_SECONDS}-${MAX_SECONDS}s; log: $LOG"
    else echo "did not start; see $LOG" >&2; exit 1; fi ;;
  stop)
    if pid="$(running_pid)"; then kill "$pid"; echo "stopped (pid $pid). The workload, sandbox and evidence are kept."
    else echo "not running"; fi ;;
  once)
    stack_ready || { echo "the demo stack is not running" >&2; exit 1; }
    ensure_workload || exit 1
    cycle_once ;;
  reset)
    if running_pid >/dev/null; then echo "stop the generator first" >&2; exit 1; fi
    rm -f "$ENVFILE"; echo "forgot the saved sandbox; the next start creates a fresh workload sandbox (the old one is left in place)." ;;
  status) status ;;
  *) echo "usage: $0 start [min_seconds] [max_seconds] | stop | status | once | reset" >&2; exit 2 ;;
esac
