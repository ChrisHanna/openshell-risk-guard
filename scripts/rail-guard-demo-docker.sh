#!/usr/bin/env bash
# Root-only, isolated Docker owner. Never touches contexts, systemd or firewall.
set -euo pipefail
ACTION="${1:---check}"
RUN=/run/openshell-risk-guard-demo
DATA=/var/lib/openshell-risk-guard-demo/docker
SOCKET="$RUN/docker.sock"
DOCKERD_BIN="${DOCKERD_BIN:-$HOME/bin/dockerd}"
DOCKER_BIN="${DOCKER_BIN:-$HOME/bin/docker}"
fail() { printf 'BLOCKED: %s\n' "$*" >&2; exit 1; }
[[ "$(uname -s)" = Linux && "$EUID" = 0 ]] || fail 'Use native Linux as root.'
[[ $# -le 1 ]] || fail 'Unexpected arguments.'
[[ "$ACTION" = --check || "$ACTION" = --start ]] || fail 'Use --check or foreground --start.'
for binary in "$DOCKERD_BIN" "$DOCKER_BIN"; do
  [[ "$binary" = /* && -x "$binary" ]] || fail "Set an absolute executable binary path: $binary"
done
getent group docker >/dev/null || fail 'Pre-provision the docker group; this helper never changes membership.'
export PATH="$(dirname "$DOCKERD_BIN"):$(dirname "$DOCKER_BIN"):$PATH"
live() {
  [[ -S "$SOCKET" ]] &&
    "$DOCKER_BIN" --host "unix://$SOCKET" info --format '{{.OSType}} {{json .SecurityOptions}}' 2>/dev/null
}
if INFO="$(live)"; then
  [[ "$INFO" = linux* && "$INFO" != *rootless* ]] || fail 'Selected daemon must be rootful Linux.'
  [[ "$(stat -c '%U:%G:%a' "$RUN")" = root:docker:750 &&
     "$(stat -c '%U:%G:%a' "$SOCKET")" = root:docker:660 ]] ||
    fail 'Isolated daemon directory/socket permissions must be root:docker 0750/0660.'
  printf '%s\n' "Isolated rootful Docker ready: $SOCKET"
  exit 0
fi
[[ "$ACTION" = --start ]] || fail "Isolated daemon unavailable at $SOCKET"
[[ ! -L "$RUN" && ! -L "${DATA%/docker}" && ! -L "$DATA" ]] ||
  fail 'Refusing symlinked daemon state.'
if [[ -f "$RUN/docker.pid" ]]; then
  read -r previous <"$RUN/docker.pid"
  [[ "$previous" =~ ^[0-9]+$ ]] || fail 'Malformed PID file; inspect it manually.'
  ! kill -0 "$previous" 2>/dev/null || fail "Existing PID $previous is alive; inspect it manually."
fi
umask 027
install -d -m 0750 -o root -g docker "$RUN"
install -d -m 0700 -o root -g root "$DATA"
LAUNCH_TOKEN="${RAIL_GUARD_DEMO_LAUNCH_TOKEN:-$(cat /proc/sys/kernel/random/uuid)}"
[[ "$LAUNCH_TOKEN" =~ ^[a-zA-Z0-9-]+$ ]] || fail 'Invalid launcher ownership token.'
printf '%s\n' "$LAUNCH_TOKEN" >"$RUN/owner-token"
PID=
cleanup() {
  trap - EXIT INT TERM
  if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -f "$RUN/owner-token"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$DOCKERD_BIN" --config-file=/dev/null --host="unix://$SOCKET" --data-root="$DATA" \
  --exec-root="$RUN/exec" --pidfile="$RUN/docker.pid" \
  --bridge=none --iptables=false --ip6tables=false --ip-forward=false \
  --ip-masq=false --group=docker &
PID=$!
for ((i=0; i<60; i++)); do
  kill -0 "$PID" 2>/dev/null || fail 'Isolated dockerd exited.'
  # dockerd can tighten its parent directory during listener setup.
  chown root:docker "$RUN"
  chmod 0750 "$RUN"
  if INFO="$(live)"; then
    [[ "$INFO" = linux* && "$INFO" != *rootless* ]] || fail 'Unexpected daemon identity.'
    chown root:docker "$SOCKET"
    chmod 0660 "$SOCKET"
    printf '%s\n' "Isolated daemon ready; foreground owner PID $PID."
    wait "$PID"
    exit $?
  fi
  sleep 1
done
fail 'Isolated dockerd did not become ready in 60 seconds.'
