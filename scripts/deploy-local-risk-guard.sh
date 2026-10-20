#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Native Linux only. No image pulls/builds, uploads, clouds or resource deletion.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -d "$ROOT/deploy/local" ]]; then
  ASSETS="$ROOT/deploy/local"
else
  ASSETS="$ROOT/openshell-risk-guard/deploy/local"
fi
ACTION="${1:---check}"
fail() { printf 'BLOCKED: %s\n' "$*" >&2; exit 1; }
case "$ACTION" in
  --help)
    printf '%s\n' 'Usage: bash scripts/deploy-local-risk-guard.sh [--check|--start --allow-insecure-local-test]' \
      'See openshell-risk-guard/deploy/local/OPERATIONS.md for mandatory environment inputs.'
    exit 0 ;;
  --check) [[ $# -le 1 ]] || fail 'Unexpected arguments.' ;;
  --start) [[ $# = 2 && $2 = --allow-insecure-local-test ]] ||
    fail 'Start requires explicit --allow-insecure-local-test consent.' ;;
  *) fail 'Unknown action. Use --help.' ;;
esac
[[ "$(uname -s)" = Linux ]] || fail 'Run inside a qualified Linux host/VM, not Windows Bash.'
GATEWAY_BIN="${GATEWAY_BIN:-openshell-gateway}"
CLI_BIN="${CLI_BIN:-openshell}"
RISK_GUARD_BIN="${RISK_GUARD_BIN:-openshell-risk-guard}"
for tool in "$GATEWAY_BIN" "$CLI_BIN" docker curl timeout realpath grep; do
  command -v "$tool" >/dev/null || fail "Missing executable: $tool"
done
# Installed 0.0.116 predates this checkout's schema/preflight contract.
"$GATEWAY_BIN" config preflight --help >/dev/null 2>&1 ||
  fail 'Gateway lacks config preflight. Install/build the gateway matching this OpenShell checkout; no old-schema fallback.'
command -v "$RISK_GUARD_BIN" >/dev/null || fail "Missing executable: $RISK_GUARD_BIN"
"$RISK_GUARD_BIN" baseline-import --help >/dev/null 2>&1 ||
  fail 'Risk Guard lacks baseline-import; build the operational CLI from this checkout.'
DOCKER_SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"
[[ "$DOCKER_SOCKET" = /* && -S "$DOCKER_SOCKET" ]] ||
  fail 'DOCKER_SOCKET must name an existing local Unix Docker API socket.'
DOCKER=(docker --host "unix://$DOCKER_SOCKET")
INFO="$("${DOCKER[@]}" info --format '{{.OSType}} {{json .SecurityOptions}}' 2>&1)" ||
  fail "Docker daemon unavailable: $INFO"
[[ "$INFO" = linux* ]] || fail 'Linux Docker daemon required.'
[[ "$INFO" != *rootless* ]] ||
  fail 'This loopback recipe requires native-host networking; rootless Docker host networking is in its own namespace and is not qualified here.'
for name in WORKLOAD_IMAGE SANDBOX_RUNTIME_IMAGE SUPERVISOR_IMAGE BASELINE_PROFILE; do
  [[ -n "${!name:-}" ]] || fail "Set $name; this script never pulls images or manufactures baselines."
done
for image in "$WORKLOAD_IMAGE" "$SANDBOX_RUNTIME_IMAGE" "$SUPERVISOR_IMAGE"; do
  [[ "$image" =~ ^[a-zA-Z0-9_./:@-]+$ && "$image" != *:latest ]] ||
    fail "Use a safe explicit version/digest, not latest: $image"
  "${DOCKER[@]}" image inspect "$image" >/dev/null 2>&1 ||
    fail "Image not preloaded in selected daemon: $image"
done
[[ -r "$BASELINE_PROFILE" ]] || fail 'BASELINE_PROFILE must be an operator-approved JSON artifact.'
STATE_DIR="${STATE_DIR:-$ASSETS/state}"
STATE_DIR="$(realpath -m "$STATE_DIR")"
[[ "$STATE_DIR" = "$ROOT/"* && "$STATE_DIR" =~ ^[a-zA-Z0-9_./-]+$ &&
   "$STATE_DIR" != *'/../'* && "$STATE_DIR" != */.. ]] ||
  fail 'STATE_DIR must be an absolute path below this checkout without spaces or traversal.'
[[ "$DOCKER_SOCKET" =~ ^[a-zA-Z0-9_./-]+$ ]] || fail 'Unsupported socket path characters.'
printf '%s\n' 'Prerequisites passed. Kernel isolation is actively qualified by OpenShell only at sandbox launch.'
if [[ "$ACTION" = --check ]]; then
  printf '%s\n' 'No files, services, images, gateways or sandboxes were changed. Start still requires explicit local-test consent.'
  exit 0
fi
# Fresh directory only: do not overwrite another deployment, signing key or DB.
[[ ! -e "$STATE_DIR" ]] || fail "State already exists: $STATE_DIR. Inspect it; choose a fresh STATE_DIR."
umask 077
mkdir -p "$STATE_DIR"
DB="$STATE_DIR/risk-guard.db"
export OPENSHELL_DB_URL="sqlite://$STATE_DIR/gateway.db"
export OPENSHELL_LOCAL_TLS_DIR="$STATE_DIR/tls"
export XDG_STATE_HOME="$STATE_DIR/xdg-state" XDG_CONFIG_HOME="$STATE_DIR/xdg-config"
# Avoid inherited operator overrides silently redirecting this bounded recipe.
while IFS= read -r name; do
  case "$name" in
    OPENSHELL_DB_URL|OPENSHELL_LOCAL_TLS_DIR) ;;
    OPENSHELL_*) fail "Unset inherited override $name before starting." ;;
  esac
done < <(compgen -e)
"$GATEWAY_BIN" generate-certs --output-dir "$STATE_DIR/tls" >"$STATE_DIR/certgen.log" 2>&1
"$RISK_GUARD_BIN" local-secrets-generate --out-dir "$STATE_DIR/risk-guard-tls" \
  --san 127.0.0.1 --san localhost >"$STATE_DIR/risk-guard-secrets.json"
CONFIG="$(<"$ASSETS/gateway.toml.in")"
for name in STATE_DIR DOCKER_SOCKET WORKLOAD_IMAGE SANDBOX_RUNTIME_IMAGE SUPERVISOR_IMAGE; do
  token="@$name@"
  CONFIG="${CONFIG//$token/${!name}}"
done
printf '%s\n' "$CONFIG" >"$STATE_DIR/gateway.toml"
"$GATEWAY_BIN" config preflight --path "$STATE_DIR/gateway.toml"
"$RISK_GUARD_BIN" baseline-import --db "$DB" --profile "$BASELINE_PROFILE" >"$STATE_DIR/baseline-import.json"
PIDS=()
stop_owned() {
  trap - EXIT INT TERM
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap stop_owned EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Refuse occupied ports; never kill pre-existing processes.
for port in 50061 17671; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    fail "Loopback port $port already occupied."
  fi
done
"$RISK_GUARD_BIN" serve --listen 127.0.0.1:50061 --db "$DB" \
  --gateway-id risk-guard-local --audience urn:openshell:extension:risk-guard \
  --default-task-profile local-repo-review \
  --public-key-pem "$STATE_DIR/tls/jwt/public.pem" \
  --tls-cert "$STATE_DIR/risk-guard-tls/tls.crt" --tls-key "$STATE_DIR/risk-guard-tls/tls.key" \
  --hmac-key-file "$STATE_DIR/risk-guard-tls/hmac.key" \
  >"$STATE_DIR/risk-guard.log" 2>&1 &
PIDS+=("$!")
for ((i=0; i<30; i++)); do
  kill -0 "${PIDS[0]}" 2>/dev/null || fail "Risk Guard exited; see $STATE_DIR/risk-guard.log"
  if (exec 3<>/dev/tcp/127.0.0.1/50061) 2>/dev/null; then break; fi
  sleep 1
done
(( i < 30 )) || fail 'Risk Guard did not bind within 30 seconds.'
# Gateway performs extension-protocol Describe negotiation (transport is
# deliberately unauthenticated here) and fails startup on incompatible services.
"$GATEWAY_BIN" --config "$STATE_DIR/gateway.toml" >"$STATE_DIR/gateway.log" 2>&1 &
PIDS+=("$!")
for ((i=0; i<60; i++)); do
  kill -0 "${PIDS[1]}" 2>/dev/null || fail "Gateway exited; see $STATE_DIR/gateway.log"
  if curl --silent --fail --max-time 2 http://127.0.0.1:17671/readyz >/dev/null; then break; fi
  sleep 1
done
(( i < 60 )) || fail "Gateway not ready; inspect $STATE_DIR/gateway.log"
# Live runtime info is evidence of BOTH registered extension families. Do not
# replace this with a dashboard HTTP poll.
timeout 20 "$CLI_BIN" --gateway-endpoint http://127.0.0.1:17671 gateway info \
  >"$STATE_DIR/gateway-info.txt"
grep -Fq 'risk-guard-governance (gateway-interceptor)' "$STATE_DIR/gateway-info.txt" ||
  fail "Gateway did not report the interceptor; inspect $STATE_DIR/gateway-info.txt"
grep -Fq 'risk-guard (supervisor-middleware)' "$STATE_DIR/gateway-info.txt" ||
  fail "Gateway did not report the middleware; inspect $STATE_DIR/gateway-info.txt"
printf '%s\n' "Gateway ready; BOTH extensions reported in $STATE_DIR/gateway-info.txt." \
  "Risk database: $DB" \
  'No sandbox has been created yet. Follow OPERATIONS.md to exercise actual supervisor traffic.' \
  'Foreground owner: Ctrl-C stops only these two processes; all state and sandbox resources are retained.'
wait -n "${PIDS[@]}"
fail 'A service exited; inspect logs. State and sandbox resources were retained.'
