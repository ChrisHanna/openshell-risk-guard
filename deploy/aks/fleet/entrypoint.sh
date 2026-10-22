#!/usr/bin/env bash
# Start point of the in-cluster agent fleet (deploy/aks/fleet.yaml): register the gateway with the `openshell` CLI, then run
# scripts/aks/agent-fleet.sh, the same loop that can also be run by hand from a workstation.
#
# The pod holds the cluster's own client certificate (Secret openshell-client-tls, mounted read-only) and reaches the gateway
# by its Service name. The gateway's certificate is valid for `localhost`, not for the Service name, so the CLI connects to
# localhost and a small relay hands the bytes to the Service; TLS still runs end to end between the CLI and the gateway.
set -euo pipefail

GATEWAY_ADDR="${GATEWAY_ADDR:-openshell.openshell.svc.cluster.local:8080}"
LOCAL_PORT="${LOCAL_PORT:-18080}"
# The CLI keeps its gateway registrations under $HOME/.config (it does not honor XDG_CONFIG_HOME).
export HOME=/tmp/fleet OPENSHELL_GATEWAY=aks
CFG="$HOME/.config/openshell/gateways/aks"

umask 077
mkdir -p "$CFG/mtls"
for f in ca.crt tls.crt tls.key; do
  [ -s "/etc/fleet/client-tls/$f" ] || { echo "missing /etc/fleet/client-tls/$f (Secret openshell-client-tls)" >&2; exit 1; }
  cp "/etc/fleet/client-tls/$f" "$CFG/mtls/$f"
done
cat > "$CFG/metadata.json" <<JSON
{"name": "aks", "gateway_endpoint": "https://localhost:$LOCAL_PORT", "is_remote": false, "gateway_port": 0, "auth_mode": "mtls"}
JSON
echo aks > "$HOME/.config/openshell/active_gateway"

# Keep the relay alive for the life of the pod; if it ever exits it is restarted.
# (socat logs a "broken pipe" whenever a client closes first; that is normal, so its messages are dropped.)
( while :; do socat "TCP-LISTEN:$LOCAL_PORT,bind=127.0.0.1,reuseaddr,fork" "TCP:$GATEWAY_ADDR" 2>/dev/null || true; sleep 1; done ) &

echo "waiting for the gateway at $GATEWAY_ADDR"
ready=0
for _ in $(seq 1 60); do
  if timeout 20 openshell provider get "${PROVIDER:-nvidia-nat}" >/dev/null 2>&1; then ready=1; break; fi
  sleep 5
done
[ "$ready" = 1 ] || { echo "the gateway did not answer, or provider '${PROVIDER:-nvidia-nat}' is missing (run 12-sync-credentials.ps1)" >&2; exit 1; }
echo "gateway ready"

exec bash /opt/fleet/scripts/aks/agent-fleet.sh "$@"
