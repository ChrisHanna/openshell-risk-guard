#!/usr/bin/env bash
# Register the AKS-hosted OpenShell gateway with the `openshell` CLI over mutual TLS.
#
# The chart generates a client certificate bundle in the Secret `openshell-client-tls`. This script
# port-forwards the gateway, registers it, and installs that bundle for the CLI (owner-only files,
# nothing printed). Run it on a machine that has kubectl pointed at the cluster and the openshell CLI:
#   scripts/aks/connect-gateway.sh [namespace] [local-port]
#
# `openshell gateway add --local` writes its own certificates, so the cluster's bundle is installed
# AFTER registration. The gateway's certificate is valid for localhost, so the CLI connects to
# https://localhost:<port> through the port-forward.
#
# WSL note: if kubectl runs on Windows and the CLI in WSL, forward on the WSL-facing Windows address and
# relay it to WSL's localhost (see docs/aks.md).
set -euo pipefail

NS="${1:-openshell}"
PORT="${2:-18080}"
NAME="${GATEWAY_NAME:-aks}"
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
MTLS="$CONFIG_HOME/openshell/gateways/$NAME/mtls"

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 1; }
command -v openshell >/dev/null || { echo "the openshell CLI was not found on PATH" >&2; exit 1; }

if ! (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  kubectl -n "$NS" port-forward svc/openshell "$PORT:8080" >/tmp/openshell-port-forward.log 2>&1 &
  echo "port-forward started (pid $!); stop it with: kill $!"
  sleep 3
fi

openshell gateway add --name "$NAME" --local "https://localhost:$PORT" >/dev/null 2>&1 || true

umask 077
mkdir -p "$MTLS"
for pair in ca.crt:ca\\.crt tls.crt:tls\\.crt tls.key:tls\\.key; do
  file="${pair%%:*}"; key="${pair#*:}"
  kubectl -n "$NS" get secret openshell-client-tls -o "jsonpath={.data.$key}" | base64 -d > "$MTLS/$file"
done
chmod 600 "$MTLS"/*

openshell gateway select "$NAME" >/dev/null
openshell gateway info
echo "--- whoami"
openshell whoami
