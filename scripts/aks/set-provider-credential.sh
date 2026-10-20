#!/usr/bin/env bash
# Store an agent credential in OpenShell's provider store without it touching a file, your shell history,
# or a chat window. The value is read silently, exported only for the one `openshell` command that needs it,
# and then discarded.
#
#   scripts/aks/set-provider-credential.sh [--stdin] <provider-profile.yaml> <provider-name> <ENV_VAR>
#
# With --stdin the value is read from standard input instead of a hidden prompt (12-sync-credentials.ps1
# uses this to copy a Key Vault secret in without it touching a file or command line).
#
# Example (the NVIDIA key for the NeMo Agent Toolkit demo agent):
#   scripts/aks/set-provider-credential.sh deploy/rail-guard-demo/agent/nvidia-nat-provider.yaml nvidia-nat NVIDIA_API_KEY
#
# Where the credential lives: in the gateway's credential store, encrypted with the key in the Secret
# `openshell-credential-storage-key-encryption-key`. Sandboxes receive an opaque placeholder, and OpenShell
# substitutes the real value only on requests to the hosts, paths and binaries the profile allows.
# Rotate by running this script again for the same provider.
#
# Requires the `openshell` CLI registered against the gateway (scripts/aks/connect-gateway.sh).
set -euo pipefail

STDIN=0
if [ "${1:-}" = "--stdin" ]; then STDIN=1; shift; fi
if [ "$#" -ne 3 ]; then
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
PROFILE="$1"; NAME="$2"; VAR="$3"

OPENSHELL="${OPENSHELL_BIN:-openshell}"
command -v "$OPENSHELL" >/dev/null || { echo "the openshell CLI was not found (set OPENSHELL_BIN or put it on PATH)" >&2; exit 1; }
[ -f "$PROFILE" ] || { echo "profile not found: $PROFILE" >&2; exit 1; }
[[ "$VAR" =~ ^[A-Z][A-Z0-9_]*$ ]] || { echo "ENV_VAR must look like NVIDIA_API_KEY" >&2; exit 1; }

TYPE="$(awk -F': *' '/^id:/ {print $2; exit}' "$PROFILE" | tr -d '"'"'"' ')"
[ -n "$TYPE" ] || { echo "no 'id:' line in $PROFILE" >&2; exit 1; }

echo "Importing profile '$TYPE' ..."
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
if ! "$OPENSHELL" provider profile import -f "$PROFILE" >"$LOG" 2>&1; then
  # Already imported: update it in place. Anything else is a real error, so show it.
  "$OPENSHELL" provider profile update "$TYPE" -f "$PROFILE" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
fi

if [ "$STDIN" = 1 ]; then
  IFS= read -r SECRET || true
  SECRET="$(printf '%s' "$SECRET" | tr -d '
')"
else
  read -rsp "Value for $VAR (input is hidden): " SECRET
  echo
fi
[ -n "$SECRET" ] || { echo "empty value, nothing stored" >&2; exit 1; }

if "$OPENSHELL" provider get "$NAME" >/dev/null 2>&1; then
  echo "Provider '$NAME' exists; updating its credential ..."
  env "$VAR=$SECRET" "$OPENSHELL" provider update "$NAME" --from-existing >/dev/null
else
  echo "Creating provider '$NAME' ..."
  env "$VAR=$SECRET" "$OPENSHELL" provider create --name "$NAME" --type "$TYPE" --from-existing >/dev/null
fi
unset SECRET
echo "Stored. Attach it to a sandbox with: openshell sandbox create --provider $NAME ..."
