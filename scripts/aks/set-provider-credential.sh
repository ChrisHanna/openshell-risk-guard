#!/usr/bin/env bash
# Store an agent credential in OpenShell's provider store without it touching a file, your shell history,
# or a chat window. The value is read silently, exported only for the one `openshell` command that needs it,
# and then discarded.
#
#   scripts/aks/set-provider-credential.sh <provider-profile.yaml> <provider-name> <ENV_VAR>
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

if [ "$#" -ne 3 ]; then
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
PROFILE="$1"; NAME="$2"; VAR="$3"

command -v openshell >/dev/null || { echo "the openshell CLI was not found on PATH" >&2; exit 1; }
[ -f "$PROFILE" ] || { echo "profile not found: $PROFILE" >&2; exit 1; }
[[ "$VAR" =~ ^[A-Z][A-Z0-9_]*$ ]] || { echo "ENV_VAR must look like NVIDIA_API_KEY" >&2; exit 1; }

TYPE="$(awk -F': *' '/^id:/ {print $2; exit}' "$PROFILE" | tr -d '"'"'"' ')"
[ -n "$TYPE" ] || { echo "no 'id:' line in $PROFILE" >&2; exit 1; }

echo "Importing profile '$TYPE' ..."
openshell provider profile import -f "$PROFILE" >/dev/null 2>&1 \
  || openshell provider profile update -f "$PROFILE" >/dev/null

read -rsp "Value for $VAR (input is hidden): " SECRET
echo
[ -n "$SECRET" ] || { echo "empty value, nothing stored" >&2; exit 1; }

if openshell provider get "$NAME" >/dev/null 2>&1; then
  echo "Provider '$NAME' exists; updating its credential ..."
  env "$VAR=$SECRET" openshell provider update "$NAME" --from-existing >/dev/null
else
  echo "Creating provider '$NAME' ..."
  env "$VAR=$SECRET" openshell provider create --name "$NAME" --type "$TYPE" --from-existing >/dev/null
fi
unset SECRET
echo "Stored. Attach it to a sandbox with: openshell sandbox create --provider $NAME ..."
