#!/usr/bin/env bash
# Run one SPIFFE token-grant sandbox: it calls the alpha and beta services with a short-lived token that its supervisor obtained using the
# sandbox's SPIFFE identity (deploy/aks/token-grant-profile.yaml), holding no stored secret. No model is involved, so it adds nothing to the
# hosted model's rate limit. Risk Guard scores every call. Needs 20-deploy-token-grant-demo.ps1.
#
#   scripts/aks/run-token-agent.sh
set -euo pipefail

CLI="${OPENSHELL_BIN:-openshell}"
ACR="${ACR_SERVER:?set ACR_SERVER, for example myregistry.azurecr.io}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
PROVIDER="${TOKEN_PROVIDER:-spiffe-token-demo}"
AGENT_ID="${TOKEN_AGENT_ID:-spiffe-token-agent}"
POLICY_FILE="$HERE/deploy/aks/agents/token/policy.yaml"
NAME="token-$(date +%H%M%S)"

cleanup_sandbox() { [ "${CLEANUP_SANDBOX:-0}" = 1 ] && "$CLI" sandbox delete "$NAME" >/dev/null 2>&1 || true; }
trap cleanup_sandbox EXIT
trap 'exit 143' TERM INT

"$CLI" provider get "$PROVIDER" >/dev/null 2>&1 || { echo "provider '$PROVIDER' not found; run 20-deploy-token-grant-demo.ps1" >&2; exit 1; }
echo "creating sandbox $NAME (workload $AGENT_ID)"
created=0; last_error=""
for attempt in 1 2 3; do
  last_error="$(timeout 120 "$CLI" sandbox create --name "$NAME" --from "$ACR/openshell-demo/nat-agent:${AGENT_IMAGE_TAG:-3}" \
    --policy "$POLICY_FILE" --provider "$PROVIDER" \
    --annotation "openshell.nvidia.com/agent-id=$AGENT_ID" --annotation "openshell.nvidia.com/agent-name=spiffe-token-agent" \
    --no-tty --detach -- /usr/bin/sleep infinity 2>&1 | tail -n 6)" || true
  if "$CLI" sandbox get "$NAME" >/dev/null 2>&1; then created=1; break; fi
  sleep 10
done
[ "$created" = 1 ] || { echo "could not create the sandbox after 3 attempts:" >&2; echo "$last_error" >&2; exit 1; }

for i in $(seq 1 80); do
  phase=$("$CLI" sandbox get "$NAME" --output json 2>/dev/null | grep -o '"phase": *"[A-Za-z]*"' | head -1 | sed 's/.*: *"//; s/"//' || true)
  [ "$phase" = Ready ] && break
  [ "$phase" = Error ] && { echo "sandbox failed to start" >&2; exit 1; }
  sleep 6
done
[ "${phase:-}" = Ready ] || { echo "sandbox did not become ready" >&2; exit 1; }

# A random handful of calls: mostly routine reads, now and then one it should not make. The sandbox has no token of its own: the supervisor
# attaches one for these hosts, using its SPIFFE identity.
SCRIPT='
import random, urllib.request, urllib.error
routine = ["GET /records", "GET /records/1", "GET /records/2", "GET /records/7"]
unwanted = ["DELETE /records/1", "DELETE /records/7", "GET /admin/export"]
for _ in range(random.randint(3, 6)):
    request = random.choice(unwanted) if random.random() < 0.2 else random.choice(routine)
    method, path = request.split(" ")
    host = random.choice(["alpha", "beta"])
    try:
        response = urllib.request.urlopen(urllib.request.Request("http://%s.openshell.svc.cluster.local%s" % (host, path), method=method), timeout=20)
        print(method, host, path, "->", response.status, response.read(80).decode().replace(chr(10), " "))
    except urllib.error.HTTPError as error:
        print(method, host, path, "->", error.code, error.read(80).decode().replace(chr(10), " "))
    except Exception as error:
        print(method, host, path, "-> failed:", error)
'
"$CLI" sandbox exec --name "$NAME" --no-tty --no-login-shell -- /opt/agent/bin/python3.12 -c "$SCRIPT" 2>&1 | tail -n 12
echo "sandbox: $NAME"
