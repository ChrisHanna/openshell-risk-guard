#!/usr/bin/env bash
# One-time preparation. Demo startup must never invoke this script.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REVISION=55bf786453395f3fe1858a187152537b457de77d
ASSETS="${RAIL_GUARD_DEMO_ASSETS:-$HOME/openshell-demo}"
TARGET="${OPENSHELL_BUILD_TARGET:-$HOME/openshell-demo-target}"
GUARD_TARGET="${RISK_GUARD_BUILD_TARGET:-$HOME/rg-target}"
DOCKER_SOCKET="${DOCKER_SOCKET:-/run/openshell-risk-guard-demo/docker.sock}"
export PATH="$HOME/bin:$PATH"
fail() { printf 'PREPARATION FAILED: %s\n' "$*" >&2; exit 1; }
[[ $# == 0 ]] || fail 'Usage: bash scripts/prepare-rail-guard-demo-assets.sh (consumes already built binaries)'
OPENSHELL_REPO="$ROOT/OpenShell"
[[ -d "$OPENSHELL_REPO" ]] || OPENSHELL_REPO="$ROOT/../OpenShell"
[[ "$(git -C "$OPENSHELL_REPO" rev-parse HEAD)" == "$REVISION" ]] ||
  fail "Expected OpenShell source revision $REVISION"
[[ -S "$DOCKER_SOCKET" ]] || fail "Start the isolated demo daemon first: $DOCKER_SOCKET"
DOCKER=(docker --host "unix://$DOCKER_SOCKET")
INFO="$("${DOCKER[@]}" info --format '{{json .SecurityOptions}}')"
[[ "$INFO" != *rootless* ]] || fail 'The demo assets belong in the isolated rootful daemon.'
for binary in openshell openshell-gateway openshell-supervisor openshell-sandbox; do
  [[ -x "$TARGET/debug/$binary" ]] || fail "Missing build output: $TARGET/debug/$binary"
done
[[ -x "$GUARD_TARGET/debug/openshell-risk-guard" ]] ||
  fail "Missing build output: $GUARD_TARGET/debug/openshell-risk-guard"
umask 077
mkdir -p "$ASSETS/bin"
for binary in openshell openshell-gateway openshell-supervisor openshell-sandbox; do
  install -m 0755 "$TARGET/debug/$binary" "$ASSETS/bin/$binary"
done
install -m 0755 "$GUARD_TARGET/debug/openshell-risk-guard" "$ASSETS/bin/openshell-risk-guard"
"$ASSETS/bin/openshell-gateway" config preflight --help >/dev/null
"$ASSETS/bin/openshell-risk-guard" run-bind --help >/dev/null
for stage in workload sandbox supervisor; do
  "${DOCKER[@]}" build --network host --target "$stage" \
    -t "risk-guard-demo/$stage:55bf78645" \
    -f "$ROOT/scripts/rail-guard-demo-assets.Dockerfile" "$ASSETS"
done
python3 - "$ASSETS" "$DOCKER_SOCKET" "$REVISION" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

assets, socket, revision = sys.argv[1:]
root = Path(assets)
images = {}
for stage in ("workload", "sandbox", "supervisor"):
    tag = f"risk-guard-demo/{stage}:55bf78645"
    images[tag] = json.loads(subprocess.check_output(
        ["docker", "--host", f"unix://{socket}", "image", "inspect", tag]
    ))[0]["Id"]
manifest = {
    "source_revision": revision,
    "binaries": {
        path.name: hashlib.file_digest(path.open("rb"), "sha256").hexdigest()
        for path in sorted((root / "bin").iterdir()) if path.is_file()
    },
    "images": images,
}
temporary = root / "assets.json.tmp"
temporary.write_text(json.dumps(manifest, indent=2) + "\n")
temporary.replace(root / "assets.json")
PY
# Preserve a portable image archive, so recovery need not contact a registry.
"${DOCKER[@]}" image save -o "$ASSETS/images.tar.tmp" \
  risk-guard-demo/workload:55bf78645 \
  risk-guard-demo/sandbox:55bf78645 \
  risk-guard-demo/supervisor:55bf78645
mv "$ASSETS/images.tar.tmp" "$ASSETS/images.tar"
printf 'Prepared binaries, immutable image manifest, and offline image archive: %s\n' "$ASSETS"
