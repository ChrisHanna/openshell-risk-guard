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
# No OpenShell checkout is needed. The revision this script stages must be the one Cargo.toml pins, and the binaries come from
# scripts/install-openshell-cli.sh --all (built from that commit), or from a local build in $TARGET/debug.
PINNED="$(grep -oE 'rev = "[0-9a-f]{40}"' "$ROOT/Cargo.toml" | head -1 | grep -oE '[0-9a-f]{40}')"
[[ "$PINNED" == "$REVISION" ]] || fail "This script stages OpenShell $REVISION but Cargo.toml pins ${PINNED:-nothing}"
for checkout in "${OPENSHELL_REPO:-}" "$ROOT/OpenShell" "$ROOT/../OpenShell"; do
  if [[ -n "$checkout" && -d "$checkout/.git" ]]; then
    [[ "$(git -C "$checkout" rev-parse HEAD)" == "$REVISION" ]] ||
      fail "The OpenShell checkout at $checkout is not at $REVISION"
  fi
done
[[ -S "$DOCKER_SOCKET" ]] || fail "Start the isolated demo daemon first: $DOCKER_SOCKET"
DOCKER=(docker --host "unix://$DOCKER_SOCKET")
INFO="$("${DOCKER[@]}" info --format '{{json .SecurityOptions}}')"
[[ "$INFO" != *rootless* ]] || fail 'The demo assets belong in the isolated rootful daemon.'
# Where each binary comes from: a local debug build if there is one, else the ones scripts/install-openshell-cli.sh --all installed.
declare -A SOURCE
for binary in openshell openshell-gateway openshell-supervisor openshell-sandbox; do
  if [[ -x "$TARGET/debug/$binary" ]]; then SOURCE[$binary]="$TARGET/debug/$binary"
  elif [[ -x "$ASSETS/bin/$binary" ]]; then SOURCE[$binary]="$ASSETS/bin/$binary"
  else fail "Missing $binary: run scripts/install-openshell-cli.sh --all (or build it into $TARGET/debug)"
  fi
done
[[ -x "$GUARD_TARGET/debug/openshell-risk-guard" ]] ||
  fail "Missing build output: $GUARD_TARGET/debug/openshell-risk-guard"
umask 077
mkdir -p "$ASSETS/bin"
for binary in openshell openshell-gateway openshell-supervisor openshell-sandbox; do
  [[ "${SOURCE[$binary]}" -ef "$ASSETS/bin/$binary" ]] || install -m 0755 "${SOURCE[$binary]}" "$ASSETS/bin/$binary"
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
