#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
#
# Install the `openshell` CLI built from the exact OpenShell commit this repository is pinned to (Cargo.toml). No OpenShell
# checkout is needed: Cargo fetches the source from NVIDIA's public repository.
#
#   scripts/install-openshell-cli.sh [--all] [install-root]    # default root: $HOME/openshell-demo
#
# By default only the `openshell` CLI is installed ($HOME/openshell-demo/bin/openshell), which is what the Azure fleet needs.
# With --all it also installs openshell-gateway, openshell-supervisor and openshell-sandbox: the four binaries the local demo
# stack runs (see docs/demo.md). That is a larger build.
#
# The CLI and the gateway must come from the same commit; a different version fails with protobuf decode errors. Build time is
# several minutes the first time. Needs Rust, a C++ toolchain and cmake (see docs/getting-started.md).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATES=(openshell-cli)
if [ "${1:-}" = "--all" ]; then CRATES=(openshell-cli openshell-gateway openshell-supervisor openshell-sandbox); shift; fi
ROOT="${1:-$HOME/openshell-demo}"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v cargo >/dev/null || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }

REV="$(grep -oE 'rev = "[0-9a-f]{40}"' "$HERE/Cargo.toml" | head -1 | grep -oE '[0-9a-f]{40}')"
[ -n "$REV" ] || { echo "no pinned OpenShell commit found in Cargo.toml" >&2; exit 1; }

echo "Installing ${CRATES[*]} from NVIDIA/OpenShell at ${REV:0:9} into $ROOT/bin"
cargo install --git https://github.com/NVIDIA/OpenShell --rev "$REV" --locked --root "$ROOT" "${CRATES[@]}"

echo
"$ROOT/bin/openshell" --version
echo "Installed: $ROOT/bin/openshell   (add $ROOT/bin to PATH, or set OPENSHELL_BIN=$ROOT/bin/openshell)"
