#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export PATH="${HOME}/bin:${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
export CARGO_TARGET_DIR="${HOME}/.cache/rg-target"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST_PATH="${CRATE_DIR}/Cargo.toml"

cargo build --manifest-path "${MANIFEST_PATH}" --bin openshell-risk-guard

exec "${CARGO_TARGET_DIR}/debug/openshell-risk-guard" demo-dashboard \
  --listen 0.0.0.0:8787 \
  --db "${HOME}/.cache/openshell-live-dashboard.db"
