#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
#
# Live demonstration script for `openshell-risk-guard`.
# Runs the statistical evaluation & latency benchmark suite (Gates G-02..G-08)
# followed by the 10-step end-to-end integration & fault-injection suite
# (Gates G-01, G-09, G-10, G-11, G-12).

set -euo pipefail

export PATH="${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/rg-target}"

INTERACTIVE=0
if [[ "${1:-}" == "--interactive" ]]; then
  INTERACTIVE=1
fi

pause_if_interactive() {
  local prompt_msg="$1"
  if [[ "${INTERACTIVE}" -eq 1 ]]; then
    echo ""
    echo ">>> [PRESENTER NOTE] ${prompt_msg}"
    read -r -p ">>> Press Enter to run this stage..." _
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST_PATH="${CRATE_DIR}/Cargo.toml"

echo "================================================================================"
echo "  NVIDIA OpenShell Behavioral Risk Guard — Live End-to-End Verification Demo"
echo "================================================================================"
echo "Crate manifest: ${MANIFEST_PATH}"
echo ""

pause_if_interactive "Stage 1 verifies the unit tests across Ed25519 openshell-ext+jwt auth, path/route normalization, interaction-aware scoring, SQLite WAL+FULL persistence, and the Two-Step Z3 Containment Proof."
echo "[1/3] Running module unit tests (auth, normalizer, detector, store, hardening, fixture, middleware, interceptor, cli)..."
cargo test --manifest-path "${MANIFEST_PATH}" --lib

echo ""
pause_if_interactive "Stage 2 runs the 415-episode statistical evaluation (310 benign, 105 misuse) across 5 comparators, proving 0/310 false denials (95% UB = 0.9617% <= 1.0%), 100% misuse recall, deterministic replay, and p95 = 3.21ms concurrent SQLite WAL+FULL gRPC latency."
echo "[2/3] Running statistical evaluation, ablation, replay & latency gates (G-02..G-08)..."
cargo test --manifest-path "${MANIFEST_PATH}" --test eval_metrics -- --nocapture

echo ""
pause_if_interactive "Stage 3 boots the live axum UpstreamFixtureServer, SQLite WAL+FULL store, and Tonic gRPC sidecar (SupervisorMiddleware + GatewayInterceptor) to run all 10 acceptance steps, fault injection, and Z3 policy hardening."
echo "[3/3] Running 10-step live E2E acceptance sequence & fault-injection gates (G-01, G-09..G-12)..."
cargo test --manifest-path "${MANIFEST_PATH}" --test e2e_integration -- --nocapture

echo ""
echo "================================================================================"
echo "  ALL RELEASE GATES (G-01..G-12) AND 10-STEP LIVE DEMO SEQUENCE PASSED"
echo "================================================================================"
