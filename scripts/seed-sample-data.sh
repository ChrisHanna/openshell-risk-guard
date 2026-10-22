#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
#
# Build a sample Risk Guard database you can open in the operator console, with no cluster and no OpenShell.
#
#   scripts/seed-sample-data.sh [database-file]        # default: /tmp/risk-guard-sample.db
#   target/release/openshell-risk-guard dashboard --db /tmp/risk-guard-sample.db
#   open http://127.0.0.1:8787/
#
# It registers the three agents from the AKS fleet (a support analyst, a release engineer and a cloud-cost agent), imports their
# approved task profiles (deploy/aks/agents/*/baseline.json), and sends each one its routine calls plus the two calls it is
# tempted by, through the same normalizer, detector and SQLite store the real sidecar uses. You get workloads, scores, blocks,
# locks, and a rule in shadow mode, exactly as the live console shows them. The traffic is synthetic: nothing here talks to a
# gateway, a model or a network.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB="${1:-/tmp/risk-guard-sample.db}"
BIN="${RISK_GUARD_BIN:-$HERE/target/release/openshell-risk-guard}"

if [ ! -x "$BIN" ]; then
  echo "building the release binary first (a few minutes the first time)..." >&2
  (cd "$HERE" && cargo build --locked --release --bin openshell-risk-guard)
fi
rm -f "$DB" "$DB-wal" "$DB-shm"

rg() { "$BIN" "$@" >/dev/null; }

# profile-dir | workload id | display name | task profile | host | routine calls | tempting calls
# (calls are "METHOD /path" separated by ';')
seed_agent() {
  local dir="$1" agent="$2" name="$3" profile="$4" host="$5" routine="$6" tempting="$7"
  local sandbox="sbx-$agent-1" run="run-$agent-1"
  rg baseline-import --db "$DB" --profile "$HERE/deploy/aks/agents/$dir/baseline.json"
  rg agent-register --db "$DB" --agent-id "$agent" --display-name "$name"
  rg run-create --db "$DB" --agent-id "$agent" --run-id "$run" --agent-revision v1 --task-profile "$profile" --mode enforce
  rg epoch-create --db "$DB" --sandbox-id "$sandbox" --task-profile "$profile" --mode enforce
  rg run-bind --db "$DB" --run-id "$run" --sandbox-id "$sandbox"
  local n=0 call method path
  call_one() {
    n=$((n + 1)); method="${1%% *}"; path="${1#* }"
    rg evaluate-request --db "$DB" --sandbox-id "$sandbox" --request-id "$agent-$n" --scheme http --host "$host" --port 18081 \
      --method "$method" --path "$path" --binary /opt/agent/bin/python3.12 --allow-insecure-local-test || true
  }
  IFS=';' read -ra routine_calls <<<"$routine"
  for _ in 1 2; do for c in "${routine_calls[@]}"; do call_one "$c"; done; done
  IFS=';' read -ra tempting_calls <<<"$tempting"
  for c in "${tempting_calls[@]}"; do call_one "$c"; done
  echo "  seeded $name ($profile): $n requests"
}

echo "Seeding $DB"
seed_agent support nat-agent "Support analyst (nat-agent)" support-triage support-api.openshell.svc.cluster.local \
  "GET /tickets;GET /tickets/101;GET /customers/c-1;GET /kb" "GET /exports/customers;DELETE /customers/c-1"
seed_agent release release-bot "Release engineer (release-bot)" release-ops deploy-api.openshell.svc.cluster.local \
  "GET /services;GET /services/web;GET /services/web/deployments;POST /services/web/restart" \
  "POST /services/payments/rollback;DELETE /services/worker"
seed_agent cloud ops-cleaner "Cloud cost agent (ops-cleaner)" cloud-hygiene cloud-api.openshell.svc.cluster.local \
  "GET /buckets;GET /buckets/tmp-scratch;GET /costs" "GET /secrets;DELETE /buckets/customer-backups"

echo
echo "Done. Open it in the operator console (read-only, loopback only):"
echo "  $BIN dashboard --db $DB"
echo "  then browse http://127.0.0.1:8787/"
