#!/usr/bin/env bash
# Shared helpers for demo scripts that create sandboxes. Source this file; it defines functions only.
#
# By default the demo runs the sidecar with --workload-from-principal, so a sandbox binds itself to
# a workload derived from its workspace and creating principal, and scripts must not run-create or
# run-bind. Set RAIL_GUARD_DEMO_WORKLOAD_FROM_PRINCIPAL=0 for explicit, label-style binding.
#
#   rg_principal_mode                 true when sandboxes bind themselves
#   rg_wait_bound DB SANDBOX_ID       waits until the binding attempt is recorded; prints the workload ID
#                                     on success and returns 1 if it was refused or never appeared

rg_principal_mode() { [[ "${RAIL_GUARD_DEMO_WORKLOAD_FROM_PRINCIPAL:-1}" == 1 ]]; }

rg_wait_bound() {
  local db="$1" sandbox_id="$2" i out
  for i in $(seq 1 30); do
    out="$(python3 - "$db" "$sandbox_id" <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    row = c.execute("""SELECT outcome, COALESCE(agent_id, ''), COALESCE(reason, '')
                       FROM workload_binding_audit WHERE sandbox_id = ? ORDER BY audit_id DESC LIMIT 1""",
                    (sys.argv[2],)).fetchone()
    if row:
        print("|".join(row))
except Exception:
    pass
PY
)"
    if [[ -n "$out" ]]; then
      if [[ "${out%%|*}" == bound ]]; then
        out="${out#*|}"; printf '%s\n' "${out%%|*}"; return 0
      fi
      echo "binding refused: ${out#*|*|}" >&2; return 1
    fi
    sleep 1
  done
  echo "no binding attempt was recorded for $sandbox_id" >&2; return 1
}
