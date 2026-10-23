#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""The promotion gate: may a control that is only watching (shadow) start refusing (enforce)?

    python scripts/promotion_gate.py                       # collect evidence from the SIEM, decide, print the report
    python scripts/promotion_gate.py --report out.json     # also keep it
    python scripts/promotion_gate.py --evidence e.json     # decide from saved evidence (no cluster needed)

Shadow mode records what the control would have refused. That record is the evidence: every "would refuse" is something enforcement will start blocking, so before enforcing, each one
must be either seen on enough observed traffic to know it is not routine behaviour that would break, or explicitly reviewed by a named person as something that should be blocked.
The gate says `promote` only when all of these hold, and otherwise says `hold` and lists exactly what is missing:

  1. Enough was observed: every agent seen has at least `min_tunnels_per_agent` tunnels in the window, and the observation spans `min_span_hours`.
  2. Nothing unreviewed would be refused: each (agent, destination, reason) the shadow mode would have refused matches an entry in `reviewed` (with a reviewer and a date).
  3. The control is healthy: Risk Guard has reported recently and has not failed to answer more than `max_middleware_failures` times in the window.
  4. It can be undone: a verified backup was taken within `require_backup_within_hours` (when required).
  5. The attack catalog still passes: the red-team report says `pass` and is recent (when required).

It never changes anything. `scripts/aks/18-enable-sandbox-egress.ps1 -RestrictionMode enforce` runs it and refuses to continue on `hold` unless an override with a written reason is given, which is recorded.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_POLICY = os.path.join(ROOT, "deploy", "aks", "promotion-policy.json")
HOUR = 3_600_000


def check(name, ok, detail, blockers=None):
    return {"check": name, "ok": bool(ok), "detail": detail, "blockers": blockers or []}


def matches(entry, finding):
    """A reviewed entry covers a finding when agent and destination match (or are "*") and the reason contains the entry's text."""
    return (entry.get("agent", "*") in ("*", finding["agent"])
            and entry.get("destination", "*") in ("*", finding["destination"])
            and entry.get("reason_contains", "") in finding["reason"])


def evaluate(evidence, policy, now_ms):
    """Pure decision: evidence and policy in, report out."""
    checks = []

    # 1. enough observed
    minimum = policy["min_tunnels_per_agent"]
    thin = [f"{a['agent']}: {a['tunnels']} tunnels (needs {minimum})" for a in evidence["agents"] if a["tunnels"] < minimum]
    span_h = (evidence["last_ms"] - evidence["first_ms"]) / HOUR if evidence["agents"] else 0
    ok = bool(evidence["agents"]) and not thin and span_h >= policy["min_span_hours"]
    detail = f"{len(evidence['agents'])} agents observed over {span_h:.1f} h (needs {policy['min_span_hours']} h)"
    if not evidence["agents"]:
        thin = ["no agent opened a tunnel in the window"]
    checks.append(check("enough_observed", ok, detail, thin + ([] if span_h >= policy["min_span_hours"] else [f"observation spans {span_h:.1f} h"])))

    # 2. nothing unreviewed would be refused
    reviewed = policy.get("reviewed", [])
    invalid = [e for e in reviewed if not (e.get("reviewer") and e.get("date") and e.get("note"))]
    unreviewed = [f for f in evidence["would_refuse"] if not any(matches(e, f) for e in reviewed if e not in invalid)]
    blockers = [f"{f['agent']} -> {f['destination']} ({f['reason'][:80]}), {f['count']} times" for f in unreviewed]
    blockers += ["a reviewed entry has no reviewer, date or note, so it does not count: " + json.dumps(e) for e in invalid]
    checks.append(check("no_unreviewed_would_refuse", not unreviewed and not invalid,
                        f"{len(evidence['would_refuse'])} kinds of would-refuse in the window, {len(unreviewed)} not reviewed", blockers))

    # 3. healthy
    age_min = (now_ms - evidence["last_risk_guard_event_ms"]) / 60_000 if evidence["last_risk_guard_event_ms"] else None
    health = []
    if age_min is None or age_min > policy["max_silence_minutes"]:
        health.append("Risk Guard has not reported recently" if age_min is not None else "Risk Guard has reported nothing")
    if evidence["middleware_failures"] > policy["max_middleware_failures"]:
        health.append(f"{evidence['middleware_failures']} times Risk Guard could not answer (allowed {policy['max_middleware_failures']})")
    checks.append(check("control_healthy", not health, f"{evidence['middleware_failures']} failures; last event {'%.0f min ago' % age_min if age_min is not None else 'never'}", health))

    # 4. can be undone
    if policy.get("require_backup_within_hours"):
        backup = evidence.get("last_backup_ms")
        limit = policy["require_backup_within_hours"]
        fresh = bool(backup) and (now_ms - backup) / HOUR <= limit
        checks.append(check("can_be_undone", fresh, f"verified backup {'%.1f h ago' % ((now_ms - backup) / HOUR) if backup else 'none recorded'} (needs within {limit} h)",
                            [] if fresh else ["take one: scripts/aks/26-backup-risk-guard.ps1 -Backup"]))

    # 5. the attack catalog passes
    if policy.get("require_red_team_pass"):
        report = evidence.get("red_team") or {}
        fresh = report.get("gate") == "pass" and report.get("age_hours", 1e9) <= policy["red_team_max_age_hours"]
        checks.append(check("attack_catalog_passes", fresh, f"red-team gate: {report.get('gate', 'no report')}, {report.get('age_hours', '?')} h old",
                            [] if fresh else ["run: cargo test --test red_team_gate"]))

    ok = all(c["ok"] for c in checks)
    return {"decision": "promote" if ok else "hold", "candidate": policy["candidate"], "checked_at_ms": now_ms, "window_hours": policy["window_hours"],
            "checks": checks, "to_revert": policy["revert_command"]}


# --------------------------------------------------------------------------- evidence from the SIEM

def collect(policy, now_ms):
    sys.path.insert(0, os.path.join(ROOT, "scripts", "siem"))
    import install_content as siem
    window = {"range": {"time": {"gte": now_ms - policy["window_hours"] * HOUR, "format": "epoch_millis"}}}

    def search(body, index="ocsf-openshell"):
        return siem.opensearch("POST", f"/{index}/_search", dict(body, size=0))

    def query(text):
        return {"bool": {"filter": [{"query_string": {"query": text}}, window]}}

    egress = search({"query": query('unmapped.risk_guard.gate:"egress"'), "aggs": {"agents": {"terms": {"field": "actor.user.name.keyword", "size": 100}, "aggs": {
        "tunnels": {"sum": {"field": "unmapped.risk_guard.total"}}, "first": {"min": {"field": "time"}}, "last": {"max": {"field": "time"}}}}}})
    agents = [{"agent": b["key"], "tunnels": int(b["tunnels"]["value"]), "first_ms": int(b["first"]["value"]), "last_ms": int(b["last"]["value"])}
              for b in egress.get("aggregations", {}).get("agents", {}).get("buckets", [])]

    shadow = search({"query": query('status_detail:"risk_guard_tunnel:tunnel_would_refuse"'), "aggs": {"agent": {"terms": {"field": "actor.user.name.keyword", "size": 100}, "aggs": {
        "destination": {"terms": {"field": "dst_endpoint.domain.keyword", "size": 50}, "aggs": {
            "reason": {"terms": {"field": "unmapped.risk_guard.reason.keyword", "size": 20}}}}}}}})
    would = []
    for a in shadow.get("aggregations", {}).get("agent", {}).get("buckets", []):
        for d in a["destination"]["buckets"]:
            for r in d["reason"]["buckets"]:
                would.append({"agent": a["key"], "destination": d["key"], "reason": r["key"], "count": r["doc_count"]})

    failures = search({"query": query("status_detail:middleware_failed*"), "track_total_hits": True})["hits"]["total"]["value"]
    last = search({"query": {"query_string": {"query": 'metadata.product.name:"OpenShell Risk Guard"'}}, "aggs": {"last": {"max": {"field": "time"}}}})
    last_ms = (last.get("aggregations", {}).get("last", {}).get("value")) or 0

    evidence = {"agents": agents, "first_ms": min((a["first_ms"] for a in agents), default=0), "last_ms": max((a["last_ms"] for a in agents), default=0),
                "would_refuse": would, "middleware_failures": failures, "last_risk_guard_event_ms": int(last_ms)}
    state_path = os.path.join(ROOT, ".aks", "state.json")
    if os.path.exists(state_path):
        with open(state_path, encoding="utf-8-sig") as handle:
            state = json.load(handle)
        if state.get("lastBackupAtMs"):
            evidence["last_backup_ms"] = int(state["lastBackupAtMs"])
    report_path = os.path.join(ROOT, "target", "red-team-report.json")
    if os.path.exists(report_path):
        with open(report_path, encoding="utf-8") as handle:
            report = json.load(handle)
        evidence["red_team"] = {"gate": report.get("gate"), "age_hours": round((time.time() - os.path.getmtime(report_path)) / 3600, 1)}
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--evidence", help="decide from saved evidence instead of querying the SIEM")
    parser.add_argument("--report")
    args = parser.parse_args()
    with open(args.policy, encoding="utf-8") as handle:
        policy = json.load(handle)
    now_ms = int(time.time() * 1000)
    if args.evidence:
        with open(args.evidence, encoding="utf-8") as handle:
            evidence = json.load(handle)
    else:
        evidence = collect(policy, now_ms)
    report = evaluate(evidence, policy, now_ms)
    text = json.dumps(report, indent=2)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(text)
    for item in report["checks"]:
        print(f"{'ok  ' if item['ok'] else 'HOLD'} {item['check']:28s} {item['detail']}")
        for blocker in item["blockers"][:8]:
            print(f"       - {blocker}")
    print(f"\ndecision: {report['decision'].upper()}   (to undo: {report['to_revert']})")
    sys.exit(0 if report["decision"] == "promote" else 1)


if __name__ == "__main__":
    main()
