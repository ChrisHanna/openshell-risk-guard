#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Suggest changes to each task profile's baseline from what the SIEM has recorded. It only suggests; a person decides.

    python scripts/siem/suggest_baselines.py                      # read the SIEM, print suggestions per task profile
    python scripts/siem/suggest_baselines.py --out DIR            # also write DIR/<profile>.proposed.json and DIR/suggestions.json
    python scripts/siem/suggest_baselines.py --evidence e.json    # decide from saved evidence (no cluster needed)

Risk Guard writes a per-minute summary of every route and every tunnel destination a workload used, with how many calls were allowed, refused or would be refused. Weeks of that
are in OpenSearch, which Risk Guard's own scoring does not see. This reads it and says, per task profile:

  * routes and egress hosts that were used steadily, never refused, and are not in the baseline (candidates to add);
  * rate limits far above anything observed (candidates to tighten).

(The console's Approvals page now computes route suggestions from Risk Guard's own history, with no SIEM. This script is for egress hosts and rate limits, which only the SIEM has; its output can be proposed through `POST /api/changes`.)

What it will not suggest, however often it was seen: a route with a destructive method (only GET and HEAD are ever proposed), anything that was refused even once, or any raising of a
rate limit. Those need a person and, to loosen, two people. The proposed baseline file has an empty `approved_by`, which `baseline-import` rejects, so nothing can be imported by
accident: a reviewer reads the evidence, fills in their name, and imports it through the same path as any baseline change.
"""
from __future__ import annotations

import argparse
import copy
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAFE_METHODS = {"GET", "HEAD"}
MIN_CALLS = 20          # a route or host needs at least this many calls
MIN_HOURS = 3           # ... spread over at least this many distinct hours (a burst is not a habit)
TIGHTEN_FACTOR = 3.0    # a rate limit this many times above what was observed is a candidate
MIN_RATE_MINUTES = 120  # ... and only when this many active minutes were observed


def shape(action_class):
    """`GET /services/{svc}` and `GET /services/{name}` are the same route; compare with the placeholder names removed."""
    return re.sub(r"\{[^}]*\}", "{}", action_class.strip())


def baseline_files():
    paths = glob.glob(os.path.join(ROOT, "deploy", "aks", "agents", "*", "baseline.json")) + [os.path.join(ROOT, "deploy", "aks", "baseline.json")]
    out = {}
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        out[data["task_profile"]] = (path, data)
    return out


def suggest_profile(baseline, evidence):
    """Suggestions for one profile. `evidence` has `routes`, `egress` and `rate`; see `fetch`."""
    known = {shape(c) for c in baseline.get("allowed_action_classes", [])}
    known_hosts = set(baseline.get("approved_egress_hosts", []))
    add_routes, not_suggested = [], []
    for row in evidence.get("routes", []):
        action_class = f"{row['method']} {row['route']}"
        if shape(action_class) in known:
            continue
        reason = None
        if row["refused"] > 0:
            reason = f"refused {row['refused']} time(s)"
        elif row["method"].upper() not in SAFE_METHODS:
            reason = "destructive method; a person must add it deliberately"
        elif row["calls"] < MIN_CALLS or row["hours"] < MIN_HOURS:
            reason = f"not steady enough yet ({row['calls']} calls in {row['hours']} hour(s); need {MIN_CALLS} in {MIN_HOURS})"
        entry = {"action_class": action_class, "host": row.get("host"), "calls": row["calls"], "hours": row["hours"], "refused": row["refused"]}
        if reason:
            not_suggested.append(dict(entry, why_not=reason))
        else:
            add_routes.append(entry)
    add_hosts = []
    for row in evidence.get("egress", []):
        host = row["destination"].rsplit(":", 1)[0]
        if host in known_hosts:
            continue
        entry = {"host": host, "destination": row["destination"], "calls": row["calls"], "hours": row["hours"], "would_refuse": row["shadow"], "refused": row["refused"]}
        if row["refused"] > 0:
            not_suggested.append(dict(entry, why_not=f"refused {row['refused']} time(s)"))
        elif row["calls"] < MIN_CALLS or row["hours"] < MIN_HOURS:
            not_suggested.append(dict(entry, why_not=f"not steady enough yet ({row['calls']} calls in {row['hours']} hour(s))"))
        else:
            add_hosts.append(entry)
    tighten = []
    rate = evidence.get("rate") or {}
    if rate.get("minutes", 0) >= MIN_RATE_MINUTES:
        for key, observed_key in (("max_req_1m_p95", "p95"), ("max_req_1m_p99", "p99")):
            limit, observed = baseline.get(key), rate.get(observed_key)
            if limit and observed is not None and limit > TIGHTEN_FACTOR * max(observed, 1):
                tighten.append({"setting": key, "now": limit, "observed": observed, "suggested": int(max(observed, 1) * 2), "minutes_observed": rate["minutes"]})
    return {"add_action_classes": add_routes, "add_egress_hosts": add_hosts, "tighten_rate": tighten, "not_suggested": not_suggested}


def propose(baseline, suggestions):
    """The baseline with the suggestions applied, unsigned: `approved_by` is blank and the version says it is a proposal."""
    new = copy.deepcopy(baseline)
    new["allowed_action_classes"] = list(baseline.get("allowed_action_classes", [])) + [s["action_class"] for s in suggestions["add_action_classes"]]
    new["approved_egress_hosts"] = list(baseline.get("approved_egress_hosts", [])) + [s["host"] for s in suggestions["add_egress_hosts"]]
    for t in suggestions["tighten_rate"]:
        new[t["setting"]] = t["suggested"]
    new["version"] = f"{baseline.get('version', 'v1')}-proposed"
    new["approved_by"] = ""
    return new


def has_suggestions(s):
    return bool(s["add_action_classes"] or s["add_egress_hosts"] or s["tighten_rate"])


# ---- reading the SIEM ------------------------------------------------------------------------------------------------------------------------------------------------
def fetch(days=7):
    sys.path.insert(0, os.path.dirname(__file__))
    import install_content as siem
    window = {"range": {"time": {"gte": f"now-{days}d"}}}
    gate = lambda g: {"term": {"unmapped.risk_guard.gate.keyword": g}}  # noqa: E731
    prefix = "unmapped.risk_guard."

    def ask(g, aggs):
        out = siem.opensearch("POST", f"/{siem.INDEX}*/_search", {"size": 0, "query": {"bool": {"filter": [gate(g), window]}}, "aggs": aggs})
        if "aggregations" not in out:
            raise SystemExit("OpenSearch did not answer: " + json.dumps(out)[:300])
        return out["aggregations"]

    sums = lambda: {  # noqa: E731
        "allowed": {"sum": {"field": prefix + "allowed_calls"}}, "refused": {"sum": {"field": prefix + "refused_calls"}},
        "hours": {"date_histogram": {"field": "time", "fixed_interval": "1h", "min_doc_count": 1}}}
    evidence = {}

    def profile(name):
        return evidence.setdefault(name, {"routes": [], "egress": [], "rate": {}})

    routes = ask("route", {"p": {"terms": {"field": prefix + "task_profile.keyword", "size": 50}, "aggs": {"m": {"terms": {"field": prefix + "method.keyword", "size": 20}, "aggs": {
        "r": {"terms": {"field": prefix + "route.keyword", "size": 500}, "aggs": dict(sums(), host={"terms": {"field": prefix + "host.keyword", "size": 1}})}}}}}})
    for p in routes["p"]["buckets"]:
        for m in p["m"]["buckets"]:
            for r in m["r"]["buckets"]:
                allowed, refused = int(r["allowed"]["value"]), int(r["refused"]["value"])
                host = (r["host"]["buckets"] or [{}])[0].get("key")
                profile(p["key"])["routes"].append({"method": m["key"], "route": r["key"], "host": host, "calls": allowed + refused, "refused": refused, "hours": len(r["hours"]["buckets"])})
    egress = ask("egress", {"p": {"terms": {"field": prefix + "task_profile.keyword", "size": 50}, "aggs": {"d": {"terms": {"field": prefix + "destination.keyword", "size": 200}, "aggs": dict(
        sums(), shadow={"sum": {"field": prefix + "shadow_calls"}})}}}})
    for p in egress["p"]["buckets"]:
        for d in p["d"]["buckets"]:
            allowed, refused, shadow = int(d["allowed"]["value"]), int(d["refused"]["value"]), int(d["shadow"]["value"])
            profile(p["key"])["egress"].append({"destination": d["key"], "calls": allowed + refused + shadow, "refused": refused, "shadow": shadow, "hours": len(d["hours"]["buckets"])})
    rate = ask("summary", {"p": {"terms": {"field": prefix + "task_profile.keyword", "size": 50}, "aggs": {"t": {"percentiles": {"field": prefix + "total", "percents": [95, 99]}}}}})
    for p in rate["p"]["buckets"]:
        values = p["t"]["values"]
        profile(p["key"])["rate"] = {"minutes": p["doc_count"], "p95": values.get("95.0"), "p99": values.get("99.0")}
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--out")
    parser.add_argument("--evidence")
    args = parser.parse_args()
    if args.evidence:
        with open(args.evidence, encoding="utf-8") as handle:
            evidence = json.load(handle)
    else:
        evidence = fetch(args.days)
    files = baseline_files()
    report = {}
    for name, ev in sorted(evidence.items()):
        if name not in files:
            print(f"{name}: no baseline file in the repository; skipped")
            continue
        path, baseline = files[name]
        s = suggest_profile(baseline, ev)
        report[name] = s
        print(f"\n== {name}  ({os.path.relpath(path, ROOT)})")
        for r in s["add_action_classes"]:
            print(f"  add route   {r['action_class']:<48} {r['calls']} calls over {r['hours']} h, none refused")
        for h in s["add_egress_hosts"]:
            print(f"  add host    {h['host']:<48} {h['calls']} tunnels over {h['hours']} h, none refused")
        for t in s["tighten_rate"]:
            print(f"  tighten     {t['setting']}: {t['now']} -> {t['suggested']}   (observed {t['observed']:.0f} over {t['minutes_observed']} active minutes)")
        for n in s["not_suggested"][:8]:
            what = n.get("action_class") or n.get("host")
            print(f"  not suggested {what}: {n['why_not']}")
        if not has_suggestions(s):
            print("  nothing to suggest yet")
        if args.out and has_suggestions(s):
            os.makedirs(args.out, exist_ok=True)
            with open(os.path.join(args.out, f"{name}.proposed.json"), "w", encoding="utf-8") as handle:
                json.dump(propose(baseline, s), handle, indent=2)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "suggestions.json"), "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"\nwritten to {args.out}. A proposed file has a blank approved_by: review the evidence, set your name, and import it with baseline-import.")


if __name__ == "__main__":
    main()
