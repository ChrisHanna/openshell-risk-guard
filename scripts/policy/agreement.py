#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Do OpenShell's generated policy and Risk Guard agree about which calls to refuse?

    python scripts/policy/agreement.py [--hours 24] [--sandbox NAME ...]    # read the SIEM, compare, print
    python scripts/policy/agreement.py --events saved.json                  # compare saved events (no cluster needed)

A generated policy in `audit` mode logs "L7_REQUEST audit ... not permitted by policy" for each request it would block, and lets it through. Risk Guard's own refusals are in the
same index. For each call, this answers one of three things:

  both            OpenShell would refuse it and Risk Guard refused it. The two agree.
  openshell only  OpenShell would refuse it and Risk Guard did not. Enforcing the policy would block something new. Review every one; this is the list that must be empty
                  (or each entry explained) before the policy is switched from audit to enforce.
  risk guard only Risk Guard refused it and the policy would not. Fine: that is what Risk Guard is for (behavior, rate, resources).

A call is matched on the sandbox, method and path, within ten seconds. Exit status 1 if there is any "openshell only".
"""
import argparse
import json
import os
import sys

WINDOW_MS = 10_000
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def key(event):
    """(sandbox, METHOD, path) of an event, from either the OpenShell shape or Risk Guard's (which carries the same fields under `http_request`)."""
    request = event.get("http_request") or {}
    path = (request.get("url") or {}).get("path")
    method = request.get("http_method")
    if not path:  # a Risk Guard event written before it carried the OpenShell field names
        http = ((event.get("unmapped") or {}).get("risk_guard") or {}).get("http") or {}
        path, method = http.get("path"), http.get("method")
    sandbox = (event.get("container") or {}).get("uid")
    if not (path and method and sandbox):
        return None
    return sandbox, str(method).upper(), str(path).split("?")[0]


def compare(audit, refusals, window_ms=WINDOW_MS):
    """`audit` and `refusals` are lists of events. Returns the three groups, each a list of (key, time)."""
    by_key = {}
    for event in refusals:
        k = key(event)
        if k:
            by_key.setdefault(k, []).append(event["time"])
    both, openshell_only, matched = [], [], set()
    for event in audit:
        k = key(event)
        if not k:
            continue
        times = by_key.get(k, [])
        hit = next((t for t in times if abs(t - event["time"]) <= window_ms), None)
        if hit is not None:
            both.append((k, event["time"]))
            matched.add((k, hit))
        else:
            openshell_only.append((k, event["time"]))
    sandboxes = {k[0] for k, _ in both + openshell_only}
    risk_guard_only = [(k, t) for k, times in by_key.items() if k[0] in sandboxes for t in times if (k, t) not in matched]
    return {"both": both, "openshell_only": openshell_only, "risk_guard_only": risk_guard_only}


def fetch(hours, sandboxes):
    sys.path.insert(0, os.path.join(ROOT, "scripts", "siem"))
    import install_content as siem
    window = {"range": {"time": {"gte": f"now-{hours}h"}}}

    def search(query):
        events, after = [], None
        while True:
            body = {"size": 5000, "sort": [{"time": "asc"}, {"metadata.uid.keyword": "asc"}], "query": {"bool": {"filter": [window, query]}}}
            if after:
                body["search_after"] = after
            hits = siem.opensearch("POST", f"/{siem.INDEX}*/_search", body).get("hits", {}).get("hits", [])
            if not hits:
                return events
            events += [h["_source"] for h in hits]
            after = hits[-1]["sort"]

    audit = search({"match_phrase": {"message": "L7_REQUEST audit"}})
    refusals = search({"term": {"unmapped.risk_guard.gate.keyword": "middleware"}})
    if sandboxes:
        audit = [e for e in audit if (e.get("container") or {}).get("name") in sandboxes]
    return audit, refusals


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--sandbox", action="append", default=[])
    parser.add_argument("--events")
    args = parser.parse_args()
    if args.events:
        with open(args.events, encoding="utf-8") as handle:
            saved = json.load(handle)
        audit, refusals = saved["audit"], saved["refusals"]
    else:
        audit, refusals = fetch(args.hours, set(args.sandbox))
    result = compare(audit, refusals)
    print(f"OpenShell audit violations: {len(audit)}   Risk Guard refusals: {len(refusals)}")
    print(f"  both agree:        {len(result['both'])}")
    print(f"  openshell only:    {len(result['openshell_only'])}   <- enforcing would block these; review each")
    for (sandbox, method, path), at in result["openshell_only"][:20]:
        print(f"      {method} {path}  (sandbox {sandbox[:8]}, t={at})")
    print(f"  risk guard only:   {len(result['risk_guard_only'])}   (behavior, rate or resource rules; expected)")
    if not audit:
        print("\nNo audit violations in the window. Either no sandbox runs a generated policy in audit mode yet, or nothing it would block was tried.")
    sys.exit(1 if result["openshell_only"] else 0)


if __name__ == "__main__":
    main()
