#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Upgrade, roll back, and roll forward Risk Guard on the live cluster, and check that its state survives each step.

    scripts/conformance/upgrade_drill.py --to-tag <tag> [--out report.json]

1. Snapshot the restrictions and quarantines in the database.
2. Upgrade to `--to-tag` with the hardened deployment (script 04 `-Hardened`: image pinned by digest, on the security node pool).
3. Smoke test through the deployed path: an allowed read is allowed, a destructive call is refused by policy.
4. Snapshot again: everything that was restricted before must still be.
5. Roll back (`kubectl rollout undo`) to the previous image, which now opens a database the newer image has written to, and repeat 3 and 4.
6. Roll forward again so the cluster ends where it started.

This restarts Risk Guard three times; each restart is a short outage during which requests fail closed. It does not test a first-time
install into an empty cluster, or teardown: those would destroy the cluster this runs on. State that plainly when reporting it.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
NS = "openshell"
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
DB = "/var/lib/openshell-risk-guard/risk-guard.db"
CALLER = ["exec", "deploy/egress-demo", "-c", "caller", "--", "python", "/etc/demo/call.py"]


def kubectl(*args, check=True, timeout=600):
    result = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, timeout=timeout, encoding="utf-8")
    if check and result.returncode:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def current_image():
    image = kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[?(@.name==\"risk-guard\")].image}").strip()
    return image.split("/", 1)[-1]


def agent_ids():
    """Every registered agent, from the read-only console API (the address is read from the deployment, never stored)."""
    import urllib.request
    host = kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[?(@.name==\"console-acme\")].env[?(@.name==\"DOMAIN\")].value}").strip()
    with urllib.request.urlopen(f"https://{host}/api/state", timeout=60) as response:
        return sorted(agent["agent_id"] for agent in json.load(response)["agents"])


def snapshot():
    risk_guard = ["exec", "deploy/risk-guard", "-c", "risk-guard", "--", "/usr/local/bin/openshell-risk-guard"]
    keys = set()
    for agent in agent_ids():
        out = kubectl(*risk_guard, "restriction-list", "--db", DB, "--agent-id", agent, check=False)
        if out.strip().startswith("{"):
            keys |= {json.dumps([r["owner_id"], r["scope"]]) for r in json.loads(out)["restrictions"]}
    quarantined = json.loads(kubectl(*risk_guard, "workload-quarantine-list", "--db", DB))["quarantined"]
    return {"restrictions": sorted(keys), "quarantined": sorted(json.dumps(q, sort_keys=True) for q in quarantined)}


def smoke():
    allowed = kubectl(*CALLER, "GET", "/repos/local/review", check=False)
    refused = kubectl(*CALLER, "DELETE", "/services/worker", check=False)
    return {"allowed_read": "-> 200" in allowed, "destructive_refused_by_policy": "denied by Risk Guard:" in refused,
            "detail": [allowed.strip()[:80], refused.strip()[:80]]}


def wait_ready(timeout=420):
    started = time.time()
    kubectl("rollout", "status", "deploy/risk-guard", f"--timeout={timeout}s")
    return round(time.time() - started, 1)


def step(name, action):
    began = time.time()
    action()
    ready = wait_ready()
    time.sleep(20)  # let the proxies and demo callers reconnect
    shot = snapshot()
    check = smoke()
    return {"step": name, "image_after": current_image(), "seconds_to_ready": ready, "seconds_total": round(time.time() - began, 1),
            "smoke": check, "state": shot}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--to-tag", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    start_image = current_image()
    before = snapshot()
    steps = []

    def deploy():
        subprocess.run(["powershell", "-NoProfile", "-File", os.path.join(ROOT, "scripts", "aks", "04-deploy-risk-guard.ps1"),
                        "-ImageTag", args.to_tag, "-Hardened"], capture_output=True, text=True, check=True)

    steps.append(step("upgrade (hardened, pinned by digest)", deploy))
    steps.append(step("roll back to the previous image", lambda: kubectl("rollout", "undo", "deploy/risk-guard")))
    steps.append(step("roll forward again", deploy))

    held = []
    previous = set(before["restrictions"])
    for entry in steps:
        now = set(entry["state"]["restrictions"])
        entry["restrictions_lost_since_previous_step"] = sorted(previous - now)
        entry["quarantine_still_listed"] = set(before["quarantined"]) <= set(entry["state"]["quarantined"])
        held.append(not entry["restrictions_lost_since_previous_step"] and entry["quarantine_still_listed"])
        previous |= now
    report = {
        "test": "upgrade_rollback_drill", "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "started_on": start_image, "target_tag": args.to_tag, "steps": steps,
        "result": {"state_survived_every_step": all(held), "smoke_passed_every_step": all(s["smoke"]["allowed_read"] and s["smoke"]["destructive_refused_by_policy"] for s in steps)},
        "not_tested": ["first-time install into an empty cluster", "teardown", "a database migration (none changed between these two images)"],
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    sys.exit(0 if all(report["result"].values()) else 1)


if __name__ == "__main__":
    main()
