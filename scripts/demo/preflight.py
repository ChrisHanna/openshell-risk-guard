#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Is everything the demo needs up, and what should I know before I start?

    python scripts/demo/preflight.py            # check the live deployment and print ok / warn / FAIL with the fix
    python scripts/demo/preflight.py --quick    # skip the checks that ask OpenSearch (about ten seconds faster)

It changes nothing. Each line is one thing the run-of-show (docs/demo-runbook.md) depends on. A FAIL means that part of the demo will not work as written; a warn means it will
work but you should know why before someone asks.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
results = []


def record(level, what, detail=""):
    results.append(level)
    mark = {"ok": "[ ok ]", "warn": "[warn]", "FAIL": "[FAIL]", "info": "[info]"}[level]
    print(f"{mark} {what}" + (f"\n         {detail}" if detail else ""), flush=True)


def kubectl(*args, timeout=60):
    try:
        r = subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
        return r.returncode, r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, str(error)


def state():
    """The deployment's saved state (gitignored). From a git worktree it lives in the main checkout, so look there too."""
    candidates = [os.path.join(ROOT, ".aks", "state.json")]
    common = subprocess.run(["git", "-C", ROOT, "rev-parse", "--git-common-dir"], capture_output=True, text=True).stdout.strip()
    if common:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(os.path.join(ROOT, common))), ".aks", "state.json"))
    for path in candidates:
        try:
            with open(path, encoding="utf-8-sig") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            continue
    return {}


def fetch(url, timeout=25):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.status, response.read().decode("utf-8", "replace")


def pods():
    code, out = kubectl("version", "--request-timeout=15s", "-o", "json")
    if code:
        record("FAIL", "kubectl cannot reach the cluster", "Sign in (az login) and run: az aks get-credentials ... (scripts/aks/common.ps1 Use-Cluster does it).")
        return False
    for ns, label, want in (("openshell", "risk-guard", "4/4"), ("siem", "opensearch-cluster-master", "1/1"), ("siem", "otel-collector", "1/1"),
                            ("siem", "dashboards-opensearch-dashboards", "1/1"), ("siem", "signal-forwarder", "3/3")):
        code, out = kubectl("-n", ns, "get", "pods", "--no-headers")
        line = next((l for l in out.splitlines() if l.startswith(label)), "")
        parts = line.split()
        if len(parts) >= 3 and parts[1] == want and parts[2] == "Running":
            record("ok", f"{ns}/{label} running ({parts[1]})")
        else:
            record("FAIL", f"{ns}/{label} is not ready", line or "no such pod. Redeploy with the script for that part (04 Risk Guard, 22 SIEM, 25 signals).")
    code, out = kubectl("-n", "openshell", "get", "deploy", "agent-fleet", "-o", "jsonpath={.status.readyReplicas}")
    if out == "1":
        record("ok", "agent fleet is running (the agents that produce live traffic)")
    else:
        record("warn", "agent fleet is not running", "Dashboards will show old data. Start it: kubectl -n openshell scale deploy/agent-fleet --replicas=1")
    code, image = kubectl("-n", "openshell", "get", "deploy", "risk-guard", "-o", "jsonpath={.spec.template.spec.containers[?(@.name==\"risk-guard\")].image}")
    head = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    tag = image.rsplit(":", 1)[-1]
    if tag == head:
        record("ok", f"Risk Guard is running the current commit ({tag})")
    else:
        changed = subprocess.run(["git", "-C", ROOT, "diff", "--name-only", f"{tag}..{head}", "--", "src", "Cargo.toml", "Cargo.lock", "migrations"], capture_output=True, text=True).stdout.split()
        if changed:
            record("warn", f"Risk Guard runs {tag}; {len(changed)} source file(s) changed since ({head})", "Rebuild and deploy (02 -LocalDocker, then 04), then run scripts/demo/smoke.py.")
        else:
            record("ok", f"Risk Guard runs {tag}; the repository is at {head} but no source changed since")
    return True


def console(host):
    base = f"https://{host}"
    for path, what in (("/", "console page"), ("/admin", "administrator sign-in page")):
        try:
            status, _ = fetch(base + path)
            record("ok" if status == 200 else "FAIL", f"{what} answers ({status})")
        except Exception as error:
            record("FAIL", f"{what} unreachable", f"{error}. Check the public IP and certificate (scripts/aks/09-expose-console.ps1).")
    try:
        _, body = fetch(base + "/api/controls")
        view = json.loads(body)
        controls = {c["id"]: c for c in view["controls"]}
        record("ok", f"Controls page data: {len(controls)} controls, {view['calls_24h']} calls in the last 24 hours")
        score = controls["behavioral_score"]
        record("info", "behavioral score: " + score["data"]["note"].split(" Until")[0])
        for cid, label in (("siem_signals", "SIEM signals"), ("latched_restriction", "latched restriction")):
            c = controls[cid]
            ev = ", ".join(f"{k}={v}" for k, v in c["evidence"].items() if k != "note")
            record("info", f"{label}: {c['mode']} ({ev})")
        feat = controls.get("siem_context")
        if feat:
            fresh, age = feat["evidence"].get("fresh_features", 0), feat["evidence"].get("newest_batch_age_seconds")
            if fresh and age is not None and age < 180:
                record("ok", f"SIEM features are arriving: {fresh} fresh, newest batch {age} s old (rule {feat['mode']})")
            else:
                record("warn", "no recent SIEM features", "The publisher container in the signal-forwarder pod posts every 30 s: kubectl -n siem logs deploy/signal-forwarder -c feature-publisher --tail=5")
        held = controls["quarantine"]["evidence"].get("quarantined_now", 0)
        if held:
            record("warn", f"{held} workload(s) are quarantined right now", "Left over from a rehearsal? Release: python scripts/demo/run_demo.py --cleanup (or the Approvals page).")
        else:
            record("ok", "nothing is quarantined (the quarantine act starts clean)")
    except Exception as error:
        record("FAIL", "Controls data unavailable", str(error))
    try:
        _, body = fetch(base + "/api/changes")
        waiting = [c for c in json.loads(body)["changes"] if c["status"] == "pending"]
        record("ok" if not waiting else "warn", f"Approvals: {len(waiting)} waiting", "" if not waiting else "Decide or reject them first so the page starts clean.")
        _, body = fetch(base + "/api/baseline-suggestions")
        found = [(p["task_profile"], r["action_class"]) for p in json.loads(body)["profiles"] for r in p["add_action_classes"]]
        record("ok" if found else "info", f"suggested baseline changes ready to show: {len(found)}", "; ".join(f"{a}: {b}" for a, b in found[:3]))
    except Exception as error:
        record("FAIL", "Approvals data unavailable", str(error))


def siem(quick):
    if quick:
        record("info", "SIEM checks skipped (--quick)")
        return
    sys.path.insert(0, os.path.join(ROOT, "scripts", "siem"))
    import install_content as s
    try:
        recent = s.opensearch("POST", "/ocsf-openshell*/_count", {"query": {"range": {"time": {"gte": "now-15m"}}}}).get("count", 0)
        rg = s.opensearch("POST", "/ocsf-openshell*/_count", {"query": {"bool": {"filter": [{"exists": {"field": "unmapped.risk_guard.gate"}}, {"range": {"time": {"gte": "now-15m"}}}]}}}).get("count", 0)
        record("ok" if recent else "FAIL", f"events reaching OpenSearch in the last 15 minutes: {recent} ({rg} from Risk Guard)",
               "" if recent else "Nothing is arriving. Check the collector (kubectl -n siem logs deploy/otel-collector) and that agent-fleet is scaled to 1.")
        monitors = s.opensearch("POST", "/_plugins/_alerting/monitors/_search", {"size": 0, "query": {"match_all": {}}}).get("hits", {}).get("total", {}).get("value", 0)
        record("ok" if monitors >= 5 else "warn", f"alert monitors installed: {monitors}", "" if monitors >= 5 else "Run: python scripts/siem/install_content.py")
        dashboards = json.loads(s.exec_in_pod("curl -s -u admin:$OPENSEARCH_PASSWORD -H 'osd-xsrf: true' 'http://localhost:5601/api/saved_objects/_find?type=dashboard&per_page=100'") or "{}")
        count = dashboards.get("total", 0)
        record("ok" if count >= 8 else "warn", f"dashboards installed: {count}", "" if count >= 8 else "Run: python scripts/siem/install_content.py")
    except Exception as error:
        record("FAIL", "OpenSearch did not answer", str(error))


def sandbox():
    code, out = kubectl("-n", "openshell", "exec", "deploy/agent-fleet", "--", "env", "HOME=/tmp/fleet", "OPENSHELL_GATEWAY=aks", "openshell", "sandbox", "list", timeout=60)
    if code == 0 and "demo-contain" in out:
        record("ok", "the standing sandbox for the quarantine act exists (demo-contain)")
    else:
        record("warn", "the standing sandbox for the quarantine act is missing", "Create it about a minute before: python scripts/demo/run_demo.py --prepare")


def gate():
    try:
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "promotion_gate.py")], capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace")
        first = next((l for l in r.stdout.splitlines() if l.strip()), "")
        record("info", "promotion gate says: " + first[:150], "Expect HOLD. Say why: thin traffic, workloads holding latched restrictions, no recent backup.")
    except Exception as error:
        record("warn", "could not run the promotion gate", str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    st = state()
    print("Demo pre-flight (changes nothing)\n")
    if pods():
        host = st.get("consoleHost")
        if host:
            console(host)
        else:
            record("FAIL", "consoleHost is not in .aks/state.json", "Run scripts/aks/09-expose-console.ps1 or set it.")
        siem(args.quick)
        sandbox()
        gate()
    print(f"\n{results.count('ok')} ok, {results.count('warn')} warn, {results.count('FAIL')} FAIL")
    sys.exit(1 if "FAIL" in results else 0)


if __name__ == "__main__":
    main()
