#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""What does quarantine do to a tunnel that is already open?

Risk Guard's tunnel gate decides when a TLS tunnel is opened (an HTTP CONNECT). This script measures what happens to traffic when a workload
is quarantined *after* that: it opens one long-lived HTTPS connection and a stream of fresh connections from a real OpenShell sandbox to an
approved host, quarantines the workload part-way through, and records, with timestamps, when each kind of traffic starts to fail and
whether the long-lived connection ever does.

    scripts/conformance/quarantine_tunnel.py [--seconds 150] [--quarantine-at 40] [--release-at 100] [--out report.json]

Needs kubectl access to the cluster, the agent-fleet pod (for the openshell CLI) and the risk-guard pod. It creates one sandbox and a test
workload (`containment-test`), and removes the sandbox and the quarantine when it finishes. It reports what was observed; it does not assume
a result. The destination is the hosted model API, so no destination-side effect can be counted: the claim measured is about the
connection, not about what the destination did.
"""
import argparse
import base64
import datetime
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
NAMESPACE = "openshell"
DB = "/var/lib/openshell-risk-guard/risk-guard.db"
WORKLOAD = "containment-test"
HOST = "integrate.api.nvidia.com"

IN_SANDBOX = r'''
import http.client, json, os, ssl, sys, threading, time
HOST, SECONDS = sys.argv[1], int(sys.argv[2])
key = os.environ.get("NVIDIA_API_KEY", "")
start = time.time()
lock = threading.Lock()
def log(kind, ok, detail, began):
    with lock:
        print(json.dumps({"at": round(time.time(), 3), "kind": kind, "ok": ok, "detail": detail, "ms": int((time.time() - began) * 1000)}), flush=True)
def request(conn):
    conn.request("GET", "/v1/models", headers={"Authorization": "Bearer " + key})
    response = conn.getresponse(); response.read()
    return response.status
def persistent():
    conn = None
    while time.time() - start < SECONDS:
        began = time.time()
        try:
            if conn is None:
                conn = http.client.HTTPSConnection(HOST, timeout=10, context=ssl.create_default_context())
            status = request(conn); log("persistent", status == 200, status, began)
        except Exception as error:
            log("persistent", False, type(error).__name__ + ": " + str(error)[:80], began); conn = None
        time.sleep(2)
def fresh():
    while time.time() - start < SECONDS:
        began = time.time()
        try:
            conn = http.client.HTTPSConnection(HOST, timeout=10, context=ssl.create_default_context())
            status = request(conn); conn.close(); log("fresh", status == 200, status, began)
        except Exception as error:
            log("fresh", False, type(error).__name__ + ": " + str(error)[:80], began)
        time.sleep(2)
# Whatever happens in the threads, the process ends: a hung request must not hold the test open.
threading.Thread(target=lambda: (time.sleep(SECONDS + 25), os._exit(0)), daemon=True).start()
threads = [threading.Thread(target=persistent, daemon=True), threading.Thread(target=fresh, daemon=True)]
[t.start() for t in threads]
time.sleep(SECONDS)
os._exit(0)
'''


def kubectl(*args, input_text=None, check=True, timeout=300):
    result = subprocess.run(["kubectl", "-n", NAMESPACE, *args], capture_output=True, text=True, input=input_text, timeout=timeout)
    if check and result.returncode:
        sys.exit(f"kubectl {' '.join(args[:4])} failed: {result.stderr.strip()[:300]}")
    return result


def fleet(*args, **kw):
    return kubectl("exec", "deploy/agent-fleet", "--", "env", "HOME=/tmp/fleet", "OPENSHELL_GATEWAY=aks", *args, **kw)


def risk_guard(*args, **kw):
    return kubectl("exec", "deploy/risk-guard", "-c", "risk-guard", "--", "/usr/local/bin/openshell-risk-guard", *args, **kw)


def deployment_revision():
    image = kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[0].image}").stdout.strip()
    helm = subprocess.run(["helm", "-n", NAMESPACE, "history", "openshell", "--max", "1", "-o", "json"], capture_output=True, text=True)
    revision = json.loads(helm.stdout)[0]["revision"] if helm.returncode == 0 and helm.stdout.strip() else None
    return {"risk_guard_image": image, "gateway_helm_revision": revision,
            "tunnel_restriction_mode": kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[0].args}").stdout.count("tunnel-restriction-mode")}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=150)
    parser.add_argument("--quarantine-at", type=int, default=40)
    parser.add_argument("--release-at", type=int, default=100)
    parser.add_argument("--out")
    args = parser.parse_args()
    name = "contain-" + datetime.datetime.now().strftime("%H%M%S")

    acr = kubectl("get", "deploy/agent-fleet", "-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name==\"ACR_SERVER\")].value}").stdout.strip()
    policy = open(os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "aks", "agents", "support", "policy.yaml"), "rb").read()
    risk_guard("agent-register", "--db", DB, "--agent-id", WORKLOAD, "--display-name", WORKLOAD, check=False)
    fleet("sh", "-c", f"echo {base64.b64encode(policy).decode()} | base64 -d > /tmp/containment-policy.yaml")
    print("creating sandbox", name)
    fleet("openshell", "sandbox", "create", "--name", name, "--from", f"{acr}/openshell-demo/nat-agent:3", "--policy", "/tmp/containment-policy.yaml",
          "--provider", "nvidia-nat", "--annotation", f"openshell.nvidia.com/agent-id={WORKLOAD}", "--annotation", "openshell.nvidia.com/agent-name=containment-test",
          "--no-tty", "--detach", "--", "/usr/bin/sleep", "infinity", timeout=180, check=False)
    for _ in range(40):
        got = fleet("openshell", "sandbox", "get", name, "--output", "json", check=False).stdout
        if '"phase": "Ready"' in got.replace('":"', '": "'):
            break
        time.sleep(6)
    else:
        sys.exit("the sandbox did not become ready")

    script = base64.b64encode(IN_SANDBOX.encode()).decode()
    t0 = time.time()
    traffic = subprocess.Popen(
        ["kubectl", "-n", NAMESPACE, "exec", "deploy/agent-fleet", "--", "env", "HOME=/tmp/fleet", "OPENSHELL_GATEWAY=aks", "openshell", "sandbox", "exec",
         "--name", name, "--no-tty", "--no-login-shell", "--", "/bin/sh", "-c",
         f"echo {script} | base64 -d > /tmp/t.py; /opt/agent/bin/python3.12 /tmp/t.py {HOST} {args.seconds}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    events, marks = [], {}
    import threading
    def reader():
        for line in traffic.stdout:
            if line.startswith("{"):
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                event["received"] = round(time.time(), 3)
                events.append(event)
    threading.Thread(target=reader, daemon=True).start()
    try:
        while traffic.poll() is None and time.time() - t0 < args.seconds + 90:
            elapsed = time.time() - t0
            if "quarantine" not in marks and elapsed >= args.quarantine_at:
                marks["quarantine_requested"] = time.time()
                risk_guard("workload-quarantine", "--db", DB, "--agent-id", WORKLOAD, "--operator", "conformance", "--reason", "tunnel containment test")
                marks["quarantine"] = marks["quarantine_done"] = time.time()
            if "release" not in marks and "quarantine" in marks and elapsed >= args.release_at:
                risk_guard("workload-release", "--db", DB, "--agent-id", WORKLOAD, "--operator", "conformance", "--reason", "test finished")
                marks["release"] = time.time()
            time.sleep(1)
    finally:
        if traffic.poll() is None:
            traffic.kill()
        risk_guard("workload-release", "--db", DB, "--agent-id", WORKLOAD, "--operator", "conformance", "--reason", "cleanup", check=False)
        fleet("openshell", "sandbox", "delete", name, check=False)

    q, r = marks.get("quarantine"), marks.get("release")
    def first_failure_after(kind, since):
        for e in events:
            if e["kind"] == kind and e["at"] >= since and not e["ok"]:
                return round(e["at"] - since, 1)
        return None
    def last_ok_before_failure(kind):
        return max((e["at"] for e in events if e["kind"] == kind and e["ok"] and e["at"] >= (q or 0)), default=None)
    persistent_after = [e for e in events if e["kind"] == "persistent" and q and e["at"] >= q and (not r or e["at"] < r)]
    fresh_after = [e for e in events if e["kind"] == "fresh" and q and e["at"] >= q + 3 and (not r or e["at"] < r)]
    report = {
        "test": "quarantine_after_tunnel_open", "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "deployment": deployment_revision(), "destination": HOST,
        "events": len(events),
        "before_quarantine": {"fresh_ok": sum(1 for e in events if e["kind"] == "fresh" and q and e["at"] < q and e["ok"]),
                              "persistent_ok": sum(1 for e in events if e["kind"] == "persistent" and q and e["at"] < q and e["ok"])},
        "seconds_until_first_failure": {"fresh_connections": first_failure_after("fresh", q) if q else None,
                                        "long_lived_connection": first_failure_after("persistent", q) if q else None},
        "after_quarantine": {"fresh_requests": len(fresh_after), "fresh_refused": sum(1 for e in fresh_after if not e["ok"]),
                             "fresh_failure_milliseconds": [e["ms"] for e in fresh_after if not e["ok"]][:12],
                             "fresh_failure_detail": sorted({e["detail"] for e in fresh_after if not e["ok"]})[:3],
                             "long_lived_requests": len(persistent_after), "long_lived_succeeded": sum(1 for e in persistent_after if e["ok"])},
        "after_release_ok": any(e["ok"] for e in events if r and e["at"] > r + 5 and e["kind"] == "fresh"),
        "interpretation": None,
    }
    survived = report["after_quarantine"]["long_lived_succeeded"]
    ended = report["seconds_until_first_failure"]["long_lived_connection"]
    window = (r or q) - q if q else 0
    if ended is not None:
        report["interpretation"] = (f"The open long-lived connection kept working for about {ended}s after quarantine ({survived} requests got through) and then "
                                    "failed: existing tunnels are ended by the proxy's bounded tunnel lifetime, not at the moment of quarantine. New connections "
                                    "were refused throughout.")
    elif survived:
        report["interpretation"] = (f"An open long-lived connection kept working after quarantine ({survived} requests succeeded) for the whole {round(window)}s "
                                    "window; quarantine stopped new connections but did not end the existing one. Existing tunnels persist until they close.")
    else:
        report["interpretation"] = "The long-lived connection failed immediately after quarantine."
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")


if __name__ == "__main__":
    main()
