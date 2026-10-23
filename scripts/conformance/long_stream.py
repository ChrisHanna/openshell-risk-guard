#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""What happens to a long-lived connection through the tunnel gate, and does a client that reconnects carry on?

From a real OpenShell sandbox (the standing one from `scripts/demo/run_demo.py --prepare`), to an approved host, three things at once:

* an **active** connection that sends a small request every 10 s, to see when the proxy ends it (expected: at the configured maximum);
* an **idle** connection that sends one request, then waits, to see whether the idle limit closes it (expected only if one is set);
* after the active connection is cut, a **fresh** connection, to show a client that reconnects is unaffected.

    scripts/conformance/long_stream.py [--seconds 160] [--idle-wait 75] [--out report.json]

The settings under test are read from the running proxy's configuration, so the report states what was configured as well as what was observed.
Needs kubectl access and the standing sandbox. It changes nothing.
"""
import argparse
import base64
import datetime
import json
import os
import re
import subprocess
import sys
import threading
import time

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
NS = "openshell"
SANDBOX = "demo-contain"
HOST = "integrate.api.nvidia.com"

IN_SANDBOX = r'''
import http.client, json, os, ssl, sys, threading, time
HOST, SECONDS, IDLE_WAIT = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
key = os.environ.get("NVIDIA_API_KEY", "")
start = time.time()
lock = threading.Lock()
def log(kind, ok, detail):
    with lock:
        print(json.dumps({"t": round(time.time() - start, 1), "kind": kind, "ok": ok, "detail": detail}), flush=True)
def get(conn):
    conn.request("GET", "/v1/models", headers={"Authorization": "Bearer " + key})
    response = conn.getresponse(); response.read()
    return response.status
def make():
    return http.client.HTTPSConnection(HOST, timeout=10, context=ssl.create_default_context())
def active():
    conn = make(); cut = False
    while time.time() - start < SECONDS:
        try:
            log("active", get(conn) == 200, "request")
        except Exception as error:
            log("active", False, type(error).__name__)
            cut = True
            break
        time.sleep(10)
    if cut:
        try:
            log("reconnect", get(make()) == 200, "fresh connection after the cut")
        except Exception as error:
            log("reconnect", False, type(error).__name__)
def idle():
    conn = make()
    try:
        log("idle_first", get(conn) == 200, "request")
    except Exception as error:
        log("idle_first", False, type(error).__name__); return
    time.sleep(IDLE_WAIT)
    try:
        log("idle_after_wait", get(conn) == 200, "request on the same connection")
    except Exception as error:
        log("idle_after_wait", False, type(error).__name__)
threading.Thread(target=lambda: (time.sleep(SECONDS + 40), os._exit(0)), daemon=True).start()
workers = [threading.Thread(target=active, daemon=True), threading.Thread(target=idle, daemon=True)]
[w.start() for w in workers]; [w.join() for w in workers]
os._exit(0)
'''


def kubectl(*args, check=True, timeout=300):
    result = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, timeout=timeout, encoding="utf-8")
    if check and result.returncode:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def configured():
    text = kubectl("get", "configmap/sandbox-egress-config", "-o", "jsonpath={.data}")
    cap = re.search(r"max_stream_duration:\s*\\n\s*max_stream_duration:\s*(\d+)s|max_stream_duration: (\d+)s", text)
    idle = re.search(r"idle_timeout: (\d+)s", text)
    cap_value = next((int(g) for g in (cap.groups() if cap else ()) if g), None)
    return {"max_stream_seconds": cap_value, "idle_timeout_seconds": int(idle.group(1)) if idle else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=160)
    parser.add_argument("--idle-wait", type=int, default=75)
    parser.add_argument("--out")
    args = parser.parse_args()
    settings = configured()
    script = base64.b64encode(IN_SANDBOX.encode()).decode()
    events = []
    process = subprocess.Popen(
        ["kubectl", "-n", NS, "exec", "deploy/agent-fleet", "--", "env", "HOME=/tmp/fleet", "OPENSHELL_GATEWAY=aks", "openshell", "sandbox", "exec",
         "--name", SANDBOX, "--no-tty", "--no-login-shell", "--", "/bin/sh", "-c",
         f"echo {script} | base64 -d > /tmp/ls.py; /opt/agent/bin/python3.12 /tmp/ls.py {HOST} {args.seconds} {args.idle_wait}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")

    def reader():
        for line in process.stdout:
            if line.startswith("{"):
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
    threading.Thread(target=reader, daemon=True).start()
    began = time.time()
    while process.poll() is None and time.time() - began < args.seconds + 100:
        time.sleep(2)
    if process.poll() is None:
        process.kill()

    active = [e for e in events if e["kind"] == "active"]
    cut = next((e["t"] for e in active if not e["ok"]), None)
    idle_after = next((e for e in events if e["kind"] == "idle_after_wait"), None)
    reconnect = next((e for e in events if e["kind"] == "reconnect"), None)
    cap, idle_limit = settings["max_stream_seconds"], settings["idle_timeout_seconds"]
    report = {
        "test": "long_lived_connection", "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "configured": settings, "idle_wait_seconds": args.idle_wait,
        "active_connection": {"requests_ok": sum(1 for e in active if e["ok"]), "cut_after_seconds": cut},
        "idle_connection": {"first_request_ok": any(e["kind"] == "idle_first" and e["ok"] for e in events),
                            "usable_after_waiting": bool(idle_after and idle_after["ok"])},
        "reconnect_after_cut_ok": bool(reconnect and reconnect["ok"]),
    }
    checks = {
        "active connection ended near the configured maximum": cap is not None and cut is not None and cap - 2 <= cut <= cap + 12,
        "a client that reconnects carries on": report["reconnect_after_cut_ok"],
        "idle connection closed when an idle limit is set, kept when none is":
            (not report["idle_connection"]["usable_after_waiting"]) if (idle_limit and args.idle_wait > idle_limit + 5) else report["idle_connection"]["usable_after_waiting"],
    }
    report["checks"] = checks
    report["passed"] = all(checks.values())
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
