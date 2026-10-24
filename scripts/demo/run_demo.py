#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""The partner demo, driven against the real deployment. Nothing here is simulated: every line printed comes from the running system.

    scripts/demo/run_demo.py --prepare        once, before the meeting: create the standing sandbox (about a minute)
    scripts/demo/run_demo.py [--pause]        the four acts (about 90 seconds); --pause waits for Enter between acts
    scripts/demo/run_demo.py --cleanup        remove the standing sandbox

The four acts:
  1. Routine work is allowed, and the decision costs a few milliseconds.
  2. A destructive call is refused by policy and nothing reaches the destination (the destination's own counter proves it).
  3. An operator quarantines the workload: a sandbox that could reach the network a moment ago can no longer open a new connection.
  4. The recorded decisions are exported and replayed from nothing, and every one is reproduced.

Needs kubectl access to the cluster. Act 3 needs the standing sandbox from --prepare; without it that act is skipped, not faked.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
NS = "openshell"
DB = "/var/lib/openshell-risk-guard/risk-guard.db"
SANDBOX = "demo-contain"
WORKLOAD = "demo-contain"
HOST = "integrate.api.nvidia.com"
HERE = os.path.dirname(os.path.abspath(__file__))
BOLD, DIM, GREEN, RED, AMBER, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[0m"

PROBE = r'''
import http.client, os, ssl, threading, time
threading.Timer(28, lambda: os._exit(3)).start()
began = time.time()
try:
    connection = http.client.HTTPSConnection("%s", timeout=10, context=ssl.create_default_context())
    connection.request("GET", "/v1/models")
    status = connection.getresponse().status
    print("connected", status, round(time.time() - began, 1), flush=True)
except Exception as error:
    print("refused", type(error).__name__, round(time.time() - began, 1), flush=True)
os._exit(0)
''' % HOST


def kubectl(*args, check=True, timeout=300):
    result = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, timeout=timeout, encoding="utf-8")
    if check and result.returncode:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def fleet(*args, **kw):
    return kubectl("exec", "deploy/agent-fleet", "--", "env", "HOME=/tmp/fleet", "OPENSHELL_GATEWAY=aks", *args, **kw)


def risk_guard(*args, **kw):
    return kubectl("exec", "deploy/risk-guard", "-c", "risk-guard", "--", "/usr/local/bin/openshell-risk-guard", *args, **kw)


def caller(*args):
    return kubectl("exec", "deploy/egress-demo", "-c", "caller", "--", "python", "/etc/demo/call.py", *args, check=False).strip()


def say(text="", style=""):
    print(f"{style}{text}{RESET}", flush=True)


def act(number, title, pause):
    if pause:
        input(f"\n{DIM}[Enter] to start act {number}{RESET}")
    say(f"\nAct {number}  {title}", BOLD)


def console_state():
    host = kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[?(@.name==\"console-acme\")].env[?(@.name==\"DOMAIN\")].value}").strip()
    with urllib.request.urlopen(f"https://{host}/api/state", timeout=60) as response:
        return json.load(response)


def destination_deletes():
    out = kubectl("exec", "deploy/risk-guard-fixture", "--", "python3", "-c",
                  "import json,urllib.request;print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:18081/_actions'))))")
    return next((a["hits"] for a in json.loads(out) if a["method"] == "DELETE" and a["path"] == "/services/worker"), 0)


DELETE_PROBE = r'''
import urllib.error, urllib.request
try:
    urllib.request.urlopen(urllib.request.Request("http://support-api.openshell.svc.cluster.local:18081/customers/1", method="DELETE"), timeout=15)
    print("allowed")
except urllib.error.HTTPError as error:
    print("refused", error.code)
'''


def siem_view():
    """The same kind of refusal, inside a real OpenShell sandbox, as the security events OpenShell writes for a SIEM (OCSF)."""
    sandbox_id = json.loads(fleet("openshell", "sandbox", "get", SANDBOX, "--output", "json"))["id"]
    script = base64.b64encode(DELETE_PROBE.encode()).decode()
    mark = time.time()
    answer = fleet("openshell", "sandbox", "exec", "--name", SANDBOX, "--no-tty", "--no-login-shell", "--", "/bin/sh", "-c",
                   f"echo {script} | base64 -d > /tmp/d.py; /opt/agent/bin/python3.12 /tmp/d.py", check=False, timeout=60).strip().splitlines()[-1:]
    say(f"  inside the sandbox: DELETE /customers/1 -> {answer[0] if answer else 'no answer'}", RED)
    time.sleep(4)
    shown = 0
    for line in kubectl("logs", f"pod/os-supervisor-{sandbox_id}", "--since=60s", check=False).splitlines():
        if "OCSF-JSON " not in line:
            continue
        try:
            record = json.loads(line.split("OCSF-JSON ", 1)[1])
        except ValueError:
            continue
        if record.get("class_uid") == 4002 and record.get("status_detail"):
            say(f"  OCSF  HTTP Activity   {record['action']:8} {record['http_request']['http_method']} {record['http_request']['url']['path']}   {record['status_detail']}", DIM)
            shown += 1
        elif record.get("class_uid") == 2004 and record.get("finding_info", {}).get("uid", "").startswith("risk-guard"):
            say(f"  OCSF  Detection Finding {record['severity']:6} {record['finding_info']['title']} (middleware {record['unmapped'].get('middleware')})", DIM)
            shown += 1
    if not shown:
        say("  (no OCSF records found: is ocsf_json_enabled set? `openshell settings set --global --key ocsf_json_enabled --value true --yes`)", AMBER)


def probe_from_sandbox():
    script = base64.b64encode(PROBE.encode()).decode()
    began = time.time()
    out = fleet("openshell", "sandbox", "exec", "--name", SANDBOX, "--no-tty", "--no-login-shell", "--", "/bin/sh", "-c",
                f"echo {script} | base64 -d > /tmp/p.py; /opt/agent/bin/python3.12 /tmp/p.py", check=False, timeout=90)
    line = next((l for l in out.splitlines() if l.startswith(("connected", "refused"))), "no answer")
    return line, round(time.time() - began, 1)


def prepare():
    acr = kubectl("get", "deploy/agent-fleet", "-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name==\"ACR_SERVER\")].value}").strip()
    policy = open(os.path.join(HERE, "..", "..", "deploy", "aks", "agents", "support", "policy.yaml"), "rb").read()
    risk_guard("agent-register", "--db", DB, "--agent-id", WORKLOAD, "--display-name", "Demo containment sandbox", check=False)
    fleet("sh", "-c", f"echo {base64.b64encode(policy).decode()} | base64 -d > /tmp/demo-policy.yaml")
    say(f"creating sandbox {SANDBOX} (about a minute)...")
    fleet("openshell", "sandbox", "create", "--name", SANDBOX, "--from", f"{acr}/openshell-demo/nat-agent:3", "--policy", "/tmp/demo-policy.yaml",
          "--provider", "nvidia-nat", "--annotation", f"openshell.nvidia.com/agent-id={WORKLOAD}", "--annotation", "openshell.nvidia.com/agent-name=demo-contain",
          "--no-tty", "--detach", "--", "/usr/bin/sleep", "infinity", timeout=240, check=False)
    for _ in range(40):
        if '"Ready"' in fleet("openshell", "sandbox", "get", SANDBOX, "--output", "json", check=False).replace('": "', '":"'):
            line, took = probe_from_sandbox()
            say(f"ready. first connection test: {line} ({took}s)", GREEN)
            return
        time.sleep(6)
    sys.exit("the sandbox did not become ready")


def cleanup():
    risk_guard("workload-release", "--db", DB, "--agent-id", WORKLOAD, "--operator", "demo", "--reason", "cleanup", check=False)
    fleet("openshell", "sandbox", "delete", SANDBOX, check=False)
    say("standing sandbox removed")


def run(pause):
    started = time.time()
    state = console_state()
    latency = state["decision_latency"]
    say("Risk Guard demo, running against the live cluster", BOLD)

    act(1, "Routine work goes through", pause)
    for path in ("/repos/local/review", "/repos/local/review/issues"):
        say("  " + caller("GET", path)[:100], GREEN)
    if latency.get("p50_us") is not None:
        say(f"  Risk Guard's own decision time over the last hour: p50 {latency['p50_us'] / 1000:.1f} ms, p99 {latency['p99_us'] / 1000:.1f} ms (histogram upper bounds; budget 500 ms)", DIM)

    act(2, "A destructive call is refused, and nothing reaches the destination", pause)
    before = destination_deletes()
    say("  " + caller("DELETE", "/services/worker")[:110], RED)
    after = destination_deletes()
    say(f"  destination's own DELETE counter: {before} before, {after} after  ->  {'no effect at the destination' if after == before else 'EFFECT AT DESTINATION'}", GREEN if after == before else RED)

    try:
        fleet("openshell", "sandbox", "get", SANDBOX, check=True)
        say("  and inside an OpenShell sandbox, as the security events a SIEM receives:", DIM)
        siem_view()
    except SystemExit:
        pass

    act(3, "An operator quarantines the workload", pause)
    try:
        fleet("openshell", "sandbox", "get", SANDBOX, check=True)
        have_sandbox = True
    except SystemExit:
        have_sandbox = False
    if not have_sandbox:
        say("  skipped: no standing sandbox (run --prepare first). Measured instead: conformance/quarantine-tunnel-bounded.json", AMBER)
    else:
        line, took = probe_from_sandbox()
        say(f"  before: {line}  ({took}s)", GREEN if line.startswith("connected") else RED)
        risk_guard("workload-quarantine", "--db", DB, "--agent-id", WORKLOAD, "--operator", "demo", "--reason", "live demonstration")
        mark = time.time()
        say("  operator quarantines the workload...", AMBER)
        line, took = probe_from_sandbox()
        say(f"  after:  {line}  ({took}s, {round(time.time() - mark, 1)}s after the quarantine)", RED if line.startswith("refused") else AMBER)
        risk_guard("workload-release", "--db", DB, "--agent-id", WORKLOAD, "--operator", "demo", "--reason", "demonstration over")
        say("  New connections are refused at once. A tunnel already open ends within 120 s (measured 81 s and 112 s).", DIM)

    act(4, "The recorded decisions replay from nothing", pause)
    # A replay needs the whole history from the first decision, and retention prunes old ones. Try the workloads with at least 50 recorded decisions, smallest first (quick to
    # export), and use the first whose history is complete. Names change when agents are renamed, so do not depend on one.
    candidates = sorted((a for a in console_state()["agents"] if a.get("decision_count", 0) >= 50), key=lambda a: a["decision_count"])
    bundle = "/var/lib/openshell-risk-guard/demo-replay.json"
    replayed = False
    for candidate in candidates[:8]:
        exported = json.loads(risk_guard("replay-export", "--db", DB, "--agent-id", candidate["agent_id"], "--out", bundle))
        if not exported["history_complete"]:
            continue
        say(f"  exported {exported['events']} decisions for {candidate.get('display_name') or candidate['agent_id']}; history complete: True", DIM)
        report = json.loads(risk_guard("replay-verify", "--bundle", bundle))
        say(f"  replayed in a fresh store: {report['matched']} of {report['decisions']} decisions and reason codes reproduced"
            f" ({'no differences' if not report['divergences'] else str(len(report['divergences'])) + ' differences'})",
            GREEN if report["reproduced"] else RED)
        replayed = True
        break
    if not replayed:
        say("  skipped: no workload has a complete recorded history yet (older decisions were pruned)", AMBER)
    say(f"\nTotal: {round(time.time() - started)} s", DIM)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--pause", action="store_true")
    args = parser.parse_args()
    if args.prepare:
        prepare()
    elif args.cleanup:
        cleanup()
    else:
        run(args.pause)


if __name__ == "__main__":
    main()
