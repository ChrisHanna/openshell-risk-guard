#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Can a sandbox, or a compromised supervisor, reach a destination around the intended path?

Two network positions are tested from a real OpenShell sandbox:

* the **agent** (the process in the Kata micro-VM): what OpenShell lets it reach;
* the **supervisor** (the pod next to it that enforces policy and holds the credentials): tested by running a short-lived curl container
  inside the supervisor's pod, which has exactly the supervisor's network position. This stands for a compromised supervisor.

Each case states what was expected and what was observed, and the report records the deployed revision and which network policies were
in force. The fixture destination counts the requests that reach it, so a case that must not have an effect is checked at the destination.

    scripts/conformance/egress_bypass.py [--out report.json]

Needs kubectl access. It creates one sandbox and removes it. Run it before and after applying the supervisor fence
(deploy/aks/supervisor-fence.yaml) to see the difference.
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
NS = "openshell"
WORKLOAD = "bypass-test"
PROBE_IMAGE = "curlimages/curl:8.10.1"

FIXTURE_COUNTS = """
import json, urllib.request
print(json.dumps({"counters": json.load(urllib.request.urlopen("http://127.0.0.1:18081/_evidence")),
                  "actions": json.load(urllib.request.urlopen("http://127.0.0.1:18081/_actions"))}))
"""

# From the agent, inside the sandbox. A mediated connection is answered by the supervisor, so "denied" here is OpenShell's policy.
AGENT_CASES = r'''
import json, sys, urllib.request, urllib.error
cases = json.loads(sys.argv[1]); out = []
for c in cases:
    try:
        r = urllib.request.urlopen(urllib.request.Request(c["url"], method=c.get("method", "GET")), timeout=8)
        out.append({"id": c["id"], "reached": True, "detail": r.status})
    except urllib.error.HTTPError as e:
        out.append({"id": c["id"], "reached": e.code < 400, "detail": e.code})
    except Exception as e:
        out.append({"id": c["id"], "reached": False, "detail": type(e).__name__})
print(json.dumps(out))
'''


def kubectl(*args, check=True, timeout=300, input_text=None):
    result = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, timeout=timeout, input=input_text)
    if check and result.returncode:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {result.stderr.strip()[:300]}")
    return result


def fleet(*args, **kw):
    return kubectl("exec", "deploy/agent-fleet", "--", "env", "HOME=/tmp/fleet", "OPENSHELL_GATEWAY=aks", *args, **kw)


def fixture_counts():
    out = kubectl("exec", "deploy/risk-guard-fixture", "--", "python3", "-c", FIXTURE_COUNTS).stdout
    data = json.loads(out)
    delete = next((a["hits"] for a in data["actions"] if a["method"] == "DELETE" and a["path"] == "/services/worker"), 0)
    return {"destructive_hits": delete, "counters": data["counters"]}


def policies_in_force():
    names = []
    for kind in ("networkpolicy", "ciliumnetworkpolicy"):
        out = kubectl("get", kind, "-o", "name", check=False).stdout.split()
        names += [n.split("/")[-1] for n in out]
    return sorted(names)


def deployment():
    image = kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[0].image}").stdout.strip()
    return {"risk_guard_image": image, "network_policies": policies_in_force()}


def supervisor_probe(pod, label, commands, wait=90):
    """Run `commands` (a shell script printing one `id=value` line each) in a curl container that shares the supervisor pod's network."""
    container = f"probe-{label}-{int(time.time())}"
    kubectl("debug", pod, "-q", "--image", PROBE_IMAGE, "--target", "supervisor", "--container", container, "--profile=general",
            "--attach=false", "--", "sh", "-c", commands)
    deadline = time.time() + wait
    while time.time() < deadline:
        status = kubectl("get", "pod", pod, "-o",
                         "jsonpath={.status.ephemeralContainerStatuses[?(@.name=='" + container + "')].state.terminated.exitCode}", check=False).stdout.strip()
        if status != "":
            break
        time.sleep(3)
    return kubectl("logs", pod, "-c", container, check=False).stdout


def curl(url_id, url, method="GET", extra=""):
    # "reachable" means the TCP connection was made (time_connect > 0), whatever the server then said: a TLS or HTTP error is still a reachable host.
    return (f'out=$(curl -s -m 6 --connect-timeout 4 {extra} -X {method} -o /dev/null -w "%{{http_code}}:%{{time_connect}}" "{url}" 2>/dev/null); '
            f'echo "{url_id}=$out"; ')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out")
    args = parser.parse_args()
    name = "bypass-" + datetime.datetime.now().strftime("%H%M%S")
    acr = kubectl("get", "deploy/agent-fleet", "-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name==\"ACR_SERVER\")].value}").stdout.strip()
    here = os.path.dirname(__file__)
    policy = open(os.path.join(here, "..", "..", "deploy", "aks", "agents", "support", "policy.yaml"), "rb").read()
    kubectl("exec", "deploy/risk-guard", "-c", "risk-guard", "--", "/usr/local/bin/openshell-risk-guard", "agent-register", "--db",
            "/var/lib/openshell-risk-guard/risk-guard.db", "--agent-id", WORKLOAD, "--display-name", WORKLOAD, check=False)
    fleet("sh", "-c", f"echo {base64.b64encode(policy).decode()} | base64 -d > /tmp/bypass-policy.yaml")
    print("creating sandbox", name, flush=True)
    fleet("openshell", "sandbox", "create", "--name", name, "--from", f"{acr}/openshell-demo/nat-agent:3", "--policy", "/tmp/bypass-policy.yaml",
          "--provider", "nvidia-nat", "--annotation", f"openshell.nvidia.com/agent-id={WORKLOAD}", "--annotation",
          "openshell.nvidia.com/agent-name=bypass-test", "--no-tty", "--detach", "--", "/usr/bin/sleep", "infinity", timeout=180, check=False)
    # The workload pod is named after the sandbox and carries the id that pairs it with its supervisor pod.
    sandbox_id = None
    for _ in range(60):
        pair = kubectl("get", "pod", f"default--{name}", "-o", r"jsonpath={.metadata.labels.openshell\.ai/boundary-pair}", check=False).stdout.strip()
        ready = kubectl("get", "pod", f"os-supervisor-{pair}", "-o", "jsonpath={.status.containerStatuses[0].ready}", check=False).stdout.strip() if pair else ""
        phase = fleet("openshell", "sandbox", "get", name, "--output", "json", check=False).stdout
        if pair and ready == "true" and '"Ready"' in phase.replace('": "', '":"').replace('"phase":"Ready"', '"Ready"'):
            sandbox_id = pair
            break
        time.sleep(6)
    if not sandbox_id:
        fleet("openshell", "sandbox", "delete", name, check=False)
        sys.exit("the sandbox did not become ready")
    supervisor = f"pod/os-supervisor-{sandbox_id}"
    results = []
    try:
        before = fixture_counts()

        # --- the agent
        cases = [
            {"id": "agent: approved destination through the intended path", "url": "http://support-api.openshell.svc.cluster.local:18081/tickets", "expect": True},
            {"id": "agent: destination its policy does not list (deploy-api)", "url": "http://deploy-api.openshell.svc.cluster.local:18081/services", "expect": False},
            {"id": "agent: a destructive call to an unlisted service", "url": "http://deploy-api.openshell.svc.cluster.local:18081/services/worker", "method": "DELETE", "expect": False},
            {"id": "agent: the internet over HTTP", "url": "http://example.com/", "expect": False},
            {"id": "agent: the internet over HTTPS", "url": "https://example.com/", "expect": False},
            {"id": "agent: the cloud metadata address", "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "expect": False},
            {"id": "agent: an arbitrary address and port", "url": "http://93.184.216.34:8080/", "expect": False},
            {"id": "agent: the Kubernetes API", "url": "https://kubernetes.default.svc/healthz", "expect": False},
        ]
        encoded = base64.b64encode(AGENT_CASES.encode()).decode()
        run = fleet("openshell", "sandbox", "exec", "--name", name, "--no-tty", "--no-login-shell", "--", "/bin/sh", "-c",
                    f"echo {encoded} | base64 -d > /tmp/c.py; /opt/agent/bin/python3.12 /tmp/c.py '{json.dumps(cases)}'", check=False, timeout=240)
        observed = {}
        for line in run.stdout.splitlines():
            if line.startswith("["):
                observed = {o["id"]: o for o in json.loads(line)}
        for case in cases:
            o = observed.get(case["id"], {"reached": None, "detail": "no result"})
            results.append({"position": "agent", "case": case["id"], "expected_reachable": case["expect"], "reached": o["reached"], "detail": o["detail"],
                            "pass": o["reached"] == case["expect"]})

        # --- the supervisor (a compromised supervisor)
        sup = [
            ("internet over HTTPS, around the proxy", "internet-https", curl("internet-https", "https://example.com/"), False),
            ("internet over HTTP", "internet-http", curl("internet-http", "http://example.com/"), False),
            ("an arbitrary address and port", "odd-port", curl("odd-port", "http://93.184.216.34:8080/"), False),
            ("the cloud metadata address", "metadata", curl("metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", extra="-H Metadata:true"), False),
            ("the Kubernetes API", "apiserver", curl("apiserver", "https://kubernetes.default.svc/healthz", extra="-k"), False),
            ("the SPIRE server", "spire", curl("spire", "http://spire-server.openshell.svc.cluster.local:8081/"), False),
            ("Risk Guard's identity listener", "rg-svid", curl("rg-svid", "https://risk-guard.openshell.svc.cluster.local:50062/", extra="-k"), False),
            ("the OpenShell gateway (needed)", "gateway", curl("gateway", "https://openshell.openshell.svc.cluster.local:8080/", extra="-k"), True),
            ("Risk Guard's middleware (needed)", "rg-mw", curl("rg-mw", "https://risk-guard.openshell.svc.cluster.local:50061/", extra="-k"), True),
            ("the tunnel proxy (needed)", "proxy", curl("proxy", "http://sandbox-egress.openshell.svc.cluster.local:8444/", extra=""), True),
            ("an in-cluster plain-HTTP destination, directly", "fixture-direct",
             curl("fixture-direct", "http://deploy-api.openshell.svc.cluster.local:18081/services/worker", method="DELETE"), "documented"),
        ]
        out = supervisor_probe(supervisor, "a", "".join(c for _, _, c, _ in sup))
        got = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        for text, key, _, expect in sup:
            raw = got.get(key, "")
            code, _, connect = raw.partition(":")
            try:
                reachable = float(connect) > 0
            except ValueError:
                reachable = False
            code = code if reachable else (code if raw else "")
            row = {"position": "supervisor", "case": text, "expected_reachable": expect, "reached": reachable, "detail": (f"connected, HTTP {code}" if reachable else "no connection") if raw else "no result"}
            row["pass"] = (reachable == expect) if isinstance(expect, bool) else None
            results.append(row)
        after = fixture_counts()
    finally:
        fleet("openshell", "sandbox", "delete", name, check=False)

    report = {
        "test": "egress_bypass", "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "deployment": deployment(),
        "destination_side": {"before": before, "after": after,
                             "destructive_requests_that_arrived": after["destructive_hits"] - before["destructive_hits"]},
        "results": results,
        "failed": [r["case"] for r in results if r["pass"] is False],
        "documented_limit": "A compromised supervisor can reach in-cluster plain-HTTP destinations directly: the supervisor is their enforcement point, "
                            "and a network policy cannot tell its legitimate forwarding from a bypass. 'destructive_requests_that_arrived' counts that.",
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    sys.exit(1 if report["failed"] else 0)


if __name__ == "__main__":
    main()
