#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""How much does the deployed enforcement path cost, and where does it stop scaling?

The same request, GET /repos/local/review (an allowed read), is sent two ways from pods inside the cluster:

* `denied` (a third path): a destructive call the policy refuses, so it never reaches the destination. With the fixture out of the way this
  shows what the enforcement path itself can sustain; the destination is the limit for the other two at high concurrency.
* `direct`: straight to the fixture API from a throwaway pod. This is the floor: the destination's own cost plus the network.
* `proxied`: through the per-request egress proxy (Envoy), which authenticates the caller by its SPIFFE X.509-SVID over mutual TLS and asks
  Risk Guard for a decision on every request. The difference is the cost of enforcement: the proxy hop, the TLS, and the decision
  (which includes scoring and a SQLite write).

Each cell is a closed loop: N workers, each sending a request as soon as the last one finishes, for a fixed time. `keepalive` reuses one
connection per worker; `fresh` opens a connection for every request (the cost of a handshake included). Latency is measured by the client.

    scripts/conformance/bench_path.py [--seconds 20] [--out report.json]

What it does not measure, so the report must not be read as more than it is: the supervisor/middleware path used by OpenShell sandboxes
(Risk Guard's own histogram for that is in the console), the model API, or a destination that does real work. The fixture is a small Python
server; at high concurrency the numbers show where the fixture or the load generator saturates as much as where Risk Guard does, and the
report records CPU for each so that can be told apart. The requests are all routine allowed reads from one identity, so this is a cost
measurement, not a detection measurement.
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

LOADER = r'''
import http.client, json, ssl, sys, threading, time
mode, keepalive, workers, seconds = sys.argv[1], sys.argv[2] == "keepalive", int(sys.argv[3]), float(sys.argv[4])
METHOD, PATH, HOST = ("DELETE", "/services/worker", "api.github.local") if mode == "denied" else ("GET", "/repos/local/review", "api.github.local")
context = None
if mode in ("proxied", "denied"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.load_verify_locations("/certs/bundle.pem")
    context.load_cert_chain("/certs/svid.pem", "/certs/svid_key.pem")
def connect():
    if mode in ("proxied", "denied"):
        return http.client.HTTPSConnection("egress-proxy.openshell.svc", 8443, context=context, timeout=10)
    return http.client.HTTPConnection("risk-guard-fixture.openshell.svc", 18081, timeout=10)
lock = threading.Lock(); samples = []; counts = {"ok": 0, "policy_denied": 0, "other_status": 0, "transport_error": 0}
end = time.time() + seconds
def worker():
    conn = None; local = []; c = {"ok": 0, "policy_denied": 0, "other_status": 0, "transport_error": 0}
    while time.time() < end:
        began = time.perf_counter()
        try:
            if conn is None: conn = connect()
            conn.request(METHOD, PATH, headers={"Host": HOST})
            response = conn.getresponse(); body = response.read(200)
            took = (time.perf_counter() - began) * 1000
            denied = response.status == 403 and b"denied by Risk Guard" in body
            if response.status == 200 and mode != "denied": c["ok"] += 1; local.append(took)
            elif denied: c["policy_denied"] += 1; (local.append(took) if mode == "denied" else None)
            else: c["other_status"] += 1
            if not keepalive: conn.close(); conn = None
        except Exception:
            c["transport_error"] += 1
            try: conn.close()
            except Exception: pass
            conn = None
    with lock:
        samples.extend(local)
        for k in c: counts[k] += c[k]
threads = [threading.Thread(target=worker) for _ in range(workers)]
started = time.time(); [t.start() for t in threads]; [t.join() for t in threads]; elapsed = time.time() - started
samples.sort()
def q(p): return round(samples[min(len(samples) - 1, int(p * len(samples)))], 2) if samples else None
print(json.dumps({"requests": sum(counts.values()), **counts, "seconds": round(elapsed, 1), "per_second": round(sum(counts.values()) / elapsed, 1),
                  "latency_ms": {"p50": q(.5), "p95": q(.95), "p99": q(.99), "max": round(samples[-1], 2) if samples else None,
                                 "mean": round(sum(samples) / len(samples), 2) if samples else None}}))
'''

DIRECT_POD = """apiVersion: v1
kind: Pod
metadata: {name: bench-direct, namespace: openshell, labels: {app.kubernetes.io/name: bench-direct}}
spec:
  automountServiceAccountToken: false
  nodeSelector: {kubernetes.azure.com/agentpool: nodepool1}
  securityContext: {runAsNonRoot: true, runAsUser: 65532, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: loader
      image: %(image)s
      command: [sleep, "3600"]
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      resources: {requests: {cpu: 100m, memory: 64Mi}, limits: {memory: 256Mi}}
"""


def kubectl(*args, input_text=None, check=True, timeout=600):
    result = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, input=input_text, timeout=timeout, encoding="utf-8")
    if check and result.returncode:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {result.stderr.strip()[:300]}")
    return result


def top(*selectors):
    """CPU and memory of the named deployments' pods (a deployment's pod is `<name>-<hash>-<suffix>`, so `risk-guard` does not match the fixture)."""
    import re
    out = kubectl("top", "pods", "--no-headers", check=False).stdout.splitlines()
    found = {}
    for line in out:
        parts = line.split()
        for selector in selectors:
            if len(parts) >= 3 and re.fullmatch(re.escape(selector) + r"(-[a-z0-9]+){2}|" + re.escape(selector), parts[0]):
                found[selector] = {"cpu_millicores": int(parts[1].rstrip("m")), "memory_mib": int(parts[2].rstrip("Mi"))}
    return found


def run_cell(target, mode, keepalive, workers, seconds, sample_pods):
    if target in ("proxied", "denied"):
        base = ["exec", "-i", "deploy/egress-demo", "-c", "caller", "--"]
    else:
        base = ["exec", "-i", "pod/bench-direct", "-c", "loader", "--"]
    process = subprocess.Popen(["kubectl", "-n", NS, *base, "python3" if target == "direct" else "python", "-", mode, keepalive, str(workers), str(seconds)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    process.stdin.write(LOADER)
    process.stdin.close()
    time.sleep(seconds / 2 + 2)
    cpu = top(*sample_pods)
    out, err = process.communicate(timeout=seconds + 120)
    line = next((l for l in reversed(out.splitlines()) if l.startswith("{")), None)
    if not line:
        return {"error": (err or out)[-300:]}
    result = json.loads(line)
    result["pod_usage_mid_run"] = cpu
    return result


def environment():
    nodes = json.loads(kubectl("get", "nodes", "-o", "json").stdout)["items"]
    image = kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[?(@.name==\"risk-guard\")].image}").stdout.strip()
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip() or None
    return {"kubernetes_version": nodes[0]["status"]["nodeInfo"]["kubeletVersion"],
            "nodes": [{"pool": n["metadata"]["labels"].get("agentpool"), "vm_size": n["metadata"]["labels"].get("node.kubernetes.io/instance-type"),
                       "vcpu": n["status"]["capacity"]["cpu"]} for n in nodes],
            "risk_guard_image": image.split("/", 1)[-1], "repository_commit": commit,
            "risk_guard_resources": json.loads(kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[?(@.name==\"risk-guard\")].resources}").stdout or "{}")}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--out")
    args = parser.parse_args()
    fixture_image = kubectl("get", "deploy/risk-guard-fixture", "-o", "jsonpath={.spec.template.spec.containers[0].image}").stdout.strip()
    env = environment()
    kubectl("delete", "pod", "bench-direct", "--ignore-not-found", "--wait=true", check=False)  # a previous run's pod may still be terminating
    kubectl("apply", "-f", "-", input_text=DIRECT_POD % {"image": fixture_image})
    cells = []
    try:
        kubectl("wait", "--for=condition=Ready", "pod/bench-direct", "--timeout=180s")
        plan = [("keepalive", n) for n in (1, 4, 16, 32, 64)] + [("fresh", n) for n in (4, 16)]
        for keepalive, workers in plan:
            for target in ("direct", "proxied", "denied"):
                if target == "denied" and keepalive == "fresh":
                    continue
                print(f"{target:8} {keepalive:9} workers={workers:<3}", flush=True, end=" ")
                sample = ("risk-guard", "egress-proxy", "risk-guard-fixture", "egress-demo", "bench-direct")
                result = run_cell(target, target, keepalive, workers, args.seconds, sample)
                cells.append({"path": target, "connections": keepalive, "workers": workers, **result})
                print(result.get("per_second"), "req/s", result.get("latency_ms"), flush=True)
                time.sleep(3)
    finally:
        kubectl("delete", "pod", "bench-direct", "--ignore-not-found", "--wait=false", check=False)
    report = {"test": "path_benchmark", "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "environment": env, "seconds_per_cell": args.seconds, "request": "GET /repos/local/review (allowed read, one SPIFFE identity)",
              "cells": cells}
    text = json.dumps(report, indent=2)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    print("done")


if __name__ == "__main__":
    main()
