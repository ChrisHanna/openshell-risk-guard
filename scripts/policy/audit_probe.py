#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Try a generated OpenShell policy in audit mode on the cluster and show what OpenShell records, before anything real uses it.

    python scripts/policy/audit_probe.py [--profile release] [--enforcement audit]

It makes the policy with `policy-export` from the repository's baseline and policy for the profile, creates one throwaway sandbox with it, makes one request the policy
allows and one it does not, waits for the events to reach OpenSearch, and prints OpenShell's own records of both. Then it deletes the sandbox. It changes no running sandbox
and no repository file. Needs kubectl access, WSL with a built `openshell-risk-guard`, and the SIEM.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
NS = "openshell"
IMAGE_TAG = os.environ.get("REDTEAM_IMAGE_TAG", "6")
# profile directory -> a path its policy allows, and one it does not (both harmless reads on the fixture service)
PROBES = {"release": ("deploy-api.openshell.svc.cluster.local", "/services", "/buckets"),
          "support": ("support-api.openshell.svc.cluster.local", None, None),
          "cloud": ("cloud-api.openshell.svc.cluster.local", None, None)}


def kubectl(*args, timeout=300, stdin=None):
    r = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace", input=stdin)
    return r.stdout + (r.stderr if r.returncode else "")


def fleet(*args, **kw):
    return kubectl("exec", "deploy/agent-fleet", "--", "env", "HOME=/tmp/fleet", "OPENSHELL_GATEWAY=aks", *args, **kw)


def generate(profile, enforcement, out):
    wsl_root = ROOT.replace("\\", "/").replace("C:", "/mnt/c")
    command = (f"cd '{wsl_root}' && $HOME/rg-target/debug/openshell-risk-guard policy-export --baseline deploy/aks/agents/{profile}/baseline.json "
               f"--policy deploy/aks/agents/{profile}/policy.yaml --enforcement {enforcement} --out '{out}'")
    r = subprocess.run(["wsl", "-d", "Ubuntu-24.04", "--", "bash", "-c", command], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode:
        sys.exit("policy-export failed: " + (r.stdout + r.stderr).replace("\x00", "")[:400])
    return json.loads(r.stdout.replace("\x00", "").strip().splitlines()[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", default="release")
    parser.add_argument("--enforcement", default="audit")
    args = parser.parse_args()
    host, allowed_path, denied_path = PROBES[args.profile]
    if not allowed_path:
        sys.exit("only the release profile has probe paths so far")
    scratch = os.path.join(ROOT, ".aks", "policy-probe")
    os.makedirs(scratch, exist_ok=True)
    out = os.path.join(scratch, f"{args.profile}.generated.yaml")
    summary = generate(args.profile, args.enforcement, out.replace("\\", "/").replace("C:", "/mnt/c"))
    print(f"generated {args.profile}: {summary['allow_rules']} allow, {summary['deny_rules']} deny, {summary['enforcement']}; prover: {summary['proof']['step2_prover']} (no wider: {summary['proof']['verified_no_wider']})")

    data = open(out, "rb").read()
    fleet("sh", "-c", f"echo {base64.b64encode(data).decode()} | base64 -d > /tmp/probe-policy.yaml")
    acr = kubectl("get", "deploy/agent-fleet", "-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name==\"ACR_SERVER\")].value}").strip()
    name = f"auditprobe-{time.strftime('%H%M%S')}"
    print(f"creating sandbox {name} (about a minute)")
    fleet("openshell", "sandbox", "create", "--name", name, "--from", f"{acr}/openshell-demo/nat-agent:{IMAGE_TAG}", "--policy", "/tmp/probe-policy.yaml",
          "--provider", "nvidia-nat", "--annotation", "openshell.nvidia.com/agent-id=red-team-agent", "--annotation", "openshell.nvidia.com/agent-name=audit-probe",
          "--no-tty", "--detach", "--", "/usr/bin/sleep", "infinity", timeout=300)
    try:
        ready = False
        for _ in range(60):
            if '"Ready"' in fleet("openshell", "sandbox", "get", name, "--output", "json").replace('": "', '":"'):
                ready = True
                break
            time.sleep(6)
        if not ready:
            sys.exit("the sandbox did not become ready")
        probe = ("import urllib.request as u, urllib.error as e\n"
                 f"for path in ({allowed_path!r}, {denied_path!r}):\n"
                 "    try:\n"
                 f"        r = u.urlopen('http://{host}:18081' + path, timeout=15); print(path, r.status)\n"
                 "    except e.HTTPError as x: print(path, x.code, x.read()[:80])\n"
                 "    except Exception as x: print(path, 'error', type(x).__name__)\n")
        out_text = fleet("openshell", "sandbox", "exec", "--name", name, "--no-tty", "--no-login-shell", "--", "/opt/agent/bin/python3.12", "-c", probe, timeout=120)
        print("the sandbox saw:\n" + out_text.strip())
        print("waiting for the events to reach OpenSearch (90 s)")
        time.sleep(90)
        sys.path.insert(0, os.path.join(ROOT, "scripts", "siem"))
        import install_content as siem
        found = siem.opensearch("POST", "/ocsf-openshell*/_search", {"size": 40, "sort": [{"time": "asc"}], "query": {"bool": {"filter": [
            {"term": {"container.name.keyword": name}}, {"exists": {"field": "http_request.url.path"}}]}}})
        rows = [h["_source"] for h in found.get("hits", {}).get("hits", [])]
        print(f"\n{len(rows)} HTTP events for {name}:")
        for d in rows:
            fr = d.get("firewall_rule") or {}
            print(f"  {d.get('http_request', {}).get('http_method'):6} {d.get('http_request', {}).get('url', {}).get('path'):28} action={d.get('action'):8} rule={fr.get('type')}:{fr.get('name')} status={d.get('status')} detail={d.get('status_detail')}\n     {str(d.get('message'))[:150]}")
    finally:
        fleet("openshell", "sandbox", "delete", name, timeout=120)
        print("sandbox deleted")


if __name__ == "__main__":
    main()
