#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Kubernetes hardening baseline: do the manifests, and the pods the cluster actually admitted, meet it?

Every container (init containers included) and every pod is held to the same list of checks, taken from the Pod Security "restricted" standard
plus a few more of our own:

    non_root, no_privilege_escalation, drop_all_capabilities, seccomp, read_only_root, requests, memory_limit,
    dedicated_service_account, no_api_token_unless_needed, no_host_access, no_privileged, secret_mounts_restricted

A failure is either fixed or listed in `deploy/aks/hardening-baseline.json` with a reason. An exception names the workload and the check, so a
new violation, or an exception that is no longer needed, shows up as a difference. The checks do not replace a component-specific review.

    scripts/conformance/hardening.py [--out report.json] [--static-only | --live-only]

* static: the workload manifests under deploy/aks, as written (placeholders such as __SVID_...__ are left in place; the pod templates do not
  depend on them). The OpenShell gateway chart and the SPIRE chart are not rendered here; their pods are covered by the live check.
* live: the pods now running in the namespace, as admitted (defaults and admission changes included).
"""
import argparse
import datetime
import glob
import json
import os
import subprocess
import sys

import yaml

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
NS = "openshell"
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
CHECKS = ["non_root", "no_privilege_escalation", "drop_all_capabilities", "seccomp", "read_only_root", "requests", "memory_limit",
          "dedicated_service_account", "no_api_token_unless_needed", "no_host_access", "no_privileged", "secret_mounts_restricted"]
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


def pod_template(doc):
    spec = doc.get("spec", {})
    if doc["kind"] == "CronJob":
        spec = spec.get("jobTemplate", {}).get("spec", {})
    return spec.get("template", {}).get("spec", {})


def pod_findings(spec):
    """Return (workload-level, per-container) findings as lists of (check, subject, detail)."""
    findings = []
    pod_sc = spec.get("securityContext") or {}
    sa = spec.get("serviceAccountName", "default")
    if sa == "default":
        findings.append(("dedicated_service_account", "pod", "runs as the namespace's default service account"))
    if spec.get("automountServiceAccountToken") is not False:
        findings.append(("no_api_token_unless_needed", "pod", "the Kubernetes API token is mounted"))
    if spec.get("hostNetwork") or spec.get("hostPID") or spec.get("hostIPC"):
        findings.append(("no_host_access", "pod", "uses the host network, PID or IPC namespace"))
    for volume in spec.get("volumes", []):
        if "hostPath" in volume:
            findings.append(("no_host_access", f"volume {volume['name']}", "hostPath volume"))
        secret = volume.get("secret")
        if secret and secret.get("defaultMode") is not None and secret["defaultMode"] > 0o440:
            findings.append(("secret_mounts_restricted", f"volume {volume['name']}", f"secret mode {oct(secret['defaultMode'])} is wider than 0440"))
    secret_volumes = {v["name"] for v in spec.get("volumes", []) if "secret" in v}
    pod_seccomp = (pod_sc.get("seccompProfile") or {}).get("type") in ("RuntimeDefault", "Localhost")
    for container in spec.get("initContainers", []) + spec.get("containers", []):
        name = container["name"]
        sc = container.get("securityContext") or {}
        if not (sc.get("runAsNonRoot") or pod_sc.get("runAsNonRoot") or (sc.get("runAsUser") or pod_sc.get("runAsUser") or 0) > 0):
            findings.append(("non_root", name, "may run as root"))
        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(("no_privilege_escalation", name, "allowPrivilegeEscalation is not false"))
        if [c.upper() for c in (sc.get("capabilities") or {}).get("drop", [])] != ["ALL"]:
            findings.append(("drop_all_capabilities", name, "capabilities are not all dropped"))
        if not (pod_seccomp or (sc.get("seccompProfile") or {}).get("type") in ("RuntimeDefault", "Localhost")):
            findings.append(("seccomp", name, "no seccomp profile"))
        if not sc.get("readOnlyRootFilesystem"):
            findings.append(("read_only_root", name, "the root filesystem is writable"))
        if sc.get("privileged"):
            findings.append(("no_privileged", name, "privileged"))
        resources = container.get("resources") or {}
        requests = resources.get("requests") or {}
        if "cpu" not in requests or "memory" not in requests:
            findings.append(("requests", name, "missing cpu or memory request"))
        if "memory" not in (resources.get("limits") or {}):
            findings.append(("memory_limit", name, "no memory limit"))
        for mount in container.get("volumeMounts", []):
            if mount["name"] in secret_volumes and not mount.get("readOnly"):
                findings.append(("secret_mounts_restricted", name, f"secret volume {mount['name']} is mounted writable"))
    return findings


def classify(findings, workload, exceptions):
    """Split findings into unexplained failures and findings covered by a documented exception."""
    allowed = exceptions.get(workload, {})
    failed, excepted = [], []
    for check, subject, detail in findings:
        entry = {"check": check, "subject": subject, "detail": detail}
        if check in allowed:
            entry["reason"] = allowed[check]
            excepted.append(entry)
        else:
            failed.append(entry)
    return failed, excepted


# What scripts/aks/04-deploy-risk-guard.ps1 puts in place of the placeholders, with every optional feature switched on (SPIFFE listener, tunnel
# gate, sign-in, sandbox identity), so the check sees the largest pod that script can produce.
RISK_GUARD_FILL = {
    '__IMAGE__': 'risk-guard:rendered',
    '__CONSOLE_SIGNIN_ARGS__': '            - --entra-tenant-id=t',
    '__SVID_ARGS__': '            - --svid-listen=0.0.0.0:50062',
    '__SVID_SERVICE_PORT__': '    - name: grpc-svid' + chr(10) + '      port: 50062' + chr(10) + '      targetPort: grpc-svid',
    '__SVID_CONTAINER_PORT__': '            - name: grpc-svid' + chr(10) + '              containerPort: 50062',
    '__SVID_MOUNT__': chr(10).join(['            - name: spire-bundle', '              mountPath: /etc/spire/bundle', '              readOnly: true']),
    '__SVID_VOLUME__': chr(10).join(['        - name: spire-bundle', '          configMap:', '            name: spire-bundle', '            optional: true']),
    '__SVID_POD_SPEC__': '      serviceAccountName: risk-guard-tunnels',
    '__CONSOLE_ENV__': chr(10).join(['          env:', '            - name: RISK_GUARD_SANDBOX_SPIFFE_TRUST_DOMAIN', '              value: x']),
}


def read_docs(path):
    text = open(path, encoding="utf-8").read()
    if os.path.basename(path) == "risk-guard.yaml":
        for key, value in RISK_GUARD_FILL.items():
            text = text.replace(key, value)
    return [d for d in yaml.safe_load_all(text.replace("__", "x_x_")) if isinstance(d, dict)]


def with_console_proxy(docs):
    """Scripts/aks/09-expose-console.ps1 patches the console proxy and certificate client into the Risk Guard pod; check the result."""
    patch_path = os.path.join(ROOT, "deploy", "aks", "console-proxy-patch.yaml")
    patch = yaml.safe_load(open(patch_path, encoding="utf-8").read().replace("__", "x_x_"))["spec"]["template"]["spec"]
    for doc in docs:
        if doc.get("kind") == "Deployment" and doc["metadata"]["name"] == "risk-guard":
            spec = doc["spec"]["template"]["spec"]
            spec["containers"] = spec["containers"] + patch.get("containers", [])
            spec["volumes"] = spec.get("volumes", []) + patch.get("volumes", [])
            spec["initContainers"] = spec.get("initContainers", []) + patch.get("initContainers", [])
    return docs


def static_report(exceptions):
    workloads = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "deploy", "aks", "*.yaml"))):
        docs = read_docs(path)
        if os.path.basename(path) == "risk-guard.yaml":
            docs = with_console_proxy(docs)
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") not in WORKLOAD_KINDS:
                continue
            name = doc["metadata"]["name"]
            failed, excepted = classify(pod_findings(pod_template(doc)), name, exceptions)
            workloads[f"{doc['kind'].lower()}/{name}"] = {"file": os.path.relpath(path, ROOT).replace("\\", "/"), "failed": failed, "excepted": excepted}
    return workloads


def kubectl_json(*args):
    out = subprocess.run(["kubectl", *args, "-o", "json"], capture_output=True, text=True, timeout=120)
    if out.returncode:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {out.stderr.strip()[:300]}")
    return json.loads(out.stdout)


def owner_name(pod):
    labels = pod["metadata"].get("labels", {})
    if labels.get("openshell.ai/component") == "supervisor":
        return "sandbox-supervisor-pod"
    if pod["metadata"]["name"].startswith("default--"):
        return "sandbox-workload-pod"
    for owner in pod["metadata"].get("ownerReferences", []):
        if owner["kind"] == "ReplicaSet":
            return owner["name"].rsplit("-", 1)[0]
        return owner["name"]
    return pod["metadata"]["name"]


def live_report(exceptions):
    pods = kubectl_json("-n", NS, "get", "pods")["items"]
    # An admitted pod has defaults and the token volume filled in; the token is "mounted" unless automount is explicitly false.
    workloads = {}
    for pod in pods:
        name = owner_name(pod)
        failed, excepted = classify(pod_findings(pod["spec"]), name, exceptions)
        entry = workloads.setdefault(name, {"pods": 0, "failed": [], "excepted": []})
        entry["pods"] += 1
        for key, found in (("failed", failed), ("excepted", excepted)):
            for item in found:
                if item not in entry[key]:
                    entry[key].append(item)
    namespace = kubectl_json("get", "ns", NS)["metadata"].get("labels", {})
    return workloads, {k: v for k, v in namespace.items() if k.startswith("pod-security.kubernetes.io/")}


def stale_exceptions(exceptions, *reports):
    """Exceptions that no longer match any finding: they should be removed, or the register stops meaning anything."""
    seen = set()
    for report in reports:
        for key, entry in report.items():
            name = key.split("/", 1)[-1]
            for item in entry["excepted"]:
                seen.add((name, item["check"]))
    unused = []
    for name, checks in exceptions.items():
        if name.startswith("_"):
            continue
        for check in checks:
            if (name, check) not in seen:
                unused.append(f"{name}: {check}")
    return unused


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--live-only", action="store_true")
    args = parser.parse_args()
    register = json.load(open(os.path.join(ROOT, "deploy", "aks", "hardening-baseline.json"), encoding="utf-8"))
    exceptions = {k: v for k, v in register["exceptions"].items()}
    report = {"test": "hardening", "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "checks": CHECKS}
    reports = []
    if not args.live_only:
        report["static"] = static_report(exceptions)
        reports.append(report["static"])
    if not args.static_only:
        report["live"], report["pod_security_labels"] = live_report(exceptions)
        reports.append(report["live"])
    failures = [f"{layer}: {name}: {item['check']} ({item['subject']}) {item['detail']}"
                for layer in ("static", "live") for name, entry in report.get(layer, {}).items() for item in entry["failed"]]
    unused = stale_exceptions(exceptions, *reports) if len(reports) == 2 else []
    report["summary"] = {
        "workloads_checked": {layer: len(report[layer]) for layer in ("static", "live") if layer in report},
        "unexplained_failures": failures, "documented_exceptions": sum(len(e["excepted"]) for r in reports for e in r.values()),
        "exceptions_no_longer_needed": unused}
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")


if __name__ == "__main__":
    main()
