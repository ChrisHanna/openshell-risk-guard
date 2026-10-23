#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Where do the security services actually run, and what can the workloads next to them change?

Two groups of checks, both against the live cluster:

* **placement**: against deploy/aks/placement-profile.json. Each security workload must run on a node carrying the profile's label, and that
  node must run nothing that belongs to sandboxes or demos. The report says which nodes the services are on *now*, so a deployment that
  has not applied the hardened profile fails these checks, and says so.
* **permissions**: for each service account that sandboxes and demo workloads run as, `kubectl auth can-i` (impersonating it) asked about
  the actions that would let it weaken the security services: read secrets, change or delete their workloads or network policies, exec into
  their pods. Every one must be refused. The service accounts the security services themselves use are listed with what they may do, so
  the exceptions are visible.

    scripts/conformance/placement.py [--out report.json] [--placement-only]

What this does not show: that the nodes are separate trust domains. They share a control plane and a cluster administrator, who can do all
of this regardless (see docs/adr/0001-security-placement.md).
"""
import argparse
import datetime
import json
import os
import subprocess
import sys

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
NS = "openshell"
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")

# Service accounts that sandboxes and demo workloads run as: none of them may change the security services.
UNTRUSTED_SERVICE_ACCOUNTS = ["openshell-sandbox", "default", "egress-demo", "svid-demo"]
# Service accounts of the platform: the security services, and the install-time certificate job. Their powers are reported, not asserted away.
SECURITY_SERVICE_ACCOUNTS = ["openshell", "openshell-certgen", "sandbox-egress", "risk-guard-tunnels", "egress-proxy", "spire-server", "spire-agent"]
# (verb, resource, name) tried against the namespace.
ATTACKS = [
    ("get", "secrets", None), ("list", "secrets", None),
    ("patch", "deployments.apps", "risk-guard"), ("delete", "deployments.apps", "risk-guard"),
    ("patch", "deployments.apps", "sandbox-egress"), ("patch", "statefulsets.apps", "spire-server"),
    ("update", "networkpolicies.networking.k8s.io", None), ("delete", "networkpolicies.networking.k8s.io", None),
    ("update", "ciliumnetworkpolicies.cilium.io", None), ("delete", "ciliumnetworkpolicies.cilium.io", None),
    ("create", "pods/exec", None), ("create", "pods/portforward", None),
    ("patch", "configmaps", "spire-bundle"), ("delete", "persistentvolumeclaims", None),
]


def kubectl(*args, check=True):
    result = subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=120)
    if check and result.returncode:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def can_i(account, verb, resource, name):
    target = f"{resource}/{name}" if name else resource
    out = kubectl("auth", "can-i", verb, target, "-n", NS, "--as", f"system:serviceaccount:{NS}:{account}", check=False).strip()
    return out.startswith("yes")


def pods():
    return json.loads(kubectl("get", "pods", "-A", "-o", "json"))["items"]


def owner_workload(pod):
    """The deployment, statefulset or daemonset a pod belongs to, by name."""
    for owner in pod["metadata"].get("ownerReferences", []):
        if owner["kind"] == "ReplicaSet":
            return "deployment", owner["name"].rsplit("-", 1)[0]
        return owner["kind"].lower(), owner["name"]
    return "pod", pod["metadata"]["name"]


def placement(profile):
    nodes = {n["metadata"]["name"]: n["metadata"].get("labels", {}) for n in json.loads(kubectl("get", "nodes", "-o", "json"))["items"]}
    label_key, label_value = next(iter(profile["node_labels"].items()))
    security_nodes = {name for name, labels in nodes.items() if labels.get(label_key) == label_value}
    allowed = {(w["kind"], w["name"]) for w in profile["security_workloads"]}
    daemons = set(profile["per_node_daemons_allowed_on_security_nodes"])
    items = pods()
    where = {}
    for pod in items:
        if pod["metadata"]["namespace"] == NS:
            kind, name = owner_workload(pod)
            where.setdefault((kind, name), set()).add(pod["spec"].get("nodeName"))
    checks = []
    for workload in profile["security_workloads"]:
        placed = sorted(n for n in where.get((workload["kind"], workload["name"]), set()) if n)
        checks.append({"check": f"{workload['kind']}/{workload['name']} runs on a '{label_key}={label_value}' node", "nodes_now": placed,
                       "pass": bool(placed) and all(n in security_nodes for n in placed)})
    strangers = []
    for pod in items:
        node = pod["spec"].get("nodeName")
        if node in security_nodes:
            kind, name = owner_workload(pod)
            if (kind, name) in allowed or pod["metadata"]["namespace"] == "kube-system":
                continue
            if kind == "daemonset" and name in daemons:
                continue
            strangers.append(f"{pod['metadata']['namespace']}/{pod['metadata']['name']}")
    checks.append({"check": "no sandbox, supervisor or demo pod shares a security node", "security_nodes": sorted(security_nodes),
                   "unexpected_pods": strangers, "pass": bool(security_nodes) and not strangers})
    service_nodes = sorted({n for key, ns in where.items() if key in allowed for n in ns if n})
    sandbox_nodes = sorted({p["spec"].get("nodeName") for p in items
                            if p["metadata"].get("labels", {}).get("openshell.ai/component") == "supervisor" and p["spec"].get("nodeName")})
    return checks, {"security_services_run_on": service_nodes, "sandbox_supervisors_run_on": sandbox_nodes,
                    "security_services_share_a_node_with_sandboxes": sorted(set(service_nodes) & set(sandbox_nodes))}


def permissions():
    untrusted = []
    for account in UNTRUSTED_SERVICE_ACCOUNTS:
        if kubectl("get", "sa", account, "-n", NS, "-o", "name", check=False).strip() == "":
            continue
        for verb, resource, name in ATTACKS:
            allowed = can_i(account, verb, resource, name)
            untrusted.append({"service_account": account, "action": f"{verb} {resource}" + (f"/{name}" if name else ""), "allowed": allowed, "pass": not allowed})
    security = []
    for account in SECURITY_SERVICE_ACCOUNTS:
        if kubectl("get", "sa", account, "-n", NS, "-o", "name", check=False).strip() == "":
            continue
        granted = [f"{verb} {resource}" + (f"/{name}" if name else "") for verb, resource, name in ATTACKS if can_i(account, verb, resource, name)]
        security.append({"service_account": account, "can_do_of_the_listed_actions": granted})
    automount = []
    for pod in pods():
        labels = pod["metadata"].get("labels", {})
        if labels.get("openshell.ai/component") == "supervisor" or pod["metadata"]["name"].startswith("default--"):
            automount.append(pod["spec"].get("automountServiceAccountToken"))
    return untrusted, security, {"sandbox_pods_checked": len(automount), "sandbox_pods_with_api_token_mounted": sum(1 for a in automount if a is not False)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out")
    parser.add_argument("--placement-only", action="store_true")
    args = parser.parse_args()
    profile = json.load(open(os.path.join(ROOT, "deploy", "aks", "placement-profile.json"), encoding="utf-8"))
    checks, summary = placement(profile)
    report = {"test": "placement", "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "profile": profile["name"], "scope_note": "node separation only; the nodes share a control plane and cluster administrators",
              "placement": {"checks": checks, **summary}}
    if not args.placement_only:
        untrusted, security, tokens = permissions()
        report["permissions"] = {"untrusted_service_accounts": untrusted, "security_service_accounts": security, "sandbox_pod_tokens": tokens}
        failed = [c["check"] for c in checks if not c["pass"]] + [f"{u['service_account']} may {u['action']}" for u in untrusted if not u["pass"]]
        if tokens["sandbox_pods_with_api_token_mounted"]:
            failed.append("a sandbox pod has the Kubernetes API token mounted")
        report["summary"] = {"placement_checks_passed": sum(1 for c in checks if c["pass"]), "placement_checks": len(checks),
                             "permission_checks_passed": sum(1 for u in untrusted if u["pass"]), "permission_checks": len(untrusted), "failed": failed}
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")


if __name__ == "__main__":
    main()
