#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""When the security service or its inputs fail, does the protected action stay blocked?

Each case states the failure, the expected result, a stable reason, and what the destination saw. A denial is classed as either a **policy
denial** (Risk Guard answered, with a reason) or a **transport failure** (nobody answered, or the handshake failed). Both must block, but they
mean different things to an operator, so the report keeps them apart.

    scripts/conformance/failure_containment.py [--out report.json] [--tests-command "<command template>"]

Two kinds of case, labelled in the report:

* `live`: run against the deployed cluster now, through the per-request egress proxy. The destination (the demo fixture API) counts
  destructive requests, so "no effect" is checked at the destination rather than assumed from the status code.
* `test`: a failure that cannot safely be induced on a running cluster (a full disk, an expired token). It is covered by a named automated
  test. These are only run, and reported as passed, when `--tests-command` is given; otherwise they are listed as `not run here`.

The live cases need kubectl access and openssl. One temporary Cilium policy is applied (and removed in a `finally`) to make Risk Guard
unreachable from the egress proxy only: the console and the sandboxes keep working while it is in place.
"""
import argparse
import base64
import datetime
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
NS = "openshell"
BLOCK_POLICY = "conformance-block-authorization"

# Runs in the demo caller container. Prints one JSON object: the status and body, or the transport error.
CALLER = r'''
import http.client, json, os, ssl, sys
method, path, cert, key = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.load_verify_locations("/certs/bundle.pem")
def in_memory(text):
    # The caller's filesystem is read-only, so a certificate that is not the pod's own is held in an anonymous memory file.
    descriptor = os.memfd_create("pem")
    os.write(descriptor, text.encode())
    return f"/proc/self/fd/{descriptor}"
if cert == "stdin":
    material = json.loads(sys.stdin.read())
    context.load_cert_chain(in_memory(material["cert"]), in_memory(material["key"]))
elif cert != "-":
    context.load_cert_chain(cert, key)
try:
    connection = http.client.HTTPSConnection("egress-proxy.openshell.svc", 8443, context=context, timeout=10)
    connection.request(method, path, headers={"Host": "api.github.local"})
    response = connection.getresponse()
    print(json.dumps({"status": response.status, "body": response.read(300).decode("utf-8", "replace").strip()}))
except Exception as error:
    print(json.dumps({"error": type(error).__name__, "detail": str(error)[:120]}))
'''

COUNTS = """
import json, urllib.request
print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:18081/_actions"))))
"""

# Cases that cannot be induced live, and the automated test that covers each.
TEST_CASES = [
    {"case": "Risk Guard cannot write its state (full disk, read-only volume)", "failure": "every database write fails",
     "expected": "the request is not forwarded (the proxy gets an unavailable error and fails closed)", "stable_reason": "risk state unavailable",
     "test": "svid_listener::a_request_is_not_forwarded_when_risk_guard_cannot_write_its_state"},
    {"case": "expired, misdirected or foreign-signed supervisor token", "failure": "an invalid token on a supervisor call",
     "expected": "refused as Unauthenticated, whatever else is correct", "stable_reason": "JWT verification failed",
     "test": "sidecar_transport::expired_misdirected_and_foreign_tokens_are_refused"},
    {"case": "no token, another sandbox's token, a gateway token on a supervisor call", "failure": "missing or wrongly scoped credentials",
     "expected": "Unauthenticated or PermissionDenied", "stable_reason": "caller kind and sandbox are enforced per call",
     "test": "sidecar_transport::tls_plus_gateway_jwt_is_required_on_every_supervisor_call"},
    {"case": "unknown workload identity (none, wrong trust domain, a workload posing as a proxy)", "failure": "an identity Risk Guard cannot verify",
     "expected": "denied, or refused outright for a pretend proxy", "stable_reason": "no verified SPIFFE identity / trust domain not accepted",
     "test": "svid_listener::a_trusted_proxy_gets_allow_and_deny_decisions_for_the_workload_it_verified"},
    {"case": "certificate that does not chain to the trust bundle, or names another trust domain", "failure": "an invalid client certificate",
     "expected": "the handshake or the call is refused", "stable_reason": "certificate rejected",
     "test": "svid_listener::certificates_that_do_not_chain_to_the_bundle_or_name_another_trust_domain_are_refused"},
    {"case": "unknown sandbox opens a tunnel", "failure": "a tunnel from an address that is not a known sandbox",
     "expected": "denied", "stable_reason": "the source is not a known sandbox",
     "test": "svid_listener::a_sandbox_tunnel_is_carried_unless_the_sandbox_is_unknown_quarantined_or_restricted_in_enforce_mode"},
]


def kubectl(*args, check=True, timeout=120, input_text=None):
    result = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True, timeout=timeout, input=input_text)
    if check and result.returncode:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {result.stderr.strip()[:300]}")
    return result


def caller(*args, stdin=None):
    flags = ["-i"] if stdin else []
    out = kubectl("exec", *flags, "deploy/egress-demo", "-c", "caller", "--", "python", "-c", CALLER, *args, check=False, timeout=60,
                  input_text=stdin).stdout
    for line in reversed(out.splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    return {"error": "no output"}


def destructive_hits():
    out = kubectl("exec", "deploy/risk-guard-fixture", "--", "python3", "-c", COUNTS).stdout
    actions = json.loads(out)
    return next((a["hits"] for a in actions if a["method"] == "DELETE" and a["path"] == "/services/worker"), 0)


def classify(result):
    """policy denial: Risk Guard answered with a reason. transport failure: no answer, or the handshake failed."""
    if "error" in result:
        return "transport failure", result["error"]
    if result["status"] == 200:
        return "allowed", None
    body = result.get("body", "")
    if "denied by Risk Guard:" in body:
        return "policy denial", body.split("denied by Risk Guard:", 1)[1].strip()
    return "transport failure", f"HTTP {result['status']} with no reason from Risk Guard"


def self_signed(directory):
    cert, key = os.path.join(directory, "c.pem"), os.path.join(directory, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "1", "-subj", "/CN=not-in-the-bundle", "-addext", "subjectAltName=URI:spiffe://risk-guard.demo/ns/openshell/sa/impostor"],
                   check=True, capture_output=True)
    return cert, key


def live_case(name, failure, expected, send, must_be):
    before = destructive_hits()
    result = send()
    after = destructive_hits()
    kind, reason = classify(result)
    return {"kind": "live", "case": name, "failure": failure, "expected": expected, "observed": result, "class": kind, "reason": reason,
            "destructive_requests_that_reached_the_destination": after - before,
            "pass": kind in must_be and after == before}


def deployment():
    image = kubectl("get", "deploy/risk-guard", "-o", "jsonpath={.spec.template.spec.containers[?(@.name==\"risk-guard\")].image}").stdout.strip()
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip() or None
    context = subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True).stdout.strip()
    return {"risk_guard_image": image, "repository_commit": commit, "cluster_context": context}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out")
    parser.add_argument("--tests-command", help="a command template with {suite} and {name}, for example: "
                        "\"wsl -d Ubuntu-24.04 -- bash -c 'cargo test --test {suite} {name}'\"")
    args = parser.parse_args()
    cases = []
    destructive = ("DELETE", "/services/worker")

    # Read once up front so the run fails early when the cluster is not as expected.
    kubectl("get", "deploy/egress-demo", "deploy/egress-proxy", "deploy/risk-guard-fixture", "-o", "name")
    workdir = tempfile.mkdtemp(prefix="containment-")
    bad_cert, bad_key = self_signed(workdir)
    impostor = json.dumps({"cert": open(bad_cert).read(), "key": open(bad_key).read()})

    cases.append(live_case("control: the allowed read goes through", "none", "200 from the destination",
                           lambda: caller("GET", "/repos/local/review", "/certs/svid.pem", "/certs/svid_key.pem"), {"allowed"})
                 )
    cases[-1]["pass"] = cases[-1]["class"] == "allowed"

    cases.append(live_case("a destructive call is refused by policy", "none (the policy decides)", "denied with a stable reason, nothing reaches the destination",
                           lambda: caller(*destructive, "/certs/svid.pem", "/certs/svid_key.pem"), {"policy denial"}))

    cases.append(live_case("the client presents a certificate that is not in the trust bundle", "an invalid client certificate",
                           "the handshake is refused; nothing reaches the destination",
                           lambda: caller(*destructive, "stdin", "-", stdin=impostor), {"transport failure"}))

    cases.append(live_case("the client presents no certificate", "no client identity",
                           "the handshake is refused; nothing reaches the destination",
                           lambda: caller(*destructive, "-", "-"), {"transport failure"}))

    policy = f"""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {{name: {BLOCK_POLICY}, namespace: {NS}}}
spec:
  endpointSelector: {{matchLabels: {{app.kubernetes.io/name: egress-proxy}}}}
  egress: [{{toEntities: [all]}}]
  egressDeny:
    - toEndpoints: [{{matchLabels: {{app.kubernetes.io/name: risk-guard}}}}]
      toPorts: [{{ports: [{{port: "50062", protocol: TCP}}]}}]
"""
    try:
        kubectl("apply", "-f", "-", input_text=policy)
        time.sleep(8)
        # Existing connections from the proxy to Risk Guard are cut by a deny rule; the next request must fail, not be waved through.
        for label, method, path in (("a destructive call", *destructive), ("a harmless read", "GET", "/repos/local/review")):
            cases.append(live_case(f"Risk Guard is unreachable from the proxy: {label}", "authorization times out or cannot connect",
                                   "denied (fail closed), nothing reaches the destination",
                                   lambda m=method, p=path: caller(m, p, "/certs/svid.pem", "/certs/svid_key.pem"), {"transport failure"}))
    finally:
        kubectl("delete", "ciliumnetworkpolicy", BLOCK_POLICY, "--ignore-not-found", check=False)
    time.sleep(8)
    recovered = caller("GET", "/repos/local/review", "/certs/svid.pem", "/certs/svid_key.pem")
    cases.append({"kind": "live", "case": "recovery: once Risk Guard is reachable again the allowed read works", "failure": "none", "expected": "200",
                  "observed": recovered, "class": classify(recovered)[0], "reason": None, "pass": recovered.get("status") == 200})

    tests_ran = {}
    for case in TEST_CASES:
        entry = {"kind": "test", "case": case["case"], "failure": case["failure"], "expected": case["expected"], "reason": case["stable_reason"],
                 "test": case["test"]}
        if args.tests_command:
            name = case["test"].split("::")[-1]
            suite = case["test"].split("::")[0]
            if name not in tests_ran:
                run = subprocess.run(shlex.split(args.tests_command.format(suite=suite, name=name)), capture_output=True, text=True)
                tests_ran[name] = run.returncode == 0 and "1 passed" in run.stdout
            entry["pass"] = tests_ran[name]
        else:
            entry["pass"] = None
            entry["note"] = "not run here; run the named test"
        cases.append(entry)

    report = {
        "test": "failure_containment", "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "deployment": deployment(),
        "summary": {"live_passed": sum(1 for c in cases if c["kind"] == "live" and c["pass"]),
                    "live_total": sum(1 for c in cases if c["kind"] == "live"),
                    "test_cases_passed": sum(1 for c in cases if c["kind"] == "test" and c["pass"]),
                    "test_cases_not_run": sum(1 for c in cases if c["kind"] == "test" and c["pass"] is None),
                    "failed": [c["case"] for c in cases if c["pass"] is False]},
        "cases": cases,
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    sys.exit(1 if report["summary"]["failed"] else 0)


if __name__ == "__main__":
    main()
