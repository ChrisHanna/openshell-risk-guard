# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""The path probe's mutations, its reading of OpenShell's events, and the committed result.   python -m unittest scripts/policy/test_path_probe.py"""
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import path_probe  # noqa: E402

RESULT = os.path.join(ROOT, "conformance", "policy-export", "path-edge-cases.json")


def event(message, status_detail=None, path=None):
    return {"message": message, "status_detail": status_detail, "path": path, "class": "HTTP Activity"}


class Mutations(unittest.TestCase):
    def test_the_probe_applies_every_mutation_kind_the_rust_fuzzer_does(self):
        source = open(os.path.join(ROOT, "tests", "red_team_fuzz.rs"), encoding="utf-8").read()
        rust = {re.sub(r"\s*\{index\}", "", m) for m in re.findall(r'add\(\s*(?:&format!\()?"([^"]+)"', source[: source.index("fn host_variants")])}
        ours = {re.sub(r" \d+$", "", kind) for kind, _ in path_probe.path_variants("/services/Worker")}
        self.assertEqual(rust - ours, set(), "a mutation kind of tests/red_team_fuzz.rs is missing from path_probe.path_variants")

    def test_a_mutation_never_equals_the_seed(self):
        self.assertTrue(all(value != "/services/worker" for _, value in path_probe.path_variants("/services/worker")))

    def test_the_cases_cover_the_catalog_evasions_and_the_hosts_and_method_spellings(self):
        ids = {c["id"] for profile in ("release", "cloud") for c in path_probe.build_cases(profile, False)}
        for wanted in ("RT-007", "RT-008", "RT-010", "RT-011", "RT-012", "control-allowed"):
            self.assertIn(wanted, ids)
        self.assertTrue(any("host upper case" in i for i in ids) and any("method lower case" in i for i in ids))


class Reading(unittest.TestCase):
    def test_an_audit_would_block_followed_by_a_risk_guard_denial(self):
        got = path_probe.classify({"status_line": "HTTP/1.1 403 Forbidden", "body": "{}"}, [
            event("L7_REQUEST audit DELETE h:18081/services/worker reason=DELETE /services/worker not permitted by policy", path="/services/worker"),
            event("MIDDLEWARE risk-guard risk-guard decision=Deny", "middleware_denied:risk-guard:task_constraint_denied", "/services/worker")])
        self.assertEqual((got["openshell"], got["final"]), ("would block (audit)", "refused by Risk Guard"))
        self.assertIn("Deny", got["risk_guard"])

    def test_an_enforce_denial_means_risk_guard_was_not_consulted(self):
        got = path_probe.classify({"status_line": "HTTP/1.1 403 Forbidden", "body": '{"error":"policy_denied"}'}, [event("L7_REQUEST deny DELETE h:18081/services/worker reason=x")])
        self.assertEqual((got["openshell"], got["risk_guard"], got["final"]), ("denied", "not consulted", "refused by OpenShell policy"))

    def test_a_request_rejected_before_policy_is_malformed_and_nothing_reaches_the_service(self):
        got = path_probe.classify({"status_line": None, "error": "ConnectionResetError"}, [event("HTTP request rejected before policy evaluation for h:18081")])
        self.assertEqual((got["openshell"], got["final"]), ("malformed (rejected before any rule)", "dropped"))

    def test_an_allowed_route_reaches_the_service(self):
        got = path_probe.classify({"status_line": "HTTP/1.1 200 OK", "body": '{"local_fixture": true}'}, [event("L7_REQUEST allow GET h:18081/services reason="), event("MIDDLEWARE risk-guard risk-guard decision=Allow")])
        self.assertEqual((got["openshell"], got["final"]), ("allowed by rule", "reached the service"))

    def test_a_method_openshell_does_not_recognise_is_refused_by_openshell(self):
        got = path_probe.classify({"status_line": "HTTP/1.1 403 Forbidden", "body": ""}, [event("CONNECT_L7 blocked unsupported tunnel protocol for h:18081")])
        self.assertEqual(got["final"], "refused by OpenShell (not recognised as HTTP)")


class CommittedResult(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(RESULT, encoding="utf-8") as f:
            cls.data = json.load(f)

    def test_every_catalog_evasion_is_stopped_in_enforce_mode_and_none_reached_a_service(self):
        for case in self.data["cases"]:
            if case["source"] == "catalog" and case["mode"] == "enforce" and case["id"] in ("RT-007", "RT-008", "RT-010", "RT-011", "RT-012"):
                self.assertFalse(case["openshell_allowed_by_rule"], case["id"])
                self.assertNotEqual(case["final"], "reached the service", case["id"])

    def test_the_unsafe_list_is_exactly_the_documented_one(self):
        # docs/policy-path-edge-cases.md explains each. A new entry means a new finding to write up; a missing one means the documentation is stale.
        documented = {f"{p} {m} traverse-3 GET {path}" for p, path in (("release", "/services/..%5ccustomers"), ("cloud", "/buckets/..%5csecrets")) for m in ("audit", "enforce")}
        self.assertEqual(set(self.data["unsafe"]), documented)

    def test_audit_and_enforce_differ_only_in_who_refuses(self):
        by_key = {}
        for case in self.data["cases"]:
            by_key.setdefault((case["profile"], case["id"]), {})[case["mode"]] = case
        for key, modes in by_key.items():
            a, e = modes["audit"], modes["enforce"]
            self.assertEqual(a["openshell_saw_path"] == e["openshell_saw_path"] or a["final"] != "reached the service", True, key)
            if e["final"] == "reached the service":
                self.assertEqual(a["final"], "reached the service", key)

    def test_no_request_reached_a_destructive_route_of_the_service(self):
        self.assertFalse([k for k in self.data["service_hits_during_run"] if k.startswith(("DELETE", "PUT", "PATCH"))])


if __name__ == "__main__":
    unittest.main()
