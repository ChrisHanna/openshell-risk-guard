# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""How OpenShell's would-block and Risk Guard's refusals are matched.   python -m unittest scripts/policy/test_agreement.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import agreement  # noqa: E402


def openshell(sandbox, method, path, at):
    return {"time": at, "container": {"uid": sandbox}, "http_request": {"http_method": method, "url": {"path": path}}}


def risk_guard_old(sandbox, method, path, at):
    # written before Risk Guard carried the OpenShell field names
    return {"time": at, "container": {"uid": sandbox}, "unmapped": {"risk_guard": {"http": {"method": method, "path": path}}}}


class Matching(unittest.TestCase):
    def test_the_same_call_in_both_places_is_agreement(self):
        r = agreement.compare([openshell("s1", "GET", "/buckets", 1000)], [openshell("s1", "GET", "/buckets", 1400)])
        self.assertEqual((len(r["both"]), len(r["openshell_only"]), len(r["risk_guard_only"])), (1, 0, 0))

    def test_a_call_only_the_policy_would_block_is_the_list_that_must_be_reviewed(self):
        r = agreement.compare([openshell("s1", "GET", "/health", 1000)], [])
        self.assertEqual([k for k, _ in r["openshell_only"]], [("s1", "GET", "/health")])

    def test_a_refusal_the_policy_would_not_make_is_risk_guards_own_work(self):
        r = agreement.compare([openshell("s1", "GET", "/buckets", 1000)], [openshell("s1", "GET", "/buckets", 1100), openshell("s1", "POST", "/services/x/restart", 5000)])
        self.assertEqual(len(r["risk_guard_only"]), 1)

    def test_the_same_path_in_another_sandbox_or_another_time_is_not_a_match(self):
        self.assertEqual(len(agreement.compare([openshell("s1", "GET", "/b", 1000)], [openshell("s2", "GET", "/b", 1000)])["openshell_only"]), 1)
        self.assertEqual(len(agreement.compare([openshell("s1", "GET", "/b", 1000)], [openshell("s1", "GET", "/b", 1000 + 60_000)])["openshell_only"]), 1)

    def test_method_case_and_query_strings_do_not_hide_a_match(self):
        r = agreement.compare([openshell("s1", "get", "/b?x=1", 1000)], [openshell("s1", "GET", "/b", 1000)])
        self.assertEqual(len(r["both"]), 1)

    def test_older_risk_guard_events_still_match(self):
        r = agreement.compare([openshell("s1", "GET", "/b", 1000)], [risk_guard_old("s1", "GET", "/b", 1000)])
        self.assertEqual(len(r["both"]), 1)

    def test_refusals_from_sandboxes_with_no_audit_policy_are_not_counted_as_risk_guard_only(self):
        r = agreement.compare([openshell("s1", "GET", "/b", 1000)], [openshell("s9", "DELETE", "/services/w", 1000)])
        self.assertEqual(len(r["risk_guard_only"]), 0)


if __name__ == "__main__":
    unittest.main()
