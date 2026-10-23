# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""What baseline suggestions may and may not say.   python -m unittest scripts/siem/test_suggest_baselines.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import suggest_baselines as sb  # noqa: E402

BASELINE = {"task_profile": "p", "version": "v1", "approved_by": "someone", "allowed_action_classes": ["GET /services/{svc}"],
            "approved_egress_hosts": ["integrate.api.nvidia.com"], "max_req_1m_p95": 60, "max_req_1m_p99": 120}


def route(method, path, calls=50, hours=5, refused=0):
    return {"method": method, "route": path, "host": "h", "calls": calls, "hours": hours, "refused": refused}


class Routes(unittest.TestCase):
    def suggest(self, *routes, **rest):
        return sb.suggest_profile(BASELINE, dict({"routes": list(routes), "egress": [], "rate": {}}, **rest))

    def test_a_steady_safe_route_not_in_the_baseline_is_suggested(self):
        s = self.suggest(route("GET", "/tickets/{id}"))
        self.assertEqual([r["action_class"] for r in s["add_action_classes"]], ["GET /tickets/{id}"])

    def test_a_route_already_there_is_not_suggested_even_if_the_placeholder_is_named_differently(self):
        self.assertEqual(self.suggest(route("GET", "/services/{name}"))["add_action_classes"], [])

    def test_a_destructive_method_is_never_suggested_however_often_it_was_seen(self):
        s = self.suggest(route("DELETE", "/services/{svc}", calls=900, hours=48))
        self.assertEqual(s["add_action_classes"], [])
        self.assertIn("destructive", s["not_suggested"][0]["why_not"])

    def test_anything_refused_even_once_is_not_suggested(self):
        s = self.suggest(route("GET", "/secrets/{name}", refused=1))
        self.assertEqual(s["add_action_classes"], [])
        self.assertIn("refused", s["not_suggested"][0]["why_not"])

    def test_a_burst_is_not_a_habit(self):
        self.assertEqual(self.suggest(route("GET", "/kb", calls=500, hours=1))["add_action_classes"], [])
        self.assertEqual(self.suggest(route("GET", "/kb", calls=5, hours=10))["add_action_classes"], [])


class Egress(unittest.TestCase):
    def test_a_steady_unrefused_host_is_suggested_and_a_known_one_is_not(self):
        egress = [{"destination": "api.example.com:443", "calls": 40, "refused": 0, "shadow": 40, "hours": 6},
                  {"destination": "integrate.api.nvidia.com:443", "calls": 99, "refused": 0, "shadow": 0, "hours": 9},
                  {"destination": "bad.example.com:443", "calls": 99, "refused": 2, "shadow": 0, "hours": 9}]
        s = sb.suggest_profile(BASELINE, {"routes": [], "egress": egress, "rate": {}})
        self.assertEqual([h["host"] for h in s["add_egress_hosts"]], ["api.example.com"])
        self.assertEqual([n["host"] for n in s["not_suggested"]], ["bad.example.com"])


class Rate(unittest.TestCase):
    def test_a_limit_far_above_what_was_seen_is_tightened_never_raised(self):
        s = sb.suggest_profile(BASELINE, {"routes": [], "egress": [], "rate": {"minutes": 500, "p95": 5, "p99": 8}})
        self.assertEqual({t["setting"]: t["suggested"] for t in s["tighten_rate"]}, {"max_req_1m_p95": 10, "max_req_1m_p99": 16})
        higher = sb.suggest_profile(BASELINE, {"routes": [], "egress": [], "rate": {"minutes": 500, "p95": 200, "p99": 400}})
        self.assertEqual(higher["tighten_rate"], [])

    def test_too_little_data_suggests_nothing(self):
        self.assertEqual(sb.suggest_profile(BASELINE, {"routes": [], "egress": [], "rate": {"minutes": 10, "p95": 1, "p99": 1}})["tighten_rate"], [])


class Proposal(unittest.TestCase):
    def test_the_proposal_cannot_be_imported_until_a_person_signs_it(self):
        s = sb.suggest_profile(BASELINE, {"routes": [route("GET", "/kb")], "egress": [], "rate": {}})
        new = sb.propose(BASELINE, s)
        self.assertEqual(new["approved_by"], "")
        self.assertTrue(new["version"].endswith("-proposed"))
        self.assertIn("GET /kb", new["allowed_action_classes"])
        self.assertEqual(BASELINE["allowed_action_classes"], ["GET /services/{svc}"], "the original is untouched")

    def test_every_baseline_in_the_repository_is_found(self):
        self.assertIn("release-ops", sb.baseline_files())


if __name__ == "__main__":
    unittest.main()
