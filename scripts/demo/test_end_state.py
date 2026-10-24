# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""The end-state demo's calls, its disclosure and its reading of Risk Guard's records, checked without a cluster.   python -m unittest scripts/demo/test_end_state.py"""
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import end_state  # noqa: E402


def glob_matches(glob, path):
    """OpenShell's path globs: `*` is within one segment, a whole `**` segment crosses segments."""
    def walk(p, t):
        if not p:
            return not t
        if p[0] == "**":
            return walk(p[1:], t) or (bool(t) and walk(p, t[1:]))
        return bool(t) and re.fullmatch(re.escape(p[0]).replace(r"\*", "[^/]*"), t[0]) is not None and walk(p[1:], t[1:])
    return walk([s for s in glob.split("/") if s], [s for s in path.split("/") if s])


def allowed_by(policy_path, method, path):
    text = open(policy_path, encoding="utf-8").read().replace("\r", "")
    rules = re.findall(r"allow:\n\s+method: (\w+)\n\s+path: (\S+)", text)
    return any(m == method and glob_matches(g, path) for m, g in rules)


class Calls(unittest.TestCase):
    def policy(self, cfg, name):
        return os.path.join(ROOT, "deploy", "aks", "agents", cfg["dir"], name)

    def test_each_act_uses_the_policy_it_claims_to(self):
        for name, cfg in end_state.PROFILES.items():
            demo = self.policy(cfg, "policy.enforce.demo.yaml")
            plain = self.policy(cfg, "policy.enforce.yaml")
            self.assertTrue(allowed_by(demo, *end_state.ACT_A), f"{name}: act A must pass OpenShell")
            self.assertFalse(allowed_by(demo, *end_state.ACT_B), f"{name}: act B must be refused by OpenShell even with the exceptions")
            self.assertTrue(allowed_by(demo, *end_state.ACT_C), f"{name}: act C must pass OpenShell because of the exception")
            self.assertFalse(allowed_by(plain, *end_state.ACT_C), f"{name}: act C must be refused by the plain enforce policy; that is what makes it an exception")
            self.assertTrue(allowed_by(demo, *end_state.ACT_D), f"{name}: act D is an approved route shape, so OpenShell passes it")

    def test_act_d_names_a_resource_the_end_state_profile_does_not_approve(self):
        baseline = json.load(open(os.path.join(ROOT, "deploy", "aks", "agents", "demo-end-state", "baseline.json"), encoding="utf-8"))
        resource = end_state.ACT_D[1].rsplit("/", 1)[1]
        self.assertNotIn(resource, baseline["approved_resources"])
        self.assertEqual(baseline["rule_modes"]["unapproved_resource"], "enforce")
        self.assertEqual(end_state.ACT_C[1].rsplit("/", 1)[1] in baseline["approved_resources"], False)

    def test_the_exceptions_say_they_are_demo_only(self):
        for cfg in end_state.PROFILES.values():
            for e in end_state.exceptions_of(cfg):
                self.assertTrue(e["reason"].startswith("DEMO ONLY"), e)


class Reading(unittest.TestCase):
    def test_rules_are_read_from_the_decision_signals(self):
        deny = {"signals": [{"feature": "I", "baseline_summary": "curated_api_semantics"},
                            {"feature": "task_constraint", "baseline_summary": "rules=unapproved_action,unapproved_resource; forbidden_actions=0,forbid_unfamiliar_high_impact=true"}]}
        self.assertEqual(end_state.rules_of(deny), (["unapproved_action", "unapproved_resource"], []))
        shadow = {"signals": [{"feature": "x", "baseline_summary": "rule=unapproved_resource; mode=shadow"}]}
        self.assertEqual(end_state.rules_of(shadow), ([], ["unapproved_resource"]))

    def test_the_rule_name_is_read_back_from_the_gateways_policy(self):
        text = 'service:\n    name: "release-api (DEMO EXCEPTIONS: 1)"\n    endpoints:'
        match = re.search(r"name:\s*\"?([^\n\"]*DEMO EXCEPTIONS: \d+\))", text)
        self.assertEqual(match.group(1), "release-api (DEMO EXCEPTIONS: 1)")

    def test_the_sandbox_name_fits_openshells_limit(self):
        self.assertLessEqual(len(end_state.SANDBOX), 19)


if __name__ == "__main__":
    unittest.main()
