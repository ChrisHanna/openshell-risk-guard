# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""The promotion gate decides from evidence, and each way of being not ready must hold it.   python -m unittest scripts/test_promotion_gate.py"""
import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import promotion_gate as gate  # noqa: E402

HOUR = gate.HOUR
NOW = 1_800_000_000_000
POLICY = {"candidate": "x", "window_hours": 24, "min_span_hours": 24, "min_tunnels_per_agent": 20, "max_silence_minutes": 180, "max_middleware_failures": 3,
          "require_backup_within_hours": 24, "require_red_team_pass": True, "red_team_max_age_hours": 168, "revert_command": "revert", "reviewed": []}


def good():
    return {"agents": [{"agent": "a", "tunnels": 100, "first_ms": NOW - 25 * HOUR, "last_ms": NOW - 60_000}],
            "first_ms": NOW - 25 * HOUR, "last_ms": NOW - 60_000, "would_refuse": [], "middleware_failures": 0,
            "last_risk_guard_event_ms": NOW - 60_000, "last_backup_ms": NOW - 2 * HOUR, "red_team": {"gate": "pass", "age_hours": 3}}


def decide(evidence=None, **policy):
    return gate.evaluate(evidence or good(), dict(POLICY, **policy), NOW)


def failing(report):
    return {c["check"] for c in report["checks"] if not c["ok"]}


class Gate(unittest.TestCase):
    def test_clean_evidence_promotes(self):
        report = decide()
        self.assertEqual(report["decision"], "promote")
        self.assertEqual(failing(report), set())
        self.assertEqual(report["to_revert"], "revert")

    def test_too_little_observed_holds(self):
        thin = good()
        thin["agents"][0]["tunnels"] = 5
        self.assertEqual(failing(decide(thin)), {"enough_observed"})
        short = good()
        short["first_ms"] = NOW - 3 * HOUR
        self.assertEqual(failing(decide(short)), {"enough_observed"})
        self.assertEqual(failing(decide({**good(), "agents": []})), {"enough_observed"})

    def test_an_unreviewed_would_refuse_holds_and_is_named(self):
        e = good()
        e["would_refuse"] = [{"agent": "a", "destination": "events.telemetry.example:443", "reason": "shadow: the destination is not approved", "count": 12}]
        report = decide(e)
        self.assertEqual(report["decision"], "hold")
        blockers = [c for c in report["checks"] if c["check"] == "no_unreviewed_would_refuse"][0]["blockers"]
        self.assertIn("events.telemetry.example:443", blockers[0])
        self.assertIn("12 times", blockers[0])

    def test_a_review_with_a_named_reviewer_covers_it_and_one_without_does_not(self):
        e = good()
        e["would_refuse"] = [{"agent": "a", "destination": "events.telemetry.example:443", "reason": "shadow: the destination is not approved", "count": 12}]
        entry = {"agent": "*", "destination": "events.telemetry.example:443", "reason_contains": "not approved", "reviewer": "pat", "date": "2026-10-23", "note": "telemetry should be blocked"}
        self.assertEqual(decide(e, reviewed=[entry])["decision"], "promote")
        anonymous = dict(entry, reviewer="")
        self.assertEqual(failing(decide(e, reviewed=[anonymous])), {"no_unreviewed_would_refuse"})
        other_destination = dict(entry, destination="somewhere.else:443")
        self.assertEqual(failing(decide(e, reviewed=[other_destination])), {"no_unreviewed_would_refuse"})
        other_reason = dict(entry, reason_contains="quarantined")
        self.assertEqual(failing(decide(e, reviewed=[other_reason])), {"no_unreviewed_would_refuse"})

    def test_an_unhealthy_control_holds(self):
        e = good()
        e["middleware_failures"] = 9
        self.assertEqual(failing(decide(e)), {"control_healthy"})
        quiet = good()
        quiet["last_risk_guard_event_ms"] = NOW - 10 * HOUR
        self.assertEqual(failing(decide(quiet)), {"control_healthy"})
        never = good()
        never["last_risk_guard_event_ms"] = 0
        self.assertEqual(failing(decide(never)), {"control_healthy"})

    def test_no_recent_backup_or_failing_attack_catalog_holds(self):
        e = good()
        e["last_backup_ms"] = NOW - 40 * HOUR
        self.assertEqual(failing(decide(e)), {"can_be_undone"})
        del e["last_backup_ms"]
        self.assertEqual(failing(decide(e)), {"can_be_undone"})
        r = good()
        r["red_team"] = {"gate": "FAIL", "age_hours": 1}
        self.assertEqual(failing(decide(r)), {"attack_catalog_passes"})
        old = good()
        old["red_team"] = {"gate": "pass", "age_hours": 400}
        self.assertEqual(failing(decide(old)), {"attack_catalog_passes"})
        self.assertEqual(decide(e, require_backup_within_hours=0)["decision"], "promote")

    def test_the_shipped_policy_is_valid_and_starts_with_nothing_reviewed(self):
        with open(gate.DEFAULT_POLICY, encoding="utf-8") as handle:
            policy = json.load(handle)
        for key in POLICY:
            self.assertIn(key, policy)
        self.assertEqual(policy["reviewed"], [], "reviews are made by people; none are pre-filled")
        self.assertEqual(gate.evaluate(copy.deepcopy(good()), policy, NOW)["decision"], "promote")


if __name__ == "__main__":
    unittest.main()
