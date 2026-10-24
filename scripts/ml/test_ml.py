# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Checks on the synthetic-data pipeline: it is reproducible, it labels what it injects, and the models behave on shapes where the answer is not in doubt.

    python -m unittest scripts/ml/test_ml.py

Skipped when scikit-learn is not installed (it is only needed for training, not for the rest of the repository).
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import generate  # noqa: E402
from agents import ATTACKS, FLEET  # noqa: E402

try:
    import train  # noqa: E402
    HAVE_SKLEARN = True
except ImportError:
    HAVE_SKLEARN = False


class Generation(unittest.TestCase):
    def test_the_same_seed_gives_the_same_traces(self):
        a, _ = generate.generate(24, 5)
        b, _ = generate.generate(24, 5)
        c, _ = generate.generate(24, 6)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_attacks_land_only_in_the_test_period_and_are_labelled_with_an_episode(self):
        events, split_ms = generate.generate(48, 3)
        attacks = [e for e in events if e["label"] == "attack"]
        self.assertTrue(attacks)
        self.assertTrue(all(e["ts"] >= split_ms for e in attacks), "no attack may leak into the training period")
        self.assertTrue(all(e["episode"] and e["attack"] in ATTACKS for e in attacks))
        self.assertEqual({e["attack"] for e in attacks}, set(ATTACKS), "every attack kind appears")

    def test_every_agent_stays_on_its_own_routes_when_benign(self):
        events, _ = generate.generate(24, 2)
        for name, model in FLEET.items():
            templates = {r.template for r in model.routes}
            benign = {e["template"] for e in events if e["agent"] == name and e["label"] == "benign"}
            self.assertTrue(benign and benign <= templates, name)

    def test_tempting_calls_are_not_among_the_routine_routes(self):
        for model in FLEET.values():
            self.assertFalse({(r.method, r.template) for r in model.tempting} & {(r.method, r.template) for r in model.routes}, model.name)


@unittest.skipUnless(HAVE_SKLEARN, "scikit-learn is not installed")
class Training(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        events, split_ms = generate.generate(72, 11)
        with open(os.path.join(cls.dir.name, "events.jsonl"), "w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")
        with open(os.path.join(cls.dir.name, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump({"synthetic": True, "seed": 11, "hours": 72, "split_ms": split_ms, "start_ms": generate.START_MS, "agents": list(FLEET)}, handle)
        cls.report = train.run(cls.dir.name, target_fpr=0.01)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_the_report_says_it_is_synthetic(self):
        self.assertTrue(self.report["synthetic"])

    def test_benign_false_positives_stay_near_the_target(self):
        # One agent has only a few dozen clean test minutes, so a single flag is several percent; judge the fleet as a whole.
        for model in ("envelope", "isolation_forest"):
            flagged = windows = 0
            for result in self.report["agents"].values():
                outcome = result["models"][model]
                flagged += round(outcome["false_positive_rate"] * outcome["benign_test_windows"])
                windows += outcome["benign_test_windows"]
            self.assertLess(flagged / windows, 0.05, model)

    def test_the_envelope_catches_a_burst_and_an_enumeration_every_time(self):
        for agent, result in self.report["agents"].items():
            kinds = result["models"]["envelope"]["attack_episodes"]
            for kind in ("burst", "enumeration"):
                if kind in kinds:
                    self.assertEqual(kinds[kind]["caught"], kinds[kind]["episodes"], f"{agent}/{kind}")

    def test_baseline_proposals_are_ordered_and_positive(self):
        for result in self.report["agents"].values():
            p = result["baseline_proposal"]
            self.assertGreater(p["max_req_1m_p95"], 0)
            self.assertGreaterEqual(p["max_req_1m_p99"], p["max_req_1m_p95"])
            self.assertGreaterEqual(p["max_distinct_resources_15m_p99"], p["max_distinct_resources_15m_p95"])


@unittest.skipUnless(HAVE_SKLEARN, "numpy is not installed")
class RealSummaries(unittest.TestCase):
    def rows(self, count, spike_at=None):
        out = []
        for n in range(count):
            total = 8 + (n % 5)
            row = {"ts": n * 60_000, "workload": "agent-a", "total": total, "refused_calls": 0, "refusal_ratio": 0.0, "distinct_routes": 4, "max_score": 10}
            if n == spike_at:
                row.update(total=90, refused_calls=30, refusal_ratio=0.33, distinct_routes=40, max_score=100)
            out.append(row)
        return out

    def test_too_little_history_learns_nothing_and_says_so(self):
        import summaries
        report = summaries.train(self.rows(summaries.MIN_ROWS - 1))
        self.assertIn("not enough history", report["workloads"]["agent-a"]["status"])
        self.assertNotIn("flagged", report["workloads"]["agent-a"])

    def test_enough_history_flags_a_burst_and_little_else(self):
        import summaries
        count = summaries.MIN_ROWS * 2
        report = summaries.train(self.rows(count, spike_at=count - 5))["workloads"]["agent-a"]
        self.assertGreaterEqual(report["flagged"], 1)
        self.assertLessEqual(report["flagged"], 3)


class RustHarnessFleet(unittest.TestCase):
    def test_the_fleet_the_rust_evaluation_reads_is_the_fleet_defined_here(self):
        import agents
        path = os.path.join(os.path.dirname(__file__), "..", "..", "testdata", "adaptive-eval", "fleet.json")
        with open(path, encoding="utf-8") as handle:
            committed = json.load(handle)
        self.assertEqual(committed, json.loads(json.dumps(agents.fleet_json())),
                         "testdata/adaptive-eval/fleet.json is stale; run: python scripts/ml/agents.py --dump > testdata/adaptive-eval/fleet.json")


if __name__ == "__main__":
    unittest.main()
