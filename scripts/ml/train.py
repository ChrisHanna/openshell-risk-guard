#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Turn traces into per-minute windows, fit one anomaly model per agent on benign training time, and measure it on later benign time and the attacks.

    python scripts/ml/train.py --data data/synthetic --report data/synthetic/report.json

Also proposes baseline limits (request rate and distinct resources, 95th and 99th percentile) from the benign training windows, next to what the agent's
`baseline.json` says today. The proposal is advice for a person to review; nothing here changes a baseline.

The honest reading of the result: the attacks come from the same author as the generator, so recall on the obvious shapes is flattering, and the line to look at is the
subtle and slow ones, where a window-level model has little to see.
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest

MINUTE = 60_000
FEATURES = ["req_1m", "distinct_paths_15m", "distinct_templates_15m", "write_ratio_15m", "unseen_paths_15m", "mean_gap_s_1m"]
WRITE = {"POST", "PUT", "PATCH", "DELETE"}


def load(data_dir):
    with open(os.path.join(data_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    with open(os.path.join(data_dir, "events.jsonl"), encoding="utf-8") as handle:
        events = [json.loads(line) for line in handle]
    return manifest, events


WARM_UP_MINUTES = 6 * 60   # until an agent has been seen for hours, everything it does is "new"; the first hours do not train the model


def windows(events, agent):
    """One row per minute that had at least one call: the minute's rate and the previous fifteen minutes' variety.

    "Unseen" counts paths whose first appearance anywhere in the stream falls inside the window. It is computed the same way in training and test time, so a
    model never learns that "new" cannot happen."""
    mine = [e for e in events if e["agent"] == agent]
    first_seen = {}
    for e in mine:
        first_seen.setdefault(e["path"], e["ts"] // MINUTE)
    stamps = [e["ts"] for e in mine]
    minutes = sorted({e["ts"] // MINUTE for e in mine})
    rows = []
    for minute in minutes:
        lo = bisect.bisect_left(stamps, minute * MINUTE)
        hi = bisect.bisect_left(stamps, (minute + 1) * MINUTE)
        wide_lo = bisect.bisect_left(stamps, (minute - 14) * MINUTE)
        now, wide = mine[lo:hi], mine[wide_lo:hi]
        gaps = np.diff([e["ts"] for e in now]) / 1000 if len(now) > 1 else np.array([60.0])
        paths = {e["path"] for e in wide}
        rows.append({
            "minute": minute, "agent": agent,
            "features": [
                len(now), len(paths), len({e["template"] for e in wide}),
                sum(e["method"] in WRITE for e in wide) / len(wide),
                sum(first_seen[p] >= minute - 14 for p in paths), float(np.mean(gaps)),
            ],
            "attack": sorted({(e["attack"], e.get("episode", "")) for e in now if e["label"] == "attack"}),
            # An attack leaves its mark on the fifteen-minute features for the next quarter hour. Those minutes are not benign and not the attack either.
            "aftermath": any(e["label"] == "attack" for e in wide),
        })
    return rows


def transform(x):
    """Counts span orders of magnitude (a burst is 100 calls where a session is 10), so work in logs."""
    return np.log1p(np.asarray(x, dtype=float))


class Envelope:
    """How far the worst feature sits beyond what benign training time looked like, in units of the benign spread. The same idea as Risk Guard's own
    p95/p99 limits, learned per feature; no trees, nothing hidden, easy to explain."""

    def fit(self, x):
        z = transform(x)
        self.median = np.median(z, axis=0)
        self.spread = np.maximum(np.percentile(z, 99, axis=0) - self.median, 0.05)
        return self

    def score(self, x):
        return np.max((transform(x) - self.median) / self.spread, axis=1)


class Forest:
    def fit(self, x):
        self.model = IsolationForest(n_estimators=200, random_state=0, contamination="auto").fit(transform(x))
        return self

    def score(self, x):
        return -self.model.score_samples(transform(x))


MODELS = {"envelope": Envelope, "isolation_forest": Forest}


def evaluate(model_class, train, test, target_fpr):
    model = model_class().fit(np.array([r["features"] for r in train]))
    # The alert line is the score that only target_fpr of the benign training windows exceed.
    threshold = float(np.quantile(model.score(np.array([r["features"] for r in train])), 1 - target_fpr))
    flags = model.score(np.array([r["features"] for r in test])) > threshold
    benign = [flag for r, flag in zip(test, flags) if not r["attack"] and not r["aftermath"]]
    episodes = defaultdict(lambda: {"flagged": False, "kind": ""})
    for r, flag in zip(test, flags):
        for kind, episode in r["attack"]:
            episodes[episode]["kind"] = kind
            episodes[episode]["flagged"] |= bool(flag)
    by_kind = defaultdict(lambda: [0, 0])
    for episode in episodes.values():
        by_kind[episode["kind"]][0] += 1
        by_kind[episode["kind"]][1] += int(episode["flagged"])
    return {
        "benign_test_windows": len(benign),
        "false_positive_rate": (sum(benign) / len(benign)) if benign else None,
        "attack_episodes": {kind: {"episodes": total, "caught": caught} for kind, (total, caught) in sorted(by_kind.items())},
    }


def run(data_dir, target_fpr=0.005, baselines_dir=None):
    manifest, events = load(data_dir)
    split_minute = manifest["split_ms"] // MINUTE
    report = {"synthetic": manifest.get("synthetic", True), "seed": manifest["seed"], "target_false_positive_rate": target_fpr, "agents": {}}
    for agent in manifest["agents"]:
        rows = windows(events, agent)
        origin = min(r["minute"] for r in rows)
        train = [r for r in rows if origin + WARM_UP_MINUTES <= r["minute"] < split_minute]
        test = [r for r in rows if r["minute"] >= split_minute]
        req = np.array([r["features"][0] for r in train])
        distinct = np.array([r["features"][1] for r in train])
        proposal = {"max_req_1m_p95": float(np.percentile(req, 95)), "max_req_1m_p99": float(np.percentile(req, 99)),
                    "max_distinct_resources_15m_p95": float(np.percentile(distinct, 95)), "max_distinct_resources_15m_p99": float(np.percentile(distinct, 99))}
        current = None
        if baselines_dir:
            path = os.path.join(baselines_dir, agent, "baseline.json")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as handle:
                    baseline = json.load(handle)
                current = {key: baseline.get(key) for key in proposal}
        report["agents"][agent] = {
            "train_windows": len(train), "test_windows": len(test),
            "models": {name: evaluate(cls, train, test, target_fpr) for name, cls in MODELS.items()},
            "baseline_proposal": proposal, "baseline_current": current,
        }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", required=True)
    parser.add_argument("--report")
    parser.add_argument("--target-fpr", type=float, default=0.005)
    parser.add_argument("--baselines", default=os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "aks", "agents"))
    args = parser.parse_args()
    report = run(args.data, args.target_fpr, baselines_dir=args.baselines)
    text = json.dumps(report, indent=2)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(text)
    for name in MODELS:
        totals = defaultdict(lambda: [0, 0])
        false_positives = benign = 0
        for result in report["agents"].values():
            model = result["models"][name]
            false_positives += round((model["false_positive_rate"] or 0) * model["benign_test_windows"])
            benign += model["benign_test_windows"]
            for kind, counts in model["attack_episodes"].items():
                totals[kind][0] += counts["episodes"]
                totals[kind][1] += counts["caught"]
        print(f"{name}: {false_positives}/{benign} benign windows flagged ({false_positives / max(benign, 1):.2%})")
        for kind, (total, caught) in sorted(totals.items()):
            print(f"  {kind:14s} caught {caught}/{total}")


if __name__ == "__main__":
    main()
