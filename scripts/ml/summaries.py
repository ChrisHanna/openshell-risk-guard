#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Train on what the agents actually did: Risk Guard's once-a-minute activity summaries, read from the SIEM.

    python scripts/ml/summaries.py --export data/real            # pull the summaries out of OpenSearch
    python scripts/ml/summaries.py --train data/real             # one baseline per workload, report what it would have flagged

A summary is one row per active workload per minute: decisions, refused, share refused, highest score, distinct paths. The model is the same per-feature envelope as
`train.py` (how far the worst feature sits beyond the workload's own benign spread). It needs history: with fewer than MIN_ROWS minutes for a workload it says so
and learns nothing, instead of producing numbers that look like a result. Nothing here changes a baseline or a decision; the output is a report for a person.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from train import Envelope  # noqa: E402

MIN_ROWS = 120          # about two hours of activity per workload before a baseline means anything
FEATURES = ["total", "refused_calls", "refusal_ratio", "distinct_paths", "max_score"]


def export(out_dir):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "siem"))
    import install_content as siem
    rows, after = [], None
    while True:
        body = {"size": 5000, "sort": [{"time": "asc"}, {"metadata.uid.keyword": "asc"}],
                "query": {"query_string": {"query": "unmapped.risk_guard.gate:summary"}}}
        if after:
            body["search_after"] = after
        hits = siem.opensearch("POST", "/ocsf-openshell/_search", body).get("hits", {}).get("hits", [])
        if not hits:
            break
        for hit in hits:
            source = hit["_source"]
            summary = source["unmapped"]["risk_guard"]
            rows.append({"ts": source["time"], "workload": (source.get("actor") or {}).get("user", {}).get("name"),
                         **{name: summary.get(name, 0) for name in FEATURES}})
        after = hits[-1]["sort"]
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "summaries.jsonl"), "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    print(f"exported {len(rows)} summaries")
    return rows


def train(rows, train_share=0.7, target_fpr=0.01):
    report = {"synthetic": False, "workloads": {}}
    for workload in sorted({r["workload"] for r in rows if r["workload"]}):
        mine = sorted((r for r in rows if r["workload"] == workload), key=lambda r: r["ts"])
        if len(mine) < MIN_ROWS:
            report["workloads"][workload] = {"rows": len(mine), "status": f"not enough history yet (needs {MIN_ROWS} active minutes)"}
            continue
        cut = int(len(mine) * train_share)
        fit, test = mine[:cut], mine[cut:]
        matrix = lambda part: np.array([[r[f] for f in FEATURES] for r in part], dtype=float)  # noqa: E731
        model = Envelope().fit(matrix(fit))
        threshold = float(np.quantile(model.score(matrix(fit)), 1 - target_fpr))
        scores = model.score(matrix(test))
        flagged = [(r["ts"], round(float(s), 2), {f: r[f] for f in FEATURES}) for r, s in zip(test, scores) if s > threshold]
        report["workloads"][workload] = {"rows": len(mine), "trained_on": len(fit), "tested": len(test), "flagged": len(flagged),
                                         "flagged_share": len(flagged) / len(test), "examples": flagged[:5]}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--export")
    parser.add_argument("--train")
    args = parser.parse_args()
    if args.export:
        export(args.export)
    if args.train:
        with open(os.path.join(args.train, "summaries.jsonl"), encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle]
        print(json.dumps(train(rows), indent=2))


if __name__ == "__main__":
    main()
