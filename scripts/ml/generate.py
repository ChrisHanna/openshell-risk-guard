#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Generate labelled synthetic traces for the fleet's sample agents.

    python scripts/ml/generate.py --out data/synthetic --hours 72 --seed 7

Writes `events.jsonl` (one call per line, with a label and, for attacks, the kind) and `manifest.json` (what was generated, with the seed and the split). Nothing here
touches a cluster. The split is by *time*: the first 70 % of the hours train, the rest test, with attacks only in the test part, as in real use.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))
from agents import ATTACKS, FLEET, MINUTE, routine_events  # noqa: E402

START_MS = 1_800_000_000_000


def generate(hours: float, seed: int, attacks_per_agent: int = 12, agents=None):
    rng = random.Random(seed)
    events = []
    split_ms = START_MS + int(hours * 0.7 * 60 * MINUTE)
    end_ms = START_MS + int(hours * 60 * MINUTE)
    for name in agents or FLEET:
        model = FLEET[name]
        events += routine_events(model, rng, START_MS, hours)
        kinds = list(ATTACKS)
        for n in range(attacks_per_agent):
            kind = kinds[n % len(kinds)]
            # Attacks land in the test period only, away from its edges so a window is not cut by the end of the data.
            at = rng.randint(split_ms + 30 * MINUTE, end_ms - 3 * 60 * MINUTE)
            for event in ATTACKS[kind](model, rng, at):
                event["episode"] = f"{name}-{n}"
                events.append(event)
    events.sort(key=lambda e: (e["ts"], e["agent"]))
    return events, split_ms


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--hours", type=float, default=72)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--attacks-per-agent", type=int, default=12)
    args = parser.parse_args()
    events, split_ms = generate(args.hours, args.seed, args.attacks_per_agent)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "events.jsonl"), "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    manifest = {"synthetic": True, "seed": args.seed, "hours": args.hours, "split_ms": split_ms, "start_ms": START_MS, "events": len(events),
                "attack_events": sum(e["label"] == "attack" for e in events), "agents": list(FLEET), "attacks_per_agent": args.attacks_per_agent}
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
