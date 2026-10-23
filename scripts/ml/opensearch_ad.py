#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Load the synthetic traces into the demo SIEM and run OpenSearch's own anomaly detection over them, one baseline per agent.

    python scripts/ml/opensearch_ad.py --data data/synthetic            # load, create the detector, run it over the whole period, score it
    python scripts/ml/opensearch_ad.py --data data/synthetic --cleanup  # remove the synthetic index and detector

Why: the SIEM's detectors need hours of history before they say anything, and the demo cluster has minutes. Synthetic history lets the same detector, with
the same settings, be trained and shown today. It goes into its own index (`ocsf-synthetic`, every document marked `unmapped.synthetic: true`), never the real
one. Talks to OpenSearch from inside the Dashboards pod, like scripts/siem/install_content.py.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "siem"))
import install_content as siem  # noqa: E402  (reuses its pod access helpers)

INDEX = "ocsf-synthetic"
DETECTOR = "synthetic-requests-per-minute-by-agent"
MINUTE = 60_000


def load_events(data_dir):
    with open(os.path.join(data_dir, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    with open(os.path.join(data_dir, "events.jsonl"), encoding="utf-8") as handle:
        return manifest, [json.loads(line) for line in handle]


def document(event):
    return {
        "time": event["ts"], "class_uid": 4002, "class_name": "HTTP Activity", "category_name": "Network Activity", "severity_id": 1,
        "actor": {"user": {"name": event["agent"]}},
        "http_request": {"http_method": event["method"], "url": {"path": event["path"]}},
        "unmapped": {"synthetic": True, "label": event["label"], "attack": event["attack"], "episode": event.get("episode", "")},
    }


def bulk(events):
    lines = []
    for event in events:
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(document(event)))
    body = ("\n".join(lines) + "\n").encode()
    command = ("curl -sk -X POST -u admin:$OPENSEARCH_PASSWORD -H 'Content-Type: application/x-ndjson' --data-binary @- "
               "'https://opensearch-cluster-master:9200/_bulk'")
    return json.loads(siem.exec_in_pod(command, body))


def cleanup():
    for detector in (siem.opensearch("POST", "/_plugins/_anomaly_detection/detectors/_search", {"query": {"term": {"name.keyword": DETECTOR}}}).get("hits", {}).get("hits", [])):
        siem.opensearch("POST", f"/_plugins/_anomaly_detection/detectors/{detector['_id']}/_stop")
        print("detector:", siem.opensearch("DELETE", f"/_plugins/_anomaly_detection/detectors/{detector['_id']}").get("_id", "not removed"))
    print("index:", siem.opensearch("DELETE", f"/{INDEX}").get("acknowledged", "not removed"))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", required=True)
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    if args.cleanup:
        cleanup()
        return
    manifest, events = load_events(args.data)
    cleanup()
    created = siem.opensearch("PUT", f"/{INDEX}", {
        "settings": {"number_of_replicas": 0},
        "mappings": {"properties": {"time": {"type": "date", "format": "epoch_millis"},
                                    "actor": {"properties": {"user": {"properties": {"name": {"type": "keyword"}}}}},
                                    "unmapped": {"properties": {"synthetic": {"type": "boolean"}, "label": {"type": "keyword"},
                                                                "attack": {"type": "keyword"}, "episode": {"type": "keyword"}}}}}})
    if not created.get("acknowledged"):
        raise SystemExit("could not create the index: " + json.dumps(created)[:300])
    for start in range(0, len(events), 2000):
        result = bulk(events[start:start + 2000])
        if result.get("errors"):
            raise SystemExit("bulk load had errors: " + json.dumps(result)[:300])
    siem.opensearch("POST", f"/{INDEX}/_refresh")
    print(f"loaded {len(events)} synthetic events into {INDEX}")

    detector = {
        "name": DETECTOR, "description": "Requests per minute, with a separate baseline for each agent (synthetic history).",
        "time_field": "time", "indices": [INDEX],
        "feature_attributes": [{"feature_name": "requests", "feature_enabled": True, "aggregation_query": {"requests": {"value_count": {"field": "time"}}}}],
        "filter_query": {"match_all": {}},
        "detection_interval": {"period": {"interval": 1, "unit": "Minutes"}},
        "window_delay": {"period": {"interval": 0, "unit": "Minutes"}}, "shingle_size": 4,
        "category_field": ["actor.user.name"]}
    made = siem.opensearch("POST", "/_plugins/_anomaly_detection/detectors", detector)
    detector_id = made.get("_id")
    if not detector_id:
        raise SystemExit("detector not created: " + json.dumps(made)[:400])
    start_ms, end_ms = manifest["start_ms"], manifest["start_ms"] + int(manifest["hours"] * 60 * MINUTE)
    started = siem.opensearch("POST", f"/_plugins/_anomaly_detection/detectors/{detector_id}/_start", {"start_time": start_ms, "end_time": end_ms})
    print("historical analysis:", json.dumps(started)[:200])
    for _ in range(120):
        time.sleep(5)
        profile = siem.opensearch("GET", f"/_plugins/_anomaly_detection/detectors/{detector_id}/_profile?_all=true")
        state = (profile.get("state") or "")
        task = (profile.get("ad_task") or {}).get("ad_task") or {}
        print("  state:", state, task.get("state", ""), task.get("task_progress", ""))
        if task.get("state") in ("FINISHED", "FAILED", "STOPPED") or state in ("INIT_FAILURE", "FAILED"):
            break
    report = score(detector_id, events, manifest)
    with open(os.path.join(args.data, "opensearch-ad-report.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))


def score(detector_id, events, manifest):
    """Which attack episodes did the detector flag (any anomaly grade above zero for that agent within the episode's span plus fifteen minutes)?"""
    query = {"size": 10000, "_source": ["entity", "data_end_time", "anomaly_grade", "anomaly_score"],
             "query": {"bool": {"filter": [{"term": {"detector_id": detector_id}}, {"range": {"anomaly_grade": {"gt": 0}}}]}}}
    hits = siem.opensearch("POST", "/_plugins/_anomaly_detection/detectors/results/_search", query).get("hits", {}).get("hits", [])
    flagged = []
    for hit in hits:
        source = hit["_source"]
        entity = (source.get("entity") or [{}])[0].get("value")
        flagged.append((entity, source["data_end_time"]))
    episodes = {}
    for event in events:
        if event["label"] == "attack":
            span = episodes.setdefault(event["episode"], {"agent": event["agent"], "kind": event["attack"], "from": event["ts"], "to": event["ts"]})
            span["from"], span["to"] = min(span["from"], event["ts"]), max(span["to"], event["ts"])
    by_kind = {}
    for span in episodes.values():
        caught = any(entity == span["agent"] and span["from"] <= end <= span["to"] + 15 * MINUTE for entity, end in flagged)
        counts = by_kind.setdefault(span["kind"], {"episodes": 0, "caught": 0})
        counts["episodes"] += 1
        counts["caught"] += int(caught)
    split_ms = manifest["split_ms"]
    attack_windows = [(s["agent"], s["from"], s["to"] + 15 * MINUTE) for s in episodes.values()]
    benign_flags = [1 for entity, end in flagged if end >= split_ms and not any(a == entity and lo <= end <= hi for a, lo, hi in attack_windows)]
    return {"synthetic": True, "detector": DETECTOR, "flagged_intervals": len(flagged), "flagged_benign_after_training": len(benign_flags), "attack_episodes": by_kind}


if __name__ == "__main__":
    main()
