#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""How long does OpenSearch take to know about a call, and to tell Risk Guard? Measured on the live system, nothing simulated.

    python scripts/siem/latency_probe.py              # needs the demo sandbox: scripts/demo/end_state.py --prepare

It reports three things:
  1. the anomaly detectors: how often they run, the delay they build in, and how far behind real time their newest result is
  2. OpenSearch's own time to answer the kind of search the feature publisher runs (the `took` it reports, many repeats)
  3. end to end: three calls OpenShell denies are sent, then it times (a) when the first one is searchable in OpenSearch and (b) when Risk Guard
     scores a routine call with the resulting feature (the siem_context signal). (b) is the real answer to "how long until OpenSearch changes a score".

It sends three denied calls from the standing demo sandbox, which adds three denials to that sandbox's features for ten minutes.
"""
import argparse
import json
import os
import statistics
import sys
import time

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts", "demo"))
import install_content as siem  # noqa: E402
import end_state as es  # noqa: E402


def detectors():
    found = siem.opensearch("POST", "/_plugins/_anomaly_detection/detectors/_search", {"size": 20, "query": {"match_all": {}}}).get("hits", {}).get("hits", [])
    print("1. Anomaly detectors (they score windows of data, not single requests)")
    if not found:
        print("   none installed")
    for hit in found:
        d = hit["_source"]
        interval = (d.get("detection_interval") or {}).get("period") or {}
        delay = (d.get("window_delay") or {}).get("period") or {}
        latest = siem.opensearch("POST", "/_plugins/_anomaly_detection/detectors/results/_search", {
            "size": 1, "sort": [{"execution_end_time": "desc"}],
            "query": {"term": {"detector_id": hit["_id"]}}, "_source": ["data_end_time", "execution_end_time", "anomaly_grade"]}).get("hits", {}).get("hits", [])
        line = f"   {d.get('name')}: runs every {interval.get('interval')} {str(interval.get('unit')).lower()}, waits {delay.get('interval')} {str(delay.get('unit')).lower()} for data"
        if latest:
            r = latest[0]["_source"]
            behind = (time.time() * 1000 - r["data_end_time"]) / 1000
            line += f"; newest result covers data up to {behind:.0f} s ago"
        print(line)


def search_latency(repeats):
    query = {"size": 0, "query": {"bool": {"filter": [{"range": {"time": {"gte": "now-15m"}}}, {"term": {"action.keyword": "Denied"}}]}},
             "aggs": {"by_sandbox": {"terms": {"field": "container.name.keyword", "size": 200}}}}
    took, wall = [], []
    for _ in range(repeats):
        t = time.time()
        result = siem.opensearch("POST", "/ocsf-openshell*/_search", query)
        wall.append((time.time() - t) * 1000)
        if "took" in result:
            took.append(result["took"])
    print("\n2. The search the feature publisher runs (denials per sandbox, last 15 minutes)")
    if not took:
        print("   no answers")
        return
    p = lambda xs, q: sorted(xs)[min(len(xs) - 1, int(len(xs) * q))]  # noqa: E731
    print(f"   OpenSearch's own time: median {statistics.median(took):.0f} ms, p95 {p(took, .95)} ms, slowest {max(took)} ms ({len(took)} runs)")
    print(f"   including kubectl exec overhead from here: median {statistics.median(wall):.0f} ms (not a measure of OpenSearch)")


def end_to_end(timeout):
    print("\n3. End to end: from an OpenShell denial to a changed score in Risk Guard")
    sandbox = es.sandbox_json()
    if not sandbox:
        print("   no demo sandbox: run scripts/demo/end_state.py --prepare")
        return
    sid = es.PROFILES["demo-end-state"]
    es.clear_restrictions(sid["workload"], "latency probe")
    es.call(*es.ACT_FOLLOWUP)  # a fresh decision: the sandbox's last recorded one may be hours old
    baseline = (es.decisions(sandbox["id"]) or [None])[-1]
    if es.siem_signal(baseline):
        print("   features from a run in the last ten minutes are still in force; wait and run again for a clean measurement")
        return
    t0 = time.time()
    t0_ms = int(t0 * 1000)
    for _ in range(3):
        es.call(*es.ACT_B)
    print(f"   sent 3 denied calls (they took {time.time() - t0:.1f} s to send)")
    seen = scored = None
    deadline = t0 + timeout
    while time.time() < deadline and not (seen and scored):
        if not seen:
            result = siem.opensearch("POST", "/ocsf-openshell*/_search", {"size": 1, "query": {"bool": {"filter": [
                {"term": {"container.name.keyword": es.SANDBOX}}, {"term": {"action.keyword": "Denied"}},
                {"range": {"time": {"gte": t0_ms - 2000}}}, {"exists": {"field": "http_request.url.path"}}]}}})
            if result.get("hits", {}).get("hits"):
                seen = time.time() - t0
                print(f"   (a) the first denial was searchable in OpenSearch after {seen:.0f} s")
        if not scored:
            es.call(*es.ACT_FOLLOWUP)
            last = (es.decisions(sandbox["id"]) or [None])[-1]
            if es.siem_signal(last):
                scored = time.time() - t0
                print(f"   (b) Risk Guard scored a routine call with the OpenSearch feature after {scored:.0f} s")
        time.sleep(4)
    if not scored:
        print(f"   (b) not scored within {timeout} s: the features had not arrived")
    es.clear_restrictions(sid["workload"], "latency probe done")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=420)
    args = parser.parse_args()
    detectors()
    search_latency(args.repeats)
    end_to_end(args.timeout)


if __name__ == "__main__":
    main()
