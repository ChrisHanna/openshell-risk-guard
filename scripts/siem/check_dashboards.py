#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Run every visualization's query against OpenSearch and say which would draw nothing, or fail.

    python scripts/siem/check_dashboards.py

It cannot see how a chart renders, but a chart that asks for a field that is not there, a text field it cannot aggregate, or a query that matches nothing is found
here. For each visualization of each installed dashboard it rebuilds the search (the saved query and each aggregation) and prints the first buckets or the reason it is empty.
"""
import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
import install_content as siem  # noqa: E402

HOUR = 3_600_000


def saved_objects(kind):
    out = siem.exec_in_pod(f"curl -s -u admin:$OPENSEARCH_PASSWORD -H 'osd-xsrf: true' 'http://localhost:5601/api/saved_objects/_find?type={kind}&per_page=200'")
    return json.loads(out)["saved_objects"]


def pattern_title(obj, patterns):
    for ref in obj.get("references", []):
        if ref["type"] == "index-pattern":
            return patterns.get(ref["id"], ref["id"])
    return "ocsf-openshell"


def translate(aggs):
    """Dashboards aggregation list -> OpenSearch aggregations, nested in order (metrics at the leaf)."""
    buckets = [a for a in aggs if a["schema"] in ("segment", "group", "bucket")]
    metrics = [a for a in aggs if a["schema"] == "metric" and a["type"] != "count"]
    leaf = {f"m{a['id']}": {a["type"]: {"field": a["params"]["field"]}} for a in metrics}
    tree = leaf
    for agg in reversed(buckets):
        params = agg["params"]
        if agg["type"] == "terms":
            body = {"terms": {"field": params["field"], "size": params.get("size", 5)}}
        elif agg["type"] == "filters":
            body = {"filters": {"filters": {f["label"]: {"query_string": {"query": f["input"]["query"]}} for f in params["filters"]}}}
        elif agg["type"] == "date_histogram":
            body = {"date_histogram": {"field": params["field"], "fixed_interval": "1h", "min_doc_count": 1}}
        else:
            raise ValueError(agg["type"])
        node = {f"b{agg['id']}": dict(body, **({"aggs": tree} if tree else {}))}
        tree = node
    return tree


def walk(buckets_node, depth=0):
    """Summarise the first few buckets of the outermost aggregation."""
    for key, value in buckets_node.items():
        if isinstance(value, dict) and "buckets" in value:
            raw = value["buckets"]
            if isinstance(raw, dict):
                raw = [dict(v, key=k) for k, v in raw.items()]
            rows = raw[:4]
            return [str(b.get("key_as_string", b.get("key"))) + f"={b['doc_count']}" for b in rows], len(raw)
    return None, 0


def main():
    patterns = {o["id"]: o["attributes"]["title"] for o in saved_objects("index-pattern")}
    problems = 0
    for vis in saved_objects("visualization"):
        attrs = vis["attributes"]
        state = json.loads(attrs["visState"])
        query = json.loads(attrs["kibanaSavedObjectMeta"]["searchSourceJSON"]).get("query", {}).get("query", "")
        index = pattern_title(vis, patterns)
        # Dashboards' query language (KQL) uses lower-case and/or/not; the search it is sent to wants them upper case.
        query = re.sub(r"(?<= )not ", "NOT ", re.sub(r" or ", " OR ", re.sub(r" and ", " AND ", query)))
        body = {"size": 0, "track_total_hits": True, "query": {"query_string": {"query": query}} if query else {"match_all": {}}}
        try:
            aggs = translate(state["aggs"])
        except ValueError as error:
            print(f"?    {vis['id']:22s} unsupported aggregation {error}")
            continue
        if aggs:
            body["aggs"] = aggs
        result = siem.opensearch("POST", f"/{index}/_search", body)
        if "error" in result:
            problems += 1
            reason = result["error"].get("root_cause", [{}])[0].get("reason", "")[:110] if isinstance(result["error"], dict) else str(result["error"])[:110]
            print(f"FAIL {vis['id']:22s} {attrs['title'][:44]:44s} {reason}")
            continue
        total = result["hits"]["total"]["value"]
        summary, count = walk(result.get("aggregations", {}))
        # A single-number chart needs only hits; a bucketed chart needs buckets.
        wants_buckets = any(a["schema"] in ("segment", "group", "bucket") for a in state["aggs"])
        empty = total == 0 or (wants_buckets and not count)
        problems += int(empty)
        print(f"{'EMPTY' if empty else 'ok   '} {vis['id']:22s} {attrs['title'][:44]:44s} hits={total:<6} {summary if summary else ''}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
