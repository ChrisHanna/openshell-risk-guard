#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Install the starter content in the demo SIEM: a dashboard, saved searches, anomaly detectors and an alert. Safe to run again.

    scripts/siem/install_content.py

It talks to OpenSearch and Dashboards from inside the Dashboards pod (which already holds the admin password), so nothing is exposed and no password is handled
here. The objects it creates are described, in plain language, in docs/siem-guide.md.
"""
import json
import subprocess
import sys

NS = "siem"
POD = "deploy/dashboards-opensearch-dashboards"
INDEX = "ocsf-openshell"
PATTERN_ID = "ocsf-openshell"

# Queries in Dashboards' own search syntax (KQL). "Refusals" = a Denied decision by the risk-guard middleware.
REFUSALS = 'status_detail:middleware_denied*'
FAILURES = 'status_detail:middleware_failed*'
DECISIONS = 'message:"risk-guard"'


def exec_in_pod(command, body=None):
    result = subprocess.run(["kubectl", "exec", "-i", "-n", NS, POD, "--", "sh", "-c", command], input=body, capture_output=True)
    return result.stdout.decode("utf-8", "replace")


def opensearch(method, path, body=None):
    command = (f"curl -sk -X {method} -u admin:$OPENSEARCH_PASSWORD -H 'Content-Type: application/json' "
               f"--data-binary @- https://opensearch-cluster-master:9200{path}")
    out = exec_in_pod(command, json.dumps(body).encode() if body is not None else b"")
    try:
        return json.loads(out)
    except ValueError:
        return {"raw": out[:300]}


def dashboards_import(ndjson):
    command = ("curl -s -u admin:$OPENSEARCH_PASSWORD -H 'osd-xsrf: true' -F 'file=@-;filename=content.ndjson' "
               "'http://localhost:5601/api/saved_objects/_import?overwrite=true'")
    return json.loads(exec_in_pod(command, ndjson.encode()))


def search_source(query):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})


INDEX_REF = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": PATTERN_ID}]


def saved_search(oid, title, description, query):
    return {"id": oid, "type": "search", "migrationVersion": {"search": "7.9.3"}, "references": INDEX_REF,
            "attributes": {"title": title, "description": description, "hits": 0,
                           "columns": ["container.name", "http_request.http_method", "http_request.url.path", "status_detail", "severity"],
                           "sort": [["time", "desc"]], "version": 1,
                           "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)}}}


def visualization(oid, title, vis_type, aggs, params, query=""):
    state = {"title": title, "type": vis_type, "aggs": aggs, "params": params}
    return {"id": oid, "type": "visualization", "migrationVersion": {"visualization": "7.10.0"}, "references": INDEX_REF,
            "attributes": {"title": title, "visState": json.dumps(state), "uiStateJSON": "{}", "description": "", "version": 1,
                           "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)}}}


COUNT = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def terms(agg_id, field, schema, size=8):
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size, "otherBucket": False, "otherBucketLabel": "Other",
                       "missingBucket": False, "missingBucketLabel": "Missing"}}


TIME_BUCKET = {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
               "params": {"field": "time", "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False, "interval": "auto",
                          "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}

METRIC_PARAMS = {"addTooltip": True, "addLegend": False, "type": "metric",
                 "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red", "metricColorMode": "None",
                            "colorsRange": [{"from": 0, "to": 100000}], "labels": {"show": True}, "invertColors": False,
                            "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48}}}

BAR_PARAMS = {"type": "histogram", "grid": {"categoryLines": False},
              "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {},
                                "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
              "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "style": {},
                             "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                             "title": {"text": "Count"}}],
              "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Count", "id": "1"},
                                "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
              "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False,
              "labels": {"show": False}, "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}}

PIE_PARAMS = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True,
              "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}

TABLE_PARAMS = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "sort": {"columnIndex": None, "direction": None},
                "showTotal": False, "totalFunc": "sum"}


def build_objects():
    objects = [{
        "id": PATTERN_ID, "type": "index-pattern", "migrationVersion": {"index-pattern": "7.6.0"}, "references": [],
        "attributes": {"title": INDEX, "timeFieldName": "time"}}]
    objects += [
        saved_search("rg-search-refusals", "Risk Guard refusals", "Every request the risk-guard middleware refused.", REFUSALS),
        saved_search("rg-search-failures", "Middleware failures (failed closed)", "Times a required middleware could not answer, so the request was refused.", FAILURES),
        saved_search("rg-search-decisions", "All risk-guard decisions", "Every decision by the risk-guard middleware, allowed or refused.", DECISIONS),
    ]
    vis = [
        visualization("rg-vis-events", "Events", "metric", [COUNT], METRIC_PARAMS),
        visualization("rg-vis-refusals", "Risk Guard refusals", "metric", [COUNT], METRIC_PARAMS, REFUSALS),
        visualization("rg-vis-failures", "Middleware failures", "metric", [COUNT], METRIC_PARAMS, FAILURES),
        visualization("rg-vis-refusals-time", "Refusals over time, by reason", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", "status_detail.keyword", "group")], BAR_PARAMS, REFUSALS),
        visualization("rg-vis-failures-time", "Middleware failures over time", "histogram", [COUNT, TIME_BUCKET], BAR_PARAMS, FAILURES),
        visualization("rg-vis-classes", "Events by OCSF class", "pie", [COUNT, terms("2", "class_name.keyword", "segment")], PIE_PARAMS),
        visualization("rg-vis-sandboxes", "Sandboxes with the most refusals", "table", [COUNT, terms("2", "container.name.keyword", "bucket", 10)], TABLE_PARAMS, REFUSALS),
        visualization("rg-vis-routes", "Routes refused most", "table", [COUNT, terms("2", "http_request.url.path.keyword", "bucket", 10)], TABLE_PARAMS, REFUSALS),
    ]
    objects += vis
    grid = [("rg-vis-events", 0, 0, 12, 8), ("rg-vis-refusals", 12, 0, 12, 8), ("rg-vis-failures", 24, 0, 12, 8), ("rg-vis-classes", 36, 0, 12, 8),
            ("rg-vis-refusals-time", 0, 8, 28, 14), ("rg-vis-failures-time", 28, 8, 20, 14),
            ("rg-vis-sandboxes", 0, 22, 24, 14), ("rg-vis-routes", 24, 22, 24, 14)]
    panels, refs = [], []
    for i, (oid, x, y, w, h) in enumerate(grid):
        panels.append({"version": "3.9.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)}, "panelIndex": str(i),
                       "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "visualization", "id": oid})
    objects.append({
        "id": "rg-dashboard-overview", "type": "dashboard", "migrationVersion": {"dashboard": "7.9.3"}, "references": refs,
        "attributes": {"title": "Risk Guard and OpenShell: overview",
                       "description": "What the Risk Guard middleware decided in OpenShell sandboxes, and when it could not decide.",
                       "hits": 0, "panelsJSON": json.dumps(panels), "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
                       "version": 1, "timeRestore": True, "timeTo": "now", "timeFrom": "now-24h",
                       "refreshInterval": {"pause": False, "value": 30000},
                       "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}}})
    return objects


def feature(name, field="metadata.uid.keyword"):
    # Counts events per interval. (A detector feature must be a single metric; the filter lives on the detector itself.)
    return {"feature_name": name, "feature_enabled": True, "aggregation_query": {name: {"value_count": {"field": field}}}}


def detector(name, description, query_filter):
    return {"name": name, "description": description, "time_field": "time", "indices": [INDEX],
            "feature_attributes": [feature("events")],
            "filter_query": {"bool": {"filter": query_filter}} if query_filter else {"match_all": {}},
            "detection_interval": {"period": {"interval": 1, "unit": "Minutes"}},
            "window_delay": {"period": {"interval": 1, "unit": "Minutes"}}, "shingle_size": 8}


def install_detectors():
    wanted = [
        detector("risk-guard-refusals-per-minute", "Unusual number of Risk Guard refusals in a minute.",
                 [{"term": {"firewall_rule.type.keyword": "middleware"}}, {"term": {"action.keyword": "Denied"}}]),
        detector("middleware-failures-per-minute", "Unusual number of times the middleware could not answer (the request was refused).",
                 [{"term": {"finding_info.uid.keyword": "openshell.middleware.failure"}}]),
        detector("all-security-events-per-minute", "Unusual overall volume of OCSF security events.", []),
    ]
    results = []
    for body in wanted:
        found = opensearch("POST", "/_plugins/_anomaly_detection/detectors/_search", {"query": {"term": {"name.keyword": body["name"]}}})
        hits = (found.get("hits") or {}).get("hits") or []
        if hits:
            results.append((body["name"], "already exists", hits[0]["_id"]))
            continue
        created = opensearch("POST", "/_plugins/_anomaly_detection/detectors", body)
        det_id = created.get("_id")
        if not det_id:
            results.append((body["name"], "NOT created: " + json.dumps(created)[:200], None))
            continue
        started = opensearch("POST", f"/_plugins/_anomaly_detection/detectors/{det_id}/_start")
        results.append((body["name"], "created and started" if "_id" in started else "created, start failed: " + json.dumps(started)[:160], det_id))
    return results


def install_monitor():
    name = "Middleware failures: 3 or more in 5 minutes"
    found = opensearch("POST", "/_plugins/_alerting/monitors/_search", {"query": {"match_phrase": {"monitor.name": name}}})
    if ((found.get("hits") or {}).get("hits")):
        return name, "already exists"
    body = {"type": "monitor", "name": name, "monitor_type": "query_level_monitor", "enabled": True,
            "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
            "inputs": [{"search": {"indices": [INDEX], "query": {"size": 0, "query": {"bool": {"filter": [
                {"term": {"finding_info.uid.keyword": "openshell.middleware.failure"}},
                {"range": {"time": {"gte": "{{period_end}}||-5m", "lte": "{{period_end}}", "format": "epoch_millis"}}}]}}}}}],
            "triggers": [{"query_level_trigger": {"name": "Risk Guard could not decide, repeatedly", "severity": "2",
                          "condition": {"script": {"source": "ctx.results[0].hits.total.value >= 3", "lang": "painless"}}, "actions": []}}]}
    created = opensearch("POST", "/_plugins/_alerting/monitors", body)
    return name, "created" if "_id" in created else "NOT created: " + json.dumps(created)[:200]


def install_report():
    name = "Risk Guard daily overview"
    listing = exec_in_pod("curl -s -u admin:$OPENSEARCH_PASSWORD -H 'osd-xsrf: true' http://localhost:5601/api/reporting/reportDefinitions")
    if name in listing:
        return name, "already exists"
    body = {"report_params": {"report_name": name, "report_source": "Dashboard", "description": "Daily PDF of the overview dashboard.",
                              "core_params": {"base_url": "/app/dashboards#/view/rg-dashboard-overview", "report_format": "pdf", "time_duration": "PT24H",
                                              "header": "", "footer": "", "origin": "http://localhost:5601"}},
            "delivery": {"configIds": [], "title": "", "textDescription": "", "htmlDescription": ""},
            "trigger": {"trigger_type": "Schedule", "trigger_params": {"enabled_time": 1, "enabled": True, "schedule_type": "Recurring",
                                                                      "schedule": {"interval": {"period": 1, "unit": "DAYS", "start_time": 1}}}}}
    out = exec_in_pod("curl -s -u admin:$OPENSEARCH_PASSWORD -H 'osd-xsrf: true' -H 'Content-Type: application/json' --data-binary @- "
                      "http://localhost:5601/api/reporting/reportDefinition", json.dumps(body).encode())
    return name, "created" if "created" in out else "NOT created: " + out[:200]


def main():
    imported = dashboards_import("\n".join(json.dumps(o) for o in build_objects()) + "\n")
    errors = imported.get("errors") or []
    print(f"dashboard objects: {imported.get('successCount', 0)} imported, {len(errors)} errors")
    for error in errors[:5]:
        print("  error:", json.dumps(error)[:240])
    for name, status, _ in install_detectors():
        print(f"anomaly detector '{name}': {status}")
    print("alert monitor '%s': %s" % install_monitor())
    print("scheduled report '%s': %s" % install_report())
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
