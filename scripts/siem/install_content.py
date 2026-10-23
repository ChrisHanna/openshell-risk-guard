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
               f"--data-binary @- 'https://opensearch-cluster-master:9200{path}'")
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


def index_ref(pattern_id):
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": pattern_id}]


def saved_search(oid, title, description, query, pattern_id=PATTERN_ID,
                 columns=("container.name", "http_request.http_method", "http_request.url.path", "status_detail", "severity")):
    return {"id": oid, "type": "search", "migrationVersion": {"search": "7.9.3"}, "references": index_ref(pattern_id),
            "attributes": {"title": title, "description": description, "hits": 0,
                           "columns": list(columns),
                           "sort": [["time", "desc"]], "version": 1,
                           "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)}}}


def visualization(oid, title, vis_type, aggs, params, query="", pattern_id=PATTERN_ID):
    state = {"title": title, "type": vis_type, "aggs": aggs, "params": params}
    return {"id": oid, "type": "visualization", "migrationVersion": {"visualization": "7.10.0"}, "references": index_ref(pattern_id),
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


def pattern_fields():
    # Dashboards expects the field list stored with the index pattern; without it, charts say "Could not locate that index-pattern-field".
    meta = "&".join(f"meta_fields={m}" for m in ("_source", "_id", "_type", "_index", "_score"))
    out = exec_in_pod(f"curl -s -u admin:$OPENSEARCH_PASSWORD 'http://localhost:5601/api/index_patterns/_fields_for_wildcard?pattern={INDEX}&{meta}'")
    fields = json.loads(out).get("fields", [])
    if not fields:
        raise SystemExit("No fields found for the index; has any event arrived yet?")
    return fields


def metric_agg(agg_id, kind, field, schema="metric"):
    return {"id": agg_id, "enabled": True, "type": kind, "schema": schema, "params": {"field": field}}


LINE_PARAMS = dict(BAR_PARAMS, type="line", seriesParams=[
    {"show": True, "type": "line", "mode": "normal", "data": {"label": "Average risk score", "id": "1"}, "valueAxis": "ValueAxis-1",
     "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True},
    {"show": True, "type": "line", "mode": "normal", "data": {"label": "Highest risk score", "id": "3"}, "valueAxis": "ValueAxis-1",
     "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}])

# Risk Guard's own events (src/ocsf.rs). Every one has unmapped.risk_guard.gate: middleware, tunnel or signal.
RG_ALL = "unmapped.risk_guard.gate:*"
RG_MIDDLEWARE = 'unmapped.risk_guard.gate:"middleware"'
RG_TUNNEL = 'unmapped.risk_guard.gate:"tunnel"'
RG_SIGNAL = 'unmapped.risk_guard.gate:"signal"'
RG_FIELD = "unmapped.risk_guard."


def dashboard(oid, title, description, grid, time_from="now-24h"):
    """grid: (object id, type, x, y, w, h) per panel."""
    panels, refs = [], []
    for i, (target, kind, x, y, w, h) in enumerate(grid):
        panels.append({"version": "3.9.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)}, "panelIndex": str(i),
                       "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": kind, "id": target})
    return {"id": oid, "type": "dashboard", "migrationVersion": {"dashboard": "7.9.3"}, "references": refs,
            "attributes": {"title": title, "description": description, "hits": 0, "panelsJSON": json.dumps(panels),
                           "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}), "version": 1, "timeRestore": True,
                           "timeTo": "now", "timeFrom": time_from, "refreshInterval": {"pause": False, "value": 30000},
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}}}


def build_risk_guard_objects():
    cols = ("actor.user.name", "unmapped.risk_guard.gate", "status_detail", "risk_score", "message")
    objects = [
        saved_search("rg2-search-all", "Risk Guard's own events", "Everything Risk Guard sent: refusals, tunnel refusals and signals, with the workload and score.", RG_ALL, columns=cols),
        saved_search("rg2-search-signals", "Signals received from the SIEM", "Each signal and what became of it.", RG_SIGNAL, columns=cols),
        saved_search("rg2-search-tunnel", "Tunnel refusals and silent supervisors", "Sandboxes the network path refused, or would refuse in enforce mode.", RG_TUNNEL, columns=cols),
    ]
    workload = terms("2", "actor.user.name.keyword", "bucket", 10)
    objects += [
        visualization("rg2-total", "Risk Guard events", "metric", [COUNT], METRIC_PARAMS, RG_ALL),
        visualization("rg2-middleware", "Refused at the middleware", "metric", [COUNT], METRIC_PARAMS, RG_MIDDLEWARE),
        visualization("rg2-tunnel", "Tunnel events", "metric", [COUNT], METRIC_PARAMS, RG_TUNNEL),
        visualization("rg2-signals", "Signals received", "metric", [COUNT], METRIC_PARAMS, RG_SIGNAL),
        visualization("rg2-workloads", "Workloads seen", "metric", [metric_agg("1", "cardinality", "actor.user.name.keyword")], METRIC_PARAMS, RG_ALL),
        visualization("rg2-reasons-time", "Middleware refusals over time, by reason", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", RG_FIELD + "reason_code.keyword", "group")], BAR_PARAMS, RG_MIDDLEWARE),
        visualization("rg2-score-time", "Risk score of refused requests", "line",
                      [metric_agg("1", "avg", "risk_score"), TIME_BUCKET, metric_agg("3", "max", "risk_score")], LINE_PARAMS, RG_MIDDLEWARE),
        visualization("rg2-by-workload", "Workloads: events and highest score", "table",
                      [COUNT, workload, metric_agg("3", "max", "risk_score")], TABLE_PARAMS, RG_ALL),
        visualization("rg2-by-task", "Events by task profile", "pie", [COUNT, terms("2", RG_FIELD + "task_profile.keyword", "segment")], PIE_PARAMS, RG_ALL),
        visualization("rg2-gates", "Where Risk Guard acted", "pie", [COUNT, terms("2", RG_FIELD + "gate.keyword", "segment")], PIE_PARAMS, RG_ALL),
        visualization("rg2-features", "Signals behind refusals", "table", [COUNT, terms("2", RG_FIELD + "signals.feature.keyword", "bucket", 10)], TABLE_PARAMS, RG_MIDDLEWARE),
        visualization("rg2-tunnel-kinds", "Tunnel events over time, by kind", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", RG_FIELD + "kind.keyword", "group")], BAR_PARAMS, RG_TUNNEL),
        visualization("rg2-signal-outcomes", "Signals over time, by outcome", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", RG_FIELD + "outcome.keyword", "group")], BAR_PARAMS, RG_SIGNAL),
        visualization("rg2-signal-sources", "Who sent signals, and which workloads they named", "table",
                      [COUNT, terms("2", RG_FIELD + "source.keyword", "bucket", 5), terms("3", RG_FIELD + "target_agent_id.keyword", "bucket", 10)], TABLE_PARAMS, RG_SIGNAL),
    ]
    decisions = dashboard("rg2-dashboard-decisions", "Risk Guard: decisions and workloads",
                          "What Risk Guard refused, for which workload, at what score and why. Uses Risk Guard's own events (workload, SPIFFE ID, task profile, score, reason).", [
        ("rg2-total", "visualization", 0, 0, 10, 7), ("rg2-middleware", "visualization", 10, 0, 10, 7), ("rg2-tunnel", "visualization", 20, 0, 10, 7),
        ("rg2-signals", "visualization", 30, 0, 9, 7), ("rg2-workloads", "visualization", 39, 0, 9, 7),
        ("rg2-reasons-time", "visualization", 0, 7, 24, 14), ("rg2-score-time", "visualization", 24, 7, 24, 14),
        ("rg2-by-workload", "visualization", 0, 21, 24, 14), ("rg2-features", "visualization", 24, 21, 24, 14),
        ("rg2-by-task", "visualization", 0, 35, 16, 13), ("rg2-gates", "visualization", 16, 35, 16, 13),
        ("rg2-search-all", "search", 0, 48, 48, 14)])
    signals = dashboard("rg2-dashboard-signals", "Risk Guard: quarantine and signals",
                        "Tunnels refused, supervisors that went quiet, and the signals the SIEM sent (applied, dry run, limited or unknown).", [
        ("rg2-tunnel", "visualization", 0, 0, 16, 7), ("rg2-signals", "visualization", 16, 0, 16, 7), ("rg2-workloads", "visualization", 32, 0, 16, 7),
        ("rg2-tunnel-kinds", "visualization", 0, 7, 24, 14), ("rg2-signal-outcomes", "visualization", 24, 7, 24, 14),
        ("rg2-signal-sources", "visualization", 0, 21, 48, 12),
        ("rg2-search-signals", "search", 0, 33, 48, 13), ("rg2-search-tunnel", "search", 0, 46, 48, 13)], time_from="now-7d")
    return objects + [decisions, signals]


SYNTHETIC = "ocsf-synthetic"


def synthetic_pattern():
    """An index pattern for the synthetic traces (scripts/ml/opensearch_ad.py), only when that index exists."""
    meta = "&".join(f"meta_fields={m}" for m in ("_source", "_id", "_type", "_index", "_score"))
    out = exec_in_pod(f"curl -s -u admin:$OPENSEARCH_PASSWORD 'http://localhost:5601/api/index_patterns/_fields_for_wildcard?pattern={SYNTHETIC}&{meta}'")
    try:
        fields = json.loads(out).get("fields", [])
    except ValueError:
        fields = []
    if not fields:
        return []
    return [{"id": SYNTHETIC, "type": "index-pattern", "migrationVersion": {"index-pattern": "7.6.0"}, "references": [],
             "attributes": {"title": SYNTHETIC, "timeFieldName": "time", "fields": json.dumps(fields)}}]


def build_synthetic_objects():
    pattern = synthetic_pattern()
    if not pattern:
        return []
    def vis(oid, title, kind, aggs, params, query=""):
        return visualization(oid, title, kind, aggs, params, query, pattern_id=SYNTHETIC)
    attack = "unmapped.label:attack"
    objects = pattern + [
        vis("ml-events", "Synthetic events", "metric", [COUNT], METRIC_PARAMS),
        vis("ml-attacks", "Of which attacks", "metric", [COUNT], METRIC_PARAMS, attack),
        vis("ml-by-agent", "Calls over time, by agent", "histogram", [COUNT, TIME_BUCKET, terms("3", "actor.user.name", "group")], BAR_PARAMS),
        vis("ml-attacks-time", "Injected attacks over time, by kind", "histogram", [COUNT, TIME_BUCKET, terms("3", "unmapped.attack", "group")], BAR_PARAMS, attack),
        vis("ml-attack-table", "Attack episodes by kind and agent", "table",
            [metric_agg("1", "cardinality", "unmapped.episode"), terms("2", "unmapped.attack", "bucket", 6), terms("3", "actor.user.name", "bucket", 4)], TABLE_PARAMS, attack),
    ]
    board = dashboard("ml-dashboard-synthetic", "Model training: the synthetic data",
                      "SYNTHETIC. Generated traffic for the four sample agents with injected attacks (scripts/ml). Open Anomaly Detection to see the detector trained on it. "
                      "Set the time range to January 2027, where the data sits.", [
        ("ml-events", "visualization", 0, 0, 24, 7), ("ml-attacks", "visualization", 24, 0, 24, 7),
        ("ml-by-agent", "visualization", 0, 7, 48, 14), ("ml-attacks-time", "visualization", 0, 21, 48, 14),
        ("ml-attack-table", "visualization", 0, 35, 48, 12)], time_from="2027-01-14T00:00:00.000Z")
    board["attributes"]["timeTo"] = "2027-01-18T00:00:00.000Z"
    return objects + [board]


def build_objects():
    objects = [{
        "id": PATTERN_ID, "type": "index-pattern", "migrationVersion": {"index-pattern": "7.6.0"}, "references": [],
        "attributes": {"title": INDEX, "timeFieldName": "time", "fields": json.dumps(pattern_fields())}}]
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
    return objects + build_risk_guard_objects() + build_synthetic_objects()


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


RETENTION_DAYS = 14
POLICY = "ocsf-retention"
FIRST_INDEX = INDEX + "-000001"

TEMPLATE = {
    "index_patterns": ["ocsf-*"], "priority": 100,
    "template": {
        "settings": {"number_of_replicas": 0, "index.plugins.index_state_management.rollover_alias": INDEX},
        "mappings": {"properties": {"time": {"type": "date", "format": "epoch_millis"}, "class_uid": {"type": "integer"},
                                    "severity_id": {"type": "integer"}, "activity_id": {"type": "integer"}}}}}


def install_retention():
    """Keep the events for RETENTION_DAYS and no longer: the index rolls over daily (or at 5 GB) and an index older than the limit is deleted.
    The name the collector writes to (`ocsf-openshell`) becomes an alias for the newest index, so nothing else changes. The first run moves the existing
    events into the first index (a few seconds of events written during the swap can be lost; run it when the demo is quiet)."""
    policy = {"policy": {
        "description": f"OCSF events: roll over daily or at 5 GB, delete after {RETENTION_DAYS} days",
        "default_state": "hot",
        "states": [
            {"name": "hot", "actions": [{"rollover": {"min_index_age": "1d", "min_primary_shard_size": "5gb"}}],
             "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{RETENTION_DAYS}d"}}]},
            {"name": "delete", "actions": [{"delete": {}}], "transitions": []}],
        "ism_template": [{"index_patterns": [INDEX + "-*"], "priority": 100}]}}
    existing = opensearch("GET", f"/_plugins/_ism/policies/{POLICY}")
    if "_seq_no" in existing:
        result = opensearch("PUT", f"/_plugins/_ism/policies/{POLICY}?if_seq_no={existing['_seq_no']}&if_primary_term={existing['_primary_term']}", policy)
    else:
        result = opensearch("PUT", f"/_plugins/_ism/policies/{POLICY}", policy)
    print("retention policy:", "ok" if "_id" in result else "NOT set: " + json.dumps(result)[:200])
    print("index template:", "ok" if opensearch("PUT", "/_index_template/ocsf", TEMPLATE).get("acknowledged") else "NOT set")

    alias = opensearch("GET", f"/_alias/{INDEX}")
    already = isinstance(alias, dict) and any(isinstance(v, dict) and "aliases" in v for v in alias.values()) and "error" not in alias
    if already:
        print(f"rollover: '{INDEX}' is already an alias")
        return
    before = opensearch("GET", f"/{INDEX}/_count").get("count")
    if before is None:
        # Nothing has been written yet: start the first index with the alias.
        made = opensearch("PUT", f"/{FIRST_INDEX}", {"aliases": {INDEX: {"is_write_index": True}}})
        print("rollover: first index created" if made.get("acknowledged") else "rollover NOT set up: " + json.dumps(made)[:200])
        return
    print(f"rollover: moving {before} existing events into {FIRST_INDEX}")
    made = opensearch("PUT", f"/{FIRST_INDEX}", {})
    if not made.get("acknowledged"):
        raise SystemExit("could not create the first index: " + json.dumps(made)[:200])
    moved = opensearch("POST", "/_reindex?wait_for_completion=true&refresh=true", {"source": {"index": INDEX}, "dest": {"index": FIRST_INDEX}})
    # An error answer has neither number; treating "None equals None" as success once lost every event, so insist on real numbers.
    if "error" in moved or moved.get("failures") or moved.get("total") is None or moved.get("total") != moved.get("created"):
        raise SystemExit("reindex incomplete; the original index was not touched: " + json.dumps(moved)[:300])
    swapped = opensearch("POST", "/_aliases", {"actions": [
        {"remove_index": {"index": INDEX}},
        {"add": {"index": FIRST_INDEX, "alias": INDEX, "is_write_index": True}}]})
    print("rollover: swapped" if swapped.get("acknowledged") else "swap FAILED: " + json.dumps(swapped)[:200])
    after = opensearch("GET", f"/{INDEX}/_count").get("count")
    print(f"events before {before}, after {after}")


SIGNALS_URL = "http://risk-guard.openshell.svc.cluster.local:50063/v1/signals"
CHANNEL = "risk-guard-signals"
SIGNAL_MONITOR = "Repeated refusals: 3 or more in 5 minutes, per sandbox (asks Risk Guard to quarantine)"


def signals_token():
    out = subprocess.run(["kubectl", "get", "secret", "siem-signals-token", "-n", "openshell", "-o", "jsonpath={.data.token}"],
                         capture_output=True)
    import base64
    token = base64.b64decode(out.stdout).decode().strip()
    if len(token) != 64:
        raise SystemExit("Secret siem-signals-token not found; run scripts/aks/25-enable-signals.ps1 first.")
    return token


def install_signals():
    """The webhook channel that carries a signal to Risk Guard, and the alert that sends one. The token goes straight from the Secret into
    OpenSearch's (admin-only) notification settings and is never printed."""
    found = opensearch("GET", f"/_plugins/_notifications/configs?config_type=webhook&text_query={CHANNEL}")
    configs = found.get("config_list") or []
    channel_body = {"config": {"name": CHANNEL, "description": "Asks Risk Guard to quarantine a workload for a while (tighten only).",
                               "config_type": "webhook", "is_enabled": True,
                               "webhook": {"url": SIGNALS_URL, "header_params": {"Content-Type": "application/json",
                                                                                 "Authorization": "Bearer " + signals_token()}}}}
    if configs:
        channel_id = configs[0]["config_id"]
        opensearch("PUT", f"/_plugins/_notifications/configs/{channel_id}", channel_body)
        print(f"webhook channel '{CHANNEL}': updated")
    else:
        created = opensearch("POST", "/_plugins/_notifications/configs", channel_body)
        channel_id = created.get("config_id")
        if not channel_id:
            raise SystemExit("channel NOT created: " + json.dumps(created)[:300])
        print(f"webhook channel '{CHANNEL}': created")

    top = "ctx.results.0.aggregations.by_sandbox.buckets.0"
    message = json.dumps({
        "signal_id": "opensearch-{{" + top + ".key}}-{{ctx.periodEnd}}", "source": "opensearch-alerting",
        "alert_id": "repeated-refusals", "sandbox_id": "{{" + top + ".key}}", "action": "quarantine", "ttl_seconds": 600,
        "reason": "three or more Risk Guard refusals for one sandbox in five minutes"})
    # A query-level monitor: its message can name the worst offender from the search result (ctx.results). A bucket-level monitor, which would handle every
    # offender, did not fill in its alert's bucket in the message on this OpenSearch version (the body arrived with empty fields; the webhook channel was
    # checked by capturing the real request). The cost: one sandbox per run, and a repeat is throttled for ten minutes.
    body = {"type": "monitor", "name": SIGNAL_MONITOR, "monitor_type": "query_level_monitor", "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [{"search": {"indices": [INDEX], "query": {"size": 0, "query": {"bool": {"filter": [
                {"wildcard": {"status_detail.keyword": "middleware_denied*"}},
                {"range": {"time": {"gte": "{{period_end}}||-5m", "lte": "{{period_end}}", "format": "epoch_millis"}}}]}},
                "aggregations": {"by_sandbox": {"terms": {"field": "container.uid.keyword", "min_doc_count": 3, "size": 1, "order": {"_count": "desc"}}}}}}}],
            "triggers": [{"query_level_trigger": {
                "name": "A sandbox keeps being refused", "severity": "1",
                "condition": {"script": {"source": "ctx.results[0].aggregations.by_sandbox.buckets.size() > 0", "lang": "painless"}},
                "actions": [{"name": "Ask Risk Guard to quarantine", "destination_id": channel_id,
                             "subject_template": {"source": "Risk Guard signal", "lang": "mustache"},
                             "message_template": {"source": message, "lang": "mustache"},
                             "throttle_enabled": True, "throttle": {"value": 10, "unit": "MINUTES"}}]}}]}
    existing = opensearch("POST", "/_plugins/_alerting/monitors/_search", {"query": {"match_phrase": {"monitor.name": "Repeated refusals"}}})
    for hit in (existing.get("hits") or {}).get("hits") or []:
        opensearch("DELETE", f"/_plugins/_alerting/monitors/{hit['_id']}")
    result = opensearch("POST", "/_plugins/_alerting/monitors", body)
    print("alert monitor: created" if "_id" in result else "alert monitor NOT created: " + json.dumps(result)[:300])


def main():
    if "--signals" in sys.argv:
        install_signals()
        return
    if "--retention" in sys.argv:
        install_retention()
        return
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
