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
RG_ALL = "unmapped.risk_guard.gate:(middleware or tunnel or signal)"
RG_MIDDLEWARE = 'unmapped.risk_guard.gate:"middleware"'
RG_TUNNEL = 'unmapped.risk_guard.gate:"tunnel"'
RG_SIGNAL = 'unmapped.risk_guard.gate:"signal"'
RG_SUMMARY = 'unmapped.risk_guard.gate:"summary"'
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


# OpenShell's own events (supervisors and gateway). These say what the agents actually do, which Risk Guard's events alone cannot.
HTTP = 'class_name:"HTTP Activity"'
NET = 'class_name:"Network Activity"'
DECISIONS_ALL = 'message:"MIDDLEWARE risk-guard"'                      # every decision Risk Guard gave a supervisor, allow or deny
MODEL_CALLS = 'class_name:"HTTP Activity" and dst_endpoint.domain:"integrate.api.nvidia.com"'
TOOL_CALLS = 'class_name:"HTTP Activity" and not dst_endpoint.domain:"integrate.api.nvidia.com" and not message:"Token grant"'
NET_DENIED = 'class_name:"Network Activity" and action:"Denied"'
NET_ALLOWED = 'class_name:"Network Activity" and action:"Allowed" and activity_name:"Open"'
AUTH_FAILED = 'class_name:"Authentication"'
STAGED = 'message:"Policy DNS staged unapproved name"'


def build_activity_objects():
    sandbox = terms("2", "container.name.keyword", "bucket", 10)
    objects = [
        saved_search("oa-search-denied", "Network connections OpenShell denied", "Destinations a sandbox tried to reach that its policy does not allow.", NET_DENIED,
                     columns=("container.name", "dst_endpoint.domain", "status_detail", "message")),
        saved_search("oa-search-auth", "Gateway authentication failures", "Callers the gateway did not recognise.", AUTH_FAILED,
                     columns=("src_endpoint.ip", "http_request.url.path", "auth_protocol", "message")),
        saved_search("oa-search-calls", "Agent calls through Risk Guard", "Every request a supervisor asked Risk Guard about.", DECISIONS_ALL,
                     columns=("container.name", "http_request.http_method", "http_request.url.hostname", "http_request.url.path", "action")),
        saved_search("oa-search-both", "One call, both layers", "OpenShell's record of each HTTP call beside Risk Guard's refusal of it. OpenShell's supervisor has no per-call id, so match on the sandbox (container.name), method, host and path; type a sandbox name or host in the search bar to follow one call.",
                     'class_name:"HTTP Activity" or unmapped.risk_guard.gate:"middleware"',
                     columns=("metadata.product.name", "container.name", "http_request.http_method", "http_request.url.hostname", "http_request.url.path", "action", "status_detail")),
        visualization("oa-model-calls", "Model calls", "metric", [COUNT], METRIC_PARAMS, MODEL_CALLS),
        visualization("oa-tool-calls", "Tool calls", "metric", [COUNT], METRIC_PARAMS, TOOL_CALLS),
        visualization("oa-decisions", "Decisions by Risk Guard", "metric", [COUNT], METRIC_PARAMS, DECISIONS_ALL),
        visualization("oa-sandboxes", "Sandboxes active", "metric", [metric_agg("1", "cardinality", "container.name.keyword")], METRIC_PARAMS, DECISIONS_ALL),
        visualization("oa-allow-deny-time", "Risk Guard decisions over time: allowed and refused", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", "action.keyword", "group")], BAR_PARAMS, DECISIONS_ALL),
        visualization("oa-per-sandbox", "Per sandbox: calls allowed and refused", "table",
                      [COUNT, sandbox, terms("3", "action.keyword", "bucket", 3)], TABLE_PARAMS, DECISIONS_ALL),
        visualization("oa-tool-destinations", "Where tool calls go", "table",
                      [COUNT, terms("2", "dst_endpoint.domain.keyword", "bucket", 8), terms("3", "action.keyword", "bucket", 3)], TABLE_PARAMS, TOOL_CALLS),
        visualization("oa-tool-routes", "Tool routes called, by method", "table",
                      [COUNT, terms("2", "http_request.url.path.keyword", "bucket", 10), terms("3", "http_request.http_method.keyword", "bucket", 3)], TABLE_PARAMS, TOOL_CALLS),
        visualization("oa-model-time", "Model calls over time, by sandbox", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", "container.name.keyword", "group", 6)], BAR_PARAMS, MODEL_CALLS),
        visualization("oa-denied-dest", "Destinations OpenShell denied", "table",
                      [COUNT, terms("2", "dst_endpoint.domain.keyword", "bucket", 8), terms("3", "status_detail.keyword", "bucket", 3)], TABLE_PARAMS, NET_DENIED),
        visualization("oa-denied-time", "Denied connections over time, by destination", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", "dst_endpoint.domain.keyword", "group", 6)], BAR_PARAMS, NET_DENIED),
        visualization("oa-allowed-dest", "Destinations sandboxes opened connections to", "pie",
                      [COUNT, terms("2", "dst_endpoint.domain.keyword", "segment", 8)], PIE_PARAMS, NET_ALLOWED),
        visualization("oa-staged", "Names agents asked for that policy has not approved", "table",
                      [COUNT, terms("2", "unmapped.normalized_domain.keyword", "bucket", 8), terms("3", "container.name.keyword", "bucket", 5)], TABLE_PARAMS, STAGED),
        visualization("oa-auth-time", "Gateway authentication failures over time", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", "http_request.url.path.keyword", "group", 4)], BAR_PARAMS, AUTH_FAILED),
        visualization("oa-auth-source", "Who the gateway did not recognise", "table",
                      [COUNT, terms("2", "src_endpoint.ip.keyword", "bucket", 10), terms("3", "auth_protocol.keyword", "bucket", 2)], TABLE_PARAMS, AUTH_FAILED),
        visualization("oa-ssh", "Operator sessions into sandboxes", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", "container.name.keyword", "group", 5)], BAR_PARAMS, 'class_name:"SSH Activity" and activity_name:"Open"'),
        visualization("oa-failures", "Times Risk Guard could not answer", "histogram",
                      [COUNT, TIME_BUCKET], BAR_PARAMS, FAILURES),
    ]
    activity = dashboard("oa-dashboard-activity", "Agent activity: what the agents do",
                         "Model calls, tool calls and what Risk Guard decided about each, per sandbox. From OpenShell's supervisor events.", [
        ("oa-model-calls", "visualization", 0, 0, 12, 7), ("oa-tool-calls", "visualization", 12, 0, 12, 7),
        ("oa-decisions", "visualization", 24, 0, 12, 7), ("oa-sandboxes", "visualization", 36, 0, 12, 7),
        ("oa-allow-deny-time", "visualization", 0, 7, 28, 14), ("oa-model-time", "visualization", 28, 7, 20, 14),
        ("oa-per-sandbox", "visualization", 0, 21, 24, 14), ("oa-tool-destinations", "visualization", 24, 21, 24, 14),
        ("oa-tool-routes", "visualization", 0, 35, 48, 13), ("oa-search-calls", "search", 0, 48, 48, 13),
        ("oa-search-both", "search", 0, 61, 48, 14)])
    egress = dashboard("oa-dashboard-egress", "Egress and policy: where agents tried to go",
                       "Destinations denied by policy, where connections were allowed, and names agents asked for that nobody has approved yet (candidates for a policy decision).", [
        ("oa-denied-dest", "visualization", 0, 0, 24, 14), ("oa-allowed-dest", "visualization", 24, 0, 24, 14),
        ("oa-denied-time", "visualization", 0, 14, 48, 14),
        ("oa-staged", "visualization", 0, 28, 48, 13), ("oa-search-denied", "search", 0, 41, 48, 13)])
    control = dashboard("oa-dashboard-control", "Control plane: gateway and sandboxes",
                        "Callers the gateway does not recognise, times Risk Guard could not answer, and operator sessions into sandboxes.", [
        ("oa-auth-time", "visualization", 0, 0, 48, 14),
        ("oa-auth-source", "visualization", 0, 14, 24, 14), ("oa-failures", "visualization", 24, 14, 24, 14),
        ("oa-ssh", "visualization", 0, 28, 48, 13), ("oa-search-auth", "search", 0, 41, 48, 13)])
    return objects + [activity, egress, control]


def build_workload_objects():
    """Per-workload activity from Risk Guard's once-a-minute summaries (every decision counted, allowed or refused)."""
    by_workload = terms("3", "actor.user.name.keyword", "group", 8)
    sum_total = metric_agg("1", "sum", RG_FIELD + "total")
    objects = [
        saved_search("wl-search", "Workload activity summaries", "One line per active sandbox per minute.", RG_SUMMARY,
                     columns=("actor.user.name", "unmapped.risk_guard.total", "unmapped.risk_guard.refused_calls", "unmapped.risk_guard.max_score", "unmapped.risk_guard.distinct_routes")),
        visualization("wl-decisions", "Decisions counted", "metric", [metric_agg("1", "sum", RG_FIELD + "total")], METRIC_PARAMS, RG_SUMMARY),
        visualization("wl-refused", "Of which refused", "metric", [metric_agg("1", "sum", RG_FIELD + "refused_calls")], METRIC_PARAMS, RG_SUMMARY),
        visualization("wl-active", "Workloads active", "metric", [metric_agg("1", "cardinality", "actor.user.name.keyword")], METRIC_PARAMS, RG_SUMMARY),
        visualization("wl-rate", "Decisions per minute, by workload", "histogram", [sum_total, TIME_BUCKET, by_workload], BAR_PARAMS, RG_SUMMARY),
        visualization("wl-refused-time", "Refused decisions, by workload", "histogram",
                      [metric_agg("1", "sum", RG_FIELD + "refused_calls"), TIME_BUCKET, by_workload], BAR_PARAMS, RG_SUMMARY),
        visualization("wl-table", "Per workload: decisions, refused, share refused, highest score", "table",
                      [metric_agg("1", "sum", RG_FIELD + "total"), terms("2", "actor.user.name.keyword", "bucket", 10),
                       metric_agg("3", "sum", RG_FIELD + "refused_calls"), metric_agg("4", "avg", RG_FIELD + "refusal_ratio"),
                       metric_agg("5", "max", RG_FIELD + "max_score")], TABLE_PARAMS, RG_SUMMARY),
        visualization("wl-variety", "Distinct paths per minute (highest), by workload", "line",
                      [metric_agg("1", "max", RG_FIELD + "distinct_routes"), TIME_BUCKET, terms("3", "actor.user.name.keyword", "group", 6)], dict(LINE_PARAMS, seriesParams=[
                          {"show": True, "type": "line", "mode": "normal", "data": {"label": "Distinct paths", "id": "1"}, "valueAxis": "ValueAxis-1",
                           "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}]), RG_SUMMARY),
        visualization("wl-tasks", "Decisions by task profile", "pie", [sum_total, terms("2", RG_FIELD + "task_profile.keyword", "segment")], PIE_PARAMS, RG_SUMMARY),
    ]
    board = dashboard("wl-dashboard", "Workloads: what each agent does",
                      "Every decision Risk Guard made, counted per workload per minute (allowed and refused), with the highest score and how many different paths it touched. "
                      "A workload that stops appearing here has gone quiet.", [
        ("wl-decisions", "visualization", 0, 0, 16, 7), ("wl-refused", "visualization", 16, 0, 16, 7), ("wl-active", "visualization", 32, 0, 16, 7),
        ("wl-rate", "visualization", 0, 7, 28, 14), ("wl-refused-time", "visualization", 28, 7, 20, 14),
        ("wl-table", "visualization", 0, 21, 48, 13),
        ("wl-variety", "visualization", 0, 34, 32, 13), ("wl-tasks", "visualization", 32, 34, 16, 13),
        ("wl-search", "search", 0, 47, 48, 13)], time_from="now-6h")
    return objects + [board]


# ---- The dashboards an operator actually uses, organised around agents -------------------------------------------------------------------------------
AGENT = "actor.user.full_name.keyword"
SUMMARY = 'unmapped.risk_guard.gate:"summary"'          # one per active workload per minute: every decision counted
ROUTES = 'unmapped.risk_guard.gate:"route"'            # one per workload per route per minute
EGRESS = 'unmapped.risk_guard.gate:"egress"'           # one per workload per destination per minute
NOTABLE = "unmapped.risk_guard.gate:(middleware or tunnel or signal)"   # refusals, tunnel refusals, signals
RGF = "unmapped.risk_guard."

OLD_DASHBOARDS = ["rg-dashboard-overview", "rg2-dashboard-decisions", "rg2-dashboard-signals", "wl-dashboard", "oa-dashboard-control"]

NAV = ("**Start here:** [Three systems](#/view/h3-start) &nbsp;|&nbsp; **Agents:** [Fleet](#/view/ag-fleet) · [One agent](#/view/ag-agent) · [Incidents](#/view/ag-incidents) · [Control health](#/view/ag-health) "
       "&nbsp;|&nbsp; **Sandboxes (OpenShell events):** [Calls](#/view/oa-dashboard-activity) · [Egress and policy](#/view/oa-dashboard-egress)")


def markdown(oid, title, text):
    state = {"title": title, "type": "markdown", "aggs": [], "params": {"fontSize": 12, "openLinksInNewTab": False, "markdown": text}}
    return {"id": oid, "type": "visualization", "migrationVersion": {"visualization": "7.10.0"}, "references": [],
            "attributes": {"title": title, "visState": json.dumps(state), "uiStateJSON": "{}", "description": "", "version": 1,
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}}}


def input_control(oid, title, field, label):
    control = {"id": "1", "indexPattern": PATTERN_ID, "fieldName": field, "parent": "", "label": label, "type": "list",
               "options": {"type": "terms", "multiselect": False, "dynamicOptions": True, "size": 25, "order": "desc"}}
    state = {"title": title, "type": "input_control_vis", "aggs": [],
             "params": {"controls": [control], "updateFiltersOnChange": True, "useTimeFilter": True, "pinFilters": False}}
    return {"id": oid, "type": "visualization", "migrationVersion": {"visualization": "7.10.0"},
            "references": [{"name": "control_0_index_pattern", "type": "index-pattern", "id": PATTERN_ID}],
            "attributes": {"title": title, "visState": json.dumps(state), "uiStateJSON": "{}", "description": "", "version": 1,
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}}}


def total(agg_id="1", field="total"):
    return metric_agg(agg_id, "sum", RGF + field)


def build_agent_dashboards():
    by_agent_group = terms("3", AGENT, "group", 8)
    by_agent_row = terms("2", AGENT, "bucket", 15)
    events_cols = (AGENT, "unmapped.risk_guard.gate", "status_detail", "risk_score", "message")
    objects = [
        markdown("ag-nav", "Navigation", NAV),
        input_control("ag-pick", "Pick an agent", AGENT, "Agent"),
        saved_search("ag-log", "What happened (newest first)", "Refusals, tunnel refusals and signals for the agent in view.", NOTABLE, columns=events_cols),
        saved_search("ag-incident-log", "Incident log", "Refusals, tunnel refusals and signals, in the order they happened.", NOTABLE, columns=events_cols),
        # --- fleet
        visualization("ag-active", "Agents active", "metric", [metric_agg("1", "cardinality", AGENT)], METRIC_PARAMS, SUMMARY),
        visualization("ag-decisions", "Decisions", "metric", [total()], METRIC_PARAMS, SUMMARY),
        visualization("ag-refused", "Refused", "metric", [total("1", "refused_calls")], METRIC_PARAMS, SUMMARY),
        visualization("ag-score", "Highest score", "metric", [metric_agg("1", "max", RGF + "max_score")], METRIC_PARAMS, SUMMARY),
        visualization("ag-contained", "Containment actions", "metric", [COUNT], METRIC_PARAMS,
                      '(unmapped.risk_guard.gate:"tunnel" and unmapped.risk_guard.refused:true) or (unmapped.risk_guard.gate:"signal" and unmapped.risk_guard.outcome:"applied")'),
        visualization("ag-table", "Agents", "table",
                      [total(), by_agent_row, terms("3", RGF + "task_profile.keyword", "bucket", 3), total("4", "refused_calls"),
                       metric_agg("5", "max", RGF + "max_score"), metric_agg("6", "max", "time")], TABLE_PARAMS, SUMMARY),
        visualization("ag-rate", "Decisions per minute, by agent", "histogram", [total(), TIME_BUCKET, by_agent_group], BAR_PARAMS, SUMMARY),
        visualization("ag-refusal-share", "Share of decisions refused (average of each minute), by agent", "line",
                      [metric_agg("1", "avg", RGF + "refusal_ratio"), TIME_BUCKET, by_agent_group], dict(LINE_PARAMS, seriesParams=[
                          {"show": True, "type": "line", "mode": "normal", "data": {"label": "Share refused", "id": "1"}, "valueAxis": "ValueAxis-1",
                           "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}]), SUMMARY),
        visualization("ag-which-sandbox", "Which sandbox is which agent", "table",
                      [COUNT, terms("2", "container.uid.keyword", "bucket", 15), terms("3", AGENT, "bucket", 2)], TABLE_PARAMS, SUMMARY),
        # --- one agent
        visualization("ag1-decisions", "Decisions", "metric", [total()], METRIC_PARAMS, SUMMARY),
        visualization("ag1-refused", "Refused", "metric", [total("1", "refused_calls")], METRIC_PARAMS, SUMMARY),
        visualization("ag1-score", "Highest score", "metric", [metric_agg("1", "max", RGF + "max_score")], METRIC_PARAMS, SUMMARY),
        visualization("ag1-routes", "Routes used", "metric", [metric_agg("1", "cardinality", RGF + "route.keyword")], METRIC_PARAMS, ROUTES),
        visualization("ag1-destinations", "Destinations", "metric", [metric_agg("1", "cardinality", RGF + "destination.keyword")], METRIC_PARAMS, EGRESS),
        visualization("ag1-over-time", "Allowed and refused over time", "histogram",
                      [total("1", "allowed_calls"), TIME_BUCKET, total("3", "refused_calls")], BAR_PARAMS, SUMMARY),
        visualization("ag1-score-time", "Highest score per minute", "line", [metric_agg("1", "max", RGF + "max_score"), TIME_BUCKET], dict(LINE_PARAMS, seriesParams=[
            {"show": True, "type": "line", "mode": "normal", "data": {"label": "Highest score", "id": "1"}, "valueAxis": "ValueAxis-1",
             "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}]), SUMMARY),
        visualization("ag1-route-table", "What it calls: route, allowed and refused", "table",
                      [total("1", "allowed_calls"), terms("2", RGF + "host.keyword", "bucket", 6), terms("3", RGF + "method.keyword", "bucket", 6),
                       terms("4", RGF + "route.keyword", "bucket", 12), total("5", "refused_calls"), metric_agg("6", "max", RGF + "max_score")], TABLE_PARAMS, ROUTES),
        visualization("ag1-egress-table", "Where it connects: destination, allowed, refused, would be refused in enforce", "table",
                      [total("1", "allowed_calls"), terms("2", RGF + "destination.keyword", "bucket", 12), total("3", "refused_calls"), total("4", "shadow_calls")],
                      TABLE_PARAMS, EGRESS),
        visualization("ag1-reasons", "Why it was refused", "pie", [COUNT, terms("2", RGF + "reason_code.keyword", "segment")], PIE_PARAMS, 'unmapped.risk_guard.gate:"middleware"'),
        # --- incidents
        visualization("in-refusals", "Refusals", "metric", [COUNT], METRIC_PARAMS, 'unmapped.risk_guard.gate:"middleware"'),
        visualization("in-tunnels", "Tunnels refused", "metric", [COUNT], METRIC_PARAMS, 'unmapped.risk_guard.gate:"tunnel" and unmapped.risk_guard.refused:true'),
        visualization("in-signals", "Signals", "metric", [COUNT], METRIC_PARAMS, 'unmapped.risk_guard.gate:"signal"'),
        visualization("in-agents", "Agents involved", "metric", [metric_agg("1", "cardinality", AGENT)], METRIC_PARAMS, NOTABLE),
        visualization("in-timeline", "Timeline of notable events, by kind", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", "status_detail.keyword", "group", 8)], BAR_PARAMS, NOTABLE),
        visualization("in-by-agent", "By agent: events, first seen, last seen, highest score", "table",
                      [COUNT, by_agent_row, metric_agg("3", "min", "time"), metric_agg("4", "max", "time"), metric_agg("5", "max", "risk_score")], TABLE_PARAMS, NOTABLE),
        visualization("in-readiness", "Enforcement readiness: what shadow mode would have refused, by agent", "table",
                      [total("1", "shadow_calls"), terms("2", AGENT, "bucket", 15), total("3", "refused_calls"), total("4", "allowed_calls")], TABLE_PARAMS, EGRESS),
        visualization("in-signal-outcomes", "Signals: who sent them, what happened", "table",
                      [COUNT, terms("2", RGF + "source.keyword", "bucket", 5), terms("3", RGF + "outcome.keyword", "bucket", 6)], TABLE_PARAMS, 'unmapped.risk_guard.gate:"signal"'),
        # --- control health
        visualization("hl-heartbeat", "Risk Guard heartbeat: summaries per minute (a gap is silence)", "histogram", [COUNT, TIME_BUCKET], BAR_PARAMS, SUMMARY),
        visualization("hl-sources", "Which sources are reporting", "pie", [COUNT, terms("2", "metadata.product.name.keyword", "segment", 6)], PIE_PARAMS),
        visualization("hl-silent", "Supervisors that went quiet", "metric", [COUNT], METRIC_PARAMS, 'unmapped.risk_guard.kind:"supervisor_silent"'),
        visualization("hl-failed", "Times Risk Guard could not answer (failed closed)", "metric", [COUNT], METRIC_PARAMS, FAILURES),
        visualization("hl-limited", "Signals held back by a limit", "metric", [COUNT], METRIC_PARAMS,
                      'unmapped.risk_guard.gate:"signal" and unmapped.risk_guard.outcome:("rate_limited" or "too_many_active")'),
        visualization("hl-routes-rate", "Decisions per minute, all agents", "histogram", [total(), TIME_BUCKET], BAR_PARAMS, SUMMARY),
    ]
    note_fleet = markdown("ag-note-fleet", "How to read this", "Every decision Risk Guard makes is counted per agent per minute. **A line that stops is an agent that went quiet.** "
                          "'Share refused' is the average of each minute's share. Pick an agent on **One agent** for its routes, destinations and reasons.")
    objects.append(note_fleet)
    fleet = dashboard("ag-fleet", "Fleet: are my agents behaving?",
                      "Every agent at a glance: how much it does, how much is refused, its highest score, when it was last seen.", [
        ("ag-nav", "visualization", 0, 0, 48, 3),
        ("ag-active", "visualization", 0, 3, 10, 7), ("ag-decisions", "visualization", 10, 3, 10, 7), ("ag-refused", "visualization", 20, 3, 10, 7),
        ("ag-score", "visualization", 30, 3, 9, 7), ("ag-contained", "visualization", 39, 3, 9, 7),
        ("ag-table", "visualization", 0, 10, 48, 14),
        ("ag-rate", "visualization", 0, 24, 24, 14), ("ag-refusal-share", "visualization", 24, 24, 24, 14),
        ("ag-which-sandbox", "visualization", 0, 38, 24, 13), ("ag-note-fleet", "visualization", 24, 38, 24, 13),
        ("ag-log", "search", 0, 51, 48, 14)], time_from="now-24h")
    one = dashboard("ag-agent", "One agent: what it does and what was refused",
                    "Choose an agent. Everything below follows the choice: its decisions, the routes it calls, where it connects, why it was refused.", [
        ("ag-nav", "visualization", 0, 0, 48, 3), ("ag-pick", "visualization", 0, 3, 48, 5),
        ("ag1-decisions", "visualization", 0, 8, 10, 6), ("ag1-refused", "visualization", 10, 8, 10, 6), ("ag1-score", "visualization", 20, 8, 10, 6),
        ("ag1-routes", "visualization", 30, 8, 9, 6), ("ag1-destinations", "visualization", 39, 8, 9, 6),
        ("ag1-over-time", "visualization", 0, 14, 28, 13), ("ag1-score-time", "visualization", 28, 14, 20, 13),
        ("ag1-route-table", "visualization", 0, 27, 48, 14), ("ag1-egress-table", "visualization", 0, 41, 30, 13), ("ag1-reasons", "visualization", 30, 41, 18, 13),
        ("ag-log", "search", 0, 54, 48, 14)], time_from="now-24h")
    incidents = dashboard("ag-incidents", "Incidents: what was refused, contained or signalled",
                          "Refusals, tunnels refused and signals from the SIEM, by agent and in time order, with what shadow mode would have refused (is it safe to enforce?).", [
        ("ag-nav", "visualization", 0, 0, 48, 3),
        ("in-refusals", "visualization", 0, 3, 12, 6), ("in-tunnels", "visualization", 12, 3, 12, 6), ("in-signals", "visualization", 24, 3, 12, 6), ("in-agents", "visualization", 36, 3, 12, 6),
        ("in-timeline", "visualization", 0, 9, 48, 14),
        ("in-by-agent", "visualization", 0, 23, 48, 13),
        ("in-readiness", "visualization", 0, 36, 28, 13), ("in-signal-outcomes", "visualization", 28, 36, 20, 13),
        ("ag-incident-log", "search", 0, 49, 48, 15)], time_from="now-7d")
    health = dashboard("ag-health", "Control health: is the control itself working?",
                       "Is Risk Guard answering, is it reporting, are callers being refused at the gateway, did a supervisor go quiet?", [
        ("ag-nav", "visualization", 0, 0, 48, 3),
        ("hl-failed", "visualization", 0, 3, 16, 6), ("hl-silent", "visualization", 16, 3, 16, 6), ("hl-limited", "visualization", 32, 3, 16, 6),
        ("hl-heartbeat", "visualization", 0, 9, 28, 13), ("hl-sources", "visualization", 28, 9, 20, 13),
        ("hl-routes-rate", "visualization", 0, 22, 48, 12),
        ("oa-auth-time", "visualization", 0, 34, 48, 13), ("oa-auth-source", "visualization", 0, 47, 24, 13), ("oa-failures", "visualization", 24, 47, 24, 13),
        ("oa-ssh", "visualization", 0, 60, 48, 12)], time_from="now-24h")
    return objects + [fleet, one, incidents, health]


# --- Start here: the three systems side by side -----------------------------------------------------------------------------------------------------------------
OS_L7_DENIED = 'firewall_rule.type:"l7" and action:"Denied"'
OS_AUDIT = 'message:"L7_REQUEST audit"'          # a policy endpoint in audit mode: logged as a violation, and let through
# What OpenShell itself refused (the sandbox supervisor, not Risk Guard's middleware, which the supervisor also logs with firewall_rule.type "middleware"). A DNS
# refusal is left out because the connection attempt that follows it is logged on its own, so one attempt would count twice. Every sandbox also tries
# events.telemetry.data.nvidia.com in the background and is refused (about 97% of the denied connections in the demo), so that one destination is not counted:
# without that, every sandbox would look like it was being refused repeatedly. Change OS_BACKGROUND_HOSTS if a deployment has other background noise.
OS_BACKGROUND_HOSTS = ["events.telemetry.data.nvidia.com"]
OS_ENFORCED = ('metadata.product.name:"OpenShell Sandbox Supervisor" and action:"Denied" and not firewall_rule.type:"middleware" and not activity_name:"Refuse"'
               + "".join(f' and not dst_endpoint.domain:"{h}"' for h in OS_BACKGROUND_HOSTS))
OS_ANY_DENIED = '(class_name:"Network Activity" and action:"Denied") or (firewall_rule.type:"l7" and action:"Denied")'


def filters_agg(agg_id, pairs):
    """Several named queries as the series of one chart: how a count splits between layers, which no single field can say."""
    return {"id": agg_id, "enabled": True, "type": "filters", "schema": "group",
            "params": {"filters": [{"input": {"query": q, "language": "kuery"}, "label": label} for label, q in pairs]}}


def build_layers_objects():
    intro = markdown("h3-intro", "How to read this page",
                     "**Read left to right: the path of one call.** **OpenShell** permits (its policy). **Risk Guard** judges, and can only narrow OpenShell's answer. "
                     "**OpenSearch** remembers: it blocks nothing, and its alerts can only ask Risk Guard to tighten. Only the first two can stop a call.  \n" + NAV)
    lane_os = markdown("h3-lane-os", "OpenShell", "### OpenShell: permits\nRefuses what its policy does not allow, before Risk Guard sees the call. Needs no learning.")
    lane_rg = markdown("h3-lane-rg", "Risk Guard", "### Risk Guard: judges\nRefuses a call that is not normal for this workload. Some controls only *watch*: see Controls in the console.")
    lane_sx = markdown("h3-lane-sx", "OpenSearch", "### OpenSearch: remembers\nStores what both layers saw. Blocks nothing; an alert can ask Risk Guard to tighten.")
    objects = [
        intro, lane_os, lane_rg, lane_sx,
        visualization("h3-os-net", "Connections OpenShell denied", "metric", [COUNT], METRIC_PARAMS, NET_DENIED),
        visualization("h3-os-l7", "Requests OpenShell's L7 policy denied", "metric", [COUNT], METRIC_PARAMS, OS_L7_DENIED),
        visualization("h3-os-audit", "Requests OpenShell would block (audit mode)", "metric", [COUNT], METRIC_PARAMS, OS_AUDIT),
        saved_search("h3-search-audit", "What OpenShell would block (audit mode)", "Requests a policy endpoint in audit mode logged as a violation and let through: what enforcing would start refusing.", OS_AUDIT,
                     columns=("container.name", "http_request.http_method", "http_request.url.path", "message")),
        visualization("h3-rg-refused", "Calls Risk Guard refused", "metric", [COUNT], METRIC_PARAMS, RG_MIDDLEWARE),
        visualization("h3-rg-tunnel", "Tunnels Risk Guard flagged (refused or would refuse)", "metric", [COUNT], METRIC_PARAMS, RG_TUNNEL),
        visualization("h3-sx-events", "Events stored", "metric", [COUNT], METRIC_PARAMS),
        visualization("h3-sx-signals", "Signals received from the SIEM", "metric", [COUNT], METRIC_PARAMS, RG_SIGNAL),
        visualization("h3-rg-reasons", "Why Risk Guard refused", "table",
                      [COUNT, terms("2", "unmapped.risk_guard.reason_code.keyword", "bucket", 8)], TABLE_PARAMS, RG_MIDDLEWARE),
        visualization("h3-sx-sources", "Where the events come from", "pie",
                      [COUNT, terms("2", "metadata.product.name.keyword", "segment", 6)], PIE_PARAMS),
        visualization("h3-os-by-sandbox", "OpenShell denials per sandbox, over time (background telemetry host not counted)", "histogram",
                      [COUNT, TIME_BUCKET, terms("3", "container.name.keyword", "group", 10)], BAR_PARAMS, OS_ENFORCED),
        saved_search("h3-search-os-denied", "What OpenShell denied (enforced, background telemetry host not counted)",
                     "Requests and connections OpenShell's policy refused. Risk Guard never sees these calls. A watch-only alert in Alerting flags 3 or more of these in 5 minutes for one sandbox.",
                     OS_ENFORCED, columns=("container.name", "class_name", "dst_endpoint.domain", "http_request.http_method", "http_request.url.path", "message")),
        visualization("h3-who", "Who stopped calls, over time", "histogram",
                      [COUNT, TIME_BUCKET, filters_agg("3", [("OpenShell refused", OS_ANY_DENIED), ("Risk Guard refused", RG_MIDDLEWARE),
                                                             ("Risk Guard tunnel gate flagged", RG_TUNNEL)])], BAR_PARAMS),
    ]
    board = dashboard("h3-start", "0. Start here: OpenShell, Risk Guard, OpenSearch",
                      "The three systems side by side, left to right: what OpenShell denied, what Risk Guard refused, and what OpenSearch holds. Start here, then follow the links.", [
        ("h3-intro", "visualization", 0, 0, 48, 6),
        ("h3-lane-os", "visualization", 0, 6, 16, 5), ("h3-lane-rg", "visualization", 16, 6, 16, 5), ("h3-lane-sx", "visualization", 32, 6, 16, 5),
        ("h3-os-net", "visualization", 0, 11, 16, 4), ("h3-os-l7", "visualization", 0, 15, 16, 4), ("h3-os-audit", "visualization", 0, 19, 16, 4),
        ("h3-rg-refused", "visualization", 16, 11, 16, 6), ("h3-rg-tunnel", "visualization", 16, 17, 16, 6),
        ("h3-sx-events", "visualization", 32, 11, 16, 6), ("h3-sx-signals", "visualization", 32, 17, 16, 6),
        ("oa-denied-dest", "visualization", 0, 23, 16, 13), ("h3-rg-reasons", "visualization", 16, 23, 16, 13), ("h3-sx-sources", "visualization", 32, 23, 16, 13),
        ("h3-who", "visualization", 0, 36, 48, 14),
        ("oa-search-both", "search", 0, 50, 48, 13),
        ("h3-os-by-sandbox", "visualization", 0, 63, 48, 14), ("h3-search-os-denied", "search", 0, 77, 48, 13)], time_from="now-24h")
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
    return objects + build_risk_guard_objects() + build_activity_objects() + build_workload_objects() + build_agent_dashboards() + build_layers_objects() + build_synthetic_objects()


def feature(name, field="metadata.uid.keyword"):
    # Counts events per interval. (A detector feature must be a single metric; the filter lives on the detector itself.)
    return {"feature_name": name, "feature_enabled": True, "aggregation_query": {name: {"value_count": {"field": field}}}}


def detector(name, description, query_filter):
    return {"name": name, "description": description, "time_field": "time", "indices": [INDEX],
            "feature_attributes": [feature("events")],
            "filter_query": {"bool": {"filter": query_filter}} if query_filter else {"match_all": {}},
            "detection_interval": {"period": {"interval": 1, "unit": "Minutes"}},
            "window_delay": {"period": {"interval": 1, "unit": "Minutes"}}, "shingle_size": 8}


def entity_detector(name, description, features, minutes=5):
    """One baseline per workload (the detector's category field), on Risk Guard's activity summaries."""
    return {"name": name, "description": description, "time_field": "time", "indices": [INDEX],
            "feature_attributes": [{"feature_name": n, "feature_enabled": True, "aggregation_query": {n: {agg: {"field": f}}}} for n, agg, f in features],
            "filter_query": {"bool": {"filter": [{"term": {"unmapped.risk_guard.gate.keyword": "summary"}}]}},
            "detection_interval": {"period": {"interval": minutes, "unit": "Minutes"}},
            "window_delay": {"period": {"interval": 1, "unit": "Minutes"}}, "shingle_size": 6,
            "category_field": ["actor.user.name.keyword"]}


def install_detectors():
    wanted = [
        entity_detector("workload-activity-by-agent",
                        "How much each workload does, how much of it is refused and how varied it is, against that workload's own normal.",
                        [("decisions", "sum", "unmapped.risk_guard.total"), ("refused", "sum", "unmapped.risk_guard.refused_calls"),
                         ("routes", "max", "unmapped.risk_guard.distinct_routes")]),
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
FORWARDER_URL = "http://signal-forwarder.siem.svc.cluster.local:8088/webhook"
CHANNEL = "risk-guard-signals"
SIGNAL_MONITOR = "Repeated refusals: 3 or more in 5 minutes, per sandbox (asks Risk Guard to quarantine)"


def secret_token(name, namespace):
    import base64
    out = subprocess.run(["kubectl", "get", "secret", name, "-n", namespace, "-o", "jsonpath={.data.token}"], capture_output=True)
    return base64.b64decode(out.stdout).decode().strip()


def signals_target():
    """Where the alert's webhook goes and the token it carries. With the SIEM-side forwarder deployed (mutual TLS to Risk Guard) it goes to the forwarder; otherwise straight to
    Risk Guard's token-protected port."""
    token = secret_token("signal-forwarder-token", "siem")
    if len(token) == 64:
        return FORWARDER_URL, token
    token = secret_token("siem-signals-token", "openshell")
    if len(token) != 64:
        raise SystemExit("No signals token found; run scripts/aks/25-enable-signals.ps1 first.")
    return SIGNALS_URL, token


def signals_token():
    return signals_target()[1]


def install_signals():
    """The webhook channel that carries a signal to Risk Guard, and the alert that sends one. The token goes straight from the Secret into
    OpenSearch's (admin-only) notification settings and is never printed."""
    found = opensearch("GET", f"/_plugins/_notifications/configs?config_type=webhook&text_query={CHANNEL}")
    configs = found.get("config_list") or []
    channel_body = {"config": {"name": CHANNEL, "description": "Asks Risk Guard to quarantine a workload for a while (tighten only).",
                               "config_type": "webhook", "is_enabled": True,
                               "webhook": {"url": signals_target()[0], "header_params": {"Content-Type": "application/json",
                                                                                         "Authorization": "Bearer " + signals_target()[1]}}}}
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


def _since(minutes):
    return {"range": {"time": {"gte": "{{period_end}}||-%dm" % minutes, "lte": "{{period_end}}", "format": "epoch_millis"}}}


# Monitors that only watch. They have no action, so they raise an alert in OpenSearch Alerting for a person to look at and never send a signal to Risk Guard (the
# one monitor that does is install_signals). Each asks a question that Risk Guard's own per-minute summaries can answer.
WATCH_MONITORS = {
    "Watch: refusal ratio jumped (half or more of 10+ calls refused in 5 minutes, per agent)": {
        "query": {"size": 0, "query": {"bool": {"filter": [
            {"term": {RG_FIELD + "gate.keyword": "summary"}}, {"range": {RG_FIELD + "refusal_ratio": {"gte": 0.5}}}, {"range": {RG_FIELD + "total": {"gte": 10}}}, _since(5)]}},
            "aggregations": {"by_agent": {"terms": {"field": RG_FIELD + "agent_id.keyword", "size": 5}}}},
        "condition": "ctx.results[0].aggregations.by_agent.buckets.size() > 0", "severity": "2", "name": "An agent is being refused far more than usual"},
    "Watch: an agent called a destination it had not called in the last day": {
        "query": {"size": 0, "query": {"bool": {"filter": [{"term": {RG_FIELD + "gate.keyword": "route"}}, _since(24 * 60)]}},
                  "aggregations": {"by_agent": {"terms": {"field": RG_FIELD + "agent_id.keyword", "size": 50}, "aggregations": {"by_host": {
                      "terms": {"field": RG_FIELD + "host.keyword", "size": 100}, "aggregations": {
                          "recent": {"filter": {"range": {"time": {"gte": "{{period_end}}||-10m", "format": "epoch_millis"}}}},
                          "only_new": {"bucket_selector": {"buckets_path": {"total": "_count", "recent": "recent>_count"}, "script": "params.total == params.recent"}}}}}}}},
        "condition": "for (a in ctx.results[0].aggregations.by_agent.buckets) { if (a.by_host.buckets.size() > 0) { return true; } } return false;",
        "severity": "3", "name": "An agent reached a new destination"},
    "Watch: a sandbox that was making calls has gone quiet for 10 minutes": {
        "query": {"size": 0, "query": {"bool": {"filter": [{"term": {RG_FIELD + "gate.keyword": "summary"}}, _since(60)]}},
                  "aggregations": {"by_sandbox": {"terms": {"field": "container.uid.keyword", "size": 50}, "aggregations": {
                      "recent": {"filter": {"range": {"time": {"gte": "{{period_end}}||-10m", "format": "epoch_millis"}}}},
                      "gone_quiet": {"bucket_selector": {"buckets_path": {"recent": "recent>_count"}, "script": "params.recent == 0"}}}}}},
        "condition": "ctx.results[0].aggregations.by_sandbox.buckets.size() > 0", "severity": "3", "name": "A sandbox stopped sending calls"},
}


# The OpenShell watch: OpenShell checks its policy before Risk Guard's middleware, so a call it refuses first never reaches Risk Guard and Risk Guard cannot count it.
# This is a bucket-level monitor, so each sandbox over the line is its own alert, named by its bucket keys (sandbox name and id). Like the others it has no action:
# nothing is sent to Risk Guard or anywhere else.
OPENSHELL_WATCH = "Watch: OpenShell refused one sandbox 3 or more times in 5 minutes (Risk Guard never saw these)"


def openshell_watch_body():
    query = {"size": 0, "query": {"bool": {"filter": [
        {"term": {"metadata.product.name.keyword": "OpenShell Sandbox Supervisor"}}, {"term": {"action.keyword": "Denied"}}, _since(5)],
        "must_not": [{"term": {"firewall_rule.type.keyword": "middleware"}}, {"term": {"activity_name.keyword": "Refuse"}},
                     {"terms": {"dst_endpoint.domain.keyword": OS_BACKGROUND_HOSTS}}]}},
        "aggregations": {"by_sandbox": {"composite": {"size": 50, "sources": [{"sandbox": {"terms": {"field": "container.name.keyword"}}},
                                                                              {"sandbox_id": {"terms": {"field": "container.uid.keyword"}}}]}}}}
    return {"type": "monitor", "name": OPENSHELL_WATCH, "monitor_type": "bucket_level_monitor", "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [{"search": {"indices": [INDEX], "query": query}}],
            "triggers": [{"bucket_level_trigger": {
                "name": "OpenShell keeps refusing one sandbox", "severity": "2",
                "condition": {"buckets_path": {"_count": "_count"}, "parent_bucket_path": "by_sandbox", "script": {"source": "params._count >= 3", "lang": "painless"}},
                "actions": []}}]}


def install_openshell_watch():
    found = opensearch("POST", "/_plugins/_alerting/monitors/_search", {"query": {"match_phrase": {"monitor.name": OPENSHELL_WATCH}}})
    for hit in (found.get("hits") or {}).get("hits") or []:
        opensearch("DELETE", f"/_plugins/_alerting/monitors/{hit['_id']}")
    created = opensearch("POST", "/_plugins/_alerting/monitors", openshell_watch_body())
    print(f"watch monitor '{OPENSHELL_WATCH[:60]}': " + ("created" if "_id" in created else "NOT created: " + json.dumps(created)[:300]))


def install_watch_monitors():
    install_openshell_watch()
    for name, spec in WATCH_MONITORS.items():
        found = opensearch("POST", "/_plugins/_alerting/monitors/_search", {"query": {"match_phrase": {"monitor.name": name}}})
        for hit in (found.get("hits") or {}).get("hits") or []:
            opensearch("DELETE", f"/_plugins/_alerting/monitors/{hit['_id']}")
        body = {"type": "monitor", "name": name, "monitor_type": "query_level_monitor", "enabled": True,
                "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
                "inputs": [{"search": {"indices": [INDEX], "query": spec["query"]}}],
                "triggers": [{"query_level_trigger": {"name": spec["name"], "severity": spec["severity"],
                                                      "condition": {"script": {"source": spec["condition"], "lang": "painless"}}, "actions": []}}]}
        created = opensearch("POST", "/_plugins/_alerting/monitors", body)
        print(f"watch monitor '{name[:60]}': " + ("created" if "_id" in created else "NOT created: " + json.dumps(created)[:300]))


def main():
    if "--signals" in sys.argv:
        install_signals()
        return
    if "--retention" in sys.argv:
        install_retention()
        return
    if "--watch" in sys.argv:
        install_watch_monitors()
        return
    for old in OLD_DASHBOARDS:
        exec_in_pod(f"curl -s -X DELETE -u admin:$OPENSEARCH_PASSWORD -H 'osd-xsrf: true' 'http://localhost:5601/api/saved_objects/dashboard/{old}'")
    imported = dashboards_import("\n".join(json.dumps(o) for o in build_objects()) + "\n")
    errors = imported.get("errors") or []
    print(f"dashboard objects: {imported.get('successCount', 0)} imported, {len(errors)} errors")
    for error in errors[:5]:
        print("  error:", json.dumps(error)[:240])
    for name, status, _ in install_detectors():
        print(f"anomaly detector '{name}': {status}")
    print("alert monitor '%s': %s" % install_monitor())
    install_watch_monitors()
    print("scheduled report '%s': %s" % install_report())
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
