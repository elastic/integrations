"""Build the corrected dashboard saved object JSON for the integration package.

All Lens column IDs use UUIDs to match the format Lens expects internally.
"""
import json
import uuid
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent.parent
# Saved object id must match the dashboard filename (see elastic-package lint).
DASHBOARD_OBJECT_ID = "elastic_workflows-8de4b190-2f1a-4c3b-b7a9-31b2c8d4e5f6"
_DASHBOARD_JSON = _PKG_ROOT / f"kibana/dashboard/{DASHBOARD_OBJECT_ID}.json"

adhoc_wf = {"adhoc_wf": {"id": "adhoc_wf", "title": ".workflows-executions", "timeFieldName": "createdAt"}}
wf_ref_inner = [{"type": "index-pattern", "id": "adhoc_wf", "name": "indexpattern-datasource-layer-layer1"}]
bq = {"query": "NOT isTestRun: true", "language": "kuery"}
bq_all = {"query": "", "language": "kuery"}
STATUS_FAILED_KQL = 'status: "failed" OR status: "timed_out"'
STATUS_COMPLETED_KQL = 'status: "completed"'
KQL_PROD_ONLY = "NOT isTestRun: true"
KQL_TEST_ONLY = "isTestRun: true"
KQL_COMPLETED_PROD = 'status: "completed" AND NOT isTestRun: true'
KQL_FAILURES_PROD = f"({STATUS_FAILED_KQL}) AND NOT isTestRun: true"


def uid():
    return str(uuid.uuid4())


def make_drilldown_config(label, url_template):
    return {
        "enhancements": {
            "dynamicActions": {
                "events": [
                    {
                        "eventId": uid(),
                        "triggers": ["VALUE_CLICK_TRIGGER"],
                        "action": {
                            "factoryId": "URL_DRILLDOWN",
                            "name": label,
                            "config": {
                                "url": {"template": url_template},
                                "openInNewTab": True,
                                "encodeUrl": True,
                            },
                        },
                    }
                ]
            }
        }
    }


def panel(pid, panel_type, x, y, w, h, ec, refs_inner):
    p = {
        "type": panel_type,
        "embeddableConfig": ec,
        "panelIndex": pid,
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
    }
    return p, [{"id": r["id"], "name": pid + ":" + r["name"], "type": r["type"]} for r in refs_inner]


def lens_ec(title, vis_type, columns, vis_config, query=None, adhoc=None, refs=None, extra_ec=None):
    if query is None:
        query = bq
    if adhoc is None:
        adhoc = adhoc_wf
    if refs is None:
        refs = wf_ref_inner
    ec = {
        "title": title,
        "attributes": {
            "title": title,
            "visualizationType": vis_type,
            "state": {
                "datasourceStates": {"formBased": {"layers": {"layer1": {
                    "columns": columns,
                    "columnOrder": list(columns.keys()),
                    "incompleteColumns": {},
                    "indexPatternId": list(adhoc.keys())[0],
                }}}},
                "visualization": vis_config,
                "query": query,
                "filters": [],
                "adHocDataViews": adhoc,
            },
            "references": refs,
        },
    }
    if extra_ec:
        ec.update(extra_ec)
    return ec


panels_list = []
all_refs = []


def add(pid, ptype, x, y, w, h, ec, refs=None):
    if refs is None:
        refs = wf_ref_inner
    p, r = panel(pid, ptype, x, y, w, h, ec, refs)
    panels_list.append(p)
    all_refs.extend(r)


# ============================================================
# ROW 1 (y:0) — KPI STRIP
# ============================================================
c1 = uid()
add("total-executions", "vis", 0, 0, 12, 8, lens_ec(
    "Total Executions", "lnsMetric",
    {c1: {"operationType": "count", "sourceField": "___records___", "label": "Executions", "dataType": "number", "isBucketed": False}},
    {"layerId": "layer1", "layerType": "data", "metricAccessor": c1},
))

# Success Rate — math(divide) with real tinymathAst (formula+math without AST renders empty)
c_completed = uid()
c_total = uid()
c_ratio = uid()
c_maxval = uid()
add("success-rate", "vis", 12, 0, 12, 8, lens_ec(
    "Success Rate", "lnsMetric",
    {
        c_completed: {
            "operationType": "count",
            "sourceField": "___records___",
            "label": "Completed",
            "dataType": "number",
            "isBucketed": False,
            "filter": {"query": STATUS_COMPLETED_KQL, "language": "kuery"},
        },
        c_total: {"operationType": "count", "sourceField": "___records___", "label": "Total", "dataType": "number", "isBucketed": False},
        c_ratio: {
            "operationType": "math",
            "label": "Success Rate",
            "dataType": "number",
            "isBucketed": False,
            "references": [c_completed, c_total],
            "customLabel": True,
            "params": {
                "tinymathAst": {
                    "type": "function",
                    "name": "divide",
                    "args": [c_completed, c_total],
                },
                "format": {"id": "percent", "params": {"decimals": 1}},
            },
        },
        c_maxval: {
            "operationType": "static_value",
            "label": "Static value: 1",
            "dataType": "number",
            "isBucketed": False,
            "isStaticValue": True,
            "scale": "ratio",
            "params": {"value": "1"},
            "references": [],
        },
    },
    {
        "layerId": "layer1",
        "layerType": "data",
        "metricAccessor": c_ratio,
        "maxAccessor": c_maxval,
        "showBar": True,
        "subtitle": " ",
        "palette": {
            "type": "palette",
            "name": "status",
            "params": {
                "name": "status",
                "reverse": False,
                "rangeType": "percent",
                "rangeMin": 0,
                "rangeMax": 100,
                "progression": "fixed",
                "stops": [
                    {"color": "#f66d64", "stop": 80},
                    {"color": "#fcd279", "stop": 95},
                    {"color": "#23be8f", "stop": 100},
                ],
                "steps": 3,
                "colorStops": [],
                "continuity": "all",
                "maxSteps": 5,
            },
        },
    },
))

c1 = uid()
add("avg-duration", "vis", 24, 0, 12, 8, lens_ec(
    "Avg Duration", "lnsMetric",
    {c1: {
        "operationType": "average", "sourceField": "duration", "label": "Avg Duration (ms)",
        "dataType": "number", "isBucketed": False,
        "params": {"format": {"id": "number", "params": {"decimals": 0, "suffix": " ms"}}},
    }},
    {"layerId": "layer1", "layerType": "data", "metricAccessor": c1},
))

c1 = uid()
add("failure-count", "vis", 36, 0, 12, 8, lens_ec(
    "Failures", "lnsMetric",
    {c1: {
        "operationType": "count", "sourceField": "___records___", "label": "Failures",
        "dataType": "number", "isBucketed": False,
        "filter": {"query": STATUS_FAILED_KQL, "language": "kuery"},
    }},
    {"layerId": "layer1", "layerType": "data", "metricAccessor": c1, "color": "#BD271E"},
))

# ============================================================
# ROW 2 (y:8) — EXECUTIONS OVER TIME + TRIGGER BREAKDOWN
# ============================================================
# Stacked bars: time on X, count on Y, one stack segment per workflow (top N by volume)
c_time, c_wf, c_count = uid(), uid(), uid()
add("executions-over-time", "vis", 0, 8, 32, 14, lens_ec(
    "Executions Over Time", "lnsXY",
    {
        c_time: {"operationType": "date_histogram", "sourceField": "createdAt", "label": "Time", "dataType": "date", "isBucketed": True, "params": {"interval": "auto"}},
        c_wf: {
            "operationType": "terms",
            "sourceField": "workflowId",
            "label": "Workflow",
            "dataType": "string",
            "isBucketed": True,
            "params": {"size": 15, "orderBy": {"type": "column", "columnId": c_count}, "orderDirection": "desc"},
        },
        c_count: {"operationType": "count", "sourceField": "___records___", "label": "Executions", "dataType": "number", "isBucketed": False},
    },
    {
        "layers": [{
            "layerId": "layer1",
            "layerType": "data",
            "seriesType": "bar_stacked",
            "xAccessor": c_time,
            "accessors": [c_count],
            "splitAccessors": [c_wf],
        }],
        "legend": {"isVisible": True, "position": "right"},
        "preferredSeriesType": "bar_stacked",
        "valueLabels": "hide",
        "yTitle": "Count",
    },
))

c_trigger, c_count = uid(), uid()
add("trigger-breakdown", "vis", 32, 8, 16, 14, lens_ec(
    "Trigger Breakdown", "lnsPie",
    {
        c_trigger: {"operationType": "terms", "sourceField": "triggeredBy", "label": "Triggered By", "dataType": "string", "isBucketed": True, "params": {"size": 10, "orderBy": {"type": "column", "columnId": c_count}, "orderDirection": "desc"}},
        c_count: {"operationType": "count", "sourceField": "___records___", "label": "Count", "dataType": "number", "isBucketed": False},
    },
    {
        "shape": "donut",
        "layers": [{"layerId": "layer1", "layerType": "data", "primaryGroups": [c_trigger], "metrics": [c_count]}],
        "legend": {"isVisible": True, "position": "right"},
    },
))

# ============================================================
# ROW 3 (y:22) — FAILURE RATE TREND (per Workflow) + DURATION DISTRIBUTION
# Use math(divide) + tinymathAst (formula+math without AST yields empty charts)
# ============================================================
c_time, c_wf, c_total, c_failed, c_fr = uid(), uid(), uid(), uid(), uid()
add("failure-rate-trend", "vis", 0, 22, 24, 14, lens_ec(
    "Failure Rate Trend (per Workflow)", "lnsXY",
    {
        c_time: {"operationType": "date_histogram", "sourceField": "createdAt", "label": "Time", "dataType": "date", "isBucketed": True, "params": {"interval": "auto"}},
        c_wf: {"operationType": "terms", "sourceField": "workflowId", "label": "Workflow", "dataType": "string", "isBucketed": True, "params": {"size": 10, "orderBy": {"type": "column", "columnId": c_total}, "orderDirection": "desc"}},
        c_total: {"operationType": "count", "sourceField": "___records___", "label": "Total", "dataType": "number", "isBucketed": False, "customLabel": True},
        c_failed: {
            "operationType": "count",
            "sourceField": "___records___",
            "label": "Failed",
            "dataType": "number",
            "isBucketed": False,
            "customLabel": True,
            "filter": {"query": STATUS_FAILED_KQL, "language": "kuery"},
        },
        c_fr: {
            "operationType": "math",
            "label": "Failure rate",
            "dataType": "number",
            "isBucketed": False,
            "references": [c_failed, c_total],
            "customLabel": True,
            "params": {
                "tinymathAst": {"type": "function", "name": "divide", "args": [c_failed, c_total]},
                "format": {"id": "percent", "params": {"decimals": 1}},
            },
        },
    },
    {
        "layers": [{"layerId": "layer1", "layerType": "data", "seriesType": "area", "xAccessor": c_time, "accessors": [c_fr], "splitAccessors": [c_wf], "yConfig": [{"forAccessor": c_fr, "axisMode": "left"}]}],
        "legend": {"isVisible": True, "position": "right"},
        "preferredSeriesType": "area", "valueLabels": "hide", "yTitle": "Failure Rate",
    },
))

c_time, c_fast, c_medium, c_slow, c_vslow = uid(), uid(), uid(), uid(), uid()
add("duration-distribution", "vis", 24, 22, 24, 14, lens_ec(
    "Duration Distribution", "lnsXY",
    {
        c_time: {"operationType": "date_histogram", "sourceField": "createdAt", "label": "Time", "dataType": "date", "isBucketed": True, "params": {"interval": "auto"}},
        c_fast: {"operationType": "count", "sourceField": "___records___", "label": "< 1s", "dataType": "number", "isBucketed": False, "filter": {"query": "duration < 1000", "language": "kuery"}, "customLabel": True},
        c_medium: {"operationType": "count", "sourceField": "___records___", "label": "1s - 5s", "dataType": "number", "isBucketed": False, "filter": {"query": "duration >= 1000 AND duration < 5000", "language": "kuery"}, "customLabel": True},
        c_slow: {"operationType": "count", "sourceField": "___records___", "label": "5s - 30s", "dataType": "number", "isBucketed": False, "filter": {"query": "duration >= 5000 AND duration < 30000", "language": "kuery"}, "customLabel": True},
        c_vslow: {"operationType": "count", "sourceField": "___records___", "label": "> 30s", "dataType": "number", "isBucketed": False, "filter": {"query": "duration >= 30000", "language": "kuery"}, "customLabel": True},
    },
    {
        "layers": [{
            "layerId": "layer1", "layerType": "data", "seriesType": "bar_stacked",
            "xAccessor": c_time, "accessors": [c_fast, c_medium, c_slow, c_vslow],
            "yConfig": [
                {"forAccessor": c_fast, "color": "#23be8f"},
                {"forAccessor": c_medium, "color": "#fcd279"},
                {"forAccessor": c_slow, "color": "#f5a623"},
                {"forAccessor": c_vslow, "color": "#BD271E"},
            ],
        }],
        "legend": {"isVisible": True, "position": "right"},
        "preferredSeriesType": "bar_stacked", "valueLabels": "hide", "yTitle": "Executions",
    },
))

# ============================================================
# ROW 4 (y:36) — DURATION OVER TIME (per Workflow) + STATUS + SLOWEST
# ============================================================
c_time, c_wf, c_avg = uid(), uid(), uid()
add("duration-over-time", "vis", 0, 36, 24, 14, lens_ec(
    "Avg Duration Over Time (per Workflow)", "lnsXY",
    {
        c_time: {"operationType": "date_histogram", "sourceField": "createdAt", "label": "Time", "dataType": "date", "isBucketed": True, "params": {"interval": "auto"}},
        c_wf: {"operationType": "terms", "sourceField": "workflowId", "label": "Workflow", "dataType": "string", "isBucketed": True, "params": {"size": 10, "orderBy": {"type": "column", "columnId": c_avg}, "orderDirection": "desc"}},
        c_avg: {"operationType": "average", "sourceField": "duration", "label": "Avg (ms)", "dataType": "number", "isBucketed": False, "params": {"format": {"id": "number", "params": {"decimals": 0}}}},
    },
    {
        "layers": [{"layerId": "layer1", "layerType": "data", "seriesType": "line", "xAccessor": c_time, "accessors": [c_avg], "splitAccessors": [c_wf]}],
        "legend": {"isVisible": True, "position": "right"},
        "preferredSeriesType": "line", "valueLabels": "hide", "yTitle": "Avg Duration (ms)",
    },
))

c_status, c_count = uid(), uid()
add("status-breakdown", "vis", 24, 36, 12, 14, lens_ec(
    "Status Breakdown", "lnsPie",
    {
        c_status: {"operationType": "terms", "sourceField": "status", "label": "Status", "dataType": "string", "isBucketed": True, "params": {"size": 10, "orderBy": {"type": "column", "columnId": c_count}, "orderDirection": "desc"}},
        c_count: {"operationType": "count", "sourceField": "___records___", "label": "Count", "dataType": "number", "isBucketed": False},
    },
    {
        "shape": "donut",
        "layers": [{"layerId": "layer1", "layerType": "data", "primaryGroups": [c_status], "metrics": [c_count]}],
        "legend": {"isVisible": True, "position": "right"},
    },
))

c_wf, c_p95, c_runs = uid(), uid(), uid()
add("slowest-workflows", "vis", 36, 36, 12, 14, lens_ec(
    "Slowest Workflows (p95)", "lnsDatatable",
    {
        c_wf: {
            "operationType": "terms",
            "sourceField": "workflowId",
            "label": "Workflow",
            "dataType": "string",
            "isBucketed": True,
            "customLabel": True,
            "params": {"size": 10, "orderBy": {"type": "column", "columnId": c_p95}, "orderDirection": "desc"},
        },
        c_p95: {
            "operationType": "percentile",
            "sourceField": "duration",
            "label": "p95 (ms)",
            "dataType": "number",
            "isBucketed": False,
            "customLabel": True,
            "params": {"percentile": 95, "format": {"id": "number", "params": {"decimals": 0}}},
        },
        c_runs: {
            "operationType": "count",
            "sourceField": "___records___",
            "label": "Runs",
            "dataType": "number",
            "isBucketed": False,
            "customLabel": True,
        },
    },
    {
        "layerId": "layer1", "layerType": "data",
        "columns": [
            {"columnId": c_wf},
            {"columnId": c_p95, "colorMode": "text", "palette": {
                "type": "palette", "name": "status",
                "params": {"name": "status", "reverse": True, "rangeType": "number", "rangeMin": 0, "rangeMax": None, "progression": "fixed", "stops": [{"color": "#23be8f", "stop": 1000}, {"color": "#fcd279", "stop": 5000}, {"color": "#f66d64", "stop": 30000}], "steps": 3, "continuity": "above"},
            }},
            {"columnId": c_runs},
        ],
    },
))

# ============================================================
# ROW 5 (y:50) — RECENT FAILURES (full width; Top Workflows merged into Per-Workflow Summary)
# ============================================================
c_wf, c_fail, c_last = uid(), uid(), uid()
add("recent-failures", "vis", 0, 50, 48, 16, lens_ec(
    "Recent Failures", "lnsDatatable",
    {
        c_wf: {
            "operationType": "terms",
            "sourceField": "workflowId",
            "label": "Workflow",
            "dataType": "string",
            "isBucketed": True,
            "customLabel": True,
            "params": {"size": 20, "orderBy": {"type": "column", "columnId": c_fail}, "orderDirection": "desc"},
        },
        c_fail: {
            "operationType": "count",
            "sourceField": "___records___",
            "label": "Failures",
            "dataType": "number",
            "isBucketed": False,
            "customLabel": True,
        },
        c_last: {
            "operationType": "last_value",
            "sourceField": "status",
            "label": "Last Status",
            "dataType": "string",
            "isBucketed": False,
            "customLabel": True,
            "params": {"sortField": "createdAt"},
        },
    },
    {
        "layerId": "layer1", "layerType": "data",
        "columns": [
            {"columnId": c_wf},
            {"columnId": c_fail},
            {"columnId": c_last},
        ],
    },
    query={"query": "(status: \"failed\" OR status: \"timed_out\") AND NOT isTestRun: true", "language": "kuery"},
    extra_ec=make_drilldown_config("View Workflow Executions", "/app/workflows/{{event.value}}?tab=executions"),
))

# ============================================================
# ROW 6 (y:66) — PER-WORKFLOW SUMMARY (executions, failures, success %, test runs, durations)
# Former "Top Workflows" columns merged here. Layer query empty for test-run counts; per-column KQL filters.
# ============================================================
c_wf = uid()
c_exec = uid()
c_failures = uid()
c_completed = uid()
c_success = uid()
c_test = uid()
c_avg = uid()
c_p95 = uid()
add(
    "per-workflow-summary",
    "vis",
    0,
    66,
    48,
    20,
    lens_ec(
        "Per-Workflow Summary",
        "lnsDatatable",
        {
            c_wf: {
                "operationType": "terms",
                "sourceField": "workflowId",
                "label": "Workflow",
                "dataType": "string",
                "isBucketed": True,
                "customLabel": True,
                "params": {
                    "size": 25,
                    "orderBy": {"type": "column", "columnId": c_exec},
                    "orderDirection": "desc",
                },
            },
            c_exec: {
                "operationType": "count",
                "sourceField": "___records___",
                "label": "Executions",
                "dataType": "number",
                "isBucketed": False,
                "customLabel": True,
                "filter": {"query": KQL_PROD_ONLY, "language": "kuery"},
            },
            c_failures: {
                "operationType": "count",
                "sourceField": "___records___",
                "label": "Failures",
                "dataType": "number",
                "isBucketed": False,
                "customLabel": True,
                "filter": {"query": KQL_FAILURES_PROD, "language": "kuery"},
            },
            c_completed: {
                "operationType": "count",
                "sourceField": "___records___",
                "label": "Completed",
                "dataType": "number",
                "isBucketed": False,
                "customLabel": True,
                "filter": {"query": KQL_COMPLETED_PROD, "language": "kuery"},
            },
            c_success: {
                "operationType": "math",
                "label": "Success %",
                "dataType": "number",
                "isBucketed": False,
                "references": [c_completed, c_exec],
                "customLabel": True,
                "params": {
                    "tinymathAst": {"type": "function", "name": "divide", "args": [c_completed, c_exec]},
                    "format": {"id": "percent", "params": {"decimals": 1}},
                },
            },
            c_test: {
                "operationType": "count",
                "sourceField": "___records___",
                "label": "Test runs",
                "dataType": "number",
                "isBucketed": False,
                "customLabel": True,
                "filter": {"query": KQL_TEST_ONLY, "language": "kuery"},
            },
            c_avg: {
                "operationType": "average",
                "sourceField": "duration",
                "label": "Avg Duration (ms)",
                "dataType": "number",
                "isBucketed": False,
                "customLabel": True,
                "filter": {"query": KQL_PROD_ONLY, "language": "kuery"},
                "params": {"format": {"id": "number", "params": {"decimals": 0}}},
            },
            c_p95: {
                "operationType": "percentile",
                "sourceField": "duration",
                "label": "p95 (ms)",
                "dataType": "number",
                "isBucketed": False,
                "customLabel": True,
                "filter": {"query": KQL_PROD_ONLY, "language": "kuery"},
                "params": {"percentile": 95, "format": {"id": "number", "params": {"decimals": 0}}},
            },
        },
        {
            "layerId": "layer1",
            "layerType": "data",
            "columns": [
                {"columnId": c_wf},
                {"columnId": c_exec},
                {
                    "columnId": c_failures,
                    "colorMode": "text",
                    "palette": {
                        "type": "palette",
                        "name": "status",
                        "params": {
                            "name": "status",
                            "reverse": True,
                            "rangeType": "number",
                            "rangeMin": 0,
                            "rangeMax": None,
                            "progression": "fixed",
                            "stops": [
                                {"color": "#23be8f", "stop": 1},
                                {"color": "#fcd279", "stop": 5},
                                {"color": "#f66d64", "stop": 20},
                            ],
                            "steps": 3,
                            "continuity": "above",
                        },
                    },
                },
                {
                    "columnId": c_success,
                    "colorMode": "text",
                    "palette": {
                        "type": "palette",
                        "name": "status",
                        "params": {
                            "name": "status",
                            "reverse": False,
                            "rangeType": "percent",
                            "rangeMin": 0,
                            "rangeMax": 100,
                            "progression": "fixed",
                            "stops": [
                                {"color": "#f66d64", "stop": 80},
                                {"color": "#fcd279", "stop": 95},
                                {"color": "#23be8f", "stop": 100},
                            ],
                            "steps": 3,
                            "continuity": "above",
                        },
                    },
                },
                {"columnId": c_test},
                {"columnId": c_avg},
                {
                    "columnId": c_p95,
                    "colorMode": "text",
                    "palette": {
                        "type": "palette",
                        "name": "status",
                        "params": {
                            "name": "status",
                            "reverse": True,
                            "rangeType": "number",
                            "rangeMin": 0,
                            "rangeMax": None,
                            "progression": "fixed",
                            "stops": [
                                {"color": "#23be8f", "stop": 1000},
                                {"color": "#fcd279", "stop": 5000},
                                {"color": "#f66d64", "stop": 30000},
                            ],
                            "steps": 3,
                            "continuity": "above",
                        },
                    },
                },
            ],
        },
        query=bq_all,
        extra_ec=make_drilldown_config("Open workflow", "/app/workflows/{{event.value}}"),
    ),
)

# ============================================================
# BUILD SAVED OBJECT
# ============================================================
so = {
    "attributes": {
        "description": "Comprehensive monitoring for Elastic Workflows. Per-workflow executions, failures, success rate, test runs, and durations; plus failure trends and performance analysis. Click workflow IDs in tables to open the workflow in Workflows.",
        "kibanaSavedObjectMeta": {"searchSourceJSON": "{}"},
        "optionsJSON": json.dumps({
            "hidePanelTitles": False,
            "hidePanelBorders": False,
            "useMargins": True,
            "autoApplyFilters": True,
            "syncColors": False,
            "syncCursor": True,
            "syncTooltips": False,
        }),
        "panelsJSON": json.dumps(panels_list),
        "pinned_panels": {"panels": {}},
        "refreshInterval": {"pause": False, "value": 30000},
        "timeFrom": "now-7d",
        "timeRestore": True,
        "timeTo": "now",
        "title": "[Elastic Workflows] Execution Overview",
    },
    "id": DASHBOARD_OBJECT_ID,
    "references": all_refs,
    "type": "dashboard",
    "typeMigrationVersion": "10.3.0",
}

output = _DASHBOARD_JSON
with open(output, "w") as f:
    json.dump(so, f, indent=2)

print("Wrote", output)
print("Panels:", len(panels_list))
print("References:", len(all_refs))
for p in panels_list:
    t = p["embeddableConfig"].get("title", "?")
    g = p["gridData"]
    has_dd = "enhancements" in p["embeddableConfig"]
    dd = " [DRILLDOWN]" if has_dd else ""
    print("  y:%2d w:%2d %s - %s%s" % (g["y"], g["w"], p["panelIndex"], t, dd))
