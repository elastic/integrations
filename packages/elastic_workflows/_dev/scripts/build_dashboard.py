"""Build the Elastic Workflows execution overview dashboard."""

import json
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent.parent
DASHBOARD_ID = "elastic_workflows-8de4b190-2f1a-4c3b-b7a9-31b2c8d4e5f6"
DASHBOARD_PATH = PACKAGE_ROOT / f"kibana/dashboard/{DASHBOARD_ID}.json"

INDEX = ".workflows-executions"
TIME_FIELD = "startedAt"
ESQL_DATA_VIEW_ID = "elastic-workflows-executions-esql"
# Production executions store isTestRun as null, not false.
IS_TEST_RUN = "COALESCE(isTestRun, false)"
RUN_TYPE = f'CASE({IS_TEST_RUN}, "test", "production")'
TIME_BUCKET = f"time_bucket = BUCKET({TIME_FIELD}, 50, ?_tstart, ?_tend)"
FAILED = 'status IN ("failed", "timed_out")'


def base_query() -> str:
    return (
        f"FROM {INDEX}\n"
        f"| WHERE {TIME_FIELD} >= ?_tstart AND {TIME_FIELD} < ?_tend\n"
        "| WHERE (?space_ids IS NULL OR spaceId IN (?space_ids)) "
        f"AND {RUN_TYPE} IN (?run_types)"
    )


DURATION_FORMAT = {
    "id": "duration",
    "params": {
        "decimals": 1,
        "fromUnit": "milliseconds",
        "toUnit": "humanizePrecise",
    },
}
PERCENT_FORMAT = {"id": "percent", "params": {"decimals": 1, "compact": True}}


def column(
    name: str,
    data_type: str,
    es_type: str,
    *,
    label: str | None = None,
    column_format: dict | None = None,
) -> dict:
    result = {
        "columnId": name,
        "fieldName": name,
        "label": label or name,
        "customLabel": label is not None,
        "meta": {"type": data_type, "esType": es_type},
    }
    if column_format is not None:
        result["params"] = {"format": column_format}
    if data_type == "number":
        result["inMetricDimension"] = True
    return result


TIME_COLUMN = column("time_bucket", "date", "date", label="Time")


def esql_data_view() -> dict:
    return {
        "id": ESQL_DATA_VIEW_ID,
        "title": INDEX,
        "timeFieldName": TIME_FIELD,
        "sourceFilters": [],
        "type": "esql",
        "fieldFormats": {},
        "runtimeFieldMap": {},
        "allowNoIndex": False,
        "name": INDEX,
        "allowHidden": True,
        "managed": False,
    }


def layer(query: str, columns: list[dict]) -> dict:
    return {
        "index": ESQL_DATA_VIEW_ID,
        "query": {"esql": query},
        "columns": columns,
        "timeField": TIME_FIELD,
    }


def lens_panel(
    panel_id: str,
    title: str,
    visualization_type: str,
    visualization: dict,
    layers: dict[str, dict],
    *,
    x: int,
    y: int,
    width: int,
    height: int,
    hide_title: bool = False,
    drilldowns: list[dict] | None = None,
) -> dict:
    main_query = next(iter(layers.values()))["query"]["esql"]
    embeddable_config: dict = {
        "title": title,
        "hide_title": hide_title,
        "attributes": {
            "title": title,
            "visualizationType": visualization_type,
            "references": [],
            "state": {
                "datasourceStates": {
                    "textBased": {
                        "layers": layers,
                        "indexPatternRefs": [
                            {
                                "id": ESQL_DATA_VIEW_ID,
                                "title": INDEX,
                                "timeField": TIME_FIELD,
                            }
                        ],
                    }
                },
                "filters": [],
                "internalReferences": [
                    {
                        "id": ESQL_DATA_VIEW_ID,
                        "name": f"indexpattern-datasource-layer-{layer_id}",
                        "type": "index-pattern",
                    }
                    for layer_id in layers
                ],
                "query": {"esql": main_query},
                "visualization": visualization,
                "adHocDataViews": {
                    ESQL_DATA_VIEW_ID: esql_data_view(),
                },
                "needsRefresh": False,
            },
            "version": 2,
        },
    }
    if drilldowns is not None:
        embeddable_config["drilldowns"] = drilldowns

    return {
        "type": "lens",
        "embeddableConfig": embeddable_config,
        "panelIndex": panel_id,
        "gridData": {
            "x": x,
            "y": y,
            "w": width,
            "h": height,
            "i": panel_id,
        },
    }


def metric_panel(
    panel_id: str,
    title: str,
    query: str,
    metric_column: dict,
    *,
    x: int,
    width: int,
    color: str | None = None,
    show_bar: bool = False,
    trend_query: str | None = None,
) -> dict:
    main_layer_id = f"{panel_id}-main"
    layers = {main_layer_id: layer(query, [metric_column])}
    visualization: dict = {
        "layerId": main_layer_id,
        "layerType": "data",
        "metricAccessor": metric_column["columnId"],
        "showBar": show_bar,
        "subtitle": "",
        "valueFontMode": "fit",
    }

    if color is not None:
        visualization["color"] = color
        visualization["applyColorTo"] = "background"

    if trend_query is not None:
        trend_layer_id = f"{panel_id}-trend"
        layers[trend_layer_id] = layer(trend_query, [metric_column, TIME_COLUMN])
        visualization.update(
            {
                "trendlineLayerId": trend_layer_id,
                "trendlineLayerType": "metricTrendline",
                "trendlineMetricAccessor": metric_column["columnId"],
                "trendlineTimeAccessor": "time_bucket",
            }
        )

    return lens_panel(
        panel_id,
        title,
        "lnsMetric",
        visualization,
        layers,
        x=x,
        y=0,
        width=width,
        height=8,
        hide_title=True,
    )


def xy_panel(
    panel_id: str,
    title: str,
    query: str,
    columns: list[dict],
    *,
    x: int,
    y: int,
    width: int,
    height: int,
    x_accessor: str,
    accessors: list[str],
    split_accessors: list[str] | None = None,
    series_type: str = "bar_stacked",
    y_config: list[dict] | None = None,
) -> dict:
    layer_id = f"{panel_id}-layer"
    visualization_layer: dict = {
        "layerId": layer_id,
        "accessors": accessors,
        "layerType": "data",
        "seriesType": series_type,
        "xAccessor": x_accessor,
    }
    if split_accessors:
        visualization_layer["splitAccessors"] = split_accessors
        visualization_layer["colorMapping"] = {
            "assignments": [],
            "specialAssignments": [
                {
                    "rules": [{"type": "other"}],
                    "color": {"type": "loop"},
                    "touched": False,
                }
            ],
            "paletteId": "elastic_line_optimized",
            "colorMode": {"type": "categorical"},
        }
    if y_config is not None:
        visualization_layer["yConfig"] = y_config

    visualization = {
        "preferredSeriesType": series_type,
        "legend": {"isVisible": False, "position": "bottom"},
        "layers": [visualization_layer],
        "axisTitlesVisibilitySettings": {
            "x": False,
            "yLeft": False,
            "yRight": False,
        },
        "tickLabelsVisibilitySettings": {
            "x": True,
            "yLeft": True,
            "yRight": True,
        },
        "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
        "gridlinesVisibilitySettings": {
            "x": True,
            "yLeft": True,
            "yRight": True,
        },
    }

    return lens_panel(
        panel_id,
        title,
        "lnsXY",
        visualization,
        {layer_id: layer(query, columns)},
        x=x,
        y=y,
        width=width,
        height=height,
    )


def treemap_panel(
    panel_id: str,
    title: str,
    query: str,
    group_column: dict,
    *,
    x: int,
    y: int,
    width: int,
    height: int,
) -> dict:
    layer_id = f"{panel_id}-layer"
    count_column = column("executions", "number", "long", label="Executions")
    visualization = {
        "shape": "treemap",
        "layers": [
            {
                "metrics": ["executions"],
                "primaryGroups": [group_column["columnId"]],
                "allowMultipleMetrics": False,
                "layerId": layer_id,
                "layerType": "data",
                "numberDisplay": "percent",
                "legendDisplay": "default",
                "collapseFns": {},
                "categoryDisplay": "default",
            }
        ],
    }
    return lens_panel(
        panel_id,
        title,
        "lnsPie",
        visualization,
        {layer_id: layer(query, [count_column, group_column])},
        x=x,
        y=y,
        width=width,
        height=height,
    )


def table_panel(
    panel_id: str,
    title: str,
    query: str,
    columns: list[dict],
    *,
    x: int,
    y: int,
    width: int,
    height: int,
    drilldown_url: str | None = None,
) -> dict:
    layer_id = f"{panel_id}-layer"
    visualization = {
        "layerId": layer_id,
        "layerType": "data",
        "columns": [
            {
                "columnId": item["columnId"],
                "isTransposed": False,
                "isMetric": item["meta"]["type"] == "number",
            }
            for item in columns
        ],
        "paging": {"enabled": True, "size": 20},
    }
    drilldowns = None
    if drilldown_url is not None:
        drilldowns = [
            {
                "label": "Open workflow",
                "encode_url": True,
                "open_in_new_tab": True,
                "trigger": "on_click_row",
                "type": "url_drilldown",
                "url": drilldown_url,
            }
        ]

    return lens_panel(
        panel_id,
        title,
        "lnsDatatable",
        visualization,
        {layer_id: layer(query, columns)},
        x=x,
        y=y,
        width=width,
        height=height,
        drilldowns=drilldowns,
    )


def build_panels() -> list[dict]:
    base = base_query()
    panels: list[dict] = []

    panels.append(
        metric_panel(
            "total-executions",
            "Total Executions",
            f"{base}\n| STATS executions = COUNT(*)",
            column("executions", "number", "long", label="Total Executions"),
            x=0,
            width=7,
        )
    )
    panels.append(
        metric_panel(
            "average-duration",
            "Avg Duration",
            f"{base}\n| STATS avg_duration_ms = AVG(duration)",
            column(
                "avg_duration_ms",
                "number",
                "double",
                label="Avg Duration",
                column_format=DURATION_FORMAT,
            ),
            x=7,
            width=7,
        )
    )
    panels.append(
        metric_panel(
            "slowest-execution",
            "Longest Execution",
            f"{base}\n| STATS max_duration_ms = MAX(duration)",
            column(
                "max_duration_ms",
                "number",
                "long",
                label="Longest Execution",
                column_format=DURATION_FORMAT,
            ),
            x=14,
            width=7,
        )
    )
    panels.append(
        metric_panel(
            "success-rate",
            "Success Rate",
            (
                f"{base}\n"
                '| STATS total = COUNT(*), completed = COUNT(*) WHERE status == "completed"\n'
                "| EVAL success_rate = CASE(total > 0, TO_DOUBLE(completed) / total, 0.0)\n"
                "| KEEP success_rate"
            ),
            column(
                "success_rate",
                "number",
                "double",
                label="Success Rate",
                column_format=PERCENT_FORMAT,
            ),
            x=21,
            width=9,
        )
    )
    panels.append(
        metric_panel(
            "timed-out-count",
            "Timed Out",
            f'{base}\n| WHERE status == "timed_out"\n| STATS timed_out = COUNT(*)',
            column("timed_out", "number", "long", label="Timed Out"),
            x=30,
            width=9,
            color="#FCD883",
            trend_query=(
                f'{base}\n| WHERE status == "timed_out"\n'
                f"| STATS timed_out = COUNT(*) BY {TIME_BUCKET}\n"
                "| SORT time_bucket"
            ),
        )
    )
    panels.append(
        metric_panel(
            "failure-count",
            "Failures",
            (f"{base}\n| WHERE {FAILED}\n| STATS failures = COUNT(*)"),
            column("failures", "number", "long", label="Failures"),
            x=39,
            width=9,
            color="#BD271E",
            trend_query=(
                f"{base}\n| WHERE {FAILED}\n"
                f"| STATS failures = COUNT(*) BY {TIME_BUCKET}\n"
                "| SORT time_bucket"
            ),
        )
    )

    panels.append(
        xy_panel(
            "executions-over-time",
            "Executions Over Time",
            (
                f"{base}\n"
                f"| STATS executions = COUNT(*) BY {TIME_BUCKET}, workflowId\n"
                "| SORT time_bucket\n"
                "| LIMIT 10000"
            ),
            [
                column("executions", "number", "long", label="Executions"),
                TIME_COLUMN,
                column("workflowId", "string", "keyword", label="Workflow"),
            ],
            x=0,
            y=8,
            width=32,
            height=14,
            x_accessor="time_bucket",
            accessors=["executions"],
            split_accessors=["workflowId"],
        )
    )
    panels.append(
        treemap_panel(
            "trigger-breakdown",
            "Trigger Breakdown",
            (
                f"{base}\n"
                "| STATS executions = COUNT(*) BY triggeredBy\n"
                "| SORT executions DESC\n"
                "| LIMIT 10"
            ),
            column("triggeredBy", "string", "keyword", label="Trigger"),
            x=32,
            y=8,
            width=16,
            height=14,
        )
    )
    panels.append(
        xy_panel(
            "failure-rate-by-workflow",
            "Failure Rate by Workflow",
            (
                f"{base}\n"
                f"| STATS total = COUNT(*), failures = COUNT(*) WHERE {FAILED} "
                f"BY {TIME_BUCKET}, workflowId\n"
                "| EVAL failure_rate = CASE(total > 0, TO_DOUBLE(failures) / total, 0.0)\n"
                "| KEEP time_bucket, workflowId, failure_rate\n"
                "| SORT time_bucket\n"
                "| LIMIT 10000"
            ),
            [
                TIME_COLUMN,
                column("workflowId", "string", "keyword", label="Workflow"),
                column(
                    "failure_rate",
                    "number",
                    "double",
                    label="Failure Rate",
                    column_format=PERCENT_FORMAT,
                ),
            ],
            x=0,
            y=22,
            width=24,
            height=14,
            x_accessor="time_bucket",
            accessors=["failure_rate"],
            split_accessors=["workflowId"],
        )
    )
    panels.append(
        xy_panel(
            "duration-distribution",
            "Duration Distribution",
            (
                f"{base}\n"
                "| STATS "
                "under_1s = COUNT(*) WHERE duration < 1000, "
                "between_1s_and_5s = COUNT(*) WHERE duration >= 1000 AND duration < 5000, "
                "between_5s_and_30s = COUNT(*) WHERE duration >= 5000 AND duration < 30000, "
                f"over_30s = COUNT(*) WHERE duration >= 30000 BY {TIME_BUCKET}\n"
                "| SORT time_bucket"
            ),
            [
                column("under_1s", "number", "long", label="< 1s"),
                column("between_1s_and_5s", "number", "long", label="1s - 5s"),
                column("between_5s_and_30s", "number", "long", label="5s - 30s"),
                column("over_30s", "number", "long", label="> 30s"),
                TIME_COLUMN,
            ],
            x=24,
            y=22,
            width=24,
            height=14,
            x_accessor="time_bucket",
            accessors=[
                "under_1s",
                "between_1s_and_5s",
                "between_5s_and_30s",
                "over_30s",
            ],
            y_config=[
                {"color": "#23be8f", "axisMode": "left", "forAccessor": "under_1s"},
                {
                    "color": "#fcd279",
                    "axisMode": "left",
                    "forAccessor": "between_1s_and_5s",
                },
                {
                    "color": "#f5a623",
                    "axisMode": "left",
                    "forAccessor": "between_5s_and_30s",
                },
                {"color": "#BD271E", "axisMode": "left", "forAccessor": "over_30s"},
            ],
        )
    )
    panels.append(
        xy_panel(
            "average-duration-by-workflow",
            "Avg Duration by Workflow",
            (
                f"{base}\n"
                f"| STATS avg_duration_ms = AVG(duration) BY {TIME_BUCKET}, workflowId\n"
                "| SORT time_bucket\n"
                "| LIMIT 10000"
            ),
            [
                column(
                    "avg_duration_ms",
                    "number",
                    "double",
                    label="Avg Duration",
                    column_format=DURATION_FORMAT,
                ),
                TIME_COLUMN,
                column("workflowId", "string", "keyword", label="Workflow"),
            ],
            x=0,
            y=36,
            width=24,
            height=14,
            x_accessor="time_bucket",
            accessors=["avg_duration_ms"],
            split_accessors=["workflowId"],
            series_type="line",
        )
    )
    panels.append(
        treemap_panel(
            "status-breakdown",
            "Status Breakdown",
            (
                f"{base}\n"
                "| STATS executions = COUNT(*) BY status\n"
                "| SORT executions DESC"
            ),
            column("status", "string", "keyword", label="Status"),
            x=24,
            y=36,
            width=12,
            height=14,
        )
    )
    panels.append(
        table_panel(
            "slowest-workflows",
            "Slowest Workflows",
            (
                f"{base}\n"
                "| STATS p95_duration_ms = PERCENTILE(duration, 95), runs = COUNT(*) BY workflowId\n"
                "| SORT p95_duration_ms DESC\n"
                "| LIMIT 10"
            ),
            [
                column(
                    "p95_duration_ms",
                    "number",
                    "double",
                    label="p95 Duration",
                    column_format=DURATION_FORMAT,
                ),
                column("runs", "number", "long", label="Runs"),
                column("workflowId", "string", "keyword", label="Workflow"),
            ],
            x=36,
            y=36,
            width=12,
            height=14,
        )
    )
    panels.append(
        table_panel(
            "recent-failures",
            "Recent Failures",
            (
                f"{base}\n| WHERE {FAILED}\n"
                f"| SORT {TIME_FIELD} DESC\n"
                f"| KEEP workflowId, status, {TIME_FIELD}, duration\n"
                "| LIMIT 20"
            ),
            [
                column("workflowId", "string", "keyword", label="Workflow"),
                column("status", "string", "keyword", label="Status"),
                column(TIME_FIELD, "date", "date", label="Started"),
                column(
                    "duration",
                    "number",
                    "long",
                    label="Duration",
                    column_format=DURATION_FORMAT,
                ),
            ],
            x=0,
            y=50,
            width=48,
            height=16,
            drilldown_url="{{kibanaUrl}}/app/workflows/{{event.values.[0]}}?tab=executions",
        )
    )
    panels.append(
        table_panel(
            "per-workflow-summary",
            "Per-Workflow Summary",
            (
                f"{base}\n"
                "| STATS "
                "executions = COUNT(*), "
                f"failures = COUNT(*) WHERE {FAILED}, "
                'completed = COUNT(*) WHERE status == "completed", '
                "avg_duration_ms = AVG(duration), "
                "p95_duration_ms = PERCENTILE(duration, 95) "
                "BY workflowId\n"
                "| EVAL success_rate = CASE(executions > 0, TO_DOUBLE(completed) / executions, 0.0)\n"
                "| KEEP workflowId, executions, failures, completed, success_rate, avg_duration_ms, p95_duration_ms\n"
                "| SORT executions DESC\n"
                "| LIMIT 25"
            ),
            [
                column("workflowId", "string", "keyword", label="Workflow"),
                column("executions", "number", "long", label="Executions"),
                column("failures", "number", "long", label="Failures"),
                column("completed", "number", "long", label="Completed"),
                column(
                    "success_rate",
                    "number",
                    "double",
                    label="Success Rate",
                    column_format=PERCENT_FORMAT,
                ),
                column(
                    "avg_duration_ms",
                    "number",
                    "double",
                    label="Avg Duration",
                    column_format=DURATION_FORMAT,
                ),
                column(
                    "p95_duration_ms",
                    "number",
                    "double",
                    label="p95 Duration",
                    column_format=DURATION_FORMAT,
                ),
            ],
            x=0,
            y=66,
            width=48,
            height=16,
            drilldown_url="{{kibanaUrl}}/app/workflows/{{event.values.[0]}}",
        )
    )
    return panels


def control_group_input() -> dict:
    time_filter = (
        f"FROM {INDEX}\n| WHERE {TIME_FIELD} >= ?_tstart AND {TIME_FIELD} < ?_tend"
    )
    controls = {
        "run-type-control": {
            "order": 0,
            "width": "medium",
            "type": "esqlControl",
            "explicitInput": {
                "id": "run-type-control",
                "title": "Run type",
                "enhancements": {},
                "selected_options": ["production"],
                "single_select": False,
                "variable_name": "run_types",
                "variable_type": "values",
                "esql_query": (
                    f"{time_filter}\n| EVAL run_type = {RUN_TYPE}\n"
                    "| STATS BY run_type\n| SORT run_type"
                ),
                "control_type": "VALUES_FROM_QUERY",
                "available_options": [],
            },
        },
        "space-control": {
            "order": 1,
            "width": "medium",
            "type": "esqlControl",
            "explicitInput": {
                "id": "space-control",
                "title": "Space",
                "enhancements": {},
                "selected_options": [],
                "single_select": False,
                "variable_name": "space_ids",
                "variable_type": "values",
                "esql_query": f"{time_filter}\n| STATS BY spaceId\n| SORT spaceId",
                "control_type": "VALUES_FROM_QUERY",
                "available_options": [],
            },
        },
    }
    return {"panelsJSON": json.dumps(controls, separators=(",", ":"))}


def build_dashboard() -> dict:
    return {
        "attributes": {
            "description": (
                "Monitor Elastic Workflows executions, failures, success rates, "
                "and duration with ES|QL."
            ),
            "controlGroupInput": control_group_input(),
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": '{"query":{"query":"","language":"kuery"}}'
            },
            "optionsJSON": json.dumps(
                {
                    "hidePanelTitles": False,
                    "hidePanelBorders": False,
                    "useMargins": True,
                    "autoApplyFilters": True,
                    "syncColors": False,
                    "syncCursor": True,
                    "syncTooltips": False,
                },
                separators=(",", ":"),
            ),
            "panelsJSON": json.dumps(build_panels(), separators=(",", ":")),
            "refreshInterval": {"pause": True, "value": 30000},
            "timeFrom": "now-7d/d",
            "timeRestore": True,
            "timeTo": "now",
            "title": "[Elastic Workflows] Execution Overview",
        },
        "id": DASHBOARD_ID,
        "references": [],
        "type": "dashboard",
        "typeMigrationVersion": "10.3.0",
    }


def main() -> None:
    dashboard = build_dashboard()
    DASHBOARD_PATH.parent.mkdir(parents=True, exist_ok=True)
    DASHBOARD_PATH.write_text(f"{json.dumps(dashboard, indent=2)}\n")
    print(f"Wrote {DASHBOARD_PATH}")


if __name__ == "__main__":
    main()
