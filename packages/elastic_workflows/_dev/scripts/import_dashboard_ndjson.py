"""Convert a Kibana saved-object NDJSON export into the integration dashboard JSON.

Usage:
    python import_dashboard_ndjson.py <path-to-ndjson>

The script:
  1. Reads the first line of the NDJSON (the dashboard saved object).
  2. Strips transient/user-specific fields (accessControl, created_at, updated_at,
     created_by, updated_by, version, managed, coreMigrationVersion).
  3. Re-IDs the object to match the integration's expected dashboard ID.
  4. Injects the adHocDataViews definition into every panel that references adhoc_wf
     but has an empty adHocDataViews block (Kibana strips these on export).
  5. Ensures duration format columns that use "duration" include fromUnit: milliseconds
     (Kibana omits this on export, causing it to default to seconds).
  6. Writes the cleaned JSON to kibana/dashboard/<DASHBOARD_ID>.json.
"""
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent.parent
DASHBOARD_OBJECT_ID = "elastic_workflows-8de4b190-2f1a-4c3b-b7a9-31b2c8d4e5f6"
_DASHBOARD_JSON = _PKG_ROOT / f"kibana/dashboard/{DASHBOARD_OBJECT_ID}.json"

ADHOC_WF = {
    "adhoc_wf": {
        "id": "adhoc_wf",
        "title": ".workflows-executions",
        "timeFieldName": "createdAt",
    }
}

TRANSIENT_KEYS = {
    "accessControl",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "version",
    "managed",
    "coreMigrationVersion",
}


def _refs_use_adhoc_wf(refs: list) -> bool:
    return any(r.get("id") == "adhoc_wf" for r in refs)


def inject_adhoc_dataviews(panel: dict) -> None:
    """Populate empty adHocDataViews blocks with the ADHOC_WF definition.

    Kibana strips adHocDataViews on export. We detect panels that reference
    adhoc_wf (via indexPatternId in layers OR via the references array) and
    re-inject the data view definition so the dashboard works on fresh install.
    """
    ec = panel.get("embeddableConfig", {})
    attrs = ec.get("attributes", {})
    state = attrs.get("state", {})

    refs = attrs.get("references", [])
    layers = (
        state.get("datasourceStates", {})
        .get("formBased", {})
        .get("layers", {})
    )
    uses_adhoc = _refs_use_adhoc_wf(refs) or any(
        layer.get("indexPatternId") == "adhoc_wf"
        for layer in layers.values()
    )

    if uses_adhoc and "adHocDataViews" in state and not state["adHocDataViews"]:
        state["adHocDataViews"] = ADHOC_WF


def fix_duration_formats(panel: dict) -> None:
    """Ensure duration-formatted columns on the 'duration' field include fromUnit.

    The underlying data stores duration in milliseconds, but Kibana's export
    omits fromUnit, causing it to default to seconds on re-import.
    """
    ec = panel.get("embeddableConfig", {})
    attrs = ec.get("attributes", {})
    state = attrs.get("state", {})
    layers = (
        state.get("datasourceStates", {})
        .get("formBased", {})
        .get("layers", {})
    )
    for layer in layers.values():
        for col in layer.get("columns", {}).values():
            fmt = col.get("params", {}).get("format", {})
            if (
                fmt.get("id") == "duration"
                and col.get("sourceField") == "duration"
                and "fromUnit" not in fmt.get("params", {})
            ):
                fmt.setdefault("params", {})["fromUnit"] = "milliseconds"


def convert(ndjson_path: str) -> None:
    with open(ndjson_path, "r") as f:
        raw = f.readline().strip()

    so = json.loads(raw)

    for key in TRANSIENT_KEYS:
        so.pop(key, None)

    so["id"] = DASHBOARD_OBJECT_ID

    panels = json.loads(so["attributes"]["panelsJSON"])
    for panel in panels:
        inject_adhoc_dataviews(panel)
        fix_duration_formats(panel)
    so["attributes"]["panelsJSON"] = json.dumps(panels)

    _DASHBOARD_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(_DASHBOARD_JSON, "w") as f:
        json.dump(so, f, indent=2)

    print(f"Wrote {_DASHBOARD_JSON}")
    print(f"Panels: {len(panels)}")
    print(f"References: {len(so.get('references', []))}")
    for p in panels:
        ec = p.get("embeddableConfig", {})
        title = ec.get("title") or ec.get("attributes", {}).get("title", "?")
        g = p["gridData"]
        print(f"  y:{g['y']:2d} x:{g['x']:2d} w:{g['w']:2d} - {title}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-ndjson>")
        sys.exit(1)
    convert(sys.argv[1])
