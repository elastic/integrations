#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyyaml>=6"]
# ///
"""Index-sort inputs for migrating one integration to columnar.

Per in-scope data stream: whether `host.name` is declared (the `logsdb_columnar`
default sort), the fields its dashboard controls and panels use, and the fields
prebuilt detection rules require. Choosing the sort stays a judgment call; see
the skill's `reference.md` (Index sorting guidance). Blockers and verdicts come
from `assess_package.py`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

from columnar_lib import (
    Package,
    Stream,
    iter_package_roots,
    load_package,
    load_prebuilt_rules,
    names_dataset,
    rule_streams,
    sde_root,
)

# Field references in Kibana saved objects. Older exports embed panels as JSON
# strings (`panelsJSON`), so the quotes may be backslash-escaped. Fields that
# only appear in KQL filter strings or saved-search columns are not captured.
KIBANA_FIELD_RE = re.compile(r'\\*"(?:fieldName|sourceField|field|geoField)\\*"\s*:\s*\\*"([^"\\]+)\\*"')
# Saved-object types users query through; ML modules and index patterns are not.
QUERY_ASSET_DIRS = ("dashboard", "visualization", "lens", "search", "map")
# Constant per data stream or not sortable, so they say nothing about the sort.
SKIP_FIELDS = {
    "@timestamp",
    "event.ingested",
    "event.dataset",
    "event.module",
    "agent.version",
    "ecs.version",
}
MAX_FIELDS = 12


def keep_field(name: str) -> bool:
    return (
        bool(name)
        and name not in SKIP_FIELDS
        and "*" not in name
        and not name.startswith(("_", "kibana.", "data_stream."))
    )


def saved_object_units(text: str) -> tuple[str, list[str]]:
    """(dashboard-level part, panels). Non-dashboard objects are a single panel."""
    try:
        attributes = json.loads(text).get("attributes") or {}
    except (json.JSONDecodeError, AttributeError):
        return "", [text]
    panels = attributes.get("panelsJSON")
    if isinstance(panels, str):
        try:
            panels = json.loads(panels)
        except json.JSONDecodeError:
            panels = None
    if not isinstance(panels, list) or not panels:
        return "", [text]
    dashboard = json.dumps({k: v for k, v in attributes.items() if k != "panelsJSON"})
    return dashboard, [json.dumps(panel) for panel in panels]


def dashboard_fields(pkg: Package) -> tuple[dict[str, Counter[str]], dict[str, Counter[str]]]:
    """Per-stream field counts from dashboard controls/filters and from panels.

    A panel counts toward the streams whose dataset it names, else the stream
    its dashboard names if that is exactly one. Otherwise it counts only fields
    the stream declares. Controls follow the same rule at dashboard level.
    """
    streams = pkg.in_scope_streams
    controls: dict[str, Counter[str]] = {s.name: Counter() for s in streams}
    panels: dict[str, Counter[str]] = {s.name: Counter() for s in streams}

    def named(text: str) -> list[Stream]:
        return [s for s in streams if names_dataset(text, s.dataset)]

    def attribute(text: str, fallback: list[Stream], counts: dict[str, Counter[str]]) -> None:
        fields = [f for f in KIBANA_FIELD_RE.findall(text) if keep_field(f)]
        if not fields:
            return
        targets = named(text) or fallback
        for stream in streams:
            if stream in targets:
                counts[stream.name].update(fields)
            elif not targets:
                counts[stream.name].update(f for f in fields if f in stream.declared_fields)

    for sub in QUERY_ASSET_DIRS:
        for path in (pkg.path / "kibana" / sub).glob("*.json"):
            dashboard, units = saved_object_units(path.read_text(errors="replace"))
            dashboard_streams = named(dashboard)
            fallback = dashboard_streams if len(dashboard_streams) == 1 else []
            attribute(dashboard, [], controls)
            for unit in units:
                attribute(unit, fallback, panels)
    return controls, panels


def top(counts: Counter[str]) -> str:
    return ", ".join(f"`{n}` ({c})" for n, c in counts.most_common(MAX_FIELDS)) or "none"


def format_hints(
    pkg: Package,
    controls: dict[str, Counter[str]],
    panels: dict[str, Counter[str]],
    rules: dict[str, Counter[str]],
    languages: dict[str, Counter[str]],
) -> str:
    lines = [f"# Index-sort inputs: {pkg.name}", ""]
    if not pkg.in_scope_streams:
        lines.append(f"No in-scope streams ({pkg.skip_reason or 'all TSDB/OTel'}).")
        return "\n".join(lines) + "\n"
    skipped = [s.name for s in pkg.streams if not s.in_scope]
    lines += [
        "Dashboard controls/filters are the fields users slice by: the strongest sort signal. "
        "Panel fields count references per panel; a panel counts toward the streams whose dataset "
        "it names, else the one dataset its dashboard names, else only fields the stream declares. "
        "Rule fields come from `required_fields` of prebuilt rules; they include grouping keys and "
        "can miss filtered fields, so read the queries before calling a field a filter.",
        "",
    ]
    if skipped:
        lines += [f"Out of scope (see `assess_package.py`): {', '.join(f'`{n}`' for n in skipped)}", ""]
    for stream in pkg.in_scope_streams:
        lines.append(f"## `{stream.name}` (`{stream.type}`, dataset `{stream.dataset}`)")
        host = (
            "declared"
            if "host.name" in stream.declared_fields
            else "not declared (`logsdb_columnar` adds the mapping for its default sort)"
        )
        lines.append(f"- `host.name`: {host}")
        lines.append(f"- dashboard controls/filters: {top(controls[stream.name])}")
        lines.append(f"- dashboard panel fields: {top(panels[stream.name])}")
        if stream.name in rules:
            by_language = ", ".join(f"{k}={v}" for k, v in languages[stream.name].most_common())
            lines.append(
                f"- rule fields ({sum(languages[stream.name].values())} rules: {by_language}): {top(rules[stream.name])}",
            )
        else:
            lines.append("- rule fields: no prebuilt rules")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", type=Path, help="Package path (packages/foo)")
    args = parser.parse_args()
    try:
        roots = iter_package_roots(args.path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if len(roots) != 1:
        print("error: pass a single package; index sort is chosen per integration", file=sys.stderr)
        return 2

    pkg = load_package(roots[0])
    sde = sde_root(roots)
    rule_fields: dict[str, Counter[str]] = {}
    languages: dict[str, Counter[str]] = {}
    for rule in load_prebuilt_rules(sde) if sde else []:
        for name in rule_streams(rule, pkg):
            rule_fields.setdefault(name, Counter()).update(f for f in set(rule.fields) if keep_field(f))
            languages.setdefault(name, Counter())[rule.language] += 1
    controls, panels = dashboard_fields(pkg)
    print(format_hints(pkg, controls, panels, rule_fields, languages), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
