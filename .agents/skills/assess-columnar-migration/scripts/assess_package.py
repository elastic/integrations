#!/usr/bin/env python3
"""Static columnar-migration assessment for Elastic integration packages.

Scans package field mappings (and stream manifests) for blockers, data-loss
risks, and degraded patterns. Does not modify packages or run elastic-package.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

BLOCKER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("store: true", re.compile(r"^\s*store:\s*true\s*$")),
    ("doc_values: false", re.compile(r"^\s*doc_values:\s*false\s*$")),
    ("copy_to", re.compile(r"^\s*copy_to:\s*")),
    ("type: runtime", re.compile(r"^\s*type:\s*runtime\s*$")),
    ("type: search_as_you_type", re.compile(r"^\s*type:\s*search_as_you_type\s*$")),
]

DATA_LOSS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dynamic: false", re.compile(r"^\s*dynamic:\s*false\s*$")),
    ("enabled: false", re.compile(r"^\s*enabled:\s*false\s*$")),
]

INFO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("type: text", re.compile(r"^\s*type:\s*text\s*$")),
    ("type: match_only_text", re.compile(r"^\s*type:\s*match_only_text\s*$")),
]

# ECS fields that commonly gain text / match_only_text subfields via the stack ECS template.
ECS_TEXT_HINTS = re.compile(
    r"(^message$|^error\.message$|\.name$|\.title$|\.description$|\.working_directory$)",
)

NAME_RE = re.compile(r"^(\s*)- name:\s*(\S.*?)\s*$")
EXTERNAL_ECS_RE = re.compile(r"^\s*-\s*external:\s*ecs\s*$")
EXTERNAL_NAME_RE = re.compile(r"^\s*name:\s*(\S+)\s*$")
TYPE_LINE_RE = re.compile(r"^type:\s*(\S+)", re.MULTILINE)
# Match top-level or under elasticsearch: (indented).
INDEX_MODE_RE = re.compile(r"^\s*index_mode:\s*[\"']?(\S+?)[\"']?\s*$", re.MULTILINE)
PACKAGE_TYPE_RE = re.compile(r"^type:\s*(\S+)\s*$", re.MULTILINE)

# Kibana saved-object field hints for index-sort seeds.
KIBANA_FIELD_RE = re.compile(
    r'"(?:fieldName|sourceField|field)"\s*:\s*"([^"]+)"',
)
SKIP_SORT_FIELDS = {
    "@timestamp",
    "_id",
    "_index",
    "event.ingested",
    "agent.id",
    "agent.version",
    "data_stream.dataset",
    "data_stream.namespace",
    "data_stream.type",
    "ecs.version",
}

MAX_LISTED_PER_KIND = 8


@dataclass
class Finding:
    severity: str  # blocker | data_loss | degraded | info
    kind: str
    path: Path
    line_no: int
    detail: str
    field_path: str | None = None


@dataclass
class StreamAssessment:
    name: str
    stream_type: str | None
    index_mode: str | None
    in_scope: bool
    skip_reason: str | None = None
    findings: list[Finding] = field(default_factory=list)
    ecs_imports: list[str] = field(default_factory=list)
    ecs_text_candidates: list[str] = field(default_factory=list)
    proposed_mode: str | None = None
    metrics_undecided: bool = False
    sort_seeds: list[tuple[str, int]] = field(default_factory=list)
    stream_verdict: str | None = None


@dataclass
class PackageAssessment:
    path: Path
    name: str
    package_type: str | None
    in_scope: bool
    skip_reason: str | None = None
    streams: list[StreamAssessment] = field(default_factory=list)
    kibana_sort_seeds: list[tuple[str, int]] = field(default_factory=list)


def field_yaml_files(stream_dir: Path) -> list[Path]:
    fields_dir = stream_dir / "fields"
    if not fields_dir.is_dir():
        return []
    return sorted(fields_dir.glob("*.yml")) + sorted(fields_dir.glob("*.yaml"))


def package_transform_field_files(package_root: Path) -> list[Path]:
    root = package_root / "elasticsearch"
    if not root.is_dir():
        return []
    return sorted(root.rglob("fields/*.yml")) + sorted(root.rglob("fields/*.yaml"))


def read_simple_yaml_key(text: str, key_pattern: re.Pattern[str]) -> str | None:
    match = key_pattern.search(text)
    return match.group(1) if match else None


def current_field_path(stack: list[tuple[int, str]]) -> str:
    return ".".join(name for _, name in stack if name != "nested")


def classify_doc_values_false(field_path: str | None) -> tuple[str, str]:
    """Return (kind, detail_suffix) for a doc_values: false hit."""
    if field_path in {"event.original", "original"} or (
        field_path and field_path.endswith(".event.original")
    ):
        return (
            "doc_values: false (event.original)",
            "ECS-style integrity field — usually packaged override; remediations differ from secrets",
        )
    if field_path:
        return ("doc_values: false", f"field `{field_path}`")
    return ("doc_values: false", "mapped field")


def scan_field_file(path: Path) -> list[Finding]:
    """Scan a fields YAML file, tracking dotted paths for nested / doc_values."""
    findings: list[Finding] = []
    # stack entries: (indent, name) for fields; nested markers use name="nested"
    stack: list[tuple[int, str]] = []
    nested_ancestors: list[tuple[int, str]] = []  # (indent, dotted path of nested field)

    lines = path.read_text(errors="replace").splitlines()
    for line_no, line in enumerate(lines, 1):
        name_match = NAME_RE.match(line)
        if name_match:
            indent = len(name_match.group(1))
            name = name_match.group(2).strip()
            while stack and stack[-1][0] >= indent:
                stack.pop()
            while nested_ancestors and nested_ancestors[-1][0] >= indent:
                nested_ancestors.pop()
            stack.append((indent, name))
            continue

        field_path = current_field_path(stack) or None

        nested_match = re.match(r"^(\s*)type:\s*nested\s*$", line)
        if nested_match:
            indent = len(nested_match.group(1))
            path_str = field_path or "(unknown)"
            # Single-level nested is valid; only nested-in-nested is a blocker.
            if nested_ancestors:
                parent = nested_ancestors[-1][1]
                findings.append(
                    Finding(
                        "blocker",
                        "nested-in-nested",
                        path,
                        line_no,
                        f"{parent} → {path_str}",
                        field_path=path_str,
                    ),
                )
            nested_ancestors.append((indent, path_str))
            continue

        for kind, pattern in BLOCKER_PATTERNS:
            if not pattern.match(line):
                continue
            if kind == "doc_values: false":
                kind, suffix = classify_doc_values_false(field_path)
                detail = f"{line.strip()} ({suffix})"
            else:
                detail = line.strip()
                if field_path:
                    detail = f"{detail} on `{field_path}`"
            findings.append(
                Finding("blocker", kind, path, line_no, detail, field_path=field_path),
            )

        for kind, pattern in DATA_LOSS_PATTERNS:
            if pattern.match(line):
                detail = line.strip()
                if field_path:
                    detail = f"{detail} on `{field_path}`"
                findings.append(
                    Finding("data_loss", kind, path, line_no, detail, field_path=field_path),
                )

        for kind, pattern in INFO_PATTERNS:
            if pattern.match(line):
                detail = line.strip()
                if field_path:
                    detail = f"{detail} on `{field_path}`"
                findings.append(
                    Finding("info", kind, path, line_no, detail, field_path=field_path),
                )

    return findings


def scan_manifest_data_loss(manifest_path: Path) -> list[Finding]:
    """Find dynamic/enabled: false under the stream manifest `elasticsearch:` block.

    Ignores Fleet stream `enabled: false` and other non-mapping keys.
    """
    if not manifest_path.is_file():
        return []
    findings: list[Finding] = []
    in_elasticsearch = False
    es_indent: int | None = None

    for line_no, line in enumerate(manifest_path.read_text(errors="replace").splitlines(), 1):
        es_header = re.match(r"^(\s*)elasticsearch:\s*$", line)
        if es_header:
            in_elasticsearch = True
            es_indent = len(es_header.group(1))
            continue

        if not in_elasticsearch or es_indent is None:
            continue

        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            indent = len(line) - len(line.lstrip(" "))
            if indent <= es_indent:
                in_elasticsearch = False
                es_indent = None
                continue

        for kind, pattern in DATA_LOSS_PATTERNS:
            if pattern.match(line):
                findings.append(
                    Finding(
                        "data_loss",
                        f"manifest/{kind}",
                        manifest_path,
                        line_no,
                        line.strip(),
                    ),
                )
    return findings


def parse_ecs_imports(path: Path) -> list[str]:
    names: list[str] = []
    expecting_name = False
    for line in path.read_text(errors="replace").splitlines():
        if EXTERNAL_ECS_RE.match(line):
            expecting_name = True
            continue
        if expecting_name:
            name_match = EXTERNAL_NAME_RE.match(line)
            if name_match:
                names.append(name_match.group(1))
                expecting_name = False
            elif line.strip() and not line.strip().startswith("#"):
                expecting_name = False
    return names


def harvest_kibana_fields(package_root: Path, limit: int = 15) -> list[tuple[str, int]]:
    kibana = package_root / "kibana"
    if not kibana.is_dir():
        return []
    counts: Counter[str] = Counter()
    for path in kibana.rglob("*.json"):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        # Prefer regex over full JSON parse — saved objects are large/nested.
        for match in KIBANA_FIELD_RE.finditer(text):
            name = match.group(1)
            if not name or name in SKIP_SORT_FIELDS or name.startswith("kibana."):
                continue
            if "*" in name or name.startswith("_"):
                continue
            counts[name] += 1
    return counts.most_common(limit)


def stream_counts(stream: StreamAssessment) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for finding in stream.findings:
        counts[finding.severity] += 1
    return counts


def verdict_for_stream(stream: StreamAssessment) -> str:
    if not stream.in_scope:
        return "out_of_scope"
    counts = stream_counts(stream)
    if counts.get("blocker", 0):
        return "defer_or_exclude"
    if stream.metrics_undecided:
        return "metrics_undecided"
    if counts.get("data_loss", 0) or counts.get("degraded", 0):
        return "migrate_with_changes"
    return "migrate_candidate"


def package_verdict_summary(pkg: PackageAssessment) -> str:
    if not pkg.in_scope:
        return "out_of_scope"
    scoped = [s for s in pkg.streams if s.in_scope]
    if not scoped:
        return "out_of_scope"

    by_verdict: dict[str, list[str]] = defaultdict(list)
    for stream in scoped:
        by_verdict[stream.stream_verdict or verdict_for_stream(stream)].append(stream.name)

    blocked = by_verdict.get("defer_or_exclude", [])
    undecided = by_verdict.get("metrics_undecided", [])
    with_changes = by_verdict.get("migrate_with_changes", [])
    candidates = by_verdict.get("migrate_candidate", [])
    cleanish = with_changes + candidates  # migratable streams

    if blocked and not cleanish and not undecided:
        return "defer_or_exclude"
    if blocked:
        blocked_list = ", ".join(blocked[:5])
        more = f" +{len(blocked) - 5}" if len(blocked) > 5 else ""
        return (
            f"migrate_with_changes ({len(cleanish)} migratable, "
            f"{len(blocked)} blocked: {blocked_list}{more}"
            f"{f', {len(undecided)} metrics_undecided' if undecided else ''})"
        )
    if with_changes:
        extra = f", {len(undecided)} metrics_undecided" if undecided else ""
        if candidates:
            return (
                f"migrate_with_changes ({len(with_changes)} with changes, "
                f"{len(candidates)} clean{extra})"
            )
        return f"migrate_with_changes{extra and ' (' + extra.lstrip(', ') + ')' or ''}"
    if undecided and not candidates:
        return f"metrics_undecided ({len(undecided)} streams)"
    if undecided:
        return f"migrate_candidate ({len(candidates)} clean, {len(undecided)} metrics_undecided)"
    return "migrate_candidate"


def verdict_sort_key(summary: str) -> int:
    if summary.startswith("defer_or_exclude"):
        return 0
    if summary.startswith("migrate_with_changes"):
        return 1
    if summary.startswith("metrics_undecided"):
        return 2
    if summary.startswith("migrate_candidate"):
        return 3
    return 4


def assess_stream(stream_dir: Path, package_sort_seeds: list[tuple[str, int]]) -> StreamAssessment:
    name = stream_dir.name
    manifest_path = stream_dir / "manifest.yml"
    stream_type = None
    index_mode = None
    manifest_findings: list[Finding] = []
    if manifest_path.is_file():
        text = manifest_path.read_text(errors="replace")
        stream_type = read_simple_yaml_key(text, TYPE_LINE_RE)
        index_mode = read_simple_yaml_key(text, INDEX_MODE_RE)
        manifest_findings = scan_manifest_data_loss(manifest_path)

    if index_mode == "time_series":
        stream = StreamAssessment(
            name=name,
            stream_type=stream_type,
            index_mode=index_mode,
            in_scope=False,
            skip_reason="TSDB (index_mode: time_series) — not columnar",
        )
        stream.stream_verdict = "out_of_scope"
        return stream

    findings: list[Finding] = list(manifest_findings)
    ecs_imports: list[str] = []
    for field_file in field_yaml_files(stream_dir):
        findings.extend(scan_field_file(field_file))
        if field_file.name in {"ecs.yml", "ecs.yaml"}:
            ecs_imports.extend(parse_ecs_imports(field_file))

    ecs_text = sorted({n for n in ecs_imports if ECS_TEXT_HINTS.search(n)})
    metrics_undecided = stream_type == "metrics"
    if stream_type == "logs" or stream_type is None:
        proposed_mode = "logsdb_columnar"
    elif metrics_undecided:
        proposed_mode = "columnar (or TSDB — undecided)"
    else:
        proposed_mode = "columnar"

    stream = StreamAssessment(
        name=name,
        stream_type=stream_type,
        index_mode=index_mode,
        in_scope=True,
        findings=findings,
        ecs_imports=sorted(set(ecs_imports)),
        ecs_text_candidates=ecs_text,
        proposed_mode=proposed_mode,
        metrics_undecided=metrics_undecided,
        sort_seeds=package_sort_seeds[:8],
    )
    stream.stream_verdict = verdict_for_stream(stream)
    return stream


def assess_package(package_root: Path) -> PackageAssessment:
    package_root = package_root.resolve()
    name = package_root.name
    manifest_path = package_root / "manifest.yml"
    package_type = None
    if manifest_path.is_file():
        package_type = read_simple_yaml_key(
            manifest_path.read_text(errors="replace"),
            PACKAGE_TYPE_RE,
        )

    if package_type == "content":
        return PackageAssessment(
            path=package_root,
            name=name,
            package_type=package_type,
            in_scope=False,
            skip_reason="content package — no data-stream mappings here",
        )

    if package_type not in {None, "integration", "input"}:
        return PackageAssessment(
            path=package_root,
            name=name,
            package_type=package_type,
            in_scope=False,
            skip_reason=f"package type {package_type!r} out of scope",
        )

    kibana_seeds = harvest_kibana_fields(package_root)

    streams_root = package_root / "data_stream"
    streams: list[StreamAssessment] = []
    if streams_root.is_dir():
        for stream_dir in sorted(p for p in streams_root.iterdir() if p.is_dir()):
            streams.append(assess_stream(stream_dir, kibana_seeds))

    transform_findings: list[Finding] = []
    for field_file in package_transform_field_files(package_root):
        for finding in scan_field_file(field_file):
            finding.kind = f"transform/{finding.kind}"
            finding.severity = "info"
            transform_findings.append(finding)

    if transform_findings:
        transform_stream = StreamAssessment(
            name="(elasticsearch/transform)",
            stream_type=None,
            index_mode=None,
            in_scope=False,
            skip_reason="transforms out of scope — findings for awareness only",
            findings=transform_findings,
        )
        transform_stream.stream_verdict = "out_of_scope"
        streams.append(transform_stream)

    in_scope = any(s.in_scope for s in streams) if streams else False
    skip_reason = None
    if not streams:
        skip_reason = "no data_stream/ directories found"
        in_scope = False
    elif not any(s.in_scope for s in streams):
        skip_reason = "no in-scope data streams (all TSDB/content/empty)"
        in_scope = False

    return PackageAssessment(
        path=package_root,
        name=name,
        package_type=package_type,
        in_scope=in_scope,
        skip_reason=skip_reason,
        streams=streams,
        kibana_sort_seeds=kibana_seeds,
    )


def rel_path(path: Path, package_root: Path) -> Path:
    try:
        return path.relative_to(package_root)
    except ValueError:
        return path


def format_findings_grouped(
    findings: list[Finding],
    package_root: Path,
    *,
    always_expand: bool = False,
) -> list[str]:
    """Group findings by kind; cap repetitive lists for mega-packages."""
    lines: list[str] = []
    by_kind: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_kind[finding.kind].append(finding)

    for kind in sorted(by_kind):
        items = by_kind[kind]
        lines.append(f"- **{kind}** ×{len(items)}")
        show = items if always_expand or len(items) <= MAX_LISTED_PER_KIND else items[:MAX_LISTED_PER_KIND]
        for finding in show:
            path = rel_path(finding.path, package_root)
            extra = f" — `{finding.detail}`" if finding.detail else ""
            lines.append(f"  - `{path}:{finding.line_no}`{extra}")
        if not always_expand and len(items) > MAX_LISTED_PER_KIND:
            lines.append(f"  - … +{len(items) - MAX_LISTED_PER_KIND} more")
    return lines


def format_package_report(pkg: PackageAssessment) -> str:
    lines: list[str] = []
    summary = package_verdict_summary(pkg)
    scoped = [s for s in pkg.streams if s.in_scope]
    skipped = [s for s in pkg.streams if not s.in_scope]

    lines.append(f"# Columnar assessment: {pkg.name}")
    lines.append("")
    lines.append(f"- Package path: `{pkg.path}`")
    lines.append(f"- Package type: `{pkg.package_type or 'unknown'}`")
    lines.append(f"- Verdict: `{summary}`")
    if pkg.skip_reason:
        lines.append(f"- Skip reason: {pkg.skip_reason}")

    if scoped:
        by_v: dict[str, list[str]] = defaultdict(list)
        for stream in scoped:
            by_v[stream.stream_verdict or "unknown"].append(stream.name)
        parts = [f"{v}={len(names)}" for v, names in sorted(by_v.items())]
        lines.append(f"- Stream verdicts: {', '.join(parts)}")
    if skipped:
        tsdb = [s.name for s in skipped if s.index_mode == "time_series"]
        other = [s.name for s in skipped if s.index_mode != "time_series"]
        if tsdb:
            lines.append(f"- Skipped TSDB: {len(tsdb)} stream(s)")
        if other:
            lines.append(f"- Skipped other: {', '.join(other)}")

    if pkg.kibana_sort_seeds:
        seeds = ", ".join(f"`{n}` ({c})" for n, c in pkg.kibana_sort_seeds[:10])
        lines.append(f"- Kibana field seeds (sort hints): {seeds}")
    lines.append("")

    if not pkg.streams:
        lines.append("No data streams found.")
        return "\n".join(lines) + "\n"

    lines.append("## Data streams")
    lines.append("")
    for stream in pkg.streams:
        status = "in scope" if stream.in_scope else "skipped"
        verdict = stream.stream_verdict or ("out_of_scope" if not stream.in_scope else "?")
        lines.append(f"### `{stream.name}` ({status}) — `{verdict}`")
        lines.append(f"- type: `{stream.stream_type or 'unknown'}`")
        lines.append(f"- index_mode: `{stream.index_mode or 'default'}`")
        if stream.skip_reason:
            lines.append(f"- reason: {stream.skip_reason}")
        if stream.in_scope:
            lines.append(f"- proposed mode: `{stream.proposed_mode}`")
            if stream.metrics_undecided:
                lines.append(
                    "- note: metrics stream without `time_series` — "
                    "prefer TSDB vs bare `columnar` is a product decision",
                )
        counts = stream_counts(stream)
        if counts:
            summary_counts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            lines.append(f"- findings: {summary_counts}")
        lines.append("")

        by_sev: dict[str, list[Finding]] = defaultdict(list)
        for finding in stream.findings:
            by_sev[finding.severity].append(finding)

        for severity, title, expand in (
            ("blocker", "Blockers", True),
            ("data_loss", "Data-loss risks", True),
            ("degraded", "Degraded / trade-offs", False),
            ("info", "Info", False),
        ):
            items = by_sev.get(severity, [])
            if not items:
                continue
            lines.append(f"**{title}**")
            lines.extend(format_findings_grouped(items, pkg.path, always_expand=expand))
            lines.append("")

        if stream.ecs_text_candidates:
            lines.append(
                f"**ECS text-subfield candidates (info)**: "
                f"{len(stream.ecs_text_candidates)} of {len(stream.ecs_imports)} imports",
            )
            preview = ", ".join(f"`{n}`" for n in stream.ecs_text_candidates[:15])
            more = ""
            if len(stream.ecs_text_candidates) > 15:
                more = f", … (+{len(stream.ecs_text_candidates) - 15} more)"
            lines.append(f"- {preview}{more}")
            lines.append("")

    lines.append("## Proposed changes (not applied)")
    lines.append("")
    lines.append(propose_changes(pkg))
    return "\n".join(lines) + "\n"


def propose_changes(pkg: PackageAssessment) -> str:
    if not pkg.in_scope:
        return f"- None — {pkg.skip_reason or 'package out of scope'}."

    bullets: list[str] = []
    scoped = [s for s in pkg.streams if s.in_scope]
    bullets.append(
        "- Raise package stack constraint to Elasticsearch / Kibana **9.5+** "
        "(columnar preview) when migration is attempted.",
    )

    blocked = [s for s in scoped if s.stream_verdict == "defer_or_exclude"]
    migratable = [
        s
        for s in scoped
        if s.stream_verdict in {"migrate_candidate", "migrate_with_changes"}
    ]
    undecided = [s for s in scoped if s.stream_verdict == "metrics_undecided"]

    if blocked:
        bullets.append(
            "- Resolve or **exclude** blocked streams (remaining streams can still migrate):",
        )
        for stream in blocked:
            kinds = sorted({f.kind for f in stream.findings if f.severity == "blocker"})
            bullets.append(f"  - `{stream.name}`: {', '.join(kinds)}")
            for finding in stream.findings:
                if finding.kind == "doc_values: false (event.original)":
                    bullets.append(
                        "    - `event.original`: ECS integrity packaging — drop "
                        "`doc_values: false` override, rely on `_source`, or exclude field",
                    )
                elif finding.kind == "doc_values: false":
                    bullets.append(
                        f"    - sensitive/custom field"
                        f"{f' `{finding.field_path}`' if finding.field_path else ''}: "
                        "remap for columnar or keep stream excluded",
                    )
                elif finding.kind == "store: true":
                    bullets.append(
                        "    - common metrics pattern: drop `store: true` or map as "
                        "`keyword` without store",
                    )
    else:
        bullets.append("- No hard mapping blockers on in-scope streams.")

    data_loss_streams = [
        s for s in scoped if any(f.severity == "data_loss" for f in s.findings)
    ]
    if data_loss_streams:
        names = ", ".join(f"`{s.name}`" for s in data_loss_streams)
        bullets.append(
            f"- Review **`dynamic: false` / `enabled: false`** on {names} "
            "(fields YAML and stream manifests): under columnar unmapped data is dropped.",
        )

    if undecided:
        names = ", ".join(f"`{s.name}`" for s in undecided)
        bullets.append(
            f"- Metrics without TSDB ({names}): decide **TSDB** vs bare **`columnar`** "
            "before enabling; do not assume columnar is preferred.",
        )

    if any(
        f.kind in {"type: text", "type: match_only_text"}
        for s in scoped
        for f in s.findings
    ) or any(s.ecs_text_candidates for s in scoped):
        bullets.append(
            "- Text / ECS multi-fields are an **info** trade-off (storage / full-text); "
            "they alone do not block migration. Optionally trim to `keyword` where "
            "dashboards only need exact match.",
        )

    sort_hint = ""
    if pkg.kibana_sort_seeds:
        top = ", ".join(f"`{n}`" for n, _ in pkg.kibana_sort_seeds[:5])
        sort_hint = f" Kibana seeds: {top}."

    for stream in migratable:
        mode = "logsdb_columnar" if stream.stream_type in {"logs", None} else "columnar"
        bullets.append(
            f"- `{stream.name}`: set `mode: {mode}` with **integration-specific index sort** "
            f"(not cluster `logs-*-*` templates).{sort_hint}",
        )
        if mode == "logsdb_columnar":
            bullets.append(
                "  - Use `host.name` + `@timestamp` only if host-centric; otherwise pick a "
                "low-cardinality dashboard filter dimension + `@timestamp`.",
            )

    bullets.append(
        "- **Out of scope for this skill (TODO/TBC):** apply the package edits, "
        "`elastic-package build`/system tests under columnar, dashboard/rule validation, "
        "changelog entry.",
    )
    return "\n".join(bullets)


def format_repo_summary(packages: list[PackageAssessment]) -> str:
    lines = [
        "# Columnar assessment summary",
        "",
        "| Package | Verdict | In-scope | Blocked streams | Data-loss | Degraded |",
        "| --- | --- | ---: | --- | ---: | ---: |",
    ]
    for pkg in sorted(packages, key=lambda p: (verdict_sort_key(package_verdict_summary(p)), p.name)):
        summary = package_verdict_summary(pkg)
        scoped = [s for s in pkg.streams if s.in_scope]
        blocked = [s.name for s in scoped if s.stream_verdict == "defer_or_exclude"]
        blocked_s = ", ".join(f"`{n}`" for n in blocked[:3])
        if len(blocked) > 3:
            blocked_s += f" +{len(blocked) - 3}"
        if not blocked_s:
            blocked_s = "—"
        data_loss = sum(stream_counts(s).get("data_loss", 0) for s in scoped)
        degraded = sum(stream_counts(s).get("degraded", 0) for s in scoped)
        # Truncate long verdicts for table readability
        verdict_cell = summary if len(summary) <= 80 else summary[:77] + "…"
        lines.append(
            f"| `{pkg.name}` | `{verdict_cell}` | {len(scoped)} | "
            f"{blocked_s} | {data_loss} | {degraded} |",
        )
    lines.append("")
    return "\n".join(lines)


def iter_package_roots(path: Path) -> list[Path]:
    path = path.resolve()
    if path.name == "packages" and path.is_dir():
        return sorted(
            p for p in path.iterdir() if p.is_dir() and (p / "manifest.yml").is_file()
        )
    if (path / "manifest.yml").is_file():
        return [path]
    packages = path / "packages"
    if packages.is_dir():
        return iter_package_roots(packages)
    raise FileNotFoundError(f"not a package or packages/ directory: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assess Elastic integration packages for columnar index mode migration.",
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Package path (packages/foo), packages/, or repo root",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="For multi-package scans, print only the summary table",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of markdown",
    )
    args = parser.parse_args()

    try:
        roots = iter_package_roots(args.path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    assessments = [assess_package(root) for root in roots]

    if args.json:
        payload = []
        for pkg in assessments:
            payload.append(
                {
                    "name": pkg.name,
                    "verdict": package_verdict_summary(pkg),
                    "in_scope": pkg.in_scope,
                    "kibana_sort_seeds": pkg.kibana_sort_seeds,
                    "streams": [
                        {
                            "name": s.name,
                            "in_scope": s.in_scope,
                            "verdict": s.stream_verdict,
                            "type": s.stream_type,
                            "index_mode": s.index_mode,
                            "proposed_mode": s.proposed_mode,
                            "metrics_undecided": s.metrics_undecided,
                            "findings": [
                                {
                                    "severity": f.severity,
                                    "kind": f.kind,
                                    "path": str(f.path),
                                    "line": f.line_no,
                                    "detail": f.detail,
                                    "field_path": f.field_path,
                                }
                                for f in s.findings
                            ],
                        }
                        for s in pkg.streams
                    ],
                },
            )
        json.dump(payload if len(payload) > 1 else payload[0], sys.stdout, indent=2)
        print()
        return 0

    if len(assessments) > 1:
        print(format_repo_summary(assessments), end="")
        if args.summary_only:
            return 0
        print("---\n")
        for pkg in assessments:
            if not pkg.in_scope and not any(s.findings for s in pkg.streams):
                continue
            print(format_package_report(pkg), end="")
            print("---\n")
        return 0

    print(format_package_report(assessments[0]), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
