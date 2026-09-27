#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyyaml>=6"]
# ///
"""Static columnar-migration assessment for Elastic integration packages.

Reports mapping blockers and data-loss risks per data stream, the stack floor
implied by `format_version`, columnar `_source` consumers (`JSON_EXTRACT` on
`_source`, Painless `params._source`), and how many prebuilt detection rules
query each stream. Does not modify packages or run elastic-package.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from columnar_lib import (
    Finding,
    Package,
    Rule,
    Stream,
    display_path,
    index_patterns_from_query,
    installs_on_8x,
    iter_package_roots,
    load_package,
    load_prebuilt_rules,
    pattern_streams,
    rule_streams,
    sde_root,
    spec_min_stack,
)

MAX_LISTED_PER_KIND = 8

# ES|QL JSON_EXTRACT(_source, "path") — case-insensitive, either quote style.
JSON_EXTRACT_SOURCE_RE = re.compile(r"""json_extract\s*\(\s*_source\s*,\s*(['"])(.*?)\1""", re.IGNORECASE | re.DOTALL)
PARAMS_SOURCE_RE = re.compile(r"""params\s*(?:\.\s*_source|\[\s*['"]_source['"]\s*\])""", re.IGNORECASE)
JSON_QUERY_RE = re.compile(r'"(?:query|esql)"\s*:\s*"((?:\\.|[^"\\])*)"', re.DOTALL)
JSON_NAME_RE = re.compile(r'"(?:name|title)"\s*:\s*"((?:\\.|[^"\\])*)"')
# Rules use `query = '''…'''`; hunting queries use `query = ['''…''', …]`.
TOML_QUERY_RE = re.compile(
    r"""^query\s*=\s*(\[.*?^\]|'''.*?'''|\"\"\".*?\"\"\"|"(?:\\.|[^"\\])*")""",
    re.DOTALL | re.MULTILINE,
)
TOML_STRING_RE = re.compile(r"""'''(.*?)'''|\"\"\"(.*?)\"\"\"|"((?:\\.|[^"\\])*)"|'([^'\n]*)'""", re.DOTALL)
TOML_NAME_RE = re.compile(r"^name\s*=\s*['\"](.+?)['\"]", re.MULTILINE)
SKIP_ASSET_DIRS = {"ingest_pipeline", "node_modules"}
VERDICT_ORDER = (
    "defer_or_exclude",
    "migrate_with_changes",
    "pending_platform",
    "metrics_undecided",
    "migrate_candidate",
    "out_of_scope",
)


@dataclass
class SourceConsumer:
    """A query or script that reads `_source` and can break under columnar."""

    kind: str  # json_extract | params_source
    origin: str  # package name, or "detection-rules"
    path: Path
    name: str
    line_no: int
    extract_paths: list[str] = field(default_factory=list)
    index_patterns: list[str] = field(default_factory=list)


@dataclass
class Report:
    pkg: Package
    consumers: list[SourceConsumer] = field(default_factory=list)
    rules: dict[str, Counter[str]] = field(default_factory=dict)  # stream -> language counts
    rule_count: int = 0


def stream_verdict(stream: Stream) -> str:
    if not stream.in_scope:
        return "out_of_scope"
    severities = {f.severity for f in stream.findings}
    if "blocker" in severities:
        return "defer_or_exclude"
    if stream.type == "metrics":
        return "metrics_undecided"
    if "data_loss" in severities:
        # Columnar drops unmapped fields today; whether it keeps them by GA is a platform decision.
        return "pending_platform"
    return "migrate_candidate"


def package_verdict(pkg: Package) -> str:
    """Headline verdict plus stream counts, so one blocked stream never hides the rest."""
    by_verdict: dict[str, list[Stream]] = defaultdict(list)
    for stream in pkg.in_scope_streams:
        by_verdict[stream_verdict(stream)].append(stream)
    if not by_verdict:
        return "out_of_scope"
    blocked = [s.name for s in by_verdict["defer_or_exclude"]]
    clean, pending = by_verdict["migrate_candidate"], by_verdict["pending_platform"]
    undecided = by_verdict["metrics_undecided"]

    if blocked:
        headline = "migrate_with_changes" if clean or pending else "defer_or_exclude"
    else:
        headline = "migrate_candidate" if clean else "pending_platform" if pending else "metrics_undecided"

    parts = []
    if clean:
        parts.append(f"{len(clean)} clean")
    if pending:
        parts.append(f"{len(pending)} pending_platform")
    if blocked:
        more = f" +{len(blocked) - 5}" if len(blocked) > 5 else ""
        parts.append(f"{len(blocked)} blocked: {', '.join(blocked[:5])}{more}")
    if undecided:
        loss = sum(1 for s in undecided if any(f.severity == "data_loss" for f in s.findings))
        parts.append(f"{len(undecided)} metrics_undecided" + (f", {loss} with data-loss" if loss else ""))
    if len(parts) == 1 and "data-loss" not in parts[0]:
        return headline
    return f"{headline} ({', '.join(parts)})"


def unescape_json_string(raw: str) -> str:
    try:
        return json.loads(f'"{raw}"')
    except json.JSONDecodeError:
        return raw


def asset_queries(path: Path, text: str) -> list[str]:
    """ES|QL query bodies in a saved object or TOML rule; the whole file when none are found."""
    if path.suffix == ".json":
        queries = [unescape_json_string(m.group(1)) for m in JSON_QUERY_RE.finditer(text)]
    else:
        queries = []
        for match in TOML_QUERY_RE.finditer(text):
            for string in TOML_STRING_RE.finditer(match.group(1)):
                triple_single, triple_double, basic, literal = string.groups()
                if basic is not None:
                    queries.append(unescape_json_string(basic))
                else:
                    queries.append(next(g for g in (triple_single, triple_double, literal) if g is not None))
    return queries or [text]


def json_extract_consumer(
    queries: list[str],
    *,
    origin: str,
    path: Path,
    name: str,
    line_no: int,
    index_patterns: list[str] | None = None,
) -> SourceConsumer | None:
    extract_paths: list[str] = []
    patterns = list(index_patterns or [])
    for query in queries:
        hits = [m.group(2) for m in JSON_EXTRACT_SOURCE_RE.finditer(query)]
        if not hits:
            continue
        extract_paths.extend(p for p in hits if p not in extract_paths)
        if index_patterns is None:
            patterns.extend(p for p in index_patterns_from_query(query) if p not in patterns)
    if not extract_paths:
        return None
    return SourceConsumer("json_extract", origin, path, name, line_no, extract_paths, patterns)


def consumers_in_file(path: Path, origin: str) -> list[SourceConsumer]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    if "_source" not in text:
        return []
    name_match = (JSON_NAME_RE if path.suffix == ".json" else TOML_NAME_RE).search(text)
    name = unescape_json_string(name_match.group(1)) if name_match else path.stem
    found: list[SourceConsumer] = []
    extract_at = text.lower().find("json_extract")
    consumer = json_extract_consumer(
        asset_queries(path, text),
        origin=origin,
        path=path,
        name=name,
        line_no=text.count("\n", 0, max(extract_at, 0)) + 1,
    )
    if consumer:
        found.append(consumer)
    params_match = PARAMS_SOURCE_RE.search(text)
    if params_match:
        found.append(
            SourceConsumer("params_source", origin, path, name, text.count("\n", 0, params_match.start()) + 1),
        )
    return found


def iter_asset_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_ASSET_DIRS]
        files.extend(Path(dirpath) / n for n in filenames if n.endswith(suffixes))
    return files


def find_detection_rules_root(explicit: Path | None) -> tuple[Path | None, str]:
    """The checkout to scan, plus a status line for the report."""
    env = os.environ.get("DETECTION_RULES_PATH")
    requested = [(explicit, "--detection-rules"), (Path(env) if env else None, "DETECTION_RULES_PATH")]
    warnings: list[str] = []
    for path, source in requested:
        if path is None:
            continue
        path = path.expanduser().resolve()
        if (path / "rules").is_dir():
            return path, f"Scanned detection-rules checkout `{path}` (`rules/`, `hunting/`)."
        warnings.append(f"{source} `{path}` has no `rules/` directory, ignored. ")
    sibling = Path(__file__).resolve().parents[4].parent / "detection-rules"
    if (sibling / "rules").is_dir():
        return sibling, "".join(warnings) + f"Scanned detection-rules checkout `{sibling}` (`rules/`, `hunting/`)."
    return None, "".join(warnings) + (
        f"detection-rules checkout not found (also looked at `{sibling}`). "
        "Hunting queries are not in this repo. Search `elastic/detection-rules` `rules/` and "
        "`hunting/` for `JSON_EXTRACT(_source` and attach each hit by its `FROM` index pattern."
    )


def collect_consumers(
    targets: list[Path],
    rules: list[Rule],
    detection_rules: Path | None,
) -> tuple[list[SourceConsumer], str]:
    """Package-owned assets, prebuilt rules, and a local detection-rules checkout."""
    consumers: list[SourceConsumer] = []
    for target in targets:
        if target.name == "security_detection_engine":
            continue
        for sub in ("kibana", "elasticsearch"):
            for path in iter_asset_files(target / sub, (".json", ".yml", ".yaml")):
                consumers.extend(consumers_in_file(path, target.name))
    for rule in rules:
        consumer = json_extract_consumer(
            [rule.query],
            origin="security_detection_engine",
            path=rule.path,
            name=rule.name,
            line_no=1,
            index_patterns=rule.index_patterns,
        )
        if consumer:
            consumers.append(consumer)
    rules_root, note = find_detection_rules_root(detection_rules)
    if rules_root is not None:
        for sub in ("rules", "hunting"):
            for path in iter_asset_files(rules_root / sub, (".toml",)):
                consumers.extend(consumers_in_file(path, "detection-rules"))
    return consumers, note


def consumer_streams(consumer: SourceConsumer, pkg: Package) -> list[str]:
    return list(dict.fromkeys(s for p in consumer.index_patterns for s in pattern_streams(p, pkg)))


def build_report(pkg: Package, consumers: list[SourceConsumer], rules: list[Rule]) -> Report:
    report = Report(pkg)
    seen: set[tuple[str, str]] = set()
    for consumer in consumers:
        if consumer.origin != pkg.name and not consumer_streams(consumer, pkg):
            continue
        key = (consumer.kind, consumer.name.strip().lower())
        if key not in seen:  # the same rule in the prebuilt snapshot and in detection-rules
            seen.add(key)
            report.consumers.append(consumer)
    for rule in rules:
        streams = rule_streams(rule, pkg)
        if streams:
            report.rule_count += 1
        for name in streams:
            report.rules.setdefault(name, Counter())[rule.language] += 1
    return report


def rel_path(path: Path, package_root: Path) -> Path:
    try:
        return path.relative_to(package_root)
    except ValueError:
        return path


def format_findings(findings: list[Finding], package_root: Path, *, expand: bool) -> list[str]:
    """Group findings by kind; cap repetitive lists for mega-packages."""
    by_kind: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_kind[finding.kind].append(finding)
    lines: list[str] = []
    for kind in sorted(by_kind):
        items = by_kind[kind]
        lines.append(f"- **{kind}** ×{len(items)}")
        shown = items if expand else items[:MAX_LISTED_PER_KIND]
        lines.extend(f"  - `{rel_path(f.path, package_root)}:{f.line}` — {f.detail}" for f in shown)
        if len(items) > len(shown):
            lines.append(f"  - … +{len(items) - len(shown)} more")
    return lines


def format_consumers(report: Report, note: str | None) -> list[str]:
    lines = [
        "## Columnar `_source` consumers",
        "",
        "These do not change stream verdicts. Rewrites are in the skill's `reference.md` "
        "(Columnar `_source`).",
        "",
    ]
    if not report.consumers:
        lines.append("- None in this package or in rules whose `FROM` names its datasets.")
    for consumer in report.consumers:
        streams = consumer_streams(consumer, report.pkg)
        stream_bit = f" — streams: {', '.join(f'`{s}`' for s in streams)}" if streams else ""
        if consumer.kind == "json_extract":
            patterns = ", ".join(f"`{p}`" for p in consumer.index_patterns) or "no `FROM` pattern"
            what = f"{patterns} — {', '.join(f'`{p}`' for p in consumer.extract_paths)}"
        else:
            what = "Painless `params._source`"
        lines.append(
            f"- **{consumer.name}** (`{consumer.origin}`){stream_bit} — {what} — `{display_path(consumer.path)}`",
        )
    if note:
        lines.append(f"- {note}")
    lines.append("")
    return lines


def format_package_report(report: Report, note: str | None) -> str:
    pkg = report.pkg
    lines = [
        f"# Columnar assessment: {pkg.name}",
        "",
        f"- Package type: `{pkg.type or 'unknown'}`",
        f"- format_version: `{pkg.format_version or 'unset'}` (minimum stack from spec: {spec_min_stack(pkg.format_version)})",
    ]
    if pkg.kibana_constraint:
        lines.append(f"- `conditions.kibana.version`: `{pkg.kibana_constraint}`")
    lines.append(f"- Verdict: `{package_verdict(pkg)}`")
    if pkg.skip_reason:
        lines.append(f"- Skip reason: {pkg.skip_reason}")
    if pkg.in_scope_streams:
        lines.append(
            f"- Prebuilt detection rules querying in-scope streams: {report.rule_count} "
            "(latest version per rule in `security_detection_engine`)",
        )
    if pkg.transforms:
        lines.append(f"- Transforms: {pkg.transforms} (out of scope)")
    lines.append("")
    lines.extend(format_consumers(report, note))

    if pkg.streams:
        lines.extend(["## Data streams", ""])
    skipped: dict[str, list[str]] = defaultdict(list)
    for stream in pkg.streams:
        if stream.skip_reason:
            skipped[stream.skip_reason].append(f"`{stream.name}`")
    for reason, names in skipped.items():
        lines.append(f"- `out_of_scope`, {reason}: {', '.join(names)}")
    if skipped:
        lines.append("")
    for stream in pkg.in_scope_streams:
        lines.append(f"### `{stream.name}` — `{stream_verdict(stream)}`")
        lines.append(f"- type: `{stream.type}`, dataset: `{stream.dataset}`, index_mode: `{stream.index_mode or 'unset'}`")
        lines.extend(f"- note: {note_}" for note_ in stream.notes)
        languages = report.rules.get(stream.name)
        if languages:
            by_language = ", ".join(f"{k}={v}" for k, v in languages.most_common())
            lines.append(f"- prebuilt detection rules: {sum(languages.values())} ({by_language})")
        lines.append("")
        for severity, title, expand in (
            ("blocker", "Blockers", True),
            ("data_loss", "Data-loss risks (pending platform decision)", True),
            ("info", "Info", False),
        ):
            items = [f for f in stream.findings if f.severity == severity]
            if items:
                lines.append(f"**{title}**")
                lines.extend(format_findings(items, pkg.path, expand=expand))
                lines.append("")
    return "\n".join(lines) + "\n"


def format_repo_summary(reports: list[Report], note: str | None) -> str:
    lines = [
        "# Columnar assessment summary",
        "",
        "| Package | Verdict | In-scope | Blocked streams | Data-loss | `_source` consumers | Rules |",
        "| --- | --- | ---: | --- | ---: | ---: | ---: |",
    ]

    def order(report: Report) -> tuple[int, str]:
        verdict = package_verdict(report.pkg)
        return next(i for i, v in enumerate(VERDICT_ORDER) if verdict.startswith(v)), report.pkg.name

    for report in sorted(reports, key=order):
        scoped = report.pkg.in_scope_streams
        blocked = [s.name for s in scoped if stream_verdict(s) == "defer_or_exclude"]
        blocked_cell = ", ".join(f"`{n}`" for n in blocked[:3]) + (f" +{len(blocked) - 3}" if len(blocked) > 3 else "")
        data_loss = sum(1 for s in scoped for f in s.findings if f.severity == "data_loss")
        verdict = package_verdict(report.pkg)
        verdict = verdict if len(verdict) <= 80 else verdict[:77] + "…"
        lines.append(
            f"| `{report.pkg.name}` | `{verdict}` | {len(scoped)} | {blocked_cell or '—'} | "
            f"{data_loss} | {len(report.consumers)} | {report.rule_count} |",
        )
    in_8x = sum(1 for r in reports if r.pkg.in_scope_streams and installs_on_8x(r.pkg.format_version))
    lines += [
        "",
        f"{in_8x} in-scope packages are still installable on 8.x. Columnar would move them to 9.5+.",
        "`_source` consumers do not change verdicts. Rules counts prebuilt detection rules "
        "that query the package's in-scope streams.",
    ]
    if note:
        lines.append(note)
    return "\n".join(lines) + "\n"


def report_json(report: Report) -> dict:
    data = asdict(report.pkg)
    data["verdict"] = package_verdict(report.pkg)
    data["spec_min_stack"] = spec_min_stack(report.pkg.format_version)
    data["rule_count"] = report.rule_count
    data["source_consumers"] = [asdict(c) for c in report.consumers]
    for stream_data, stream in zip(data["streams"], report.pkg.streams):
        del stream_data["declared_fields"]
        stream_data["verdict"] = stream_verdict(stream)
        stream_data["rule_languages"] = dict(report.rules.get(stream.name, {}))
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "paths",
        type=Path,
        nargs="+",
        help="Package paths (packages/foo) for full reports, or packages/ / the repo root for a summary table",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of markdown")
    parser.add_argument(
        "--detection-rules",
        type=Path,
        help="Local elastic/detection-rules checkout. Defaults to DETECTION_RULES_PATH or a sibling of this repo.",
    )
    args = parser.parse_args()

    roots: list[Path] = []
    summary = False
    for path in args.paths:
        try:
            found = iter_package_roots(path)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        summary |= found != [path.resolve()]
        roots.extend(found)

    sde = sde_root(roots)
    rules = load_prebuilt_rules(sde) if sde else []
    consumers, note = collect_consumers(roots, rules, args.detection_rules)
    reports = [build_report(load_package(root), consumers, rules) for root in roots]

    if args.json:
        payload = [report_json(r) for r in reports]
        json.dump(payload if len(payload) > 1 else payload[0], sys.stdout, indent=2, default=str)
        print()
    elif summary:
        print(format_repo_summary(reports, note), end="")
    else:
        print("\n".join(format_package_report(r, note) for r in reports), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
