#!/usr/bin/env python3
"""
Per-integration scan for *target* semantics outside core ECS *.target.* fields.

Captures:
  - Vendor / integration namespaced dotted paths (e.g. okta.target, canva.audit.target.id)
  - Ingest pipeline references (target_field / field / copy_from) with "target" in the path
  - Pipeline test *expected.json keys when they look like dotted field paths with "target"

Does not fully parse all YAML shapes; focuses on Elastic integration conventions.
"""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import scan as sc  # noqa: E402
import manifest_util  # noqa: E402

# Pipeline: processor keys that carry dotted field paths.
RE_PIPELINE_ASSIGN = re.compile(
    r"(?i)(?:target_field|field|copy_from)\s*:\s*([a-z0-9_.]+)",
)

# Fully-qualified - name: in fields YAML (single-line path).
RE_FIELDS_FLAT_NAME = re.compile(
    r"(?i)^\s*-\s*name:\s*([a-z0-9_]+(?:\.[a-z0-9_]+)+)\s*(?:#|$)",
)

MAX_FIELDS_LINES = 50_000
MAX_JSON_BYTES = 350_000

MAX_PIPELINE_LINES = 80_000

# JSON: linear scan of quoted keys (avoid regex backtracking on huge fixtures).
RE_JSON_ANY_KEY = re.compile(r'"([A-Za-z0-9_.]{1,200})"\s*:')


def strip_yaml_line_comment(line: str) -> str:
    idx = line.find(" #")
    return line[:idx] if idx != -1 else line


def path_has_target_token(path: str) -> bool:
    p = path.lower()
    if "target" not in p:
        return False
    for seg in p.split("."):
        if "target" in seg:
            return True
    return False


def first_segment(path: str) -> str:
    return path.split(".", 1)[0].lower() if path else ""


def classify_namespace(pkg: str, path: str) -> str:
    fs = first_segment(path)
    if fs in (
        "source",
        "destination",
        "host",
        "user",
        "event",
        "process",
        "file",
        "registry",
        "threat",
        "dns",
        "url",
        "network",
        "client",
        "server",
        "observer",
        "ecs",
        "labels",
        "tags",
        "message",
        "log",
        "cloud",
        "organization",
        "orchestrator",
        "container",
        "kubernetes",
        "agent",
    ):
        return "ecs_top_level"
    if fs == pkg.replace("-", "_"):
        return "vendor_root"
    if path.lower().startswith(pkg.lower().replace("-", "_") + "."):
        return "vendor_namespaced"
    return "other_vendor_or_nested"


def suggest_bucket(path: str) -> str:
    pl = path.lower()
    if any(
        x in pl
        for x in (
            "user",
            "principal",
            "identity",
            "upn",
            "username",
            "actor",
            "impersonat",
        )
    ):
        return "likely_user_target_or_entity"
    if any(x in pl for x in ("host", "hostname", "device", "instance", "computer")):
        return "likely_host_target_or_entity"
    if any(x in pl for x in ("service", "application", "app_id", "bucket", "function")):
        return "likely_service_target_or_entity"
    return "entity_target_generic"


@dataclass
class Hit:
    package: str
    data_stream: str
    source: str  # fields_yml | ingest_pipeline | expected_json
    file: str
    line: int
    field_path: str
    namespace_class: str
    suggest_bucket: str


def parse_data_stream(rel_parts: list[str]) -> str:
    try:
        i = rel_parts.index("data_stream")
        if i + 1 < len(rel_parts):
            return rel_parts[i + 1]
    except ValueError:
        pass
    return ""


MAX_FIELDS_FILE_BYTES = 15_000_000


def fields_yml_hits(pkg: str, path: Path, rel: str) -> list[Hit]:
    """Stack-based path builder for common integration fields YAML."""
    hits: list[Hit] = []
    parts = rel.split("/")
    ds = parse_data_stream(parts)
    try:
        if path.stat().st_size > MAX_FIELDS_FILE_BYTES:
            return hits
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    if len(lines) > MAX_FIELDS_LINES:
        lines = lines[:MAX_FIELDS_LINES]

    stack: list[tuple[int, str]] = []

    for i, raw in enumerate(lines, start=1):
        line = strip_yaml_line_comment(raw)
        if not line.strip():
            continue
        mflat = RE_FIELDS_FLAT_NAME.match(line)
        if mflat:
            full = mflat.group(1)
            if path_has_target_token(full):
                nc = classify_namespace(pkg, full)
                hits.append(
                    Hit(
                        pkg,
                        ds,
                        "fields_yml_flat",
                        rel,
                        i,
                        full,
                        nc,
                        suggest_bucket(full),
                    )
                )
            continue

        m = re.match(r"^(\s*)-\s*name:\s*([^\s#]+?)\s*$", line)
        if not m:
            continue
        indent = len(m.group(1).replace("\t", "    "))
        name = m.group(2).strip()
        if not name or name == ".":
            continue

        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1] if stack else ""
        if parent:
            full = f"{parent}.{name}" if not name.startswith(".") else f"{parent}{name}"
        else:
            full = name
        stack.append((indent, full))

        if "." in full and path_has_target_token(full):
            nc = classify_namespace(pkg, full)
            hits.append(
                Hit(
                    pkg,
                    ds,
                    "fields_yml_nested",
                    rel,
                    i,
                    full,
                    nc,
                    suggest_bucket(full),
                )
            )
    return hits


def ingest_pipeline_hits(pkg: str, path: Path, rel: str) -> list[Hit]:
    hits: list[Hit] = []
    parts = rel.split("/")
    ds = parse_data_stream(parts)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    if len(lines) > MAX_PIPELINE_LINES:
        lines = lines[:MAX_PIPELINE_LINES]

    for i, raw in enumerate(lines, start=1):
        line = strip_yaml_line_comment(raw)
        if sc.should_skip_line(line, False):
            continue
        for m in RE_PIPELINE_ASSIGN.finditer(line):
            val = m.group(1)
            if "target" not in val.lower():
                continue
            nc = classify_namespace(pkg, val)
            hits.append(
                Hit(
                    pkg,
                    ds,
                    "ingest_pipeline",
                    rel,
                    i,
                    val,
                    nc,
                    suggest_bucket(val),
                )
            )
    return hits


def expected_json_hits(pkg: str, path: Path, rel: str) -> list[Hit]:
    hits: list[Hit] = []
    parts = rel.split("/")
    ds = parse_data_stream(parts)
    try:
        sz = path.stat().st_size
        n = min(sz, MAX_JSON_BYTES)
        raw = path.read_bytes()[:n].decode("utf-8", errors="replace")
    except OSError:
        return hits

    for m in RE_JSON_ANY_KEY.finditer(raw):
        key = m.group(1)
        if "target" not in key.lower():
            continue
        nc = classify_namespace(pkg, key)
        hits.append(
            Hit(
                pkg,
                ds,
                "expected_json",
                rel,
                0,
                key,
                nc,
                suggest_bucket(key),
            )
        )
    return hits


def git_head(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def iter_scan_paths(pkg_dir: Path) -> list[Path]:
    """Only paths that can contain field defs, pipelines, or pipeline tests."""
    paths: list[Path] = []
    globs = [
        "data_stream/**/fields/**/*.yml",
        "data_stream/**/elasticsearch/ingest_pipeline/*.yml",
        "data_stream/**/elasticsearch/ingest_pipeline/*.yaml",
        "data_stream/**/_dev/test/pipeline/*-expected.json",
        "data_stream/**/_dev/test/pipeline/*.log-expected.json",
        "fields/**/*.yml",
    ]
    for pattern in globs:
        paths.extend(pkg_dir.glob(pattern))
    return paths


def main() -> int:
    ap = argparse.ArgumentParser(description="Vendor / integration *target* field scan")
    ap.add_argument("--repo-root", type=Path, default=SCRIPT_DIR.parents[1])
    ap.add_argument("--output-dir", type=Path, default=SCRIPT_DIR / "out")
    ap.add_argument(
        "--security-only",
        action="store_true",
        help="Only include packages whose root manifest.yml lists category `security`",
    )
    args = ap.parse_args()

    repo = args.repo_root.resolve()
    packages = repo / "packages"
    if not packages.is_dir():
        print(f"error: {packages}", file=sys.stderr)
        return 1

    sec_set: set[str] | None = None
    if args.security_only:
        sec_set = manifest_util.security_package_names(packages)

    all_hits: list[Hit] = []
    packages_in_scope = 0
    for pkg_dir in sorted(packages.iterdir()):
        if not pkg_dir.is_dir():
            continue
        pkg = pkg_dir.name
        if sec_set is not None and pkg not in sec_set:
            continue
        packages_in_scope += 1
        for path in iter_scan_paths(pkg_dir):
            if not path.is_file():
                continue
            rel = str(path.relative_to(repo)).replace("\\", "/")
            if "/fields/" in rel and rel.endswith(".yml"):
                all_hits.extend(fields_yml_hits(pkg, path, rel))
            elif "/elasticsearch/ingest_pipeline/" in rel and rel.endswith((".yml", ".yaml")):
                all_hits.extend(ingest_pipeline_hits(pkg, path, rel))
            elif "/_dev/test/pipeline/" in rel and (
                rel.endswith("-expected.json") or rel.endswith(".log-expected.json")
            ):
                all_hits.extend(expected_json_hits(pkg, path, rel))

    # Dedupe identical (package, field_path, source file) keeping lowest line
    dedup: dict[tuple[str, str, str, str], Hit] = {}
    for h in all_hits:
        k = (h.package, h.field_path, h.source, h.file)
        if k not in dedup or (h.line and dedup[k].line and h.line < dedup[k].line):
            dedup[k] = h
    hits = sorted(dedup.values(), key=lambda x: (x.package, x.field_path, x.file, x.line))

    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "vendor_target_special_cases.csv"
    md_path = out_dir / "vendor_target_special_cases_report.md"

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "package",
                "data_stream",
                "source",
                "file",
                "line",
                "field_path",
                "namespace_class",
                "suggest_bucket",
            ]
        )
        for h in hits:
            w.writerow(
                [
                    h.package,
                    h.data_stream,
                    h.source,
                    h.file,
                    h.line,
                    h.field_path,
                    h.namespace_class,
                    h.suggest_bucket,
                ]
            )

    # Per-package summary
    pkg_fields: dict[str, set[str]] = defaultdict(set)
    pkg_sources: dict[str, set[str]] = defaultdict(set)
    for h in hits:
        pkg_fields[h.package].add(h.field_path)
        pkg_sources[h.package].add(h.source)

    pkgs_with_vendor = {
        p
        for p, paths in pkg_fields.items()
        for fp in paths
        if classify_namespace(p, fp) in ("vendor_root", "vendor_namespaced")
    }

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sha = git_head(repo)

    by_ns: dict[str, int] = defaultdict(int)
    for h in hits:
        by_ns[h.namespace_class] += 1

    md_head: list[str] = [
        "# Vendor / integration `*target*` special cases",
        "",
        f"- **git HEAD:** `{sha}`",
        f"- **generated (UTC):** {ts}",
        f"- **integration packages in scope:** {packages_in_scope}",
    ]
    if args.security_only:
        md_head.extend(
            [
                "- **filter:** Only integrations whose root `packages/<name>/manifest.yml` includes the `security` category.",
                "",
            ]
        )
    md_head.extend(
        [
            f"- **deduplicated field hits:** {len(hits)}",
            f"- **unique packages with any hit:** {len(pkg_fields)}",
            f"- **unique packages with vendor-namespaced `*target*` paths:** {len(pkgs_with_vendor)}",
            "",
            "## What was scanned",
            "",
            "| Surface | Scope |",
            "| --- | --- |",
            "| `fields/**/*.yml` | Flat `- name: a.b.target...` and nested `- name:` stack paths containing `target`. |",
            "| `elasticsearch/ingest_pipeline/*.{yml,yaml}` | `target_field`, `field`, `copy_from` values containing `target`. |",
            "| `*_dev/test/pipeline/*expected.json` | Quoted dotted JSON keys containing `target` (truncated read). |",
            "",
            "## Namespace classification",
            "",
            "| `namespace_class` | Meaning |",
            "| --- | --- |",
            "| `vendor_root` / `vendor_namespaced` | First path segment matches the integration package slug (e.g. `okta.target`). |",
            "| `ecs_top_level` | Starts with common ECS top-level field (e.g. `file.target_path`). |",
            "| `other_vendor_or_nested` | Other dotted paths (nested vendor, transforms, rare shapes). |",
            "",
            "## `suggest_bucket` (heuristic only)",
            "",
            "Keyword-based guess for runtime `CASE` prioritisation — **not** a product mapping decision.",
            "",
            "## Counts by namespace_class",
            "",
        ]
    )
    md = md_head
    for k in sorted(by_ns.keys(), key=lambda x: -by_ns[x]):
        md.append(f"- **{k}:** {by_ns[k]}")
    md.append("")
    md.append("## Machine-readable outputs")
    md.append("")
    md.append(f"- All hits: [`vendor_target_special_cases.csv`]({csv_path.name})")
    md.append(f"- Triage playbook: [`../VENDOR_TARGET_ANALYSIS_PLAN.md`](../VENDOR_TARGET_ANALYSIS_PLAN.md)")
    md.append("")
    md.append("## Packages with most distinct `field_path` values (top 25)")
    md.append("")
    ranked = sorted(pkg_fields.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:25]
    md.append("| package | distinct_field_paths |")
    md.append("| --- | ---: |")
    for p, s in ranked:
        md.append(f"| {p} | {len(s)} |")
    md_path.write_text("\n".join(md), encoding="utf-8")

    print(f"Wrote {len(hits)} hits -> {csv_path}")
    print(f"Wrote {md_path}")
    print(f"Packages with any hit: {len(pkg_fields)}, vendor-namespaced: {len(pkgs_with_vendor)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
