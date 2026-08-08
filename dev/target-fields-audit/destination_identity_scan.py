#!/usr/bin/env python3
"""
List integrations that reference destination.user or destination.host in ingest pipelines.

Produces a per-line CSV and a package-grouped Markdown review list for manual triage.
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

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import scan as sc  # noqa: E402
import manifest_util  # noqa: E402

RE_PIPELINE_ASSIGN = re.compile(
    r"(?i)(?:target_field|field|copy_from|rename|set)\s*:\s*([a-z0-9_.]+)",
)

# Match ECS destination identity paths (not related.*).
RE_DEST_USER = re.compile(r"destination\.user(?:\.|\b)", re.IGNORECASE)
RE_DEST_HOST = re.compile(r"destination\.(?:host|hostname)(?:\.|\b)", re.IGNORECASE)

MAX_PIPELINE_LINES = 80_000


@dataclass
class Hit:
    package: str
    data_stream: str
    dest_kind: str  # destination.user | destination.host
    file: str
    line: int
    field_path: str
    snippet: str


def parse_data_stream(rel_parts: list[str]) -> str:
    try:
        i = rel_parts.index("data_stream")
        if i + 1 < len(rel_parts):
            return rel_parts[i + 1]
    except ValueError:
        pass
    return ""


def classify_dest_kind(text: str) -> list[str]:
    hay = sc.line_for_prefix_search(text)
    kinds: list[str] = []
    if RE_DEST_USER.search(hay):
        kinds.append("destination.user")
    if RE_DEST_HOST.search(hay):
        kinds.append("destination.host")
    return kinds


def scan_pipeline_file(pkg: str, path: Path, rel: str) -> list[Hit]:
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
        if sc.should_skip_line(raw, False):
            continue
        line = sc.line_for_prefix_search(raw)
        kinds = classify_dest_kind(line)
        if not kinds:
            continue
        snippet = raw.strip()
        if len(snippet) > 240:
            snippet = snippet[:237] + "..."
        paths_found: set[str] = set()
        for m in RE_PIPELINE_ASSIGN.finditer(line):
            val = m.group(1)
            for k in kinds:
                if k == "destination.user" and RE_DEST_USER.search(val):
                    paths_found.add(val)
                elif k == "destination.host" and RE_DEST_HOST.search(val):
                    paths_found.add(val)
        if not paths_found:
            for k in kinds:
                hits.append(Hit(pkg, ds, k, rel, i, k, snippet))
        else:
            for val in sorted(paths_found):
                if RE_DEST_USER.search(val):
                    hits.append(Hit(pkg, ds, "destination.user", rel, i, val, snippet))
                if RE_DEST_HOST.search(val):
                    hits.append(Hit(pkg, ds, "destination.host", rel, i, val, snippet))
    return hits


def iter_pipeline_files(pkg_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for pattern in (
        "data_stream/**/elasticsearch/ingest_pipeline/*.yml",
        "data_stream/**/elasticsearch/ingest_pipeline/*.yaml",
    ):
        paths.extend(pkg_dir.glob(pattern))
    return paths


def git_head(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def write_csv(path: Path, hits: list[Hit]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            ["package", "data_stream", "dest_kind", "file", "line", "field_path", "snippet"]
        )
        for h in hits:
            w.writerow(
                [h.package, h.data_stream, h.dest_kind, h.file, h.line, h.field_path, h.snippet]
            )


def write_review_md(path: Path, hits: list[Hit], packages_scanned: int, filter_note: str, sha: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_pkg: dict[str, list[Hit]] = defaultdict(list)
    for h in hits:
        by_pkg[h.package].append(h)

    pkg_has_user: set[str] = set()
    pkg_has_host: set[str] = set()
    for h in hits:
        if h.dest_kind == "destination.user":
            pkg_has_user.add(h.package)
        else:
            pkg_has_host.add(h.package)

    lines: list[str] = [
        "# Destination identity review list",
        "",
        f"- **git HEAD:** `{sha}`",
        f"- **generated (UTC):** {ts}",
        f"- **integration packages scanned:** {packages_scanned}",
        f"- **packages with `destination.user` in pipeline:** {len(pkg_has_user)}",
        f"- **packages with `destination.host` / `destination.hostname` in pipeline:** {len(pkg_has_host)}",
        f"- **packages with either:** {len(by_pkg)}",
        f"- **evidence rows:** {len(hits)}",
        "",
    ]
    if filter_note:
        lines.append(f"- **filter:** {filter_note}")
        lines.append("")

    lines.extend(
        [
            "Use [`destination_identity_hits.csv`](destination_identity_hits.csv) for line-level evidence.",
            "",
            "## Package checklist (sorted A–Z)",
            "",
            "Review each integration: confirm whether `destination.user` / `destination.host`",
            "represents the **target** of the action (candidate for `user.target.*` / `host.target.*`)",
            "or only network/session context.",
            "",
            "| # | package | destination.user | destination.host | data_streams |",
            "| ---: | --- | :---: | :---: | --- |",
        ]
    )

    for idx, pkg in enumerate(sorted(by_pkg.keys()), start=1):
        ph = by_pkg[pkg]
        has_u = "yes" if pkg in pkg_has_user else ""
        has_h = "yes" if pkg in pkg_has_host else ""
        streams = ", ".join(sorted({h.data_stream for h in ph if h.data_stream}))
        lines.append(f"| {idx} | {pkg} | {has_u} | {has_h} | {streams} |")

    lines.append("")
    lines.append("## Per-package detail")
    lines.append("")

    for pkg in sorted(by_pkg.keys()):
        ph = sorted(by_pkg[pkg], key=lambda x: (x.data_stream, x.file, x.line))
        lines.append(f"### {pkg}")
        lines.append("")
        for h in ph:
            ds = h.data_stream or "(package-level)"
            lines.append(
                f"- **{h.dest_kind}** — `{h.field_path}` — `{h.file}:{h.line}` — data_stream: `{ds}`"
            )
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="List packages referencing destination.user or destination.host in pipelines"
    )
    ap.add_argument("--repo-root", type=Path, default=_SCRIPT_DIR.parents[1])
    ap.add_argument("--output-dir", type=Path, default=_SCRIPT_DIR / "out")
    ap.add_argument(
        "--security-only",
        action="store_true",
        help="Only packages with manifest category `security`",
    )
    args = ap.parse_args()

    repo = args.repo_root.resolve()
    packages = repo / "packages"
    if not packages.is_dir():
        print(f"error: {packages}", file=sys.stderr)
        return 1

    sec: set[str] | None = None
    if args.security_only:
        sec = manifest_util.security_package_names(packages)

    all_hits: list[Hit] = []
    scanned = 0
    for pkg_dir in sorted(packages.iterdir()):
        if not pkg_dir.is_dir():
            continue
        pkg = pkg_dir.name
        if sec is not None and pkg not in sec:
            continue
        scanned += 1
        for path in iter_pipeline_files(pkg_dir):
            rel = str(path.relative_to(repo)).replace("\\", "/")
            all_hits.extend(scan_pipeline_file(pkg, path, rel))

    dedup: dict[tuple[str, str, str, str, int], Hit] = {}
    for h in all_hits:
        k = (h.package, h.dest_kind, h.file, h.field_path, h.line)
        dedup[k] = h
    hits = sorted(
        dedup.values(),
        key=lambda x: (x.package, x.dest_kind, x.data_stream, x.file, x.line),
    )

    out = args.output_dir.resolve()
    csv_path = out / "destination_identity_hits.csv"
    md_path = out / "destination_identity_review.md"
    write_csv(csv_path, hits)

    filter_note = ""
    if args.security_only:
        filter_note = (
            "Only integrations whose root manifest lists the `security` category."
        )
    write_review_md(md_path, hits, scanned, filter_note, git_head(repo))

    print(f"packages scanned: {scanned}")
    print(f"packages with hits: {len({h.package for h in hits})}")
    print(f"rows -> {csv_path}")
    print(f"review -> {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
