#!/usr/bin/env python3
"""
Scan Elastic integrations under packages/ for ECS-style *.target.* field references.

See SCOPE.md and OUTPUT.md in this directory.
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
import manifest_util  # noqa: E402

PREFIXES = (
    "host.target.",
    "user.target.",
    "service.target.",
    "entity.target.",
)


def classify_tier(rel_path: str) -> str | None:
    p = rel_path.replace("\\", "/")
    if "/elasticsearch/ingest_pipeline/" in p and (p.endswith(".yml") or p.endswith(".yaml")):
        return "A"
    if "/fields/" in p and p.endswith(".yml"):
        return "B"
    if "/kibana/" in p and p.endswith(".json"):
        return "C"
    return None


def parse_package_stream(rel_under_packages: str) -> tuple[str, str]:
    parts = rel_under_packages.split("/")
    package = parts[0] if parts else ""
    data_stream = ""
    try:
        i = parts.index("data_stream")
        if i + 1 < len(parts):
            data_stream = parts[i + 1]
    except ValueError:
        pass
    return package, data_stream


def line_for_prefix_search(line: str) -> str:
    """
    Drop typical YAML end-of-line comments (' <space># ...') so we do not count
    prefixes that appear only in comments (heuristic; not a full YAML lexer).
    """
    idx = line.find(" #")
    if idx != -1:
        return line[:idx]
    return line


def line_matches_prefixes(line: str) -> list[str]:
    hay = line_for_prefix_search(line)
    found: list[str] = []
    for pref in PREFIXES:
        if pref in hay:
            found.append(pref)
    return found


def should_skip_line(line: str, ignore_whole_line_comments: bool) -> bool:
    if not ignore_whole_line_comments:
        return False
    s = line.lstrip()
    return s.startswith("#")


def iter_scan_files(packages_dir: Path, only_packages: set[str] | None) -> list[Path]:
    files: list[Path] = []
    for pkg_dir in sorted(packages_dir.iterdir()):
        if not pkg_dir.is_dir():
            continue
        if only_packages is not None and pkg_dir.name not in only_packages:
            continue
        for path in pkg_dir.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(packages_dir.parent)
            except ValueError:
                continue
            rel_s = str(rel).replace("\\", "/")
            if not rel_s.startswith("packages/"):
                continue
            rel_under = rel_s[len("packages/") :]
            if classify_tier(rel_under) is None:
                continue
            files.append(path)
    return files


def scan(
    repo_root: Path,
    packages_dir: Path,
    only_packages: set[str] | None,
    ignore_whole_line_comments: bool,
    max_snippet: int,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    rel_repo = lambda p: str(p.relative_to(repo_root)).replace("\\", "/")

    for path in iter_scan_files(packages_dir, only_packages):
        rel_full = rel_repo(path)
        rel_under = rel_full[len("packages/") :]
        tier = classify_tier(rel_under)
        assert tier is not None
        package, data_stream = parse_package_stream(rel_under)

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"warn: skip read {rel_full}: {e}", file=sys.stderr)
            continue

        for lineno, line in enumerate(text.splitlines(), start=1):
            if should_skip_line(line, ignore_whole_line_comments):
                continue
            matches = line_matches_prefixes(line)
            if not matches:
                continue
            snippet = line.strip()
            if len(snippet) > max_snippet:
                snippet = snippet[: max_snippet - 3] + "..."
            for pref in matches:
                rows.append(
                    {
                        "tier": tier,
                        "package": package,
                        "data_stream": data_stream,
                        "file": rel_full,
                        "line": str(lineno),
                        "matched_prefix": pref,
                        "snippet": snippet,
                    }
                )
    rows.sort(key=lambda r: (r["package"], r["file"], int(r["line"]), r["matched_prefix"]))
    return rows


def git_head(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["tier", "package", "data_stream", "file", "line", "matched_prefix", "snippet"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def count_scanned_packages(packages_dir: Path, only_packages: set[str] | None) -> int:
    """Number of integration directories under packages/ included in this run."""
    dirs = [p for p in packages_dir.iterdir() if p.is_dir()]
    if only_packages is None:
        return len(dirs)
    return sum(1 for p in dirs if p.name in only_packages)


def package_confidence_short(tiers: set[str]) -> str:
    """Single-word label for table cells; see summary section 'Confidence labels'."""
    if "A" in tiers:
        return "high"
    if "B" in tiers:
        return "medium"
    return "low"


def tiers_compact(tiers: set[str]) -> str:
    return "+".join(t for t in ("A", "B", "C") if t in tiers)


def write_summary(
    path: Path,
    rows: list[dict[str, str]],
    repo_root: Path,
    packages_scanned: int,
    top_n: int,
    filter_note: str = "",
) -> None:
    sha = git_head(repo_root)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    packages_by_tier_prefix: dict[tuple[str, str], set[str]] = defaultdict(set)
    ds_tier_a: set[tuple[str, str]] = set()
    pkg_hits_a: dict[str, int] = defaultdict(int)
    pkg_hits_b: dict[str, int] = defaultdict(int)
    pkg_hits_c: dict[str, int] = defaultdict(int)
    pkg_tiers: dict[str, set[str]] = defaultdict(set)
    pkg_prefixes: dict[str, set[str]] = defaultdict(set)

    for r in rows:
        key = (r["tier"], r["matched_prefix"])
        packages_by_tier_prefix[key].add(r["package"])
        pkg_tiers[r["package"]].add(r["tier"])
        pkg_prefixes[r["package"]].add(r["matched_prefix"])
        if r["tier"] == "A":
            pkg_hits_a[r["package"]] += 1
            if r["data_stream"]:
                ds_tier_a.add((r["package"], r["data_stream"]))
        elif r["tier"] == "B":
            pkg_hits_b[r["package"]] += 1
        else:
            pkg_hits_c[r["package"]] += 1

    def md_table(headers: list[str], body_rows: list[list[str]]) -> str:
        lines = [
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
        ]
        for br in body_rows:
            lines.append("| " + " | ".join(br) + " |")
        return "\n".join(lines)

    uniq_pkg_any = sorted({r["package"] for r in rows})
    uniq_pkg_a = {r["package"] for r in rows if r["tier"] == "A"}

    def prefix_short(pref: str) -> str:
        return pref.removesuffix(".")

    lines_out: list[str] = [
        "# ECS `*.target.*` audit summary",
        "",
        f"- **git HEAD:** `{sha}`",
        f"- **generated (UTC):** {ts}",
        f"- **integration packages scanned:** {packages_scanned}",
        f"- **evidence rows (matches):** {len(rows)}",
        "",
    ]
    if filter_note:
        lines_out.append(f"- **filter:** {filter_note}")
        lines_out.append("")
    lines_out.extend(
        [
        "Prefixes scanned: `host.target.`, `user.target.`, `service.target.`, `entity.target.`",
        "",
        "## Confidence labels",
        "",
        "| Label | Meaning |",
        "| --- | --- |",
        "| **high** | At least one hit under **Tier A** (ingest pipeline YAML). Strongest signal that documents may receive these fields at ingest. |",
        "| **medium** | Hits only under **Tier B** (field YAML). Declared schema; not proof the pipeline populates it. |",
        "| **low** | Hits only under **Tier C** (Kibana JSON). Saved objects referencing field names; not ingest. |",
        "",
        "If a package has multiple tiers, the label reflects the **strongest** tier present.",
        "",
        "## Unique packages by tier and prefix",
        "",
        ]
    )

    for tier in ("A", "B", "C"):
        tier_name = {"A": "Pipeline", "B": "Fields", "C": "Kibana JSON"}[tier]
        lines_out.append(f"### Tier {tier} — {tier_name}")
        lines_out.append("")
        body: list[list[str]] = []
        for pref in PREFIXES:
            n = len(packages_by_tier_prefix.get((tier, pref), set()))
            body.append([pref, str(n)])
        lines_out.append(md_table(["matched_prefix", "unique_packages"], body))
        lines_out.append("")

    lines_out.append("## Tier A — unique (package, data_stream) pairs")
    lines_out.append("")
    lines_out.append(str(len(ds_tier_a)))
    lines_out.append("")

    lines_out.append("## Integrations with hits — full list")
    lines_out.append("")
    lines_out.append(
        "Every package under `packages/` that produced at least one evidence row, "
        "sorted by package name."
    )
    lines_out.append("")
    full_rows: list[list[str]] = []
    for pkg in uniq_pkg_any:
        tiers = pkg_tiers[pkg]
        prefs = sorted(pkg_prefixes[pkg], key=lambda p: PREFIXES.index(p) if p in PREFIXES else 99)
        pref_cell = ", ".join(prefix_short(p) for p in prefs)
        full_rows.append(
            [
                pkg,
                package_confidence_short(tiers),
                tiers_compact(tiers),
                str(pkg_hits_a[pkg]),
                str(pkg_hits_b[pkg]),
                str(pkg_hits_c[pkg]),
                pref_cell,
            ]
        )
    lines_out.append(
        md_table(
            [
                "package",
                "confidence",
                "tiers",
                "rows_A",
                "rows_B",
                "rows_C",
                "prefixes_seen",
            ],
            full_rows,
        )
    )
    lines_out.append("")

    if top_n > 0:
        lines_out.append(f"## Tier A — top {top_n} packages by evidence row count (optional quick view)")
        lines_out.append("")
        ranked = sorted(pkg_hits_a.items(), key=lambda x: (-x[1], x[0]))[:top_n]
        lines_out.append(md_table(["package", "tier_A_rows"], [[p, str(c)] for p, c in ranked if c > 0]))
        lines_out.append("")

    lines_out.append("## Totals")
    lines_out.append("")
    lines_out.append(f"- **integration packages scanned:** {packages_scanned}")
    lines_out.append(f"- **unique packages with any hit:** {len(uniq_pkg_any)}")
    lines_out.append(f"- **unique packages with Tier A hit:** {len(uniq_pkg_a)}")
    lines_out.append("")

    path.write_text("\n".join(lines_out), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="ECS *.target.* integration audit scanner")
    ap.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Repository root (parent of packages/)",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "out",
        help="Directory for CSV and summary",
    )
    ap.add_argument(
        "--only-packages",
        type=str,
        default="",
        help="Comma-separated package names for pilot runs (default: all under packages/)",
    )
    ap.add_argument(
        "--ignore-yaml-comments",
        action="store_true",
        help="Skip lines whose first non-space char is # (whole-line YAML comments only)",
    )
    ap.add_argument("--max-snippet", type=int, default=240)
    ap.add_argument(
        "--top-n",
        type=int,
        default=0,
        help="If > 0, append a 'top N by Tier A rows' section (default 0: full list only)",
    )
    ap.add_argument(
        "--security-only",
        action="store_true",
        help="Only include packages whose root manifest.yml lists category `security`",
    )
    args = ap.parse_args()

    repo_root = args.repo_root.resolve()
    packages_dir = repo_root / "packages"
    if not packages_dir.is_dir():
        print(f"error: missing packages dir: {packages_dir}", file=sys.stderr)
        return 1

    only: set[str] | None = None
    if args.only_packages.strip():
        only = {p.strip() for p in args.only_packages.split(",") if p.strip()}
    if args.security_only:
        sec = manifest_util.security_package_names(packages_dir)
        if only is not None:
            only = only & sec
        else:
            only = sec

    rows = scan(
        repo_root=repo_root,
        packages_dir=packages_dir,
        only_packages=only,
        ignore_whole_line_comments=args.ignore_yaml_comments,
        max_snippet=args.max_snippet,
    )

    out_dir = args.output_dir.resolve()
    csv_path = out_dir / "target_fields_audit.csv"
    md_path = out_dir / "target_fields_audit_summary.md"
    scanned = count_scanned_packages(packages_dir, only)
    write_csv(csv_path, rows)
    filter_note = ""
    if args.security_only:
        filter_note = (
            "Only integrations whose root `packages/<name>/manifest.yml` includes the "
            "`security` category (Elastic catalog tag)."
        )
    write_summary(
        md_path,
        rows,
        repo_root,
        packages_scanned=scanned,
        top_n=args.top_n,
        filter_note=filter_note,
    )

    print(f"Wrote {len(rows)} rows -> {csv_path}")
    print(f"Wrote summary -> {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
