#!/usr/bin/env python3
"""
Generate a report of Elastic Agent input types for integrations owned by the
obs-infraobs-integrations GitHub team.

Usage:
    python3 scripts/generate_obs_infraobs_report.py [--output PATH]

The script reads .github/CODEOWNERS to identify packages (and per-package
data_stream overrides) owned exclusively by @elastic/obs-infraobs-integrations,
then for every matching data stream it reads:
  - packages/<pkg>/data_stream/<ds>/manifest.yml  → streams[].input
  - packages/<pkg>/data_stream/<ds>/agent/stream/*.yml.hbs  → filename stem

The resulting table is written to docs/obs-infraobs-integrations-input-types.md
(or the path supplied via --output).
"""

import argparse
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required. Install it with:  pip install pyyaml", file=sys.stderr)
    sys.exit(1)

TEAM = "@elastic/obs-infraobs-integrations"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_codeowners(codeowners_path: Path):
    """Return two structures built from CODEOWNERS:

    owned_packages  – set of package names wholly owned by TEAM (i.e. the
                      /packages/<pkg>  line lists TEAM and TEAM only, or TEAM
                      is one of several owners — we include both cases since
                      the question asks for packages *owned by* the team).

    ds_overrides    – dict mapping (pkg, datastream) → list[owner] for lines
                      that explicitly override ownership at the data_stream level.
    """
    owned_packages: set[str] = set()
    ds_overrides: dict[tuple[str, str], list[str]] = {}

    pkg_re = re.compile(r"^/packages/([^/\s]+)\s+(.+)$")
    ds_re = re.compile(r"^/packages/([^/\s]+)/data_stream/([^/\s]+)\s+(.+)$")

    with codeowners_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # data_stream-level override
            m = ds_re.match(line)
            if m:
                pkg, ds, owners_str = m.group(1), m.group(2), m.group(3)
                owners = owners_str.split()
                ds_overrides[(pkg, ds)] = owners
                continue

            # package-level entry (skip sub-paths like /changelog.yml, /kibana …)
            m = pkg_re.match(line)
            if m:
                pkg, owners_str = m.group(1), m.group(2)
                owners = owners_str.split()
                if TEAM in owners:
                    owned_packages.add(pkg)

    return owned_packages, ds_overrides


def get_input_types_from_manifest(manifest_path: Path) -> list[str]:
    """Parse a data_stream manifest.yml and return all stream input types."""
    try:
        with manifest_path.open() as fh:
            doc = yaml.safe_load(fh)
    except Exception:
        return []

    if not isinstance(doc, dict):
        return []

    inputs: list[str] = []
    for stream in doc.get("streams", []) or []:
        inp = stream.get("input")
        if inp and inp not in inputs:
            inputs.append(inp)
    return inputs


def get_hbs_files(stream_dir: Path) -> list[Path]:
    """Return sorted list of *.yml.hbs files in *stream_dir*."""
    if not stream_dir.is_dir():
        return []
    return sorted(stream_dir.glob("*.yml.hbs"))


def input_type_from_hbs_stem(hbs_path: Path) -> str:
    """Derive an input type name from a .yml.hbs file stem.

    The stem of the file typically encodes the input type,
    e.g. ``aws-s3.yml.hbs`` → ``aws-s3``.
    """
    return hbs_path.name.replace(".yml.hbs", "")


def discover_data_streams(pkg_dir: Path) -> list[str]:
    ds_root = pkg_dir / "data_stream"
    if not ds_root.is_dir():
        return []
    return sorted(p.name for p in ds_root.iterdir() if p.is_dir())


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def collect_rows(repo_root: Path, owned_packages: set[str],
                 ds_overrides: dict[tuple[str, str], list[str]]) -> list[dict]:
    rows = []
    packages_dir = repo_root / "packages"

    for pkg in sorted(owned_packages):
        pkg_dir = packages_dir / pkg
        if not pkg_dir.is_dir():
            continue

        for ds in discover_data_streams(pkg_dir):
            # Determine effective ownership for this data stream
            effective_owners = ds_overrides.get((pkg, ds))
            if effective_owners is not None:
                # Data stream has explicit owner; only include if TEAM is listed
                if TEAM not in effective_owners:
                    continue
            # else: inherits package-level ownership → include

            manifest_path = pkg_dir / "data_stream" / ds / "manifest.yml"
            stream_dir = pkg_dir / "data_stream" / ds / "agent" / "stream"

            manifest_inputs = get_input_types_from_manifest(manifest_path)
            hbs_files = get_hbs_files(stream_dir)

            if manifest_inputs:
                # Manifest is authoritative.  Build per-input evidence from
                # matching hbs files (via template_path) or fall back to manifest.
                for input_type in manifest_inputs:
                    # Find hbs files whose stem matches this input type
                    matching_hbs = [h for h in hbs_files
                                    if input_type_from_hbs_stem(h) == input_type]
                    evidence_parts: list[str] = [
                        str(manifest_path.relative_to(repo_root))
                    ]
                    for h in matching_hbs:
                        evidence_parts.append(str(h.relative_to(repo_root)))
                    rows.append({
                        "package": pkg,
                        "data_stream": ds,
                        "input_type": input_type,
                        "evidence": ", ".join(evidence_parts),
                    })
            elif hbs_files:
                # No manifest streams section – derive input type from hbs names
                for hbs in hbs_files:
                    input_type = input_type_from_hbs_stem(hbs)
                    rows.append({
                        "package": pkg,
                        "data_stream": ds,
                        "input_type": input_type,
                        "evidence": str(hbs.relative_to(repo_root)),
                    })
            else:
                rows.append({
                    "package": pkg,
                    "data_stream": ds,
                    "input_type": "(unknown)",
                    "evidence": str(manifest_path.relative_to(repo_root))
                    if manifest_path.exists() else "—",
                })

    return rows


def render_markdown(rows: list[dict]) -> str:
    lines = [
        "# Input Types for Integrations Owned by `obs-infraobs-integrations`",
        "",
        "This report lists each integration and data stream owned by the GitHub team",
        "`@elastic/obs-infraobs-integrations`, together with the Elastic Agent input",
        "type(s) each data stream uses.",
        "",
        "> **Generated automatically** by `scripts/generate_obs_infraobs_report.py`.",
        "> Re-run the script to refresh this file.",
        "",
        "| Package | Data Stream | Input Type | Evidence (file path) |",
        "| ------- | ----------- | ---------- | -------------------- |",
    ]
    for row in rows:
        pkg = row["package"]
        ds = row["data_stream"]
        inp = row["input_type"]
        ev = row["evidence"]
        lines.append(f"| {pkg} | {ds} | {inp} | `{ev}` |")

    lines.append("")
    lines.append(f"*Total rows: {len(rows)}*")
    lines.append("")
    return "\n".join(lines)


def render_text_table(rows: list[dict]) -> str:
    """Render a simple fixed-width ASCII table for terminal output."""
    col_widths = {
        "package": max(len("Package"), max((len(r["package"]) for r in rows), default=0)),
        "data_stream": max(len("Data Stream"), max((len(r["data_stream"]) for r in rows), default=0)),
        "input_type": max(len("Input Type"), max((len(r["input_type"]) for r in rows), default=0)),
        "evidence": max(len("Evidence"), max((len(r["evidence"]) for r in rows), default=0)),
    }

    def row_str(pkg, ds, inp, ev):
        return (f"| {pkg:<{col_widths['package']}} "
                f"| {ds:<{col_widths['data_stream']}} "
                f"| {inp:<{col_widths['input_type']}} "
                f"| {ev:<{col_widths['evidence']}} |")

    sep = (f"+-{'-' * col_widths['package']}-"
           f"+-{'-' * col_widths['data_stream']}-"
           f"+-{'-' * col_widths['input_type']}-"
           f"+-{'-' * col_widths['evidence']}-+")

    out = [sep,
           row_str("Package", "Data Stream", "Input Type", "Evidence"),
           sep]
    for r in rows:
        out.append(row_str(r["package"], r["data_stream"], r["input_type"], r["evidence"]))
    out.append(sep)
    out.append(f"Total rows: {len(rows)}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Report input types for integrations owned by obs-infraobs-integrations."
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Path to the root of the elastic/integrations repository. "
             "Defaults to the parent directory of this script's location.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output Markdown file path. "
             "Defaults to docs/obs-infraobs-integrations-input-types.md inside the repo.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the ASCII table to stdout instead of (or in addition to) writing the file.",
    )
    args = parser.parse_args()

    # Resolve repo root
    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        repo_root = Path(__file__).resolve().parent.parent

    codeowners_path = repo_root / ".github" / "CODEOWNERS"
    if not codeowners_path.exists():
        print(f"CODEOWNERS not found at {codeowners_path}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output).resolve() if args.output else \
        repo_root / "docs" / "obs-infraobs-integrations-input-types.md"

    print(f"Parsing CODEOWNERS: {codeowners_path}", file=sys.stderr)
    owned_packages, ds_overrides = parse_codeowners(codeowners_path)
    print(f"  Packages owned by {TEAM}: {len(owned_packages)}", file=sys.stderr)

    print("Collecting data stream input types …", file=sys.stderr)
    rows = collect_rows(repo_root, owned_packages, ds_overrides)
    print(f"  Rows collected: {len(rows)}", file=sys.stderr)

    if args.stdout:
        print(render_text_table(rows))

    md = render_markdown(rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md, encoding="utf-8")
    print(f"Report written to: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
