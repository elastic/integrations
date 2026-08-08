#!/usr/bin/env python3
"""
Build a stakeholder matrix CSV for all integration packages.

Columns:
  package,
  security category (Y/N),
  observability category (Y/N),
  other catalog categories (semicolon-separated; excludes security and observability),
  graph visualization support (supported | missing | identified potential),
  new strategy support (destination field) (Y/N),
  support verified (Y/N)

Data sources (under --reports-dir, default dev/target-fields-audit/out/):
  - packages/*/manifest.yml — catalog categories
  - target_fields_audit.csv — ECS host|user|service|entity.target.* hits by tier
  - destination_identity_hits.csv — destination.user / destination.host in pipelines
  - vendor_target_special_cases.csv — vendor *target* field paths (optional signal)

Graph visualization support (automated heuristic):
  - supported: Tier A pipeline evidence for ECS *.target.* (ingest maps target fields)
  - identified potential: not Tier A, but destination-field strategy (Y) OR Tier B/C ECS
    target only OR vendor-namespaced *target* field path in vendor CSV
  - missing: none of the above

support verified: always N (no human sign-off in this pipeline; update CSV manually).
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import manifest_util  # noqa: E402


def load_audit_packages(csv_path: Path) -> tuple[set[str], set[str], set[str]]:
    """Returns (any_hit, tier_a, tier_bc_only)."""
    any_hit: set[str] = set()
    tier_a: set[str] = set()
    tiers_by_pkg: dict[str, set[str]] = {}
    if not csv_path.is_file():
        return any_hit, tier_a, set()
    with csv_path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            pkg = row["package"]
            any_hit.add(pkg)
            tiers_by_pkg.setdefault(pkg, set()).add(row["tier"])
    tier_bc_only = set()
    for pkg, tiers in tiers_by_pkg.items():
        if "A" in tiers:
            tier_a.add(pkg)
        elif tiers & {"B", "C"}:
            tier_bc_only.add(pkg)
    return any_hit, tier_a, tier_bc_only


def load_packages_from_csv_column(csv_path: Path, column: str = "package") -> set[str]:
    if not csv_path.is_file():
        return set()
    out: set[str] = set()
    with csv_path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            out.add(row[column])
    return out


def load_vendor_namespaced_packages(csv_path: Path) -> set[str]:
    if not csv_path.is_file():
        return set()
    out: set[str] = set()
    with csv_path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            nc = row.get("namespace_class", "")
            if nc in ("vendor_root", "vendor_namespaced"):
                out.add(row["package"])
    return out


def graph_support(
    pkg: str,
    tier_a: set[str],
    tier_bc_only: set[str],
    dest_strategy: set[str],
    vendor_target: set[str],
) -> str:
    if pkg in tier_a:
        return "supported"
    if pkg in dest_strategy or pkg in tier_bc_only or pkg in vendor_target:
        return "identified potential"
    return "missing"


def main() -> int:
    ap = argparse.ArgumentParser(description="Stakeholder matrix for all integration packages")
    ap.add_argument("--repo-root", type=Path, default=_SCRIPT_DIR.parents[1])
    ap.add_argument(
        "--reports-dir",
        type=Path,
        default=_SCRIPT_DIR / "out",
        help="Directory with target_fields_audit.csv, destination_identity_hits.csv, etc.",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=_SCRIPT_DIR / "out" / "packages_stakeholder_matrix.csv",
    )
    args = ap.parse_args()

    repo = args.repo_root.resolve()
    packages_dir = repo / "packages"
    reports = args.reports_dir.resolve()

    all_packages = sorted(p.name for p in packages_dir.iterdir() if p.is_dir())
    if len(all_packages) != 445:
        print(f"warn: expected 445 packages, found {len(all_packages)}", file=sys.stderr)

    security = manifest_util.security_package_names(packages_dir)
    observability = manifest_util.package_names_with_category(packages_dir, "observability")
    pkg_categories = manifest_util.load_package_categories(packages_dir)

    _, tier_a, tier_bc_only = load_audit_packages(reports / "target_fields_audit.csv")
    dest_strategy = load_packages_from_csv_column(reports / "destination_identity_hits.csv")
    vendor_target = load_vendor_namespaced_packages(
        reports / "vendor_target_special_cases.csv"
    )

    rows: list[dict[str, str]] = []
    for pkg in all_packages:
        dest_y = "Y" if pkg in dest_strategy else "N"
        rows.append(
            {
                "package": pkg,
                "security category": "Y" if pkg in security else "N",
                "observability category": "Y" if pkg in observability else "N",
                "other catalog categories": manifest_util.other_categories_label(
                    pkg_categories.get(pkg, [])
                ),
                "graph visualization support": graph_support(
                    pkg, tier_a, tier_bc_only, dest_strategy, vendor_target
                ),
                "new strategy support (destination field)": dest_y,
                "support verified": "N",
            }
        )

    out = args.output.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "package",
        "security category",
        "observability category",
        "graph visualization support",
        "new strategy support (destination field)",
        "support verified",
        "other catalog categories",
    ]
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    # Summary to stderr
    g_counts = {"supported": 0, "identified potential": 0, "missing": 0}
    for r in rows:
        g_counts[r["graph visualization support"]] += 1
    print(f"Wrote {len(rows)} rows -> {out}")
    print(f"security Y: {sum(1 for r in rows if r['security category']=='Y')}")
    print(f"observability Y: {sum(1 for r in rows if r['observability category']=='Y')}")
    print(f"destination strategy Y: {sum(1 for r in rows if r['new strategy support (destination field)']=='Y')}")
    print(f"graph support: {g_counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
