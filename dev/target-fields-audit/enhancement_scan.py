#!/usr/bin/env python3
"""
Heuristic scan for integrations that may be enhanced with ECS *target* semantics
(host.target.*, user.target.*, service.target.*, entity.target.*), including
generic entity.target.* when classification is unclear.

Reads existing pipeline/field evidence from target_fields_audit.csv when present,
and adds broader signals from ingest pipelines, pipeline test fixtures (*expected.json),
and package docs.

This is engineering judgment from repository text — not runtime log analysis.
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

# Import shared helpers from sibling module
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import scan as sc  # noqa: E402
import manifest_util  # noqa: E402

MAX_FIXTURE_BYTES = 4_000_000
MAX_DOC_BYTES = 400_000

# Ingest pipeline: identity-like destination (maps cleanly to "who/what was targeted").
RE_PIPELINE_DEST_IDENTITY = re.compile(
    r"destination\.(user|host|hostname|domain|username|email)",
    re.IGNORECASE,
)

# Network-style destination (common; weaker signal alone).
RE_PIPELINE_DEST_NETWORK = re.compile(
    r"destination\.(address|ip|ipv6|mac|port|geo\.|bytes|packets)",
    re.IGNORECASE,
)

# Actor / victim / impersonation language (excludes related.* — actor vs target is ambiguous).
RE_PIPELINE_ACTOR = re.compile(
    r"(\b(principal|impersonat|victim)\b|protoPayload\.(authentication|authorization)|"
    r"threat\.target|source\.user\.(name|id)|user\.changes\.)",
    re.IGNORECASE,
)

# Generic ECS entity.* (not already entity.target.*) may be a mapping source.
RE_PIPELINE_ENTITY_OTHER = re.compile(
    r"entity\.(id|name|type|domain)(\.|\b)",
    re.IGNORECASE,
)

# Fixture / doc patterns
RE_FIXTURE_STRONG = re.compile(
    r"(destination\.(user|host|hostname|domain|username|email)|"
    r"\"(host|user|service|entity)\.target\.|"
    r"\"[^\"]{0,64}[Tt]arget[^\"]{0,64}\"\s*:)",
    re.IGNORECASE,
)

RE_DOCS_LEXICON = re.compile(
    r"(target (user|host|resource|principal|account|service)|"
    r"affected (user|host|resource|asset)|security principal|"
    r"resource (affected|targeted)|\bvictim\b|impersonat|"
    r"subject (of|user)|object (user|principal)|"
    r"who was (targeted|affected)|principal (that|was))",
    re.IGNORECASE,
)


@dataclass
class PackageSignals:
    ecs_target_pipeline: bool = False  # from audit CSV: Tier A + ECS target prefixes
    pipeline_dest_identity: bool = False
    pipeline_dest_network: bool = False
    pipeline_actor: bool = False
    pipeline_entity_other: bool = False
    fixture_strong: bool = False
    docs_lexicon: bool = False

    def pipeline_any(self) -> bool:
        return (
            self.pipeline_dest_identity
            or self.pipeline_dest_network
            or self.pipeline_actor
            or self.pipeline_entity_other
        )


def load_ecs_target_packages_from_audit(csv_path: Path) -> set[str]:
    if not csv_path.is_file():
        return set()
    out: set[str] = set()
    with csv_path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("tier") == "A" and row.get("matched_prefix") in sc.PREFIXES:
                out.add(row["package"])
    return out


def scan_pipeline_file(path: Path, sig: PackageSignals) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    ecs_hit = False
    for line in text.splitlines():
        if sc.should_skip_line(line, False):
            continue
        hay = sc.line_for_prefix_search(line)
        if sc.line_matches_prefixes(line):
            ecs_hit = True
        if RE_PIPELINE_DEST_IDENTITY.search(hay):
            sig.pipeline_dest_identity = True
        if RE_PIPELINE_DEST_NETWORK.search(hay):
            sig.pipeline_dest_network = True
        if RE_PIPELINE_ACTOR.search(hay):
            sig.pipeline_actor = True
        if RE_PIPELINE_ENTITY_OTHER.search(hay):
            sig.pipeline_entity_other = True
    if ecs_hit:
        sig.ecs_target_pipeline = True


def scan_fixture_file(path: Path, sig: PackageSignals) -> None:
    try:
        sz = path.stat().st_size
        if sz > MAX_FIXTURE_BYTES:
            data = path.read_bytes()[:MAX_FIXTURE_BYTES].decode("utf-8", errors="replace")
        else:
            data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if RE_FIXTURE_STRONG.search(data):
        sig.fixture_strong = True


def scan_doc_file(path: Path, sig: PackageSignals) -> None:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
        if len(data) > MAX_DOC_BYTES:
            data = data[:MAX_DOC_BYTES]
    except OSError:
        return
    if RE_DOCS_LEXICON.search(data):
        sig.docs_lexicon = True


def classify_priority(
    ecs_from_audit: bool,
    s: PackageSignals,
) -> str:
    """Single label per package for reporting."""
    if ecs_from_audit or s.ecs_target_pipeline:
        return "already_maps_ecs_target"
    if s.pipeline_dest_identity or s.pipeline_actor:
        return "strong_candidate"
    if s.fixture_strong or s.pipeline_entity_other:
        return "moderate_candidate"
    if s.pipeline_dest_network:
        return "moderate_candidate_network_dest"
    if s.docs_lexicon:
        return "exploratory_docs"
    return "none"


def iter_package_dirs(packages_dir: Path) -> list[Path]:
    return sorted(p for p in packages_dir.iterdir() if p.is_dir())


def analyze_package(pkg_dir: Path, ecs_from_audit: set[str]) -> PackageSignals:
    name = pkg_dir.name
    sig = PackageSignals()

    for path in pkg_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(pkg_dir.parent.parent)).replace("\\", "/")
        if not rel.startswith(f"packages/{name}/"):
            continue
        rel_under = rel[len("packages/") + len(name) + 1 :]
        tier = sc.classify_tier(f"{name}/{rel_under}")

        if tier == "A" and (path.suffix in (".yml", ".yaml")):
            scan_pipeline_file(path, sig)

        if path.name.endswith("-expected.json") or path.name.endswith(".log-expected.json"):
            if "/_dev/test/" in rel.replace("\\", "/"):
                scan_fixture_file(path, sig)

        if "/docs/" in rel and path.suffix.lower() == ".md":
            scan_doc_file(path, sig)

    if name in ecs_from_audit:
        sig.ecs_target_pipeline = True

    return sig


def main() -> int:
    ap = argparse.ArgumentParser(description="ECS target enhancement opportunity scan")
    ap.add_argument("--repo-root", type=Path, default=_SCRIPT_DIR.parents[1])
    ap.add_argument(
        "--audit-csv",
        type=Path,
        default=_SCRIPT_DIR / "out" / "target_fields_audit.csv",
        help="Existing Tier A ECS target audit (optional)",
    )
    ap.add_argument("--output-dir", type=Path, default=_SCRIPT_DIR / "out")
    ap.add_argument(
        "--security-only",
        action="store_true",
        help="Only include packages whose root manifest.yml lists category `security`",
    )
    args = ap.parse_args()

    repo_root = args.repo_root.resolve()
    packages_dir = repo_root / "packages"
    if not packages_dir.is_dir():
        print(f"error: missing {packages_dir}", file=sys.stderr)
        return 1

    ecs_from_audit = load_ecs_target_packages_from_audit(args.audit_csv.resolve())

    pkg_dirs = iter_package_dirs(packages_dir)
    if args.security_only:
        sec = manifest_util.security_package_names(packages_dir)
        pkg_dirs = [p for p in pkg_dirs if p.name in sec]

    rows: list[dict[str, str]] = []
    by_priority: dict[str, list[str]] = defaultdict(list)

    for pkg_dir in pkg_dirs:
        name = pkg_dir.name
        sig = analyze_package(pkg_dir, ecs_from_audit)
        priority = classify_priority(name in ecs_from_audit, sig)
        by_priority[priority].append(name)

        rows.append(
            {
                "package": name,
                "priority": priority,
                "ecs_target_tierA_audit": str(name in ecs_from_audit).lower(),
                "pipeline_dest_identity": str(sig.pipeline_dest_identity).lower(),
                "pipeline_dest_network": str(sig.pipeline_dest_network).lower(),
                "pipeline_actor": str(sig.pipeline_actor).lower(),
                "pipeline_entity_other": str(sig.pipeline_entity_other).lower(),
                "fixture_strong": str(sig.fixture_strong).lower(),
                "docs_lexicon": str(sig.docs_lexicon).lower(),
            }
        )

    rows.sort(key=lambda r: (r["priority"], r["package"]))

    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "target_enhancement_packages.csv"
    md_path = out_dir / "target_enhancement_report.md"

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "package",
            "priority",
            "ecs_target_tierA_audit",
            "pipeline_dest_identity",
            "pipeline_dest_network",
            "pipeline_actor",
            "pipeline_entity_other",
            "fixture_strong",
            "docs_lexicon",
        ]
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        audit_rel = args.audit_csv.resolve().relative_to(repo_root)
    except ValueError:
        audit_rel = args.audit_csv.resolve()
    try:
        sha = subprocess.check_output(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        sha = "unknown"

    total = len(pkg_dirs)
    total_safe = max(total, 1)
    already = len(by_priority["already_maps_ecs_target"])
    strong = len(by_priority["strong_candidate"])
    mod = len(by_priority["moderate_candidate"])
    mod_net = len(by_priority["moderate_candidate_network_dest"])
    expl = len(by_priority["exploratory_docs"])
    none = len(by_priority["none"])

    # Non-overlapping enhancement funnel (exclude already mapped)
    enhance_union = strong + mod + mod_net + expl

    md_lines = [
        "# ECS target semantics — enhancement opportunity report",
        "",
        f"- **git HEAD:** `{sha}`",
        f"- **generated (UTC):** {ts}",
        f"- **packages scanned:** {total}",
        "",
    ]
    if args.security_only:
        md_lines.extend(
            [
                "- **filter:** Only integrations whose root `packages/<name>/manifest.yml` includes the `security` category.",
                "",
            ]
        )
    md_lines.extend(
        [
        f"- **audit CSV used:** `{audit_rel}` (Tier A ECS `*.target.*` packages: {already})",
        "",
        "## What this report is (and is not)",
        "",
        "**Is:** A static, heuristic pass over this repository only — ingest pipeline YAML,",
        "pipeline `*expected.json` fixtures (truncated for very large files), and `docs/**/*.md`.",
        "Signals are meant to suggest where vendor logs *might* describe a second party",
        "(user/host/service/resource) that could be modeled as ECS **target** fields or",
        "**`entity.target.*`** when classification is unclear.",
        "",
        "**Is not:** Log volume, production field population, or vendor API guarantees.",
        "Each row still needs product/security review before changing mappings.",
        "",
        "## Method — signal definitions",
        "",
        "| Signal | Meaning |",
        "| --- | --- |",
        "| `pipeline_dest_identity` | Pipeline references `destination.user`, `destination.host`, `destination.domain`, etc. |",
        "| `pipeline_dest_network` | Pipeline references `destination.ip`, `destination.address`, ports/geo/bytes (common in flow logs). |",
        "| `pipeline_actor` | `principal`, `victim`, `impersonat`, `protoPayload.authentication`, `source.user`, etc. (not `related.*`) |",
        "| `pipeline_entity_other` | `entity.id` / `entity.name` / `entity.type` (not already `entity.target.*`). |",
        "| `fixture_strong` | Pipeline expected JSON contains destination identity, ECS `*.target.*`, or JSON keys containing `target`. |",
        "| `docs_lexicon` | Docs mention “target user/host”, “affected user”, “principal”, “victim”, etc. |",
        "",
        "## Priority labels (per package)",
        "",
        "| Label | Rule |",
        "| --- | --- |",
        "| `already_maps_ecs_target` | Listed with Tier A hits for `host|user|service|entity.target.*` in the audit CSV. |",
        "| `strong_candidate` | Not already mapped **and** (`pipeline_dest_identity` **or** `pipeline_actor`). |",
        "| `moderate_candidate` | Not stronger **and** (`fixture_strong` **or** `pipeline_entity_other`). |",
        "| `moderate_candidate_network_dest` | Not stronger **and** only `pipeline_dest_network` among pipeline/fixture signals. |",
        "| `exploratory_docs` | Not above **and** `docs_lexicon` only. |",
        "| `none` | No heuristic signal. |",
        "",
        "## Counts",
        "",
        f"| Priority | Packages | Share of scanned |",
        f"| --- | ---: | ---: |",
        f"| Already maps ECS target (Tier A audit) | {already} | {already/total_safe:.1%} |",
        f"| **Strong enhancement candidate** | {strong} | {strong/total_safe:.1%} |",
        f"| Moderate (fixtures / generic entity) | {mod} | {mod/total_safe:.1%} |",
        f"| Moderate (network `destination.*` only) | {mod_net} | {mod_net/total_safe:.1%} |",
        f"| Exploratory (documentation phrasing only) | {expl} | {expl/total_safe:.1%} |",
        f"| No signal | {none} | {none/total_safe:.1%} |",
        "",
        "### Interpretation",
        "",
        f"- **Already using ECS target fields in pipelines (audit):** {already} / {total} packages.",
        f"- **Packages we would revisit first for new target mappings:** **{strong}** strong candidates.",
        f"- **Broader backlog (includes weaker / noisier signals):** **{enhance_union}** packages "
        f"(strong + moderate + moderate_network_only + exploratory), i.e. anything not `none` and not already mapped.",
        f"- If you only trust identity/actor-style pipeline evidence, focus on the **{strong}** strong bucket first, "
        f"then selectively pull from **{mod}** moderate cases after reviewing fixtures.",
        "",
        "**Note:** `strong_candidate` is an **upper bound**. Some regex matches (e.g. "
        "`destination.host` in pure flow telemetry) reflect common ECS patterns without always "
        "implying a distinct “target” entity for SIEM. Use [`target_enhancement_packages.csv`](target_enhancement_packages.csv) "
        "to triage by toggling signals off in a spreadsheet filter.",
        "",
        "## Machine-readable output",
        "",
        f"- Per-package flags: [`target_enhancement_packages.csv`](target_enhancement_packages.csv)",
        "",
        "## Follow-ups (not automated here)",
        "",
        "- Vendor-specific field dictionaries (OCSF, ASIM, raw vendor `target*`) → ECS mapping tables.",
        "- Runtime sampling / simulate ingest to confirm population rates.",
        "- When entity type is unknown, map remaining attributes to **`entity.target.*`** per your placeholder rule.",
        "",
        ]
    )
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    print(f"Wrote {csv_path} ({len(rows)} packages)")
    print(f"Wrote {md_path}")
    print(
        f"Summary: total={total}, already_target={already}, "
        f"strong={strong}, moderate={mod}, mod_net={mod_net}, exploratory={expl}, "
        f"enhancement_backlog_union={enhance_union}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
