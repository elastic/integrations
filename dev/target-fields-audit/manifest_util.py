"""Read integration package manifests under packages/<pkg>/manifest.yml."""

from __future__ import annotations

import re
from pathlib import Path


def parse_categories_block(text: str) -> list[str]:
    """Extract category strings from the `categories:` YAML block (list or inline array)."""
    m = re.search(r"(?ms)^categories:\s*(.*?)(?=^[a-zA-Z0-9_]+:\s*|\Z)", text)
    if not m:
        return []
    block = m.group(1).strip()
    if not block:
        return []
    if block.startswith("["):
        inner = block.strip()
        if inner.startswith("["):
            inner = inner[1:]
        if inner.endswith("]"):
            inner = inner[:-1]
        parts = re.split(r",\s*", inner)
        return [p.strip().strip("'\"") for p in parts if p.strip()]
    cats: list[str] = []
    for line in block.splitlines():
        line = line.strip()
        if line.startswith("- "):
            cats.append(line[2:].strip().strip("'\""))
    return cats


def package_names_with_category(packages_dir: Path, category: str) -> set[str]:
    """Package directory names whose root manifest lists the given category (case-insensitive)."""
    want = category.lower()
    out: set[str] = set()
    for manifest in sorted(packages_dir.glob("*/manifest.yml")):
        pkg = manifest.parent.name
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        cats = [c.lower() for c in parse_categories_block(text)]
        if want in cats:
            out.add(pkg)
    return out


def security_package_names(packages_dir: Path) -> set[str]:
    """Integrations tagged with `security` in root manifest categories."""
    return package_names_with_category(packages_dir, "security")


def load_package_categories(packages_dir: Path) -> dict[str, list[str]]:
    """Map package name -> catalog categories from root manifest (lowercase, order preserved)."""
    out: dict[str, list[str]] = {}
    for manifest in sorted(packages_dir.glob("*/manifest.yml")):
        pkg = manifest.parent.name
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            out[pkg] = []
            continue
        out[pkg] = [c.lower() for c in parse_categories_block(text)]
    return out


def other_categories_label(
    categories: list[str],
    *,
    exclude: frozenset[str] = frozenset({"security", "observability"}),
    separator: str = "; ",
) -> str:
    """Join manifest categories excluding named ones (for stakeholder CSV)."""
    rest = [c for c in categories if c not in exclude]
    return separator.join(rest)
