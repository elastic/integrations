"""Kibana assets: dashboard fields and filter fields."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from typing import Any, Dict, List, Tuple

from .consumers import kibana_source_consumers


DASHBOARD_FIELD_RE = re.compile(r'\\?"(?:field|key|sourceField)\\?"\s*:\s*\\?"([a-zA-Z][\w.@-]*)\\?"')

# Field name on the left of a KQL comparison: `user.name : "bob"`, `bytes >= 100`.
KQL_FIELD_RE = re.compile(r'([a-zA-Z][\w.@*-]*)\s*(?::|>=|<=|>|<)')
KQL_KEYWORDS = {"and", "or", "not"}


def scan_kibana_assets(pkg_dir: str, count_fields: bool = True,
                       limit_bytes: int = 4_000_000
                       ) -> Tuple[Counter, Counter, List[Dict[str, Any]]]:
    """(referenced, filtered, `_source` consumers) from the package's Kibana assets.

    Every `kibana/**/*.json` is read exactly once. The two field counters feed the
    index-sort tie-break and are skipped when `count_fields` is false
    (`--no-dashboards`); the `_source` consumer scan always runs, because it is a
    correctness check rather than a sort hint.

    `referenced` is every `field`/`key`/`sourceField` mention — axes, group-bys,
    metrics, columns. It is the benchmark workload.

    `filtered` counts only fields used in a **filter or query clause**: Kibana filter
    pills (`filter[].meta.key`) and KQL query strings. That is much stronger evidence
    for an index-sort key, because sorting only pays off for fields queries *prune*
    on. Being plotted on an axis says nothing about pruning.
    """
    referenced: Counter = Counter()
    filtered: Counter = Counter()
    texts: List[Tuple[str, str]] = []
    kibana_dir = os.path.join(pkg_dir, "kibana")
    if not os.path.isdir(kibana_dir):
        return referenced, filtered, []
    for root, _dirs, files in os.walk(kibana_dir):
        # NOT sorted: `filter_fields.most_common()` breaks ties by insertion order, so
        # changing the walk order would silently move the tier-3 dashboard hint of
        # streams whose filter fields are all tied at 1 (`elastic_agent`).
        for name in files:
            if not name.endswith(".json"):
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) > limit_bytes:
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if "_source" in text or "script" in text:
                texts.append((os.path.relpath(path, pkg_dir), text))
            if not count_fields:
                continue
            for match in DASHBOARD_FIELD_RE.finditer(text):
                referenced[match.group(1)] += 1
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            _collect_filter_fields(doc, filtered)
    return referenced, filtered, kibana_source_consumers(texts)


def _collect_filter_fields(node: Any, counts: Counter, depth: int = 0) -> None:
    """Walk a Kibana saved object, descending into embedded JSON strings."""
    if depth > 40:
        return
    if isinstance(node, list):
        for item in node:
            _collect_filter_fields(item, counts, depth + 1)
        return
    if isinstance(node, str):
        # searchSourceJSON / filtersJSON / panelsJSON hold JSON as a string.
        stripped = node.strip()
        if stripped[:1] in ("{", "[") and len(stripped) > 2:
            try:
                _collect_filter_fields(json.loads(stripped), counts, depth + 1)
            except ValueError:
                pass
        return
    if not isinstance(node, dict):
        return

    # Filter pill: {"meta": {"key": "cloud.account.id", "negate": false, ...}, ...}
    meta = node.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("key"), str):
        key = meta["key"]
        if key and not key.startswith("_") and meta.get("type") != "custom":
            counts[key] += 1

    # Query bar: {"query": "host.name : foo", "language": "kuery"}
    if node.get("language") in ("kuery", "lucene") and isinstance(node.get("query"), str):
        for match in KQL_FIELD_RE.finditer(node["query"]):
            name = match.group(1)
            if name.lower() in KQL_KEYWORDS or "*" in name:
                continue
            counts[name] += 1

    for value in node.values():
        _collect_filter_fields(value, counts, depth + 1)
