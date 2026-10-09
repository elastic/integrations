"""Small helpers: status ordering, YAML loading, booleans and the finding record."""

from __future__ import annotations

from typing import Any, Dict, Optional

import yaml

from .constants import STATUS_ORDER


def worse(a: str, b: str) -> str:
    return a if STATUS_ORDER.index(a) >= STATUS_ORDER.index(b) else b


YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class LineDict(dict):
    """A YAML mapping that remembers its own line and the line of each key (1-based)."""

    line: Optional[int] = None

    def line_of(self, key: Optional[str] = None) -> Optional[int]:
        lines = getattr(self, "key_lines", None) or {}
        return lines.get(key, self.line) if key else self.line


class LineLoader(YAML_LOADER):  # type: ignore[misc,valid-type]
    """The fast loader, building `LineDict`s so findings can point at `file:line`."""


def _construct_line_dict(loader: Any, node: Any) -> LineDict:
    mapping = LineDict(loader.construct_mapping(node, deep=True))
    mapping.line = node.start_mark.line + 1
    mapping.key_lines = {str(key.value): key.start_mark.line + 1 for key, _ in node.value}
    return mapping


LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_line_dict)


def line_of(node: Any, key: Optional[str] = None) -> Optional[int]:
    """Source line of `key` in a mapping from `load_yaml`, else of the mapping; None if unknown."""
    return node.line_of(key) if isinstance(node, LineDict) else None


def load_yaml(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.load(fh, Loader=LineLoader)
    except Exception as exc:  # unparseable file: surfaced as a finding by the caller
        raise RuntimeError(f"{path}: {exc}") from exc


def is_false(value: Any) -> bool:
    """`dynamic: false` may be a bool or the string "false"."""
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() == "false"
    return False


def is_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value is True
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


SEVERITIES = ("blocker", "review", "auto_fix", "info", "platform")


def finding(code: str, klass: str, severity: str, message: str,
            remediation: str, where: str, field: Optional[str] = None,
            line: Optional[int] = None) -> Dict[str, Any]:
    assert severity in SEVERITIES, severity
    return {
        "code": code,
        "class": klass,
        "severity": severity,
        "auto_fixable": severity == "auto_fix",
        "field": field,
        "where": where,
        "line": line,
        "message": message,
        "remediation": remediation,
    }


def location(f: Dict[str, Any]) -> str:
    """`file:line` for a finding, or just the file when the line is unknown."""
    return f"{f['where']}:{f['line']}" if f.get("line") else f["where"]
