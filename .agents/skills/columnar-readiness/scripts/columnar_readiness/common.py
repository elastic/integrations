"""Small helpers: status ordering, YAML loading, booleans and the finding record."""

from __future__ import annotations

from typing import Any, Dict, Optional

import yaml

from .constants import STATUS_ORDER


def worse(a: str, b: str) -> str:
    return a if STATUS_ORDER.index(a) >= STATUS_ORDER.index(b) else b


YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def load_yaml(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.load(fh, Loader=YAML_LOADER)
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


SEVERITIES = ("blocker", "review", "auto_fix", "info")


def finding(code: str, klass: str, severity: str, message: str,
            remediation: str, where: str, field: Optional[str] = None) -> Dict[str, Any]:
    assert severity in SEVERITIES, severity
    return {
        "code": code,
        "class": klass,
        "severity": severity,
        "auto_fixable": severity == "auto_fix",
        "field": field,
        "where": where,
        "message": message,
        "remediation": remediation,
    }
