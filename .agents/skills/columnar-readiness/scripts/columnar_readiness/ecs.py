"""ECS definitions for `external: ecs` fields, from elastic-package's cache."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional, Tuple

from .common import load_yaml
from .constants import ECS_ARRAY_FIELDS_FALLBACK, ECS_CACHE_DIR, TEXT_TYPES


_ECS_SCHEMA: Optional[Dict[str, Dict[str, Any]]] = None
# Which ECS definitions the run used, printed in every report: results differ between
# a machine with elastic-package's cache and one without it.
_ECS_SOURCE: Optional[str] = None


def ecs_schema() -> Dict[str, Dict[str, Any]]:
    """flat_name -> {"type", "array", "text_subfields"} from elastic-package's ECS cache.

    An `external: ecs` reference carries no `type` in the package source, so without
    this the sort-candidate type and array checks cannot see anything. Falls back to
    `ECS_ARRAY_FIELDS_FALLBACK` (arrays only, no types) when the cache is absent.
    """
    global _ECS_SCHEMA, _ECS_SOURCE
    if _ECS_SCHEMA is not None:
        return _ECS_SCHEMA

    schema: Dict[str, Dict[str, Any]] = {}
    versions = []
    if os.path.isdir(ECS_CACHE_DIR):
        versions = sorted(
            (d for d in os.listdir(ECS_CACHE_DIR)
             if os.path.isfile(os.path.join(ECS_CACHE_DIR, d, "ecs_nested.yml"))),
            key=_version_key,
        )
    if versions:
        path = os.path.join(ECS_CACHE_DIR, versions[-1], "ecs_nested.yml")
        try:
            doc = load_yaml(path) or {}
        except RuntimeError:
            doc = {}
        for group in doc.values() if isinstance(doc, dict) else []:
            if not isinstance(group, dict):
                continue
            for flat, fdef in (group.get("fields") or {}).items():
                if not isinstance(fdef, dict):
                    continue
                schema[flat] = {
                    "type": fdef.get("type"),
                    "array": "array" in (fdef.get("normalize") or []),
                    "text_subfields": [
                        mf.get("name") for mf in (fdef.get("multi_fields") or [])
                        if isinstance(mf, dict) and mf.get("type") in TEXT_TYPES
                    ],
                }
        _ECS_SOURCE = (f"elastic-package ECS cache {versions[-1]} "
                       f"(`{os.path.join(ECS_CACHE_DIR, versions[-1])}`)")
    if not schema:
        for flat in ECS_ARRAY_FIELDS_FALLBACK:
            schema[flat] = {"type": None, "array": True, "text_subfields": []}
        _ECS_SOURCE = ("built-in fallback: no elastic-package ECS cache found in "
                       f"`{ECS_CACHE_DIR}`, so `external: ecs` fields have no type and sort "
                       "proposals are more conservative (run `elastic-package build` once "
                       "to populate the cache)")

    _ECS_SCHEMA = schema
    return schema


def ecs_source() -> str:
    """Human-readable description of the ECS definitions this run used."""
    ecs_schema()
    return _ECS_SOURCE or "unknown"


def _version_key(name: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", name)) or (0,)


# libyaml when it is available: the catalog run now parses every ingest pipeline in
# the repo, and the pure-Python loader makes that several times slower.
