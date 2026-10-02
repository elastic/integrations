"""Transforms that read `_source`, including `latest` transforms across packages."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .common import finding, line_of, load_yaml
from .constants import OTEL_INPUTS
from .consumers import source_access_hits
from .patches import DOT_EXPANDER_JSON, DOT_EXPANDER_YAML, patch
from .rules import index_pattern_matches, stream_index_name, strip_cluster


# Keys whose string values are Painless / runtime-field scripts:
# `pivot.aggregations.*.scripted_metric.map_script`,
# `source.runtime_mappings.<field>.script.source`, `bucket_script`, `script_fields`.
_SCRIPT_KEY_HINTS = ("script", "runtime_mappings", "inline")


def _script_texts(node: Any, path: str = "", depth: int = 0) -> Iterator[Tuple[str, str]]:
    """(dotted key path, string) for every string that sits under a script-ish key."""
    if depth > 20:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            yield from _script_texts(value, child, depth + 1)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            yield from _script_texts(value, f"{path}[{idx}]", depth + 1)
    elif isinstance(node, str):
        if any(hint in path for hint in _SCRIPT_KEY_HINTS):
            yield path, node


_TRANSFORM_INDEX_RE = re.compile(r"^(?:logs|metrics|traces|profiling)-([a-z0-9_]+)\.([a-z0-9_]+)")


def _transform_stream_names(indices: Any, pkg_name: str) -> Tuple[set, bool]:
    """(data stream names of THIS package the transform reads, reads_elsewhere)."""
    names: set = set()
    external = False
    if isinstance(indices, str):
        indices = [indices]
    for entry in indices if isinstance(indices, list) else []:
        for part in str(entry).split(","):
            match = _TRANSFORM_INDEX_RE.match(part.strip().strip('"\''))
            if not match:
                continue
            if match.group(1) == pkg_name:
                names.add(match.group(2))
            else:
                external = True
    return names, external


def transform_source_consumers(pkg_dir: str) -> List[Dict[str, Any]]:
    """Transforms of this package whose scripts read the document `_source`.

    Layout: `elasticsearch/transform/<name>/transform.yml` (the `manifest.yml` and
    `fields/` beside it are metadata, not scripts). Across the whole catalog this
    currently returns nothing: every packaged transform script reads `doc[...]`.
    """
    out: List[Dict[str, Any]] = []
    root = os.path.join(pkg_dir, "elasticsearch", "transform")
    if not os.path.isdir(root):
        return out
    pkg_name = os.path.basename(pkg_dir)
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name, "transform.yml")
        if not os.path.isfile(path):
            continue
        try:
            doc = load_yaml(path) or {}
        except RuntimeError:
            continue
        if not isinstance(doc, dict):
            continue
        hits: List[Tuple[str, str, str]] = []
        for where, text in _script_texts(doc):
            for label, excerpt in source_access_hits(text):
                hits.append((where, label, excerpt))
        if not hits:
            continue
        streams, external = _transform_stream_names(
            (doc.get("source") or {}).get("index") if isinstance(doc.get("source"), dict) else None,
            pkg_name)
        out.append({
            "name": name,
            "file": os.path.relpath(path, pkg_dir),
            "streams": sorted(streams),
            "external_source": external,
            "hits": hits[:4],
        })
    return out


# --------------------------------------------------------------------------- #
# `latest` transforms
# --------------------------------------------------------------------------- #

_INGEST_PIPELINE_NAME_RE = re.compile(r'ingestPipelineName\s+"([^"]+)"')


def _pipeline_expands_dotted_keys(path: str) -> bool:
    """Whether a pipeline turns dotted top-level keys back into objects first.

    Either a leading `dot_expander` with `field: "*"`, or the pipeline-level
    `field_access_pattern: flexible`, which resolves dotted names on access.
    """
    try:
        doc = load_yaml(path) or {}
    except RuntimeError:
        return False
    if not isinstance(doc, dict):
        return False
    if str(doc.get("field_access_pattern", "")).strip().lower() == "flexible":
        return True
    procs = doc.get("processors") if isinstance(doc.get("processors"), list) else []
    first = procs[0] if procs and isinstance(procs[0], dict) else {}
    expander = first.get("dot_expander")
    return isinstance(expander, dict) and str(expander.get("field")) == "*"


def latest_transforms(pkg_dir: str) -> List[Dict[str, Any]]:
    """The package's `latest` transforms, with their source patterns and destination.

    A `latest` transform keeps the newest document per `unique_key` and writes that
    document's `_source` to its destination index. It is a `_source` consumer even
    without a single script, which is why it is scanned separately from
    `transform_source_consumers`.
    """
    out: List[Dict[str, Any]] = []
    root = os.path.join(pkg_dir, "elasticsearch", "transform")
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name, "transform.yml")
        if not os.path.isfile(path):
            continue
        try:
            doc = load_yaml(path) or {}
        except RuntimeError:
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("latest"), dict):
            continue
        source = doc.get("source") if isinstance(doc.get("source"), dict) else {}
        indices = source.get("index")
        indices = [indices] if isinstance(indices, str) else (indices or [])
        patterns = [part.strip() for entry in indices for part in str(entry).split(",")
                    if part.strip()]
        dest = doc.get("dest") if isinstance(doc.get("dest"), dict) else {}
        ref = str(dest.get("pipeline") or "")
        match = _INGEST_PIPELINE_NAME_RE.search(ref)
        pipeline_name = match.group(1) if match else (ref or None)
        pipeline_file = None
        if pipeline_name:
            for ext in (".yml", ".yaml", ".json"):
                candidate = os.path.join(pkg_dir, "elasticsearch", "ingest_pipeline",
                                         pipeline_name + ext)
                if os.path.isfile(candidate):
                    pipeline_file = candidate
                    break
        unique_key = doc["latest"].get("unique_key") or []
        out.append({
            "name": name,
            "file": os.path.relpath(path, pkg_dir),
            "line": line_of(source, "index"),
            "patterns": patterns,
            "unique_key": unique_key if isinstance(unique_key, list) else [unique_key],
            "dest_index": dest.get("index"),
            "dest_pipeline": (os.path.relpath(pipeline_file, pkg_dir) if pipeline_file
                              else pipeline_name),
            "expands_dotted": bool(pipeline_file) and _pipeline_expands_dotted_keys(pipeline_file),
        })
    return out


_CATALOG_LATEST_CACHE: Dict[str, List[Dict[str, Any]]] = {}
_CATALOG_STREAMS_CACHE: Dict[str, List[Tuple[str, str, str]]] = {}


def catalog_latest_transforms(packages_root: str) -> List[Dict[str, Any]]:
    """Every package's `latest` transforms under `packages_root`, tagged with the owner.

    A `latest` transform in one package can read another package's data stream, and
    that stream is the one whose opt-in changes the transform's output, so the finding
    has to land there, not only in the owner's report. Read once per run.
    """
    root = os.path.abspath(packages_root)
    if root in _CATALOG_LATEST_CACHE:
        return _CATALOG_LATEST_CACHE[root]
    out: List[Dict[str, Any]] = []
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            pkg_dir = os.path.join(root, name)
            if not os.path.isdir(os.path.join(pkg_dir, "elasticsearch", "transform")):
                continue
            for tr in latest_transforms(pkg_dir):
                out.append(dict(tr, package=name))
    _CATALOG_LATEST_CACHE[root] = out
    return out


def pattern_could_match_package(pattern: str, pkg: str) -> bool:
    """Cheap pre-check: could this index pattern match a logs stream of `pkg`?

    Compares the pattern's literal prefix (up to the first wildcard) with
    `logs-<pkg>`; exact glob matching per stream happens later.
    """
    literal = strip_cluster(pattern).split("*", 1)[0].split("?", 1)[0]
    if not literal or literal.startswith("-"):
        return not literal
    target = f"logs-{pkg}"
    return target.startswith(literal) or literal.startswith(target)


def catalog_stream_index_names(packages_root: str) -> List[Tuple[str, str, str]]:
    """(package, data stream, index name) for every in-scope logs stream under the root.

    Only needed to say where a transform that reads no stream of its own package is
    flagged, so it is built lazily, once per run. Mirrors the scope rules of
    `audit_data_stream`: `type: logs`, and no OpenTelemetry input.
    """
    root = os.path.abspath(packages_root)
    if root in _CATALOG_STREAMS_CACHE:
        return _CATALOG_STREAMS_CACHE[root]
    out: List[Tuple[str, str, str]] = []
    if os.path.isdir(root):
        for pkg in sorted(os.listdir(root)):
            ds_root = os.path.join(root, pkg, "data_stream")
            if not os.path.isdir(ds_root):
                continue
            for ds in sorted(os.listdir(ds_root)):
                path = os.path.join(ds_root, ds, "manifest.yml")
                if not os.path.isfile(path):
                    continue
                try:
                    manifest = load_yaml(path) or {}
                except RuntimeError:
                    continue
                if not isinstance(manifest, dict) or manifest.get("type") != "logs":
                    continue
                inputs = {s.get("input") for s in (manifest.get("streams") or [])
                          if isinstance(s, dict)}
                if inputs & OTEL_INPUTS:
                    continue
                out.append((pkg, ds, stream_index_name("logs", pkg, ds, manifest)))
    _CATALOG_STREAMS_CACHE[root] = out
    return out


def latest_transform_findings(index_name: str, transforms: List[Dict[str, Any]],
                              current_pkg: Optional[str] = None) -> List[Dict[str, Any]]:
    """`source_consumer_latest_transform` for the latest transforms reading this stream.

    `transforms` holds the package's own transforms and, tagged with `package`, the
    ones other packages own; `current_pkg` is the audited package's directory name.
    """
    out: List[Dict[str, Any]] = []
    for tr in transforms:
        if not any(index_pattern_matches(p, index_name) for p in tr["patterns"]):
            continue
        owner = tr.get("package")
        foreign = bool(owner) and owner != current_pkg
        subject = (f"The `{owner}` package's `{tr['name']}` transform" if foreign
                   else f"The `{tr['name']}` transform")
        keys = ", ".join(f"`{k}`" for k in tr["unique_key"]) or "unique key"
        # A resolved pipeline is a path inside the owner package; say which package.
        pipe_ref = tr["dest_pipeline"]
        if foreign and pipe_ref and "/" in pipe_ref:
            pipe_ref = f"packages/{owner}/{pipe_ref}"
        if tr["dest_pipeline"] and not tr["expands_dotted"]:
            pipeline = (f" Its destination pipeline `{pipe_ref}` addresses fields "
                        f"by path, so its processors will not find the dotted keys: `rename`, "
                        f"`set` and `remove` with `ignore_missing` skip silently, and scripts "
                        f"see `ctx.<object>` as null.")
        elif tr["dest_pipeline"]:
            pipeline = (f" Its destination pipeline `{pipe_ref}` already expands "
                        f"dotted keys, so only the array shapes change.")
        else:
            pipeline = ""
        out.append(finding(
            "source_consumer_latest_transform", "C", "review",
            f"{subject} is a `latest` transform: for each {keys} it "
            f"copies the newest document's `_source` into `{tr['dest_index']}`. On a "
            f"columnar source that `_source` is rebuilt flat (dotted keys, object arrays "
            f"as parallel arrays, single-element arrays as plain values), so the "
            f"destination documents change shape.{pipeline}",
            "Start the destination pipeline with `dot_expander` and `field: \"*\"` (a no-op "
            "on logsdb input), or set `field_access_pattern: flexible` on it. Check that no "
            "consumer of the destination index depends on object-array pairing or reads its "
            "`_source`. Then run the transform on this stream in both modes and diff the "
            "destination documents. Pivot transforms are unaffected: they aggregate from "
            "doc values."
            + (f" The fix belongs in the `{owner}` package, which owns the transform; "
               f"coordinate with its owners before this stream declares readiness."
               if foreign else ""),
            f"packages/{owner}/{tr['file']}" if foreign else tr["file"],
            line=tr.get("line")))
        # A resolved pipeline file that does not expand dotted keys yet gets the exact
        # processor to add, in the owner's file.
        if tr["dest_pipeline"] and "/" in tr["dest_pipeline"] and not tr["expands_dotted"]:
            is_json = tr["dest_pipeline"].endswith(".json")
            out[-1]["patch"] = patch(
                pipe_ref, "as the first entry under `processors:`",
                DOT_EXPANDER_JSON if is_json else DOT_EXPANDER_YAML,
                lang="json" if is_json else "yaml",
                note="Or set `field_access_pattern: flexible` at the top level of the pipeline. "
                     "Test it with `_ingest/pipeline/_simulate`: the same document sent nested "
                     "and with dotted keys must give the same output.")
    return out
