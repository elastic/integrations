"""Columnar `_source` consumers: access patterns, Kibana assets, object arrays."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .common import finding
from .ecs import ecs_schema
from .pipelines import PIPELINE_TEMP_ROOTS


# --------------------------------------------------------------------------- #
# Columnar `_source` consumers (Class C — `references/blockers.md` C6-C10)
#
# Columnar never stores the original JSON. What comes back as `_source` is
# reconstructed from doc values, and it is NOT a faithful copy:
#
#   * object arrays under a non-`nested` object are flattened into parallel
#     arrays — `[{a:1,b:2},{a:3,b:4}]` reads back as `{a:[1,3], b:[2,4]}`
#     (multi-value order within a field IS preserved);
#   * the hierarchy a consumer walked is therefore not the hierarchy it gets.
#
# Who cares, and who does not:
#
#   * ingest pipelines: NOT affected. They run before indexing, on the real
#     document, so nothing here flags them.
#   * transforms, Kibana runtime/scripted fields, anything reading `params._source`
#     or `ctx._source`: affected, because they run at query time on the
#     reconstructed source.
#   * ES|QL: mostly unaffected — it reads doc values — unless the query explicitly
#     asks for `METADATA _source` (and then usually picks it apart with
#     `JSON_EXTRACT(_source, ...)`).
#   * dashboards, alerting rules and detection rules that query *fields*: unaffected.
#
# `doc[...]` is not a `_source` consumer. A runtime field that only reads doc values
# behaves identically in columnar — doc values are precisely what columnar keeps — so
# the three ml-module assets in the catalog that define `runtime_mappings`
# (`dga`, `lmd`, `problemchild`) are deliberately NOT reported.
# --------------------------------------------------------------------------- #

# `_source` as a *token*. The negative look-behind is what keeps the three false
# positives a naive substring search finds in the catalog out: `low_source_bytes`
# and `mean_source_bytes` (`beaconing`), `avg_source_bytes` (`ded`) and
# `labels.is_ioc_transform_source` (`ti_rapid7_threat_command`) all contain the
# letters `_source` and none of them touches the document source.
_SOURCE_ACCESS_PATTERNS = [
    (re.compile(r"""params\s*\.\s*_source\b|params\s*\[\s*['"]_source['"]\s*\]"""),
     "params._source"),
    (re.compile(r"""ctx\s*\.\s*_source\b|ctx\s*\[\s*['"]_source['"]\s*\]"""),
     "ctx._source"),
    (re.compile(r"(?i)json_extract\s*\(\s*_source\b"), "JSON_EXTRACT(_source, ...)"),
    (re.compile(r"(?<![A-Za-z0-9])_source\s*[.\[]"), "_source field access"),
]

# ES|QL `FROM ... METADATA _source`, the one way an ES|QL query does depend on the
# `_source` shape.
_ESQL_METADATA_SOURCE_RE = re.compile(r"(?i)metadata\s+[^|\n\"]{0,80}?_source\b")

# Kibana scripted fields (deprecated, and none are left in this catalog) in an
# index-pattern / data-view saved object, in both the plain and the
# embedded-JSON-string spelling.
_KIBANA_SCRIPTED_FIELD_RE = re.compile(
    r"""\\?"scriptedFields\\?"|\\?"scripted\\?"\s*:\s*true""")


def source_access_hits(text: str, limit: int = 3) -> List[Tuple[str, str]]:
    """[(label, excerpt)] for every distinct way `text` reads the document source.

    One hit per pattern, and the catch-all `_source.` / `_source[` pattern is only
    reported when nothing more specific matched — `params._source.foo` is one finding,
    not two.
    """
    hits: List[Tuple[str, str]] = []
    generic: List[Tuple[str, str]] = []
    for regex, label in _SOURCE_ACCESS_PATTERNS + [
            (_ESQL_METADATA_SOURCE_RE, "ES|QL METADATA _source")]:
        match = regex.search(text)
        if not match:
            continue
        entry = (label, _excerpt(text, match.start(), match.end()))
        if label == "_source field access":
            generic.append(entry)
        else:
            hits.append(entry)
    return (hits or generic)[:limit]


def _excerpt(text: str, start: int, end: int, pad: int = 60) -> str:
    """A one-line, whitespace-collapsed window around a match."""
    chunk = text[max(0, start - pad):end + pad]
    chunk = re.sub(r"\s+", " ", chunk).strip()
    return (chunk[:160] + ("…" if len(chunk) > 160 else "")).replace("`", "'")


# --------------------------------------------------------------------------- #
# Kibana assets
# --------------------------------------------------------------------------- #

def kibana_source_consumers(texts: List[Tuple[str, str]],
                            limit: int = 12) -> List[Dict[str, Any]]:
    """Kibana saved objects that read `_source` — scripts, runtime fields, ES|QL.

    `texts` is [(relative path, file text)]; the caller reads every `kibana/*.json`
    once and hands the text to both this and the dashboard field counters.
    """
    out: List[Dict[str, Any]] = []
    for rel, text in texts:
        if len(out) >= limit:
            break
        hits: List[Tuple[str, str]] = []
        if "_source" in text:
            hits.extend(source_access_hits(text))
        match = _KIBANA_SCRIPTED_FIELD_RE.search(text)
        if match:
            hits.append(("scripted field",
                         _excerpt(text, match.start(), match.end())))
        if hits:
            out.append({"file": rel, "hits": hits[:3]})
    return out


# --------------------------------------------------------------------------- #
# Object arrays in the package's own example documents
# --------------------------------------------------------------------------- #

# Docs to read per data stream, and how much of them. `_dev/test/pipeline` is 104 MB
# across the catalog, so it is sampled rather than read whole: an object array shows
# up in the first documents or not at all.
_EXPECTED_FILES_PER_STREAM = 4
_EXPECTED_FILE_MAX_BYTES = 2_000_000
_EXPECTED_DOCS_PER_FILE = 10

# Types whose JSON value is an object (or an array of them) without being an object
# *array* in the flattening sense.
_NON_OBJECT_ARRAY_TYPES = {"nested", "flattened", "geo_point", "object_from_dotted"}


def _object_array_paths(doc: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None,
                        depth: int = 0) -> Dict[str, Any]:
    """field path -> the array value, for every field holding an array of objects.

    Does not descend into the array: the flattening happens at the outermost object
    array, and reporting its children as well would say the same thing three times.
    """
    if out is None:
        out = {}
    if depth > 12 or not isinstance(doc, dict):
        return out
    for key, value in doc.items():
        if not isinstance(key, str) or key.startswith("_"):
            continue
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, list):
            if any(isinstance(item, dict) for item in value):
                out.setdefault(path, value)
        elif isinstance(value, dict):
            _object_array_paths(value, path, out, depth + 1)
    return out


def _object_array_exemption(path: str, field_index: Dict[str, Dict[str, Any]]
                            ) -> Optional[Tuple[str, str]]:
    """(reason, owning field) when `path` is not reported, None when it is.

    `nested` is reported by `nested_single_level` / `nested_in_nested`, `flattened`
    keeps its JSON verbatim, and a `geo_point` array is a list of coordinates rather
    than an object array.

    The caller collects the `flattened` ones so the report can name them. That
    matters for reading a negative result: the field really does hold an array of
    objects, and "checked, exempt because it is `flattened`" is a different statement
    from "no object arrays anywhere".
    """
    parts = path.split(".")
    if parts[0] in PIPELINE_TEMP_ROOTS:
        return ("pipeline_scratch", parts[0])  # not an indexed field
    for i in range(1, len(parts) + 1):
        ancestor = ".".join(parts[:i])
        fdef = field_index.get(ancestor)
        if fdef is not None:
            ftype = fdef.get("type") or fdef.get("object_type")
            if ftype in ("nested", "flattened"):
                return (ftype, ancestor)
            if ancestor == path and ftype == "geo_point":
                return ("geo_point", ancestor)
        ecs_type = (ecs_schema().get(ancestor) or {}).get("type")
        if ecs_type in ("nested", "flattened", "geo_point"):
            return (ecs_type, ancestor)
    return None


def object_array_findings(ds_dir: str, ds_name: str, field_index: Dict[str, Dict[str, Any]],
                          sample: Dict[str, Any],
                          flattened_exempt: Optional[set] = None) -> List[Dict[str, Any]]:
    """`object_array_flattening` — one finding per data stream, not per field.

    `flattened_exempt`, when given, is filled with the `flattened` fields that hold an
    object array in the sampled documents and are therefore *not* findings — the
    report lists them, so a reader can tell "exempt" from "not looked at".
    """
    docs: List[Tuple[str, Dict[str, Any]]] = []
    if sample:
        docs.append(("sample_event.json", sample))
    test_dir = os.path.join(ds_dir, "_dev", "test", "pipeline")
    if os.path.isdir(test_dir):
        expected = sorted(f for f in os.listdir(test_dir) if f.endswith("-expected.json"))
        for fname in expected[:_EXPECTED_FILES_PER_STREAM]:
            path = os.path.join(test_dir, fname)
            try:
                if os.path.getsize(path) > _EXPECTED_FILE_MAX_BYTES:
                    continue
                with open(path, "r", encoding="utf-8") as fh:
                    parsed = json.load(fh)
            except (OSError, ValueError):
                continue
            entries = parsed.get("expected") if isinstance(parsed, dict) else None
            for entry in (entries or [])[:_EXPECTED_DOCS_PER_FILE]:
                if isinstance(entry, dict):
                    docs.append((f"_dev/test/pipeline/{fname}", entry))

    found: Dict[str, Tuple[str, Any]] = {}
    for where, doc in docs:
        for path, value in _object_array_paths(doc).items():
            if path in found:
                continue
            exemption = _object_array_exemption(path, field_index)
            if exemption is not None:
                kind, owner = exemption
                if kind == "flattened" and flattened_exempt is not None:
                    flattened_exempt.add(owner)
                continue
            found[path] = (where, value)
    if not found:
        return []

    paths = sorted(found)
    shown = paths[:6]
    listed = "; ".join(f"`{p}` ({found[p][0]})" for p in shown)
    if len(paths) > len(shown):
        listed += f"; and {len(paths) - len(shown)} more"
    first = paths[0]
    example = json.dumps(found[first][1], sort_keys=True)
    if len(example) > 120:
        example = example[:120] + "…"
    return [finding(
        "object_array_flattening", "C", "info",
        f"{len(paths)} object field(s) hold an **array of objects** in this package's "
        f"own example documents: {listed}. Example — `{first}` = `{example}`. Columnar "
        f"`_source` flattens these into parallel arrays "
        f"(`[{{a:1,b:2}},{{a:3,b:4}}]` reads back as `{{a:[1,3], b:[2,4]}}`; multi-value "
        f"order is preserved, the association between one element's leaves is not). "
        f"See `references/blockers.md` C8.",
        "No mapping change is required and this is not a blocker: dashboards, alerting "
        "rules and ES|QL that query the **leaf fields** are unaffected, and so are "
        "ingest pipelines (they run before indexing). What changes is what a `_source` "
        "reader sees — a transform or runtime field using `params._source`, Kibana code "
        "walking `_source`, an ES|QL query with `METADATA _source`, or a user reading "
        "the JSON in Discover. Confirm those consumers before declaring the package "
        "`logsdb_columnar`; mapping the field as `nested` does not restore the shape "
        "either (see `nested_single_level`).",
        f"data_stream/{ds_name}/sample_event.json", first)]


def source_consumer_findings(ds_name: str, transforms: List[Dict[str, Any]],
                             kibana: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """`source_consumer_transform` / `source_consumer_kibana` for one data stream.

    Both are package-level artifacts. A transform is attached to the data streams its
    `source.index` names; one that reads another package's indices (`beaconing` reads
    `logs-endpoint.events.network-*`) is attached to every logs stream, because its
    own package is where the fix would be discussed. Kibana assets are not attributable
    to a single stream at all, so they are attached to all of them.
    """
    out: List[Dict[str, Any]] = []
    for tr in transforms:
        if tr["streams"] and ds_name not in tr["streams"]:
            continue
        detail = "; ".join(f"`{where}` reads `{label}` — `{excerpt}`"
                           for where, label, excerpt in tr["hits"])
        scope = (f"its source index is `{', '.join(tr['streams'])}`" if tr["streams"]
                 else "its source index is outside this package")
        out.append(finding(
            "source_consumer_transform", "C", "review",
            f"The `{tr['name']}` transform reads the document `_source` in a script "
            f"({scope}): {detail}. A transform runs at **query time** against the "
            f"source Elasticsearch reconstructs, so on a columnar index it sees the "
            f"flattened shape — nested objects collapsed, object arrays turned into "
            f"parallel arrays — not the document the ingest pipeline produced.",
            "Rewrite the script to read doc values (`doc['field']`) or the aggregated "
            "fields instead of `_source`, or confirm against a real columnar index that "
            "the transform still produces the same destination documents. Ingest "
            "pipelines need no change — they run before indexing.",
            tr["file"]))
    for asset in kibana:
        detail = "; ".join(f"{label} — `{excerpt}`" for label, excerpt in asset["hits"])
        out.append(finding(
            "source_consumer_kibana", "C", "review",
            f"`{asset['file']}` consumes the document `_source`: {detail}. Kibana "
            f"runtime fields, scripted fields and ES|QL queries that ask for "
            f"`METADATA _source` all read the source Elasticsearch reconstructs, which "
            f"on a columnar index is flattened and is not the original JSON.",
            "Check the expression against a columnar index. A runtime field that only "
            "reads `doc['field']` needs no change — doc values are exactly what columnar "
            "keeps — and plain ES|QL is unaffected; it is `params._source`, `ctx._source` "
            "and `METADATA _source` (usually with `JSON_EXTRACT(_source, ...)`) that see "
            "the flattened shape. Move the logic onto doc values or onto the mapped "
            "fields where possible.",
            asset["file"]))
    return out
