"""Field-tree walking and the mapping checks."""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Tuple

from .common import finding, is_false, is_true, line_of
from .constants import ECS_DOC_VALUES_FALSE, FIELD_CHILD_KEYS, UNSUPPORTED_TYPES
from .patches import patch


def walk_fields(defs: Any, prefix: str = "", nested_depth: int = 0,
                in_multi_field: bool = False) -> Iterator[Tuple[Dict[str, Any], str, int, bool]]:
    """Yield (field_def, flat_name, ancestor_nested_depth, in_multi_field).

    `ancestor_nested_depth` counts `type: nested` ancestors, excluding the field itself.
    """
    if not isinstance(defs, list):
        return
    for fdef in defs:
        if not isinstance(fdef, dict):
            continue
        name = fdef.get("name")
        flat = f"{prefix}.{name}" if prefix and name else (name or prefix)
        if not isinstance(flat, str):
            continue
        yield fdef, flat, nested_depth, in_multi_field

        child_depth = nested_depth + 1 if fdef.get("type") == "nested" else nested_depth
        for key in FIELD_CHILD_KEYS:
            if key in fdef:
                yield from walk_fields(fdef[key], flat, child_depth, in_multi_field)
        if "multi_fields" in fdef:
            yield from walk_fields(fdef["multi_fields"], flat, child_depth, True)


def has_runtime(fdef: Dict[str, Any]) -> bool:
    """Mapping-level runtime field: `runtime: true` or a `runtime:` script block."""
    runtime = fdef.get("runtime")
    if runtime is None or runtime is False:
        return False
    if isinstance(runtime, bool):
        return runtime
    if isinstance(runtime, str):
        return runtime.strip().lower() != "false"
    return bool(runtime)  # dict / mapping with a script


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

# The field attribute each check_field finding is about, so `file:line` points at it
# (`doc_values: false`, not the `- name:` line). Codes not listed use the entry line.
CODE_KEYS = {
    "copy_to": "copy_to",
    "doc_values_false": "doc_values",
    "doc_values_false_ecs": "external",
    "dynamic_false_field": "dynamic",
    "dynamic_runtime": "dynamic",
    "enabled_false": "enabled",
    "keyword_normalizer": "normalizer",
    "keyword_normalizer_lowercase": "normalizer",
    "nested_in_nested": "type",
    "nested_single_level": "type",
    "runtime_field": "runtime",
    "store_true": "store",
    "unsupported_type": "type",
}


# `doc_values: false` and `store: true` are not package fixes: per the package-spec#1250
# review the spec has no field-level override for them, and Fleet drops them from the
# generated mappings when it installs a data stream in logsdb_columnar mode
# (elastic/kibana#292285, tracked in elastic/kibana#296252). Elasticsearch itself still
# rejects both, so the finding stays visible as a dependency on that Fleet release.
PLATFORM_PENDING = (
    "No package change. Elasticsearch rejects {what} in columnar modes and the spec has "
    "no field-level override for it (package-spec#1250 review); Fleet drops {what} from "
    "the generated mappings when it installs this data stream in `logsdb_columnar` mode "
    "(elastic/kibana#292285, tracked in elastic/kibana#296252). The stream can go "
    "columnar with that Fleet release; do not mark it `logsdb_columnar: unsupported` "
    "for this reason."
)


def check_field(fdef: Dict[str, Any], flat: str, nested_depth: int,
                in_multi_field: bool, rel_file: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    ftype = fdef.get("type")

    # --- Class A: rejected by Elasticsearch -------------------------------- #
    if ftype == "nested":
        if nested_depth >= 1:
            # `nested_depth` counts nested ancestors both through `fields:` children and
            # through dotted names declared as sibling entries (`whats` nested, then a
            # separate `whats.intel_intra_ids` nested): Fleet expands the dotted names
            # into the same hierarchy, so both are nested inside nested.
            out.append(finding(
                "nested_in_nested", "A", "blocker",
                f"`{flat}` is a `nested` field inside another `nested` field. Columnar "
                f"supports one level of nesting only (`NestedObjectMapper`: \"columnar "
                f"index modes support only a single level of nesting\"), so the index "
                f"template PUT fails.",
                "First check that no dashboard or detection rule runs a `nested` query on "
                "this inner path. Then, in order of preference: (1) map the inner level as "
                "`type: flattened`: every value is kept and stays with its outer element in "
                "both modes, but its sub-fields become untyped keywords (no numeric ranges "
                "or sums; ES|QL reads them with `FIELD_EXTRACT`) and matching within one "
                "inner element is lost; (2) `type: group` keeps the types, but columnar "
                "indexes each inner object apart from its outer element unless the ingest "
                "pipeline sends them as dotted keys (`nested_object_children`), so take it "
                "only together with that pipeline change; (3) if the pairing inside each "
                "inner element matters, build a single-level `nested` array in the ingest "
                "pipeline, one entry per (outer, inner) pair carrying both sets of keys. All "
                "three change the mapping for logsdb installs too. On an existing data stream the type "
                "change takes effect at the next rollover: Fleet rolls the stream over when "
                "the write index rejects the mapping (\"can't merge a non-nested mapping "
                "... with a nested mapping\"). Or keep this stream on LogsDB: mark it "
                "`elasticsearch.logsdb_columnar: unsupported` in its manifest.",
                rel_file, flat))
            children = [str(c.get("name")) for c in fdef.get("fields") or []
                        if isinstance(c, dict) and c.get("name")]
            shown = ", ".join(children[:6]) + (", …" if len(children) > 6 else "")
            out[-1]["patch"] = patch(
                rel_file, f"the definition of `{flat}`",
                f"- name: {fdef.get('name', flat)}\n"
                "  type: flattened   # was: nested (columnar allows one level of nesting)\n"
                "  # keep its description; drop its `fields:` children"
                + (f" ({shown})" if shown else "") + ":\n"
                "  # a flattened field declares none\n",
                note="Mapping-only: the documents do not change, and the values stay with their "
                     "outer element in both modes. `type: group` would keep their types, but "
                     "columnar then detaches the inner objects from their outer element unless "
                     "the pipeline sends them as dotted keys (`nested_object_children`). Check "
                     "first that nothing runs a `nested` query on this path, or a numeric or "
                     "date query on its sub-fields.")
        else:
            # Single-level nested is supported; per the package-spec#1250 review this is
            # only a note for `_source` consumers that expect the original structure.
            out.append(finding(
                "nested_single_level", "C", "info",
                f"`{flat}` is a single-level `nested` field.",
                "Supported by columnar mode. Note for `_source` consumers that expect the "
                "original structure: they get the columnar shape (objects inside an element "
                "are a separate case: `nested_object_children`).",
                rel_file, flat))

    # Multi-fields are exempt from the reconstructability check
    # (`MappingLookup#firstFieldNotReconstructableFromDocValues` skips
    # `isMultiField(...)`), so only top-level fields matter here.
    if is_false(fdef.get("doc_values")) and not in_multi_field:
        out.append(finding(
            "doc_values_false", "A", "platform",
            f"`{flat}` sets `doc_values: false`; columnar mode cannot reconstruct it, and "
            f"Elasticsearch rejects the mapping today.",
            PLATFORM_PENDING.format(what="`doc_values: false`"),
            rel_file, flat))

    if is_true(fdef.get("store")):
        out.append(finding(
            "store_true", "A", "platform",
            f"`{flat}` sets `store: true`, which Elasticsearch rejects in columnar modes "
            f"(`[store] cannot be enabled on field [...] in [logsdb_columnar] index mode`).",
            PLATFORM_PENDING.format(what="`store: true` (the review suggests the same "
                                         "handling as for `doc_values: false`)"),
            rel_file, flat))

    if fdef.get("copy_to") is not None:
        # Rejected at mapping-parse time, with no multi-field exemption:
        # `FieldMapper.TypeParser#parse` throws for `copy_to` under `isStrictColumnar()`,
        # and `copy_to` from/to a multi-field is refused independently in
        # `FieldMapper#validate`.
        out.append(finding(
            "copy_to", "A", "auto_fix",
            f"`{flat}` uses `copy_to`, which columnar mode rejects unconditionally.",
            "Do the copy in the ingest pipeline — the suggested `script` processor appends "
            "to the targets the way `copy_to` does, keeping arrays and types — then delete "
            "`copy_to` from the field; or drop the target field.",
            rel_file, flat))

    if ftype == "keyword" and fdef.get("normalizer") and not in_multi_field:
        # A normalizer only forces FALLBACK synthetic source when the original value
        # cannot be recovered. For `normalizer: lowercase` Elasticsearch defaults
        # `normalizer_skip_store_original_value` to true (KeywordFieldMapper.Builder),
        # so synthetic source stays Native — lossy (lowercased), but accepted.
        if str(fdef.get("normalizer")).strip() == "lowercase":
            out.append(finding(
                "keyword_normalizer_lowercase", "C", "info",
                f"`{flat}` is a keyword with `normalizer: lowercase`; accepted by columnar "
                f"mode, but synthetic source returns the lowercased value, not the "
                f"original casing.",
                "No change required. If the original casing must survive a read, move the "
                "normalized variant into `multi_fields:` and keep the parent raw.",
                rel_file, flat))
        else:
            out.append(finding(
                "keyword_normalizer", "A", "auto_fix",
                f"`{flat}` is a keyword with `normalizer: {fdef.get('normalizer')}`, which "
                f"is not the built-in `lowercase` normalizer, so the original value cannot "
                f"be recovered from doc values and the field falls back to stored source.",
                "Apply the transformation in the ingest pipeline and map a plain `keyword`; "
                "or move the normalized variant into `multi_fields:` (multi-fields are "
                "exempt from the reconstructability check).",
                rel_file, flat))
            out[-1]["patch"] = patch(
                rel_file, f"the definition of `{flat}`",
                f"- name: {fdef.get('name', flat)}\n"
                "  type: keyword   # the parent keeps the raw value\n"
                "  multi_fields:\n"
                "    - name: normalized\n"
                "      type: keyword\n"
                f"      normalizer: {fdef.get('normalizer')}\n",
                note="Keep the field's other attributes. Queries that relied on the normalized "
                     "comparison move to `<field>.normalized`. If the original value is not "
                     "needed, normalize in the pipeline instead (`lowercase`, `trim`, `gsub`).")

    if str(fdef.get("dynamic", "")).strip().lower() == "runtime":
        out.append(finding(
            "dynamic_runtime", "A", "auto_fix",
            f"`{flat}` sets `dynamic: runtime`, which columnar mode rejects at "
            f"**mapping-parse time**: `ObjectMapper` refuses the value outright "
            f"(`dynamic [runtime] is not supported in strict columnar mode`), so the "
            f"index template PUT fails and the data stream is never created. It does "
            f"not wait for a document with an unknown field.",
            "Use `dynamic: true` (unmapped leaves become non-indexed doc values — cheap "
            "under columnar mode), or map the sub-fields explicitly.",
            rel_file, flat))

    if has_runtime(fdef):
        out.append(finding(
            "runtime_field", "A", "review",
            f"`{flat}` is a mapping-level runtime field, which columnar mode rejects.",
            "Compute a concrete field with a `script` processor in the ingest pipeline, or "
            "move the logic to query time (ES|QL `EVAL`, or a search-request runtime field).",
            rel_file, flat))

    if ftype in UNSUPPORTED_TYPES:
        out.append(finding(
            "unsupported_type", "A", "blocker",
            f"`{flat}` has type `{ftype}`, which has no doc values.",
            "Remap to a type with doc values. (Defensive check: the package-spec type enum "
            "does not currently allow this type.)",
            rel_file, flat))

    # --- Class B: accepted but lossy --------------------------------------- #
    if is_false(fdef.get("dynamic")):
        out.append(finding(
            "dynamic_false_field", "B", "review",
            f"`{flat}` sets `dynamic: false`; unmapped sub-fields are permanently lost.",
            "Confirm the unmapped fields are expendable, add explicit mappings, switch to "
            "`dynamic: true` (unmapped leaves become non-indexed doc values), or "
            "`dynamic: strict` so unexpected documents go to the failure store.",
            rel_file, flat))

    if is_false(fdef.get("enabled")):
        out.append(finding(
            "enabled_false", "B", "review",
            f"`{flat}` sets `enabled: false`; its contents are never stored.",
            "Change to `type: flattened`, or map the sub-fields explicitly.",
            rel_file, flat))

    # --- ECS-inherited attributes ------------------------------------------ #
    # `external: ecs` imports `index` and `doc_values` from the ECS schema, so the
    # built package can carry `doc_values: false` that the source never declares.
    if fdef.get("external") == "ecs" and flat in ECS_DOC_VALUES_FALSE and not in_multi_field:
        # Only an explicit `doc_values: true` in the package overrides the imported
        # value: elastic-package merges with `transformed.DeepUpdate(def)`, so package
        # attributes win.
        if not is_true(fdef.get("doc_values")):
            out.append(finding(
                "doc_values_false_ecs", "A", "platform",
                f"`{flat}` is imported from ECS, which defines it with `doc_values: false`; "
                f"elastic-package copies that into the built package.",
                PLATFORM_PENDING.format(what="`doc_values: false` (also when it is "
                                             "imported from ECS)"),
                rel_file, flat))

    for f in out:
        f["line"] = line_of(fdef, CODE_KEYS.get(f["code"]))
    return out


def nested_object_children(entries: List[Tuple[Dict[str, Any], str, int, bool, str, str]]
                           ) -> List[Dict[str, Any]]:
    """`nested_object_children`: single-level `nested` fields whose elements hold objects.

    Columnar indexes an object sent as JSON inside a nested element as a nested document
    of its own, detached from the element's other fields (seen on 9.5.4 and on 9.6
    snapshots up to 2026-10-01; logsdb is not affected; dotted keys are not affected).
    `entries` are every field of the stream (`read_field_files`), so objects declared
    through `fields:` and through dotted names both count. Inner `nested` levels are
    `nested_in_nested`, and `flattened` children are exempt: both are skipped.
    """
    fields = [(fdef, flat, rel_file) for fdef, flat, _, in_mf, rel_file, _ in entries if not in_mf]
    types = {flat: fdef.get("type") for fdef, flat, _ in fields}
    nested = sorted(p for p, t in types.items() if t == "nested")
    out: List[Dict[str, Any]] = []
    for path in nested:
        if any(path.startswith(o + ".") for o in nested):
            continue
        inner = [p for p in nested if p.startswith(path + ".")]
        objects = set()
        for flat in types:
            if not flat.startswith(path + ".") or any(
                    flat == q or flat.startswith(q + ".") for q in inner):
                continue
            rel = flat[len(path) + 1:]
            head = rel.split(".", 1)[0]
            if types.get(f"{path}.{head}") == "flattened":
                continue
            if "." in rel or types.get(flat) in ("group", "object"):
                objects.add(head)
        if not objects:
            continue
        fdef, _, rel_file = next(e for e in fields if e[1] == path)
        names = sorted(objects)
        shown = ", ".join(f"`{n}`" for n in names[:4]) + (", …" if len(names) > 4 else "")
        out.append(finding(
            "nested_object_children", "C", "review",
            f"`{path}` is `nested` and its elements hold objects ({shown}). On columnar, an "
            f"object sent as JSON inside a nested element is indexed as a nested document of "
            f"its own, detached from the element's other fields (seen on 9.5.4 and on 9.6 "
            f"snapshots up to 2026-10-01; logsdb is not affected). A `nested` query that "
            f"combines `{path}.<field>` with `{path}.{names[0]}.<field>` stops matching, and "
            f"`_source` returns those objects as separate array elements. Values sent as "
            f"dotted keys are not affected.",
            "Pick one and record it in the PR: (1) send the objects as dotted keys from the "
            "ingest pipeline (the suggested change, checked on both modes): `nested` queries "
            "keep matching, and logsdb rebuilds plain objects in `_source` from the mapping, "
            "though an array of objects inside an element comes back as one array per leaf; "
            "(2) accept it, when nothing combines an element's own fields with these objects "
            "in one `nested` query and nothing reads this part of `_source`; (3) map the "
            "objects as `type: flattened`, which keeps them with their element but makes "
            "their sub-fields untyped keywords; (4) keep the stream on LogsDB until "
            "Elasticsearch fixes it: mark it `elasticsearch.logsdb_columnar: unsupported`.",
            rel_file, path, line=line_of(fdef, "type")))
    return out


def check_stream_manifest(manifest: Dict[str, Any], rel_file: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    es = manifest.get("elasticsearch") or {}
    if not isinstance(es, dict):
        return out

    # Note: `elasticsearch.source_mode` is not checked here. Its package-spec enum is
    # `default | synthetic` only, so there is no `stored` value to catch, and neither
    # value conflicts with columnar mode. Stored `_source` can still be requested
    # through the raw index template mappings below.

    itpl = es.get("index_template") or {}
    if not isinstance(itpl, dict):
        return out
    mappings = itpl.get("mappings") or {}
    if not isinstance(mappings, dict):
        return out

    source = mappings.get("_source") or {}
    if isinstance(source, dict):
        if is_false(source.get("enabled")):
            out.append(finding(
                "source_disabled", "A", "blocker",
                "`_source.enabled: false` is incompatible with columnar mode.",
                "Remove the `_source` override.", rel_file, line=line_of(source, "enabled")))
        if source.get("mode") == "stored":
            out.append(finding(
                "source_mode_stored", "A", "blocker",
                "`_source.mode: stored` is incompatible with columnar mode.",
                "Remove the `_source` override.", rel_file, line=line_of(source, "mode")))

    if is_false(mappings.get("dynamic")):
        out.append(finding(
            "dynamic_false_manifest", "B", "review",
            "`elasticsearch.index_template.mappings.dynamic: false`; with no stored `_source`, "
            "every unmapped field in this data stream is permanently lost.",
            "Confirm the unmapped fields are expendable, add explicit mappings, or switch to "
            "`dynamic: true` / `dynamic: strict`.",
            rel_file, line=line_of(mappings, "dynamic")))

    if str(mappings.get("dynamic", "")).strip().lower() == "runtime":
        out.append(finding(
            "dynamic_runtime", "A", "auto_fix",
            "`elasticsearch.index_template.mappings.dynamic: runtime` is rejected when the "
            "mapping is parsed (`ObjectMapper`: `dynamic [runtime] is not supported in "
            "strict columnar mode`) — the index template PUT fails, before any document "
            "is indexed.",
            "Use `dynamic: true` (unmapped leaves become non-indexed doc values) or map the "
            "fields explicitly.",
            rel_file, line=line_of(mappings, "dynamic")))

    dts = mappings.get("dynamic_templates")
    if dts:
        if _contains_dynamic_false(dts):
            out.append(finding(
                "dynamic_false_template", "B", "review",
                "A `dynamic_templates` entry sets `dynamic: false`; objects it matches lose "
                "their unmapped sub-fields.",
                "Review the template; prefer `dynamic: true` or explicit mappings.",
                rel_file, line=line_of(mappings, "dynamic_templates")))
    return out


def _contains_dynamic_false(node: Any) -> bool:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "dynamic" and is_false(value):
                return True
            if _contains_dynamic_false(value):
                return True
    elif isinstance(node, list):
        return any(_contains_dynamic_false(item) for item in node)
    return False
