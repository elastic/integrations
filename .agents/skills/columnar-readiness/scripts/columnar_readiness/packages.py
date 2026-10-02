"""Package and data stream audit."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from .common import finding, is_true, load_yaml, worse
from .constants import COLUMNAR_INDEX_MODES, OTEL_INPUTS, TEXT_TYPES
from .consumers import object_array_findings, source_consumer_findings
from .ecs import ecs_schema
from .fields import check_field, check_stream_manifest, walk_fields
from .kibana import scan_kibana_assets
from .patches import attach_pipeline_patches
from .pipelines import scan_pipelines
from .rules import (
    default_rules_dir,
    detection_rule_findings,
    index_pattern_matches,
    load_detection_rules,
    lookup_candidates,
    rule_workload,
    rules_for_stream,
    stream_index_name,
)
from .sorting import recommend_sort
from .spec import (
    DECLARATION_CODES,
    columnar_block,
    existing_index_sort,
    spec_supports_columnar,
)
from .transforms import (
    catalog_latest_transforms,
    catalog_stream_index_names,
    latest_transform_findings,
    latest_transforms,
    pattern_could_match_package,
    transform_source_consumers,
)


def audit_package(pkg_dir: str, scan_dashboards: bool = True,
                  rules_dir: Optional[str] = "auto") -> Dict[str, Any]:
    pkg_dir = os.path.abspath(pkg_dir.rstrip("/"))
    pkg_name = os.path.basename(pkg_dir)
    result: Dict[str, Any] = {
        "package": pkg_name,
        "path": pkg_dir,
        "status": "OUT_OF_SCOPE",
        "errors": [],
        "data_streams": [],
    }

    manifest_path = os.path.join(pkg_dir, "manifest.yml")
    try:
        manifest = load_yaml(manifest_path) or {}
    except RuntimeError as exc:
        result["errors"].append(str(exc))
        return result

    result["package"] = manifest.get("name", pkg_name)
    result["version"] = manifest.get("version")
    result["format_version"] = manifest.get("format_version")
    result["type"] = manifest.get("type", "integration")
    result["kibana_condition"] = (
        ((manifest.get("conditions") or {}).get("kibana") or {}).get("version")
    )

    if result["type"] == "input":
        result["out_of_scope_reason"] = "input package (no data_stream directories to opt in)"
        return result

    ds_root = os.path.join(pkg_dir, "data_stream")
    if not os.path.isdir(ds_root):
        result["out_of_scope_reason"] = "no data_stream directory"
        return result

    # Kibana assets are read once: the field counters are the index-sort tie-break
    # (off by default in catalog mode), the `_source` consumer scan always runs.
    dash_fields, filter_fields, kibana_consumers = scan_kibana_assets(
        pkg_dir, count_fields=scan_dashboards)
    transforms = transform_source_consumers(pkg_dir)
    latest = latest_transforms(pkg_dir)
    # `latest` transforms other packages own: one of them may read this package's streams.
    # Pre-filtered on the literal prefix of each pattern (`logs-*` could match anything,
    # `logs-other_pkg.x-*` or `metrics-…` cannot), so the per-stream glob matching only
    # sees the handful that could apply.
    own_dir = os.path.basename(pkg_dir)
    packages_root = os.path.dirname(pkg_dir)
    foreign_latest = [t for t in catalog_latest_transforms(packages_root)
                      if t["package"] != own_dir
                      and any(pattern_could_match_package(p, own_dir) for p in t["patterns"])]
    result["source_consumer_assets"] = (
        [t["file"] for t in transforms] + [k["file"] for k in kibana_consumers]
        + [t["file"] for t in latest])
    result["latest_transforms"] = latest
    result["dashboard_top_fields"] = [f for f, _ in dash_fields.most_common(15)]
    result["dashboard_filter_fields"] = [f for f, _ in filter_fields.most_common(15)]

    if rules_dir == "auto":
        rules_dir = default_rules_dir(pkg_dir)
    rule_set = load_detection_rules(rules_dir)
    result["detection_rules_dir"] = rule_set["dir"]
    result["detection_rules_scanned"] = len(rule_set["rules"])

    status = "OUT_OF_SCOPE"
    for ds_name in sorted(os.listdir(ds_root)):
        ds_dir = os.path.join(ds_root, ds_name)
        if not os.path.isdir(ds_dir):
            continue
        stream = audit_data_stream(pkg_dir, ds_dir, ds_name, dash_fields, filter_fields,
                                   format_version=result.get("format_version"),
                                   transforms=transforms, kibana=kibana_consumers,
                                   latest=latest, foreign_latest=foreign_latest,
                                   rule_set=rule_set, pkg_name=result["package"])
        result["data_streams"].append(stream)
        status = worse(status, stream["status"])
    result["status"] = status

    # Where each of the package's own `latest` transforms lands: its own in-scope
    # streams, or, for one that reads none of them, the other packages' streams that
    # carry its finding (possibly none: metrics streams, alert indices).
    for tr in latest:
        tr["streams"] = [s["data_stream"] for s in result["data_streams"]
                         if s.get("index_name")
                         and any(index_pattern_matches(p, s["index_name"]) for p in tr["patterns"])]
        if not tr["streams"]:
            tr["flagged_on"] = [f"{pkg}/{ds}" for pkg, ds, idx
                                in catalog_stream_index_names(packages_root)
                                if pkg != own_dir
                                and any(index_pattern_matches(p, idx) for p in tr["patterns"])]
    return result


def audit_data_stream(pkg_dir: str, ds_dir: str, ds_name: str,
                      dash_fields: Counter, filter_fields: Counter,
                      format_version: Any = None,
                      transforms: Optional[List[Dict[str, Any]]] = None,
                      kibana: Optional[List[Dict[str, Any]]] = None,
                      latest: Optional[List[Dict[str, Any]]] = None,
                      foreign_latest: Optional[List[Dict[str, Any]]] = None,
                      rule_set: Optional[Dict[str, Any]] = None,
                      pkg_name: Optional[str] = None) -> Dict[str, Any]:
    rel = lambda p: os.path.relpath(p, pkg_dir)  # noqa: E731
    stream: Dict[str, Any] = {
        "data_stream": ds_name,
        "status": "OUT_OF_SCOPE",
        "type": None,
        "index_mode": None,
        "columnar_supported": False,
        "columnar_enabled": False,
        "columnar_supported_with_blockers": False,
        "existing_index_sort": None,
        "has_es_key": False,
        "inputs": [],
        "findings": [],
        "errors": [],
    }

    manifest_path = os.path.join(ds_dir, "manifest.yml")
    try:
        manifest = load_yaml(manifest_path) or {}
    except RuntimeError as exc:
        stream["errors"].append(str(exc))
        return stream
    if not isinstance(manifest, dict):
        stream["errors"].append(f"{rel(manifest_path)}: manifest is not a mapping")
        return stream

    stream["type"] = manifest.get("type")
    # Whether the manifest has an `elasticsearch:` key *at all*, which decides the
    # wording of the Stream manifest line: "merge into the existing key" vs "add a
    # new top-level key". Membership, not truthiness — a present-but-empty
    # `elasticsearch:` still has to be merged into, never duplicated.
    stream["has_es_key"] = "elasticsearch" in manifest
    es_section = manifest.get("elasticsearch") if isinstance(manifest.get("elasticsearch"), dict) else {}
    stream["index_mode"] = es_section.get("index_mode")
    # package-spec 3.7.0 stream-level readiness flag. Fleet shows the per-stream
    # opt-in toggle when it is set; a columnar `index_mode` forces columnar instead
    # (the toggle is locked on and existing streams switch at the next rollover).
    # Either one means "this stream is columnar-enabled" as far as this report is
    # concerned.
    stream["columnar_supported"] = is_true(columnar_block(es_section).get("supported"))
    stream["columnar_enabled"] = bool(
        stream["columnar_supported"] or stream["index_mode"] in COLUMNAR_INDEX_MODES
    )
    stream["existing_index_sort"] = existing_index_sort(es_section)

    if stream["type"] != "logs":
        stream["out_of_scope_reason"] = f"data stream type is `{stream['type']}` (logs only)"
        return stream

    stream["inputs"] = sorted({
        s.get("input") for s in (manifest.get("streams") or []) if isinstance(s, dict) and s.get("input")
    })

    otel_inputs = [i for i in stream["inputs"] if i in OTEL_INPUTS]
    if otel_inputs:
        stream["out_of_scope_reason"] = (
            f"OpenTelemetry input ({', '.join(f'`{i}`' for i in otel_inputs)}): OTel log "
            f"streams stay on LogsDB until logs sharing the same resource attributes can be "
            f"clustered (derived fields), per the rollout strategy")
        return stream

    pkg_name = pkg_name or os.path.basename(pkg_dir)
    stream["index_name"] = stream_index_name(stream["type"], pkg_name, ds_name, manifest)

    findings = check_stream_manifest(manifest, rel(manifest_path))

    # Every place the package uses one of the two package-spec 3.7.0 columnar
    # constructs, for the `format_version` gate below.
    columnar_construct_sites: List[str] = []
    if columnar_block(es_section):
        columnar_construct_sites.append(
            f"`elasticsearch.columnar` ({rel(manifest_path)})")

    # Fields
    field_index: Dict[str, Dict[str, Any]] = {}
    # flat name -> the `fields/*.yml` that declared it. The *file* matters: a
    # `cloud.account.id` declared only in the generated `agent.yml` is Elastic
    # Agent's metadata, not the event's tenant (`_tier1_event_evidence`).
    field_sources: Dict[str, str] = {}
    # Two passes: nested ancestry is decided by full path over every field file of the
    # stream, because packages declare nested children both through `fields:` and as
    # separate entries with dotted names (tanium: `whats` nested, then
    # `whats.intel_intra_ids` nested next to it), and Fleet expands both into the
    # same hierarchy.
    entries: List[Tuple[Dict[str, Any], str, int, bool, str, str]] = []
    fields_dir = os.path.join(ds_dir, "fields")
    if os.path.isdir(fields_dir):
        for fname in sorted(os.listdir(fields_dir)):
            if not fname.endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(fields_dir, fname)
            try:
                defs = load_yaml(fpath)
            except RuntimeError as exc:
                stream["errors"].append(str(exc))
                continue
            for fdef, flat, depth, in_mf in walk_fields(defs):
                entries.append((fdef, flat, depth, in_mf, rel(fpath), fname))
    nested_paths = {flat for fdef, flat, _, in_mf, _, _ in entries
                    if not in_mf and fdef.get("type") == "nested"}
    text_subfields: set = set()
    for fdef, flat, depth, in_mf, rel_file, fname in entries:
        if not in_mf:
            field_index.setdefault(flat, fdef)
            field_sources.setdefault(flat, fname)
        if columnar_block(fdef):
            columnar_construct_sites.append(f"`{flat}` ({rel_file})")
        path_depth = sum(1 for p in nested_paths if flat.startswith(p + "."))
        findings.extend(check_field(fdef, flat, max(depth, path_depth), in_mf, rel_file))
        # Text sub-fields keep an inverted index in columnar: input for the ECS `.text`
        # review. Declared ones, plus the ones `external: ecs` imports carry.
        if in_mf and fdef.get("type") in TEXT_TYPES:
            text_subfields.add(flat)
        elif not in_mf and fdef.get("external") == "ecs":
            for sub in (ecs_schema().get(flat) or {}).get("text_subfields") or []:
                text_subfields.add(f"{flat}.{sub}")

    # --- package-spec version gate -------------------------------------- #
    # Both constructs are new in package-spec 3.7.0. Declaring either one under
    # an older `format_version` fails validation: the field-level `columnar:`
    # block is an unknown property in the fields schema, and
    # `elasticsearch.columnar` is an unknown property in the data stream
    # manifest schema. It is the root manifest that decides, not the data stream.
    if columnar_construct_sites and not spec_supports_columnar(format_version):
        findings.append(finding(
            "columnar_requires_spec_3_7", "A", "auto_fix",
            f"The package declares a package-spec 3.7.0 columnar construct "
            f"({', '.join(columnar_construct_sites[:4])}"
            f"{', …' if len(columnar_construct_sites) > 4 else ''}) but the root "
            f"`manifest.yml` says `format_version: {format_version}`. Both the "
            f"field-level `columnar:` block and `elasticsearch.columnar` are new in "
            f"package-spec 3.7.0, so the package fails validation as an unknown "
            f"property.",
            "Bump `format_version` to `\"3.7.0\"` in the root `manifest.yml`, then run "
            "`elastic-package lint` immediately, before anything else: a multi-minor jump "
            "(3.4.x -> 3.7.0) turns on every validator added in between, so expect "
            "pre-existing findings that have nothing to do with columnar (a 3.4 -> 3.7 bump "
            "surfaces `SVR00008`/`SVR00009`, the ingest-pipeline `on_failure` requirements). "
            "Prefer FIXING them when the fix is cheap — `on_failure` handlers do not change "
            "pipeline test expectations — and use `validation.yml` exclusions only for the "
            "rest, one comment each. Never exclude a columnar validator error.",
            "manifest.yml"))

    # --- `columnar.supported: true` with unresolved Class A findings ----- #
    # The 3.7.0 validator rejects the declaration while a blocker remains, so
    # this is a contradiction inside the package, not merely a readiness gap.
    blocking = [f for f in findings
                if f["class"] == "A" and f["code"] not in DECLARATION_CODES]
    if stream["columnar_supported"] and blocking:
        stream["columnar_supported_with_blockers"] = True
        codes = sorted({f["code"] for f in blocking})
        findings.append(finding(
            "columnar_supported_with_blockers", "A", "blocker",
            f"`elasticsearch.columnar.supported: true` asserts this data stream is "
            f"columnar-ready, but it still has {len(blocking)} Class A finding(s) "
            f"({', '.join('`%s`' % c for c in codes)}). The package-spec 3.7.0 columnar "
            f"validator rejects the declaration while any of them remains, and a user who "
            f"did manage to turn the Fleet toggle on would get a failed index template "
            f"PUT.",
            "Fix the Class A findings listed above, or drop "
            "`elasticsearch.columnar.supported: true` from this data stream's manifest "
            "until they are fixed. The flag is per data stream, so the other streams in "
            "the package can keep it.",
            f"data_stream/{ds_name}/manifest.yml"))

    sample = load_sample_event(ds_dir)
    pipeline_arrays = scan_pipelines(ds_dir)
    attach_pipeline_patches(findings, field_index, ds_dir, pkg_dir)

    # --- columnar `_source` consumers (C6-C10) --------------------------- #
    # Appended last: they are Class C, so they cannot turn a Class A verdict, but a
    # `review` one does move a stream to NEEDS_REVIEW, which is the point — a stream
    # whose `_source` is read by a transform, a Kibana runtime field or an ES|QL
    # `METADATA _source` query should not be declared `supported` before someone has
    # looked at it.
    findings.extend(source_consumer_findings(ds_name, transforms or [], kibana or []))
    findings.extend(latest_transform_findings(
        stream["index_name"], (latest or []) + (foreign_latest or []),
        current_pkg=os.path.basename(pkg_dir)))
    rule_set = rule_set or {}
    specific_rules, broad_rules = rules_for_stream(rule_set, stream["index_name"],
                                                   stream["type"], pkg_name)
    findings.extend(detection_rule_findings(specific_rules, broad_rules))
    flattened_exempt: set = set()
    findings.extend(object_array_findings(ds_dir, ds_name, field_index, sample,
                                          flattened_exempt))

    # What the `_source` consumer scan actually looked at. Recorded so the report can
    # state the NEGATIVE result in words: an empty Class C section is indistinguishable
    # from a check that never ran, and the reader has to know which one it was before
    # declaring a stream ready.
    code_counts = Counter(f["code"] for f in findings)
    stream["source_consumers"] = {
        "transform": code_counts["source_consumer_transform"],
        "latest_transform": code_counts["source_consumer_latest_transform"],
        "kibana": code_counts["source_consumer_kibana"],
        "detection_rule": code_counts["source_consumer_detection_rule"],
        "object_arrays": code_counts["object_array_flattening"],
        "flattened_exempt": sorted(flattened_exempt),
    }
    stream["detection_rules"] = rule_workload(specific_rules, broad_rules,
                                              scanned=bool(rule_set.get("rules")))

    stream["findings"] = findings
    stream["field_count"] = len(field_index)
    stream["text_subfields"] = sorted(text_subfields)
    stream["host_name_in_sample"] = sample_has_host_name(sample)
    stream["sort"] = recommend_sort(stream, field_index, dash_fields, filter_fields,
                                    array_fields=sample_array_fields(sample),
                                    pipeline_arrays=pipeline_arrays,
                                    sample=sample,
                                    field_sources=field_sources)
    stream["lookup_candidates"] = lookup_candidates(
        specific_rules, filter_fields, field_index, stream["sort"].get("sort_fields") or [])
    stream["status"] = status_from_findings(findings)
    return stream


def status_from_findings(findings: List[Dict[str, Any]]) -> str:
    severities = {f["severity"] for f in findings}
    if "blocker" in severities:
        return "BLOCKED"
    if "review" in severities:
        return "NEEDS_REVIEW"
    if "auto_fix" in severities:
        return "READY_AFTER_AUTO_FIX"
    return "READY"


def load_sample_event(ds_dir: str) -> Dict[str, Any]:
    path = os.path.join(ds_dir, "sample_event.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def sample_has_host_name(doc: Dict[str, Any]) -> bool:
    """Informational only — it does not decide the sort (see `recommend_sort`)."""
    host = doc.get("host")
    if isinstance(host, dict) and host.get("name"):
        return True
    return bool(doc.get("host.name"))


def sample_array_fields(doc: Dict[str, Any], prefix: str = "") -> set:
    """Flat field names that the sample event shows carrying a list value."""
    out: set = set()
    for key, value in doc.items():
        if not isinstance(key, str):
            continue
        flat = f"{prefix}.{key}" if prefix else key
        if isinstance(value, list):
            out.add(flat)
        elif isinstance(value, dict):
            out |= sample_array_fields(value, flat)
    return out
