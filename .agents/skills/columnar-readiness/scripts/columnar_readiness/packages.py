"""Package and data stream audit."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from .common import finding, is_false, line_of, load_yaml, worse
from .constants import COLUMNAR_INDEX_MODES, OTEL_INPUTS, TEXT_TYPES
from .consumers import object_array_findings, source_consumer_findings
from .ecs import ecs_schema
from .fields import check_field, check_stream_manifest, nested_object_children, walk_fields
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
    attribute_rules,
    attribute_templates,
    find_detection_rules_repo,
    load_detection_rules_repo,
    load_query_templates,
    repo_reader_findings,
    repo_readers_for,
    stream_index_name,
)
from .sorting import recommend_sort
from .spec import (
    DECLARATION_CODES,
    LOGSDB_COLUMNAR_PACKAGE_VALUES,
    LOGSDB_COLUMNAR_STREAM_VALUES,
    existing_index_sort,
    installs_on_8x,
    logsdb_columnar_value,
    spec_min_stack,
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
                  rules_dir: Optional[str] = "auto",
                  detection_rules: Optional[str] = None) -> Dict[str, Any]:
    """Audit one package. `rules_dir` is the prebuilt rules directory ("auto": the
    `security_detection_engine` sibling; None: no rule scan at all), `detection_rules`
    an `elastic/detection-rules` checkout (default: `$DETECTION_RULES_PATH`, then a
    sibling of this repo)."""
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
    result["spec_min_stack"] = spec_min_stack(result["format_version"])
    result["installs_on_8x"] = installs_on_8x(result["format_version"],
                                              result["kibana_condition"])
    # The package-level `elasticsearch.logsdb_columnar` (opt_in | default): every logs
    # data stream takes it unless its own manifest overrides it.
    package_es = manifest.get("elasticsearch") if isinstance(manifest.get("elasticsearch"), dict) else {}
    result["logsdb_columnar"] = logsdb_columnar_value(package_es)
    result["has_es_key"] = "elasticsearch" in manifest

    if result["type"] == "input":
        result["out_of_scope_reason"] = INPUT_PACKAGE_REASON
        result["data_streams"] = input_package_streams(pkg_dir, manifest)
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
    template_streams = {
        str(t["name"]): [str(ds) for ds in (t.get("data_streams") or [])]
        for t in (manifest.get("policy_templates") or [])
        if isinstance(t, dict) and t.get("name")}
    identities = logs_stream_identities(ds_root, result["package"])
    attribution = attribute_rules(rule_set, identities, result["package"], template_streams)
    query_templates = attribute_templates(load_query_templates(pkg_dir), identities,
                                          result["package"])
    repo = {}
    if rules_dir:  # `--no-rules` skips the checkout too
        repo_dir, looked = find_detection_rules_repo(detection_rules, packages_root)
        repo = load_detection_rules_repo(repo_dir)
        result["detection_rules_repo"] = {"dir": repo["dir"], "files": repo["files"],
                                          "looked_at": looked}

    status = "OUT_OF_SCOPE"
    for ds_name in sorted(os.listdir(ds_root)):
        ds_dir = os.path.join(ds_root, ds_name)
        if not os.path.isdir(ds_dir):
            continue
        stream = audit_data_stream(pkg_dir, ds_dir, ds_name, dash_fields, filter_fields,
                                   format_version=result.get("format_version"),
                                   format_version_line=line_of(manifest, "format_version"),
                                   transforms=transforms, kibana=kibana_consumers,
                                   latest=latest, foreign_latest=foreign_latest,
                                   rules=attribution.get(ds_name),
                                   rules_scanned=bool(rule_set["rules"]), repo=repo,
                                   templates=query_templates.get(ds_name),
                                   package_logsdb_columnar=(
                                       result["logsdb_columnar"],
                                       line_of(package_es, "logsdb_columnar")),
                                   pkg_name=result["package"])
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


FieldEntry = Tuple[Dict[str, Any], str, int, bool, str, str]

INPUT_PACKAGE_REASON = (
    "input package: `elasticsearch.logsdb_columnar` is for integration packages (the "
    "package-spec#1250 review leans towards leaving input packages out), so Fleet has "
    "nothing to offer an opt-in on. Its policy templates are assessed for information")


def input_package_streams(pkg_dir: str, manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One out-of-scope stream per policy template of an input package, for information.

    An input package has no `data_stream/`: each policy template is a stream, mapped
    from the root `fields/`, whose dataset is the `data_stream.dataset` variable's
    default (users can override it). The mapping checks run so the work is known if
    input packages come into scope; their results go to `informational_findings`,
    never `findings`, so they cannot move a status or a catalog count.
    """
    rel = lambda p: os.path.relpath(p, pkg_dir)  # noqa: E731
    errors: List[str] = []
    entries = read_field_files(os.path.join(pkg_dir, "fields"), rel, errors)
    nested_paths = {flat for fdef, flat, _, in_mf, _, _ in entries
                    if not in_mf and fdef.get("type") == "nested"}
    info: List[Dict[str, Any]] = []
    for fdef, flat, depth, in_mf, rel_file, _ in entries:
        path_depth = sum(1 for p in nested_paths if flat.startswith(p + "."))
        info.extend(check_field(fdef, flat, max(depth, path_depth), in_mf, rel_file))

    streams: List[Dict[str, Any]] = []
    for template in manifest.get("policy_templates") or []:
        if not isinstance(template, dict) or not template.get("name"):
            continue
        name = str(template["name"])
        ttype = template.get("type") or "logs"
        inputs = [str(template["input"])] if template.get("input") else []
        dataset = next((str(v["default"]) for v in template.get("vars") or []
                        if isinstance(v, dict) and v.get("name") == "data_stream.dataset"
                        and v.get("default")), f"{manifest.get('name', os.path.basename(pkg_dir))}.{name}")
        stream: Dict[str, Any] = {
            "data_stream": name, "status": "OUT_OF_SCOPE", "type": ttype, "dataset": dataset,
            "inputs": inputs, "findings": [], "informational_findings": [],
            "errors": list(errors)}
        if ttype != "logs":
            stream["out_of_scope_reason"] = f"policy template type is `{ttype}` (logs only)"
        elif any(i in OTEL_INPUTS for i in inputs):
            stream["out_of_scope_reason"] = (
                f"OpenTelemetry input ({', '.join(f'`{i}`' for i in inputs)}): OTel log "
                f"streams stay on LogsDB until logs sharing the same resource attributes can "
                f"be clustered (derived fields), per the rollout strategy")
        else:
            stream["out_of_scope_reason"] = (
                f"input package policy template (dataset `{dataset}` by default): "
                "assessed for information only")
            stream["informational_findings"] = [dict(f) for f in info]
        streams.append(stream)
    return streams


def read_field_files(fields_dir: str, rel: Any, errors: List[str]) -> List[FieldEntry]:
    """(definition, flat name, nested depth, in multi-field, file, file name) for every
    field of a `fields/` directory, in file order; parse errors go to `errors`."""
    entries: List[FieldEntry] = []
    if not os.path.isdir(fields_dir):
        return entries
    for fname in sorted(os.listdir(fields_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        fpath = os.path.join(fields_dir, fname)
        try:
            defs = load_yaml(fpath)
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        for fdef, flat, depth, in_mf in walk_fields(defs):
            entries.append((fdef, flat, depth, in_mf, rel(fpath), fname))
    return entries


def logs_stream_identities(ds_root: str, pkg_name: str) -> List[Tuple[str, str, str, str]]:
    """(name, type, dataset, index name) of each logs data stream, for rule attribution."""
    out: List[Tuple[str, str, str, str]] = []
    for ds_name in sorted(os.listdir(ds_root)):
        path = os.path.join(ds_root, ds_name, "manifest.yml")
        if not os.path.isfile(path):
            continue
        try:
            manifest = load_yaml(path) or {}
        except RuntimeError:
            continue
        if not isinstance(manifest, dict) or manifest.get("type") != "logs":
            continue
        dataset = manifest.get("dataset")
        dataset = dataset if isinstance(dataset, str) else f"{pkg_name}.{ds_name}"
        out.append((ds_name, "logs", dataset,
                    stream_index_name("logs", pkg_name, ds_name, manifest)))
    return out


def audit_data_stream(pkg_dir: str, ds_dir: str, ds_name: str,
                      dash_fields: Counter, filter_fields: Counter,
                      format_version: Any = None,
                      format_version_line: Optional[int] = None,
                      transforms: Optional[List[Dict[str, Any]]] = None,
                      kibana: Optional[List[Dict[str, Any]]] = None,
                      latest: Optional[List[Dict[str, Any]]] = None,
                      foreign_latest: Optional[List[Dict[str, Any]]] = None,
                      rules: Optional[Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]] = None,
                      rules_scanned: bool = False,
                      repo: Optional[Dict[str, Any]] = None,
                      templates: Optional[List[Dict[str, Any]]] = None,
                      package_logsdb_columnar: Tuple[Optional[str], Optional[int]] = (None, None),
                      pkg_name: Optional[str] = None) -> Dict[str, Any]:
    rel = lambda p: os.path.relpath(p, pkg_dir)  # noqa: E731
    stream: Dict[str, Any] = {
        "data_stream": ds_name,
        "status": "OUT_OF_SCOPE",
        "type": None,
        "index_mode": None,
        "logsdb_columnar": None,
        "logsdb_columnar_effective": None,
        "columnar_enabled": False,
        "logsdb_columnar_with_blockers": False,
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
    # `elasticsearch.logsdb_columnar` (package-spec 3.7.0): the data stream's own value
    # wins over the package one, and only logs data streams take either.
    own = logsdb_columnar_value(es_section)
    own_line = line_of(es_section, "logsdb_columnar")
    package_value, package_line = package_logsdb_columnar
    stream["logsdb_columnar"] = own
    stream["existing_index_sort"] = existing_index_sort(es_section)

    if stream["type"] != "logs":
        reason = f"data stream type is `{stream['type']}` (logs only)"
        if own is not None:
            reason += (f"; it sets `elasticsearch.logsdb_columnar: {own}`, which only logs "
                       f"data streams may set: remove it")
            stream["findings"].append(finding(
                "logsdb_columnar_not_logs", "A", "blocker",
                f"This `{stream['type']}` data stream sets `elasticsearch.logsdb_columnar: "
                f"{own}`. The setting applies to logs data streams only, and the validator "
                f"rejects it on any other type (the package-level value is ignored for them).",
                "Remove `logsdb_columnar` from this data stream's manifest.",
                rel(manifest_path), line=own_line))
        stream["out_of_scope_reason"] = reason
        return stream

    effective = (own if own in LOGSDB_COLUMNAR_STREAM_VALUES
                 else package_value if package_value in LOGSDB_COLUMNAR_PACKAGE_VALUES
                 else None)
    stream["logsdb_columnar_effective"] = effective
    stream["columnar_enabled"] = effective in ("opt_in", "default")

    stream["inputs"] = sorted({
        s.get("input") for s in (manifest.get("streams") or []) if isinstance(s, dict) and s.get("input")
    })

    otel_inputs = [i for i in stream["inputs"] if i in OTEL_INPUTS]
    if otel_inputs:
        stream["out_of_scope_reason"] = (
            f"OpenTelemetry input ({', '.join(f'`{i}`' for i in otel_inputs)}): OTel log "
            f"streams stay on LogsDB until logs sharing the same resource attributes can be "
            f"clustered (derived fields), per the rollout strategy"
            + ("; the package declares `logsdb_columnar`, so mark this data stream "
               "`logsdb_columnar: unsupported`" if stream["columnar_enabled"] else ""))
        return stream

    pkg_name = pkg_name or os.path.basename(pkg_dir)
    stream["index_name"] = stream_index_name(stream["type"], pkg_name, ds_name, manifest)

    findings = check_stream_manifest(manifest, rel(manifest_path))

    mode = stream["index_mode"]
    if mode in COLUMNAR_INDEX_MODES:
        findings.append(finding(
            "index_mode_columnar", "A", "blocker",
            f"`elasticsearch.index_mode: {mode}` is not a package-spec value. `index_mode` "
            f"is for a fixed mode the user cannot change (`time_series`); LogsDB columnar "
            f"is declared with `elasticsearch.logsdb_columnar`, and there is no plain "
            f"`columnar` mode for integrations.",
            "Remove `index_mode` here, and declare `elasticsearch.logsdb_columnar: opt_in` "
            "in the root `manifest.yml` (or on this data stream).",
            rel(manifest_path), line=line_of(es_section, "index_mode")))
    elif mode and stream["columnar_enabled"]:
        findings.append(finding(
            "logsdb_columnar_with_index_mode", "A", "blocker",
            f"`index_mode: {mode}` and `logsdb_columnar: {effective}` both apply to this "
            f"data stream. `logsdb_columnar` only applies when `index_mode` is unset, and the "
            f"validator rejects the combination.",
            "Mark this data stream `elasticsearch.logsdb_columnar: unsupported`, or drop "
            "`index_mode`.",
            rel(manifest_path), line=line_of(es_section, "index_mode")))

    # Fields
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
    entries = read_field_files(os.path.join(ds_dir, "fields"), rel, stream["errors"])
    nested_paths = {flat for fdef, flat, _, in_mf, _, _ in entries
                    if not in_mf and fdef.get("type") == "nested"}
    text_subfields: set = set()
    for fdef, flat, depth, in_mf, rel_file, fname in entries:
        if not in_mf:
            field_index.setdefault(flat, fdef)
            field_sources.setdefault(flat, fname)
        path_depth = sum(1 for p in nested_paths if flat.startswith(p + "."))
        findings.extend(check_field(fdef, flat, max(depth, path_depth), in_mf, rel_file))
        # Text sub-fields keep an inverted index in columnar: input for the ECS `.text`
        # review. Declared ones, plus the ones `external: ecs` imports carry.
        if in_mf and fdef.get("type") in TEXT_TYPES:
            text_subfields.add(flat)
        elif not in_mf and fdef.get("external") == "ecs":
            for sub in (ecs_schema().get(flat) or {}).get("text_subfields") or []:
                text_subfields.add(f"{flat}.{sub}")
    findings.extend(nested_object_children(entries))

    # --- index sort ------------------------------------------------------ #
    # For a columnar-ready data stream the sort fields must be mapped, have doc
    # values, and include `@timestamp` (package-spec#1250 review). `host.name` counts
    # as mapped: the logs profile adds its mapping when the package does not.
    existing = stream["existing_index_sort"]
    if existing:
        mapped = {flat for _, flat, _, _, _, _ in entries}
        problems: List[str] = []
        if "@timestamp" not in existing["field"]:
            problems.append("`@timestamp` is not in it")
        for name in existing["field"]:
            fdef = field_index.get(name)
            if name in ("@timestamp", "host.name") and name not in mapped:
                continue
            if name not in mapped:
                problems.append(f"`{name}` is not mapped in this data stream")
            elif fdef is not None and is_false(fdef.get("doc_values")):
                problems.append(f"`{name}` has `doc_values: false`")
        if problems:
            findings.append(finding(
                "index_sort_invalid", "A", "blocker",
                f"The explicit `index.sort` (`{', '.join(existing['field'])}`) does not fit a "
                f"columnar-ready data stream: {'; '.join(problems)}.",
                "Sort fields must be mapped, have doc values, and include `@timestamp`. Fix "
                "the sort, or leave it to the logs profile default "
                "(`host.name`, `@timestamp`).",
                rel(manifest_path), line=line_of(es_section, "index_template")))

    # --- package-spec version gate -------------------------------------- #
    # `elasticsearch.logsdb_columnar` is new in package-spec 3.7.0: under an older
    # `format_version` it is an unknown property. The root manifest decides.
    sites = ([f"`elasticsearch.logsdb_columnar` (`{rel(manifest_path)}`)"] if own is not None else []) \
        + (["`elasticsearch.logsdb_columnar` (`manifest.yml`)"] if package_value is not None else [])
    if sites and not spec_supports_columnar(format_version):
        findings.append(finding(
            "logsdb_columnar_requires_spec_3_7", "A", "auto_fix",
            f"The package declares {' and '.join(sites)}, but the root `manifest.yml` says "
            f"`format_version: {format_version}`. `elasticsearch.logsdb_columnar` is new in "
            f"package-spec 3.7.0, so the package fails validation as an unknown property.",
            "Bump `format_version` to `\"3.7.0\"` in the root `manifest.yml`, then run "
            "`elastic-package lint` immediately, before anything else: a multi-minor jump "
            "(3.4.x -> 3.7.0) turns on every validator added in between, so expect "
            "pre-existing findings that have nothing to do with columnar (a 3.4 -> 3.7 bump "
            "surfaces `SVR00008`/`SVR00009`, the ingest-pipeline `on_failure` requirements). "
            "Prefer FIXING them when the fix is cheap — `on_failure` handlers do not change "
            "pipeline test expectations — and use `validation.yml` exclusions only for the "
            "rest, one comment each. Never exclude a columnar validator error.",
            "manifest.yml", line=format_version_line))

    # --- declared ready with unresolved Class A findings ----------------- #
    # The validator checks every logs data stream that ends up ready, and rejects the
    # declaration while a blocker remains: a contradiction inside the package.
    blocking = [f for f in findings
                if f["class"] == "A" and f["code"] not in DECLARATION_CODES]
    if stream["columnar_enabled"] and blocking:
        stream["logsdb_columnar_with_blockers"] = True
        codes = sorted({f["code"] for f in blocking})
        from_stream = own in ("opt_in", "default")
        findings.append(finding(
            "logsdb_columnar_with_blockers", "A", "blocker",
            f"`logsdb_columnar: {effective}` "
            f"({'this data stream' if from_stream else 'the package, inherited by this data stream'}) "
            f"declares it columnar-ready, but it still has {len(blocking)} Class A "
            f"finding(s) ({', '.join('`%s`' % c for c in codes)}). The validator checks every "
            f"logs data stream that ends up ready and rejects the declaration while any of "
            f"them remains.",
            "Fix the Class A findings listed above, or mark this data stream "
            "`elasticsearch.logsdb_columnar: unsupported` in its manifest, so it stays on "
            "LogsDB while the rest of the package opts in.",
            rel(manifest_path) if from_stream else "manifest.yml",
            line=own_line if from_stream else package_line))

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
    specific_rules, broad_rules = rules or ([], [])
    findings.extend(detection_rule_findings(specific_rules, broad_rules))
    repo_readers = repo_readers_for(stream["index_name"], repo or {},
                                    [r for r in specific_rules + broad_rules if r["source_hits"]])
    findings.extend(repo_reader_findings(repo_readers))
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
                                              scanned=rules_scanned)
    stream["detection_rules"]["repo_readers"] = [r["name"] for r in repo_readers]
    stream["query_templates"] = {
        "alerting_rule_template": sum(t["kind"] == "alerting_rule_template" for t in templates or []),
        "slo_template": sum(t["kind"] == "slo_template" for t in templates or []),
        "names": [t["name"] for t in templates or []][:25],
    }

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
