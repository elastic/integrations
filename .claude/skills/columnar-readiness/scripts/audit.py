#!/usr/bin/env python3
"""Static columnar-readiness audit for Elastic integration packages.

Scans a package (or the whole catalog) for mapping features that Elasticsearch
rejects or silently degrades under the `logsdb_columnar` index mode, and proposes
an index sort key per data stream.

Usage:
    scripts/audit.py packages/nginx                 # one package, Markdown report
    scripts/audit.py packages/nginx --format json   # one package, JSON report
    scripts/audit.py packages/ --catalog            # whole catalog summary
    scripts/audit.py packages/ --catalog --format json --out report.json

Requires: Python 3.8+ and PyYAML.
    python3 -m pip install --user pyyaml
    # or, without touching the system interpreter:
    python3 -m venv /tmp/columnar-venv && /tmp/columnar-venv/bin/pip install pyyaml
    /tmp/columnar-venv/bin/python3 scripts/audit.py packages/nginx

Scope: logs data streams only. Metrics/traces/synthetics streams and `type: input`
packages are reported as OUT_OF_SCOPE and skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit(
        "PyYAML is required.\n"
        "  python3 -m pip install --user pyyaml\n"
        "or use a venv:\n"
        "  python3 -m venv /tmp/columnar-venv && /tmp/columnar-venv/bin/pip install pyyaml\n"
        "  /tmp/columnar-venv/bin/python3 scripts/audit.py <package>"
    )

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Statuses, worst last. Package status = worst of its data streams.
STATUS_ORDER = ["OUT_OF_SCOPE", "READY", "READY_AFTER_AUTO_FIX", "NEEDS_REVIEW", "BLOCKED"]

# Field types with no synthetic-source implementation in Elasticsearch.
# Defensive only: the package-spec `type` enum does not allow these today.
UNSUPPORTED_TYPES = {
    "search_as_you_type",
    "completion",
    "token_count",
    "rank_feature",
    "rank_features",
    "percolator",
}

# Types that cannot be used as an index sort key.
UNSORTABLE_TYPES = {"text", "match_only_text", "wildcard", "flattened", "nested", "object", "group",
                    "geo_point", "geo_shape", "histogram", "aggregate_metric_double", "binary"}

# ECS fields that ship with `doc_values: false`. elastic-package's dependency
# manager (internal/fields/dependency_manager.go, transformImportedField) copies
# `index` and `doc_values` from the ECS schema into the built package, so a bare
# `external: ecs` reference to one of these lands `doc_values: false` in the
# built fields file even though the package source never mentions it.
# Verified against ECS v8.11.0 and v9.3.0 schemas.
ECS_DOC_VALUES_FALSE = {
    "event.original",
    "gen_ai.agent.description",
    "x509.public_key_exponent",
    "file.x509.public_key_exponent",
    "tls.client.x509.public_key_exponent",
    "tls.server.x509.public_key_exponent",
    "threat.indicator.x509.public_key_exponent",
    "threat.indicator.file.x509.public_key_exponent",
    "threat.enrichments.indicator.x509.public_key_exponent",
    "threat.enrichments.indicator.file.x509.public_key_exponent",
}

# Inputs where the agent runs on the machine that produced the log, so
# `host.name` is a meaningful, high-cardinality dimension.
HOST_MEANINGFUL_INPUTS = {
    "logfile", "filestream", "log", "journald", "winlog", "unix", "system/metrics",
    "docker", "containerd", "filestream-container", "event/file", "udp", "tcp",
    "syslog", "etw", "audit/auditd", "audit/file_integrity", "system/auth",
}

# Inputs that poll a remote API: the agent host is the collector, not the subject.
COLLECTOR_INPUTS = {
    "httpjson", "cel", "aws-s3", "aws-cloudwatch", "gcp-pubsub", "gcs", "azure-eventhub",
    "azure-blob-storage", "o365audit", "entity-analytics", "salesforce", "http_endpoint",
    "streaming", "websocket", "lumberjack", "cometd", "netflow", "azure-monitor",
    "benchmark", "cloudfoundry", "kafka", "redis", "mqtt",
}

# Preferred index-sort grouping fields, best first.
SORT_CANDIDATES = [
    "cloud.account.id",
    "organization.id",
    "cloud.project.id",
    "cloud.instance.id",
    "orchestrator.namespace",
    "observer.name",
    "observer.serial_number",
    "service.name",
    "agent.id",
]

# Vendor-specific tenant identifiers, matched on the normalised leaf name
# ("OrganizationId" and "organization_id" both normalise to "organizationid"),
# best first.
SORT_CANDIDATE_LEAVES = [
    "tenantid", "tenant", "organizationid", "orgid", "accountid", "customerid",
    "subscriptionid", "workspaceid", "projectid", "clientid", "organization",
    "instanceid", "siteid",
]

# Low-cardinality enum leaves: a poor leading sort key, so they are not accepted
# from the dashboard-frequency fallback tier.
LOW_CARDINALITY_LEAVES = {
    "severity", "priority", "level", "status", "state", "type", "action", "outcome",
    "category", "kind", "result", "verdict", "code", "reason", "provider", "direction",
}

# Constant (or near-constant) within a single data stream, so useless as a sort key
# even when dashboards filter on them constantly.
SORT_EXCLUDED_FIELDS = {
    "@timestamp", "host.name", "data_stream.type", "data_stream.dataset",
    "data_stream.namespace", "event.dataset", "event.module", "event.kind",
    "input.type", "agent.type", "agent.version", "ecs.version",
    # free-text fields: an `external: ecs` reference carries no local `type`, so they
    # would otherwise slip past the UNSORTABLE_TYPES check.
    "message", "event.original", "error.message", "url.full", "url.original",
    "user_agent.original", "process.command_line", "file.path",
}

FIELD_CHILD_KEYS = ("fields",)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def worse(a: str, b: str) -> str:
    return a if STATUS_ORDER.index(a) >= STATUS_ORDER.index(b) else b


def load_yaml(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
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


# Severity drives the data stream status:
#   blocker  -> BLOCKED              (Class A, no mechanical fix)
#   auto_fix -> READY_AFTER_AUTO_FIX (Class A, mechanical fix available)
#   review   -> NEEDS_REVIEW         (data loss, or a judgement call)
#   info     -> no status impact     (Class C behaviour change)
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


# --------------------------------------------------------------------------- #
# Field-tree walking
# --------------------------------------------------------------------------- #

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

def check_field(fdef: Dict[str, Any], flat: str, nested_depth: int,
                in_multi_field: bool, rel_file: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    ftype = fdef.get("type")

    # --- Class A: rejected by Elasticsearch -------------------------------- #
    if ftype == "nested":
        if nested_depth >= 1:
            out.append(finding(
                "nested_in_nested", "A", "blocker",
                f"`{flat}` is a `nested` field inside another `nested` field.",
                "Flatten the inner level to leaf arrays, or map it as `type: flattened`.",
                rel_file, flat))
        else:
            # Single level nested is accepted but the flattened shape changes.
            out.append(finding(
                "nested_single_level", "A", "review",
                f"`{flat}` is a single-level `nested` field.",
                "Accepted by columnar mode, but confirm consumers tolerate the flattened "
                "synthetic-source shape (object arrays are not retained faithfully).",
                rel_file, flat))

    if is_false(fdef.get("doc_values")) and not in_multi_field:
        if is_true(fdef.get("store")):
            pass  # reconstructable from the stored field: accepted by Elasticsearch
        else:
            out.append(finding(
                "doc_values_false", "A", "auto_fix",
                f"`{flat}` sets `doc_values: false`; columnar mode cannot reconstruct it.",
                "Remove `doc_values: false`, or add `store: true` (good for large "
                "search-only strings such as `event.original`), or use `match_only_text` "
                "for message-like content.",
                rel_file, flat))

    if fdef.get("copy_to") is not None:
        out.append(finding(
            "copy_to", "A", "auto_fix",
            f"`{flat}` uses `copy_to`, which blocks synthetic-source reconstruction.",
            "Do the copy in the ingest pipeline (`set`/`append` processor), or drop the "
            "target field.",
            rel_file, flat))

    if ftype == "keyword" and fdef.get("normalizer"):
        out.append(finding(
            "keyword_normalizer", "A", "auto_fix",
            f"`{flat}` is a keyword with a `normalizer`, which blocks reconstruction.",
            "Apply the transformation in the ingest pipeline (`lowercase` processor) and map "
            "a plain `keyword`; or move the normalized variant into `multi_fields` "
            "(multi-fields are exempt).",
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
    if fdef.get("external") == "ecs" and flat in ECS_DOC_VALUES_FALSE:
        overridden = is_true(fdef.get("doc_values")) or is_true(fdef.get("store"))
        if not overridden:
            out.append(finding(
                "doc_values_false_ecs", "A", "auto_fix",
                f"`{flat}` is imported from ECS, which defines it with `doc_values: false`; "
                f"elastic-package copies that into the built package.",
                f"Override it in the package fields file:\n"
                f"    - name: {flat}\n      external: ecs\n      store: true\n"
                f"(`store: true` keeps the value retrievable and satisfies the columnar "
                f"reconstructability check.)",
                rel_file, flat))

    return out


def check_stream_manifest(manifest: Dict[str, Any], rel_file: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    es = manifest.get("elasticsearch") or {}
    if not isinstance(es, dict):
        return out

    if es.get("source_mode") == "stored":
        out.append(finding(
            "source_mode_stored", "A", "blocker",
            "`elasticsearch.source_mode: stored` conflicts with columnar mode, which never "
            "stores the original `_source`.",
            "Remove the `source_mode` override, or keep the data stream on logsdb.",
            rel_file))

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
                "Remove the `_source` override.", rel_file))
        if source.get("mode") == "stored":
            out.append(finding(
                "source_mode_stored", "A", "blocker",
                "`_source.mode: stored` is incompatible with columnar mode.",
                "Remove the `_source` override.", rel_file))

    if is_false(mappings.get("dynamic")):
        out.append(finding(
            "dynamic_false_manifest", "B", "review",
            "`elasticsearch.index_template.mappings.dynamic: false`; with no stored `_source`, "
            "every unmapped field in this data stream is permanently lost.",
            "Confirm the unmapped fields are expendable, add explicit mappings, or switch to "
            "`dynamic: true` / `dynamic: strict`.",
            rel_file))

    dts = mappings.get("dynamic_templates")
    if dts:
        if _contains_dynamic_false(dts):
            out.append(finding(
                "dynamic_false_template", "B", "review",
                "A `dynamic_templates` entry sets `dynamic: false`; objects it matches lose "
                "their unmapped sub-fields.",
                "Review the template; prefer `dynamic: true` or explicit mappings.",
                rel_file))
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


# --------------------------------------------------------------------------- #
# Index sort recommendation
# --------------------------------------------------------------------------- #

DASHBOARD_FIELD_RE = re.compile(r'\\?"(?:field|key|sourceField)\\?"\s*:\s*\\?"([a-zA-Z][\w.@-]*)\\?"')


def dashboard_field_frequency(pkg_dir: str, limit_bytes: int = 4_000_000) -> Counter:
    """Field names referenced by the package's Kibana assets (filters, group-bys)."""
    counts: Counter = Counter()
    kibana_dir = os.path.join(pkg_dir, "kibana")
    if not os.path.isdir(kibana_dir):
        return counts
    for root, _dirs, files in os.walk(kibana_dir):
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
            for match in DASHBOARD_FIELD_RE.finditer(text):
                counts[match.group(1)] += 1
    return counts


def recommend_sort(stream: Dict[str, Any], field_index: Dict[str, Dict[str, Any]],
                   dash_fields: Counter) -> Dict[str, Any]:
    """Decide whether the logsdb_columnar default sort is right for this stream."""
    inputs = stream["inputs"]
    host_inputs = sorted(i for i in inputs if i in HOST_MEANINGFUL_INPUTS)
    api_inputs = sorted(i for i in inputs if i in COLLECTOR_INPUTS)
    host_mapped = "host.name" in field_index or "host.hostname" in field_index
    host_in_sample = stream.get("host_name_in_sample", False)

    host_meaningful = bool(host_inputs) and not api_inputs and (host_mapped or host_in_sample)

    reason_bits = []
    if host_inputs:
        reason_bits.append(f"host-local input(s): {', '.join(host_inputs)}")
    if api_inputs:
        reason_bits.append(f"remote/API input(s): {', '.join(api_inputs)} (host = collector)")
    if host_in_sample:
        reason_bits.append("`host.name` present in sample_event.json")
    elif host_mapped:
        reason_bits.append("`host.name` mapped but not seen in sample data")
    else:
        reason_bits.append("`host.name` not mapped")

    if host_meaningful:
        return {
            "recommendation": "default OK",
            "sort_fields": ["host.name", "@timestamp"],
            "sort_orders": ["asc", "desc"],
            "reason": "; ".join(reason_bits),
            "explicit_sort_yaml": None,
            "dashboard_top_fields": [f for f, _ in dash_fields.most_common(10)],
        }

    candidate = _pick_sort_candidate(field_index, dash_fields)
    if candidate:
        yaml_block = (
            "elasticsearch:\n"
            "  index_template:\n"
            "    settings:\n"
            "      index:\n"
            "        sort:\n"
            f'          field: ["{candidate}", "@timestamp"]\n'
            '          order: ["asc", "desc"]\n'
        )
        return {
            "recommendation": f"explicit sort proposed: {candidate} asc, @timestamp desc",
            "sort_fields": [candidate, "@timestamp"],
            "sort_orders": ["asc", "desc"],
            "reason": "; ".join(reason_bits),
            "explicit_sort_yaml": yaml_block,
            "dashboard_top_fields": [f for f, _ in dash_fields.most_common(10)],
        }

    return {
        "recommendation": "explicit sort proposed: @timestamp desc only (no grouping field found)",
        "sort_fields": ["@timestamp"],
        "sort_orders": ["desc"],
        "reason": "; ".join(reason_bits) + "; no tenant/account/observer field found",
        "explicit_sort_yaml": (
            "elasticsearch:\n"
            "  index_template:\n"
            "    settings:\n"
            "      index:\n"
            "        sort:\n"
            '          field: ["@timestamp"]\n'
            '          order: ["desc"]\n'
        ),
        "dashboard_top_fields": [f for f, _ in dash_fields.most_common(10)],
    }


def _normalise_leaf(name: str) -> str:
    return name.rsplit(".", 1)[-1].replace("_", "").replace("-", "").lower()


def _sortable(field_index: Dict[str, Dict[str, Any]], name: str) -> bool:
    fdef = field_index.get(name)
    if fdef is None:
        return False
    if name in SORT_EXCLUDED_FIELDS:
        return False
    if fdef.get("type") in UNSORTABLE_TYPES:
        return False
    if fdef.get("type") == "constant_keyword":
        return False
    if is_false(fdef.get("doc_values")):
        return False
    if is_true(fdef.get("normalize_as_array")) or fdef.get("normalize"):
        # ECS marks these as arrays; index sort requires single-valued fields.
        return False
    return True


def _pick_sort_candidate(field_index: Dict[str, Dict[str, Any]],
                         dash_fields: Counter) -> Optional[str]:
    # 1. Well-known ECS grouping fields.
    for name in SORT_CANDIDATES:
        if _sortable(field_index, name):
            return name
    # 2. Vendor tenant/account identifiers, by normalised leaf name.
    for leaf in SORT_CANDIDATE_LEAVES:
        hits = sorted(
            (n for n in field_index
             if _normalise_leaf(n) == leaf and _sortable(field_index, n)),
            key=lambda n: (n.count("."), len(n)),
        )
        if hits:
            return hits[0]
    # 3. Otherwise the field the package's own dashboards lean on most.
    for name, _count in dash_fields.most_common(40):
        if name.startswith("_") or _normalise_leaf(name) in LOW_CARDINALITY_LEAVES:
            continue
        if _sortable(field_index, name):
            return name
    return None


# --------------------------------------------------------------------------- #
# Package audit
# --------------------------------------------------------------------------- #

def audit_package(pkg_dir: str, scan_dashboards: bool = True) -> Dict[str, Any]:
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

    dash_fields = dashboard_field_frequency(pkg_dir) if scan_dashboards else Counter()
    result["dashboard_top_fields"] = [f for f, _ in dash_fields.most_common(15)]

    status = "OUT_OF_SCOPE"
    for ds_name in sorted(os.listdir(ds_root)):
        ds_dir = os.path.join(ds_root, ds_name)
        if not os.path.isdir(ds_dir):
            continue
        stream = audit_data_stream(pkg_dir, ds_dir, ds_name, dash_fields)
        result["data_streams"].append(stream)
        status = worse(status, stream["status"])
    result["status"] = status
    return result


def audit_data_stream(pkg_dir: str, ds_dir: str, ds_name: str,
                      dash_fields: Counter) -> Dict[str, Any]:
    rel = lambda p: os.path.relpath(p, pkg_dir)  # noqa: E731
    stream: Dict[str, Any] = {
        "data_stream": ds_name,
        "status": "OUT_OF_SCOPE",
        "type": None,
        "index_mode": None,
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
    stream["index_mode"] = ((manifest.get("elasticsearch") or {}) or {}).get("index_mode") \
        if isinstance(manifest.get("elasticsearch"), dict) else None

    if stream["type"] != "logs":
        stream["out_of_scope_reason"] = f"data stream type is `{stream['type']}` (logs only)"
        return stream

    stream["inputs"] = sorted({
        s.get("input") for s in (manifest.get("streams") or []) if isinstance(s, dict) and s.get("input")
    })

    findings = check_stream_manifest(manifest, rel(manifest_path))

    # Fields
    field_index: Dict[str, Dict[str, Any]] = {}
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
                if not in_mf:
                    field_index.setdefault(flat, fdef)
                findings.extend(check_field(fdef, flat, depth, in_mf, rel(fpath)))

    stream["findings"] = findings
    stream["field_count"] = len(field_index)
    stream["host_name_in_sample"] = sample_has_host_name(ds_dir)
    stream["sort"] = recommend_sort(stream, field_index, dash_fields)
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


def sample_has_host_name(ds_dir: str) -> bool:
    path = os.path.join(ds_dir, "sample_event.json")
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return False
    host = doc.get("host")
    if isinstance(host, dict) and host.get("name"):
        return True
    return bool(doc.get("host.name"))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def md_package(result: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append(f"# Columnar readiness: `{result['package']}`")
    lines.append("")
    lines.append(f"- Status: **{result['status']}**")
    lines.append(f"- Package type: `{result.get('type')}`, version `{result.get('version')}`, "
                 f"format_version `{result.get('format_version')}`")
    if result.get("kibana_condition"):
        lines.append(f"- Kibana condition: `{result['kibana_condition']}` "
                     f"(needs `^9.5.0` for logsdb_columnar)")
    if result.get("out_of_scope_reason"):
        lines.append(f"- Out of scope: {result['out_of_scope_reason']}")
    for err in result.get("errors", []):
        lines.append(f"- Parse error: {err}")
    lines.append("")

    in_scope = [s for s in result["data_streams"] if s["status"] != "OUT_OF_SCOPE"]
    skipped = [s for s in result["data_streams"] if s["status"] == "OUT_OF_SCOPE"]

    if in_scope:
        lines.append("| Data stream | Status | Findings | Index sort |")
        lines.append("| --- | --- | --- | --- |")
        for s in in_scope:
            lines.append(f"| `{s['data_stream']}` | {s['status']} | {len(s['findings'])} | "
                         f"{s['sort']['recommendation']} |")
        lines.append("")

    for s in in_scope:
        lines.append(f"## `{s['data_stream']}` — {s['status']}")
        lines.append("")
        lines.append(f"- Inputs: {', '.join(f'`{i}`' for i in s['inputs']) or '(none declared)'}")
        lines.append(f"- Current `index_mode`: `{s['index_mode'] or 'unset (logsdb default)'}`")
        lines.append(f"- Sort: **{s['sort']['recommendation']}** — {s['sort']['reason']}")
        if s["sort"]["explicit_sort_yaml"]:
            lines.append("")
            lines.append("  Add to `data_stream/%s/manifest.yml`:" % s["data_stream"])
            lines.append("")
            lines.append("  ```yaml")
            for ln in s["sort"]["explicit_sort_yaml"].rstrip("\n").split("\n"):
                lines.append(f"  {ln}")
            lines.append("  ```")
        lines.append("")
        if not s["findings"]:
            lines.append("No blocking or lossy mapping features found.")
            lines.append("")
            continue
        for klass, title in (("A", "Class A — rejected by Elasticsearch"),
                             ("B", "Class B — accepted but lossy"),
                             ("C", "Class C — behaviour change")):
            group = [f for f in s["findings"] if f["class"] == klass]
            if not group:
                continue
            lines.append(f"### {title}")
            lines.append("")
            for f in group:
                tag = " (auto-fixable)" if f["auto_fixable"] else ""
                lines.append(f"- `{f['code']}`{tag} — {f['message']}")
                lines.append(f"  - Where: `{f['where']}`")
                for idx, ln in enumerate(f["remediation"].split("\n")):
                    lines.append(f"  - {ln}" if idx == 0 else f"    {ln}")
            lines.append("")

    if skipped:
        lines.append("## Out of scope")
        lines.append("")
        for s in skipped:
            lines.append(f"- `{s['data_stream']}`: {s.get('out_of_scope_reason', 'skipped')}")
        lines.append("")
    if result.get("dashboard_top_fields"):
        lines.append("## Dashboard fields (benchmark workload / sort tie-break)")
        lines.append("")
        lines.append(", ".join(f"`{f}`" for f in result["dashboard_top_fields"]))
        lines.append("")
    return "\n".join(lines)


def md_catalog(results: List[Dict[str, Any]]) -> str:
    by_status: Dict[str, List[str]] = {st: [] for st in STATUS_ORDER}
    for r in results:
        by_status[r["status"]].append(r["package"])

    stream_status: Counter = Counter()
    for r in results:
        for s in r["data_streams"]:
            stream_status[s["status"]] += 1

    # code -> {package -> set(data streams)}
    by_code: Dict[str, Dict[str, set]] = {}
    code_class: Dict[str, Tuple[str, str]] = {}
    for r in results:
        for s in r["data_streams"]:
            for f in s["findings"]:
                by_code.setdefault(f["code"], {}).setdefault(r["package"], set()).add(s["data_stream"])
                code_class[f["code"]] = (f["class"], f["severity"])

    def code_rows(codes: List[str]) -> List[str]:
        out: List[str] = []
        for code in codes:
            pkgs = by_code.get(code)
            if not pkgs:
                continue
            nstreams = sum(len(v) for v in pkgs.values())
            klass, sev = code_class[code]
            out.append(f"### `{code}` — class {klass}, {sev}")
            out.append("")
            out.append(f"{len(pkgs)} packages, {nstreams} data streams.")
            out.append("")
            for pkg in sorted(pkgs):
                out.append(f"- `{pkg}`: " + ", ".join(sorted(pkgs[pkg])))
            out.append("")
        return out

    def union(codes: List[str]) -> Tuple[int, int, List[str]]:
        pkgs: Dict[str, set] = {}
        for code in codes:
            for pkg, streams in by_code.get(code, {}).items():
                pkgs.setdefault(pkg, set()).update(streams)
        return len(pkgs), sum(len(v) for v in pkgs.values()), sorted(pkgs)

    lines: List[str] = []
    lines.append("# Columnar readiness — catalog audit")
    lines.append("")
    in_scope_pkgs = sum(1 for r in results
                        if any(s["status"] != "OUT_OF_SCOPE" for s in r["data_streams"]))
    lines.append(f"Packages scanned: {len(results)}")
    lines.append(f"Candidate packages (at least one `type: logs` data stream): {in_scope_pkgs}")
    lines.append("")
    lines.append("| Status | Packages | Logs data streams |")
    lines.append("| --- | --- | --- |")
    for st in ("BLOCKED", "NEEDS_REVIEW", "READY_AFTER_AUTO_FIX", "READY"):
        lines.append(f"| {st} | {len(by_status[st])} | {stream_status[st]} |")
    lines.append(f"| OUT_OF_SCOPE (input package / no logs streams) | "
                 f"{len(by_status['OUT_OF_SCOPE'])} | {stream_status['OUT_OF_SCOPE']} |")
    lines.append("")

    BLOCKER_CODES = ["nested_in_nested", "unsupported_type", "source_mode_stored", "source_disabled"]
    AUTOFIX_SRC_CODES = ["doc_values_false", "copy_to", "keyword_normalizer"]
    LOSS_CODES = ["dynamic_false_manifest", "dynamic_false_field", "dynamic_false_template",
                  "enabled_false"]

    npkg, nds, _ = union(BLOCKER_CODES)
    lines.append(f"## Blockers — Class A, no mechanical fix ({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(BLOCKER_CODES) or ["(none)", ""])

    npkg, nds, pkglist = union(BLOCKER_CODES + ["doc_values_false"])
    lines.append("## Hard mapping errors declared in the package source "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append("Union of `nested_in_nested` and `doc_values_false`. This is the set the "
                 "preliminary catalog analysis called *blocked*; under the status rules in "
                 "`references/report-template.md` the `doc_values_false` ones are "
                 "READY_AFTER_AUTO_FIX because `store: true` fixes them mechanically.")
    lines.append("")
    lines.append(", ".join(f"`{p}`" for p in pkglist) or "(none)")
    lines.append("")

    npkg, nds, _ = union(AUTOFIX_SRC_CODES)
    lines.append("## Class A, mechanically fixable — declared in the package source "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(AUTOFIX_SRC_CODES) or ["(none)", ""])

    npkg, nds, _ = union(["doc_values_false_ecs"])
    lines.append("## Class A, mechanically fixable — inherited from ECS "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append("`external: ecs` imports `doc_values` from the ECS schema into the built "
                 "package, so these never appear in the package source. See "
                 "`references/blockers.md`.")
    lines.append("")
    lines.extend(code_rows(["doc_values_false_ecs"]) or ["(none)", ""])

    npkg, nds, pkglist = union(LOSS_CODES)
    lines.append(f"## Data-loss review — Class B ({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append(", ".join(f"`{p}`" for p in pkglist) or "(none)")
    lines.append("")
    lines.extend(code_rows(LOSS_CODES))

    npkg, nds, _ = union(["nested_single_level", "runtime_field"])
    lines.append(f"## Judgement calls — review ({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(["nested_single_level", "runtime_field"]) or ["(none)", ""])

    lines.append("## Packages by status")
    lines.append("")
    for st in ("BLOCKED", "NEEDS_REVIEW", "READY_AFTER_AUTO_FIX", "READY"):
        pkgs = sorted(by_status[st])
        lines.append(f"### {st} ({len(pkgs)})")
        lines.append("")
        lines.append(", ".join(f"`{p}`" for p in pkgs) or "(none)")
        lines.append("")

    default_ok, explicit = 0, 0
    for r in results:
        for s in r["data_streams"]:
            if s["status"] == "OUT_OF_SCOPE":
                continue
            if s["sort"]["recommendation"] == "default OK":
                default_ok += 1
            else:
                explicit += 1
    lines.append("## Index sort")
    lines.append("")
    lines.append(f"- Default `host.name asc, @timestamp desc` looks right: {default_ok} data streams")
    lines.append(f"- Explicit sort proposed: {explicit} data streams "
                 "(run the audit per package to see the proposal)")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("path", help="package directory, or the packages/ root with --catalog")
    parser.add_argument("--catalog", action="store_true",
                        help="treat PATH as a directory of packages and print a catalog summary")
    parser.add_argument("--format", choices=["markdown", "json", "both"], default="markdown")
    parser.add_argument("--out", help="write the report to this file instead of stdout")
    parser.add_argument("--status", action="append",
                        help="in catalog mode, only list packages with this status (repeatable)")
    parser.add_argument("--dashboards", dest="dashboards", action="store_true", default=None,
                        help="scan kibana/ assets for sort tie-breaks (default: on for a single "
                             "package, off for --catalog)")
    parser.add_argument("--no-dashboards", dest="dashboards", action="store_false")
    args = parser.parse_args(argv)

    scan_dashboards = (not args.catalog) if args.dashboards is None else args.dashboards

    if args.catalog:
        root = os.path.abspath(args.path.rstrip("/"))
        pkg_dirs = [os.path.join(root, d) for d in sorted(os.listdir(root))
                    if os.path.isfile(os.path.join(root, d, "manifest.yml"))]
        results = [audit_package(p, scan_dashboards) for p in pkg_dirs]
        if args.status:
            wanted = {s.upper() for s in args.status}
            results_out = [r for r in results if r["status"] in wanted]
        else:
            results_out = results
        md = md_catalog(results)
        payload: Any = {
            "mode": "catalog",
            "root": root,
            "packages": results_out,
            "summary": {
                "scanned": len(results),
                "by_status": {s: sorted(r["package"] for r in results if r["status"] == s)
                              for s in STATUS_ORDER},
            },
        }
    else:
        result = audit_package(args.path, scan_dashboards)
        md = md_package(result)
        payload = result

    chunks = []
    if args.format in ("markdown", "both"):
        chunks.append(md)
    if args.format in ("json", "both"):
        chunks.append(json.dumps(payload, indent=2, sort_keys=False))
    text = "\n\n".join(chunks)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
