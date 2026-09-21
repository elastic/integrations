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

# The only types accepted as the *leading* index-sort field. This is an allow-list:
# everything else is rejected, including types Lucene can technically sort on.
#   * `text`, `match_only_text`, `wildcard`, `flattened`, `nested`, `object`, `group`,
#     `geo_point`, `geo_shape`, `histogram`, `aggregate_metric_double` and `binary`
#     cannot be sorted on at all;
#   * `boolean` and low-cardinality enums prune almost nothing;
#   * `double`/`float`/`scaled_float`/`half_float` are per-event measurements, so a
#     sort on them destroys time locality and compresses worse, not better;
#   * `date` other than `@timestamp` is a second clock, not a grouping dimension;
#   * `constant_keyword` has exactly one value per index.
SORTABLE_STRING_TYPES = {"keyword", "ip"}

# Integer types are sortable *in Lucene*, but the overwhelming majority of integer
# fields in an integration are measurements (`*.total.bytes`, `*.time_to_close.sec`,
# `*.progress`), and sorting on a measurement is actively harmful: it shuffles
# documents out of time order and compresses worse. So an integer field is only
# accepted when its **name** says it is an identifier — see `_numeric_leaf_is_id`.
SORTABLE_NUMERIC_TYPES = {"long", "integer", "short", "byte", "unsigned_long"}

SORTABLE_TYPES = SORTABLE_STRING_TYPES | SORTABLE_NUMERIC_TYPES

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

# Inputs where the agent runs on (or next to) the machine that produced the log, so
# `host.name` is a meaningful, high-cardinality dimension.
#
# Whether the default sort is right is decided from the input types ALONE. Elastic
# Agent's `add_host_metadata` processor populates `host.name` on every event
# regardless of what the package's `fields/*.yml` declare, and Elasticsearch injects
# the `host.name` mapping itself when the template does not define one
# (`LogsdbIndexModeSettingsProvider.MappingHints`, `IndexSortConfig#buildIndexSort`).
# So "`host.name` is not in fields/*.yml" and "no sample_event.json" are NOT evidence
# that the default sort is wrong.
HOST_MEANINGFUL_INPUTS = {
    "logfile", "filestream", "log", "journald", "winlog", "unix", "system/metrics",
    "docker", "containerd", "filestream-container", "event/file",
    "etw", "audit/auditd", "audit/file_integrity", "audit/system",
    "auditd-logfile", "system/auth", "unifiedlogs", "osquery", "packet",
    "cloud_defend/control", "kubernetes/container_logs",
}

# Network receivers: the agent listens and a *remote* device pushes to it. The agent
# host is neither the subject (as with `filestream`) nor a poller of a single tenant
# (as with `httpjson`) — it is a syslog sink for many devices, and what `host.name`
# ends up holding is decided by the ingest pipeline, not by the input:
#
#   * `cisco_asa` sets `host.name` in one grok branch only, and copies
#     `host.hostname` into `observer.hostname`;
#   * `fortinet_fortigate` renames `devname` to `observer.name` but sets `host.name`
#     from `fortinet.firewall.srcname` — the *client*, not the firewall;
#   * `checkpoint` sets `observer.name` from `origin`, and `host.name` only on
#     login events;
#   * `panw` fills `observer.hostname`/`observer.serial_number` from the syslog
#     header in every sub-pipeline and sets `host.name` only for client events.
#
# So these get their own class and their own evidence source: the pipeline.
# Deliberately narrow — `http_endpoint`, `netflow`, `lumberjack`, `cometd` and
# `kafka` are also push-style, but they stay in `COLLECTOR_INPUTS` because their
# payloads carry a tenant/exporter identity rather than a syslog device header.
RECEIVER_INPUTS = {"tcp", "udp", "syslog"}

# Device identifiers a receiver pipeline may populate from the syslog header, best
# first. These are the only sort keys proposed for a receiver stream.
RECEIVER_SORT_FIELDS = ["observer.name", "observer.hostname", "observer.serial_number"]

# Inputs that poll or receive from a remote API: the agent host is the collector, not
# the subject, so the default `host.name` sort degenerates to one value per agent.
COLLECTOR_INPUTS = {
    "httpjson", "cel", "aws-s3", "aws-cloudwatch", "gcp-pubsub", "gcs", "azure-eventhub",
    "azure-blob-storage", "o365audit", "entity-analytics", "salesforce", "http_endpoint",
    "streaming", "websocket", "lumberjack", "cometd", "netflow", "azure-monitor",
    "benchmark", "cloudfoundry", "kafka", "redis", "mqtt", "okta",
    "cloudbeat/asset_inventory_aws", "cloudbeat/asset_inventory_azure",
    "cloudbeat/asset_inventory_gcp", "cloudbeat/cis_aws", "cloudbeat/cis_azure",
    "cloudbeat/cis_eks", "cloudbeat/cis_gcp", "cloudbeat/cis_k8s",
    "cloudbeat/vuln_mgmt_aws",
}

# Preferred index-sort grouping fields, best first.
#
# These are accepted from two sources: a declaration in `fields/*.yml`, and — because
# ECS fields are supplied by the `ecs@mappings` component template at install time and
# therefore frequently left undeclared — a scalar value in `sample_event.json`, with
# the type and the array flag resolved from the ECS cache. See
# `_ecs_sample_candidate`.
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

# `agent.id` identifies the *collector*, so it is only a grouping dimension when the
# agent is the subject. For an API poller it is one value for the whole data stream,
# and 334 poller streams carry it in their sample event — so it is never taken from
# the sample-event path, and it is dropped from tier 1 entirely when the stream
# offers a poller input. It is kept for streams that declare no input at all
# (`elastic_agent`/`fleet_server` self-telemetry), where the agent *is* the subject
# and `agent.id` is one series per agent across the fleet.
SORT_CANDIDATES_COLLECTOR_ONLY = {"agent.id"}

# Vendor-specific tenant identifiers, matched on the normalised leaf name
# ("OrganizationId" and "organization_id" both normalise to "organizationid"),
# best first.
SORT_CANDIDATE_LEAVES = [
    "tenantid", "tenant", "organizationid", "orgid", "accountid", "customerid",
    "subscriptionid", "workspaceid", "projectid", "clientid", "organization",
    "instanceid", "siteid",
]

# --------------------------------------------------------------------------- #
# Leaf-name vocabulary
#
# The tiers below decide from the *name* whether a field is a grouping dimension.
# All of these match on **tokens** of the last path segment — the leaf is split on
# `_`, `-` and camelCase boundaries and lowercased, so `errorMessage` is
# `{error, message}` and `response_time_in_seconds` is
# `{response, time, in, seconds}`. Token matching, not substring matching, is what
# keeps `security_id` out of the `sec` (seconds) bucket.
# --------------------------------------------------------------------------- #

# Marks an integer field as an identifier rather than a measurement. Either the leaf
# carries an id token (`id`, `uid`, so `account_id` / `eventId` / plain `id`), or it
# names a tenant-like entity outright (`tenant`, `organization`, …).
ID_TOKENS = {"id", "uid", "identifier"}  # `guid` is in HASH_TOKENS: it is per-event
TENANT_TOKENS = {
    "account", "tenant", "organization", "organisation", "org", "customer",
    "project", "subscription", "workspace", "client", "site", "instance",
}

# Measurement words. A field whose leaf carries one of these is a per-event number:
# sorting on it destroys time locality, and it prunes nothing a dashboard filters on.
MEASUREMENT_TOKENS = {
    "bytes", "byte", "bits", "kb", "mb", "gb", "count", "total", "sum", "avg", "mean",
    "min", "max", "seconds", "second", "sec", "ms", "millis", "duration", "time",
    "memory", "size", "length", "progress", "percent", "pct", "ratio", "rate",
    "value", "latency", "elapsed", "age", "score", "usage", "credits", "remaining",
}

# Per-event hashes and UUIDs: maximum cardinality, zero grouping. Any token ending in
# `hash` counts too, which is what catches `pehash`, `imphash` and `authentihash`.
HASH_TOKENS = {
    "hash", "uuid", "guid", "checksum", "fingerprint", "digest", "nonce",
    "md5", "sha", "sha1", "sha256", "sha384", "sha512", "ssdeep", "tlsh", "imphash",
}

# Free text. An `external: ecs` reference carries no local `type`, and plenty of
# vendor fields map prose as `keyword`, so the type allow-list does not catch these.
FREE_TEXT_TOKENS = {
    "message", "description", "summary", "comment", "note", "reason", "solution",
    "text", "title", "body", "detail", "details", "remediation", "recommendation",
    "command", "commandline", "query", "useragent", "synopsis",
}

# Path segment *before* an `id`/`uid` leaf that makes it a per-event id rather than a
# tenant id: `blacklens.alert.id` is one value per document, `netbox.tenant.id` is
# the grouping dimension. Only the `<entity>.id` path form is rejected — a leaf that
# spells the whole thing out (`event_id`, `alert_id`) still has to pass the other
# rules, and `event_id` is a legitimate, low-ish cardinality identifier.
PER_EVENT_ENTITIES = {
    "alert", "event", "incident", "item", "message", "record", "request", "finding",
    "detection", "document", "doc", "log", "case", "ticket", "notification", "job",
    "task", "scan", "report", "trace", "span", "run", "execution", "invocation",
    "batch", "transaction", "upload", "download",
}

# A leaf ending in `s` is an array in disguise (`threat_types`,
# `product_vulnerabilities`, `tags`, `roles`, `actors`) unless it ends in one of
# these — English singulars that happen to end in `s` (`address`, `status`,
# `process`, `alias`, `analysis`, `os`).
SINGULAR_S_ENDINGS = ("ss", "us", "is", "as", "os")

# Low-cardinality enum leaves: a poor leading sort key, so they are not accepted
# from the dashboard-filter fallback tier. Matched as a **suffix** of the normalised
# leaf name, so `tls_verify_status`, `http_status`, `log_type` and `scanResult` are
# caught too.
LOW_CARDINALITY_LEAVES = {
    "severity", "priority", "level", "status", "state", "type", "action", "outcome",
    "category", "kind", "result", "verdict", "code", "reason", "provider", "direction",
    "evaluation", "decision", "disposition", "enabled", "flag", "class", "activity",
    "role", "mode", "protocol", "input", "stage", "phase", "tier", "family", "method",
    "health", "criticality", "classification", "version", "dataset", "operation",
    "whitelisted", "blacklisted",
}

# Matched on the whole normalised leaf rather than as a suffix, because they are too
# short to suffix-match safely (`op` would eat `desktop`).
LOW_CARDINALITY_EXACT = {"op", "verb", "rc", "env"}

# `<low-cardinality thing>.name` is the same enum spelled out: `alert_type.name` has
# as many values as `alert_type` does.
LOW_CARDINALITY_NAME_LEAVES = {"name", "label", "title", "display", "displayname"}

# Boolean-in-disguise prefixes: `is_portable`, `has_agent` are keyword-mapped yes/no
# flags, so they prune nothing.
BOOLEAN_LEAF_PREFIXES = ("is", "has", "can", "should", "was", "allow")

# A vendor tenant/account id nested this deep is an artifact of some request payload
# (`...context.http_request.args.client_id`), not the dataset's grouping dimension.
SORT_CANDIDATE_MAX_DEPTH = 3

# Constant (or near-constant) within a single data stream, so useless as a sort key
# even when dashboards filter on them constantly.
SORT_EXCLUDED_FIELDS = {
    "@timestamp", "host.name", "data_stream.type", "data_stream.dataset",
    "data_stream.namespace", "event.dataset", "event.module", "event.kind",
    "input.type", "agent.type", "agent.version", "ecs.version",
    # free-text fields: an `external: ecs` reference carries no local `type`, so they
    # would otherwise slip past the type allow-list.
    "message", "event.original", "error.message", "url.full", "url.original",
    "user_agent.original", "process.command_line", "file.path",
    # collector artifacts: they describe where the agent picked the data up, not who
    # the data is about, so they group nothing a dashboard filters on.
    "aws.s3.bucket.name", "aws.s3.object.key", "log.file.path", "log.offset",
    "azure.blob_storage.container", "gcs.storage.bucket.name",
}

# ECS fields that are arrays (`normalize: [array]`). Index sorting on a multi-valued
# field silently sorts on min/max, so these are never candidates. Used only when the
# ECS schema cache is unavailable; the full list is read from
# `~/.elastic-package/cache/fields/ecs/<version>/ecs_nested.yml` when it is present.
ECS_ARRAY_FIELDS_FALLBACK = {
    "tags", "event.category", "event.type", "host.ip", "host.mac",
    "related.ip", "related.hash", "related.hosts", "related.user",
    "dns.answers", "dns.resolved_ip", "dns.header_flags",
    "process.args", "process.thread.capabilities.effective",
    "user.roles", "client.user.roles", "server.user.roles", "source.user.roles",
    "destination.user.roles", "email.to.address", "email.cc.address",
    "email.bcc.address", "email.from.address", "email.reply_to.address",
    "email.attachments", "container.image.tag", "threat.tactic.id",
    "threat.tactic.name", "threat.technique.id", "threat.technique.name",
    "vulnerability.category", "registry.data.strings", "rule.author",
}

ECS_CACHE_DIR = os.path.expanduser("~/.elastic-package/cache/fields/ecs")

FIELD_CHILD_KEYS = ("fields",)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def worse(a: str, b: str) -> str:
    return a if STATUS_ORDER.index(a) >= STATUS_ORDER.index(b) else b


# --------------------------------------------------------------------------- #
# ECS schema (for `external: ecs` fields, which carry no local `type`)
# --------------------------------------------------------------------------- #

_ECS_SCHEMA: Optional[Dict[str, Dict[str, Any]]] = None


def ecs_schema() -> Dict[str, Dict[str, Any]]:
    """flat_name -> {"type": ..., "array": bool} from elastic-package's ECS cache.

    An `external: ecs` reference carries no `type` in the package source, so without
    this the sort-candidate type and array checks cannot see anything. Falls back to
    `ECS_ARRAY_FIELDS_FALLBACK` (arrays only, no types) when the cache is absent.
    """
    global _ECS_SCHEMA
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
                }
    else:
        for flat in ECS_ARRAY_FIELDS_FALLBACK:
            schema[flat] = {"type": None, "array": True}

    _ECS_SCHEMA = schema
    return schema


def _version_key(name: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", name)) or (0,)


# libyaml when it is available: the catalog run now parses every ingest pipeline in
# the repo, and the pure-Python loader makes that several times slower.
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

    # Multi-fields are exempt from the reconstructability check
    # (`MappingLookup#firstFieldNotReconstructableFromDocValues` skips
    # `isMultiField(...)`), so only top-level fields matter here.
    if is_false(fdef.get("doc_values")) and not in_multi_field:
        out.append(finding(
            "doc_values_false", "A", "auto_fix",
            f"`{flat}` sets `doc_values: false`; columnar mode cannot reconstruct it.",
            "Remove `doc_values: false` — under columnar mode the field is stored as doc "
            "values and there is no inverted index to pay for, so the original "
            "\"save space\" motivation is gone. `store: true` is NOT an alternative: "
            "Elasticsearch rejects `store` outright in columnar modes "
            "(`FieldMapper.Builder#storeParam`). For message-like content "
            "`match_only_text` also works, but only on fields the package defines itself.",
            rel_file, flat))

    if is_true(fdef.get("store")):
        out.append(finding(
            "store_true", "A", "auto_fix",
            f"`{flat}` sets `store: true`, which Elasticsearch rejects in columnar modes "
            f"(`[store] cannot be enabled on field [...] in [logsdb_columnar] index mode`).",
            "Remove `store: true`. The value is reconstructed from doc values, and "
            "`fields`/`_source` retrieval keeps working.",
            rel_file, flat))

    if fdef.get("copy_to") is not None:
        # Rejected at mapping-parse time, with no multi-field exemption:
        # `FieldMapper.TypeParser#parse` throws for `copy_to` under `isStrictColumnar()`,
        # and `copy_to` from/to a multi-field is refused independently in
        # `FieldMapper#validate`.
        out.append(finding(
            "copy_to", "A", "auto_fix",
            f"`{flat}` uses `copy_to`, which columnar mode rejects unconditionally.",
            "Do the copy in the ingest pipeline (`set`/`append` processor), or drop the "
            "target field.",
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
        # attributes win. `store: true` is not an option (rejected by Elasticsearch),
        # and `type: match_only_text` is not either — elastic-package forces the ECS
        # type unless the field is in `allowedTypeOverride`.
        if not is_true(fdef.get("doc_values")):
            out.append(finding(
                "doc_values_false_ecs", "A", "auto_fix",
                f"`{flat}` is imported from ECS, which defines it with `doc_values: false`; "
                f"elastic-package copies that into the built package.",
                f"Override it in the package fields file:\n"
                f"    - name: {flat}\n      external: ecs\n      doc_values: true\n"
                f"(package attributes win over the imported ECS ones via "
                f"`transformed.DeepUpdate(def)`.)",
                rel_file, flat))

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

    if str(mappings.get("dynamic", "")).strip().lower() == "runtime":
        out.append(finding(
            "dynamic_runtime", "A", "auto_fix",
            "`elasticsearch.index_template.mappings.dynamic: runtime` is rejected when the "
            "mapping is parsed (`ObjectMapper`: `dynamic [runtime] is not supported in "
            "strict columnar mode`) — the index template PUT fails, before any document "
            "is indexed.",
            "Use `dynamic: true` (unmapped leaves become non-indexed doc values) or map the "
            "fields explicitly.",
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

# Field name on the left of a KQL comparison: `user.name : "bob"`, `bytes >= 100`.
KQL_FIELD_RE = re.compile(r'([a-zA-Z][\w.@*-]*)\s*(?::|>=|<=|>|<)')
KQL_KEYWORDS = {"and", "or", "not"}


def dashboard_fields(pkg_dir: str, limit_bytes: int = 4_000_000) -> Tuple[Counter, Counter]:
    """(referenced, filtered) field-name counters from the package's Kibana assets.

    `referenced` is every `field`/`key`/`sourceField` mention — axes, group-bys,
    metrics, columns. It is the benchmark workload.

    `filtered` counts only fields used in a **filter or query clause**: Kibana filter
    pills (`filter[].meta.key`) and KQL query strings. That is much stronger evidence
    for an index-sort key, because sorting only pays off for fields queries *prune*
    on. Being plotted on an axis says nothing about pruning.
    """
    referenced: Counter = Counter()
    filtered: Counter = Counter()
    kibana_dir = os.path.join(pkg_dir, "kibana")
    if not os.path.isdir(kibana_dir):
        return referenced, filtered
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
                referenced[match.group(1)] += 1
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            _collect_filter_fields(doc, filtered)
    return referenced, filtered


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


# --------------------------------------------------------------------------- #
# Ingest-pipeline evidence
#
# Two questions the mapping cannot answer:
#   * which object paths actually hold *lists* (CloudTrail's
#     `aws.cloudtrail.resources` is a plain `group` in `fields.yml`);
#   * which fields a **receiver** pipeline populates, and whether it does so
#     unconditionally (`host.name` set in one grok branch out of twelve is not the
#     same thing as `host.name` parsed from every syslog header).
# --------------------------------------------------------------------------- #

# Painless roots used for the not-yet-renamed source document. A path under one of
# these is matched against a field's ancestors by its tail, because
# `$("json.resources", []).stream()` and `aws.cloudtrail.resources` are the same
# object at two points in the pipeline.
PIPELINE_TEMP_ROOTS = {"json", "_temp_", "_temp", "_tmp", "_conf", "_ingest"}

# Painless array idioms.
_PAINLESS_ARRAY_RES = [
    re.compile(r'\$\(\s*"([\w.@]+)"\s*,\s*\[\s*\]\s*\)\s*\.stream\(\)'),
    re.compile(r'ctx\.?\??\.?([\w.?@]+?)\s*\.stream\(\)'),
    re.compile(r'ctx\.?\??\.?([\w.?@]+?)\s+instanceof\s+List'),
    re.compile(r'for\s*\(\s*def\s+\w+\s*:\s*ctx\.?\??\.?([\w.?@]+?)\s*\)'),
    re.compile(r'ctx\.?\??\.?([\w.?@]+?)\s*=\s*new\s+ArrayList'),
]

# `%{PATTERN:target.field}` / `%{PATTERN:target.field:type}` inside a grok pattern,
# and `%{target.field}` inside a dissect pattern.
_GROK_TARGET_RE = re.compile(r'%\{[A-Z0-9_]+:([\w.@]+)(?::\w+)?\}')
_DISSECT_TARGET_RE = re.compile(r'%\{[+&?*]?([\w.@]+)[^}]*\}')

# Processors that do not produce their `field` as an output.
_NON_PRODUCING_PROCESSORS = {
    "remove", "drop", "fail", "pipeline", "grok", "dissect", "script", "enrich",
    "terminate", "reroute",
}


class PipelineFacts:
    """What the ingest pipelines of one data stream say about its fields."""

    def __init__(self) -> None:
        self.array_paths: set = set()        # exact dotted paths iterated as lists
        self.array_tails: set = set()        # same, below a temp root: matched by tail
        self.targets: set = set()            # every field the pipelines write
        self.unconditional_targets: set = set()

    def is_array(self, path: str) -> bool:
        if path in self.array_paths:
            return True
        return any(path == tail or path.endswith("." + tail) for tail in self.array_tails)

    def _add_array(self, raw: str) -> None:
        path = raw.replace("?", "").strip(".")
        if not path:
            return
        self.array_paths.add(path)
        head, _, tail = path.partition(".")
        if head in PIPELINE_TEMP_ROOTS and tail:
            self.array_tails.add(tail)


def scan_pipelines(ds_dir: str) -> PipelineFacts:
    facts = PipelineFacts()
    pipeline_dir = os.path.join(ds_dir, "elasticsearch", "ingest_pipeline")
    if not os.path.isdir(pipeline_dir):
        return facts
    for fname in sorted(os.listdir(pipeline_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(pipeline_dir, fname)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for regex in _PAINLESS_ARRAY_RES:
            for match in regex.finditer(text):
                facts._add_array(match.group(1))
        try:
            doc = yaml.load(text, Loader=YAML_LOADER)
        except Exception:
            continue
        if isinstance(doc, dict):
            _walk_processors(doc.get("processors") or [], facts, conditional=False)
            _walk_processors(doc.get("on_failure") or [], facts, conditional=True)
    return facts


def _walk_processors(procs: Any, facts: PipelineFacts, conditional: bool) -> None:
    if not isinstance(procs, list):
        return
    for entry in procs:
        if not isinstance(entry, dict):
            continue
        for ptype, body in entry.items():
            if not isinstance(body, dict):
                continue
            cond = conditional or body.get("if") is not None
            if ptype == "foreach":
                field = body.get("field")
                if isinstance(field, str):
                    facts._add_array(field)
                _walk_processors([body.get("processor")] if body.get("processor") else [],
                                 facts, conditional=True)
            elif ptype in ("grok", "dissect"):
                _add_pattern_targets(ptype, body, facts, cond)
            elif ptype not in _NON_PRODUCING_PROCESSORS:
                target = body.get("target_field") or body.get("field")
                if isinstance(target, str):
                    facts.targets.add(target)
                    if not cond:
                        facts.unconditional_targets.add(target)
            _walk_processors(body.get("on_failure") or [], facts, conditional=True)


def _add_pattern_targets(ptype: str, body: Dict[str, Any], facts: PipelineFacts,
                         conditional: bool) -> None:
    """Grok/dissect targets.

    A target is unconditional only when it appears in **every** pattern of the
    processor: `cisco_asa` sets `host.name` in one branch of a twelve-pattern grok,
    which is not the same as a syslog header parsed the same way every time.
    """
    regex = _GROK_TARGET_RE if ptype == "grok" else _DISSECT_TARGET_RE
    # Named sub-patterns are always a branch of an alternation, never guaranteed.
    for definition in (body.get("pattern_definitions") or {}).values():
        if isinstance(definition, str):
            facts.targets |= {m.group(1) for m in regex.finditer(definition)}
    patterns = body.get("patterns") or body.get("pattern") or []
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(patterns, list):
        return
    per_pattern = []
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        found = {m.group(1) for m in regex.finditer(pattern)}
        per_pattern.append(found)
        facts.targets |= found
    if per_pattern and not conditional:
        facts.unconditional_targets |= set.intersection(*per_pattern)


SORT_YAML_HEADER = (
    "elasticsearch:\n"
    "  index_template:\n"
    "    settings:\n"
    "      index:\n"
    "        sort:\n"
)


def _sort_yaml(fields: List[str], orders: List[str]) -> str:
    return (
        SORT_YAML_HEADER
        + "          field: [" + ", ".join(f'"{f}"' for f in fields) + "]\n"
        + "          order: [" + ", ".join(f'"{o}"' for o in orders) + "]\n"
    )


def recommend_sort(stream: Dict[str, Any], field_index: Dict[str, Dict[str, Any]],
                   dash_fields: Counter, filter_fields: Counter,
                   array_fields: Optional[set] = None,
                   pipeline_arrays: Optional[PipelineFacts] = None,
                   sample: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Decide whether the logsdb_columnar default sort is right for this stream.

    The input types pick the **regime**:

      * host-local (`filestream`, `winlog`, …) — the agent runs on the subject, so
        the default `host.name asc, @timestamp desc` is right. Elastic Agent
        populates `host.name` on every event via `add_host_metadata`, and
        Elasticsearch injects the mapping when the template lacks one, so the
        absence of `host.name` from `fields/*.yml` or from `sample_event.json`
        proves nothing. Mapping evidence is used only to downgrade.
      * receiver (`tcp`, `udp`, `syslog`) — a remote device pushes to the agent, and
        what `host.name` holds is whatever the pipeline put there. Evidence comes
        from the pipeline, not from the input.
      * collector / API poller — the agent host is one value, so an explicit sort on
        a tenant-like dimension is needed.
    """
    inputs = stream["inputs"]
    host_inputs = sorted(i for i in inputs if i in HOST_MEANINGFUL_INPUTS)
    receiver_inputs = sorted(i for i in inputs if i in RECEIVER_INPUTS)
    api_inputs = sorted(i for i in inputs if i in COLLECTOR_INPUTS)
    unknown_inputs = sorted(
        set(inputs) - HOST_MEANINGFUL_INPUTS - RECEIVER_INPUTS - COLLECTOR_INPUTS)
    top_dash = [f for f, _ in dash_fields.most_common(10)]
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    sample = sample or {}

    reason_bits = []
    if host_inputs:
        reason_bits.append(f"host-local input(s): {', '.join(host_inputs)}")
    if receiver_inputs:
        reason_bits.append(f"receiver input(s): {', '.join(receiver_inputs)} "
                           f"(host = whatever the pipeline sets)")
    if api_inputs:
        reason_bits.append(f"remote/API input(s): {', '.join(api_inputs)} (host = collector)")
    if unknown_inputs:
        reason_bits.append(f"unclassified input(s): {', '.join(unknown_inputs)}")
    if not inputs:
        reason_bits.append("no inputs declared")

    def result(klass: str, recommendation: str, fields: List[str], orders: List[str],
               extra_reason: str = "", explicit: bool = False) -> Dict[str, Any]:
        return {
            "class": klass,
            "recommendation": recommendation,
            "sort_fields": fields,
            "sort_orders": orders,
            "reason": "; ".join(reason_bits + ([extra_reason] if extra_reason else [])),
            "explicit_sort_yaml": _sort_yaml(fields, orders) if explicit else None,
            "dashboard_top_fields": top_dash,
        }

    def default_or_degraded(extra_reason: str) -> Dict[str, Any]:
        bad_type = _host_name_sort_problem(field_index)
        if bad_type:
            return result("degraded",
                          "default DEGRADED: falls back to `@timestamp` desc only",
                          ["@timestamp"], ["desc"], bad_type)
        return result("default_ok", "default OK", ["host.name", "@timestamp"],
                      ["asc", "desc"], extra_reason)

    host_meaningful = bool(host_inputs) and not receiver_inputs and not api_inputs \
        and not unknown_inputs

    if host_meaningful:
        return default_or_degraded("`host.name` is agent-populated and sort-compatible")

    # Receiver regime: the pipeline decides. Do not fall through to the tenant tiers —
    # a syslog stream has no tenant, and the device identity is the whole question.
    if receiver_inputs and not api_inputs:
        device = next((f for f in RECEIVER_SORT_FIELDS if f in pipeline_arrays.targets), None)
        if device:
            return result(
                "receiver_proposed",
                f"explicit sort proposed: {device} asc, @timestamp desc",
                [device, "@timestamp"], ["asc", "desc"],
                f"receiver input: sort on the device identifier the pipeline "
                f"populates (`{device}`)",
                explicit=True)
        if "host.name" in pipeline_arrays.unconditional_targets:
            return default_or_degraded(
                "the pipeline sets `host.name` from the header on every event")
        return result(
            "receiver_no_candidate",
            "receiver input — no confident candidate; needs human choice",
            ["@timestamp"], ["desc"],
            "the pipeline populates no `observer.*` device identifier, and `host.name` "
            "only on some branches — a human has to say which field identifies the "
            "sending device",
            explicit=True)

    candidate, tier = _pick_sort_candidate(
        field_index, filter_fields, array_fields or set(), pipeline_arrays, sample,
        allow_agent_id=not api_inputs)
    if candidate:
        return result("explicit",
                      f"explicit sort proposed: {candidate} asc, @timestamp desc",
                      [candidate, "@timestamp"], ["asc", "desc"],
                      f"candidate from {tier}", explicit=True)

    return result(
        "no_candidate",
        "explicit sort proposed: @timestamp desc only — no confident candidate; "
        "needs human choice",
        ["@timestamp"], ["desc"],
        "no single-valued tenant/account/observer field and no dashboard filter "
        "field survived validation",
        explicit=True)


def _host_name_sort_problem(field_index: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """Why Elasticsearch would refuse to sort on this package's `host.name` mapping.

    `LogsdbIndexModeSettingsProvider` only keeps `host.name` in the sort when it is a
    keyword or a number **with doc values**; otherwise `IndexSortConfig` resolves to
    `@timestamp` alone.
    """
    fdef = field_index.get("host.name")
    if fdef is None:
        return None  # Elasticsearch injects the mapping itself
    ftype = fdef.get("type")
    if ftype is None and fdef.get("external") == "ecs":
        ftype = (ecs_schema().get("host.name") or {}).get("type")
    if ftype is not None and ftype not in SORTABLE_TYPES:
        return f"`host.name` is mapped as `{ftype}`, which Elasticsearch cannot sort on"
    if is_false(fdef.get("doc_values")):
        return "`host.name` is mapped with `doc_values: false`"
    return None


def _normalise_leaf(name: str, segments: int = 1) -> str:
    """Last `segments` path segments, squashed to lowercase letters/digits.

    `segments=1` turns `o365.audit.OrganizationId` into `organizationid`.
    `segments=2` turns `netbox.tenant.id` into `tenantid`, which is how the
    `<object>.id` spelling of a tenant identifier is recognised. A trailing `uid` is
    folded to `id` so the OCSF spelling (`cloud.account.uid`) matches too.
    """
    tail = ".".join(name.split(".")[-segments:])
    out = re.sub(r"[^a-z0-9]", "", tail.lower())
    if out.endswith("uid"):
        out = out[:-3] + "id"
    return out


_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _leaf_tokens(name: str) -> List[str]:
    """Lowercased words of the last path segment.

    `errorMessage` -> `["error", "message"]`; `response_time_in_seconds` ->
    `["response", "time", "in", "seconds"]`. Token matching (rather than a substring
    test on the squashed name) is what keeps `security_id` out of the `sec` bucket
    and `account_number` out of the `num` one.
    """
    leaf = name.rsplit(".", 1)[-1]
    return [t for t in re.split(r"[^a-zA-Z0-9]+", _CAMEL_RE.sub(" ", leaf)) if t]


def _numeric_leaf_is_id(name: str) -> bool:
    """Whether an integer-typed field's name claims to be an identifier.

    Integers are only admitted as a sort key on the strength of their name: either an
    id token (`id`, `uid`) or a tenant-like entity word. Everything else — `bytes`,
    `count`, `progress`, `seconds_to_triaged`, `observables_count` — is a
    measurement, and sorting a log index by a measurement is worse than not sorting
    it at all.
    """
    tokens = {t.lower() for t in _leaf_tokens(name)}
    return bool(tokens & ID_TOKENS) or bool(tokens & TENANT_TOKENS)


def _is_per_event_id(name: str) -> bool:
    """`<per-event entity>.id` / `.uid`, e.g. `blacklens.alert.id`."""
    parts = name.split(".")
    if len(parts) < 2:
        return False
    if parts[-1].lower() not in ID_TOKENS:
        return False
    return parts[-2].lower() in PER_EVENT_ENTITIES


def _is_plural_leaf(name: str) -> bool:
    squashed = _normalise_leaf(name)
    if not squashed.endswith("s") or squashed.endswith(SINGULAR_S_ENDINGS):
        return False
    return not _numeric_leaf_is_id(name)


def _weak_sort_leaf(name: str) -> Optional[str]:
    """Why this field name disqualifies it as the dashboard-tier sort key, or None.

    Applied to tier 3 only: tiers 1 and 2 match curated field/leaf lists, so their
    names are known good. Tier 3 takes whatever the package's dashboards filter on,
    which is where measurements, hashes, prose and enums get in.
    """
    tokens = {t.lower() for t in _leaf_tokens(name)}
    if tokens & MEASUREMENT_TOKENS:
        return "measurement"
    if (tokens & HASH_TOKENS) or any(t.endswith("hash") for t in tokens):
        return "per-event hash/uuid"
    if tokens & FREE_TEXT_TOKENS:
        return "free text"
    if _is_per_event_id(name):
        return "per-event id"
    if _is_plural_leaf(name):
        return "plural / array-ish"
    leaf_tokens = _leaf_tokens(name)
    if leaf_tokens and leaf_tokens[0].lower() in BOOLEAN_LEAF_PREFIXES:
        return "boolean flag"
    if _is_low_cardinality(name):
        return "low-cardinality enum"
    return None


def _resolved_type(fdef: Dict[str, Any], name: str) -> Optional[str]:
    """Field type, resolving `external: ecs` references against the ECS schema."""
    ftype = fdef.get("type")
    if ftype:
        return ftype
    if fdef.get("external") == "ecs":
        return (ecs_schema().get(name) or {}).get("type")
    return None


def _declared_multi_valued(field_index: Dict[str, Dict[str, Any]], name: str,
                           array_fields: set, pipeline_arrays: "PipelineFacts") -> bool:
    """Whether `name`, or any object it lives inside, holds a list.

    Index sorting on a multi-valued field is a *correctness* hazard, not a weak pick:
    Lucene picks one value out of the array and every later pruning decision silently
    follows that choice. A member of an array of objects is just as multi-valued as
    the array itself — `aws.cloudtrail.resources.account_id` is one value *per
    resource*, not per event — so every ancestor is checked, from three directions:

      1. the `sample_event.json` shows the ancestor as a list;
      2. the ancestor is declared `type: nested` or `normalize: [array]`;
      3. the ingest pipeline iterates the ancestor (`foreach`, `.stream()`,
         `instanceof List`, a Painless `for (def x : ctx.<path>)` loop).

    (3) is what catches CloudTrail: the sample event has no `resources` at all, and
    `fields.yml` declares it as a plain `group`, but the pipeline builds it with
    `$("json.resources", []).stream()` and `ctx.aws.cloudtrail.resources = new
    ArrayList(...)`.
    """
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        path = ".".join(parts[:i])
        if path in array_fields:
            return True
        if pipeline_arrays.is_array(path):
            return True
        anc = field_index.get(path)
        if anc is None:
            continue
        if anc.get("type") == "nested":
            return True
        normalize = anc.get("normalize")
        if isinstance(normalize, list) and "array" in normalize:
            return True
        if is_true(anc.get("normalize_as_array")):
            return True
        if anc.get("external") == "ecs" and (ecs_schema().get(path) or {}).get("array"):
            return True
    return False


def _sortable(field_index: Dict[str, Dict[str, Any]], name: str,
              array_fields: set,
              pipeline_arrays: Optional["PipelineFacts"] = None) -> bool:
    """Whether `name` may be used as the leading index-sort field.

    Rejects anything that is not a single-valued identifier-ish type.
    """
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    fdef = field_index.get(name)
    if fdef is None:
        return False
    if name in SORT_EXCLUDED_FIELDS:
        return False
    ftype = _resolved_type(fdef, name)
    if ftype not in SORTABLE_TYPES:
        # Also covers `constant_keyword`, `boolean`, all floating-point types,
        # `date`, every type Lucene cannot sort on, and `external: ecs` fields whose
        # ECS type is unknown (the cache is missing) — in which case "no confident
        # candidate" is the right answer anyway.
        return False
    if ftype in SORTABLE_NUMERIC_TYPES and not _numeric_leaf_is_id(name):
        # An integer that is not named like an identifier is a measurement.
        return False
    if is_false(fdef.get("doc_values")):
        return False
    normalize = fdef.get("normalize")
    if normalize and not isinstance(normalize, list):
        return False
    if _declared_multi_valued(field_index, name, array_fields, pipeline_arrays):
        return False
    return True


def _sample_scalar(sample: Dict[str, Any], name: str) -> bool:
    """Whether `sample_event.json` holds a non-empty **scalar** at `name`.

    Handles both the nested (`{"cloud": {"account": {"id": ...}}}`) and the dotted
    (`{"cloud.account.id": ...}`) spellings, and refuses to descend through a list.
    """
    parts = name.split(".")
    for split in range(len(parts), 0, -1):
        node: Any = sample
        ok = True
        for i, part in enumerate(parts[:split]):
            key = part if i < split - 1 else ".".join(parts[split - 1:])
            if not isinstance(node, dict) or key not in node:
                ok = False
                break
            node = node[key]
        if ok:
            return isinstance(node, (str, int, float)) and not isinstance(node, bool) \
                and str(node) != ""
    return False


def _ecs_sample_candidate(name: str, field_index: Dict[str, Dict[str, Any]],
                          sample: Dict[str, Any]) -> bool:
    """Tier 1 acceptance for an ECS field the package never declares.

    ECS fields are installed by the `ecs@mappings` component template, so a package
    that populates `cloud.account.id` in its pipeline has no reason to list it in
    `fields/*.yml` — and most do not (21 streams for `cloud.account.id`, 31 for
    `organization.id`). The sample event is then the only static evidence that the
    field exists at all. Type and array flag still come from the ECS cache, so a
    missing cache falls back to "no confident candidate", the safe direction.
    """
    if name in field_index:
        return False  # declared: the normal `_sortable` path already ruled on it
    if name in SORT_CANDIDATES_COLLECTOR_ONLY:
        return False
    ecs = ecs_schema().get(name)
    if not ecs or ecs.get("array"):
        return False
    if ecs.get("type") not in SORTABLE_STRING_TYPES:
        return False
    return _sample_scalar(sample, name)


def _tier2_hits(field_index: Dict[str, Dict[str, Any]], leaf: str,
                array_fields: set, pipeline_arrays: PipelineFacts) -> List[str]:
    """Fields whose last one *or two* path segments normalise to `leaf`.

    The two-segment form is how the `<object>.id` spelling of a tenant identifier is
    found: `netbox.tenant.id`, `sentinel_one.*.account.id`,
    `withsecure_elements.security_events.organization.id`, `ocsf.cloud.account.uid`.
    The depth cap is applied to the *effective* depth — the path with the matched
    suffix collapsed to one segment — so those survive it while a tenant id buried in
    a request payload (`...context.http_request.args.client_id`) still does not.
    """
    hits: List[Tuple[int, int, str]] = []
    for name in field_index:
        for segments in (1, 2):
            if name.count(".") + 1 < segments:
                continue
            if _normalise_leaf(name, segments) != leaf:
                continue
            depth = name.count(".") - (segments - 1)
            if depth > SORT_CANDIDATE_MAX_DEPTH:
                continue
            if not _sortable(field_index, name, array_fields, pipeline_arrays):
                continue
            hits.append((depth, len(name), name))
            break
    return [n for _d, _l, n in sorted(hits)]


def _pick_sort_candidate(field_index: Dict[str, Dict[str, Any]],
                         filter_fields: Counter,
                         array_fields: set,
                         pipeline_arrays: Optional[PipelineFacts] = None,
                         sample: Optional[Dict[str, Any]] = None,
                         allow_agent_id: bool = True) -> Tuple[Optional[str], str]:
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    sample = sample or {}
    # Tier 1: well-known ECS grouping fields, declared or merely populated.
    for name in SORT_CANDIDATES:
        if name in SORT_CANDIDATES_COLLECTOR_ONLY and not allow_agent_id:
            continue
        if _sortable(field_index, name, array_fields, pipeline_arrays):
            return name, "tier 1 (ECS grouping field)"
        if _ecs_sample_candidate(name, field_index, sample):
            return name, "tier 1 (ECS grouping field, populated in sample_event.json)"
    # Tier 2: vendor tenant/account identifiers, by normalised leaf name.
    for leaf in SORT_CANDIDATE_LEAVES:
        hits = _tier2_hits(field_index, leaf, array_fields, pipeline_arrays)
        if hits:
            return hits[0], "tier 2 (vendor tenant/account id)"
    # Tier 3: a field the package's own dashboards actually FILTER on. Being plotted
    # or grouped by is not enough — sorting only pays off for pruning. Unlike tiers 1
    # and 2 this is an uncurated name, so the leaf vocabulary applies here.
    for name, _count in filter_fields.most_common(40):
        if name.startswith("_") or _weak_sort_leaf(name):
            continue
        if _sortable(field_index, name, array_fields, pipeline_arrays):
            return name, "tier 3 (dashboard filter field)"
    return None, ""


def _is_low_cardinality(name: str) -> bool:
    """Suffix match on the normalised leaf, and again with a trailing `id`/`uid`.

    Catches `tls_verify_status`, `log_type`, `scanResult`, and the OCSF-style enum
    ids `class_uid`, `severity_id`, `activity_id` — while leaving real identifiers
    (`account_id`, `tenant_id`, `event_id`) alone.
    """
    leaf = _normalise_leaf(name)
    if leaf in LOW_CARDINALITY_EXACT:
        return True
    if leaf in LOW_CARDINALITY_NAME_LEAVES and "." in name:
        # `alert_type.name` is the `alert_type` enum with a nicer spelling.
        parent = name.rsplit(".", 2)[-2] if name.count(".") >= 1 else ""
        if parent and _is_low_cardinality(parent):
            return True
    variants = [leaf]
    for suffix in ("uid", "id"):
        if leaf.endswith(suffix) and len(leaf) > len(suffix):
            variants.append(leaf[: -len(suffix)])
            break
    return any(v.endswith(token) for v in variants for token in LOW_CARDINALITY_LEAVES)


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

    if scan_dashboards:
        dash_fields, filter_fields = dashboard_fields(pkg_dir)
    else:
        dash_fields, filter_fields = Counter(), Counter()
    result["dashboard_top_fields"] = [f for f, _ in dash_fields.most_common(15)]
    result["dashboard_filter_fields"] = [f for f, _ in filter_fields.most_common(15)]

    status = "OUT_OF_SCOPE"
    for ds_name in sorted(os.listdir(ds_root)):
        ds_dir = os.path.join(ds_root, ds_name)
        if not os.path.isdir(ds_dir):
            continue
        stream = audit_data_stream(pkg_dir, ds_dir, ds_name, dash_fields, filter_fields)
        result["data_streams"].append(stream)
        status = worse(status, stream["status"])
    result["status"] = status
    return result


def audit_data_stream(pkg_dir: str, ds_dir: str, ds_name: str,
                      dash_fields: Counter, filter_fields: Counter) -> Dict[str, Any]:
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

    sample = load_sample_event(ds_dir)
    pipeline_arrays = scan_pipelines(ds_dir)
    stream["findings"] = findings
    stream["field_count"] = len(field_index)
    stream["host_name_in_sample"] = sample_has_host_name(sample)
    stream["sort"] = recommend_sort(stream, field_index, dash_fields, filter_fields,
                                    array_fields=sample_array_fields(sample),
                                    pipeline_arrays=pipeline_arrays,
                                    sample=sample)
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
        lines.append("## Dashboard fields (benchmark workload)")
        lines.append("")
        lines.append(", ".join(f"`{f}`" for f in result["dashboard_top_fields"]))
        lines.append("")
    if result.get("dashboard_filter_fields"):
        lines.append("## Dashboard filter fields (sort tie-break)")
        lines.append("")
        lines.append("Fields used in a filter pill or KQL query clause — the only "
                     "dashboard evidence the sort heuristic accepts.")
        lines.append("")
        lines.append(", ".join(f"`{f}`" for f in result["dashboard_filter_fields"]))
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
    AUTOFIX_SRC_CODES = ["doc_values_false", "store_true", "copy_to", "keyword_normalizer",
                         "dynamic_runtime"]
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
                 "READY_AFTER_AUTO_FIX because deleting the `doc_values: false` line fixes "
                 "them mechanically.")
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

    REVIEW_CODES = ["nested_single_level", "runtime_field"]
    npkg, nds, _ = union(REVIEW_CODES)
    lines.append(f"## Judgement calls — review ({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(REVIEW_CODES) or ["(none)", ""])

    npkg, nds, _ = union(["keyword_normalizer_lowercase"])
    lines.append("## Informational — Class C "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(["keyword_normalizer_lowercase"]) or ["(none)", ""])

    lines.append("## Packages by status")
    lines.append("")
    for st in ("BLOCKED", "NEEDS_REVIEW", "READY_AFTER_AUTO_FIX", "READY"):
        pkgs = sorted(by_status[st])
        lines.append(f"### {st} ({len(pkgs)})")
        lines.append("")
        lines.append(", ".join(f"`{p}`" for p in pkgs) or "(none)")
        lines.append("")

    sort_class: Counter = Counter()
    for r in results:
        for s in r["data_streams"]:
            if s["status"] == "OUT_OF_SCOPE":
                continue
            sort_class[s["sort"].get("class", "no_candidate")] += 1
    lines.append("## Index sort")
    lines.append("")
    lines.append(f"- Default `host.name asc, @timestamp desc` looks right: "
                 f"{sort_class['default_ok']} data streams")
    lines.append(f"- Default would degrade to `@timestamp` only (incompatible `host.name` "
                 f"mapping): {sort_class['degraded']} data streams")
    lines.append(f"- Receiver input, explicit sort proposed on the device identifier the "
                 f"pipeline populates: {sort_class['receiver_proposed']} data streams")
    lines.append(f"- Receiver input, no confident candidate — needs a human choice: "
                 f"{sort_class['receiver_no_candidate']} data streams")
    lines.append(f"- Explicit sort proposed on a validated grouping field: "
                 f"{sort_class['explicit']} data streams (run the audit per package to see "
                 "the proposal)")
    lines.append(f"- No confident candidate — `@timestamp desc` only, needs a human choice: "
                 f"{sort_class['no_candidate']} data streams")
    lines.append("")
    lines.append("Candidate fields are validated: `keyword` and `ip` are accepted, integer "
                 "types only when the leaf name says the field is an identifier rather than "
                 "a measurement, and the field must have doc values. Arrays are rejected — "
                 "ECS `normalize: [array]`, a list in `sample_event.json`, a `nested` or "
                 "list-valued *ancestor*, or an object the ingest pipeline iterates. The "
                 "dashboard tier additionally requires the field to appear in a filter or "
                 "query clause, not merely on an axis, and drops measurement, hash/uuid, "
                 "free-text, plural and enum leaf names.")
    lines.append("")
    if not any(r.get("dashboard_filter_fields") for r in results):
        lines.append("Kibana assets were not scanned (`--catalog` defaults to "
                     "`--no-dashboards`), so the dashboard tier never fired and the "
                     "\"no confident candidate\" count is an upper bound. Re-run with "
                     "`--dashboards`, or audit the package on its own, before concluding "
                     "that a data stream has no grouping field.")
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
