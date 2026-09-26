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
    "observer.name",
    "observer.serial_number",
    "service.name",
    # Demoted to the bottom of tier 1. Both are frequently *present* without being
    # the dataset's grouping dimension: `orchestrator.namespace` is carried by every
    # Kubernetes-adjacent sample event and its value is very often the literal
    # placeholder `"string"` (`sentinel_one/alert`, `sentinel_one/unified_alert`),
    # and `cloud.instance.id` is the collector VM for a poller. A vendor tenant id
    # from tier 2 is a better key than either, so they now rank below tier 1's
    # curated leaders and, in practice, below tier 2 for streams that have one.
    "cloud.instance.id",
    "orchestrator.namespace",
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
    "subscriptionid", "workspaceid", "projectid", "organization",
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
# `client` is deliberately NOT here. An OAuth application id is what it almost always
# spells in this catalog — `okta.client.id`, `auth0.logs.data.client_id`,
# `ping_one.audit.actors.client.id`, `zeronetworks.audit.details.clientId` — and a
# per-application id is neither a tenant nor low enough in cardinality to lead an
# index sort. `infoblox_bloxone_ddi.dhcp_lease.client_id` is not even an application:
# it is the DHCP client, one value per device.
TENANT_TOKENS = {
    "account", "tenant", "organization", "organisation", "org", "customer",
    "project", "subscription", "workspace", "site", "instance",
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

# Index modes that make a data stream columnar.
COLUMNAR_INDEX_MODES = {"logsdb_columnar", "columnar"}

# --------------------------------------------------------------------------- #
# package-spec 3.7.0 columnar constructs
#
# 1. Field-level, mode-scoped override block. Fleet applies it ONLY when the
#    resolved index mode is `logsdb_columnar` or `columnar` — the same way it
#    only emits TSDB's `dimension: true` for `time_series`:
#
#        - name: event.original
#          external: ecs
#          columnar:
#            doc_values: true    # only `true` is valid
#
#    That mode scoping is the point: the same package version installed on a
#    logsdb or standard stack keeps today's mapping byte for byte, so repairing
#    a columnar blocker costs nothing on the installs that are not columnar.
#
#    The block also accepts `index`, for the rare field that benchmarks prove
#    still needs an inverted index. This audit only ever *reports* that one and
#    asks for the evidence; it never proposes it (rollout rule 2).
#
#    Fleet applies it to STATIC LEAF FIELDS ONLY. It does not apply it to a
#    field it renders as a `dynamic_templates` entry (`type: object`/`group`
#    with `object_type`), nor to anything under `multi_fields:`, and
#    package-spec 3.7.0 rejects the block in both places. A `doc_values: false`
#    there has no scoped fix: `columnar_override_misplaced`.
#
# 2. Stream-level readiness flag in `data_stream/<ds>/manifest.yml`:
#
#        elasticsearch:
#          columnar:
#            supported: true
#
#    The 3.7.0 validator enforces zero columnar blockers when it is set, and
#    Fleet only offers the per-stream opt-in toggle for streams that set it (or
#    that already declare a columnar `index_mode`).
#
# Both require `format_version: "3.7.0"` (`columnar_requires_spec_3_7`) and a
# `conditions.kibana.version` of at least COLUMNAR_KIBANA_CONSTRAINT, because
# both are read by Fleet and a Kibana without that support ignores them.
# --------------------------------------------------------------------------- #


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


def columnar_block(container: Any) -> Dict[str, Any]:
    """The mode-scoped `columnar:` block of a field definition or of the
    `elasticsearch:` section of a data stream manifest ({} when absent)."""
    if not isinstance(container, dict):
        return {}
    block = container.get("columnar")
    return block if isinstance(block, dict) else {}


def existing_index_sort(es_section: Any) -> Optional[Dict[str, List[str]]]:
    """The `index.sort` a data stream manifest already declares, or None.

    Read so the report can say "already present" instead of proposing a sort the
    package has had for three releases. Package sources write the settings both
    nested (`index: {sort: {field: [...]}}`) and with dotted keys
    (`index.sort.field: [...]`), so both are flattened before the lookup.
    """
    if not isinstance(es_section, dict):
        return None
    itpl = es_section.get("index_template")
    settings = itpl.get("settings") if isinstance(itpl, dict) else None
    if not isinstance(settings, dict):
        return None
    flat: Dict[str, Any] = {}

    def walk(node: Dict[str, Any], prefix: str) -> None:
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                walk(value, path)
            else:
                flat[path] = value

    walk(settings, "")
    fields = flat.get("index.sort.field")
    if fields is None:
        return None
    listed = lambda v: [str(x) for x in (v if isinstance(v, list) else [v])]  # noqa: E731
    orders = flat.get("index.sort.order")
    return {"field": listed(fields), "order": listed(orders) if orders is not None else []}


# The package-spec version that introduced both columnar constructs.
COLUMNAR_SPEC_VERSION = (3, 7)

# `conditions.kibana.version` a migrated package has to declare.
#
# The constraint is NOT about Elasticsearch: 9.5 already has the index mode.
# It is about Fleet. Fleet has to (a) parse `elasticsearch.columnar.supported`
# in order to offer the per-stream opt-in toggle at all, and (b) apply the
# field-level `columnar:` overrides when it builds the mapping — on the install
# path and on the toggle path. A Kibana without those changes silently ignores
# both: the toggle is not offered, and a manual columnar opt-in still ships the
# unpatched `doc_values: false`, so the index template PUT fails. So the
# constraint must be at least the first Kibana minor that ships that Fleet
# support, which is 9.6.
COLUMNAR_KIBANA_CONSTRAINT = "^9.6.0"
COLUMNAR_KIBANA_NOTE = (
    "the Fleet support ships in 9.6; on older Kibana the override and the flag are "
    "silently ignored, so the toggle is unavailable and any `doc_values: false` field "
    "will make a manual columnar opt-in fail"
)

# The constraint is not free, and this is the sentence the package owner has to read
# before declaring readiness. `conditions.kibana.version: "^9.6.0"` (and the
# `format_version: "3.7.0"` bump that goes with it) RAISES THE PACKAGE'S MINIMUM
# STACK VERSION to 9.6: Fleet will not offer the new package version to a stack older
# than that, so every user still on 9.5 or below stops receiving this package's
# updates altogether — not just the columnar ones. Fixing a bug for those users then
# needs a backport: a separate release line off the last pre-9.6 version. That is a
# real, recurring maintenance cost, so readiness is declared deliberately, for the
# packages chosen as tech-preview targets, and not swept across the catalog.
COLUMNAR_MIN_STACK_COST = (
    "**Cost:** declaring `columnar.supported` (and bumping `format_version` to "
    "`\"3.7.0\"`) raises this package's **minimum stack version to 9.6**. Users on an "
    "older stack stop receiving *any* further update to this package, so a bug fix for "
    "them needs a backport branch/release line. That makes it a **breaking change**: "
    "ship it as a **major** version bump with a `type: breaking-change` changelog entry "
    "(\"Raise the minimum required Kibana version to 9.6.0 …\") alongside the "
    "`enhancement` one — the convention elastic/integrations follows for a Kibana floor "
    "raise (`aws` 7.0.0, `aws_bedrock` 2.0.0, `aws_bedrock_agentcore` 1.0.0). Declare "
    "readiness deliberately, for the packages picked as tech-preview targets — not "
    "catalog-wide."
)

# Finding codes that describe the columnar *declaration* itself rather than a
# mapping feature Elasticsearch or the validator would reject on its own merits.
# They are excluded when deciding whether a `columnar.supported: true` stream is
# inconsistent, so the report does not accuse a declaration of blocking itself.
DECLARATION_CODES = {"columnar_requires_spec_3_7", "columnar_supported_with_blockers"}


def spec_version_tuple(raw: Any) -> Optional[Tuple[int, int]]:
    """(major, minor) of a `format_version`, or None if it cannot be parsed.

    Tolerates pre-release suffixes (`3.7.0-next`, `3.7.0-rc1`).
    """
    if raw is None:
        return None
    text = str(raw).strip().strip('"').strip("'")
    if not text:
        return None
    text = re.split(r"[-+]", text, maxsplit=1)[0]
    parts = text.split(".")
    try:
        return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    except (ValueError, IndexError):
        return None


def spec_supports_columnar(raw: Any) -> bool:
    """True when `format_version` is >= 3.7.0.

    An unparseable / missing `format_version` returns True: the audit does not
    invent a finding it cannot substantiate.
    """
    parsed = spec_version_tuple(raw)
    if parsed is None:
        return True
    return parsed >= COLUMNAR_SPEC_VERSION


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

    # package-spec 3.7.0 mode-scoped override block: only applied by Fleet when
    # the resolved index mode is columnar, so it repairs a columnar blocker
    # without touching logsdb/standard installs of the same package version.
    #
    # Fleet only applies it to **static leaf fields**. Two places it does not:
    #   * a dynamic-template field — `type: object` (or `group`) with an
    #     `object_type`, which Fleet renders as a `dynamic_templates` entry and
    #     not as a concrete mapping;
    #   * anything inside `multi_fields:`.
    # package-spec 3.7.0 rejects a `columnar:` block in both places, so an
    # override written there does not merely do nothing — it fails the build.
    # Consequence for remediation: a `doc_values: false` on such a field cannot
    # be repaired by a scoped override, it has to be deleted outright, which is
    # mode-agnostic and therefore also costs storage on logsdb and standard.
    columnar = columnar_block(fdef)
    dynamic_template_field = fdef.get("object_type") is not None
    columnar_override_allowed = not dynamic_template_field and not in_multi_field
    columnar_doc_values_fix = (is_true(columnar.get("doc_values"))
                               and columnar_override_allowed)

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
    if is_false(fdef.get("doc_values")) and not in_multi_field and not columnar_doc_values_fix:
        if dynamic_template_field:
            # No scoped override is available here — see `columnar_override_allowed`.
            remediation = (
                "Delete the `doc_values: false` line. The mode-scoped "
                "`columnar: {doc_values: true}` override is **not** an option on this "
                f"field: it declares `object_type: {fdef.get('object_type')}`, so Fleet "
                "renders it as a `dynamic_templates` entry and never applies a `columnar:` "
                "block to it, and package-spec 3.7.0 rejects the block there outright "
                "(`columnar_override_misplaced`). The removal is therefore mode-agnostic: "
                "doc values come on for logsdb and standard installs of this package "
                "version too, and those indices grow. If that cost is unacceptable, the "
                "honest alternative is to leave the field alone and keep this data stream "
                "on logsdb. `store: true` is NOT an alternative either: Elasticsearch "
                "rejects `store` outright in columnar modes "
                "(`FieldMapper.Builder#storeParam`)."
            )
        else:
            remediation = (
                "Keep `doc_values: false` and add the mode-scoped override next to it "
                "(package-spec 3.7.0):\n"
                f"    - name: {flat}\n"
                "      ...\n"
                "      doc_values: false      # kept: still applies to logsdb/standard\n"
                "      columnar:\n"
                "        doc_values: true\n"
                "Fleet applies the `columnar:` block only when the resolved index mode is "
                "`logsdb_columnar`/`columnar` (the same way `dimension: true` is only "
                "emitted for `time_series`), so a logsdb or standard install of this same "
                "package version keeps exactly today's storage profile — the fix costs "
                "nothing off-columnar, which is why it is preferred over deleting the "
                "line. Deleting `doc_values: false` outright also unblocks columnar, but "
                "it turns doc values on in every mode and grows those indices. Requires "
                "`format_version: \"3.7.0\"`. `store: true` is NOT an alternative: "
                "Elasticsearch rejects `store` outright in columnar modes "
                "(`FieldMapper.Builder#storeParam`). For message-like content "
                "`match_only_text` also works, but only on fields the package defines "
                "itself."
            )
        out.append(finding(
            "doc_values_false", "A", "auto_fix",
            f"`{flat}` sets `doc_values: false`; columnar mode cannot reconstruct it.",
            remediation,
            rel_file, flat))

    if is_false(columnar.get("doc_values")):
        out.append(finding(
            "columnar_doc_values_false", "A", "blocker",
            f"`{flat}` sets `columnar.doc_values: false`. That is not a valid value: the "
            f"mode-scoped `columnar:` block exists only to turn doc values back ON for "
            f"columnar modes, and a columnar index cannot reconstruct a field that has "
            f"none. package-spec 3.7.0 allows `true` only.",
            "Set `columnar.doc_values: true`, or delete the `columnar:` block. Whoever "
            "wrote `false` meant something — find out what before flipping it, which is "
            "why this is not treated as a mechanical fix.",
            rel_file, flat))

    if is_true(columnar.get("index")):
        out.append(finding(
            "columnar_index_true", "C", "info",
            f"`{flat}` keeps an inverted index under columnar modes "
            f"(`columnar.index: true`) — benchmark-justified inverted index; confirm the "
            f"evidence exists.",
            "This skill never proposes this override and no static analysis can justify "
            "it: the premise of the rollout is that columnar does not need inverted "
            "indexes, and index sorting is the per-integration lever "
            "(`references/sorting.md`). Keep it only if a benchmark on this specific field "
            "is linked from the PR that added it; otherwise remove it.",
            rel_file, flat))

    if columnar and not columnar_override_allowed:
        placement = ("inside `multi_fields:`" if in_multi_field
                     else f"a dynamic-template field (`object_type: "
                          f"{fdef.get('object_type')}`)")
        out.append(finding(
            "columnar_override_misplaced", "A", "blocker",
            f"`{flat}` carries a mode-scoped `columnar:` block on {placement}, where it "
            f"does nothing. Fleet only applies `columnar` overrides to static leaf "
            f"fields: it skips them for `multi_fields:` entries and for fields it renders "
            f"as a `dynamic_templates` entry (`object_type`). package-spec 3.7.0 rejects "
            f"the block in both places, so the package fails validation before the "
            f"override ever gets a chance to be ignored.",
            "Delete the `columnar:` block here. If it was added to repair a "
            "`doc_values: false`: a multi-field needs no repair at all (multi-fields are "
            "exempt from the reconstructability check, "
            "`MappingLookup#firstFieldNotReconstructableFromDocValues`), and on an "
            "`object_type` field the only fix is to delete the `doc_values: false` itself "
            "— which applies in every index mode, not just columnar. Not treated as a "
            "mechanical fix: deleting the block may re-expose the blocker it was meant to "
            "hide, so decide what the field should actually do.",
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
        if not is_true(fdef.get("doc_values")) and not columnar_doc_values_fix:
            out.append(finding(
                "doc_values_false_ecs", "A", "auto_fix",
                f"`{flat}` is imported from ECS, which defines it with `doc_values: false`; "
                f"elastic-package copies that into the built package.",
                f"Add the mode-scoped override to the field entry in the package's ECS "
                f"fields file:\n"
                f"    - name: {flat}\n      external: ecs\n      columnar:\n"
                f"        doc_values: true\n"
                f"Package attributes win over the imported ECS ones "
                f"(`transformed.DeepUpdate(def)`), and Fleet applies the `columnar:` block "
                f"only when the resolved index mode is `logsdb_columnar`/`columnar` — so "
                f"logsdb and standard installs of this same package version still get "
                f"ECS's `doc_values: false` and store not one byte more. A plain "
                f"`doc_values: true` would also unblock columnar, but it would turn doc "
                f"values on for `{flat}` in every mode. Requires "
                f"`format_version: \"3.7.0\"`."
                + ("" if columnar_override_allowed else
                   " NOTE: this entry declares `object_type`, so Fleet renders it as a "
                   "`dynamic_templates` entry and will not apply a `columnar:` block to "
                   "it, and package-spec 3.7.0 rejects the block there. Here the only "
                   "fix is a plain `doc_values: true`, which applies in every index "
                   "mode."),
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


def scan_kibana_assets(pkg_dir: str, count_fields: bool = True,
                       limit_bytes: int = 4_000_000
                       ) -> Tuple[Counter, Counter, List[Dict[str, Any]]]:
    """(referenced, filtered, `_source` consumers) from the package's Kibana assets.

    Every `kibana/**/*.json` is read exactly once. The two field counters feed the
    index-sort tie-break and are skipped when `count_fields` is false
    (`--no-dashboards`); the `_source` consumer scan always runs, because it is a
    correctness check rather than a sort hint.

    `referenced` is every `field`/`key`/`sourceField` mention — axes, group-bys,
    metrics, columns. It is the benchmark workload.

    `filtered` counts only fields used in a **filter or query clause**: Kibana filter
    pills (`filter[].meta.key`) and KQL query strings. That is much stronger evidence
    for an index-sort key, because sorting only pays off for fields queries *prune*
    on. Being plotted on an axis says nothing about pruning.
    """
    referenced: Counter = Counter()
    filtered: Counter = Counter()
    texts: List[Tuple[str, str]] = []
    kibana_dir = os.path.join(pkg_dir, "kibana")
    if not os.path.isdir(kibana_dir):
        return referenced, filtered, []
    for root, _dirs, files in os.walk(kibana_dir):
        # NOT sorted: `filter_fields.most_common()` breaks ties by insertion order, so
        # changing the walk order would silently move the tier-3 dashboard hint of
        # streams whose filter fields are all tied at 1 (`elastic_agent`).
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
            if "_source" in text or "script" in text:
                texts.append((os.path.relpath(path, pkg_dir), text))
            if not count_fields:
                continue
            for match in DASHBOARD_FIELD_RE.finditer(text):
                referenced[match.group(1)] += 1
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            _collect_filter_fields(doc, filtered)
    return referenced, filtered, kibana_source_consumers(texts)


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

# `observer.name` / `observer.hostname` / `observer.serial_number` written or read
# anywhere in a pipeline's *text*. `script` is in `_NON_PRODUCING_PROCESSORS` — its
# `field` is not its output — so the structured walk never sees the very common
# "params map -> ECS field" idiom, where the mapping lives in the processor's
# `params` and only Painless writes it:
#
#     - script:
#         params:
#           fw:  [{to: observer.hostname}]
#           id:  [{to: observer.name}]
#           sn:  [{to: observer.serial_number}]
#
# (`sonicwall_firewall/log`). The optional `?` covers Painless null-safe access
# (`ctx?.observer?.hostname`), which is how `cef/log` refers to the CEF header
# fields that the Beats `decode_cef` processor populates before ingest.
_OBSERVER_DEVICE_RE = re.compile(
    r"(?<!\w)observer\??\.\??(name|hostname|serial_number)\b")
# `ctx['observer']['hostname']` — the bracket spelling of the same thing.
_OBSERVER_DEVICE_BRACKET_RE = re.compile(
    r"""\[\s*['"]observer['"]\s*\]\s*\[\s*['"](name|hostname|serial_number)['"]\s*\]""")


def _observer_device_hits(text: str) -> set:
    """Device identifiers named in a chunk of pipeline text."""
    if not text:
        return set()
    hits = {"observer." + m.group(1) for m in _OBSERVER_DEVICE_RE.finditer(text)}
    hits |= {"observer." + m.group(1)
             for m in _OBSERVER_DEVICE_BRACKET_RE.finditer(text)}
    return hits


# The tier-1 ECS grouping fields that need *event* evidence before they can lead an
# index sort — see `_tier1_event_evidence`. `agent.id` is excluded because it already
# has its own, stricter rule (`SORT_CANDIDATES_COLLECTOR_ONLY`).
TIER1_EVENT_EVIDENCE_FIELDS = frozenset(SORT_CANDIDATES) - SORT_CANDIDATES_COLLECTOR_ONLY


def _field_name_res(names):
    """(name, dotted_re, bracket_re) for each dotted field name.

    `cloud.account.id` is matched as `cloud.account.id`, `ctx?.cloud?.account?.id`
    (Painless null-safe access) and `ctx['cloud']['account']['id']`.
    """
    out = []
    for name in names:
        parts = name.split(".")
        dotted = r"(?<!\w)" + r"\??\.\??".join(re.escape(p) for p in parts) + r"\b"
        bracket = r"\s*".join(r"\[\s*['\"]%s['\"]\s*\]" % re.escape(p) for p in parts)
        out.append((name, re.compile(dotted), re.compile(bracket)))
    return out


# Fields a `script` processor is allowed to claim as a write. Kept to an allow-list
# on purpose: a Painless mention is not proof of a write, so this is only trusted for
# the handful of names where the alternative is a *worse* answer (an `observer.*`
# device for a receiver stream, a tenant id for a poller).
_SCRIPT_TARGET_RES = _field_name_res(
    sorted(set(RECEIVER_SORT_FIELDS) | TIER1_EVENT_EVIDENCE_FIELDS))


def _script_field_hits(text: str) -> set:
    """Allow-listed field names a chunk of Painless / processor params refers to."""
    if not text:
        return set()
    return {name for name, dotted, bracket in _SCRIPT_TARGET_RES
            if dotted.search(text) or bracket.search(text)}


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
    texts: List[str] = []
    for fname in sorted(os.listdir(pipeline_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(pipeline_dir, fname)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        texts.append(text)
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
    # Last resort for the receiver device pick only: if neither the structured walk
    # nor the `script` scan found an `observer.*` device identifier, look for one in
    # the raw pipeline text. This is deliberately loose — a mention is not a write —
    # but it feeds `targets` ONLY (never `unconditional_targets`), the allow-list it
    # can match is three fields long, and the alternative outcome is "no confident
    # candidate". It never overrides a structured hit, so a precisely detected
    # `observer.hostname` is not displaced by a loosely mentioned `observer.name`.
    if not facts.targets.intersection(RECEIVER_SORT_FIELDS):
        for text in texts:
            facts.targets |= _observer_device_hits(text)
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
            elif ptype == "script":
                # Painless writes are invisible to the structured walk, so the
                # allow-listed names (`observer.*` device identifiers and the tier-1
                # ECS grouping fields) are recovered from the text of `source` and
                # `params` — `aws_bedrock_agentcore/memory_application_logs` sets
                # `ctx.service.name` that way and nowhere else. `targets` only: a
                # Painless write is almost always branch-dependent, so it is never
                # evidence of an unconditional target.
                chunks = [body.get("source") or ""]
                params = body.get("params")
                if params is not None:
                    chunks.append(json.dumps(params, default=str))
                for chunk in chunks:
                    facts.targets |= _script_field_hits(chunk)
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


# The index sort as the CHILDREN of the stream manifest's `elasticsearch:` key. A
# data stream manifest has exactly one `elasticsearch:` mapping, so the sort and the
# `columnar.supported` flag are siblings inside it — the report therefore emits a
# single merged block (`stream_manifest_block`). Two separate `elasticsearch:`
# snippets are a duplicate key when pasted literally, and YAML keeps only the last.
SORT_YAML_BODY = (
    "  index_template:\n"
    "    settings:\n"
    "      index:\n"
    "        sort:\n"
)
SORT_YAML_HEADER = "elasticsearch:\n" + SORT_YAML_BODY

# Same, for the stream-level readiness flag.
SUPPORTED_YAML_BODY = "  columnar:\n    supported: true\n"


def _sort_yaml(fields: List[str], orders: List[str], header: bool = True) -> str:
    return (
        (SORT_YAML_HEADER if header else SORT_YAML_BODY)
        + "          field: [" + ", ".join(f'"{f}"' for f in fields) + "]\n"
        + "          order: [" + ", ".join(f'"{o}"' for o in orders) + "]\n"
    )


def recommend_sort(stream: Dict[str, Any], field_index: Dict[str, Dict[str, Any]],
                   dash_fields: Counter, filter_fields: Counter,
                   array_fields: Optional[set] = None,
                   pipeline_arrays: Optional[PipelineFacts] = None,
                   sample: Optional[Dict[str, Any]] = None,
                   field_sources: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
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
    field_sources = field_sources or {}

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
               extra_reason: str = "", explicit: bool = False,
               hint: Optional[str] = None) -> Dict[str, Any]:
        return {
            "class": klass,
            "recommendation": recommendation,
            "sort_fields": fields,
            "sort_orders": orders,
            "reason": "; ".join(reason_bits + ([extra_reason] if extra_reason else [])),
            "explicit_sort_yaml": _sort_yaml(fields, orders) if explicit else None,
            "dashboard_top_fields": top_dash,
            # The tier-3 dashboard hint: a field the package's own dashboards filter
            # on. Never a proposal — see `review_candidate` below.
            "dashboard_sort_hint": hint,
            "dashboard_sort_hint_filters": filter_fields.get(hint, 0) if hint else 0,
            # Tier-1 ECS fields that are present but were refused for want of event
            # evidence — see `_tier1_event_evidence`.
            "rejected_candidates": list(rejected),
        }

    rejected: List[str] = []

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

    device = next((f for f in RECEIVER_SORT_FIELDS if f in pipeline_arrays.targets), None)

    # Receiver regime: the pipeline decides. Do not fall through to the tenant tiers —
    # a pure syslog stream has no tenant, and the device identity is the whole
    # question. A stream that *also* offers a collector input is not in this regime:
    # see the mixed-input step below.
    if receiver_inputs and not api_inputs:
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
        allow_agent_id=not api_inputs, field_sources=field_sources, rejected=rejected)
    if rejected:
        reason_bits.append(
            "rejected tier-1 " + ", ".join(f"`{n}`" for n in rejected)
            + ": populated by agent metadata (collector), not by the event")
    if candidate:
        return result("explicit",
                      f"explicit sort proposed: {candidate} asc, @timestamp desc",
                      [candidate, "@timestamp"], ["asc", "desc"],
                      f"candidate from {tier}", explicit=True)

    # Mixed inputs (`tcp`/`udp` *and* `http_endpoint`, as in `zscaler_zia/firewall`
    # and `gigamon/ami`): tiers 1-2 above already had first refusal, because a tenant
    # id carried in the collector payload beats a syslog device. But receiver
    # evidence — an `observer.*` identifier the pipeline actually populates — is
    # still real evidence, and it outranks the dashboard hint below.
    if receiver_inputs and device:
        return result(
            "receiver_proposed",
            f"explicit sort proposed: {device} asc, @timestamp desc",
            [device, "@timestamp"], ["asc", "desc"],
            f"mixed receiver/collector inputs and no tenant id: sort on the device "
            f"identifier the pipeline populates (`{device}`)",
            explicit=True)

    # Tier 3 is a *hint*, not a proposal. It takes whatever the package's dashboards
    # happen to filter on, and across the catalog two thirds of its picks are junk
    # (`aws.elb.listener`, `domaintools.domain`, `zscaler_zia.web.threat.name`). It
    # is printed for a human to judge and deliberately emits no `index.sort` YAML.
    hint = _dashboard_sort_hint(
        field_index, filter_fields, array_fields or set(), pipeline_arrays)
    if hint:
        return result(
            "review_candidate",
            f"no confident candidate — dashboard hint: {hint} "
            f"(filtered {filter_fields[hint]}\u00d7); needs human choice",
            ["@timestamp"], ["desc"],
            f"no single-valued tenant/account/observer field; the package's own "
            f"dashboards filter on `{hint}` ({filter_fields[hint]}\u00d7), which is a "
            f"lead for a human, not a validated grouping dimension",
            hint=hint)

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


# `fields/*.yml` files that describe what **Elastic Agent** adds to every event, not
# what this data stream's events contain. A `cloud.account.id` whose only declaration
# lives here is `add_cloud_metadata` talking about the collector VM.
AGENT_METADATA_FIELD_FILES = {"agent.yml", "beats.yml"}


def _tier1_event_evidence(name: str, field_index: Dict[str, Dict[str, Any]],
                          field_sources: Dict[str, str],
                          pipeline_arrays: PipelineFacts) -> Optional[str]:
    """Why `name` holds the EVENT's tenant rather than the collector's, or None.

    Elastic Agent's `add_cloud_metadata` puts `cloud.account.id`, `cloud.project.id`
    and `cloud.instance.id` on every event it ships, and the generated
    `fields/agent.yml` declares them, so "the field exists" is worth nothing: on a
    poller those are the *collector's* cloud account, one value for the whole data
    stream, which is the worst possible leading sort key. `netflow/log`,
    `kubernetes/audit_logs` and all twelve `elastic_agent/*_logs` streams were being
    proposed `cloud.account.id` on exactly that evidence.

    Two things count as evidence that the *event* carries it:

      * an ingest pipeline of this data stream writes it — a `set` (including
        `copy_from`), `rename`, `append`, grok/dissect target or an allow-listed
        Painless write. `aws/cloudtrail`, `aws/guardduty` and `aws/vpcflow` all set
        `cloud.account.id` from the record, and keep their proposal;
      * the package declares the field itself, with its own description, outside the
        generated agent-metadata files. A bare `external: ecs` stub in `ecs.yml`
        does not count: it asserts nothing about who populates the field.

    A CSPM-style stream where the *input* (not the pipeline) supplies the tenant —
    `cloud_security_posture/findings`, `cloud_asset_inventory/asset_inventory` — is
    rejected here too. That is the intended direction: the audit says "no confident
    candidate; needs human choice" instead of proposing the collector's account id.
    """
    if name in pipeline_arrays.targets:
        return "the data stream's ingest pipeline writes it"
    fdef = field_index.get(name)
    if fdef is not None:
        source_file = field_sources.get(name, "")
        described = str(fdef.get("description") or "").strip()
        if described and source_file not in AGENT_METADATA_FIELD_FILES:
            return f"declared with a package-specific description in `fields/{source_file}`"
    return None


def _tier2_hits(field_index: Dict[str, Dict[str, Any]], leaf: str,
                array_fields: set, pipeline_arrays: PipelineFacts,
                exclude: Optional[set] = None) -> List[str]:
    """Fields whose last one *or two* path segments normalise to `leaf`.

`exclude` keeps tier 1's names out: `cloud.account.id` normalises to `accountid`
    and `organization.id` to `organizationid`, so without it a tier-1 field that was
    just *refused* for want of event evidence would walk straight back in through
    tier 2 (`netflow/log`).

    The two-segment form is how the `<object>.id` spelling of a tenant identifier is
    found: `netbox.tenant.id`, `sentinel_one.*.account.id`,
    `withsecure_elements.security_events.organization.id`, `ocsf.cloud.account.uid`.
    The depth cap is applied to the *effective* depth — the path with the matched
    suffix collapsed to one segment — so those survive it while a tenant id buried in
    a request payload (`...context.http_request.args.client_id`) still does not.
    """
    exclude = exclude or set()
    hits: List[Tuple[int, int, str]] = []
    for name in field_index:
        if name in exclude:
            continue
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
                         allow_agent_id: bool = True,
                         field_sources: Optional[Dict[str, str]] = None,
                         rejected: Optional[List[str]] = None
                         ) -> Tuple[Optional[str], str]:
    """Tiers 1 and 2 — the curated lists, the only tiers that yield a *proposal*.

    Tier 3 (dashboard filter fields) lives in `_dashboard_sort_hint`, because it is
    reported as a human-review hint rather than proposed.
    """
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    sample = sample or {}
    field_sources = field_sources or {}
    # Tier 1: well-known ECS grouping fields, declared or merely populated — but only
    # when the *event* is what populates them (`_tier1_event_evidence`).
    for name in SORT_CANDIDATES:
        if name in SORT_CANDIDATES_COLLECTOR_ONLY and not allow_agent_id:
            continue
        present = (_sortable(field_index, name, array_fields, pipeline_arrays)
                   or _ecs_sample_candidate(name, field_index, sample))
        if not present:
            continue
        if name in TIER1_EVENT_EVIDENCE_FIELDS:
            evidence = _tier1_event_evidence(name, field_index, field_sources,
                                             pipeline_arrays)
            if not evidence:
                if rejected is not None and name not in rejected:
                    rejected.append(name)
                continue
            return name, f"tier 1 (ECS grouping field; {evidence})"
        return name, "tier 1 (ECS grouping field)"
    # Tier 2: vendor tenant/account identifiers, by normalised leaf name. Tier 1's
    # own field names are excluded: tier 1 has already ruled on them, and a name it
    # rejected for want of event evidence must not come back through the leaf match.
    for leaf in SORT_CANDIDATE_LEAVES:
        hits = _tier2_hits(field_index, leaf, array_fields, pipeline_arrays,
                           exclude=set(SORT_CANDIDATES))
        if hits:
            return hits[0], "tier 2 (vendor tenant/account id)"
    return None, ""


def _dashboard_sort_hint(field_index: Dict[str, Dict[str, Any]],
                         filter_fields: Counter,
                         array_fields: set,
                         pipeline_arrays: Optional[PipelineFacts] = None
                         ) -> Optional[str]:
    """Tier 3: a field the package's own dashboards actually FILTER on.

    Being plotted or grouped by is not enough — sorting only pays off for pruning.
    Unlike tiers 1 and 2 this is an uncurated name, so the leaf vocabulary applies
    here. And unlike tiers 1 and 2 the result is only a **hint**: the caller reports
    it as `review_candidate` and writes no `index.sort` YAML, because the vocabulary
    filters out bad *names*, not fields that are merely irrelevant — a dashboard
    filtering on `domaintools.domain` says nothing about whether it is the dataset's
    grouping dimension.
    """
    pipeline_arrays = pipeline_arrays or PipelineFacts()
    for name, _count in filter_fields.most_common(40):
        if name.startswith("_") or _weak_sort_leaf(name):
            continue
        if _sortable(field_index, name, array_fields, pipeline_arrays):
            return name
    return None


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
# Columnar `_source` consumers (Class C — `references/blockers.md` C6-C8)
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


def _source_access_hits(text: str, limit: int = 3) -> List[Tuple[str, str]]:
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
# Transforms
# --------------------------------------------------------------------------- #

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
            for label, excerpt in _source_access_hits(text):
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
            hits.extend(_source_access_hits(text))
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
        "the JSON in Discover. Confirm those consumers before declaring this stream "
        "`columnar.supported: true`; mapping the field as `nested` does not restore the "
        "shape either (see `nested_single_level`).",
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

    # Kibana assets are read once: the field counters are the index-sort tie-break
    # (off by default in catalog mode), the `_source` consumer scan always runs.
    dash_fields, filter_fields, kibana_consumers = scan_kibana_assets(
        pkg_dir, count_fields=scan_dashboards)
    transforms = transform_source_consumers(pkg_dir)
    result["source_consumer_assets"] = (
        [t["file"] for t in transforms] + [k["file"] for k in kibana_consumers])
    result["dashboard_top_fields"] = [f for f, _ in dash_fields.most_common(15)]
    result["dashboard_filter_fields"] = [f for f, _ in filter_fields.most_common(15)]

    status = "OUT_OF_SCOPE"
    for ds_name in sorted(os.listdir(ds_root)):
        ds_dir = os.path.join(ds_root, ds_name)
        if not os.path.isdir(ds_dir):
            continue
        stream = audit_data_stream(pkg_dir, ds_dir, ds_name, dash_fields, filter_fields,
                                   format_version=result.get("format_version"),
                                   transforms=transforms, kibana=kibana_consumers)
        result["data_streams"].append(stream)
        status = worse(status, stream["status"])
    result["status"] = status
    return result


def audit_data_stream(pkg_dir: str, ds_dir: str, ds_name: str,
                      dash_fields: Counter, filter_fields: Counter,
                      format_version: Any = None,
                      transforms: Optional[List[Dict[str, Any]]] = None,
                      kibana: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
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
    es_section = manifest.get("elasticsearch") if isinstance(manifest.get("elasticsearch"), dict) else {}
    stream["index_mode"] = es_section.get("index_mode")
    # package-spec 3.7.0 stream-level readiness flag. Fleet shows the per-stream
    # opt-in toggle when it is set; a columnar `index_mode` makes columnar the
    # default for new installs instead. Either one means "this stream is
    # columnar-enabled" as far as this report is concerned.
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
                    field_sources.setdefault(flat, fname)
                if columnar_block(fdef):
                    columnar_construct_sites.append(f"`{flat}` ({rel(fpath)})")
                findings.extend(check_field(fdef, flat, depth, in_mf, rel(fpath)))

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

    # --- columnar `_source` consumers (C6-C8) ---------------------------- #
    # Appended last: they are Class C, so they cannot turn a Class A verdict, but a
    # `review` one does move a stream to NEEDS_REVIEW, which is the point — a stream
    # whose `_source` is read by a transform, a Kibana runtime field or an ES|QL
    # `METADATA _source` query should not be declared `supported` before someone has
    # looked at it.
    findings.extend(source_consumer_findings(ds_name, transforms or [], kibana or []))
    flattened_exempt: set = set()
    findings.extend(object_array_findings(ds_dir, ds_name, field_index, sample,
                                          flattened_exempt))

    # What the C6-C8 scan actually looked at. Recorded so the report can state the
    # NEGATIVE result in words: an empty Class C section is indistinguishable from a
    # check that never ran, and the reader has to know which one it was before
    # declaring a stream ready.
    code_counts = Counter(f["code"] for f in findings)
    stream["source_consumers"] = {
        "transform": code_counts["source_consumer_transform"],
        "kibana": code_counts["source_consumer_kibana"],
        "object_arrays": code_counts["object_array_flattening"],
        "flattened_exempt": sorted(flattened_exempt),
    }

    stream["findings"] = findings
    stream["field_count"] = len(field_index)
    stream["host_name_in_sample"] = sample_has_host_name(sample)
    stream["sort"] = recommend_sort(stream, field_index, dash_fields, filter_fields,
                                    array_fields=sample_array_fields(sample),
                                    pipeline_arrays=pipeline_arrays,
                                    sample=sample,
                                    field_sources=field_sources)
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

def columnar_optin_label(stream: Dict[str, Any]) -> str:
    """How (and whether) the data stream is already columnar-enabled.

    Two independent declarations, and the difference matters:
      * `elasticsearch.columnar.supported: true` — the stream is *ready*; Fleet
        exposes the per-stream opt-in toggle, but logsdb stays the default.
      * `elasticsearch.index_mode: logsdb_columnar` — columnar is the *default*
        for new installs of this package version.
    """
    mode = stream.get("index_mode")
    parts: List[str] = []
    if mode in COLUMNAR_INDEX_MODES:
        parts.append(f"**columnar by default** via `index_mode: {mode}` — new installs of "
                     f"this package version get columnar without the user asking")
    if stream.get("columnar_supported"):
        parts.append("**declared ready** via `elasticsearch.columnar.supported: true` — "
                     "Fleet offers the per-stream opt-in toggle; users have to turn it on")
    if not parts:
        return ("not declared (`elasticsearch.columnar.supported` unset, no columnar "
                "`index_mode`) — Fleet offers no opt-in for this stream yet")
    label = "; ".join(parts)
    blocking = [f for f in stream.get("findings", [])
                if f["class"] == "A" and f["code"] not in DECLARATION_CODES]
    if blocking:
        code = (" (`columnar_supported_with_blockers`)"
                if stream.get("columnar_supported_with_blockers") else "")
        label += (f". **Inconsistent**{code}: the stream still has {len(blocking)} Class A "
                  "finding(s), which the 3.7.0 columnar validator rejects — fix them or "
                  "drop the declaration")
    # Plumbing pointer only. The 9.6 minimum-stack cost is stated ONCE, in the
    # package header: repeating it per data stream turned a one-stream report into
    # three copies of the same paragraph, which is how a warning stops being read.
    label += (f". Plumbing: `format_version: \"3.7.0\"` + "
              f"`conditions.kibana.version: \"{COLUMNAR_KIBANA_CONSTRAINT}\"` — see the "
              f"package header for the 9.6 minimum-stack cost")
    return label


def kibana_condition_meets_columnar(condition: Any) -> bool:
    """Whether `conditions.kibana.version` already floors the package at 9.6+.

    The condition is a semver range, usually with several `||` branches
    (`"^8.19.0 || ^9.1.0"`). EVERY branch has to be 9.6 or newer: one older branch is
    enough for Fleet to keep offering the package to a stack that ignores both
    columnar constructs, which is exactly the case the constraint exists to prevent.
    That is why the remediation is "replace the whole range", not "add a branch".
    """
    if not condition:
        return False
    branches = [b.strip() for b in str(condition).split("||") if b.strip()]
    if not branches:
        return False
    for branch in branches:
        match = re.search(r"(\d+)\.(\d+)", branch)
        if not match or (int(match.group(1)), int(match.group(2))) < (9, 6):
            return False
    return True


def stream_manifest_block(s: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """(YAML body lines, notes) for the one `elasticsearch:` key of a stream manifest.

    The readiness flag and the index sort live under the same `elasticsearch:`
    mapping, so they are emitted merged — a reader who pastes two snippets gets a
    duplicate key and loses one of them.

    Anything the manifest already declares becomes a note ("already present") instead
    of a proposal: the audit is run again after the migration, and a report that still
    says "add this" about a line that is already there is indistinguishable from a
    migration that did not take.
    """
    body: List[str] = []
    notes: List[str] = []

    if s.get("columnar_supported"):
        notes.append("`elasticsearch.columnar.supported: true` already present")
    elif s["status"] in ("READY", "READY_AFTER_AUTO_FIX"):
        body.extend(SUPPORTED_YAML_BODY.rstrip("\n").split("\n"))
    else:
        notes.append(f"`columnar.supported: true` is not proposed while this stream is "
                     f"{s['status']} — the 3.7.0 validator rejects the flag until the "
                     f"findings below are resolved")

    sort = s["sort"]
    existing = s.get("existing_index_sort")
    if existing:
        shown = _sort_summary(existing["field"], existing["order"])
        note = f"explicit `index.sort` already present ({shown})"
        proposed = _sort_summary(sort["sort_fields"], sort["sort_orders"])
        if sort["explicit_sort_yaml"] and shown != proposed:
            note += (f" — the audit would propose {proposed}; keep the existing sort "
                     f"unless the dataset says otherwise, changing it rewrites the "
                     f"segment layout on the next rollover")
        notes.append(note)
    elif sort["explicit_sort_yaml"]:
        body.extend(_sort_yaml(sort["sort_fields"], sort["sort_orders"],
                               header=False).rstrip("\n").split("\n"))
    elif sort["class"] == "default_ok":
        notes.append("no `index.sort` to write — the `logsdb_columnar` logs profile "
                     "already sorts on `host.name asc, @timestamp desc`")
    return body, notes


def _sort_summary(fields: List[str], orders: List[str]) -> str:
    """`organization.id asc, @timestamp desc`, for prose rather than YAML."""
    pairs = []
    for idx, field in enumerate(fields):
        order = orders[idx] if idx < len(orders) else ""
        pairs.append(f"`{field}`" + (f" {order}" if order else ""))
    return ", ".join(pairs) or "(no fields)"


def source_consumer_line(result: Dict[str, Any], s: Dict[str, Any]) -> str:
    """The C6-C8 result for one stream — stated in words even when it is empty.

    A negative result has to be printed: an absent Class C section reads as "not
    checked", and the migration decision depends on knowing which one it was. The
    consumer class the audit genuinely cannot see — detection rules, which live in
    `elastic/detection-rules` — is named every time so it is never mistaken for part
    of the "none found".
    """
    sc = s.get("source_consumers") or {}
    pkg = result.get("package")
    hits: List[str] = []
    if sc.get("transform"):
        hits.append(f"{sc['transform']} transform finding(s) (`source_consumer_transform`)")
    if sc.get("kibana"):
        hits.append(f"{sc['kibana']} `kibana/` asset finding(s) (`source_consumer_kibana`)")
    if hits:
        head = "**" + " and ".join(hits) + "** — see the Class C findings below"
    else:
        head = ("none found in this package (no transforms reading `_source`, no "
                "scripted/runtime fields in `kibana/`, no ES|QL `METADATA _source`)")
    if sc.get("object_arrays"):
        arrays = "see `object_array_flattening` below"
    else:
        arrays = ("none in the sampled documents (`sample_event.json` and up to four "
                  "`_dev/test/pipeline/*-expected.json`)")
    exempt = sc.get("flattened_exempt") or []
    if exempt:
        arrays += ("; fields of type `flattened` are exempt, they keep their JSON "
                   "verbatim: " + ", ".join(f"`{f}`" for f in exempt))
    return (f"`_source` consumers: {head}; object arrays: {arrays}. Detection rules are "
            f"**not** part of the package — still check `elastic/detection-rules` by hand "
            f"for rules that read `_source` of `logs-{pkg}.*` (command at the end of this "
            f"report).")


def md_package(result: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append(f"# Columnar readiness: `{result['package']}`")
    lines.append("")
    lines.append(f"- Status: **{result['status']}**")
    lines.append(f"- Package type: `{result.get('type')}`, version `{result.get('version')}`, "
                 f"format_version `{result.get('format_version')}`")
    if result.get("kibana_condition"):
        if kibana_condition_meets_columnar(result["kibana_condition"]):
            lines.append(f"- Kibana condition: `{result['kibana_condition']}` — already at "
                         f"the `{COLUMNAR_KIBANA_CONSTRAINT}` floor the columnar constructs "
                         f"need; nothing to change ({COLUMNAR_KIBANA_NOTE})")
        else:
            lines.append(
                f"- Kibana condition: `{result['kibana_condition']}` — declaring readiness "
                f"means **replacing the whole range** with "
                f"`conditions.kibana.version: \"{COLUMNAR_KIBANA_CONSTRAINT}\"`, not adding "
                f"a branch to it: every `||` branch has to be 9.6+, so the older branches "
                f"go away. That is the point of the declaration *and* its cost — if this "
                f"package must keep serving older stacks, do not declare readiness on this "
                f"release line ({COLUMNAR_KIBANA_NOTE})")
        lines.append(f"- {COLUMNAR_MIN_STACK_COST}")
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
        lines.append(f"- Columnar opt-in: {columnar_optin_label(s)}")
        lines.append(f"- Sort: **{s['sort']['recommendation']}** — {s['sort']['reason']}")
        lines.append(f"- {source_consumer_line(result, s)}")
        body, notes = stream_manifest_block(s)
        segments: List[str] = list(notes)
        if body:
            segments.append(
                f"merge the block below into `data_stream/{s['data_stream']}/manifest.yml` — "
                f"a manifest has a **single** `elasticsearch:` key, so add these children to "
                f"the one already there; a second `elasticsearch:` is a duplicate key and "
                f"the file keeps only one of them")
        lines.append("- Stream manifest: "
                     + ("; ".join(segments) if segments else "nothing to add") + ".")
        if body:
            lines.append("")
            lines.append("  ```yaml")
            lines.append("  elasticsearch:")
            for ln in body:
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
    if in_scope:
        lines.append("## `_source` consumers the audit cannot see (manual)")
        lines.append("")
        lines.append("Detection rules are generated from `elastic/detection-rules` and reach "
                     "users through the `security_detection_engine` package, so a rule that "
                     "reads the `_source` of this package's indices is invisible to an audit "
                     "of this package. There is no automated check — run it by hand:")
        lines.append("")
        lines.append("```bash")
        lines.append("git clone https://github.com/elastic/detection-rules")
        lines.append("cd detection-rules")
        lines.append(f"grep -rl 'logs-{result['package']}\\.' rules/ | xargs grep -l '_source'")
        lines.append("```")
        lines.append("")
        lines.append("A hit is a rule that walks the document source of a data stream in this "
                     "package — read it before declaring readiness. Rules that only query "
                     "*fields* (KQL, EQL, ES|QL without `METADATA _source`) are unaffected.")
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

    # Streams that already carry one of the package-spec 3.7.0 columnar
    # declarations. Omitted entirely while the count is zero, so the section
    # only appears once the rollout has actually landed somewhere.
    supported = [(r["package"], s_["data_stream"]) for r in results for s_ in r["data_streams"]
                 if s_.get("columnar_supported")]
    default_mode = [(r["package"], s_["data_stream"]) for r in results for s_ in r["data_streams"]
                    if s_.get("index_mode") in COLUMNAR_INDEX_MODES]
    if supported or default_mode:
        lines.append("## Already columnar-enabled")
        lines.append("")
        plural = lambda n: "data stream" if n == 1 else "data streams"  # noqa: E731
        if supported:
            lines.append(f"`elasticsearch.columnar.supported: true` — opt-in toggle offered, "
                         f"logsdb still the default ({len(supported)} {plural(len(supported))}): "
                         + ", ".join(f"`{p}`/{d}" for p, d in sorted(supported)))
            lines.append("")
        if default_mode:
            lines.append(f"Columnar `index_mode` — columnar is the default for new installs "
                         f"({len(default_mode)} {plural(len(default_mode))}): "
                         + ", ".join(f"`{p}`/{d}" for p, d in sorted(default_mode)))
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
                 "READY_AFTER_AUTO_FIX because the fix is mechanical: keep the existing "
                 "`doc_values: false` and add a mode-scoped "
                 "`columnar: {doc_values: true}` beside it, so logsdb and standard installs "
                 "of the same package version are unchanged. (On the two placements Fleet "
                 "does not apply overrides to — a `multi_fields:` entry, or an "
                 "`object_type` dynamic-template field — there is no scoped form and the "
                 "`doc_values: false` has to be deleted outright, in every index mode.)")
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

    REVIEW_CODES = ["nested_single_level", "runtime_field",
                    "source_consumer_transform", "source_consumer_kibana"]
    npkg, nds, _ = union(REVIEW_CODES)
    lines.append(f"## Judgement calls — review ({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.extend(code_rows(REVIEW_CODES) or ["(none)", ""])

    # Problems with the package-spec 3.7.0 columnar declarations themselves.
    # Kept out of the blocker/auto-fix sections above on purpose: those count
    # mapping features, these count mistakes in the opt-in plumbing. Omitted
    # while empty, like "Already columnar-enabled".
    DECLARATION_PROBLEM_CODES = ["columnar_supported_with_blockers",
                                 "columnar_requires_spec_3_7",
                                 "columnar_override_misplaced",
                                 "columnar_doc_values_false"]
    npkg, nds, _ = union(DECLARATION_PROBLEM_CODES)
    if npkg:
        lines.append("## Columnar declaration problems "
                     f"({npkg} packages, {nds} data streams)")
        lines.append("")
        lines.append("Mistakes in the package-spec 3.7.0 opt-in plumbing itself, not in "
                     "the mappings. See `references/blockers.md`.")
        lines.append("")
        lines.extend(code_rows(DECLARATION_PROBLEM_CODES))

    INFO_CODES = ["keyword_normalizer_lowercase", "object_array_flattening"]
    npkg, nds, _ = union(INFO_CODES)
    lines.append("## Informational — Class C "
                 f"({npkg} packages, {nds} data streams)")
    lines.append("")
    lines.append("`object_array_flattening` changes no status: it records that the data "
                 "stream's own example documents contain object arrays, whose columnar "
                 "`_source` shape is flattened into parallel arrays. Queries on the leaf "
                 "fields are unaffected; `_source` readers are not. See "
                 "`references/blockers.md` C8.")
    lines.append("")
    lines.extend(code_rows(INFO_CODES) or ["(none)", ""])

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
    lines.append(f"- No confident candidate, but the package's dashboards filter on "
                 f"something — reported as a hint, no sort proposed: "
                 f"{sort_class['review_candidate']} data streams")
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
                 "free-text, plural and enum leaf names — but even then it only yields a "
                 "hint for a human, never an `index.sort` proposal.")
    lines.append("")
    if not any(r.get("dashboard_filter_fields") for r in results):
        lines.append("Kibana assets were not scanned **for sort hints** (`--catalog` "
                     "defaults to `--no-dashboards`), so the dashboard tier never fired "
                     "and the \"no confident candidate\" count is an upper bound. Re-run "
                     "with `--dashboards`, or audit the package on its own, before "
                     "concluding that a data stream has no grouping field. (The "
                     "`source_consumer_kibana` scan runs either way.)")
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
