"""Constants and the leaf-name vocabulary shared by the checks."""

from __future__ import annotations

import os


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
#
# The `external: ecs` declaration is what makes it a blocker, which is why the check
# below requires it. A package that never declares the field gets its mapping from the
# stack's `ecs@mappings` component template instead, and that template's
# `ecs_non_indexed_keyword` dynamic template (`*event.original`,
# `*gen_ai.agent.description`) sets `index: false` ONLY — no `doc_values: false`
# (verified on 9.6.0-SNAPSHOT). So a pipeline that merely populates `event.original`
# is columnar-clean and must not be flagged.
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

# Inputs whose streams are OpenTelemetry data. The rollout strategy keeps OTel log
# streams off columnar until logs sharing the same resource attributes can be
# clustered (derived fields): a single base mapping covers every OTel dataset, so a
# per-dataset sort key is the wrong tool, and `host.name` alone is not enough.
OTEL_INPUTS = {"otelcol"}

# Field types whose inverted index columnar mode keeps. Counted per stream as input
# for the ECS `.text` sub-field review; they never change a status.
TEXT_TYPES = {"text", "match_only_text"}

# Selective lookup fields the columnar mapping plan calls out: exact-value filters on
# them become doc-value scans unless they are in the sort key or indexed. Used only to
# flag lookup candidates for the per-stream `index: true` review.
LOOKUP_RISK_FIELDS = {
    "trace.id", "transaction.id", "span.id", "event.id", "error.id",
    "source.ip", "destination.ip", "client.ip", "server.ip", "user.name", "user.id",
    "url.path", "http.request.id", "host.id",
}
LOOKUP_RISK_PREFIXES = ("file.hash.", "process.hash.", "process.parent.hash.", "dll.hash.")
