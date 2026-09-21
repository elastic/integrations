# Choosing an index sort key

Index sorting is the **only per-integration performance lever** in the columnar
rollout. Fields in the sort key get effective doc-value skipper pruning without an
inverted index; everything else is a scan. It is also the cheapest lever — one block
of YAML in the data stream manifest, no mapping or pipeline changes.

## The default

`logsdb_columnar` = base `columnar` mode + the logs profile. The logs profile sets:

- default index sort `host.name asc, @timestamp desc`
- `ignore_malformed` and `ignore_above` defaults

If the data stream has no `host.name` mapping, Elasticsearch **adds one**
(`LogsdbIndexModeSettingsProvider.MappingHints`). It keeps `host.name` in the sort
when the mapping is a keyword or a number **with doc values**; otherwise
`IndexSortConfig#buildIndexSort` falls back to `@timestamp` alone.

So the default is never an error — it is just frequently useless.

## Decide from the inputs, not from the field files

The single most common mistake here is to read "`host.name` is not in
`data_stream/<ds>/fields/*.yml`" or "`sample_event.json` has no `host.name`" as
evidence that the default sort is wrong. It is not evidence of anything:

- Elastic Agent's `add_host_metadata` processor populates `host.name` on **every**
  event, whatever the package declares;
- Elasticsearch injects the `host.name` mapping itself when the index template does
  not define one.

So the question "is `host.name` a meaningful dimension for this dataset?" is answered
by **what the input collects**, not by what the package happens to have written down.

The only mapping fact that matters is a *downgrade*: if the package maps `host.name`
as something other than a keyword/number with doc values — `text`,
`match_only_text`, `doc_values: false` — the default silently degenerates to
`@timestamp` only, and you need an explicit sort (or a fixed `host.name` mapping).

## Three input classes

| Class | Inputs | Who `host.name` identifies | Decision |
| --- | --- | --- | --- |
| **host-local** | `logfile`, `filestream`, `journald`, `winlog`, `etw`, `unix`, `system/*`, `audit/*`, `auditd-logfile`, `unifiedlogs`, `osquery`, `packet`, `docker`, `containerd`, `filestream-container`, `kubernetes/container_logs` | the subject | default is right |
| **receiver** | `tcp`, `udp`, `syslog` | whatever the ingest pipeline put there | read the pipeline |
| **collector / poller** | `httpjson`, `cel`, `aws-s3`, `aws-cloudwatch`, `gcp-pubsub`, `gcs`, `azure-eventhub`, `azure-blob-storage`, `azure-monitor`, `o365audit`, `entity-analytics`, `salesforce`, `okta`, `http_endpoint`, `streaming`, `websocket`, `lumberjack`, `netflow`, `cloudbeat/*`, `kafka`, `redis`, `mqtt` | the collector — one value | propose an explicit sort |

### When the default is right

`host.name asc, @timestamp desc` is a good sort key for anything the agent collects
on, or immediately next to, the machine that produced it: `system`, `nginx`,
`apache`, `kubernetes/container_logs`, `auditd`, `windows`.

### When the default is wrong

For SaaS and cloud audit logs the agent is a poller: `host.name` is the single
collector host, so a sort on it is a no-op that also wastes a sort slot.
Examples: `o365`, `okta`, `aws/cloudtrail`, `github`, `salesforce`, `google_workspace`,
`atlassian_cloud`.

### Receivers are not host-local

`tcp`, `udp` and `syslog` look host-local and are not: the agent is a syslog **sink**
for many remote devices, and what lands in `host.name` is decided by the ingest
pipeline, not by the input. Four pipelines, four different answers:

| Package | `observer.*` | `host.name` |
| --- | --- | --- |
| `cisco_asa` | `observer.hostname` ← `host.hostname`, unconditional `set` | set in **one** grok branch |
| `fortinet_fortigate` | `observer.name` ← `devname`, the firewall | ← `fortinet.firewall.srcname` — the *client* |
| `checkpoint` | `observer.name` ← `origin` | only on login events |
| `panw` | `observer.hostname` / `observer.serial_number` from the syslog header, in every sub-pipeline | only for client events |

So for a receiver stream the audit scans the data stream's ingest pipelines for
`set` / `rename` / `grok` / `dissect` targets and decides:

1. the pipeline populates `observer.name`, `observer.hostname` or
   `observer.serial_number` (in that order of preference) → propose it, with
   `@timestamp desc` second. That device *is* the dimension `host.name` was supposed
   to be;
2. the pipeline sets `host.name` **unconditionally** from the header → the default is
   fine. A grok target counts as unconditional only when it appears in *every*
   pattern of the processor and the processor carries no `if:` — `host.name` in one
   branch out of twelve is not a header field;
3. neither → `receiver input — no confident candidate; needs human choice`. Do **not**
   fall through to the tenant tiers: a syslog stream has no tenant, and an unrelated
   payload field is worse than `@timestamp` alone.

Other push-style inputs (`http_endpoint`, `netflow`, `lumberjack`, `cometd`, `kafka`)
stay in the collector class: their payloads carry a tenant or exporter identity
rather than a syslog device header.

### Mixed inputs

A data stream can offer several (`kubernetes/audit_logs` accepts `filestream` *and*
`gcp-pubsub`; `cisco_asa` accepts `logfile`, `tcp` and `udp`). Precedence:

- any collector input → **collector**, because a deployment using the API input would
  otherwise get a degenerate sort;
- otherwise any receiver input → **receiver**;
- an input the audit does not recognise → collector: unknown means "propose an
  explicit sort and let a human look".

## Proposing an explicit sort

Put it in `data_stream/<ds>/manifest.yml`:

```yaml
elasticsearch:
  index_template:
    settings:
      index:
        sort:
          field: ["cloud.account.id", "@timestamp"]
          order: ["asc", "desc"]
```

**Keep it to two fields**: the dominant grouping field, then `@timestamp desc`. A third
field rarely pays for the extra sort cost at index time.

### Candidate selection, in order of preference

**Tier 1 — a well-known ECS grouping field.** `cloud.account.id`, `organization.id`,
`cloud.project.id`, `cloud.instance.id`, `orchestrator.namespace`, `observer.name`,
`observer.serial_number`, `service.name`, `agent.id`. This is almost always the right
answer for SaaS logs, because every dashboard, detection rule and SLO scopes by it.

Accepted from **two** sources:

- a declaration in `data_stream/<ds>/fields/*.yml`; **or**
- a scalar value in `sample_event.json`. ECS fields are supplied by the
  `ecs@mappings` component template at install time, so a package whose pipeline
  fills `cloud.account.id` has no reason to also declare it — and most do not.
  Across the catalog, 21 streams populate `cloud.account.id`, 31 `organization.id`,
  4 `cloud.project.id` and 5 `observer.name` without declaring any of them. Without
  this path the audit says "no confident candidate" while the tenant id is sitting
  in the sample event. The type and the array flag still come from the ECS cache, so
  a missing cache falls back to "no confident candidate" — the safe direction.

  This is also why `aws/cloudtrail` sorts on `cloud.account.id` and not on a vendor
  leaf: the ECS field is the same AWS account id, populated by the pipeline, and it
  is single-valued.

Two exceptions for `agent.id`, which identifies the **collector**, not the subject:
it is never taken from the sample-event path (334 poller streams carry it), and it
is dropped from tier 1 altogether when the stream offers a poller input.

It is deliberately *kept* for streams that declare no inputs at all — `elastic_agent`
and `fleet_server` self-telemetry (`pf_host_agent_logs`, `status_change_logs`,
`output_health_logs`). There the agent is not the collector of someone else's data,
it is the subject, and `agent.id` is one series per agent across the fleet: exactly
the grouping dimension `host.name` would have been.

**Tier 2 — a vendor tenant/account identifier**, matched on the normalised **last one
or two** path segments: `tenant`, `tenantid`, `organizationid`, `orgid`, `accountid`,
`customerid`, `subscriptionid`, `workspaceid`, `projectid`, `clientid`,
`organization`, `instanceid`, `siteid`. A trailing `uid` folds to `id`, so the OCSF
spelling matches too (`ocsf.metadata.tenant_uid`, `...cloud.account.uid`).

The two-segment form is what finds the `<object>.id` spelling, which is at least as
common as `<object>_id`: `netbox.tenant.id`, `sentinel_one.activity.account.id`,
`withsecure_elements.security_events.organization.id`,
`trend_micro_vision_one.network_activity.customer.id`, `doppler.activity.project.id`.
There is still a depth cap — a tenant id buried in a request payload
(`...context.http_request.args.client_id`) is an artifact, not the dataset's grouping
dimension — but it is applied to the *effective* depth, with the matched suffix
collapsed to one segment, so `aws_securityhub.finding.cloud.account.uid` survives it.

**Tier 3 — a field the package's own dashboards actually FILTER on.** Being plotted on
an axis, used as a group-by or listed as a table column is *not* enough — index
sorting only pays off for fields that queries **prune** on. The audit counts only
Kibana filter pills (`filter[].meta.key`) and KQL/Lucene query clauses, and prints
them under "Dashboard filter fields". The broader "Dashboard fields" list is the
benchmark workload, not a source of sort candidates.

Tiers 1 and 2 match curated lists, so their names are known good. Tier 3 takes
whatever the dashboards happen to filter on, which is where the junk gets in — so
the leaf vocabulary below applies to tier 3 only.

### Hard constraints on a sort field

A sort field must be:

- **single-valued — including every object it lives inside.** A multi-valued sort
  field is a *correctness* hazard, not a weak pick: Lucene sorts the document by one
  selected value from the array and every later pruning decision silently follows
  that choice. A member of an array of objects is just as multi-valued as the array
  itself: `aws.cloudtrail.resources.account_id` is one value *per resource*, not per
  event. So the audit checks the field **and every ancestor** from four directions:
  - ECS `normalize: [array]` (`tags`, `event.category`, `event.type`, `related.ip`,
    `host.ip`, `host.mac`, `process.args`, …) or a package field declaring it;
  - a `type: nested` ancestor;
  - a list value in `sample_event.json`, at the field or at any ancestor;
  - an object the **ingest pipeline** iterates — a `foreach` processor, or the
    Painless idioms `$("json.x", []).stream()`, `ctx.a.b instanceof List`,
    `for (def r : ctx.a.b)`, `ctx.a.b = new ArrayList(...)`.

  The pipeline check is not redundant. CloudTrail declares `resources` as a plain
  `group`, its `sample_event.json` has no `resources` key at all, and the pipeline
  still builds it as a list
  (`packages/aws/data_stream/cloudtrail/elasticsearch/ingest_pipeline/default.yml`:
  `$("json.resources", []).stream().forEach(...)`,
  `ctx.aws.cloudtrail.resources = new ArrayList(...)`). Only the pipeline says so.
- **backed by doc values** — so not a field carrying `doc_values: false`.
- **`keyword` or `ip`** — or an integer type (`long`, `integer`, `short`, `byte`,
  `unsigned_long`) **whose leaf name says it is an identifier**. This is an
  allow-list, and it is deliberately narrower than "what Lucene can sort":
  - `boolean` and low-cardinality enums (`*.log_type`, `*.entity_state`,
    `result.evaluation`) prune almost nothing;
  - `double`/`float`/`scaled_float`/`half_float` are per-event measurements
    (`*.response_time`) — sorting on them destroys time locality and compresses
    *worse*;
  - `date` other than `@timestamp` is a second clock, not a grouping dimension;
  - `text`, `match_only_text`, `wildcard`, `flattened`, `nested`, `object`, `group`,
    `geo_point`, `geo_shape`, `histogram`, `aggregate_metric_double` and `binary`
    cannot be sorted on at all.
- **not constant within the index** — `data_stream.dataset`, `data_stream.namespace`,
  `event.dataset`, `event.module`, `agent.type`, any `constant_keyword`. These are
  frequent in dashboard filters and completely useless as a sort prefix.
- **not a collector artifact.** `aws.s3.bucket.name`, `aws.s3.object.key`,
  `log.file.path` and friends describe where the agent picked the data up, not who
  the data is about. They look like a grouping field and are not one.

An `external: ecs` reference carries no local `type`, so the audit resolves the type
and the array flag from elastic-package's ECS cache
(`~/.elastic-package/cache/fields/ecs/<version>/ecs_nested.yml`). Without that cache
it falls back to a small deny-list and rejects ECS fields whose type it cannot
determine, which biases it towards "no confident candidate" — the safe direction.

### The leaf vocabulary

Type and cardinality are not enough, because an integer type says nothing about
whether the number is an account id or a byte count. So the audit reads the **leaf
name**. Every rule matches on *tokens* of the last path segment — the leaf is split
on `_`, `-` and camelCase and lowercased, so `errorMessage` is `{error, message}` and
`response_time_in_seconds` is `{response, time, in, seconds}`. Token matching rather
than substring matching is what keeps `security_id` out of the `sec` (seconds)
bucket and `account_number` out of the `num` one. All of the lists live in one block
at the top of `scripts/audit.py`.

**Integers must look like identifiers** (applies to every tier). A numeric field is
accepted only when its leaf carries an id token — `id`, `uid`, `identifier`, so
`account_id`, `eventId`, plain `id` — or names a tenant-like entity: `account`,
`tenant`, `organization`, `org`, `customer`, `project`, `subscription`, `workspace`,
`client`, `site`, `instance`. Everything else is a measurement. Without this rule
about a third of the dashboard-tier picks were things like
`ceph.cluster_disk.total.bytes`, `golang.heap.system.total.bytes`,
`github.issues.time_to_close.sec`, `crowdstrike.alert.seconds_to_triaged`,
`tenable_io.scan.progress` and `opencti.indicator.observables_count`.

**Tier 3 additionally rejects** (tiers 1 and 2 are curated, so they skip this):

| Rejected | Tokens / rule | Caught |
| --- | --- | --- |
| measurement | `bytes`, `count`, `total`, `sum`, `avg`, `min`, `max`, `seconds`, `sec`, `ms`, `duration`, `time`, `memory`, `size`, `length`, `progress`, `percent`, `ratio`, `rate`, `value`, `latency`, `elapsed`, `age`, `score`, `usage`, `credits`, … | `admin_by_request_epm.auditlog.response_time_in_seconds`, `tines.time_saved.value`, `php_fpm.process.request.last.memory` |
| per-event hash / uuid | `hash`, `uuid`, `guid`, `checksum`, `fingerprint`, `md5`, `sha*`, … and any token ending in `hash` | `onepassword.item_uuid`, `threat.indicator.file.hash.pehash` |
| free text | `message`, `description`, `summary`, `reason`, `solution`, `text`, `title`, `body`, `detail(s)`, `command`, `query`, … | `tencent_cloud.audit.errorMessage`, `tenable_sc.plugin.solution` |
| per-event id | `<entity>.id` / `<entity>.uid` where the **parent segment** is `alert`, `event`, `incident`, `item`, `message`, `record`, `request`, `finding`, `detection`, `case`, `ticket`, `job`, `scan`, … | `blacklens.alert.id` |
| plural / array-ish | leaf ends in `s` and not in `ss`/`us`/`is`/`as`/`os`, and is not itself an id | `ticura.indicator.additional_info.threat_types`, `xm_cyber.product.product_vulnerabilities` |
| boolean flag | first token is `is`, `has`, `can`, `should`, `was`, `allow` | `trellix_epo_cloud.device.attributes.is_portable` |
| low-cardinality enum | suffix of the normalised leaf, also after stripping a trailing `id`/`uid`: `severity`, `status`, `type`, `action`, `result`, `state`, `category`, `role`, `mode`, `protocol`, `input`, `health`, `criticality`, `classification`, `version`, `dataset`, … plus exact `op`/`verb`/`rc`/`env`, plus `<enum>.name` (`alert_type.name`) | `github.members.role`, `citrix_adc.lbvserver.protocol`, `crowdstrike.host.reduced_functionality_mode`, `filebeat_input.input` |

The distinction that matters in the per-event-id row: a **tenant** id
(`cloud.account.id`, `netbox.tenant.id`, `misp.org.id`) is the grouping dimension and
is wanted; an **event** id (`blacklens.alert.id`) is one value per document and is
not. Only the `<entity>.id` path form is rejected, so a leaf that spells the whole
thing out (`event_id`) still counts as an identifier for the numeric rule above.

These lists are heuristics with a deliberate bias: a false reject costs one "no
confident candidate" that a human then decides, a false accept ships a bad sort key.

### When nothing survives

Say so. `explicit sort proposed: @timestamp desc only — no confident candidate; needs
human choice` — and its receiver variant, `receiver input — no confident candidate;
needs human choice` — are legitimate, useful outcomes: `@timestamp desc` still beats
sorting on a field that prunes nothing, and it tells the package owner exactly what
decision is being asked of them. Never promote a weak candidate just to fill the
slot.

### Soft guidance

- Prefer higher cardinality for the leading field, but not unbounded: a tenant id with
  hundreds to millions of values is ideal; a `severity` enum with five values barely
  prunes anything; a per-event UUID prunes nothing and destroys compression. The
  leaf vocabulary above is how the audit encodes that: enum words, measurements,
  hashes and prose are dropped, real identifiers (`account_id`, `tenant_id`) are
  kept.
- The leading field should be the one queries **filter on**, not the one they sort by.
- Sorting improves compression too: co-locating documents from the same tenant makes
  the doc-value blocks far more compressible.
- If no good grouping field exists, propose `@timestamp desc` alone. That is still
  better than sorting on an empty `host.name` that Elasticsearch invented.

## Verifying

After installing the package against a 9.5+ stack:

```
GET _index_template/logs-<pkg>.<ds>
GET .ds-logs-<pkg>.<ds>-*/_settings?filter_path=**.index.mode,**.index.sort
```

`index.mode` must be `logsdb_columnar`, and `index.sort.field` must be what you
intended — if you left the default in place, confirm it really resolved to
`host.name, @timestamp` and not to the `@timestamp`-only fallback.
