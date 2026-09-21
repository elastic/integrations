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

## When the default is right

`host.name asc, @timestamp desc` is a good sort key for anything the agent collects
on, or immediately next to, the machine that produced it:

- `system`, `nginx`, `apache`, `kubernetes/container_logs`, `auditd`, `windows`

Host-local inputs: `logfile`, `filestream`, `journald`, `winlog`, `etw`, `unix`,
`system/*`, `audit/*`, `auditd-logfile`, `unifiedlogs`, `osquery`, `packet`,
`docker`, `containerd`, `filestream-container`, and the `tcp`/`udp`/`syslog`
receivers.

## When the default is wrong

For SaaS and cloud audit logs the agent is a poller: `host.name` is the single
collector host, so a sort on it is a no-op that also wastes a sort slot.
Examples: `o365`, `okta`, `aws/cloudtrail`, `github`, `salesforce`, `google_workspace`,
`atlassian_cloud`.

Collector inputs: `httpjson`, `cel`, `aws-s3`, `aws-cloudwatch`, `gcp-pubsub`, `gcs`,
`azure-eventhub`, `azure-blob-storage`, `azure-monitor`, `o365audit`,
`entity-analytics`, `salesforce`, `okta`, `http_endpoint`, `streaming`, `websocket`,
`lumberjack`, `netflow`, `cloudbeat/*`, `kafka`, `redis`, `mqtt`.

Careful: a data stream can offer both (`kubernetes/audit_logs` accepts `filestream`
*and* `gcp-pubsub`). If any collector-style input is offered, treat host as not
meaningful — a deployment using the API input would otherwise get a degenerate sort.
Same for an input the audit does not recognise: unknown means "propose an explicit
sort and let a human look".

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

1. **A tenant / account / organisation identifier.** This is almost always the right
   answer for SaaS logs, because every dashboard, detection rule and SLO scopes by it.
   `cloud.account.id`, `organization.id`, `cloud.project.id`, or a vendor field —
   `o365.audit.OrganizationId`, `withsecure_elements.incidents.organizationId`,
   `aws.cloudtrail.resources.account_id`.
2. **A collector / sensor identity** when there is no tenant: `observer.name`,
   `observer.serial_number`, `agent.id`.
3. **A field the package's own dashboards actually FILTER on.** Being plotted on an
   axis, used as a group-by or listed as a table column is *not* enough — index
   sorting only pays off for fields that queries **prune** on. The audit counts only
   Kibana filter pills (`filter[].meta.key`) and KQL/Lucene query clauses, and prints
   them under "Dashboard filter fields". The broader "Dashboard fields" list is the
   benchmark workload, not a source of sort candidates.

### Hard constraints on a sort field

A sort field must be:

- **single-valued.** A multi-valued sort field is a *correctness* hazard, not a weak
  pick: Lucene sorts the document by one selected value from the array and every
  later pruning decision silently follows that choice. Out: ECS fields marked
  `normalize: [array]` (`tags`, `event.category`, `event.type`, `related.ip`,
  `host.ip`, `host.mac`, `process.args`, …), package fields declaring
  `normalize: [array]`, and any field the `sample_event.json` shows as a list.
- **backed by doc values** — so not a field carrying `doc_values: false`.
- **one of `keyword`, `ip`, `long`, `integer`, `short`, `byte`, `unsigned_long`.**
  This is an allow-list, and it is deliberately narrower than "what Lucene can sort":
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

### When nothing survives

Say so. `explicit sort proposed: @timestamp desc only — no confident candidate; needs
human choice` is a legitimate, useful outcome: `@timestamp desc` still beats sorting
on a field that prunes nothing, and it tells the package owner exactly what decision
is being asked of them. Never promote a weak candidate just to fill the slot.

### Soft guidance

- Prefer higher cardinality for the leading field, but not unbounded: a tenant id with
  hundreds to millions of values is ideal; a `severity` enum with five values barely
  prunes anything; a per-event UUID prunes nothing and destroys compression. The audit
  drops dashboard candidates whose leaf name ends in an enum word — `*_status`,
  `*_type`, `*_result`, `*.evaluation`, and the OCSF-style `class_uid`, `severity_id`,
  `activity_id` — while keeping real identifiers such as `account_id` and `tenant_id`.
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
