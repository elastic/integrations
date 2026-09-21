# Choosing an index sort key

Index sorting is the **only per-integration performance lever** in the columnar
rollout. Fields in the sort key get effective doc-value skipper pruning without an
inverted index; everything else is a scan. It is also the cheapest lever — one block
of YAML in the data stream manifest, no mapping or pipeline changes.

## The default

`logsdb_columnar` = base `columnar` mode + the logs profile. The logs profile sets:

- default index sort `host.name asc, @timestamp desc`
- `ignore_malformed` and `ignore_above` defaults

If the data stream has no `host.name` mapping, Elasticsearch **adds one**. If an
existing `host.name` mapping is incompatible with sorting (wrong type, multi-valued),
it falls back to `@timestamp` only.

So the default is never an error — it is just frequently useless.

## When the default is right

`host.name asc, @timestamp desc` is a good sort key when `host.name` is a meaningful,
populated, reasonably high-cardinality dimension for the dataset. That is the case for
infrastructure logs collected on the machine that produced them:

- `system`, `nginx`, `apache`, `kubernetes/container_logs`, `auditd`, `windows`

Signals that say "host is meaningful":

- the data stream's inputs are local: `logfile`, `filestream`, `journald`, `winlog`,
  `unix`, `tcp`/`udp` syslog, `docker`, `audit/*`;
- `host.name` is mapped **and** populated with something other than the collector
  hostname in `sample_event.json`, `_dev/test/pipeline/*-expected.json`, or
  `_dev/test/system/*`.

## When the default is wrong

For SaaS and cloud audit logs the agent is a poller: `host.name` is either absent or is
the single collector host, so a sort on it is a no-op that also wastes a sort slot.
Examples: `o365`, `okta`, `aws/cloudtrail`, `github`, `salesforce`, `google_workspace`,
`atlassian_cloud`.

Signals that say "host is the collector, not the subject":

- inputs are `httpjson`, `cel`, `aws-s3`, `aws-cloudwatch`, `gcp-pubsub`, `gcs`,
  `azure-eventhub`, `azure-blob-storage`, `o365audit`, `entity-analytics`,
  `salesforce`, `http_endpoint`, `streaming`, `websocket`;
- `host.name` is unmapped, or present only via `base-fields.yml` boilerplate.

Careful: a data stream can offer both (`kubernetes/audit_logs` accepts `filestream`
*and* `gcp-pubsub`). If any collector-style input is offered, treat host as not
meaningful — a deployment using the API input would otherwise get a degenerate sort.

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
3. **The field the package's own dashboards filter or group by most often.** Extract
   these from `kibana/dashboard/*.json`, `kibana/lens/*.json`, `kibana/search/*.json`
   and `kibana/ml_module/*.json`. `scripts/audit.py <package>` prints the ranked list
   under "Dashboard fields".

### Hard constraints on a sort field

A sort field must be:

- **single-valued** — arrays break index sorting. ECS fields marked
  `normalize: [array]` are out.
- **backed by doc values** — so not a field carrying `doc_values: false`.
- **not** `text`, `match_only_text`, `wildcard`, `flattened`, `nested`, `object`,
  `geo_point`, `geo_shape`, `histogram`, `aggregate_metric_double` or `binary`.
- **not constant within the index** — `data_stream.dataset`, `data_stream.namespace`,
  `event.dataset`, `event.module`, `agent.type`, any `constant_keyword`. These are
  frequent in dashboard filters and completely useless as a sort prefix.

### Soft guidance

- Prefer higher cardinality for the leading field, but not unbounded: a tenant id with
  hundreds to millions of values is ideal; a `severity` enum with five values barely
  prunes anything; a per-event UUID prunes nothing and destroys compression.
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
