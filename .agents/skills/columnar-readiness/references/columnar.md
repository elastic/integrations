# Columnar: fixes, index sort, `_source` consumers, validation

## Validator findings (`elastic-package check`)

Every fix below changes the mapping or pipeline for LogsDB installs too: say so in the
changelog. Pipeline processors go inline in the stream's pipeline, tagged `columnar_*`
with a `description` starting "columnar:" (a pipeline cannot see the index mode).

**`nested` inside `nested`** (error). Columnar supports one level of nesting. First
check that no dashboard or rule runs a `nested` query on the inner path, then:

1. map the inner level as `type: flattened` and drop its `fields:` children: values stay
   with their outer element; sub-fields become untyped keywords (ES|QL reads them with
   `FIELD_EXTRACT`), and matching within one inner element is lost;
2. or `type: group` to keep the types, only together with the dotted-key pipeline
   change of `nested_object_children` below;
3. or build a single-level `nested` array in the pipeline, one entry per (outer, inner)
   pair;
4. or leave the package undeclared until one of these fits.

On an existing stream the type change applies at the next rollover.

**`copy_to`** (error). Do the copy in the pipeline, after the processors that set the
source and before any that read the target, then delete `copy_to`. A `set` with
`copy_from` is enough when the field is the target's only source:

```yaml
- set:
    tag: columnar_copy_my_source
    description: "columnar: replaces copy_to on my.source"
    field: my.combined
    copy_from: my.source
    ignore_empty_value: true
```

Several sources into one target need a `script` that appends (keep arrays and types,
never overwrite). Regenerate the pipeline test expectations with `-g` and read them.

**Keyword normalizer other than `lowercase`** (error). Keep the parent raw and move the
normalizer into a multi-field (`multi_fields: [{name: normalized, type: keyword,
normalizer: <it>}]`; queries move to `<field>.normalized`), or normalize in the
pipeline. `normalizer: lowercase` is accepted, but `_source` returns the lowercased
value.

**Mapping-level runtime field** (error). Compute a concrete field with a `script`
processor (port `doc[...]`/`emit()` to `ctx` assignments), or move the logic to query
time (ES|QL `EVAL`, a search-request runtime field). `runtime: true` without a script
just becomes the plain type.

**`dynamic: false`, `dynamic: runtime`, `enabled: false`** (errors). Elasticsearch
rejects them in columnar modes: with no stored `_source`, unmapped data would be gone
for good and runtime fields would have nothing to load from. Map the subfields that
matter, use `dynamic: true` (unmapped leaves become cheap non-indexed doc values; watch
the field limit) or `dynamic: strict`, or `type: flattened` for open-ended objects; for
`enabled: false`, prefer `flattened`. Say in the PR which fields you mapped. If none of
that fits yet, the package stays undeclared.

**`index.sort`** (errors; `SVR00016` warning). Sort fields must be defined in the
stream's fields (only `@timestamp` is implicit; a custom sort must map `host.name`),
keep their doc values, not be `text`, `match_only_text`, `wildcard`, `flattened`,
`nested`, `object` or `group`, and `order` needs one entry per field. Leaving
`@timestamp` out is allowed but rarely right.

**`logsdb_columnar` on a non-logs stream, or with `index_mode`** (errors). Remove it
from that stream's manifest.

**`doc_values: false`, `store: true`** (errors; before readiness is declared, the script
reports them as `doc_values_false`, `store_true` and `import_mappings`). Elasticsearch
rejects both in columnar modes, and Fleet installs the mappings as they are: with a field,
turning the integration on fails with Elasticsearch's error; with a dynamic template, every
event with a matching field is rejected. ECS imports (`event.original`,
`*.x509.public_key_exponent`) and the ECS dynamic templates of `import_mappings: true` bring
`doc_values: false` in at build time.

Keep the integration blocked: don't declare readiness, and say why in the report.
Elasticsearch plans to accept `doc_values: false` in columnar modes. Don't change the
mappings just to unblock it: the change applies to LogsDB installs too, and the rollout opts
in integrations that work as they are. Change them only when that is justified for LogsDB as
well, and name the reason in the PR and the changelog:

- a field of the package: remove `store: true` or `doc_values: false` (a multi-field may
  keep `doc_values: false`);
- an `external: ecs` field: `doc_values: true` on its entry in `fields/ecs.yml`, the way
  Elasticsearch's `ecs@mappings` maps `event.original`:

  ```yaml
  - name: event.original
    external: ecs
    doc_values: true
  ```
- `import_mappings: true` in `_dev/build/build.yml`: remove it (it is deprecated, and Fleet
  adds `ecs@mappings` to every integration template), then diff the LogsDB mappings of a
  test install before and after.

## Script findings (`scripts/audit.py`)

**`nested_object_children`**: a single-level `nested` field whose elements hold objects.
On columnar, an object sent as JSON inside an element is indexed apart from it: a
`nested` query combining the element's fields with the object's stops matching, and
`_source` splits the element. Values sent as dotted keys are not affected. Pick one and
record it: a `script` at the end of the default pipeline (tag
`columnar_nested_dotted_<field>`) that rewrites each element's objects as dotted keys
(regenerate expectations with `-g`); accept it when nothing combines those fields in one
`nested` query or reads that `_source`; or map the objects `flattened`. Otherwise the
package stays undeclared.

**`_source` consumers.** Columnar `_source` has dotted keys, scalar single-element
arrays and parallel object arrays. Field-level reads (`doc[...]`, KQL, aggregations,
ES|QL columns, ingest pipelines on the stream) are unaffected; readers of `_source` are
not, and they fail silently.

- `source_consumer_latest_transform`: a `latest` transform copies the newest
  `_source` into its destination index, whichever package owns it. Its destination
  documents change shape, and its destination pipeline stops finding dotted keys
  (`rename`/`set`/`remove` with `ignore_missing` skip). Make the pipeline's first
  processor expand them (no-op on LogsDB input), or set `field_access_pattern:
  flexible` on it; test with `_ingest/pipeline/_simulate` (nested and dotted inputs
  must give the same output). The fix belongs in the package that owns the transform.

  ```yaml
  - dot_expander:
      tag: columnar_expand_dotted_keys
      field: "*"
  ```
- `source_consumer_transform`: a transform script reads `params._source`. Read doc
  values or the aggregated fields instead.
- `source_consumer_kibana`: a scripted or runtime field reading `_source`, or ES|QL
  `METADATA _source` / `JSON_EXTRACT(_source, …)`. Move it to doc values or columns.
- `source_consumer_detection_rule`: a shipped rule reading `_source`.
  `JSON_EXTRACT(_source, "a.b")` returns null on dotted keys, so the rule stops
  matching. Hold the package back until the rule is fixed in `elastic/detection-rules`:
  read the column (`COALESCE(network_traffic.sip.method, sip.method)` when patterns name
  it differently), or `FIELD_EXTRACT(<flattened field>, "sub.key")` for a `flattened`
  field (tech preview). `SET unmapped_fields = "nullify"` only when a field is mapped
  nowhere; `"load"` is never a fix. No `JSON_EXTRACT` path matches both shapes.

## Index sort

Fields in the sort key prune with doc-value skippers and need no inverted index. Keep
two fields: the grouping field `asc`, then `@timestamp desc`. Decide from the inputs:

| Inputs | `host.name` is | Sort |
| --- | --- | --- |
| host-local: `filestream`, `logfile`, `winlog`, `journald`, `etw`, container inputs | the subject | default `host.name asc, @timestamp desc`, write nothing (Elasticsearch maps `host.name` itself) |
| receivers: `tcp`, `udp`, `syslog` | whatever the pipeline set | `observer.name` / `observer.hostname` / `observer.serial_number` written by the pipeline; else default if the pipeline sets `host.name` on every event; else human choice |
| collectors and pollers: `httpjson`, `cel`, `aws-s3`, `gcp-pubsub`, `azure-eventhub`, … | the collector, one value | a tenant/account id |

Mixed inputs: any collector input makes it a collector; an unknown input counts as a
collector. Collector candidates, best first:

1. ECS grouping fields: `cloud.account.id`, `organization.id`, `cloud.project.id`,
   `observer.name`, `observer.serial_number`, `service.name`, then
   `cloud.instance.id`, `orchestrator.namespace`, and `agent.id` (only when no poller
   input). Accepted when declared or scalar in `sample_event.json`, and only with event
   evidence: the pipeline writes it, or the package declares it with its own
   description (not in the generated `agent.yml`/`beats.yml`, which describe the
   collector);
2. a vendor tenant id by leaf name (`tenant_id`, `org_id`, `account.id`,
   `subscription_id`, `workspace_id`, `customer_id`, …), at most three levels deep;
3. a field the package's dashboards filter on: a hint for a human, never a proposal.

A sort field must be single-valued (itself and every parent: check ECS `normalize:
array`, `nested` parents, lists in the sample event, `foreach`/`.stream()` in the
pipeline), keep doc values, be a `keyword`/`ip` or an integer named like an
identifier, and not be constant (`data_stream.*`, `event.dataset`, `constant_keyword`)
or a collector artifact (`log.file.path`, `aws.s3.bucket.name`). A weak or multi-valued
key is worse than `@timestamp desc` alone.

**Declare the sort field.** package-spec rejects a sort field the stream does not
define, and Elasticsearch cannot sort on a field unmapped at index creation. For an
ECS field the stream does not declare, add to `fields/ecs.yml` (needs an ECS
dependency in `_dev/build/build.yml`):

```yaml
- name: cloud.account.id
  external: ecs
```

Keep an existing explicit sort unless the dataset says otherwise; changing it rewrites
the segment layout at the next rollover. Verify after install:
`GET .ds-logs-<pkg>.<ds>-*/_settings?filter_path=**.index.mode,**.index.sort` shows
`logsdb_columnar` and the intended sort (the default can fall back to `@timestamp`
alone when `host.name` is mapped as something unsortable).

## Lookup fields (`index: true`)

A filter on a non-sort field becomes a doc-value scan, slowest for a single value over
a long time range. For each lookup candidate, find the query that filters on it by
exact value; if the benchmark shows it too slow and it cannot join the sort key, add
`index: true` to the field and name the query in the PR. Not valid on `wildcard`.

## Validate and benchmark

- **Pipeline tests** never index anything: their output must be identical in both
  modes. A diff is a bug or test nondeterminism.
- **System tests** in both modes (`elastic-package test system --defer-cleanup 4m`,
  snapshot `GET logs-<pkg>.<ds>-*/_search` during the deferral), matched on a flattened
  `event.id`. Expected differences, and only these: dotted `_source` keys
  (`geo_point` stays `{lat, lon}`); single-element arrays as scalars; object arrays as
  parallel arrays; multi-value order preserved; objects inside `nested` elements split
  off (until fixed); `normalizer: lowercase` values
  lowercased. elastic-package fails columnar runs with "expected array, found
  <scalar>": tooling, not a package bug; check the values and note it. Anything else
  (a changed value, a dropped mapped field, precision loss) is a bug to report with
  the input document and both indexed versions.
- **Benchmark** realistic volume (weeks, not `_dev/test` samples) in one LogsDB and one
  columnar stream: the package's dashboard queries (filter pills, KQL, aggregations),
  the stream's direct detection rules (EQL and KQL run as Query DSL) and its lookup
  candidates. Compare latency, storage and CPU. Aggregations and ES|QL should be neutral
  or better, storage should drop; needle-in-a-haystack lookups outside the sort key are
  the worst case and the evidence for `index: true`. Re-run on newer builds before
  concluding.
