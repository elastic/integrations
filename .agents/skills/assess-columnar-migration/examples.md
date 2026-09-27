# Examples — assess-columnar-migration

Illustrative triage shapes. Re-run the script for current line numbers.

Every in-scope proposal states the minimum stack implied by `format_version`
and that columnar bumps it. Spec 3.0 means 8.11, spec 3.4 means 8.19, spec 3.6
means 9.4. The bump raises that floor to 9.5+.

## `checkpoint` — migrate candidate

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/checkpoint
```

- Verdict: typically `migrate_candidate` (single-level nested is fine; not reported)
- At migration time: `observer.name` + `@timestamp` (firewall; override host default).
  Dashboard hints often surface `event.action` / network fields; use observer as the low-cardinality partition

## `o365` — defer (nested-in-nested with paths)

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/o365
```

Blockers look like:

```text
nested-in-nested — ExchangeAggregatedFolders → ExchangeAggregatedFolders.FolderItems
nested-in-nested — ExchangeAggregatedMessages → ExchangeAggregatedMessages.MessageItems
```

If migrated after remediating, the sort would be `user.name` + `@timestamp` (cloud audit).

## `aws` — package summary ≠ one blocked stream

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/aws
```

Expected shape:

```text
Verdict: migrate_with_changes (19 clean, 1 blocked: waf, 3 metrics_undecided)
Stream verdicts: defer_or_exclude=1, metrics_undecided=3, migrate_candidate=19
Skipped TSDB: … metrics streams
```

Only `waf` needs nested-in-nested work; other log streams can be proposed independently.
Metrics with `index_mode: time_series` are skipped, not proposed as columnar.

All 213 prebuilt aws rules land on `cloudtrail` (rules on `logs-aws*` are
narrowed by the dataset the query names), so that stream carries most of the
testing work. At migration time, `index_sort_hints.py packages/aws` shows its
rule fields lead with `event.action`, `event.outcome`, `event.provider`:
`event.provider` is a low-cardinality sort candidate next to `cloud.account.id`;
`user_agent.original` and `source.ip` are inverted-index candidates.

## `tanium` / `logstash` — dotted nested siblings

The inner nested field is declared as a sibling with a dotted name:

```text
nested-in-nested — tanium.threat_response.match_details.finding.whats → …whats.intel_intra_ids
nested-in-nested — logstash.node.stats.pipelines.vertices → …vertices.long_counters
```

The check compares dotted paths across all field files of a stream, so this
counts even though the YAML is not indented under the parent.

## `withsecure_elements` — `event.original` doc_values

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/withsecure_elements
```

Blocker kind is `doc_values: false (event.original)`, not a generic secret omit.
Proposed change should mention ECS integrity packaging / `_source` semantics.

Contrast with `doppel` (`cred_leaks_password`) — same severity, different remediation story.

## `sysdig` / `dynamic: false` in fields

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/sysdig
```

Surfaces **data_loss** from `fields/*.yml`. Packages that set
`elasticsearch.index_template.mappings.dynamic: false` in stream manifests
(e.g. parts of `elastic_agent`) are scanned too — Fleet stream
`enabled: false` is ignored.

The affected stream is `pending_platform`, and the package reads
`migrate_candidate (3 clean, 1 pending_platform)`. The clean streams can be
proposed now; the proposal for the other one waits on whether columnar stores
unmapped fields by GA.

## `winlog` / `filestream` — input packages

Input packages have no `data_stream/`. The script assesses one stream per
policy template from the root `fields/` and root `elasticsearch:` block, with
the template's `data_stream.dataset` var default (`winlog.winlog`), falling
back to `<package>.<template>`. Users can
override the dataset, so rules and dashboards may target another name. OTel
input packages (`input: otelcol`) are skipped.

## `panw_metrics` / `cisco_meraki_metrics` — TSDB, not columnar

These packages previously looked like `store: true` blockers; with correct
`elasticsearch.index_mode: time_series` detection they are **`out_of_scope`**
(TSDB). Columnar assessment should skip them rather than propose `columnar`.

## `vercel_otel` — out of scope

`type: content` → no data-stream mappings; stack OTel template owns mode/sort.

## `nginx` — clean logs, TSDB metrics

- `access` / `error`: `migrate_candidate` → `logsdb_columnar`. At migration
  time, `index_sort_hints.py` shows the dashboard control filters on
  `host.hostname`. Nginx is host-centric, so keep the default `host.name` +
  `@timestamp` sort (`logsdb_columnar` adds the mapping). Most rule fields are
  `STATS … BY` keys (`source.ip`, `agent.id`), not filters, and `url.original`
  is matched with leading wildcards, so no inverted-index candidates.
- `stubstatus`: `index_mode: time_series` → skipped (TSDB)

## `_source` consumers — join by dataset

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/gcp
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/network_traffic
```

`gcp` stays `migrate_candidate` on `audit`. The GKE certificate-signing rule in
`security_detection_engine` is listed against stream `audit` because its `FROM`
is `logs-gcp.audit-*`. The path `$.gcp.audit.request.spec.request` reads
`type: flattened`; the cross-mode rewrite is
`FIELD_EXTRACT(gcp.audit.request, "spec.request")`.

`network_traffic` lists the SIP and NFS rules against `sip` and `nfs`. Those
paths are mapped leaves (`network_traffic.sip.method`, `sip.method`, …). The
cross-mode rewrite is a field reference, for example
`COALESCE(network_traffic.sip.method, sip.method)`. `packetbeat-*` in the same
`FROM` is not an integrations dataset.

`azure` has no in-repo `JSON_EXTRACT(_source` hit. The AKS hunting query that
reads `logs-azure.platformlogs-*` is only in `elastic/detection-rules`. If the
script says that checkout is missing, search the repo and attach the hit to
`platformlogs`.

`security_detection_engine` has no data streams (`out_of_scope` for storage)
and still lists the four prebuilt rules. Verdicts do not move because of these
consumers.

## Repo-wide scoreboard

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/
```

The table includes a **Blocked streams** column so mega-packages with one bad
stream do not look globally blocked, and a **`_source` consumers** column that
does not change the verdict. A line after the table counts in-scope packages
columnar would move from 8.x to 9.x.
