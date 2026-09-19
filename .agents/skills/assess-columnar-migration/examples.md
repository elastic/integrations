# Examples — assess-columnar-migration

Illustrative triage shapes. Re-run the script for current line numbers.

## `checkpoint` — migrate candidate

```bash
python3 .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/checkpoint
```

- Verdict: typically `migrate_candidate` (single-level nested is fine; not reported)
- Index sort: `observer.name` + `@timestamp` (firewall; override host default)
- Kibana seeds often surface `event.action` / network fields — use observer as the low-card partition

## `o365` — defer (nested-in-nested with paths)

```bash
python3 .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/o365
```

Blockers look like:

```text
nested-in-nested — ExchangeAggregatedFolders → ExchangeAggregatedFolders.FolderItems
nested-in-nested — ExchangeAggregatedMessages → ExchangeAggregatedMessages.MessageItems
```

Sort (only after remediating): `user.name` + `@timestamp` for cloud audit.

## `aws` — package summary ≠ one blocked stream

```bash
python3 .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/aws
```

Expected shape:

```text
Verdict: migrate_with_changes (N migratable, 1 blocked: waf)
Stream verdicts: defer_or_exclude=1, migrate_with_changes=…, migrate_candidate=…
Skipped TSDB: … metrics streams
```

Only `waf` needs nested-in-nested work; other log streams can be proposed independently.
Metrics with `index_mode: time_series` are skipped, not proposed as columnar.

## `withsecure_elements` — `event.original` doc_values

```bash
python3 .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/withsecure_elements
```

Blocker kind is `doc_values: false (event.original)`, not a generic secret omit.
Proposed change should mention ECS integrity packaging / `_source` semantics.

Contrast with `doppel` (`cred_leaks_password`) — same severity, different remediation story.

## `sysdig` / `dynamic: false` in fields

```bash
python3 .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/sysdig
```

Surfaces **data_loss** from `fields/*.yml`. Packages that set
`elasticsearch.index_template.mappings.dynamic: false` in stream manifests
(e.g. parts of `elastic_agent`) are scanned too — Fleet stream
`enabled: false` is ignored.

## `panw_metrics` / `cisco_meraki_metrics` — TSDB, not columnar

These packages previously looked like `store: true` blockers; with correct
`elasticsearch.index_mode: time_series` detection they are **`out_of_scope`**
(TSDB). Columnar assessment should skip them rather than propose `columnar`.

## `vercel_otel` — out of scope

`type: content` → no data-stream mappings; stack OTel template owns mode/sort.

## `nginx` — clean logs + undecided metrics

- `access` / `error`: often `migrate_candidate` → `logsdb_columnar`, sort `host.name`
- `stubstatus`: `metrics_undecided` if not TSDB

## Repo-wide scoreboard

```bash
python3 .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/ --summary-only
```

Table includes **Blocked streams** column so mega-packages with one bad stream
do not look globally blocked.
