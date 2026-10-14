---
name: columnar-readiness
description: Audits and migrates Elastic integration packages to the logsdb_columnar Elasticsearch index mode. Use for "columnar readiness", "logsdb_columnar", "migrate to columnar", "columnar audit", "index sorting for columnar", "is this package columnar-ready", or when asked why a package is blocked, what index sort a data stream should use, which fields need an inverted index, or what columnar `_source` does to transforms, detection rules and other `_source` consumers.
compatibility: Designed for packages in elastic/integrations. Needs elastic-package built against package-spec >= 3.7.0 (it runs the columnar checks), Python 3.9+ with PyYAML for scripts/audit.py (`uv run` installs it), and for stack tests a Kibana with the Fleet columnar support.
license: Apache-2.0
metadata:
  origin: elastic/integrations
---

# Columnar readiness

Move an integration's **logs** data streams to `logsdb_columnar`: declare readiness, let
the package-spec validator find the mappings Elasticsearch rejects, review what the
validator cannot see, pick the index sort, and validate on a stack. How to fix each
finding: [`references/columnar.md`](references/columnar.md).

## Current status

Last reviewed 2026-10-14; update these facts here when they change.

- **Elasticsearch:** `logsdb_columnar` is tech preview since 9.5, GA targeted for 9.7.
  Keyword doc-value skippers and bloom filters are still to come, so benchmarks move.
- **package-spec 3.7.0** is unreleased: elastic/package-spec#1250 adds
  `elasticsearch.logsdb_columnar` and the columnar validator. Until it ships, build
  elastic-package against that branch (`go mod edit -replace
  github.com/elastic/package-spec/v3=/path/to/package-spec`).
- **Fleet** (elastic/kibana#292285, Kibana 9.6, unmerged) offers one toggle per
  integration and strips `doc_values: false` and `store: true` from the templates of a
  stream installed in `logsdb_columnar` mode: those need no package change.
- **Objects inside `nested` fields** are split off their element on columnar (9.5.4, 9.6
  snapshots up to 2026-10-01): an Elasticsearch bug, re-check on newer builds.
- **Open team decisions** the skill follows a default for: the `breaking-change`
  changelog type for the Kibana floor (repo precedent); OTel and input packages out of
  scope.

## What logsdb_columnar is

Every field is stored once, as doc values. Non-`text` fields lose their inverted index
and BKD tree; queries prune with index sorting and doc-value skippers. `_source` is
never stored: it is rebuilt from the columns, **flat** (dotted keys), with
single-element arrays as plain values and object arrays as parallel arrays. The logs
profile adds the default sort `host.name asc, @timestamp desc` (Elasticsearch maps
`host.name` if absent). Integrations use `logsdb_columnar`, never the base `columnar`.

## Rollout rules — decisions, not preferences

1. **Logs data streams only.** Metrics, traces and synthetics streams, input packages,
   and streams fed by an OpenTelemetry input (`otelcol`) are out of scope.
2. **Per-field inverted indexes are a per-stream human decision** from the queries the
   stream's dashboards and rules run; "none" is valid. Never add `index: true` without
   a named query that needs it.
3. **Index sorting is the first lever.** A field in the sort key needs no index.
4. **Declare per package, with per-stream exceptions:** `opt_in` in the root manifest,
   `unsupported` on each stream that stays on LogsDB.
5. **Only for the chosen tech-preview targets**, never catalog-wide: declaring raises
   the package's minimum stack to 9.6, so older stacks need a backport line. Tell the
   user before writing the change.

## The setting (package-spec 3.7.0)

```yaml
# manifest.yml (package)          # data_stream/<ds>/manifest.yml (exceptions only)
elasticsearch:                    elasticsearch:
  logsdb_columnar: opt_in           logsdb_columnar: unsupported
```

| Value | Effect |
| --- | --- |
| `opt_in` | Fleet offers the integration's toggle; LogsDB stays the default. Write this for the tech preview. |
| `default` | New installations get columnar; existing streams keep their mode, also on an `opt_in` → `default` upgrade. |
| `unsupported` (stream only) | The stream stays on LogsDB. Marking a stream `unsupported` in a later version moves it back at the next rollover: a breaking change (major bump, `breaking-change` entry). |

- `type: logs` streams only: the package value is ignored elsewhere, and a non-logs
  stream that sets it fails validation.
- Never together with `index_mode` on the same stream (validation error); a stream with
  `index_mode` (`time_series`) ignores the package value. There is no
  `index_mode: logsdb_columnar` and no field-level `columnar:` block.
- Mode changes take effect at the next rollover.

## Procedure

### 1. Declare readiness

In the root `manifest.yml`:

- `format_version: "3.7.0"`. Run `elastic-package check` right after this bump alone:
  a multi-minor jump surfaces pre-existing findings (`SVR00008`/`SVR00009` `on_failure`
  handlers: fix; `SVR00006` processor tags: fix or exclude with a comment; `JSE00001`
  `message` → `event.original`: fix, prove with `test pipeline` without `-g`). Keep
  them apart from the columnar changes.
- `conditions.kibana.version: "^9.6.0"`, replacing the whole range (every `||` branch
  must be 9.6+), and a **major** version bump.
- `elasticsearch.logsdb_columnar: opt_in`, merged into an existing `elasticsearch:` key.
- `logsdb_columnar: unsupported` on every stream that stays on LogsDB: OTel-input
  streams, and streams that steps 2 or 3 leave blocked. A manifest has one
  `elasticsearch:` key: merge, never paste a second one (YAML keeps only one).
- Changelog, breaking entry first, with placeholder links: `breaking-change` "Raise the
  minimum required Kibana version to 9.6.0 …", `enhancement` "Declare LogsDB columnar
  support (logsdb_columnar opt_in) …", plus one for any pipeline change.

### 2. Run `elastic-package check` and fix every columnar finding

With `opt_in` declared, the validator checks every logs stream that ends up ready. Fix
each error and warning it reports; [`references/columnar.md`](references/columnar.md)
says how:

- errors: `copy_to`, a keyword normalizer other than `lowercase`, a mapping-level
  runtime field, `nested` inside `nested`, an invalid `index.sort`, `logsdb_columnar`
  on a non-logs stream or together with `index_mode`;
- warnings: `dynamic: false` (`SVR00014`), `enabled: false` (`SVR00015`), a custom
  `index.sort` without `@timestamp` (`SVR00016`).

Never exclude a columnar finding in `validation.yml`, except `SVR00016` with a comment
when the dataset is never queried by time range. A stream you cannot fix now gets
`unsupported`. `doc_values: false` and `store: true` are not reported: Fleet strips them.

### 3. Run the script for what the validator cannot see

From the repository root (`<skill-dir>` is where this file is installed):

```bash
python3 <skill-dir>/scripts/audit.py packages/<pkg>            # markdown
python3 <skill-dir>/scripts/audit.py packages/<pkg> --format json
uv run <skill-dir>/scripts/audit.py packages/<pkg>             # installs PyYAML
```

Flags: `--no-dashboards`, `--rules DIR` (default
`packages/security_detection_engine/kibana/security_rule`), `--no-rules`. Per logs
stream it reports a status (`READY`, `NEEDS_REVIEW`, `BLOCKED`, `OUT_OF_SCOPE`; `READY`
only means this script found nothing), the effective `logsdb_columnar`, and findings:

- `source_consumer_latest_transform`, `source_consumer_transform`,
  `source_consumer_kibana`, `source_consumer_detection_rule`: readers of the rebuilt
  `_source`. Nothing fails; they silently get the flat shape. Review each one;
- `nested_object_children`: objects inside a `nested` field (the Elasticsearch bug);
- `dynamic_runtime`: rejected by Elasticsearch at install, not by the validator.

A stream keeps `unsupported` until its `_source` consumers are reviewed. Quote the
**Detection rules** line in the PR even when it is zero; rules users wrote are not
covered.

### 4. Pick the index sort

The script proposes one per stream from its input types; confirm it, it is static
analysis. Host-local inputs (`filestream`, `winlog`, …) keep the default
`host.name asc, @timestamp desc` and write nothing. Receivers (`tcp`, `udp`, `syslog`)
sort on the `observer.*` device id the pipeline writes; collectors and pollers
(`httpjson`, `cel`, `aws-s3`, …) on a tenant or account id. "No confident candidate;
needs human choice" is a valid outcome. The sort goes in the stream manifest:

```yaml
elasticsearch:
  index_template:
    settings:
      index:
        sort:
          field: ["cloud.account.id", "@timestamp"]
          order: ["asc", "desc"]
```

When the sort field is not declared in the stream's `fields/*.yml`, the script prints
its `external: ecs` declaration for `fields/ecs.yml`: apply both, or the validator
rejects the sort. An explicit sort lands in the `@package` component template, so it
applies to LogsDB installs too: say so in the changelog. Heuristics and constraints:
[`references/columnar.md`](references/columnar.md#index-sort).

### 5. Decide the lookup fields

The script lists **lookup candidates**: `keyword`/`ip` fields the stream's rules and
dashboard filters use outside the sort key, high-risk lookups (`source.ip`,
`user.name`, hashes) first. For each, a human decides whether a named query needs an
inverted index; if so, add `index: true` to the field (a no-op on LogsDB) and record the
query in the PR. "None" is a valid decision.

### 6. Validate on a stack and benchmark

`opt_in` alone never produces a columnar index, and elastic-package has no flag for the
toggle. Get one with a Kibana that has the Fleet support (temporarily and uncommitted,
set `logsdb_columnar: default` and install fresh, or turn the toggle on), or on any
9.5+ stack with a `logs-<pkg>.<ds>@custom` component template that sets
`index.mode: logsdb_columnar` (only without `doc_values: false`/`store: true` fields:
Fleet does not strip them there). Run `elastic-package lint`, `build`, `test pipeline`
(identical in both modes; no `-g` unless a fix moved logic into the pipeline),
`test static`, and `test system` in both modes, diff, then benchmark the dashboard and
rule queries (Query DSL and EQL, not only ES|QL), needle-in-a-haystack lookups first.
Expected differences:
[`references/columnar.md`](references/columnar.md#validate-and-benchmark).

## Reporting back

Lead with each stream's status and the one-line reason, name the field and file for
every finding, quote the Detection rules line and the lookup candidates, and say what
the user still has to decide (sort, lookup fields, `_source` consumers).
