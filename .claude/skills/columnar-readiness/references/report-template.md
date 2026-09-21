# Readiness report format

`scripts/audit.py` emits this shape; use the same shape when you write a report by
hand or summarise one in a PR description.

## Statuses

Per data stream, worst finding wins:

| Status | Meaning |
| --- | --- |
| `READY` | No findings. Opt in. |
| `READY_AFTER_AUTO_FIX` | Only Class A findings with a mechanical fix: `copy_to` → ingest pipeline, a non-`lowercase` `normalizer` → pipeline or multi-field, `store: true` → removed, `doc_values: false` → removed (or `doc_values: true` on an `external: ecs` field), `dynamic: runtime` → `dynamic: true`. |
| `NEEDS_REVIEW` | A Class B data-loss finding (`dynamic: false`, `enabled: false`), a single-level `nested` field, or a mapping-level runtime field. Needs a human decision before opting in. |
| `BLOCKED` | `nested` inside `nested`, an unsupported field type, or a stored-`_source` override. No mechanical fix. |
| `OUT_OF_SCOPE` | Not a `type: logs` data stream, or the package is `type: input`. |

Per package: the worst status among its data streams, plus a sort recommendation.
**A package can be mixed** — `aws` has one blocked data stream (`waf`) and eighteen
migratable ones. Opt in per data stream; never hold a whole package back for one
stream.

Sort recommendation is one of (JSON: `sort.class`):

- `default OK` (`default_ok`) — `host.name asc, @timestamp desc` suits this data
  stream, either because the inputs are host-local or because a receiver pipeline
  sets `host.name` from the header on every event
- `default DEGRADED: falls back to @timestamp desc only` (`degraded`) — host-local
  inputs, but the package maps `host.name` as something Elasticsearch cannot sort on
- `explicit sort proposed: <field> asc, @timestamp desc` — from a receiver pipeline's
  `observer.*` device identifier (`receiver_proposed`) or from candidate tier 1 or 2
  (`explicit`)
- `receiver input — no confident candidate; needs human choice`
  (`receiver_no_candidate`) — a `tcp`/`udp`/`syslog` stream whose pipeline populates
  no `observer.*` field and sets `host.name` only on some branches
- `no confident candidate — dashboard hint: <field> (filtered N×); needs human choice`
  (`review_candidate`) — tier 1 and tier 2 found nothing and the only lead is a field
  the package's own dashboards filter on. Reported for a human to judge: **no**
  `index.sort` YAML is emitted, and `sort_fields` stays `["@timestamp"]`. The field
  and its filter count are in the JSON as `sort.dashboard_sort_hint` and
  `sort.dashboard_sort_hint_filters`
- `explicit sort proposed: @timestamp desc only — no confident candidate; needs human
  choice` (`no_candidate`) — no field passed validation. Deliberately not a guess: a
  weak or multi-valued sort key is worse than none.

Only `default_ok`, `degraded`, `receiver_proposed`, `explicit` and `no_candidate`
carry an `explicit_sort_yaml` block; `review_candidate` deliberately does not, so a
migration PR cannot pick up a dashboard hint by accident.

## Per-package report

```markdown
# Columnar readiness: `<package>`

- Status: **<STATUS>**
- Package type: `integration`, version `X.Y.Z`, format_version `3.x.y`
- Kibana condition: `^9.x.0` (needs `^9.5.0` for logsdb_columnar)

| Data stream | Status | Findings | Index sort |
| --- | --- | --- | --- |
| `<ds>` | <STATUS> | <n> | <sort recommendation> |

## `<ds>` — <STATUS>

- Inputs: `cel`, `httpjson`
- Current `index_mode`: `unset (logsdb default)`
- Sort: **<recommendation>** — <why: inputs, host.name evidence>

  Add to `data_stream/<ds>/manifest.yml`:

  ```yaml
  elasticsearch:
    index_template:
      settings:
        index:
          sort:
            field: ["<field>", "@timestamp"]
            order: ["asc", "desc"]
  ```

### Class A — rejected by Elasticsearch

- `<code>` (auto-fixable) — <what and where>
  - Where: `data_stream/<ds>/fields/fields.yml`
  - <remediation>

### Class B — accepted but lossy

- `<code>` — <what and where>
  - Where: `data_stream/<ds>/manifest.yml`
  - <remediation>

## Out of scope

- `<ds>`: data stream type is `metrics` (logs only)

## Dashboard fields (benchmark workload)

`field.a`, `field.b`, …

## Dashboard filter fields (sort tie-break)

`field.a`, `field.b`, …
```

## Catalog report

```markdown
# Columnar readiness — catalog audit

Packages scanned: <n>
Candidate packages (at least one `type: logs` data stream): <n>

| Status | Packages | Logs data streams |
| --- | --- | --- |
| BLOCKED | | |
| NEEDS_REVIEW | | |
| READY_AFTER_AUTO_FIX | | |
| READY | | |
| OUT_OF_SCOPE (input package / no logs streams) | | |

## Blockers — Class A, no mechanical fix (<n> packages, <n> data streams)
### `<code>` — class A, blocker
<n> packages, <n> data streams.
- `<package>`: <ds>, <ds>

## Hard mapping errors declared in the package source (<n> packages, <n> data streams)
## Class A, mechanically fixable — declared in the package source
## Class A, mechanically fixable — inherited from ECS
## Data-loss review — Class B (<n> packages, <n> data streams)
## Judgement calls — review (<n> packages, <n> data streams)
## Informational — Class C (<n> packages, <n> data streams)
## Packages by status
## Index sort
```

Findings are grouped **by code**, not only by status, so a run can be diffed against a
previous one and against the preliminary catalog analysis even when the status rules
change.

## JSON output

`--format json` emits the same data with stable keys. Per finding:

```json
{
  "code": "doc_values_false",
  "class": "A",
  "severity": "auto_fix",
  "auto_fixable": true,
  "field": "event.original",
  "where": "data_stream/incidents/fields/ecs.yml",
  "message": "...",
  "remediation": "..."
}
```

`severity` is one of `blocker`, `review`, `auto_fix`, `info` and maps 1:1 onto the
status table above. Use `--format json` when feeding another tool; use the Markdown
for humans and PR descriptions.
