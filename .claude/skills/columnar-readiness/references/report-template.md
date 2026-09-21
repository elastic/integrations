# Readiness report format

`scripts/audit.py` emits this shape; use the same shape when you write a report by
hand or summarise one in a PR description.

## Statuses

Per data stream, worst finding wins:

| Status | Meaning |
| --- | --- |
| `READY` | No findings. Opt in. |
| `READY_AFTER_AUTO_FIX` | Only Class A findings with a mechanical fix: `copy_to` → ingest pipeline, a non-`lowercase` `normalizer` → pipeline or multi-field, `store: true` → removed, `doc_values: false` → a mode-scoped `columnar: {doc_values: true}` override on the field (package-owned or `external: ecs` alike), `dynamic: runtime` → `dynamic: true`. |
| `NEEDS_REVIEW` | A Class B data-loss finding (`dynamic: false`, `enabled: false`), a single-level `nested` field, or a mapping-level runtime field. Needs a human decision before opting in. |
| `BLOCKED` | `nested` inside `nested`, an unsupported field type, a stored-`_source` override, or an invalid `columnar: {doc_values: false}`. No mechanical fix. |
| `OUT_OF_SCOPE` | Not a `type: logs` data stream, or the package is `type: input`. |

A field that already carries `columnar: {doc_values: true}` is **resolved**: the
`doc_values_false` / `doc_values_false_ecs` finding is not raised, because Fleet
supplies doc values for exactly the modes that need them. An existing
`columnar: {index: true}` is reported as Class C (`columnar_index_true`,
"benchmark-justified inverted index — confirm evidence exists") and never
affects the status.

The **Columnar opt-in** line reports how (and whether) the stream is already
columnar-enabled, and the two declarations are not interchangeable:
`elasticsearch.columnar.supported: true` means Fleet offers the per-stream opt-in
toggle while logsdb stays the default, and a columnar `elasticsearch.index_mode`
means columnar is the default for new installs. Either one counts as
columnar-enabled for reporting; in JSON they are `columnar_supported`,
`index_mode` and the derived `columnar_enabled`. A stream that declares one while
still carrying Class A findings is called out as inconsistent — the 3.7.0
validator rejects that combination — and when the declaration is
`columnar.supported: true` that inconsistency also gets its own Class A finding,
`columnar_supported_with_blockers` (severity `blocker`), plus the boolean
`columnar_supported_with_blockers` on the data stream in JSON.

Two more checks on the plumbing rather than the mappings:
`columnar_requires_spec_3_7` (Class A, `auto_fix`) fires when either construct
appears while the root `format_version` is below 3.7.0 — bump it — and
`columnar_override_misplaced` (Class A, `blocker`) fires on a field-level
`columnar:` block that Fleet would never apply, i.e. on an `object_type`
dynamic-template field or inside `multi_fields:`.

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
- Kibana condition: `^9.x.0` (needs at least `^9.7.0`, the first Kibana minor with Fleet support for `columnar.supported` and the field-level `columnar` overrides — adjust to the actual Fleet release; on older Kibana the override and the flag are silently ignored, so the toggle is unavailable and any `doc_values: false` field will make a manual columnar opt-in fail)

| Data stream | Status | Findings | Index sort |
| --- | --- | --- | --- |
| `<ds>` | <STATUS> | <n> | <sort recommendation> |

## `<ds>` — <STATUS>

- Inputs: `cel`, `httpjson`
- Current `index_mode`: `unset (logsdb default)`
- Columnar opt-in: <declared ready via `elasticsearch.columnar.supported: true` | columnar by default via `index_mode: logsdb_columnar` | not declared>
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

## Already columnar-enabled
`elasticsearch.columnar.supported: true` — opt-in toggle offered, logsdb still the default (<n> data streams): `<pkg>`/<ds>
Columnar `index_mode` — columnar is the default for new installs (<n> data streams): `<pkg>`/<ds>

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

The **Already columnar-enabled** section is omitted entirely while both counts are
zero, which is where the catalog stands today — so its appearance in a run is
itself the signal that the rollout has landed somewhere.

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

Per data stream, alongside `index_mode`:

```json
{
  "columnar_supported": true,
  "columnar_enabled": true,
  "columnar_supported_with_blockers": false
}
```

`severity` is one of `blocker`, `review`, `auto_fix`, `info` and maps 1:1 onto the
status table above. Use `--format json` when feeding another tool; use the Markdown
for humans and PR descriptions.
