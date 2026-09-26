# Readiness report format

`scripts/audit.py` emits this shape; use the same shape when you write a report by
hand or summarise one in a PR description.

## Statuses

Per data stream, worst finding wins:

| Status | Meaning |
| --- | --- |
| `READY` | No findings. Opt in. |
| `READY_AFTER_AUTO_FIX` | Only Class A findings with a mechanical fix: `copy_to` → ingest pipeline, a non-`lowercase` `normalizer` → pipeline or multi-field, `store: true` → removed, `doc_values: false` → a mode-scoped `columnar: {doc_values: true}` override on the field (package-owned or `external: ecs` alike), `dynamic: runtime` → `dynamic: true`. |
| `NEEDS_REVIEW` | A Class B data-loss finding (`dynamic: false`, `enabled: false`), a single-level `nested` field, a mapping-level runtime field, or a columnar `_source` consumer — a transform (`source_consumer_transform`) or Kibana asset (`source_consumer_kibana`) that reads `_source`. Needs a human decision before opting in. |
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

Three Class C codes cover the columnar `_source` shape
([`blockers.md`](blockers.md) C6-C8). `source_consumer_transform` and
`source_consumer_kibana` are severity `review`, so they move the stream to
NEEDS_REVIEW: columnar `_source` is reconstructed and flattened, and anything that
reads it at query time has to be checked first. `object_array_flattening` is severity
`info` and never changes a status — it records the object arrays in the stream's own
example documents, which come back as parallel arrays. Ingest pipelines are never
flagged (they run before indexing), and plain ES|QL is unaffected unless the query
asks for `METADATA _source`.

**The negative result is printed too.** Every in-scope data stream gets a
`` `_source` consumers: `` line whether or not anything was found, because an empty
Class C section is indistinguishable from a check that never ran. When the scan is
clean the line reads "none found in this package (no transforms reading `_source`, no
scripted/runtime fields in `kibana/`, no ES|QL `METADATA _source`); object arrays: none
in the sampled documents", and it names any `flattened` field that held an object array
in the sample as exempt. It always ends with the reminder that detection rules live in
`elastic/detection-rules` and have to be checked by hand; the command is in the
per-package **`_source` consumers the audit cannot see (manual)** section at the end of
the report. In JSON this is `source_consumers`:
`{"transform": 0, "kibana": 0, "object_arrays": 0, "flattened_exempt": [...]}`.

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

`receiver_proposed`, `explicit`, `receiver_no_candidate` and `no_candidate` carry an
`explicit_sort_yaml` fragment; `default_ok` and `degraded` do not (there is nothing to
write — the logs profile default already applies), and `review_candidate` deliberately
does not, so a migration PR cannot pick up a dashboard hint by accident.

In the Markdown report that fragment is never printed on its own: it is merged with
`columnar.supported: true` into the **one** `elasticsearch:` block of the stream
manifest (see the **Stream manifest** line below), because a manifest has a single
`elasticsearch:` key and two pasted snippets would be a duplicate key. An `index.sort`
the manifest already declares is read back into `existing_index_sort` (dotted or nested
spelling) and reported as "already present" instead of being proposed again.

## Per-package report

```markdown
# Columnar readiness: `<package>`

- Status: **<STATUS>**
- Package type: `integration`, version `X.Y.Z`, format_version `3.x.y`
- Kibana condition: `^8.19.0 || ^9.1.0` — declaring readiness means **replacing the whole range** with `conditions.kibana.version: "^9.6.0"`, not adding a branch to it: every `||` branch has to be 9.6+, so the older branches go away. That is the point of the declaration *and* its cost — if this package must keep serving older stacks, do not declare readiness on this release line (…). <When the package is already at ^9.6.0 the line instead reads "already at the `^9.6.0` floor …; nothing to change".>
- **Cost:** … raises this package's **minimum stack version to 9.6**. … That makes it a **breaking change**: ship it as a **major** version bump with a `type: breaking-change` changelog entry ("Raise the minimum required Kibana version to 9.6.0 …") alongside the `enhancement` one — the convention elastic/integrations follows for a Kibana floor raise (`aws` 7.0.0, `aws_bedrock` 2.0.0, `aws_bedrock_agentcore` 1.0.0). Declare readiness deliberately, for the packages picked as tech-preview targets — not catalog-wide.

| Data stream | Status | Findings | Index sort |
| --- | --- | --- | --- |
| `<ds>` | <STATUS> | <n> | <sort recommendation> |

## `<ds>` — <STATUS>

- Inputs: `cel`, `httpjson`
- Current `index_mode`: `unset (logsdb default)`
- Columnar opt-in: <declared ready via `elasticsearch.columnar.supported: true` | columnar by default via `index_mode: logsdb_columnar` | not declared>. Plumbing: `format_version: "3.7.0"` + `conditions.kibana.version: "^9.6.0"` — see the package header for the 9.6 minimum-stack cost.
- Sort: **<recommendation>** — <why: inputs, host.name evidence>
- `_source` consumers: none found in this package (no transforms reading `_source`, no scripted/runtime fields in `kibana/`, no ES|QL `METADATA _source`); object arrays: none in the sampled documents (`sample_event.json` and up to four `_dev/test/pipeline/*-expected.json`); fields of type `flattened` are exempt, they keep their JSON verbatim: `<pkg>.<ds>.updates`. Detection rules are **not** part of the package — still check `elastic/detection-rules` by hand for rules that read `_source` of `logs-<pkg>.*` (command at the end of this report).
- Stream manifest: merge the block below into `data_stream/<ds>/manifest.yml` — a manifest has a **single** `elasticsearch:` key, so add these children to the one already there; a second `elasticsearch:` is a duplicate key and the file keeps only one of them.

  ```yaml
  elasticsearch:
    columnar:
      supported: true
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

### Class C — behaviour change

- `source_consumer_transform` — the `<name>` transform reads `_source` in `<script path>`
  - Where: `elasticsearch/transform/<name>/transform.yml`
  - <remediation>
- `source_consumer_kibana` — `<asset>` consumes `_source`: <ES|QL METADATA _source | params._source | scripted field> — `<expression>`
  - Where: `kibana/<type>/<asset>.json`
  - <remediation>
- `object_array_flattening` — <n> object field(s) hold an array of objects: `<field>` (`sample_event.json`), …
  - Where: `data_stream/<ds>/sample_event.json`
  - <remediation>

## Out of scope

- `<ds>`: data stream type is `metrics` (logs only)

## Dashboard fields (benchmark workload)

`field.a`, `field.b`, …

## Dashboard filter fields (sort tie-break)

`field.a`, `field.b`, …

## `_source` consumers the audit cannot see (manual)

```bash
git clone https://github.com/elastic/detection-rules
cd detection-rules
grep -rl 'logs-<pkg>\.' rules/ | xargs grep -l '_source'
```
```

The **Stream manifest** line is idempotent: whatever the manifest already declares is
reported as "already present" (`` `elasticsearch.columnar.supported: true` already
present; explicit `index.sort` already present (`organization.id` asc, `@timestamp`
desc) ``) and left out of the YAML block, which disappears entirely once there is
nothing to add. Re-running the audit after a migration is therefore a check that the
migration landed. On a stream that is not READY the flag is not proposed at all — the
3.7.0 validator would reject it — and the line says so.

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
  "columnar_supported_with_blockers": false,
  "existing_index_sort": { "field": ["organization.id", "@timestamp"], "order": ["asc", "desc"] },
  "source_consumers": { "transform": 0, "kibana": 0, "object_arrays": 0,
                        "flattened_exempt": ["anthropic.audit.updates"] }
}
```

`existing_index_sort` is `null` when the manifest declares no sort; it is read from
both the nested (`index: {sort: {...}}`) and the dotted (`index.sort.field`) spelling.
`source_consumers` is the C6-C8 scan result, including when every count is zero — that
is the negative the Markdown line states in words.

`severity` is one of `blocker`, `review`, `auto_fix`, `info` and maps 1:1 onto the
status table above. Use `--format json` when feeding another tool; use the Markdown
for humans and PR descriptions.
