# Readiness report format

`scripts/audit.py` emits this shape; use the same shape when you write a report by
hand or summarise one in a PR description.

## Contents

- Statuses
- Per-stream lines (opt-in, sort, `_source` consumers, detection rules, lookup
  candidates, text sub-fields, stream manifest)
- Per-package report
- Catalog report
- JSON output

## Statuses

Per data stream, worst finding wins. Package status is the worst of its streams.

| Status | Meaning |
| --- | --- |
| `READY` | No mapping blocker found. **Not a validation result**: correctness and performance tests are still to do. The report prints this gloss next to the status. |
| `READY_AFTER_AUTO_FIX` | Only Class A findings with a mechanical fix: `copy_to` → ingest pipeline, a non-`lowercase` `normalizer` → pipeline or multi-field, `store: true` → removed, `doc_values: false` → a mode-scoped `columnar: {doc_values: true}` override on the field (package-owned or `external: ecs` alike), `dynamic: runtime` → `dynamic: true`. |
| `NEEDS_REVIEW` | A Class B data-loss finding (`dynamic: false`, `enabled: false`), a single-level `nested` field, a mapping-level runtime field, or a `_source` consumer: a transform script (`source_consumer_transform`), a `latest` transform (`source_consumer_latest_transform`), a Kibana asset (`source_consumer_kibana`) or a shipped detection rule (`source_consumer_detection_rule`). Needs a human decision before opting in. |
| `BLOCKED` | `nested` inside `nested`, an unsupported field type, a stored-`_source` override, or an invalid `columnar: {doc_values: false}`. No mechanical fix. |
| `OUT_OF_SCOPE` | Not a `type: logs` data stream, a stream fed by an OpenTelemetry input (`otelcol`), or the package is `type: input`. |

A field that already carries `columnar: {doc_values: true}` is **resolved**: the
`doc_values_false` / `doc_values_false_ecs` finding is not raised, because Fleet
supplies doc values for exactly the modes that need them. An existing
`columnar: {index: true}` is reported as Class C (`columnar_index_true`, "confirm the
query that needs it") and never affects the status.

Two checks on the plumbing rather than the mappings:
`columnar_requires_spec_3_7` (Class A, `auto_fix`) fires when either construct
appears while the root `format_version` is below 3.7.0 — bump it — and
`columnar_override_misplaced` (Class A, `blocker`) fires on a field-level
`columnar:` block that Fleet would never apply, i.e. on an `object_type`
dynamic-template field or inside `multi_fields:`.

**A package can be mixed** — `aws` has one blocked data stream (`waf`) and eighteen
migratable ones. Opt in per data stream; never hold a whole package back for one
stream.

## Per-stream lines

**Columnar opt-in** reports how (and whether) the stream is already
columnar-enabled. The two declarations are not interchangeable:
`elasticsearch.columnar.supported: true` means Fleet offers the per-stream opt-in
toggle while logsdb stays the default; a columnar `elasticsearch.index_mode` forces
columnar for every install (toggle locked on, existing streams switch at the next
rollover). Either one counts as columnar-enabled for reporting; in JSON they are
`columnar_supported`, `index_mode` and the derived `columnar_enabled`. A stream that
declares one while still carrying Class A findings is called out as inconsistent,
and for `columnar.supported: true` that also raises
`columnar_supported_with_blockers` (severity `blocker`).

**Sort** is one of (JSON: `sort.class`):

- `default OK` (`default_ok`) — `host.name asc, @timestamp desc` suits this data
  stream, either because the inputs are host-local or because a receiver pipeline
  sets `host.name` from the header on every event
- `default DEGRADED: falls back to @timestamp desc only` (`degraded`) — host-local
  inputs, but the package maps `host.name` as something Elasticsearch cannot sort on
- `explicit sort proposed: <field> asc, @timestamp desc` — from a receiver pipeline's
  `observer.*` device identifier (`receiver_proposed`) or from candidate tier 1 or 2
  (`explicit`)
- `receiver input — no confident candidate; needs human choice`
  (`receiver_no_candidate`)
- `no confident candidate — dashboard hint: <field> (filtered N×); needs human choice`
  (`review_candidate`) — **no** `index.sort` YAML is emitted; the hint is in
  `sort.dashboard_sort_hint` and `sort.dashboard_sort_hint_filters`
- `explicit sort proposed: @timestamp desc only — no confident candidate; needs human
  choice` (`no_candidate`) — deliberately not a guess: a weak or multi-valued sort key
  is worse than none

`receiver_proposed`, `explicit`, `receiver_no_candidate` and `no_candidate` carry an
`explicit_sort_yaml` fragment; `default_ok` and `degraded` do not, and
`review_candidate` deliberately does not.

**`_source` consumers** is printed for every in-scope stream, found or not, because an
empty Class C section is indistinguishable from a check that never ran. Clean, it
reads "none found (no transform script reading `_source`, no `latest` transform, no
scripted/runtime fields or ES|QL `METADATA _source` in `kibana/`, no shipped detection
rule reading `_source`); object arrays: none in the sampled documents", and it names
any `flattened` field that held an object array as exempt. When the detection rules
could not be scanned it says so. JSON: `source_consumers`.

**Detection rules** states how many shipped rules query the stream directly (by
language), how many reach it through broad patterns such as `logs-*`, and how many
read `_source`: "71 shipped rule(s) query this stream directly (10 esql, 61 kuery); 10
more reach it through broad patterns such as `logs-*`; 1 read `_source`". Quote it in
the PR with both numbers. JSON: `detection_rules`.

**Lookup candidates** lists the `keyword`/`ip` fields the stream's direct rules and
scanned dashboard filters reference outside the sort key, high-risk lookup fields
first. It is input for the per-stream `index: true` decision, never a
recommendation. JSON: `lookup_candidates`.

**Text sub-fields** counts the `text`/`match_only_text` multi-fields the stream's
mapping carries (declared, or imported with `external: ecs`), which keep an inverted
index in columnar: input for the ECS `.text` review. Sub-fields `ecs@mappings` adds at
index time are not counted. JSON: `text_subfields`.

**Stream manifest** gives the one `elasticsearch:` block to write and *where* it goes,
read from the manifest (`has_es_key`):

- manifest already has an `elasticsearch:` key → "merge the block below into the
  existing `elasticsearch:` key of `data_stream/<ds>/manifest.yml` — a manifest has a
  **single** `elasticsearch:` key …"
- manifest has no `elasticsearch:` key → "add the block below to
  `data_stream/<ds>/manifest.yml` (there is no `elasticsearch:` key yet) — it goes in
  as a new top-level key, conventionally after `streams:` at the end of the file"

The line is idempotent: whatever the manifest already declares is reported as
"already present" and left out of the YAML block, so re-running the audit after a
migration checks that it landed. On a stream that is not READY the flag is not
proposed at all.

## Per-package report

```markdown
# Columnar readiness: `<package>`

- Status: **<STATUS>** (<gloss, for READY>)
- Package type: `integration`, version `X.Y.Z`, format_version `3.x.y`
- ECS definitions: elastic-package ECS cache v9.3.0 (`…`) | built-in fallback: …
- Detection rules: <n> shipped rules scanned (latest version of each, from `security_detection_engine`) | not scanned
- Kibana condition: `^8.19.0 || ^9.1.0` — declaring readiness means **replacing the whole range** with `conditions.kibana.version: "^9.6.0"` …
- **Cost:** … raises this package's **minimum stack version to 9.6** …

| Data stream | Status | Findings | Index sort |
| --- | --- | --- | --- |
| `<ds>` | <STATUS> | <n> | <sort recommendation> |

## `<ds>` — <STATUS>

- Inputs: `cel`, `httpjson`
- Current `index_mode`: `unset (logsdb default)`
- Columnar opt-in: <declared ready | columnar forced via `index_mode` | not declared>. Plumbing: …
- Sort: **<recommendation>** — <why>
- `_source` consumers: <none found (…) | **<n> … (`<code>`)** — see the Class C findings below>; object arrays: …
- Detection rules: <n> shipped rule(s) query this stream directly (…); <n> more reach it through broad patterns such as `logs-*`; <none reads | n read> `_source`. …
- Lookup candidates for the `index: true` review, a starting point and not a recommendation ("none" is a valid decision): `source.ip` (high-risk lookup): 12 rules; …
- Text sub-fields (they keep an inverted index in columnar; …): <n>, `user_agent.original.text`, …
- Stream manifest: <merge … | add …>.

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
  - **Suggested change** in `<file>`, <position>:

    ```yaml
    <ready-to-paste snippet>
    ```

    <note: what else to change, how to test>

### Class B — accepted but lossy

- `<code>` — <what and where>
  - Where: `data_stream/<ds>/manifest.yml`
  - <remediation>

### Class C — behaviour change

- `source_consumer_latest_transform` — the `<name>` transform is a `latest` transform: … <destination pipeline note>
  - Where: `elasticsearch/transform/<name>/transform.yml`
  - <remediation>
- `source_consumer_detection_rule` — the shipped detection rule "<name>" (esql) reads this stream's `_source`: …
  - Where: `packages/security_detection_engine/kibana/security_rule/<rule_id>_<version>.json`
  - <remediation>
- `object_array_flattening` — <n> object field(s) hold an array of objects: …

## Out of scope

- `<ds>`: data stream type is `metrics` (logs only)
- `<ds>`: OpenTelemetry input (`otelcol`): OTel log streams stay on LogsDB until …

## Dashboard fields (benchmark workload)

`field.a`, `field.b`, …

## Dashboard filter fields (sort tie-break)

`field.a`, `field.b`, …

## `latest` transforms that read no stream of this package

- `<name>` (`elasticsearch/transform/<name>/transform.yml`): `<source patterns>` — <flagged on `<other_pkg>/<ds>` | reads no in-scope logs stream of a package in this repo, so no columnar opt-in here changes its output>

## Detection rules in the PR notes

Record the per-stream **Detection rules** lines above in the PR, with both numbers …
```

## Catalog report

```markdown
# Columnar readiness — catalog audit

Packages scanned: <n>
Candidate packages (at least one in-scope `type: logs` data stream): <n>
ECS definitions: …
Detection rules: <n> shipped rules scanned …

| Status | Packages | Logs data streams |
| --- | --- | --- |
| BLOCKED | | |
| NEEDS_REVIEW | | |
| READY_AFTER_AUTO_FIX | | |
| READY (no mapping blocker found; this is not a validation result) | | |
| OUT_OF_SCOPE (input package / no logs streams / OTel input) | | |

OTel log streams out of scope until derived fields land (<n>): `<pkg>`/<ds>, …

## Already columnar-enabled
## Blockers — Class A, no mechanical fix (<n> packages, <n> data streams)
## Hard mapping errors declared in the package source (<n> packages, <n> data streams)
## Class A, mechanically fixable — declared in the package source
## Class A, mechanically fixable — inherited from ECS
## Data-loss review — Class B (<n> packages, <n> data streams)
## Judgement calls — review (<n> packages, <n> data streams)
## `_source` readers outside the mappings — review (<n> packages, <n> data streams)
## Informational — Class C (<n> packages, <n> data streams)
## Packages by status
## Index sort
```

The **Already columnar-enabled** section is omitted while both counts are zero.
Findings are grouped **by code**, not only by status, so a run can be diffed against
a previous one even when the status rules change.

## JSON output

`--format json` emits the same data with stable keys. The top level carries
`ecs_schema_source`; each package carries `latest_transforms` (each with `streams`,
the package's own streams it reads, and, when that is empty, `flagged_on`, the
`<package>/<ds>` streams elsewhere that carry its finding), `detection_rules_dir` and
`detection_rules_scanned`. Per finding:

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

Findings with a mechanical fix also carry `patch`: `{"file", "position", "lang",
"body", "note"}`. This is the **Suggested change**: `nested_in_nested` (the
`type: group` mapping), `keyword_normalizer` (the multi-field), `copy_to` (the
`script` processor), `runtime_field` (a script skeleton, or the mapping change for
`runtime: true`), and `source_consumer_latest_transform` (the `dot_expander`, for a
destination pipeline that does not expand dotted keys yet). Pipeline snippets are
tagged `columnar_*`.

Per data stream, alongside `index_mode`:

```json
{
  "index_name": "logs-gcp.audit-default",
  "columnar_supported": true,
  "columnar_enabled": true,
  "columnar_supported_with_blockers": false,
  "existing_index_sort": { "field": ["organization.id", "@timestamp"], "order": ["asc", "desc"] },
  "source_consumers": { "transform": 0, "latest_transform": 0, "kibana": 0,
                        "detection_rule": 1, "object_arrays": 0, "flattened_exempt": [] },
  "detection_rules": { "scanned": true, "specific": 71, "broad": 10,
                       "by_language": {"esql": 10, "kuery": 61},
                       "reading_source": ["GKE Certificate Signing Request for Privileged Identity"],
                       "names": ["…"] },
  "lookup_candidates": [ { "field": "source.ip", "type": "ip", "rules": 12,
                           "dashboard_filters": 0, "high_risk": true } ],
  "text_subfields": ["user_agent.original.text"]
}
```

`existing_index_sort` is `null` when the manifest declares no sort. `source_consumers`
is the C6-C10 scan result, including when every count is zero. `severity` is one of
`blocker`, `review`, `auto_fix`, `info` and maps 1:1 onto the status table above. Use
`--format json` when feeding another tool; use the Markdown for humans and PR
descriptions.
