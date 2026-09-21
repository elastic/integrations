# Columnar blockers catalog

Every mapping feature that `logsdb_columnar` rejects or degrades, with the detection
rule the audit uses and the remediation to apply.

## Why these exist

`logsdb_columnar` stores every field exactly once, as doc values. It drops inverted
indexes and BKD trees for all non-`text` fields, and it **never stores the original
JSON `_source`** — it reconstructs a flattened *synthetic source* from doc values at
read time. Anything that makes a field unreconstructable from doc values is therefore
either rejected outright or silently lossy.

Three classes:

| Class | Meaning | Effect on status |
| --- | --- | --- |
| **A** | Elasticsearch rejects the index template at PUT time | `BLOCKED`, or `READY_AFTER_AUTO_FIX` when the fix is mechanical |
| **B** | Accepted, but data is permanently lost | `NEEDS_REVIEW` |
| **C** | Accepted, behaviour changes | informational only |

---

## Class A — rejected by Elasticsearch

### A1. `nested` inside `nested` — `nested_in_nested`

**Rule.** A field of `type: nested` that has a descendant (at any depth, through
`fields:`) also of `type: nested`.

Single-level `nested` is accepted, but it is reported separately as
`nested_single_level` (severity *review*) because the synthetic-source shape changes.

**Remediation.** Flatten the inner level to leaf arrays (e.g. `a.b.c: [x, y]` instead
of an array of objects), or remap the inner object as `type: flattened`. Both change
the query surface, so this is never an automatic fix.

**Known in catalog:** `o365/audit`, `aws/waf`.

### A2. `doc_values: false` — `doc_values_false`

**Rule.** `doc_values: false` on a field that is **not** a multi-field, **unless** the
same field also sets `store: true`.

- Multi-fields (`multi_fields:`) are exempt: the parent field carries the value, so the
  sub-field does not need to be reconstructable.
- `doc_values: false` + `store: true` is accepted by Elasticsearch — the value is
  reconstructable from the stored field.

**Remediation**, in order of preference:

1. Remove `doc_values: false`. Under columnar mode the field is stored as doc values
   anyway and there is no inverted index to pay for, so the original "save space by
   not indexing" motivation largely disappears.
2. Add `store: true`. Right answer for large, search-only strings — `event.original`
   is the canonical case.
3. Change the type to `match_only_text` for message-like content.

**Known in catalog (declared in source):** `doppel/alerts`
(`doppel.alerts.cred_leaks_password`), `withsecure_elements/incidents` and
`withsecure_elements/security_events` (`event.original`).

### A2b. `doc_values: false` inherited from ECS — `doc_values_false_ecs`

**This one is invisible in the package source.** `elastic-package`'s dependency manager
(`internal/fields/dependency_manager.go`, `transformImportedField`) copies `index` and
`doc_values` from the ECS schema into the built package when a field is declared as
`external: ecs`. ECS defines `event.original` with `index: false, doc_values: false`,
so:

```yaml
# data_stream/<ds>/fields/ecs.yml  — source
- name: event.original
  external: ecs
```

becomes, in `build/packages/<pkg>/<version>/data_stream/<ds>/fields/ecs.yml`:

```yaml
- description: Raw text message of entire event. ...
  doc_values: false
  index: false
  name: event.original
  type: keyword
```

which columnar mode rejects. Verify with `elastic-package build` and read the built
fields file — do not trust the source.

ECS fields that carry `doc_values: false` (checked against ECS v8.11.0 and v9.3.0):

- `event.original`
- `gen_ai.agent.description` (ECS 9.x only)
- `x509.public_key_exponent` and its seven reuse locations
  (`file.`, `tls.client.`, `tls.server.`, `threat.indicator.`,
  `threat.indicator.file.`, `threat.enrichments.indicator.`,
  `threat.enrichments.indicator.file.`)

**Remediation.** Override locally — package attributes win over imported ones
(`transformed.DeepUpdate(def)`), except for `type`:

```yaml
- name: event.original
  external: ecs
  store: true
```

`store: true` keeps `event.original` retrievable and searchable-by-fetch without paying
for doc values on a large string, which is exactly what the ECS definition was trying
to achieve.

**Known in catalog:** 49 packages. Run `scripts/audit.py packages/ --catalog` for the
current list.

### A3. `copy_to` — `copy_to`

**Rule.** Any field with a `copy_to` attribute.

`copy_to` writes into a second field that is not present in the document, so the
synthetic source cannot be reconstructed faithfully
(`FieldMapper.calculateSyntheticSourceMode`).

**Remediation.** Do the copy in the ingest pipeline with a `set` processor (or `append`
when the target is multi-valued), or drop the target field if nothing queries it.

```yaml
# elasticsearch/ingest_pipeline/default.yml
- set:
    field: my.combined
    copy_from: my.source
    ignore_empty_value: true
```

### A4. `keyword` with `normalizer` — `keyword_normalizer`

**Rule.** `type: keyword` together with a `normalizer`.

The normalizer rewrites the value before it is stored, so doc values hold the
normalized form and the original cannot be reconstructed.

**Remediation.**

- Apply the transformation in the ingest pipeline (usually a `lowercase` processor) and
  map a plain `keyword`; or
- move the normalized variant into `multi_fields:` — multi-fields are exempt from the
  reconstructability check, so `field` stays raw and `field.lowercase` carries the
  normalizer.

```yaml
- name: user.name
  type: keyword
  multi_fields:
    - name: lowercase
      type: keyword
      normalizer: lowercase
```

**Known in catalog:** `crowdstrike/fdr`, `m365_defender/event`,
`sentinel_one_cloud_funnel/event`, `system/security`, `windows/forwarded`,
`windows/sysmon_operational`.

### A5. Mapping-level runtime fields — `runtime_field`

**Rule.** A field definition with `runtime: true`, or with a `runtime:` block
containing a script.

**Remediation.**

- Materialise the value with a `script` processor in the ingest pipeline (best when the
  field is queried often); or
- move it to query time: ES|QL `EVAL`, or a runtime field defined in the search
  request rather than in the mapping. Both still work against a columnar index.

### A6. Stored `_source` overrides — `source_mode_stored`, `source_disabled`

**Rule.** Any of:

- `elasticsearch.source_mode: stored` in `data_stream/<ds>/manifest.yml`
- `elasticsearch.index_template.mappings._source.enabled: false`
- `elasticsearch.index_template.mappings._source.mode: stored`

Columnar mode never stores `_source`; these settings are a direct contradiction.

**Remediation.** Remove the override. If the data stream genuinely needs a byte-exact
`_source`, it is not a columnar candidate — leave it on logsdb.

### A7. Types with no doc values — `unsupported_type`

**Rule.** `type` in `search_as_you_type`, `completion`, `token_count`, `rank_feature`,
`rank_features`, `percolator`.

**Defensive only.** The `type` enum in
`spec/integration/data_stream/fields/fields.spec.yml` does not allow these, so
JSON-schema validation rejects them before the columnar check runs. The check exists to
guard against a future enum expansion.

---

## Class B — accepted but lossy

These do **not** fail the template PUT. They silently drop data, and in columnar mode
the data is gone for good because there is no `_source` to fall back to. Each one needs
a human decision before the data stream is opted in.

### B1. `dynamic: false` — `dynamic_false_manifest`, `dynamic_false_field`, `dynamic_false_template`

**Rule.** `dynamic: false` (bool or the string `"false"`) in any of:

- `elasticsearch.index_template.mappings.dynamic` in the data stream manifest
- any object/`group` field definition in `fields/*.yml`
- anywhere inside `elasticsearch.index_template.mappings.dynamic_templates`

**What changes.** In `standard` and `logsdb` modes, a field under a `dynamic: false`
object is not searchable but *is* retained in `_source`, so it shows up in the Discover
document view and can be recovered by reindexing. In columnar mode there is no
`_source`: the field is dropped at ingest and is unrecoverable.

**Remediation options**, in the order you should consider them:

1. Confirm the unmapped fields genuinely do not matter — keep `dynamic: false` and
   document the decision in the PR.
2. Add explicit mappings for the fields that do matter.
3. `dynamic: true` — unmapped leaves become non-indexed `keyword`/`long`/`double` doc
   values. Cheap under columnar mode (no inverted index is built), but watch the field
   count against `index.mapping.total_fields.limit`.
4. `dynamic: strict` — documents with unknown fields are rejected into the failure
   store instead of being silently truncated. The safest option when the upstream
   schema is supposed to be stable and you want to be told when it isn't.

**Known in catalog:** `beyondinsight_password_safe`, `cloud_asset_inventory`,
`cloud_security_posture`, `elastic_agent`, `falco`, `fleet_server`, `kubernetes`,
`sysdig`.

### B2. `enabled: false` on an object — `enabled_false`

**Rule.** `enabled: false` on a field definition.

The object is accepted but nothing under it is indexed or stored, so under columnar
mode the whole subtree disappears.

**Remediation.** Change the field to `type: flattened` (keeps the whole subtree
queryable as a single doc-values field), or map the sub-fields explicitly.

**Known in catalog:** `hpe_aruba_cx`, `osquery_manager`,
`proofpoint_365totalprotection`.

---

## Class C — accepted, behaviour changes

Informational. These never block a migration but they explain the test diffs and the
benchmark results.

### C1. No inverted index on non-`text` fields

Every non-`text` field loses its inverted index / BKD tree. `text` and
`match_only_text` keep theirs; `wildcard` keeps its own n-gram structure.

Filters on non-sorted fields become doc-value scans pruned by skippers rather than
posting-list lookups, so query cost goes up — most visibly for needle-in-a-haystack
queries (a single user name or file hash over a long time range).

The lever a package owner controls is **index sorting** — see
[`sorting.md`](sorting.md). Do **not** add `index: true` overrides on keyword fields:
the premise of the rollout is that columnar does not need inverted indexes, and
per-field indexing decisions are made later from benchmark data, never from static
analysis.

Elasticsearch is closing the gap independently: keyword skippers land in 9.7, bloom
filters after GA.

### C2. Synthetic source shape

The document you get back is a reconstruction, not the bytes that were ingested:

- the object structure is flattened;
- arrays of objects are **not** retained faithfully;
- multi-value arrays keep their original order (in plain logsdb synthetic source they
  are sorted and de-duplicated).

Pipeline test expected documents
(`data_stream/<ds>/_dev/test/pipeline/*-expected.json`) will therefore show diffs. See
[`correctness-and-performance.md`](correctness-and-performance.md) for which diffs are
expected and which are bugs.

### C3. Dynamically mapped fields

Fields created by dynamic mapping become non-indexed `keyword`/`long`/`double` doc
values rather than indexed fields.
