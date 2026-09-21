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

**Rule.** `doc_values: false` on a field that is **not** a multi-field.

Multi-fields (`multi_fields:`) are exempt: `MappingLookup.firstFieldNotReconstructableFromDocValues`
skips anything `isMultiField(...)` returns true for, because a multi-field never
appears in `_source` on its own. For a top-level keyword,
`KeywordFieldMapper.syntheticSourceSupport` returns `FALLBACK` when neither `stored()`
nor doc values are available, and columnar mode disables the `_ignored_source`
fallback and forbids `synthetic_source_keep`, so the index template is rejected
(`IndexMode.LOGSDB_COLUMNAR#validateMapping`).

**Remediation.** Set `doc_values: true` — i.e. delete the `doc_values: false` line, or
for an `external: ecs` field add an explicit `doc_values: true` (see A2b). Under
columnar mode the field is stored as doc values anyway and there is no inverted index
to pay for, so the original "save space by not indexing" motivation is gone.

`match_only_text` is an alternative for message-like content, but **only** for fields
the package defines itself — elastic-package refuses to override the type of an
`external: ecs` field unless it is on the `allowedTypeOverride` list.

**`store: true` is not an option.** See A2c: Elasticsearch rejects `store` in columnar
modes.

**Known in catalog (declared in source):** `doppel/alerts`
(`doppel.darkweb.cred_leaks_password`), `withsecure_elements/incidents` and
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

**Remediation.** Override `doc_values` locally — package attributes win over imported
ones, because elastic-package merges with `transformed.DeepUpdate(def)`
(`internal/fields/dependency_manager.go`):

```yaml
- name: event.original
  external: ecs
  doc_values: true
```

Two things that do **not** work here:

- `store: true` — rejected by Elasticsearch in columnar modes (A2c).
- `type: match_only_text` — elastic-package forces the ECS type for an
  `external: ecs` field unless the field is in `allowedTypeOverride`
  (`dependency_manager.go`), and `event.original` is not.

**Where it surfaces.** `elastic-package lint` validates the package *source*, where
the field has no `doc_values` at all, so it sees nothing. `elastic-package build`
validates the *built zip*, where ECS has been resolved — that is where every affected
package will fail, whatever spec version it declares.

**Known in catalog:** 49 packages, 72 data streams. Run
`scripts/audit.py packages/ --catalog` for the current list.

### A2c. `store: true` — `store_true`

**Rule.** Any field with `store: true`.

Elasticsearch refuses it while parsing the mapping
(`FieldMapper.Builder#storeParam`):

```
[store] cannot be enabled on field [foo] in [logsdb_columnar] index mode
```

(see `KeywordFieldMapperTests.testStoreNotAllowedInColumnarMode`). This is why
`store: true` can never be the answer to A2 or A2b — the two settings are rejected by
different checks, and swapping one for the other just trades one failure for another.

**Remediation.** Remove `store: true`. The value is reconstructed from doc values;
`fields` retrieval and `_source` retrieval keep working.

**Known in catalog:** none in a `type: logs` data stream. The only two occurrences
(`cisco_meraki_metrics/device_health`, `panw_metrics/system`) are in `type: metrics`
streams, which are out of scope.

### A3. `copy_to` — `copy_to`

**Rule.** Any field with a `copy_to` attribute. **No multi-field exemption**, unlike
`doc_values: false`.

`copy_to` writes into a second field that is not present in the document, so the
synthetic source cannot be reconstructed faithfully. Columnar mode does not reason
about it at all: `FieldMapper.TypeParser#parse` throws as soon as it sees the
attribute under `isStrictColumnar()` —

```
[copy_to] is not allowed on field [foo] in [logsdb_columnar] index mode
```

— and that parse path is the same one used for the sub-fields of a `multi_fields:`
block. (`FieldMapper#validate` separately refuses `copy_to` from or to a multi-field
in every index mode.)

**Remediation.** Do the copy in the ingest pipeline with a `set` processor (or `append`
when the target is multi-valued), or drop the target field if nothing queries it.

```yaml
# elasticsearch/ingest_pipeline/default.yml
- set:
    field: my.combined
    copy_from: my.source
    ignore_empty_value: true
```

### A4. `keyword` with a non-`lowercase` `normalizer` — `keyword_normalizer`

**Rule.** `type: keyword` with a `normalizer` **other than** `lowercase`, on a field
that is **not** a multi-field.

Two exemptions, both of them easy to get wrong:

1. **Multi-fields are exempt.** `MappingLookup.firstFieldNotReconstructableFromDocValues`
   skips `isMultiField(...)`, so a `caseless` sub-field under `multi_fields:` is fine
   no matter what normalizer it uses. The parent carries the raw value.
2. **`normalizer: lowercase` is exempt.** `KeywordFieldMapper.Builder` defaults
   `normalizer_skip_store_original_value` to `true` when the normalizer resolves to
   the built-in `LowercaseNormalizer` (`AnalysisModule`), so
   `syntheticSourceSupport()` returns `Native` rather than `FALLBACK`. The field is
   accepted; it is merely lossy — see C4.

Anything else (a custom normalizer with `asciifolding`, a custom char filter, …)
returns `FALLBACK` and is rejected on a top-level field.

**Remediation.**

- Apply the transformation in the ingest pipeline and map a plain `keyword`; or
- move the normalized variant into `multi_fields:` — `field` stays raw and
  `field.caseless` carries the normalizer.

```yaml
- name: user.name
  type: keyword
  multi_fields:
    - name: caseless
      type: keyword
      normalizer: lowercase
```

**Known in catalog:** none. The six data streams the earlier analysis flagged —
`crowdstrike/fdr`, `m365_defender/event`, `sentinel_one_cloud_funnel/event`,
`system/security`, `windows/forwarded`, `windows/sysmon_operational` — all declare the
normalizer on a `caseless` **multi-field**, which is exempt. They are clean;
`system/security` is `READY`.

### A5. Mapping-level runtime fields — `runtime_field`

**Rule.** A field definition with `runtime: true`, or with a `runtime:` block
containing a script.

**Remediation.**

- Materialise the value with a `script` processor in the ingest pipeline (best when the
  field is queried often); or
- move it to query time: ES|QL `EVAL`, or a runtime field defined in the search
  request rather than in the mapping. Both still work against a columnar index.

### A5b. `dynamic: runtime` — `dynamic_runtime`

**Rule.** `dynamic: runtime` on a field definition, or on
`elasticsearch.index_template.mappings.dynamic`.

Unmapped leaves would be materialised as **mapping-level** runtime fields, which is
what columnar mode refuses. But it does **not** wait for a document to prove it:
`ObjectMapper` rejects the value while the mapping is being parsed —

```
dynamic [runtime] is not supported in strict columnar mode
```

— so the **index template PUT fails** and the data stream is never created. It is a
setup-time failure, exactly like the rest of Class A, not a surprise on first ingest.
(An earlier version of this document said it failed "later, when the first document
with an unknown field arrives". That was wrong.)

**Severity: `auto_fix`.** The fix is mechanical and has a single obvious form —
replace `runtime` with `true` — with no judgement call about what the data means, so
it belongs with `copy_to` and `doc_values: false` rather than with the review items.
The behaviour change it implies (unmapped leaves become concrete doc values instead
of computed-on-read fields) is what columnar mode wants anyway.

**Remediation.** Use `dynamic: true`: unmapped leaves become non-indexed
`keyword`/`long`/`double` doc values, which is cheap in columnar mode because no
inverted index is built for them anyway. Or map the fields explicitly.

### A6. Stored `_source` overrides — `source_mode_stored`, `source_disabled`

**Rule.** Either of:

- `elasticsearch.index_template.mappings._source.enabled: false`
- `elasticsearch.index_template.mappings._source.mode: stored`

(`elasticsearch.source_mode` is **not** one of them: its package-spec enum is
`default | synthetic`, so there is no `stored` value to catch and neither value
conflicts with columnar mode. A stored `_source` can only be requested through the raw
index-template mappings above.)

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

**This does not change pipeline test expectations.** `elastic-package test pipeline`
calls `_ingest/pipeline/_simulate`; no document is ever indexed, so `index_mode` has
no way to influence `*-expected.json`. Those files must be byte-identical between the
two modes — a diff there is a real bug or test nondeterminism, never an expected
columnar effect. The shape changes above are only observable in a system test or in a
`GET _search` against documents actually indexed in both modes. See
[`correctness-and-performance.md`](correctness-and-performance.md).

### C3. Dynamically mapped fields

Fields created by dynamic mapping become non-indexed `keyword`/`long`/`double` doc
values rather than indexed fields.

### C4. `normalizer: lowercase` is lossy — `keyword_normalizer_lowercase`

A top-level keyword with `normalizer: lowercase` is accepted (see A4), but the
original value is not stored anywhere: synthetic source returns the **lowercased**
form. Anything that round-trips a document — reindex, a UI that displays `_source`,
a detection rule that string-compares the raw value — sees the normalized casing.

No change is required. If the original casing has to survive a read, keep the parent
field raw and move the normalizer into `multi_fields:`.
