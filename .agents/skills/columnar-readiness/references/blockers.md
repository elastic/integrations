# Columnar blockers catalog

Every mapping feature that `logsdb_columnar` rejects or degrades, with the detection
rule the audit uses and the remediation to apply.

## Contents

- Why these exist
- The two package-spec 3.7.0 constructs (the `columnar:` block, the readiness flag)
- Class A — rejected by Elasticsearch: A1 nested in nested, A2 `doc_values: false`
  (A2b from ECS, A2c `store`, A2d invalid override, A2e misplaced override), A3
  `copy_to`, A4 normalizer, A5 runtime fields (A5b `dynamic: runtime`), A6 stored
  `_source`, A7 types without doc values
- Class B — accepted but lossy: B1 `dynamic: false`, B2 `enabled: false`
- Class C — behaviour changes: C1 no inverted index, C2 source shape, C3 dynamic
  fields, C4 lowercase normalizer, C5 `columnar: {index: true}`
- C6-C10 `_source` consumers: C6 transform scripts, C7 Kibana assets, C8 object
  arrays, C9 shipped detection rules, C10 `latest` transforms

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

## The two package-spec 3.7.0 constructs

Both of these are new in `format_version: "3.7.0"` and both are what the
remediations below reach for. Read this before applying any fix.

### 1. The field-level, mode-scoped `columnar:` block

```yaml
- name: event.original
  external: ecs
  columnar:
    doc_values: true
```

Fleet applies the attributes inside `columnar:` **only** when the resolved index
mode of the data stream is `logsdb_columnar` or `columnar` — exactly the pattern
TSDB already uses for `dimension: true`, which Fleet only emits into the mapping
when the mode is `time_series`.

That mode scoping is the entire reason to prefer it. A bare `doc_values: true`
changes the mapping for **every** install of that package version: logsdb and
standard indices that have been happily not storing doc values for
`event.original` suddenly start storing them, and those are the installs that get
no benefit from it, because they still have `_source`. With the `columnar:` block
the logsdb and standard mappings of the same package version are byte for byte
what they are today, and only columnar installs see the override. The fix is
free off-columnar, which is what makes it safe to ship to the whole user base
during a tech preview.

Valid keys:

| Key | Valid values | Who writes it |
| --- | --- | --- |
| `doc_values` | `true` only | the remediation for A2 / A2b |
| `index` | `true` | a human, per stream, for a field that a named dashboard or rule query filters on by exact value — see C5. The audit lists candidates; it never writes one |

`columnar: {doc_values: false}` is invalid — see A2d.

**Where the block may go: static leaf fields only.** Fleet applies `columnar`
overrides when it builds the concrete mapping for a field. Two kinds of field
never get that treatment:

- a **dynamic-template field** — `type: object` (or `group`) carrying an
  `object_type`, which Fleet turns into a `dynamic_templates` entry rather than
  a named mapping;
- anything inside **`multi_fields:`**.

Fleet ignores a `columnar:` block in both places, and package-spec 3.7.0 rejects
it there, so the package does not even build. See A2e. The practical consequence
is for A2: on those two placements there is **no mode-scoped fix**, and a
`doc_values: false` has to be deleted outright — which applies in every index
mode, not only columnar. (A multi-field needs no fix in the first place; an
`object_type` field does.)

### 2. The stream-level readiness flag

```yaml
# data_stream/<ds>/manifest.yml
elasticsearch:
  columnar:
    supported: true
```

**A manifest has one `elasticsearch:` key.** The readiness flag and the index sort are
children of the same mapping, so they go in as one merged block — and that block is
merged into whatever `elasticsearch:` the manifest already has (`index_mode`,
`source_mode`, an existing `index_template`). Pasting a second `elasticsearch:`
snippet is a duplicate key: YAML does not error, it keeps one of them and drops the
other, and the migration silently loses either the flag or the sort.

```yaml
# data_stream/<ds>/manifest.yml — the whole block, merged into the existing key
elasticsearch:
  columnar:
    supported: true
  index_template:              # only when an explicit sort was proposed
    settings:
      index:
        sort:
          field: ["<field>", "@timestamp"]
          order: ["asc", "desc"]
```

This asserts "this data stream is columnar-ready". The 3.7.0 validator enforces
it: setting it while the stream still has a Class A blocker is a validation
error. Fleet enables the per-stream columnar opt-in toggle for a stream that sets
it (or that already declares a columnar `index_mode`).

`supported: true` and `index_mode: logsdb_columnar` are **different decisions**:

| Declaration | Effect |
| --- | --- |
| `elasticsearch.columnar.supported: true` | The stream is ready. Fleet shows the opt-in toggle. logsdb stays the default; nothing changes for existing or new installs until a user turns it on, and the user can turn it off again. |
| `elasticsearch.index_mode: logsdb_columnar` | Columnar is **forced** for every install of this package version: Fleet shows the toggle locked on (the API cannot turn it off either), and streams that already hold data switch at the next rollover on upgrade. |

For the tech-preview wave the answer is `supported: true` alone, with
`index_mode` left unset: the rollout strategy is that users opt in and can opt out,
and that an integration that already has data does not flip. Whether package-spec
3.7.0 should allow a columnar `index_mode` at all is an open team decision.

Both constructs are read by **Fleet**, not only by the spec validator, so both
need a `conditions.kibana.version` of at least the first Kibana minor that ships
that Fleet support. That is **9.6**, so write `"^9.6.0"` (on older Kibana the
override and the flag are silently ignored, so the toggle is unavailable and any
`doc_values: false` field will make a manual columnar opt-in fail).

**Replace the whole range, do not add a branch to it.** A package on
`"^8.19.0 || ^9.1.0"` becomes `"^9.6.0"`, full stop — every `||` branch has to be
9.6+, because one older branch is precisely what keeps Fleet offering this version to
a stack that ignores both constructs. Dropping the older branches is the point of the
declaration and its cost at the same time; if the package has to keep serving older
stacks, it does not declare readiness on this release line. And both need
`format_version: "3.7.0"` in the root
manifest: declaring either one under an older spec version is
`columnar_requires_spec_3_7`. Setting `supported: true` on a stream that still
has a Class A finding is `columnar_supported_with_blockers` — the 3.7.0
validator rejects it, and a user who did turn the toggle on would get a failed
index template PUT.

### The cost of declaring readiness

Declaring readiness raises the package's minimum stack version to 9.6, so older stacks
need a backport line. The full explanation, and why readiness is declared only for the
chosen tech-preview targets, is in [`migration.md`](migration.md#the-cost-of-declaring-readiness).
`READY` means "no mapping blocker"; it does not mean "worth the 9.6 floor".

---

## Class A — rejected by Elasticsearch

### A1. `nested` inside `nested` — `nested_in_nested`

**Rule.** A field of `type: nested` that has a `type: nested` ancestor. Ancestry is
decided by full path over all of the stream's field files, because packages declare
nested children two ways: through `fields:`, and as separate entries with dotted
names (tanium declares `whats` as `nested`, then `whats.intel_intra_ids` as `nested`
next to it). Fleet expands both into the same hierarchy.

**Why.** Columnar supports one level of nesting: "columnar index modes support only
a single level of nesting" (`NestedObjectMapper`). The index template PUT fails.

Single-level `nested` is accepted, but it is reported separately as
`nested_single_level` (severity *review*): `nested` queries still match within one
element, but `_source` consumers see the columnar shape, and any `nested` field turns
off columnar's batch indexing for the whole stream (`ShardBatchMapper`).

**Remediation.** First check that no dashboard or detection rule runs a `nested`
query on the inner path. Then, in order of preference:

1. Change the inner level to `type: group` (a plain object). Every value is kept; you
   only lose matching within a single inner element. The report prints this change
   for the field as a **Suggested change**.
2. Map it as `type: flattened` when its keys are open-ended.
3. If the pairing inside each inner element matters, build a single-level `nested`
   array in the ingest pipeline, one entry per (outer, inner) pair carrying both sets
   of keys.
4. Or keep the stream on logsdb: the opt-in is per stream.

All of 1–3 change the mapping for logsdb installs too, so this is never an automatic
fix. On an existing data stream the type change applies at the next rollover: the
write index rejects it ("can't merge a non-nested mapping ... with a nested mapping")
and Fleet rolls the stream over at package upgrade.

**Known in catalog:** `aws/waf` (`aws.waf.non_terminating_matching_rules` →
`ruleMatchDetails`), `o365/audit` (`ExchangeAggregatedFolders` → `FolderItems`,
`ExchangeAggregatedMessages` → `MessageItems`), `tanium/threat_response`
(`…match_details.finding.whats` → `intel_intra_ids` and
`artifact_activity.relevant_actions`). None of them is used by a dashboard or queried
by a shipped detection rule, so option 1 unblocks all three.

### A2. `doc_values: false` — `doc_values_false`

**Rule.** `doc_values: false` on a field that is **not** a multi-field.

Multi-fields (`multi_fields:`) are exempt: `MappingLookup.firstFieldNotReconstructableFromDocValues`
skips anything `isMultiField(...)` returns true for, because a multi-field never
appears in `_source` on its own. For a top-level keyword,
`KeywordFieldMapper.syntheticSourceSupport` returns `FALLBACK` when neither `stored()`
nor doc values are available, and columnar mode disables the `_ignored_source`
fallback and forbids `synthetic_source_keep`, so the index template is rejected
(`IndexMode.LOGSDB_COLUMNAR#validateMapping`).

**Remediation.** Keep the existing `doc_values: false` and add the mode-scoped
override beside it:

```yaml
- name: doppel.darkweb.cred_leaks_password
  type: keyword
  doc_values: false     # unchanged: still applies on logsdb and standard
  columnar:
    doc_values: true    # applied by Fleet only when the mode is columnar
```

Under columnar mode the field is stored as doc values anyway and there is no
inverted index to pay for, so the original "save space by not indexing"
motivation is gone *there* — but it is not gone on logsdb and standard, which is
why the override is scoped rather than unconditional. Same package version, same
mapping as today everywhere except columnar. Needs `format_version: "3.7.0"`.

Deleting the `doc_values: false` line also unblocks columnar, and it is the right
call if the attribute was never justified in the first place. It is the bigger
change: it turns doc values on in every index mode, for every install of the new
version. Prefer the scoped form unless you have decided you want that.

**Two placements where the scoped form is not available.** Fleet only applies
`columnar` overrides to static leaf fields, and package-spec 3.7.0 rejects the
block anywhere else (A2e):

- **`object_type` dynamic-template fields** (`type: object` with
  `object_type: keyword`, and friends). Fleet renders these as a
  `dynamic_templates` entry and never applies a `columnar:` block to them. The
  only fix is to delete the `doc_values: false` itself, and it is mode-agnostic:
  logsdb and standard installs of the new version get doc values too, and those
  indices grow. If that cost is not acceptable, leave the field alone and keep
  the data stream on logsdb — that is a legitimate outcome.
- **`multi_fields:` entries.** Nothing to fix: multi-fields are exempt from the
  reconstructability check to begin with (see the rule above), so a
  `doc_values: false` there is not a blocker and the audit does not report one.
  Do not add a `columnar:` block to "fix" it.

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
`external: ecs`. The **ECS schema** defines `event.original` with
`index: false, doc_values: false`, so:

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

**Remediation.** Override it locally with the mode-scoped block — package
attributes win over imported ones, because elastic-package merges with
`transformed.DeepUpdate(def)` (`internal/fields/dependency_manager.go`). Paste
the whole entry into the data stream's ECS fields file
(`data_stream/<ds>/fields/ecs.yml`, or wherever the package declares its
`external: ecs` references):

```yaml
- name: event.original
  external: ecs
  columnar:
    doc_values: true
```

Nothing else about the entry changes: ECS's own `doc_values: false` still lands
in the built package and still applies on logsdb and standard, where
`event.original` is a large raw blob that genuinely should not carry doc values
and where `_source` makes them unnecessary. Only a columnar install gets the
override. A plain `doc_values: true` would work too, but it would add doc values
for `event.original` — often the single largest field in the document — to every
logsdb install of the new version, in exchange for nothing. Needs
`format_version: "3.7.0"`.

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

#### The dynamic path is *not* a blocker — packages that never declare the field

`doc_values: false` is an attribute of the **ECS schema**, and a package only imports
that schema where it writes `external: ecs`. It is **not** an attribute of
`event.original` as such, and that distinction decides whether a package has the
blocker at all.

A package that never declares `event.original` — `rabbitmq`, `apache`, `nginx`, and
most `logfile`/`filestream` packages — puts no mapping for it in its index template at
all. The field is mapped at index time by the stack's `ecs@mappings` component
template, whose `ecs_non_indexed_keyword` dynamic template matches `*event.original`
and `*gen_ai.agent.description` and sets:

```json
{ "ecs_non_indexed_keyword": {
    "mapping": { "type": "keyword", "index": false },
    "path_match": ["*event.original", "*gen_ai.agent.description"] } }
```

`index: false` **only** — no `doc_values: false` (`ecs@mappings.json` in
`x-pack/plugin/core/template-resources`, verified on 9.6.0-SNAPSHOT). Its sibling
`ecs_non_indexed_long` does the same for `*.x509.public_key_exponent`, so the whole
`doc_values: false` list above behaves this way on the dynamic path. Doc values are
on, so columnar accepts the mapping and reconstructs the field from them.

An ingest pipeline that merely *populates* `event.original` — the `rename` + `remove`
pattern in half the log packages — is therefore columnar-clean and is **not** a
finding. The audit requires `external: ecs` on the field before it raises
`doc_values_false_ecs`, for exactly this reason.

So the blocker exists in exactly two situations:

1. the package declares the field with `external: ecs` (this section), or
2. the package writes `doc_values: false` on it itself (A2).

Nothing else about `event.original` — populating it, renaming into it, reading it back
— is a columnar problem.

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

### A2d. `columnar: {doc_values: false}` — `columnar_doc_values_false`

**Rule.** The field-level `columnar:` block sets `doc_values: false`.

Invalid. The mode-scoped block exists only to turn attributes back **on** for
columnar modes; `doc_values: false` scoped to columnar is the one combination
that can never make sense, because columnar mode has no `_source` to fall back on
and cannot reconstruct the field at all. package-spec 3.7.0 allows `true` only,
so the package fails spec validation before Elasticsearch ever sees it.

**Remediation.** Set `columnar.doc_values: true`, or delete the `columnar:`
block. Deliberately **not** classified as an auto-fix: someone wrote `false` on
purpose and the audit cannot tell whether they meant "this field must not have
doc values" (in which case the stream is not a columnar candidate at all) or
simply inverted the flag. Ask.

A wrong *value* is this finding; a `columnar:` block in a place Fleet will never
look at is A2e.

**Known in catalog:** none.

### A2e. `columnar:` where Fleet will not apply it — `columnar_override_misplaced`

**Rule.** A field-level `columnar:` block on a field that declares `object_type`,
or on a field inside `multi_fields:`.

Fleet applies `columnar` overrides only to **static leaf fields**, the ones it
turns into a named mapping. It skips a field it renders as a `dynamic_templates`
entry (`type: object`/`group` with an `object_type`) and it skips everything
under `multi_fields:`. package-spec 3.7.0 refuses the block in both places, so
this does not even reach Fleet: the package fails validation first.

The finding therefore means one of two things, and they need different answers:

- the block was written to repair a `doc_values: false` on an **`object_type`**
  field — the repair is not possible in scoped form; delete the
  `doc_values: false` instead and accept that it applies in every index mode
  (A2);
- the block was written to repair a `doc_values: false` on a **multi-field** —
  there was nothing to repair; multi-fields are exempt from the
  reconstructability check.

**Remediation.** Delete the `columnar:` block. Deliberately **not** an auto-fix:
deleting it may re-expose the blocker it was meant to hide, so decide what the
field should actually do first.

**Known in catalog:** none — no package uses a field-level `columnar:` block yet.

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

**Remediation.** Do the copy in the data stream's ingest pipeline, then delete
`copy_to` from the field (in every index mode), or drop the target field if nothing
queries it. The report prints the processor as a **Suggested change**: a `script`
tagged `columnar_copy_<field>` that appends the field's values to every target, the
way `copy_to` does — creating parent objects, keeping arrays and types, never
overwriting (verified with `_ingest/pipeline/_simulate` on 9.6). A plain `set` with
`copy_from` is enough only when the field is the target's single source:

```yaml
# data_stream/<ds>/elasticsearch/ingest_pipeline/default.yml
- set:
    tag: columnar_copy_my_source
    field: my.combined
    copy_from: my.source
    ignore_empty_value: true
```

Place it after the processors that set the source and before any that read the
target, then regenerate the pipeline test expectations with `-g`: the targets now
appear in the documents.

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

**Remediation.** The report prints the multi-field version as a **Suggested change**
(mapping-only, the documents do not change):

- move the normalized variant into `multi_fields:` — `field` stays raw and
  `field.caseless` (or `.normalized`) carries the normalizer; or
- apply the transformation in the ingest pipeline and map a plain `keyword`, when the
  original value is not needed.

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
  field is queried often). The report prints a skeleton tagged
  `columnar_compute_<field>` with the runtime script quoted in it; porting it is manual
  (`ctx` instead of `doc[...]`, an assignment instead of `emit()`). A plain
  `runtime: true` without a script needs no pipeline change: delete it and keep the
  type. Or
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
5. `type: flattened` for an object whose keys are open-ended (a raw request or
   response body): every key is kept as a keyword leaf, with no mapping explosion.

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

The first lever a package owner controls is **index sorting** — see
[`sorting.md`](sorting.md): a field in the sort key needs no index. The second is a
per-stream decision on which fields, if any, keep an inverted index (C5). "None" is a
valid answer, and the audit never writes one itself: it lists **lookup candidates**,
the `keyword`/`ip` fields the stream's shipped rules and dashboard filters reference
outside the sort key, flagging the high-risk lookup fields from the mapping plan
(`trace.id`, `source.ip`, `user.name`, hashes, …).

Elasticsearch is closing the gap independently (keyword skippers, then bloom filters;
see **Current status** in `SKILL.md` for where they stand).

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

### C5. `columnar: {index: true}` — `columnar_index_true`

**Rule.** A field whose mode-scoped `columnar:` block sets `index: true`, keeping
an inverted index for that one field under columnar modes.

**A per-stream human decision.** The rollout strategy asks, for each data stream
made columnar-ready, which fields (if any) keep an inverted index, decided from the
queries its dashboards and detection rules run. The audit reports an existing override
as an informational finding and lists lookup candidates per stream; it never writes
one. A human adds one when a named query filters on the field by exact value and the
field is not in the sort key, and records that query in the PR.

**Which spelling.** Prefer the mode-scoped `columnar: {index: true}`: explicit, and a
no-op on logsdb and standard installs. (A plain `index: true` is emitted by Fleet as
is and is also the logsdb default for keyword fields, so it works too; which one the
catalog standardizes on is an open team decision.) `index` is not valid on `wildcard`
fields.

**What to do when you find one.** Look for the query it serves. If there is one,
keep it and carry the reference forward. If there is not, remove it and reach for
index sorting instead ([`sorting.md`](sorting.md)).

**Known in catalog:** none.

---

## C6-C10: columnar `_source` consumers

Columnar `_source` **is not a faithful representation of the original source**. It
is reconstructed from doc values, and:

- **nested objects are flattened to dotted keys** — the document comes back as
  `{"event.id": "...", "anthropic.audit.actor.type": "user_actor"}` where logsdb
  returns `{"event": {"id": "..."}}`. Any consumer doing nested access on the source
  (`_source.event.id`, Painless `params._source.event.id`, an ES|QL
  `JSON_EXTRACT(_source, "event.id")`-style path, Kibana code walking the object)
  breaks; field-level access — `doc[...]`, KQL, aggregations, ES|QL columns — is
  unaffected. `geo_point` values are the exception that stays an object: they still
  come back as `{lat, lon}`;
- **single-element arrays collapse to scalars** — `event.category: ["web"]` reads
  back as `"web"`. logsdb keeps the array because it defaults
  `index.mapping.synthetic_source_keep: arrays`, a setting columnar does not support.
  A consumer that indexes into the array (`event.category[0]`) or asserts a list type
  has to tolerate a scalar. Observed on `event.category`, `event.type`, `related.ip`,
  `related.hosts` and `anthropic.audit.scopes` in the same document set;
- **object arrays under a non-`nested` object become parallel arrays** —
  `[{a:1,b:2},{a:3,b:4}]` reads back as `{a:[1,3], b:[2,4]}`. The association
  between one element's leaves is gone;
- **multi-value order is preserved** (unlike plain logsdb synthetic source, which
  sorts and de-duplicates).

**Those four are the complete set of expected differences.** They were measured on
`anthropic`, system-testing the same mock data twice — once on logsdb, once with a
temporary `index_mode: logsdb_columnar` — and matching the 8 resulting documents on
`event.id`: **zero value differences**, only shape. Anything else you see in such a
diff — a changed value, a dropped field that is explicitly mapped, numeric precision
loss, `null`/empty-string confusion — is a bug, not a columnar effect. The procedure
is in
[`correctness-and-performance.md`](correctness-and-performance.md#comparing-the-two-modes).

**The ES|QL exception.** Experiences that use ES|QL are **mostly unaffected**: ES|QL
reads doc values, not `_source`. The exception is a query that explicitly requests
`METADATA _source` — and those normally go on to pick the document apart with
`JSON_EXTRACT(_source, "...")`, which is exactly where the flattened shape shows up.

**Ingest pipelines on the data stream are NOT affected.** They run *before* indexing,
on the real document. The exception is the destination pipeline of a `latest`
transform, which runs on the rebuilt `_source` the transform copies (C10).

So a data stream should not be declared `elasticsearch.columnar.supported: true`
until this review is done. It is a per-integration question about *consumers*, which
no mapping check can answer.

### Reading a negative result

The audit prints the C6-C10 outcome for every data stream **including when it is
empty** — "`_source` consumers: none found (no transform script reading `_source`, no
`latest` transform, no scripted/runtime fields or ES|QL `METADATA _source` in
`kibana/`, no shipped detection rule reading `_source`); object arrays: none in the
sampled documents". Silence would be ambiguous: an absent Class C section looks
identical to a check that never ran. When the detection rules could not be scanned,
the line says so.

Fields of type `flattened` that *do* hold an object array in the sampled documents are
listed on that same line as exempt (they keep their JSON verbatim under columnar, so
the parallel-array reshaping does not apply to them) — `anthropic.audit.updates` is
one. Naming them is the difference between "checked, exempt" and "not looked at".

**Detection rules are scanned automatically** (C9): the prebuilt rules ship in this
repo as `packages/security_detection_engine/kibana/security_rule/*.json`. Rules a user
wrote, or installed from elsewhere, are not covered.

### C6. Transform reads `_source` — `source_consumer_transform`

**Rule.** Any `elasticsearch/transform/<name>/transform.yml` in the package whose
scripts reference `_source` — a `scripted_metric` script, a `bucket_script`, or a
runtime field under `source.runtime_mappings`. Severity `review`, so the stream
becomes NEEDS_REVIEW.

**Why.** A transform runs at **query time** against the source Elasticsearch
reconstructs. On a columnar index that is the flattened shape, not the document the
ingest pipeline produced, so a `params._source.a.b` walk can return something else —
or nothing.

**Which data streams it is attached to.** The transform's `source.index` patterns
are resolved against this package's data streams (`logs-<pkg>.<ds>-*`). A transform
reading another package's indices — `beaconing` reads `logs-endpoint.events.network-*`
— is attached to every logs stream of its own package, because that is where the fix
would be discussed.

**Remediation.** Read doc values (`doc['field']`) or the aggregated fields instead of
`_source`; or verify against a real columnar index that the destination documents are
unchanged.

**Known in catalog:** none. All 67 packages with transforms use `doc[...]`. Three of
them contain the letters `_source` in an identifier — `low_source_bytes_variation`
and `mean_source_bytes` (`beaconing`), `avg_source_bytes` (`ded`),
`labels.is_ioc_transform_source` (`ti_rapid7_threat_command`) — and are **not** hits;
the detector matches `_source` as a token, never as a substring.

### C7. Kibana asset reads `_source` — `source_consumer_kibana`

**Rule.** A saved object under `kibana/` that consumes the document source:
`params._source` / `ctx._source` in a script, a scripted field (`scriptedFields`,
`"scripted": true`), a runtime field (`runtimeFieldMap`, `runtime_mappings`) whose
script reads `_source`, or an ES|QL query with `METADATA _source` (usually together
with `JSON_EXTRACT(_source, ...)`). Severity `review`. The finding names the asset
file and the expression.

**`doc[...]` is deliberately not a hit.** A runtime field that only reads doc values
behaves identically under columnar — doc values are precisely what columnar keeps.
The three ml-module assets in this catalog that define `runtime_mappings` (`dga`,
`lmd`, `problemchild`) are all of that kind and are not reported. Reporting them
would be noise, not signal.

**Remediation.** Move the expression onto doc values or onto the mapped fields; or
check it against a columnar index.

**Known in catalog:** none in the integrations' own `kibana/` assets. Detection
rules are a separate consumer class, see C9.

### C8. Object arrays in the documents — `object_array_flattening`

**Rule.** An object/`group` field — not `nested`, not `flattened` — whose value is an
array of objects in `sample_event.json` or in a `_dev/test/pipeline/*-expected.json`
document. Severity `info`: it never changes a status.

**Why it is only informational.** Dashboards, alerting rules and ES|QL that query the
**leaf fields** are unaffected — the leaves are all still there, with their order
intact. What changes is the shape a `_source` reader sees: a runtime field on
`params._source`, Kibana code walking the object, an ES|QL `METADATA _source` query,
or a person reading the JSON in Discover.

Mapping the field as `nested` does **not** restore the shape (see A1/C2); it only
restores per-element query semantics.

**Known in catalog:** 226 logs data streams in 119 packages. Security packages
dominate — `crowdstrike/alert` (7 fields, e.g. `crowdstrike.alert.ioc_context`,
`crowdstrike.alert.quarantined_files`), `okta/system` (`okta.target`), `o365/audit`
(`o365.audit.Actor`, `o365.audit.Target`), `aws/securityhub_findings` — but so do
plain ECS arrays such as `dns.answers` (`aws/route53_resolver_logs`).

### C9. Shipped detection rule reads `_source` — `source_consumer_detection_rule`

**Rule.** A prebuilt rule in `packages/security_detection_engine/kibana/security_rule/`
(latest version of each `rule_id`) whose index patterns match the stream — `index`,
the ES|QL `FROM` clause, or an indicator match rule's `threat_index` — and whose query
reads `_source`: `METADATA _source`, `JSON_EXTRACT(_source, …)`, `params._source`.
Severity `review`.

**Why.** Columnar returns `_source` with dotted top-level keys, so
`JSON_EXTRACT(_source, "a.b")` looks for an `a` object, finds none, and returns null.
Rules filter on the extracted value, so they stop matching, with no error. Nothing
fails at install either: this is silent detection loss.

**Remediation.** Hold the stream back from the tech preview until the rule is fixed
in `elastic/detection-rules` (the rules are generated there):

- Reference the mapped fields as columns instead of `_source`. Cast with `TO_STRING`
  where the index patterns disagree on a type.
- Add `SET unmapped_fields = "nullify";` when a field may be missing from one of the
  patterns (the usual reason the rule reached for `JSON_EXTRACT`).
- Values inside a `flattened` field cannot be read as ES|QL columns (`LOAD` does not
  support flattened subfields either): promote the value to its own field in the
  ingest pipeline, or wait for elasticsearch#160300, a `JSON_EXTRACT` that resolves
  dotted keys.

The same scan feeds the **Detection rules** line of each stream: how many rules query
it directly (by language), how many reach it through broad patterns such as `logs-*`,
and how many read `_source`. The direct ones are the rule half of the performance
workload; EQL and KQL run as Query DSL.

**Known in catalog:** 4 rules on 3 streams — "Potential SIP Extension Enumeration" and
"Potential SIP REGISTER Brute Force" (`network_traffic/sip`), "Potential NFS
Destructive Operation Burst" (`network_traffic/nfs`), "GKE Certificate Signing
Request for Privileged Identity" (`gcp/audit`, reads the `flattened`
`gcp.audit.request`). The network_traffic package maps every field those rules
extract, so the SIP and NFS ones only need the column rewrite.

### C10. `latest` transform over the stream — `source_consumer_latest_transform`

**Rule.** A transform with a `latest:` section whose `source.index` patterns match the
stream, **whichever package owns it**. Severity `review`. Unlike C6, no script is
needed: a `latest` transform copies the newest document's whole `_source` (per
`unique_key`) into its destination index.

**Cross-package transforms.** The audit reads every package's `latest` transforms,
because the stream whose opt-in changes a transform's output can belong to another
package. Such a finding names the owning package, points at its files, and says the
fix belongs there. The owner's report lists its transforms that read none of its own
streams, with the streams they are flagged on, or says they read no in-scope logs
stream in this repo (metrics streams, `.alerts-security.alerts-*`). The catalog has no
cross-package case today.

**Why.** On a columnar source that `_source` is the rebuilt, flat one:

- the destination documents get dotted keys, parallel arrays in place of object
  arrays, and plain values in place of single-element arrays — permanently, because
  the destination is a normal index that stores what it is given;
- a destination pipeline addresses fields by path, so its processors do not find the
  dotted keys: `rename`/`set`/`remove` with `ignore_missing` skip silently, and
  scripts see `ctx.<object>` as null. The finding says whether the pipeline already
  expands dotted keys.

**Remediation.**

1. Start the destination pipeline with a `dot_expander` using `field: "*"` (a no-op
   on logsdb input), or set `field_access_pattern: flexible` on it. The report prints
   the processor as a **Suggested change** for each destination pipeline file that
   does not expand dotted keys yet:

   ```yaml
   processors:
     - dot_expander:
         tag: columnar_expand_dotted_keys
         field: "*"
   ```

   Verified with `_ingest/pipeline/_simulate` on 9.6 against CrowdStrike's
   `aidmaster_lookup_namespaced` pipeline: today a flat (columnar-shaped) document
   comes out with its renames skipped; with the processor, the flat and the nested
   document give the same output, and the nested output does not change.

2. Check that no consumer of the destination index depends on object-array pairing,
   or reads its `_source` (indicator match rules read threat intel indices).
3. Run the transform on the stream in both modes and diff the destination documents.
   `elastic-package test pipeline` only covers data stream pipelines, so test a
   package-level destination pipeline with `_ingest/pipeline/_simulate`: send one
   document nested and once with dotted keys; the outputs must match.

Pivot transforms are unaffected: they aggregate from doc values.

**Known in catalog:** 146 `latest` transforms in 61 packages, flagging 141 in-scope
logs streams (every `ti_*` package, `crowdstrike/fdr`, `cloud_security_posture`, …).
CrowdStrike's `latest_aidmaster` and `latest_userinfo` destination pipelines rename
`crowdstrike` and `host.*` under `crowdstrike.info.host.*`, which silently does
nothing on dotted keys.
