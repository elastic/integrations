---
name: columnar-readiness
description: Audits and migrates Elastic integration packages to the logsdb_columnar Elasticsearch index mode. Use for "columnar readiness", "logsdb_columnar", "migrate to columnar", "columnar audit", "index sorting for columnar", "is this package columnar-ready", "columnar blockers", or when asked which integrations can adopt columnar index mode, why a package is blocked, or what index sort a data stream should use.
---

# Columnar readiness

Decide whether an integration's **logs** data streams can move to
`logsdb_columnar`, fix what is mechanically fixable, propose an index sort key, and
plumb the opt-in through the package.

## What logsdb_columnar is

Tech-preview index mode in Elasticsearch 9.5, GA targeted for 9.7. It stores every
field once as doc values, drops inverted indexes and BKD trees for all non-`text`
fields by default, and relies on index sorting plus doc-value skippers for query
pruning. It **never stores the original JSON `_source`** — it reconstructs a flattened
synthetic source from doc values.

`logsdb_columnar` = base `columnar` mode + the logs profile: default index sort
`host.name asc, @timestamp desc` (it adds a `host.name` mapping if absent; if an
existing `host.name` mapping is incompatible with sorting it falls back to
`@timestamp` only), plus `ignore_malformed` and `ignore_above` defaults.

## Rollout rules — follow these, they are decisions, not preferences

1. **Logs data streams only.** `type: logs` in `data_stream/<ds>/manifest.yml`.
   Metrics, traces and synthetics are out of scope. `type: input` packages are out of
   scope — report and skip.
2. **Never recommend or generate inverted-index overrides for keyword fields** —
   neither the plain `index: true` attribute nor the mode-scoped
   `columnar: {index: true}` block. The premise of the rollout is that columnar does
   not need inverted indexes; only `text` fields keep one. Per-field indexing is
   decided later from benchmarks, never from static analysis. If an existing package
   already has one, report it and ask for the benchmark — never add one.
3. **Index sorting is the per-integration lever**, not indexing.
4. **Opt in per data stream.** A package can be mixed: migrate the ready streams and
   leave the rest alone.

## The two things you write into a package (package-spec 3.7.0)

Both are new in `format_version: "3.7.0"`. Everything below — remediations and the
migration plumbing — uses them, so learn them first.

**1. The field-level, mode-scoped `columnar:` block.** Fleet applies what is inside
it *only* when the resolved index mode of the data stream is `logsdb_columnar` or
`columnar`, the same way it only emits TSDB's `dimension: true` for `time_series`:

```yaml
- name: event.original
  external: ecs
  columnar:
    doc_values: true    # the only valid value
```

Use it for every `doc_values: false` remediation. A bare `doc_values: true` fixes
columnar but also adds doc values to every logsdb and standard install of the new
package version — installs that still have `_source` and gain nothing from it. The
scoped form leaves their mapping byte for byte what it is today, so the fix is free
off-columnar. The block also accepts `index`, which this skill never writes; see
rollout rule 2 and `references/blockers.md` C5.

**2. The stream-level readiness flag**, in `data_stream/<ds>/manifest.yml`:

```yaml
elasticsearch:
  columnar:
    supported: true
```

It asserts the stream is columnar-ready; the 3.7.0 validator rejects it if any
blocker remains. It is **not** the same as setting a columnar `index_mode`:

| Declaration | Effect |
| --- | --- |
| `elasticsearch.columnar.supported: true` | Fleet offers the per-stream columnar opt-in toggle. logsdb stays the default; nothing changes until a user turns it on. |
| `elasticsearch.index_mode: logsdb_columnar` | Columnar becomes the **default** for new installs of this package version. |

**For the tech-preview wave, write `supported: true` and leave `index_mode` unset** —
the rollout strategy is that users opt in.

## Workflow

### 1. Audit

```bash
# one package
.claude/skills/columnar-readiness/scripts/audit.py packages/<pkg>

# whole catalog (~30 s over ~490 packages)
.claude/skills/columnar-readiness/scripts/audit.py packages/ --catalog

# machine-readable
.claude/skills/columnar-readiness/scripts/audit.py packages/<pkg> --format json
```

Needs PyYAML. If `python3 -c "import yaml"` fails:

```bash
python3 -m pip install --user pyyaml
# or, without touching the system interpreter:
python3 -m venv /tmp/columnar-venv && /tmp/columnar-venv/bin/pip install pyyaml
/tmp/columnar-venv/bin/python3 .claude/skills/columnar-readiness/scripts/audit.py packages/<pkg>
```

The script is deterministic and static: it reads the root manifest, every
`data_stream/*/manifest.yml`, every `data_stream/*/fields/*.yml`, `sample_event.json`
and the `kibana/` assets. It never runs Elasticsearch.

### 2. Read the findings

Statuses, per data stream: `READY`, `READY_AFTER_AUTO_FIX`, `NEEDS_REVIEW`,
`BLOCKED`, `OUT_OF_SCOPE`. Package status is the worst of its streams.
Full definitions and report shape: **[references/report-template.md](references/report-template.md)**.

The full catalog of blockers — detection rule, why Elasticsearch rejects it, and the
remediation for each — is in **[references/blockers.md](references/blockers.md)**.
Short version:

- **Class A, rejected by Elasticsearch:** `nested` in `nested`; `doc_values: false`
  (unless it is a multi-field, or a `columnar: {doc_values: true}` override already
  resolves it); `store: true`; `copy_to`; `keyword` + a non-`lowercase` `normalizer`;
  mapping-level runtime fields and `dynamic: runtime`; stored-`_source` overrides;
  types with no doc values; an invalid `columnar: {doc_values: false}`.
- **Class B, accepted but lossy:** `dynamic: false`; `enabled: false`. With no stored
  `_source` the unmapped data is gone for good, not merely unsearchable. Always a
  human decision.
- **Class C, informational:** no inverted index on non-`text` fields; flattened
  synthetic-source shape; dynamic fields become non-indexed doc values;
  `normalizer: lowercase` returns the lowercased value from synthetic source; an
  existing `columnar: {index: true}` override, which is reported so its benchmark
  evidence can be confirmed and is never proposed.

**`store: true` is not an escape hatch.** Elasticsearch rejects `store` outright in
columnar modes (`[store] cannot be enabled on field [...] in [logsdb_columnar] index
mode`, `FieldMapper.Builder#storeParam`). The only mechanical fix for
`doc_values: false` is doc values on — preferably scoped to columnar with
`columnar: {doc_values: true}`.

**The trap worth knowing about:** `external: ecs` imports `doc_values` from the ECS
schema at build time, and ECS defines `event.original` with `doc_values: false`. Around
50 packages therefore carry a Class A blocker that is invisible in their source and
only appears after `elastic-package build`. The audit detects it as
`doc_values_false_ecs`; the fix is to add a `columnar: {doc_values: true}` block next
to the `external: ecs` reference, so ECS's `doc_values: false` keeps applying on
logsdb and standard and only columnar installs get doc values on what is usually the
largest field in the document:

```yaml
# data_stream/<ds>/fields/ecs.yml
- name: event.original
  external: ecs
  columnar:
    doc_values: true
```

See [references/blockers.md](references/blockers.md), section A2b.

### 3. Decide the index sort

The audit proposes one per data stream. Confirm it before writing it — the proposal is
static analysis, and the person who knows the dataset should sanity-check the
cardinality.

The **input types** pick the regime, and the regime picks the evidence:

| Input class | Inputs | Regime |
| --- | --- | --- |
| host-local | `logfile`, `filestream`, `journald`, `winlog`, `etw`, `system/*`, `audit/*`, container inputs | the default `host.name asc, @timestamp desc` is right |
| receiver | `tcp`, `udp`, `syslog` | read the ingest pipeline |
| collector / poller | `httpjson`, `cel`, `aws-s3`, `gcp-pubsub`, `azure-eventhub`, `o365audit`, … | propose an explicit sort on the dataset's grouping dimension |

- **Host-local.** Elastic Agent's `add_host_metadata` populates `host.name` on every
  event regardless of the package's `fields/*.yml`, and Elasticsearch injects the
  mapping when the template has none — so "`host.name` is not in the field
  definitions" is **not** evidence against the default.
- **Receiver.** `tcp`/`udp`/`syslog` are *not* host-local: the agent is a syslog sink
  and `host.name` holds whatever the pipeline put there — the collector in
  `cisco_asa`, the *client* in `fortinet_fortigate`, nothing at all on most events in
  `checkpoint` and `panw`. The audit scans the stream's pipelines: if they populate
  `observer.name` / `observer.hostname` / `observer.serial_number`, that is the
  proposal; if they set `host.name` unconditionally from the header, the default is
  fine; otherwise it asks for a human choice.
- **Collector.** `host.name` is the collector. Propose an explicit sort on a
  tenant/account/org id first — declared in `fields/*.yml` **or** merely populated in
  `sample_event.json`, since ECS fields arrive via `ecs@mappings` and packages
  routinely leave them undeclared — then a vendor tenant id. `agent.id` is not
  proposed here: for a poller it is the collector, one value for the whole data
  stream. What the dashboards **filter** on is reported as a *hint* only
  (`review_candidate`), never as a proposal — two thirds of those picks are junk.
- **Mixed receiver + collector inputs** (`zscaler_zia/firewall`, `gigamon/ami`): the
  tenant tiers go first, then the pipeline's `observer.*` evidence, then the hint.
- The only mapping fact that matters is a *downgrade*: if the package maps `host.name`
  as something other than a keyword/number with doc values, Elasticsearch falls back
  to `@timestamp` only.

A weak candidate is worse than none. A field survives validation only if it is
single-valued — itself *and* every object it lives inside, checked against the sample
event, `nested`/`normalize: [array]` declarations and the objects the pipeline
iterates — has doc values, is `keyword`/`ip` or an integer whose **name** says it is
an identifier rather than a measurement, and is not constant. Otherwise the audit
says `no confident candidate; needs human choice` rather than inventing a sort key.

Constraints, candidate ranking and the YAML to write:
**[references/sorting.md](references/sorting.md)**.

### 4. Migrate a package (only when asked to)

For each data stream whose status is `READY` (or `READY_AFTER_AUTO_FIX` once you have
applied the fix):

1. Apply the mechanical fixes: `copy_to` → `set`/`append` in the ingest pipeline; a
   non-`lowercase` `normalizer` → ingest processor or a multi-field; `store: true` →
   delete it; `dynamic: runtime` → `dynamic: true`; and for `doc_values: false`,
   whether the package declares it or inherits it from `external: ecs`, add the
   mode-scoped override rather than flipping the attribute outright:
   ```yaml
   - name: event.original
     external: ecs
     columnar:
       doc_values: true
   ```
   ```yaml
   # a package-owned field: keep the existing attribute, scope the fix
   - name: doppel.darkweb.cred_leaks_password
     type: keyword
     doc_values: false
     columnar:
       doc_values: true
   ```
   Fleet applies the `columnar:` block only on a columnar install, so the logsdb and
   standard mappings of this same package version are unchanged and no existing user
   pays storage for a fix they cannot use. Never write `columnar: {index: true}`.
   The `copy_to` and `normalizer` fixes change what the ingest pipeline emits, so
   pipeline test expectations will have to be regenerated — see step 5.
2. `data_stream/<ds>/manifest.yml` — declare the stream ready:
   ```yaml
   elasticsearch:
     columnar:
       supported: true
   ```
   plus the explicit `index.sort` settings if you proposed any. Leave non-ready
   streams untouched: the flag is per data stream, and the 3.7.0 validator fails the
   build if you set it on a stream that still has a blocker.

   **Do not add `index_mode: logsdb_columnar` unless the user asks for it.**
   `supported: true` makes Fleet offer the per-stream opt-in toggle and leaves logsdb
   as the default; `index_mode: logsdb_columnar` makes columnar the default for new
   installs of this version and takes the choice away from the user. For the
   tech-preview wave the default is `supported: true` only, because the rollout
   strategy is that users opt in. When the user does ask for the default to flip,
   both go in together:
   ```yaml
   elasticsearch:
     index_mode: logsdb_columnar
     columnar:
       supported: true
   ```
3. Root `manifest.yml`: `format_version: "3.7.0"`,
   `conditions.kibana.version: "^9.5.0"`, and a minor version bump.
4. `changelog.yml` — a new entry at the top, type `enhancement`, with a placeholder
   link the user must replace:
   ```yaml
   - version: "<new version>"
     changes:
       - description: Declare logsdb_columnar support for <data streams>
         type: enhancement
         link: https://github.com/elastic/integrations/pull/XXXXX
   ```
   Say *declare support for* when you only set `columnar.supported: true`, and
   *enable ... index mode* when you also set `index_mode` — the two are different
   promises to the user reading the changelog.
5. `elastic-package build` to regenerate `docs/README.md` (never edit it directly —
   edit `_dev/build/docs/README.md`).
6. `elastic-package lint` **and** `elastic-package build` — `build` is the only one
   that sees the resolved ECS attributes, which is also the only place a
   `columnar: {doc_values: true}` override on an `external: ecs` field can be
   confirmed to have won the merge. Add `validation.yml` exclusions **only** for
   pre-existing failures that the `format_version` bump surfaced, each with a comment.
   **Never** exclude a columnar validator error (`SVR00011`, `SVR00012`, `SVR00013`);
   the hard mapping errors have no code and cannot be excluded at all.

Tell the user that both `elasticsearch.columnar.supported` and the field-level
`columnar:` block require package-spec 3.7.0, which is unreleased (`3.7.0-next`), so a
stock `elastic-package` binary will reject the manifest and the fields files locally.
[references/correctness-and-performance.md](references/correctness-and-performance.md)
explains how to build `elastic-package` against a local package-spec checkout.

### 5. Validate

Static lint and **build** → install against a 9.5+ stack and verify `index.mode` and
`index.sort.field` on the real index → run `elastic-package test pipeline` and
`test system` with and without the opt-in and diff → benchmark the dashboard workload
at scale. Which test diffs are expected and which are bugs, and the exact commands:
**[references/correctness-and-performance.md](references/correctness-and-performance.md)**.

`elastic-package lint` validates the package **source**, where an `external: ecs`
reference to `event.original` carries no `doc_values` at all — so the ECS blocker is
invisible to it. `elastic-package build` validates the **built zip**, where ECS has
already been resolved into `doc_values: false`, and that is where the blocker
surfaces. Every affected package will fail `build` once it opts in, independent of
which spec version it declares. Always run both.

Pipeline tests are run through `_ingest/pipeline/_simulate` — nothing is indexed, so
the index mode cannot influence their output. **If the only change is `index_mode`,
the results must be identical in both modes**; a diff there is a real bug, never an
expected columnar effect, and `-g` should never be needed.

That stops being true the moment an auto-fix touches the pipeline. Moving a `copy_to`
into a `set` processor, or replacing a non-`lowercase` normalizer with a `lowercase`
processor, changes what `_simulate` returns — by design. Then `*-expected.json` does
have to be regenerated with `-g`, and every hunk of the resulting diff has to be read
and justified: the only changes you should see are the fields the auto-fix moved or
normalised.

## Where things live in a package

| Path | Relevance |
| --- | --- |
| `manifest.yml` | `format_version`, `version`, `type`, `conditions.kibana.version` |
| `data_stream/<ds>/manifest.yml` | `type`, `elasticsearch.columnar.supported` (3.7.0 readiness flag), `elasticsearch.index_mode`, `elasticsearch.source_mode`, `index_template.settings` (index sort), `index_template.mappings` (`dynamic`, `dynamic_templates`, `_source`) |
| `data_stream/<ds>/fields/*.yml` | field definitions; nesting via `fields:`, multi-fields via `multi_fields:`, ECS imports via `external: ecs`, mode-scoped overrides via `columnar:` (3.7.0) |
| `data_stream/<ds>/elasticsearch/ingest_pipeline/*.yml` | where `copy_to`, normalizers and runtime scripts get re-implemented |
| `data_stream/<ds>/sample_event.json`, `_dev/test/pipeline/*`, `_dev/test/system/*` | evidence for which fields are actually populated |
| `kibana/dashboard\|lens\|search\|ml_module/*.json` | dominant slicing fields → sort key and benchmark workload |
| `changelog.yml`, `_dev/build/docs/README.md`, `validation.yml` | release plumbing |

## Reporting back

Lead with the status and the one-line reason. Name the specific field and file for
every finding — "`o365.audit.ExchangeAggregatedFolders.FolderItems` is `nested` inside
`nested` (`data_stream/audit/fields/fields.yml`)", not "has nested fields". For a
catalog run, give the counts per status and the package list per blocker code, and
call out anything that changed since the last run.
