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
2. **Never recommend or generate `index: true` overrides for keyword fields.** The
   premise of the rollout is that columnar does not need inverted indexes; only `text`
   fields keep one. Per-field indexing is decided later from benchmarks, never from
   static analysis.
3. **Index sorting is the per-integration lever**, not indexing.
4. **Opt in per data stream.** A package can be mixed: migrate the ready streams and
   leave the rest alone.

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
  (unless it is a multi-field); `store: true`; `copy_to`; `keyword` + a
  non-`lowercase` `normalizer`; mapping-level runtime fields and `dynamic: runtime`;
  stored-`_source` overrides; types with no doc values.
- **Class B, accepted but lossy:** `dynamic: false`; `enabled: false`. With no stored
  `_source` the unmapped data is gone for good, not merely unsearchable. Always a
  human decision.
- **Class C, informational:** no inverted index on non-`text` fields; flattened
  synthetic-source shape; dynamic fields become non-indexed doc values;
  `normalizer: lowercase` returns the lowercased value from synthetic source.

**`store: true` is not an escape hatch.** Elasticsearch rejects `store` outright in
columnar modes (`[store] cannot be enabled on field [...] in [logsdb_columnar] index
mode`, `FieldMapper.Builder#storeParam`). The only mechanical fix for
`doc_values: false` is `doc_values: true`.

**The trap worth knowing about:** `external: ecs` imports `doc_values` from the ECS
schema at build time, and ECS defines `event.original` with `doc_values: false`. Around
50 packages therefore carry a Class A blocker that is invisible in their source and
only appears after `elastic-package build`. The audit detects it as
`doc_values_false_ecs`; the fix is to add `doc_values: true` next to the
`external: ecs` reference. See
[references/blockers.md](references/blockers.md), section A2b.

### 3. Decide the index sort

The audit proposes one per data stream. Confirm it before writing it — the proposal is
static analysis, and the person who knows the dataset should sanity-check the
cardinality.

The call is made from the **input types alone**:

- `host.name asc, @timestamp desc` (the default) is right when the agent runs on the
  machine that produced the log: `logfile`, `filestream`, `journald`, `winlog`, `etw`,
  `system/*`, container inputs, syslog/tcp/udp receivers. Note that Elastic Agent's
  `add_host_metadata` populates `host.name` on every event regardless of the package's
  `fields/*.yml`, and Elasticsearch injects the mapping when the template has none —
  so "`host.name` is not in the field definitions" is **not** evidence against the
  default.
- It is wrong for API pollers (`httpjson`, `cel`, `aws-s3`, `gcp-pubsub`,
  `azure-eventhub`, `o365audit`, …) where `host.name` is the collector. Propose an
  explicit sort on the dataset's dominant grouping field — a tenant/account/org id
  first, then `agent.id`/`observer.name`, then whatever the dashboards **filter** on
  most.
- The only mapping fact that matters is a *downgrade*: if the package maps `host.name`
  as something other than a keyword/number with doc values, Elasticsearch falls back
  to `@timestamp` only.

A weak candidate is worse than none. If no field survives validation — single-valued,
`keyword`/`ip`/integer, doc values, not constant — the audit says
`no confident candidate; needs human choice` rather than inventing a sort key.

Constraints, candidate ranking and the YAML to write:
**[references/sorting.md](references/sorting.md)**.

### 4. Migrate a package (only when asked to)

For each data stream whose status is `READY` (or `READY_AFTER_AUTO_FIX` once you have
applied the fix):

1. Apply the mechanical fixes: `copy_to` → `set`/`append` in the ingest pipeline; a
   non-`lowercase` `normalizer` → ingest processor or a multi-field; `store: true` →
   delete it; `doc_values: false` → delete it, or, for an `external: ecs` field, add
   `doc_values: true`.
2. `data_stream/<ds>/manifest.yml`:
   ```yaml
   elasticsearch:
     index_mode: logsdb_columnar
   ```
   plus the explicit `index.sort` settings if you proposed any. Leave non-ready
   streams untouched.
3. Root `manifest.yml`: `format_version: "3.7.0"`,
   `conditions.kibana.version: "^9.5.0"`, and a minor version bump.
4. `changelog.yml` — a new entry at the top, type `enhancement`, with a placeholder
   link the user must replace:
   ```yaml
   - version: "<new version>"
     changes:
       - description: Enable logsdb_columnar index mode for <data streams>
         type: enhancement
         link: https://github.com/elastic/integrations/pull/XXXXX
   ```
5. `elastic-package build` to regenerate `docs/README.md` (never edit it directly —
   edit `_dev/build/docs/README.md`).
6. `elastic-package lint` **and** `elastic-package build` — `build` is the only one
   that sees the resolved ECS attributes. Add `validation.yml` exclusions **only** for
   pre-existing failures that the `format_version` bump surfaced, each with a comment.
   **Never** exclude a columnar validator error (`SVR00011`, `SVR00012`, `SVR00013`);
   the hard mapping errors have no code and cannot be excluded at all.

Tell the user that `index_mode: logsdb_columnar` requires package-spec 3.7.0, which is
unreleased (`3.7.0-next`), so a stock `elastic-package` binary will reject the manifest
locally. [references/correctness-and-performance.md](references/correctness-and-performance.md)
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
the index mode cannot influence their output. Their result must be **identical** in
both modes; a diff there is a real bug, never an expected columnar effect, and `-g`
should never be needed for this migration.

## Where things live in a package

| Path | Relevance |
| --- | --- |
| `manifest.yml` | `format_version`, `version`, `type`, `conditions.kibana.version` |
| `data_stream/<ds>/manifest.yml` | `type`, `elasticsearch.index_mode`, `elasticsearch.source_mode`, `index_template.settings` (index sort), `index_template.mappings` (`dynamic`, `dynamic_templates`, `_source`) |
| `data_stream/<ds>/fields/*.yml` | field definitions; nesting via `fields:`, multi-fields via `multi_fields:`, ECS imports via `external: ecs` |
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
