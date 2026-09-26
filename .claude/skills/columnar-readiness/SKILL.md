---
name: columnar-readiness
description: Audits and migrates Elastic integration packages to the logsdb_columnar Elasticsearch index mode. Use for "columnar readiness", "logsdb_columnar", "migrate to columnar", "columnar audit", "index sorting for columnar", "is this package columnar-ready", "columnar blockers", or when asked which integrations can adopt columnar index mode, why a package is blocked, what index sort a data stream should use, or what columnar `_source` does to transforms, runtime fields and other `_source` consumers.
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

**Static leaf fields only.** Fleet applies the block when it builds a concrete
mapping, so it does *not* apply it to a field it renders as a `dynamic_templates`
entry (`type: object`/`group` with an `object_type`) or to anything inside
`multi_fields:` — and package-spec 3.7.0 rejects the block in both places, so the
package will not build. There is no scoped fix on those two placements: an
`object_type` field's `doc_values: false` has to be deleted outright, in every index
mode, and a multi-field needs no fix at all. The audit reports a misplaced block as
`columnar_override_misplaced` (`references/blockers.md` A2e).

**2. The stream-level readiness flag**, in `data_stream/<ds>/manifest.yml`:

```yaml
elasticsearch:
  columnar:
    supported: true
```

A data stream manifest has **one** `elasticsearch:` key, and the index sort lives
under the same one. Write them as a single block and merge that block into whatever
`elasticsearch:` the manifest already has — two pasted `elasticsearch:` snippets are a
duplicate key, and the file silently keeps only one of them. The merged shape is in
step 4.2 of the migration, and the audit emits it that way.

It asserts the stream is columnar-ready; the 3.7.0 validator rejects it if any
blocker remains. It is **not** the same as setting a columnar `index_mode`:

| Declaration | Effect |
| --- | --- |
| `elasticsearch.columnar.supported: true` | Fleet offers the per-stream columnar opt-in toggle. logsdb stays the default; nothing changes until a user turns it on. |
| `elasticsearch.index_mode: logsdb_columnar` | Columnar becomes the **default** for new installs of this package version. |

**For the tech-preview wave, write `supported: true` and leave `index_mode` unset** —
the rollout strategy is that users opt in.

Both constructs need `format_version: "3.7.0"` in the root manifest, and because both
are read by **Fleet** they also need `conditions.kibana.version: "^9.6.0"` — the Fleet
support ships in 9.6. **That is the expensive part of the decision**: it raises the
package's minimum stack version to 9.6, so users on an older stack stop receiving this
package's updates and a bug fix for them needs a backport. See step 3 of the
migration.

## Workflow

### 1. Audit

```bash
# one package — `kibana/` assets are scanned by default
.claude/skills/columnar-readiness/scripts/audit.py packages/<pkg>

# one package, dashboards spelled out (same thing), or skipped on a package that
# ships hundreds of saved objects and whose sort you have already decided
.claude/skills/columnar-readiness/scripts/audit.py packages/<pkg> --dashboards
.claude/skills/columnar-readiness/scripts/audit.py packages/<pkg> --no-dashboards

# whole catalog (~15-30 s over ~490 packages). Dashboards are OFF here by default;
# `--dashboards` turns the sort tie-break on for every package and costs ~2x
.claude/skills/columnar-readiness/scripts/audit.py packages/ --catalog --dashboards

# catalog, only the statuses you care about, written to a file
.claude/skills/columnar-readiness/scripts/audit.py packages/ --catalog \
  --status READY --status READY_AFTER_AUTO_FIX --out /tmp/columnar-ready.md

# machine-readable (`both` prints Markdown and JSON)
.claude/skills/columnar-readiness/scripts/audit.py packages/<pkg> --format json
```

| Flag | Default | Effect |
| --- | --- | --- |
| `--catalog` | off | PATH is the `packages/` root; prints the catalog summary instead of a per-package report |
| `--dashboards` / `--no-dashboards` | on for one package, off for `--catalog` | count the fields in `kibana/` saved objects, for the sort tie-break hint and the benchmark workload list. The `_source` consumer scan (C6-C8) runs either way — it is not affected by this flag |
| `--format markdown\|json\|both` | `markdown` | JSON has stable keys; use it when feeding another tool |
| `--out FILE` | stdout | write the report to FILE |
| `--status STATUS` | all | catalog mode only, repeatable: list only packages with that status |

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
  (unless it is a multi-field, or a `columnar: {doc_values: true}` override on a
  static leaf field already resolves it); `store: true`; `copy_to`; `keyword` + a
  non-`lowercase` `normalizer`; mapping-level runtime fields and `dynamic: runtime`;
  stored-`_source` overrides; types with no doc values; an invalid
  `columnar: {doc_values: false}`; a `columnar:` block where Fleet will never apply
  it (`columnar_override_misplaced`); a 3.7.0 construct under an older
  `format_version` (`columnar_requires_spec_3_7`); and `columnar.supported: true` on a
  stream that still has blockers (`columnar_supported_with_blockers`).
- **Class B, accepted but lossy:** `dynamic: false`; `enabled: false`. With no stored
  `_source` the unmapped data is gone for good, not merely unsearchable. Always a
  human decision.
- **Class C, informational:** no inverted index on non-`text` fields; flattened
  synthetic-source shape; dynamic fields become non-indexed doc values;
  `normalizer: lowercase` returns the lowercased value from synthetic source; an
  existing `columnar: {index: true}` override, which is reported so its benchmark
  evidence can be confirmed and is never proposed; and object arrays in the stream's
  own example documents (`object_array_flattening`).
- **Class C, but severity `review`, so the stream becomes NEEDS_REVIEW:** a columnar
  **`_source` consumer** — a transform (`source_consumer_transform`) or a Kibana asset
  (`source_consumer_kibana`) that reads `_source` at query time. See below.

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

**Columnar `_source` is not a faithful copy of what was ingested.** It is
reconstructed from doc values: nested objects are flattened, and an object array under
a non-`nested` object becomes parallel arrays — `[{a:1,b:2},{a:3,b:4}]` reads back as
`{a:[1,3], b:[2,4]}` (multi-value order *is* preserved). That is invisible to anything
querying the leaf fields — dashboards, alerting rules, ES|QL — and it is invisible to
**ingest pipelines**, which run before indexing. It is *not* invisible to anything that
reads `_source` at query time: transforms, Kibana runtime and scripted fields, and
ES|QL queries that explicitly ask for `METADATA _source` (usually with
`JSON_EXTRACT(_source, ...)`).

The audit reports these as `source_consumer_transform`, `source_consumer_kibana`
(both `review`) and `object_array_flattening` (`info`). **Do not declare a data stream
`columnar.supported: true` until that review is done** — it is a question about the
stream's consumers, and no mapping check can answer it.

**A negative result is a result, and the report prints it.** Every data stream gets a
`_source` consumers: line, including when nothing was found — "none found in this
package (no transforms reading `_source`, no scripted/runtime fields in `kibana/`, no
ES|QL `METADATA _source`); object arrays: none in the sampled documents". Fields of
type `flattened` are exempt (they keep their JSON verbatim) and are listed by name when
they did hold an object array in the sample, so "exempt" is never mistaken for "not
looked at". Quote that line in the report you hand back; an empty Class C section
reads as "not checked".

**Detection rules are the one consumer class the audit cannot see.** They are
generated from `elastic/detection-rules` and reach users through the
`security_detection_engine` package, so they are invisible to an audit of the package
they query. Check them by hand — there is no automated equivalent:

```bash
git clone https://github.com/elastic/detection-rules
cd detection-rules
grep -rl 'logs-<pkg>\.' rules/ | xargs grep -l '_source'
```

A hit is a rule that walks the document source of one of this package's data streams;
read it before declaring readiness. Rules that only query *fields* (KQL, EQL, ES|QL
without `METADATA _source`) are unaffected.

Full rules and what is deliberately *not* flagged (a runtime field that only
reads `doc[...]` is unaffected):
[references/blockers.md](references/blockers.md), section C6-C8.

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
   pipeline test expectations will have to be regenerated — see step 4.5 below.
2. `data_stream/<ds>/manifest.yml` — declare the stream ready. The readiness flag and
   the index sort are children of the manifest's **single** `elasticsearch:` key, so
   write them as one block, and **merge it into the `elasticsearch:` that is already
   there** rather than appending a second one (a duplicate key is not an error in
   YAML — the file just keeps one of them, and you lose the other silently):
   ```yaml
   elasticsearch:
     columnar:
       supported: true
     index_template:              # only when you proposed an explicit sort
       settings:
         index:
           sort:
             field: ["<field>", "@timestamp"]
             order: ["asc", "desc"]
   ```
   With the default sort (`host.name asc, @timestamp desc` from the logs profile),
   the `index_template` half is omitted and the block is just `columnar.supported`.
   If the manifest already declares an explicit `index.sort`, leave it alone unless
   the dataset says otherwise: changing a sort key rewrites the segment layout on the
   next rollover. Leave non-ready
   streams untouched: the flag is per data stream, and the 3.7.0 validator fails the
   build if you set it on a stream that still has a blocker. Do not set it before the
   columnar `_source` consumer review of step 2 is done either — the validator cannot
   check that one, and a transform or runtime field reading `_source` will not fail,
   it will quietly return a different shape.

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
   `conditions.kibana.version: "^9.6.0"`, and a **major** version bump.

   **A major bump, not a minor one.** Raising the Kibana floor to `^9.6.0` drops 8.x
   and 9.0-9.5 users, and elastic/integrations treats a floor raise as a breaking
   change with a major version: `aws` 7.0.0 ("Require Kibana and Elastic Agent
   ^9.4.0 (drop support for Kibana 8.x…)"), `aws_bedrock` 2.0.0, `aws_logs` 2.0.0,
   `aws_mq` 2.0.0, `aws_securityhub` 2.0.0, `aws_bedrock_agentcore` 1.0.0 ("Raise the
   minimum required Kibana … to 9.6.0 … Deployments on older stacks cannot upgrade").
   The many "Update Kibana constraint to support 9.0.0" entries shipped as minors are
   range *expansions*, not floor raises — they are not precedent for this. The major
   bump is what makes the backport cost below visible to the user instead of arriving
   as a surprise on upgrade.

   **Replace the entire `conditions.kibana.version` range with `"^9.6.0"`** — do not
   add a branch to it. A package on `"^8.19.0 || ^9.1.0"` becomes:
   ```yaml
   conditions:
     kibana:
       version: "^9.6.0"      # replaces the whole range, 8.19 and 9.1 branches included
   ```
   Every `||` branch has to be 9.6+, because a single older branch is exactly what lets
   Fleet keep offering this version to a stack that ignores both columnar constructs.
   Dropping the older branches is the **point** of declaring readiness — and its cost.
   If the package has to keep serving older stacks, do not declare readiness on this
   release line.

   The Kibana constraint is **not** about Elasticsearch — 9.5 already has the index
   mode. Both constructs are read by **Fleet**: Fleet parses
   `elasticsearch.columnar.supported` to decide whether to offer the per-stream opt-in
   toggle, and Fleet applies the field-level `columnar:` overrides when it builds the
   mapping, on the install path and on the toggle path. The Fleet changes ship in
   **9.6**, which is where the floor comes from *(on older Kibana the
   override and the flag are silently ignored, so the toggle is unavailable and any
   `doc_values: false` field will make a manual columnar opt-in fail)*.

   > ### ⚠ This raises the package's minimum stack version to 9.6
   >
   > Enhancing the package spec and the opt-in mechanism **automatically bumps the
   > minimum stack version of a columnar-ready integration to 9.6**. Fleet will not
   > offer the new package version to an older stack, so every user still on 9.5 or
   > below **stops receiving any further update to this package** — security fixes and
   > unrelated bug fixes included, not only the columnar ones. Fixing a bug for them
   > then requires a **backport**: a separate branch and release line off the last
   > pre-9.6 version.
   >
   > Say this to the user before writing the change, and **declare readiness
   > deliberately, only for the integrations picked as tech-preview targets — never
   > catalog-wide**. A `READY` status means "no mapping blocker"; it does not mean
   > "worth a 9.6 floor and a backport line".
4. `changelog.yml` — a new entry at the top with **two** changes, the breaking one
   first, both with a placeholder link the user must replace:
   ```yaml
   - version: "<new major version>"
     changes:
       - description: Raise the minimum required Kibana version to 9.6.0 (drops support
           for Kibana 8.x and 9.x below 9.6.0), required for columnar index mode support.
         type: breaking-change
         link: https://github.com/elastic/integrations/pull/XXXXX
       - description: Declare columnar index mode support for the <ds> data stream(s),
           enabling the per-data-stream logsdb_columnar opt-in in Fleet (tech preview).
         type: enhancement
         link: https://github.com/elastic/integrations/pull/XXXXX
   ```
   The `breaking-change` entry is not optional: it is the only place a user on 9.3
   learns why this package stopped updating for them. Say *declare support for* when
   you only set `columnar.supported: true`, and *enable ... index mode* when you also
   set `index_mode` — the two are different promises to the user reading the changelog.
5. Build and check, in this order:
   ```bash
   cd packages/<pkg>
   elastic-package lint                      # run this FIRST, right after the bump
   # ... fix what is cheap, exclude the rest in validation.yml, one comment each ...
   elastic-package build                     # regenerates docs/README.md
   elastic-package test pipeline             # no -g unless an auto-fix touched the pipeline
   elastic-package test static
   ```
   - **`lint` immediately after the `format_version` bump, before anything else.** A
     multi-minor jump turns on every validator added in between, and they fire on
     code that was already there. Bumping `anthropic` from 3.4.x to 3.7.0 surfaced
     `SVR00008`/`SVR00009` — the ingest-pipeline `on_failure` requirements — which
     have nothing to do with columnar. Expect that, and do not read it as damage from
     your change.
   - **Prefer fixing those findings when the fix is cheap.** `on_failure` handlers are
     the cheap case: they add an error path that the pipeline tests never take, so
     `*-expected.json` does not move. Use `validation.yml` exclusions only for what is
     genuinely out of scope, each with a comment saying why. **Never exclude a columnar
     finding** — `SVR00011`, `SVR00012`, `SVR00013`, or a hard mapping error (those
     have no code and cannot be excluded at all). They are what the exercise is about.
   - **`build` is not optional and it is not the same check as `lint`.** `build`
     validates the built zip, the only place the resolved ECS attributes exist — and
     therefore the only place a `columnar: {doc_values: true}` override on an
     `external: ecs` field can be confirmed to have won the merge.
   - **`docs/README.md` is generated by `build`** from `_dev/build/docs/README.md`;
     never edit the generated file. When validation legitimately fails only on
     something you cannot fix yet — `PSR00001` for the unreleased 3.7.0 spec, or the
     `https://github.com/elastic/integrations/pull/XXXXX` changelog placeholder —
     `elastic-package build --skip-validation` regenerates the docs anyway.
     `--skip-validation` is acceptable **only** when you have read the whole error
     list, every entry in it is one of those two, and you re-run `lint`/`build`
     without the flag before opening the PR. It is **never** acceptable as a way past
     a columnar finding: that ships a data stream whose index template PUT fails.
   - **`test pipeline` with no `-g`.** Pipeline tests run through
     `_ingest/pipeline/_simulate`; nothing is indexed, so the index mode cannot change
     their output. `-g` is correct only when an auto-fix moved a `copy_to` into a
     processor or replaced a normalizer — then read every hunk of the diff.

Tell the user that both `elasticsearch.columnar.supported` and the field-level
`columnar:` block require package-spec 3.7.0, which is unreleased (`3.7.0-next`), so a
stock `elastic-package` binary will reject the manifest and the fields files locally.
[references/correctness-and-performance.md](references/correctness-and-performance.md)
explains how to build `elastic-package` against a local package-spec checkout.

### 5. Validate against a stack

The static half — `lint` → fix/exclude → `build` → `test pipeline` → `test static` —
is step 4.5 above and is where most migrations end. This step is the rest: install
against a 9.5+ stack (with a Kibana new enough to have the Fleet support from step 3)
and verify `index.mode` and `index.sort.field` on the real index → run
`elastic-package test system` with and without columnar and diff → benchmark the
dashboard workload at scale.

**`supported: true` on its own never produces a columnar index.** The stream still
installs on logsdb, `index.mode` reads `logsdb`, and no `elastic-package` flag flips
the Fleet per-stream toggle — so a system test run against a package that only
declares `supported: true` does not exercise columnar at all, and a green run proves
nothing about it. To actually exercise columnar locally, pick one of:

- temporarily add `elasticsearch.index_mode: logsdb_columnar` to the stream manifest,
  leave it **uncommitted**, run `elastic-package install` and
  `elastic-package test system`, then revert it; or
- install the package as it is and opt the data stream in afterwards through the Fleet
  API (`experimental_data_stream_features`), then re-run the system tests.

Both routes, the exact commands, and which test diffs are expected versus which are
bugs:
**[references/correctness-and-performance.md](references/correctness-and-performance.md)**.

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
| `elasticsearch/transform/<name>/transform.yml` | package-level transforms; scripts here run at query time, so `_source` access is a `source_consumer_transform` finding |
| `kibana/dashboard\|lens\|search\|ml_module/*.json` | dominant slicing fields → sort key and benchmark workload; also scanned for `_source` consumers (`params._source`, scripted/runtime fields, ES|QL `METADATA _source`) |
| `changelog.yml`, `_dev/build/docs/README.md`, `validation.yml` | release plumbing |

## Reporting back

Lead with the status and the one-line reason. Name the specific field and file for
every finding — "`o365.audit.ExchangeAggregatedFolders.FolderItems` is `nested` inside
`nested` (`data_stream/audit/fields/fields.yml`)", not "has nested fields". For a
catalog run, give the counts per status and the package list per blocker code, and
call out anything that changed since the last run.
