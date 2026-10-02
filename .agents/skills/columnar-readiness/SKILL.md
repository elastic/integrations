---
name: columnar-readiness
description: Audits and migrates Elastic integration packages to the logsdb_columnar Elasticsearch index mode. Use for "columnar readiness", "logsdb_columnar", "migrate to columnar", "columnar audit", "index sorting for columnar", "is this package columnar-ready", "columnar blockers", or when asked which integrations can adopt columnar index mode, why a package is blocked, what index sort a data stream should use, which fields need an inverted index, or what columnar `_source` does to transforms, detection rules, runtime fields and other `_source` consumers.
compatibility: Designed for packages in elastic/integrations. scripts/audit.py needs Python 3.9+ and PyYAML (`uv run` installs it from the script's inline metadata). Migrations also need elastic-package built against package-spec 3.7.0, and stack tests a Kibana with the Fleet columnar support.
license: Apache-2.0
metadata:
  origin: elastic/integrations
---

# Columnar readiness

Decide whether an integration's **logs** data streams can move to `logsdb_columnar`,
fix what is mechanically fixable, propose an index sort key, and plumb the opt-in
through the package.

## Current status

The facts in this section change between releases; update them here, not elsewhere.
Last reviewed 2026-10-02.

- **Elasticsearch:** `logsdb_columnar` is tech preview since 9.5; GA is targeted for
  9.7 (January 27). Keyword doc-value skippers are still pending and bloom filters
  come after GA, so benchmark numbers from today will move.
- **package-spec 3.7.0** is unreleased (`3.7.0-next`). A stock `elastic-package`
  rejects everything this skill writes; build one against a local package-spec
  ([`references/migration.md`](references/migration.md#local-tooling)).
- **Fleet support** ships in Kibana 9.6, from the `feat/columnar-index-mode` branch; no
  snapshot has it yet. Kibana's registry `spec.max` is still 3.6, so 3.7.0 packages only
  reach Kibana through `elastic-package install` for now.
- **Objects inside `nested` fields** lose their link to the element on columnar (9.5.4,
  and 9.6 snapshots up to 2026-10-01): an object sent as JSON inside a nested element
  is indexed apart from it. Dotted keys are not affected. The audit flags it
  (`nested_object_children`), and fixes nested inside nested with `flattened`, not
  `group` ([`references/blockers.md`](references/blockers.md) C2b). Re-check on newer
  builds.
- **Open team decisions** this skill follows a default for:
  - whether manifests may set a columnar `index_mode` (the skill never writes one);
  - how per-field inverted indexes are spelled (the skill prefers `columnar: {index: true}`);
  - the `breaking-change` changelog type for the Kibana floor (the skill follows the repo precedent);
  - OTel scope (out of scope).

## What logsdb_columnar is

It stores every field once, as doc values. It drops the inverted indexes and BKD trees
of all non-`text` fields, and relies on index sorting plus doc-value skippers to prune
queries. It **never stores the original JSON `_source`**: `_source` is rebuilt from
the columns, and because columnar flattens the mapping itself, the rebuilt `_source`
is flat (dotted keys).

`logsdb_columnar` = base `columnar` + the logs profile: default index sort
`host.name asc, @timestamp desc` (Elasticsearch adds a `host.name` mapping if absent,
and falls back to `@timestamp` alone if an existing one cannot be sorted), plus
`ignore_malformed` and `ignore_above` defaults.

## Rollout rules — decisions, not preferences

1. **Logs data streams only.** Metrics, traces and synthetics streams, `type: input`
   packages, and streams fed by an OpenTelemetry input (`otelcol`) are out of scope —
   OTel log streams wait for derived fields (clustering logs by resource attributes).
   Input packages cannot declare columnar under package-spec 3.7.0; the audit still
   checks their logs policy templates and lists the findings for information.
2. **Per-field inverted indexes are a per-stream human decision**, from the queries
   the stream's dashboards and detection rules run, and "none" is a valid answer. The
   audit lists **lookup candidates**; it never writes `index: true` or
   `columnar: {index: true}` itself. When a human decides a field needs one, write
   `columnar: {index: true}` on it and record the query that justifies it.
3. **Index sorting is the first per-integration lever.** A field in the sort key needs
   no index.
4. **Opt in per data stream.** A package can be mixed: migrate the ready streams and
   leave the rest alone.
5. **Declare readiness only for the chosen tech-preview targets**, never catalog-wide:
   it raises the package's minimum stack to 9.6 and needs a backport line
   ([`references/migration.md`](references/migration.md#the-cost-of-declaring-readiness)).
   Say so to the user before writing the change.

## The two things you write into a package (package-spec 3.7.0)

**1. The field-level, mode-scoped `columnar:` block.** Fleet applies what is inside it
*only* when the resolved index mode is `logsdb_columnar` or `columnar`, the same way it
only emits TSDB's `dimension: true` for `time_series`:

```yaml
- name: event.original
  external: ecs
  columnar:
    doc_values: true    # the only valid value
```

Use it for every `doc_values: false` remediation: logsdb and standard installs of the
same version keep their mapping byte for byte, so the fix is free off-columnar. It is
honored on **static leaf fields only**. Fleet ignores it, and package-spec 3.7.0
rejects it, on a field rendered as a dynamic template (`object_type`) or inside
`multi_fields:` (`columnar_override_misplaced`).

**2. The stream-level readiness flag**, in `data_stream/<ds>/manifest.yml`:

```yaml
elasticsearch:
  columnar:
    supported: true
```

A manifest has **one** `elasticsearch:` key, and the index sort lives under the same
one: merge, never paste a second `elasticsearch:` (a duplicate key silently drops one
of them). The 3.7.0 validator rejects the flag while any blocker remains. It is **not**
the same as a columnar `index_mode`:

| Declaration | Effect |
| --- | --- |
| `elasticsearch.columnar.supported: true` | Fleet offers the per-stream toggle. logsdb stays the default; the user turns columnar on, and can turn it off again. |
| `elasticsearch.index_mode: logsdb_columnar` | Columnar is **forced** for every install of the version: the toggle is locked on (the API cannot turn it off either), and streams that already hold data switch at the next rollover on upgrade. |

**Write `supported: true` and leave `index_mode` unset.** The rollout strategy is
opt-in, with opt-out, and no flip of data that already exists.

Both constructs need `format_version: "3.7.0"` and `conditions.kibana.version:
"^9.6.0"` in the root manifest ([`references/migration.md`](references/migration.md)).

## Workflow

### 1. Audit

The audit is the bundled script `scripts/audit.py`, relative to this skill's directory
(written `<skill-dir>` below: wherever this `SKILL.md` is installed). Run it from the
root of the integrations repository, which is where `packages/` is:

```bash
# one package — `kibana/` assets and the shipped detection rules are scanned
python3 <skill-dir>/scripts/audit.py packages/<pkg>
uv run <skill-dir>/scripts/audit.py packages/<pkg>    # same, installs PyYAML on the fly

# whole catalog (~20 s over ~500 packages); dashboards are off by default here
python3 <skill-dir>/scripts/audit.py packages/ --catalog
python3 <skill-dir>/scripts/audit.py packages/ --catalog \
  --status READY --status READY_AFTER_AUTO_FIX --out /tmp/columnar-ready.md

# machine-readable (`both` prints Markdown and JSON)
python3 <skill-dir>/scripts/audit.py packages/<pkg> --format json
```

| Flag | Default | Effect |
| --- | --- | --- |
| `--catalog` | off | PATH is the `packages/` root; prints the catalog summary |
| `--dashboards` / `--no-dashboards` | on for one package, off for `--catalog` | count the fields in `kibana/` saved objects, for sort hints, lookup candidates and the benchmark workload. The `_source` consumer scan runs either way |
| `--rules DIR` / `--no-rules` | `packages/security_detection_engine/kibana/security_rule` next to the package | where to read the shipped detection rules, or skip them (and the checkout below) |
| `--detection-rules DIR` | `$DETECTION_RULES_PATH`, then a `detection-rules` checkout next to this repository | an `elastic/detection-rules` checkout whose `rules/` and `hunting/` queries are scanned for `_source` readers; the report says when none was found |
| `--format markdown\|json\|both` | `markdown` | JSON has stable keys |
| `--out FILE` | stdout | write the report to FILE |
| `--status STATUS` | all | catalog mode only, repeatable |

Needs Python 3.9+ and PyYAML: `uv run` installs it, otherwise
`python3 -m pip install --user pyyaml` or a venv. `audit.py` only parses the command
line; the checks live in the `scripts/columnar_readiness/` package next to it, one
module per concern (fields, sort, `_source` consumers, rules, report). It is
deterministic and static and never contacts Elasticsearch. It reads:

- the manifests and `fields/*.yml`;
- the ingest pipelines, `sample_event.json`, pipeline test expectations and transforms;
- the `kibana/` assets, including the alerting rule and SLO templates;
- the shipped detection rules, and an `elastic/detection-rules` checkout when one is found.

It exits with code 2 on a path that is not a package (or not a `packages/` root with
`--catalog`).

**ECS definitions come from elastic-package's cache**
(`~/.elastic-package/cache/fields/ecs/`). Without it, a built-in fallback is used, the
sort checks are more conservative, and the report header says so. Run
`elastic-package build` on any package once to populate the cache.

### 2. Read the findings

Statuses per data stream: `READY` (no mapping blocker found — not a validation
result), `READY_AFTER_AUTO_FIX`, `NEEDS_REVIEW`, `BLOCKED`, `OUT_OF_SCOPE`. Package
status is the worst of its streams, so the report prints the split next to it
(`20 logs streams: 1 blocked (waf), 3 need review, 16 ready`): the other streams can
still go ahead. Every finding gives `file:line`. The header also says which stacks can
install the package today, from its `format_version` (3.4: 8.19 and 9.1+), which
declaring readiness raises to 9.6. Report shape:
[`references/report-template.md`](references/report-template.md). Every finding, its
detection rule and its remediation:
[`references/blockers.md`](references/blockers.md). Short version:

- **Class A, rejected by Elasticsearch:**
  - `nested` inside `nested`, whether declared through `fields:` or as dotted-name
    sibling entries;
  - `doc_values: false` (unless it is a multi-field, or a static leaf with a
    `columnar: {doc_values: true}` override);
  - `store: true`, `copy_to`, and a keyword `normalizer` other than `lowercase`;
  - mapping-level runtime fields and `dynamic: runtime`;
  - stored-`_source` overrides, and types without doc values;
  - misuse of the 3.7.0 constructs (`columnar_doc_values_false`,
    `columnar_override_misplaced`, `columnar_requires_spec_3_7`,
    `columnar_supported_with_blockers`).
- **Class B, accepted but lossy:** `dynamic: false`, `enabled: false`. With no stored
  `_source` the unmapped data is gone for good. Always a human decision.
- **Class C, behaviour changes:**
  - **info:** no inverted index on non-`text` fields; the flat source shape;
    dynamically mapped fields; `normalizer: lowercase`; an existing
    `columnar: {index: true}`; object arrays in the stream's example documents.
  - **review** (the stream becomes NEEDS_REVIEW): objects inside a `nested` field
    (`nested_object_children`), and anything that reads `_source` —
    a transform script (`source_consumer_transform`), a `latest` transform
    (`source_consumer_latest_transform`), a Kibana asset (`source_consumer_kibana`),
    or a shipped detection rule (`source_consumer_detection_rule`).

**`store: true` is not an escape hatch.** Elasticsearch rejects `store` outright in
columnar modes. The mechanical fix for `doc_values: false` is doc values on, scoped to
columnar with `columnar: {doc_values: true}`.

**The ECS trap.** `external: ecs` imports `doc_values` from the ECS schema at build
time, and ECS defines `event.original` with `doc_values: false`. About 50 packages
carry a Class A blocker that is invisible in their source (`doc_values_false_ecs`); the
fix is a `columnar: {doc_values: true}` block next to the `external: ecs` reference. A
package that never *declares* `event.original` is fine: the field is mapped at index
time by `ecs@mappings`, which sets `index: false` only and keeps doc values. The
blocker is the declaration, not the field.

**Columnar `_source` is not a faithful copy of what was ingested.** The differences:

- keys are dotted;
- single-element arrays become plain values;
- object arrays become parallel arrays (`[{a:1,b:2},{a:3,b:4}]` → `{a:[1,3], b:[2,4]}`);
- multi-value order is preserved.

Anything that queries leaf fields is unaffected: dashboards, KQL, EQL, ES|QL columns,
ingest pipelines on the stream (they run before indexing). Anything that reads
`_source` is affected. The audit looks for four such readers:

- **transform scripts** reading `params._source`;
- **`latest` transforms**, including ones another package owns, which copy the newest
  document's `_source` into their destination index. The destination documents change
  shape, and a destination pipeline stops finding fields that arrive as dotted keys.
  Fix: a leading `dot_expander` with `field: "*"`;
- **Kibana assets:** scripted and runtime fields, ES|QL `METADATA _source`,
  `JSON_EXTRACT(_source, …)`;
- **detection rules**: the shipped ones (`packages/security_detection_engine`,
  scanned automatically) and, with a checkout, `elastic/detection-rules` rules and
  hunting queries. A query that does `JSON_EXTRACT(_source, "a.b")` gets null on
  columnar and silently stops matching. Hold the stream back until it reads columns,
  or `FIELD_EXTRACT` for a `flattened` field, instead
  ([`references/blockers.md`](references/blockers.md) C9).

**Do not declare a stream `columnar.supported: true` until that review is done.** A
negative result is printed too: every stream gets a `_source` consumers line, and a
**Detection rules** line with both numbers ("N shipped rules query this stream; none
read `_source`"). Quote both in the PR; an empty section reads as "not checked". Rules
a user wrote, or installed from elsewhere, are not covered.

**Suggested changes.** Where a fix is mechanical, the finding carries a ready-to-paste
snippet, the file it goes in and where in that file:

- the `dot_expander` for a `latest` transform's destination pipeline;
- the `script` processor that replaces `copy_to`;
- a skeleton for a runtime field's ingest script;
- the multi-field for a custom normalizer;
- the `type: flattened` change for nested inside nested;
- the `script` processor that sends the objects inside a `nested` field as dotted keys.

Pipeline snippets go **inline** in the pipeline that needs them, tagged `columnar_*`
with a `description` starting "columnar:", so `grep columnar_` finds them all. Do not
move them into a separate "columnar" pipeline file: a pipeline cannot see which index
mode a document lands in, so these processors run in every mode anyway, and they need
different positions (a `dot_expander` first, a `copy_to` replacement after the
processors that set its source).

More per-stream lines feed decisions, not statuses:

- **Lookup candidates** — the `keyword`/`ip` fields the stream's rules and dashboard
  filters reference outside the sort key, high-risk lookups (`source.ip`, `user.name`,
  hashes, `trace.id`, …) first. The input to rule 2, never a recommendation.
- **Text sub-fields** — `.text`-style multi-fields that keep an inverted index in
  columnar; input for the ECS `.text` review.
- **Detection rules** — the rule half of the performance workload (EQL and KQL run as
  Query DSL). A rule counts for the streams its query names by dataset, else the
  policy templates its `related_integrations` lists, so a package-wide `logs-aws*`
  rule lands on `cloudtrail`, not on all twenty aws streams.
- **Alerting rule and SLO templates** — the package's own query templates that query
  the stream. They must return the same results on columnar.

### 3. Decide the index sort

The audit proposes one per data stream. Confirm it before writing it — the proposal is
static analysis. The **input types** pick the regime:

| Input class | Inputs | Regime |
| --- | --- | --- |
| host-local | `logfile`, `filestream`, `journald`, `winlog`, `etw`, `system/*`, `audit/*`, container inputs | the default `host.name asc, @timestamp desc` is right |
| receiver | `tcp`, `udp`, `syslog` | the device id the pipeline writes (`observer.name` / `observer.hostname` / `observer.serial_number`), else a human choice |
| collector / poller | `httpjson`, `cel`, `aws-s3`, `gcp-pubsub`, `azure-eventhub`, `o365audit`, … | an explicit sort on the dataset's tenant/account/org id |

- **Host-local:** Elastic Agent populates `host.name` on every event and Elasticsearch
  injects the mapping, so "`host.name` is not in `fields/*.yml`" is not evidence
  against the default.
- **Collector:** `host.name` is the collector. Candidates are ECS grouping fields
  declared in `fields/*.yml` or populated in `sample_event.json` (`cloud.account.id`,
  `organization.id`, `cloud.project.id`, …), then vendor tenant ids. What dashboards
  filter on is only a hint.
- A candidate must be **single-valued** (itself and every object it lives in), have doc
  values, be a `keyword`/`ip` or an identifier-named integer, and not be constant.
  Otherwise the audit says "no confident candidate; needs human choice": a weak or
  multi-valued sort key is worse than none. Keep sorts to two fields.
- An explicit sort goes into the `@package` component template, so it applies to
  logsdb and standard installs too. Say so in the changelog.

Constraints, candidate ranking and the YAML: [`references/sorting.md`](references/sorting.md).

### 4. Migrate a package (only when asked)

Follow [`references/migration.md`](references/migration.md) step by step, with its
checklist. In short:

1. baseline `lint`;
2. bump `format_version` to 3.7.0 alone and `lint` again, resolving the findings the
   spec jump surfaces (fix `SVR00008`/`SVR00009`; `SVR00006` may be excluded with a
   comment; never exclude a columnar finding);
3. apply the mechanical fixes;
4. add `columnar.supported: true` (plus the sort) to each ready stream;
5. `conditions.kibana.version: "^9.6.0"` and a major version bump;
6. changelog entries;
7. `lint`, `build`, `test pipeline` (no `-g` unless a fix moved logic into the
   pipeline), `test static`, and re-run the audit.

Blocked streams are not mechanical. For `nested` inside `nested`, the usual fix is to
map the inner level as `type: flattened`, after checking that nothing runs `nested`
queries on it: the values stay with their outer element, and the sub-fields become
keywords. `type: group` keeps the types, but on columnar it needs the dotted-key
pipeline change too ([`references/blockers.md`](references/blockers.md) A1, C2b).

### 5. Validate against a stack

**`supported: true` on its own never produces a columnar index.** The stream installs
on logsdb until someone opts in, and `elastic-package` has no flag for the toggle, so a
green system test proves nothing about columnar. To get a columnar index:

- **Route A** (needs a Kibana built with the Fleet support): add
  `index_mode: logsdb_columnar` to the stream manifest temporarily and uncommitted.
- **Route B** (same Kibana): opt the stream in through
  `PUT /api/fleet/package_policies/<id>` with
  `package.experimental_data_stream_features`.
- **Route C** (any stock 9.5+ stack): set `index.mode: logsdb_columnar` in a
  `logs-<pkg>.<ds>@custom` component template. Only for packages without
  `doc_values: false` fields.

Then diff system tests between the two modes: dotted keys, collapsed single-element
arrays, parallel object arrays and preserved order are expected, and so is
elastic-package's "expected array, found <scalar>" failure. Anything else is a bug.
Pipeline tests never index anything, so they must be identical in both modes. The
performance workload is the dashboards plus the stream's direct detection rules,
including Query DSL and EQL, with needle-in-a-haystack lookups measured explicitly.

Everything, with commands:
[`references/correctness-and-performance.md`](references/correctness-and-performance.md).

## Where things live in a package

| Path | Relevance |
| --- | --- |
| `manifest.yml` | `format_version`, `version`, `type`, `conditions.kibana.version` |
| `data_stream/<ds>/manifest.yml` | `type`, `dataset`, `elasticsearch.columnar.supported`, `elasticsearch.index_mode`, `index_template.settings` (index sort), `index_template.mappings` (`dynamic`, `dynamic_templates`, `_source`) |
| `data_stream/<ds>/fields/*.yml` | field definitions; nesting via `fields:` or dotted names, multi-fields via `multi_fields:`, ECS imports via `external: ecs`, overrides via `columnar:` |
| `data_stream/<ds>/elasticsearch/ingest_pipeline/*.yml` | where `copy_to`, normalizers and runtime scripts get re-implemented |
| `data_stream/<ds>/sample_event.json`, `_dev/test/pipeline/*`, `_dev/test/system/*` | evidence for which fields are populated |
| `elasticsearch/transform/<name>/transform.yml` | `latest` transforms and transform scripts: `_source` consumers |
| `elasticsearch/ingest_pipeline/*.yml` | package-level pipelines, including transform destination pipelines |
| `kibana/dashboard\|lens\|search\|ml_module/*.json` | sort hints, lookup candidates, benchmark workload, `_source` consumers |
| `kibana/alerting_rule_template\|slo_template/*.json` | the package's own query templates, per stream |
| `fields/*.yml` at the package root, `policy_templates` | an input package's streams (assessed for information only) |
| `../security_detection_engine/kibana/security_rule/*.json` | the shipped detection rules that query the package's streams |
| an `elastic/detection-rules` checkout: `rules/`, `hunting/` | hunting queries and unreleased rules, scanned for `_source` readers |
| `changelog.yml`, `_dev/build/docs/README.md`, `validation.yml` | release plumbing |

## Reporting back

Lead with the status and the one-line reason. Name the specific field and file for
every finding — "`o365.audit.ExchangeAggregatedFolders.FolderItems` is `nested` inside
`nested` (`data_stream/audit/fields/fields.yml:291`)", not "has nested fields". Quote the
`_source` consumers and Detection rules lines, and the lookup candidates when the user
is deciding on indexes. For a catalog run, give the counts per status and the package
list per blocker code, and call out anything that changed since the last run.
