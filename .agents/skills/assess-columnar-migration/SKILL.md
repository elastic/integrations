---
name: assess-columnar-migration
description: >-
  Assess whether an Elastic integration can migrate to columnar index mode, and
  propose the package changes required. Use when the user asks about columnar
  compatibility, columnar migration, index_mode columnar, logsdb_columnar,
  LogsDB vs columnar, columnar `_source`, JSON_EXTRACT on `_source`, or which
  integrations can move to columnar storage. Also use when choosing the index
  sort for an integration that is being migrated to columnar. Assessment and
  change proposals only — does not apply migrations.
compatibility: Columnar is in tech preview from Elasticsearch 9.5; columnar-ready packages need 9.6+. Designed for packages in elastic/integrations.
license: Apache-2.0
metadata:
  origin: elastic/integrations
  source: LOX program meeting transcript, 2026-07-31
---

# assess-columnar-migration

Assess Elastic integrations for **columnar index mode** and propose what would
need to change. **Do not edit package files, run migration validation, or open
migration PRs** — applying the migration is TODO/TBC.

If the user asks which index sort an integration should use for its
migration, go to [Choosing the index sort](#choosing-the-index-sort-at-migration-time).
Otherwise follow the [Workflow](#workflow).

Read [reference.md](reference.md) only when you need columnar semantics detail.
Read the matching entry in [examples.md](examples.md) when a package is listed
there, or when a finding is unfamiliar.

## Rules

1. **Assess and propose only.** Never modify `packages/**` as part of this skill.
2. Prefer the assess script output. Do not propose index sorts during the
   assessment; the sort is chosen when a specific integration is migrated
   (see [Choosing the index sort](#choosing-the-index-sort-at-migration-time)).
3. Search **mapping sources** (`data_stream/*/fields/`) and stream **manifests**
   (for `dynamic: false` / `index_mode`). Do not treat Fleet var `type: text` as
   a field mapping, or a stream-level `enabled: false` (a Fleet toggle) as a
   mapping. Only `elasticsearch.index_template.mappings` in a manifest counts.
4. Integrations must **opt in per data stream** with an integration-specific
   index sort. Do not recommend cluster-wide `logs-*-*` component templates as
   the Fleet enablement path.
5. Assess **log data streams only**, for `logsdb_columnar`. Metrics streams
   (TSDB or not), other stream types such as `synthetics`, and `type: content`
   are out of scope.
6. **Report the stack floor.** The script prints the minimum implied by
   `format_version` (full table in
   [reference.md](reference.md#package-spec-version); patch is ignored). The
   effective floor is the higher of that and the lower bound of
   `conditions.kibana.version`. Columnar requires a `format_version` bump, which
   raises the floor to 9.6+ (or keeps the constraint, if it is already higher).
   Say which stacks lose upgrades, for example "drops 8.19 and 9.3–9.5". A
   constraint already at 9.6+ does not remove the bump.
7. **Columnar `_source` consumers do not change stream verdicts.** Attach them
   by the `FROM` dataset (`logs-gcp.audit-*` → package `gcp`, stream `audit`).
   Do not decide this from an observability-versus-Security label. The same
   stream is often used by both. See [reference.md](reference.md#columnar-source).

## Scope

| Package shape | Assess? | Notes |
| --- | --- | --- |
| `type: integration` with `data_stream/*/fields/` | Yes | Assess **per data stream** |
| `type: input` (e.g. `winlog`, `filestream`, `cel`) | Per policy template | Root `fields/` and root `elasticsearch:`. Dataset is the template's `data_stream.dataset` var default, else `<package>.<template>`; users can override it, so rules and dashboards may target another name |
| OTel input (`input: otelcol`) | No | Stack OTel template owns storage |
| Mixed logs + metrics (e.g. `system`) | Per stream | Log streams only |
| Metrics streams, with or without `index_mode: time_series` | No | Not a logging workload |
| Data stream `type` other than `logs` / `metrics` (e.g. `synthetics`) | No | Not a logging workload |
| `type: content` (e.g. `vercel_otel`) | No | Stack/OTel template owns storage |
| `elasticsearch/transform/` | No | Script reports the transform count only |

## Finding severity

| Severity | Meaning |
| --- | --- |
| **blocker** | Must fix or exclude stream (`store: true`, `doc_values: false`, `copy_to`, `runtime` fields, nested-in-nested, incompatible types, `_source` disabled). `doc_values: false (event.original)` is called out separately from secret-style fields. `external: ecs` fields count too: ECS sets `doc_values: false` on `event.original` and `*.x509.public_key_exponent`, and elastic-package copies it. |
| **data_loss** | `dynamic: false` / `enabled: false` in fields **or** stream manifest `index_template.mappings`. Columnar in tech preview drops that data; whether it keeps unmapped fields by GA is an open platform decision |
| **info** | Soft signals: package `text` / `match_only_text` |

Do **not** report: `subobjects: false`, single-level `nested`, `flattened`. ECS multi-fields / package text alone do not change the verdict.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `migrate_candidate` | No blockers or data-loss on the stream |
| `pending_platform` | Only data-loss findings. Waits on the platform decision about unmapped fields; no package work yet |
| `defer_or_exclude` | Has blockers |
| `out_of_scope` | Content / metrics / OTel / transforms / non-logs stream types |

**Package verdict is a summary of stream verdicts**, e.g.
`migrate_with_changes (19 clean, 1 blocked: waf)`. The headline is the first
match:

1. Some streams blocked, others clean or pending → `migrate_with_changes`
2. All in-scope streams blocked → `defer_or_exclude`
3. Any clean stream → `migrate_candidate`
4. Otherwise → `pending_platform`

The counts in parentheses carry the rest, so clean streams are never hidden.

## Workflow

```
Assessment progress:
- [ ] Phase 0 — Confirm target package(s)
- [ ] Phase 1 — Run static assess script
- [ ] Phase 2 — Triage report + proposed changes
- [ ] Stop — do not migrate
```

### Phase 0 — Target

Identify `packages/<name>/`. Pass several package paths for one full report
each. For scoreboards, run the script on `packages/`; that prints only the
summary table.

### Phase 1 — Static assessment

The script needs PyYAML. `uv run` installs it from the inline script metadata;
without `uv`, use `pip install pyyaml` and `python3`.

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/<pkg> [packages/<pkg2> …]

uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/
```

Add `--json` for machine-readable output.

After the table, the summary notes how many in-scope packages are still
installable on 8.x. Columnar would move those to 9.6+. The `_source` consumers
column counts `JSON_EXTRACT(_source` hits and Painless `params._source` hits.
It does not change the verdict. The Rules column counts prebuilt detection
rules that query the package's in-scope streams; it signals how much
correctness and performance testing a migration needs. The count uses the
latest version of each rule in `security_detection_engine`, including `logs-*`
rules whose `related_integrations` names the package, so it differs from a grep
of `detection-rules`. Hunting queries are not counted. The Templates column
counts the package's own alerting rule and SLO templates
(`kibana/alerting_rule_template/`, `kibana/slo_template/`) that query in-scope
streams; they are part of the same testing workload.

The script scans this repo (`kibana/` and `elasticsearch/`, skipping ingest
pipelines) and `security_detection_engine`, then looks up the package's
datasets. It also scans a local `elastic/detection-rules` checkout
(`rules/` and `hunting/` `*.toml`) when one exists at `--detection-rules`,
`DETECTION_RULES_PATH`, or as a sibling of this repo (`../detection-rules`).
Hunting queries are not in `security_detection_engine`. The `_source` consumers
section says which checkout was scanned.

If it says the detection-rules checkout was not found, search that repo before
finishing the triage:

```bash
gh search code --repo elastic/detection-rules "JSON_EXTRACT(_source" --limit 100
```

Attach each hit by its `FROM` pattern. `packetbeat-*` is not an integrations
dataset; keep the rule on the integration pattern in the same `FROM`
(`logs-network_traffic.sip-*`).

### Phase 2 — Triage report

Use the template below, one report per package. Leave out zero counts in
"Stream verdicts". List skipped streams by reason, with names (or a count when
there are more than ten). End by asking the user which streams to prioritize.
**Do not migrate.**

When writing blockers:
- Do not report single-level `nested` or `flattened`.
- For nested-in-nested, name the options: map the inner level as `object` or
  `flattened`, or keep only the outer level nested. Check dashboards and rules
  for `nested` queries on those paths first.
- If every in-scope stream is blocked, excluding streams is not an option; the
  package moves only after the remapping.

For input packages, note in Scope that users can override the dataset, and
that the columnar template has to follow the dataset they pick.

## Triage response template

```markdown
# Columnar assessment: <package>

## Scope
- Package type: …
- `format_version`: …
- Minimum stack: … from spec, … from `conditions.kibana.version` (columnar raises this to 9.6+; say which stacks lose upgrades)
- Stream verdicts: migrate_candidate=N, pending_platform=N, defer_or_exclude=N
- Skipped: <reason>: `stream`, … (metrics / content / OTel / transforms)

## Blockers (per stream)
- `stream` — kind — field path (or “None”)

## Data-loss risks (pending platform)
- fields and/or manifest `dynamic: false` / `enabled: false` (or “None”)
- No package rework yet; depends on whether columnar stores unmapped fields by GA

## Degraded / trade-offs
- Info: package text / match_only_text

## Columnar `_source` consumers
- `JSON_EXTRACT(_source, ...)` and Painless `params._source` (or “None”)
- These do not change the stream verdict
- Rewrites: [reference.md](reference.md#columnar-source). Do not use `SET unmapped_fields="load"` (`LOAD` reads `_source` and cannot see `flattened` subfields)

## Testing workload
- Prebuilt detection rules per stream, by language (or “None”)
- Package alerting rule and SLO templates per stream (or “None”)

## Proposed changes (not applied)
1. Minimum stack is … (`format_version` …, `conditions.kibana.version` …). Bump `format_version` for columnar; that raises the minimum to 9.6+
2. Fix or exclude blocker streams (others can proceed)
3. pending_platform streams wait on the unmapped-field decision
4. Rewrite `_source` consumers in `detection-rules` / `security_detection_engine` (not a mapping blocker)
5. **Deferred to migration (columnar-ready PR):** per-stream index sort and indexed fields, apply edits, tests in both LogsDB and `logsdb_columnar`, verification that dashboards, rules (EQL/KQL too), alerting rule and SLO templates return the same results as on LogsDB, changelog

## Verdict
`<package summary from script>`
```

## Choosing the index sort (at migration time)

Only when the user is migrating a specific integration, not during assessment.
The sort applies in both LogsDB and `logsdb_columnar`, so it also changes LogsDB
for existing users on rollover. Indexed fields are an explicit decision per
stream, possibly an empty list. See [migration-design.md](migration-design.md)
for the columnar-ready bar. Run both scripts; the assess script gives the in-scope streams and their
blockers, and the hints script gives the sort inputs:

```bash
uv run .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/<pkg>
uv run .agents/skills/assess-columnar-migration/scripts/index_sort_hints.py packages/<pkg>
```

Per in-scope stream, the hints script prints whether `host.name` is declared,
the fields dashboard controls/filters use, the fields dashboard panels use, and
the fields prebuilt rules require (`required_fields`).

1. `logsdb_columnar` sorts on `host.name` asc + `@timestamp` desc by default and
   adds the `host.name` mapping if missing. If the stream maps `host.name` with a
   type that cannot be sorted on, the default falls back to `@timestamp` only.
   Keep that default for host-centric streams (one log source per host, such as
   web servers or system logs), whether or not the stream declares `host.name`.
2. Otherwise prefer a **low-cardinality dimension** users slice by, plus
   `@timestamp` desc. Dashboard controls/filters are the strongest signal. A
   field that is not declared can still be the sort; say the mapping has to be
   added.
3. Domain overrides win over the hints: firewall (`observer.name`), cloud
   (`cloud.account.id` / tenant / org), IdP (`user.name` / actor id).
4. Read the rule queries before trusting rule fields: `required_fields`
   includes `STATS … BY` grouping keys and can miss the fields a rule filters
   on. High-cardinality identifiers that rules filter on by exact value (users,
   IPs, hashes, process names) scan doc values when outside the sort; list them
   as candidates for an explicit inverted index (`index: true`). Leading-wildcard
   matches (`LIKE "*…"`) don't benefit from one. Indexing all fields for
   Security-heavy streams is a product option, not a per-package call.
5. EQL, KQL, and Lucene rules run as Query DSL, and so do many dashboards.
   Performance tests must cover them, not only ES|QL. Include the package's
   alerting rule and SLO templates (the assess script counts them). These
   tests are a separate workstream from the columnar-ready PR; their results
   decide whether columnar becomes the default for new installs at GA.

Answer with one row per stream:

```markdown
| Data stream | Mode | Index sort | Rationale | Mapping additions | Inverted-index candidates |
| --- | --- | --- | --- | --- | --- |
| `access` | `logsdb_columnar` | `host.name` asc, `@timestamp` desc (default) | … | … | … |
```

Name the change; don't write the package YAML (Rule 1). See
[reference.md](reference.md#index-sorting-guidance).

## Open items (platform / follow-up)

- **Package spec for columnar-ready integrations.** New minor (a stack-gated feature, so not a patch on 3.4 or 3.6). Define mode (`logsdb_columnar` / `columnar`) and a required index sort. Kibana 9.5 shipped with `REGISTRY_SPEC_MAX_VERSION` `3.6`, so the new minor lands in 9.6 at the earliest, and packages can bump only after that. See [reference.md](reference.md#package-spec-version).
- **Unmapped fields under columnar.** Tech preview drops data under `dynamic: false` / `enabled: false`. If columnar stores unmapped fields by GA, `pending_platform` streams become `migrate_candidate` with no package change.
- ECS dynamic templates: skip text subfields under columnar (~10.0 breaking change)
- Repo-wide nested-in-nested + compatibility CI (like LogsDB pass)
- Transform destination indices — separate columnar rules
- **Rerouted documents.** Streams with `dynamic_dataset: true` (e.g. aws `cloudwatch_logs`) can route documents to other datasets, which don't get the stream's columnar template or sort.
- **Apply migration + validation skill/workflow** — not covered here; draft design in [migration-design.md](migration-design.md). Indexed-document checks go there: pipeline tests stay valid; LogsDB golden `_source` is normalized per [reference.md](reference.md#columnar-source) before comparing.
- **No `JSON_EXTRACT` path matches both LogsDB and columnar `_source`.** Rewrites are in [reference.md](reference.md#columnar-source). A lenient path is [elastic/elasticsearch#160300](https://github.com/elastic/elasticsearch/issues/160300).

## Further reading

Don't fetch eagerly; fetch when the user asks for detail.

- [Columnar reference](https://www.elastic.co/docs/reference/elasticsearch/columnar)
- [Search Labs overview](https://www.elastic.co/search-labs/blog/elasticsearch-columnar-storage)
- [`subobjects: false` and auto-flattening](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/subobjects#subobjects-auto-flattening)
- [Built-in ECS template](https://github.com/elastic/elasticsearch/blob/main/x-pack/plugin/core/template-resources/src/main/resources/ecs%40mappings.json)
- Skill detail: [reference.md](reference.md), [examples.md](examples.md)
