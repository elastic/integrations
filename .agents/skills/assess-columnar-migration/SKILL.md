---
name: assess-columnar-migration
description: >-
  Assess whether an Elastic integration can migrate to columnar index mode, and
  propose the package changes required. Use when the user asks about columnar
  compatibility, columnar migration, index_mode columnar, logsdb_columnar,
  LogsDB vs columnar, or which integrations can move to columnar storage.
  Assessment and change proposals only — does not apply migrations.
compatibility: Requires Elasticsearch 9.5+ (columnar preview) for eventual migration. Designed for packages in elastic/integrations.
license: Apache-2.0
metadata:
  origin: elastic/integrations
  source: LOX program meeting transcript, 2026-07-31
---

# assess-columnar-migration

Assess Elastic integrations for **columnar index mode** and propose what would
need to change. **Do not edit package files, run migration validation, or open
migration PRs** — applying the migration is TODO/TBC.

Read [reference.md](reference.md) only when you need columnar semantics detail.
See [examples.md](examples.md) for filled triage samples.

## Rules

1. **Assess and propose only.** Never modify `packages/**` as part of this skill.
2. Prefer the assess script output; enrich with Phase 2 index-sort judgment.
3. Search **mapping sources** (`data_stream/*/fields/`) and stream **manifests**
   (for `dynamic: false` / `index_mode`). Do not treat Fleet var `type: text` as
   a field mapping.
4. Integrations must **opt in per data stream** with an integration-specific
   index sort. Do not recommend cluster-wide `logs-*-*` component templates as
   the Fleet enablement path.
5. Use `logsdb_columnar` for log data streams. For metrics without
   `index_mode: time_series`, report **`metrics_undecided`** (TSDB vs bare
   `columnar`) — do not assume columnar. Skip TSDB streams and `type: content`.
6. **Report the stack floor implied by `format_version`.** Patch is ignored.
   State that minimum (spec 3.0 → 8.11, 3.4 → 8.19, 3.6 → 9.4) and that columnar
   requires a `format_version` bump, which raises it to 9.5+. A
   `conditions.kibana.version` already at 9.5 does not remove that bump. See
   [reference.md](reference.md#package-spec-version).

## Scope

| Package shape | Assess? | Notes |
| --- | --- | --- |
| `type: integration` with `data_stream/*/fields/` | Yes | Assess **per data stream** |
| Mixed logs + metrics (e.g. `system`) | Per stream | `elasticsearch.index_mode: time_series` → skip (TSDB) |
| Metrics without `time_series` | Yes, flagged | Verdict `metrics_undecided` |
| `type: content` (e.g. `vercel_otel`) | No | Stack/OTel template owns storage |
| `elasticsearch/transform/` | No | Script notes as info only |

## Finding severity

| Severity | Meaning |
| --- | --- |
| **blocker** | Must fix or exclude stream (`store: true`, `doc_values: false`, `copy_to`, mapping-level `runtime`, nested-in-nested, incompatible types). `doc_values: false (event.original)` is called out separately from secret-style fields. |
| **data_loss** | `dynamic: false` / `enabled: false` in fields **or stream manifests** — data dropped under columnar |
| **info** | Soft signals: package `text` / `match_only_text`, ECS text-subfield candidates, transform-field notes |

Do **not** report: `subobjects: false`, single-level `nested`, `flattened`. ECS multi-fields / package text alone do **not** drive `migrate_with_changes`.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `migrate_candidate` | No blockers or data-loss on the stream |
| `migrate_with_changes` | Data-loss risks to review; migratable with work |
| `defer_or_exclude` | Has blockers |
| `metrics_undecided` | Metrics stream, not TSDB — product choice |
| `out_of_scope` | Content / TSDB / transforms |

**Package verdict is a summary of stream verdicts**, e.g.
`migrate_with_changes (44 migratable, 1 blocked: waf)` — never hide clean
streams behind one blocked stream.

## Workflow

```
Assessment progress:
- [ ] Phase 0 — Confirm target package(s)
- [ ] Phase 1 — Run static assess script
- [ ] Phase 2 — Index-sort proposal (script kibana seeds + judgment)
- [ ] Phase 3 — Triage report + proposed changes
- [ ] Stop — do not migrate
```

### Phase 0 — Target

Identify `packages/<name>/`. For scoreboards, use repo-wide `--summary-only`.

### Phase 1 — Static assessment

```bash
python3 .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/<pkg>

python3 .agents/skills/assess-columnar-migration/scripts/assess_package.py packages/ --summary-only
```

After the table, the summary notes how many in-scope packages are still
installable on 8.x. Columnar would move those to 9.5+.

### Phase 2 — Index-sort proposal

1. Start from script **Kibana field seeds** (top dashboard/control fields).
   Seeds are package-wide; ignore fields that belong to another stream.
2. Prefer a **low-cardinality dimension** those assets filter on + `@timestamp` desc.
3. Use `host.name` + `@timestamp` **only** when host-centric and declared in
   that stream's `fields/`. A dashboard field that is not declared can still be
   the sort; say the mapping has to be added.
4. These overrides win over seeds: firewall (`observer.name`), cloud
   (`cloud.account.id` / tenant/org), IdP (`user.name` / actor id).

### Phase 3 — Triage report

Use the template below. Ask which streams to prioritize later — **do not migrate**.

## Triage response template

```markdown
# Columnar assessment: <package>

## Scope
- Package type: …
- `format_version`: …
- Minimum stack from spec: … (columnar requires a `format_version` bump, which raises this to 9.5+)
- Stream verdicts: migrate_candidate=N, migrate_with_changes=N, defer_or_exclude=N, …
- Skipped: TSDB / content / transforms

## Blockers (per stream)
- `stream` — kind — field path (or “None”)

## Data-loss risks
- fields and/or manifest `dynamic: false` / `enabled: false` (or “None”)

## Degraded / trade-offs
- Info: package text / match_only_text, ECS text candidates
- Do not report single-level `nested` or `flattened`

## Index sort (proposed)
| Data stream | Mode | Proposed sort | Rationale |
| --- | --- | --- | --- |
| … | logsdb_columnar | … | kibana seeds + domain |

## Proposed changes (not applied)
1. Minimum stack from spec is … (`format_version` …). Bump `format_version` for columnar; that raises the minimum to 9.5+
2. Fix or exclude blocker streams (others can proceed)
3. Data-loss / metrics_undecided decisions
4. Per-stream `mode` + index sort
5. **Deferred (TODO/TBC):** apply edits, build/test, validate UI/rules, changelog

## Verdict
`<package summary from script>`
```

## Open items (platform / follow-up)

- **Package spec for columnar-ready integrations.** New minor (a stack-gated feature, so not a patch on 3.4 or 3.6). Define mode (`logsdb_columnar` / `columnar`) and a required index sort. Kibana 9.5 `REGISTRY_SPEC_MAX_VERSION` is still `3.6` and must include the new minor before any package bump. See [reference.md](reference.md#package-spec-version).
- ECS dynamic templates: skip text subfields under columnar (~10.0 breaking change)
- Repo-wide nested-in-nested + compatibility CI (like LogsDB pass)
- Transform destination indices — separate columnar rules
- **Apply migration + validation skill/workflow** — not covered here

## Further reading

Don't fetch eagerly; fetch when the user asks for detail.

- [Columnar reference](https://www.elastic.co/docs/reference/elasticsearch/columnar)
- [Search Labs overview](https://www.elastic.co/search-labs/blog/elasticsearch-columnar-storage)
- [`subobjects: false` and auto-flattening](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/subobjects#subobjects-auto-flattening)
- [Built-in ECS template](https://github.com/elastic/elasticsearch/blob/main/x-pack/plugin/core/template-resources/src/main/resources/ecs%40mappings.json)
- Skill detail: [reference.md](reference.md), [examples.md](examples.md)
