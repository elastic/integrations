---
name: migrate-required-input-dependency
description: >-
  Migrate an Elastic integration package from a legacy inline agent template to
  integrations with required input dependencies (`requires.input`, `streams[].package`).
  Gathers developer decisions on dataset naming, variable overrides, stack constraints,
  and tests before applying changes. Use when the user asks to migrate an integration to
  an input package, adopt `requires.input`, switch to `streams[].package`, or mentions
  required input dependencies. Requires elastic-package CLI.
compatibility: Requires `elastic-package` CLI. Designed for packages in elastic/integrations.
license: Apache-2.0
metadata:
  origin: elastic/integrations
  guide: elastic-package/docs/howto/migrate_integration_required_input_dependency.md
---

# migrate-required-input-dependency

Migrate an integration package to **integrations with required input dependencies**.

**Authoritative guide:** [HOWTO: Migrate an integration package to use required input dependencies](https://github.com/elastic/elastic-package/blob/main/docs/howto/migrate_integration_required_input_dependency.md) (`docs/howto/migrate_integration_required_input_dependency.md` in elastic-package on `main`)

At the start of Phase 1, read that guide from a local elastic-package checkout or from the URL above.

**Reference implementation:** [elastic/integrations#19719](https://github.com/elastic/integrations/pull/19719) (`packages/elastic_package_registry`). If `main` still shows legacy `input:` / inline collector templates, diff against the PR branch — do not copy pre-migration patterns from `main`.

## Rules

1. **Never edit package files until all decision gates in Phase 2 are answered** and you have presented a migration plan summary for confirmation.
2. Prefer **manifest variable overrides** over hardcoding values in `stream.yml.hbs` (hardcoding causes Fleet UI values that have no effect). For each variable, be explicit about **intent** per the [how-to guide Variable overrides section](https://github.com/elastic/elastic-package/blob/main/docs/howto/migrate_integration_required_input_dependency.md#variable-overrides): who sets it (integration author vs end user), whether it appears in Fleet, and whether the rendered agent template references it via `{{variable}}` rather than a hardcoded literal.
3. Set **`dataset:` on the data stream manifest** when the integration dataset must differ from the input package default — do not expose `data_stream.dataset` as a user variable unless the developer explicitly chooses that approach.
4. Keep local `stream.yml.hbs` limited to integration-owned template fragments only.
5. Run `elastic-package build` and `elastic-package test` after migration; use `elastic-package test policy --generate` only after the developer reviews generated expectations.
6. **Do not treat an unmigrated reference package on `main` as source of truth** — use the guide and PR #19719 when `packages/elastic_package_registry` is still legacy.

## Phase 1 — Discover the package

0. Confirm `elastic-package version` succeeds. If missing, stop and point to the [elastic-package install guide](https://github.com/elastic/elastic-package#getting-started). Version should be minimum v0.125.1.

1. Locate the integration package root (`manifest.yml`, `type: integration`).
2. Read the legacy setup:
   - `manifest.yml` — `policy_templates`, `format_version`, `conditions`, existing `requires`
   - Each data stream's `manifest.yml` and `agent/stream/*.hbs`
   - `fields/`, ingest pipelines, dashboards tied to the current dataset/index name
   - `_dev/test/config.yml`, policy/system/pipeline tests
3. Identify the target **input package** — search local `packages/` for `type: input`; if not found, check the package registry or ask the developer.
4. Diff legacy template vars/defaults against the input package manifest vars/defaults. Flag **input-only variables** (present on input, absent from legacy template) for Gate D.
5. Record the integration's **historical dataset** name(s) from policy tests, dashboards, `output_permissions`, or `data_stream.dataset` usage.

Present a short inventory: package name, data streams, legacy input type, proposed input package, variables that differ between legacy and input defaults, input-only variables, and common diffs (for example `hosts` path format).

## Phase 2 — Gather developer decisions (required before migration)

Use `AskQuestion` when available; otherwise ask conversationally. **Do not proceed to Phase 3 until every applicable gate below is resolved.**

### Gate 0 — Migration appropriateness

| Decision | Options / prompt |
| --- | --- |
| Suitable input package exists? | Yes — proceed · No — stop; recommend creating/publishing an input package first |
| Stack supports `format_version` ≥ 3.6? | Yes (stack 9.4+) · No — stop; plan stack upgrade or defer migration |
| Drop-in replacement assumed? | Confirm developer understands dataset, variable precedence, and policy expectations need explicit work |
| Multiple data streams | Same input package for all streams, or per-stream input packages (rare)? |

### Gate A — Scope and dependency

| Decision | Options / prompt |
| --- | --- |
| Input package | Which input package? (e.g. `prometheus_input`) |
| Input version pin | Exact version for `requires.input` (e.g. `"1.0.1"`) — use `elastic-package requires update` later to bump pins |
| Input version source | Published registry version · Unpublished — local `requires.source` for tests (build still fetches from registry unless using a [local registry](https://github.com/elastic/elastic-package/blob/main/docs/howto/local_package_registry.md)) |
| Data streams in scope | All data streams or a subset? |

### Gate B — Stack and format version

| Decision | Options / prompt |
| --- | --- |
| `format_version` | Default `3.6.5` unless developer specifies otherwise (minimum `3.6` for `requires.input`) |
| `conditions.kibana.version` | Required minimum for target stack? (guide example: `^9.4.4`) |
| Changelog type for stack drop | `enhancement` (typical) or `breaking-change`? |

### Gate C — Dataset management

Explain the risk: without an explicit dataset, documents may index under the **input package default** (e.g. `metrics-prometheus-*`).

| Decision | Options / prompt |
| --- | --- |
| Dataset name per data stream | Confirm historical name (e.g. `elastic_package_registry.metrics`) |
| Dataset strategy | **`dataset:` on data stream manifest (recommended)** · `data_stream.dataset` stream var · Auto-naming `package_name.stream_type` (only if historically correct) |

Default recommendation when unsure: **`dataset:` on the data stream manifest**.

### Gate D — Variable overrides (per variable)

Follow the [how-to guide Variable overrides section](https://github.com/elastic/elastic-package/blob/main/docs/howto/migrate_integration_required_input_dependency.md#variable-overrides). The rendered agent policy merges three layers: input package template defaults, integration `stream.yml.hbs`, and user-selected values. **Understanding which layer wins is critical.**

Include **every** variable from the input package manifest, even if absent from the legacy template. For `data_stream.dataset` on the input package, prefer manifest `dataset:` (Gate C), not a stream var override.

Variables can be declared at **stream level** (`streams[].vars` in the data stream manifest) or **input level** (`policy_templates[].inputs[].vars` in the package manifest). Input-level declarations are **promoted** to input-scoped variables. Use stream-level vars for per-data-stream tuning; use input-level vars when the override applies to every data stream that references the input package in that policy template.

For each variable, ask the developer to classify:

| Category | Meaning | Action |
| --- | --- | --- |
| **A — Integration-only** | Not in input package (e.g. `metrics_path`) | Add data stream var + reference in slim `stream.yml.hbs` via `{{variable}}` |
| **B — Override input default** | Input default differs from legacy behaviour (e.g. `rate_counters: false`) | Redeclare on `streams[].vars` with integration default |
| **C — Inherit** | Input default matches legacy (e.g. `use_types: true`) | Remove from local template and data stream manifest; do not redeclare or hardcode |

For each **A** and **B** variable, also confirm **variable intent**:

- **Who sets it:** integration author default vs end user at policy creation?
- **Fleet visibility:** `show_user: true` (user-facing) or `false` (advanced/hidden)?
- **Template binding:** referenced via `{{variable}}` in `stream.yml.hbs` or merged from the input template — not a hardcoded literal that bypasses Fleet?
- Default value (confirm against legacy template)

Category **C** variables inherit from the input package during bundling with `show_user: false` by default (advanced options in Fleet) — no explicit redeclaration needed.

**Explicitly ask** whether any variable should be **hardcoded in `stream.yml.hbs`**. If yes, warn that Fleet may still show the input default in the UI and user edits will not apply. Document the choice in the migration plan.

Present the variable matrix (name → category → intent → default → `show_user` → template binding) and get confirmation before editing.

### Gate E — Local development and tests

| Decision | Options / prompt |
| --- | --- |
| Local input `source` path | Relative path for `_dev/test/config.yml` (e.g. `../prometheus_input`) if input is unpublished — affects `elastic-package test` only |
| Policy tests | Confirm default (`vars: ~`) + overrides test; which vars to exercise in overrides? For multiple data streams sharing the same input type, policy expectations must list sibling streams as `enabled: false` |
| Policy expectation generation | Generate with `--generate` after plan approval, or defer until post-edit review? |
| Pipeline regression tests | Any known edge cases (null **and** missing fields)? |
| System test traffic | Does the service need synthetic traffic for metrics to appear? Which hit assertions need extending? |
| Fleet variable spot-check | Install built package in local stack and create a policy when possible — confirm Fleet-visible variables map to the rendered agent template and user edits take effect |

### Gate F — Collateral changes

| Decision | Options / prompt |
| --- | --- |
| Field mapping fixes | Any `long` → `double` or similar type corrections? Compare integration and input package `fields/` against collector output. **Check for breaking changes** if users may already have data indexed under the old type (mapping conflicts, reindex). Changelog: `bugfix` when the prior type was wrong and never worked; `breaking-change` when the correction is incompatible with existing indices. |
| Ingest pipeline re-test | Re-test against real collector output after input package switch? |
| Dashboard migration | Re-export for target stack Lens version · Validate only · N/A |
| Documentation | Manually document input dependency if `{{ inputDocs }}` is empty? |
| Package version bump | Minor bump typical for this migration? |

### Gate G — Plan confirmation

Summarize the full plan:

- Manifest changes (`requires.input`, `policy_templates`, `format_version`, `version` bump)
- Per data stream: remove legacy `input:` key, `streams[].package`, `dataset:`, category A/B `streams[].vars` only, slim template contents with `{{variable}}` bindings
- Variable intent matrix (categories A/B/C, Fleet visibility, template binding)
- Test and changelog changes

**Ask the developer to confirm the plan before making any edits.**

## Phase 3 — Execute migration

Apply changes in this order (see [migrate_integration_required_input_dependency.md](https://github.com/elastic/elastic-package/blob/main/docs/howto/migrate_integration_required_input_dependency.md)):

1. **`manifest.yml`** — `format_version`, `requires.input`, `policy_templates` → `package: <input>`, bump `version` per Gate F
2. **`data_stream/<name>/manifest.yml`** — set `dataset:`; replace legacy `input:` with `streams[].package`; add `template_path: stream.yml.hbs`; declare `streams[].vars` for categories A/B only; remove category C vars from local manifest
3. **`agent/stream/stream.yml.hbs`** — keep only integration-owned fragments; remove all collector config merged from the input package
4. **`_dev/test/config.yml`** — `policy`/`system` `requires.source` if Gate E applies
5. **Policy tests** — `test-default.yml`, `test-overrides.yml`; generate expectations only after developer approval; confirm every Fleet-visible variable maps to the rendered agent template and user-set values take effect; confirm every Fleet-visible variable maps to the rendered agent template and user-set values take effect
6. **Ingest pipelines** — re-run pipeline tests; add null and missing-field cases per Gate E/F
7. **System tests** — extend hit assertions and traffic fixtures per Gate E
8. **`changelog.yml`** — migration (`enhancement`), stack constraint, field fixes (`bugfix`) per Gate B/F
9. **Docs** — `elastic-package build` to regenerate docs; then manual input section in `_dev/build/docs/` if Gate F requires it

Do not bump unrelated packages or refactor outside migration scope.

## Phase 4 — Verify

From the package directory:

```bash
elastic-package build
elastic-package check
elastic-package test -v
```

If system tests need variants or traffic, run what the developer confirmed in Gate E.

### Verify variables in Fleet

Per the [how-to guide end-to-end verification step](https://github.com/elastic/elastic-package/blob/main/docs/howto/migrate_integration_required_input_dependency.md#8-verify-end-to-end), install the built package in a local stack and create an agent policy when possible:

1. **Fleet UI ↔ template binding** — every variable shown in Fleet should have a corresponding entry in the rendered agent template (`{{variable}}` reference or merged input-template binding). Flag any variable visible in the UI whose effective value is a hardcoded literal in `stream.yml.hbs` — user edits to that field will not apply.
2. **User overrides take effect** — change a Fleet-visible variable in the policy UI and confirm the rendered agent policy updates (policy test overrides should cover this; Fleet spot-check when a variable is not exercised in tests).
3. **Defaults match intent** — Fleet defaults for categories A/B match the integration manifest; category C inherited vars appear under advanced options unless explicitly redeclared.

Report:

- Build/test pass/fail with relevant log excerpts
- Policy output: `data_stream.dataset` and `output_permissions` index names (e.g. `metrics-<dataset>-ep`); confirm every Fleet-visible variable maps to the rendered agent template
- Fleet variable spot-check results (UI fields shown, template bindings, user override behaviour) when a local stack was available
- Dashboard spot-check on target stack when Gate F confirmed
- Platform gaps still relevant after migration:

| Gap | Tracking |
| --- | --- |
| Variables visible in UI but ignored by template | [elastic/integrations#19719](https://github.com/elastic/integrations/pull/19719) |
| No integration-level opt-out for input variables | Future enhancement |
| `{{ inputDocs }}` empty for `streams[].package` | [elastic/elastic-package#3696](https://github.com/elastic/elastic-package/issues/3696) |
| Dataset variable vs manifest `dataset:` field | [elastic/elastic-package#3713](https://github.com/elastic/elastic-package/pull/3713), [elastic/elastic-package#3719](https://github.com/elastic/elastic-package/pull/3719), [elastic/kibana#275312](https://github.com/elastic/kibana/pull/275312) |

### Verification checklist

Mark each item done or N/A:

- [ ] `format_version` ≥ 3.6.5 and `requires.input` pinned to a published input version
- [ ] `dataset:` explicitly set on the data stream manifest when it must differ from the input default
- [ ] Local `stream.yml.hbs` contains only integration-owned template fragments; integration-specific or overridden values use `{{variable}}` references, not hardcoded literals that bypass Fleet
- [ ] Variable intent is explicit per [Variable overrides](https://github.com/elastic/elastic-package/blob/main/docs/howto/migrate_integration_required_input_dependency.md#variable-overrides): manifest `vars` for categories A/B, inherit input defaults when acceptable (category C) — avoid silent template hardcoding that leaves misleading values in the Fleet UI
- [ ] Variable overrides use `streams[].vars`, not silent template hardcoding
- [ ] Legacy `input:` key removed; `streams[].package` in place
- [ ] `_dev/test/config.yml` declares `requires` for local input package during development
- [ ] Policy tests (default + overrides): expectations confirm every Fleet-visible variable maps to the rendered agent template and user-set values take effect — review dataset, overridden defaults, sibling streams (`enabled: false` where required); spot-check in Fleet when policy tests do not cover a variable
- [ ] System tests pass with realistic service traffic where needed
- [ ] Pipeline regression tests for edge cases found during migration
- [ ] Changelog entries: migration, stack constraint, field-mapping fixes (use `breaking-change` when mapping type updates affect existing indices)
- [ ] Docs manually updated if `{{ inputDocs }}` is empty
- [ ] Dashboards validated on the target stack version

## Decision quick-reference

```
Suitable input package + stack 3.6+?     → Gate 0 must pass before migrating
Legacy var differs from input default?  → B: redeclare on streams[].vars
Var only in integration template?       → A: add var + {{variable}} in slim template
Input default matches legacy?           → C: inherit; remove from local template/manifest
Input-only var on input package?        → Classify in Gate D (often C or N/A)
Per-stream vs all-streams override?     → streams[].vars vs policy_templates[].inputs[].vars
Variable intent unclear?                → Who sets it, Fleet visibility, template binding — see how-to Variable overrides
Fleet UI shows var but template ignores?→ Hardcoding anti-pattern; use manifest override or document intentional
Dataset must stay stable?               → dataset: on data stream manifest
Unpublished input package?              → _dev/test/config.yml requires.source (tests only)
Bump input pins later?                  → elastic-package requires update
```

## Anti-patterns

- Starting migration without Gate 0 — no suitable input package or unsupported stack
- Copying patterns from `packages/elastic_package_registry` on `main` while PR #19719 is unmerged
- Migrating without confirming dataset name → silent index rename
- Skipping `output_permissions` index name review in policy expectations
- Hardcoding overrides in `stream.yml.hbs` without developer acknowledgement → Fleet UI mismatch; variable shown in UI but user edits ignored
- Using hardcoded literals in `stream.yml.hbs` for values that should be Fleet-configurable — use `{{variable}}` and manifest `vars` instead
- Using `data_stream.dataset` as a user variable when `dataset:` field suffices
- Leaving legacy `input:` alongside new `streams[].package`
- Running `elastic-package test policy --generate` and committing expectations without developer review
- Leaving full collector config in local template after switching to `streams[].package`
- Skipping ingest pipeline re-test after collector output shape changes
- Assuming `requires.source` in test config satisfies `elastic-package build` (build still uses registry)
