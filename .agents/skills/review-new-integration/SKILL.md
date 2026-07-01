---
name: review-new-integration
description: >-
  Full code review of a pull request that adds a new package to elastic/integrations.
  Covers README auto-generation setup, sample_event.json, ECS pipeline mapping correctness
  (event.reference, host.domain semantics, event.kind, deprecated fields), pipeline/system/static
  test coverage, format_version vs Kibana condition alignment, dashboard export hygiene, and field
  definitions. Use when asked to review a new integration PR, a new package submission, or when
  checking if a community integration follows elastic-package conventions.
compatibility: Requires gh CLI and internet access to fetch live how-to guides.
allowed-tools: WebFetch Bash Read
---

# Review a New Integration PR

## 1. Gather context

```bash
gh pr view <NUMBER> --repo elastic/integrations \
  --json title,body,author,baseRefName,headRefName,state,additions,deletions,changedFiles,labels

gh pr diff <NUMBER> --repo elastic/integrations
```

## 2. How-to guides — always fetch live content

The guides below change as new stack versions ship. **Do not rely on cached knowledge.**
Fetch the upstream URL for any section you need to cite before quoting it.

| Topic | URL |
|---|---|
| README auto-generation | https://github.com/elastic/elastic-package/blob/main/docs/howto/add_package_readme.md |
| Static tests | https://github.com/elastic/elastic-package/blob/main/docs/howto/static_testing.md |
| Pipeline tests | https://github.com/elastic/elastic-package/blob/main/docs/howto/pipeline_testing.md |
| System tests | https://github.com/elastic/elastic-package/blob/main/docs/howto/system_testing.md |
| Create a package | https://github.com/elastic/elastic-package/blob/main/docs/howto/create_new_package.md |
| format_version compatibility | https://github.com/elastic/elastic-package/blob/main/docs/howto/format_version.md |
| Kibana version constraints | https://github.com/elastic/elastic-package/blob/main/docs/howto/stack_version_support.md |
| Dashboard export | https://github.com/elastic/elastic-package/blob/main/docs/howto/make_dashboards_editable.md |

## 3. Review checklist

Work through every section. Classify each finding as **Blocker**, **Should-fix**, or **Minor**.

### 3.1 README

- [ ] `_dev/build/docs/README.md` **template exists** — this is the file developers edit.
- [ ] `docs/README.md` is **auto-generated**: starts with the elastic-package header and must not be hand-written.
- [ ] Template uses `{{ fields "<data_stream>" }}` to render the field table.
- [ ] Template uses `{{ event "<data_stream>" }}` to embed a sample event (requires `sample_event.json`).

A PR that ships only `docs/README.md` with no template → **Blocker**.

Reference: `add_package_readme.md`

### 3.2 Sample event

- [ ] `data_stream/<name>/sample_event.json` exists for every data stream.

Required by `{{ event }}` in the README template and by `elastic-package test static`.
Absence → **Blocker**.

Reference: `static_testing.md`, `add_package_readme.md`

### 3.3 Ingest pipeline — ECS correctness

- [ ] **`event.reference`** — must be a URL. Deduplication keys, IDs, or opaque strings are not valid. Use a custom field (e.g. `<package>.deduplication_key`) instead. → **Blocker**
- [ ] **`host.domain` / `host.name`** — ECS defines these as the asset running the Elastic Agent, not a monitored third-party domain. For threat/lookalike domains use `threat.indicator.domain`, `url.domain`, or a custom field. `related.hosts` is fine as a collector. → **Blocker**
- [ ] **`event.kind`** — `alert` is only for events requiring human attention. Routine operational events (DNS changes, domain added, integration status) must use `event.kind: event`. → **Should-fix**
- [ ] **`event.module`** — deprecated; `event.dataset` is the current standard. Drop the `set` processor. → **Minor**
- [ ] **`labels.*`** — `labels` is for free-form metadata tags. Structured identifiers (tenant ID, severity text) belong in `organization.id`, the appropriate ECS field, or a custom package field. → **Should-fix**
- [ ] **Redundant field copies** — e.g. a `labels.event_type` that duplicates `event.action`. Remove duplicates. → **Should-fix**
- [ ] **`ignore_failure: true` on Painless scripts** — silently swallows runtime errors; verify the script is genuinely non-critical before accepting. → **Minor**

Reference: `pipeline_testing.md`

### 3.4 Pipeline tests

- [ ] `data_stream/<name>/_dev/test/pipeline/` directory exists.
- [ ] At least one input file and a matching `*-expected.json` file are present.
- [ ] Fixtures cover a meaningful spread of event types.

Reference: `pipeline_testing.md`

### 3.5 System tests

- [ ] `data_stream/<name>/_dev/test/system/test-default-config.yml` exists.

For inputs that require an external live service (e.g. `http_endpoint`, cloud APIs), a `skip:` stanza with a reason and a tracking issue link is the minimum acceptable substitute:

```yaml
input: <input_type>
skip:
  reason: <why CI cannot run this>
  link: <issue URL>
```

Absence of both a real config and a `skip:` stanza → **Should-fix**.

Reference: `system_testing.md`

### 3.6 `format_version` vs Kibana version alignment

1. Fetch `format_version.md` (URL above) for the current support table — it changes as new stack versions ship.
2. Check: does the declared Kibana minimum match the lowest stack version the `format_version` actually supports?
3. Flag any unexplained gap (e.g. `format_version` supports 8.16+ but `kibana.version` starts at `^8.18.0` without a stated reason).
4. Check whether bumping to a newer `format_version` would drop currently-supported stack versions.

Reference: `format_version.md`, `stack_version_support.md`

### 3.7 Dashboard

- [ ] Dashboard JSON was exported via `elastic-package export dashboards`, not hand-crafted.
  - Signal of hand-crafting: all panel `references` point to a catch-all index pattern like `logs-*`.
- [ ] Dashboard references the package-specific data view.
- [ ] `manifest.yml` includes a `screenshots:` array (not just `icons:`).

Reference: `create_new_package.md`, `make_dashboards_editable.md`

### 3.8 Field definitions

- [ ] Every field set or renamed in the ingest pipeline is declared in `fields/*.yml`.
- [ ] ECS fields use `external: ecs` instead of inline type+description.
- [ ] Custom fields have clear `description:` values.

### 3.9 Package manifest

- [ ] `CODEOWNERS` entry present for `/packages/<name>`.
- [ ] `changelog.yml` has an entry for the initial version.
- [ ] `manifest.yml` has `type: community` in the `owner:` block for community packages.

## 4. Output format

Produce a review with four sections:

1. **Blockers** — must be resolved before merge.
2. **Should-fix** — strong recommendations; should be addressed in this PR.
3. **Minor / Nice-to-have** — low priority; can be follow-up issues.
4. **Questions for the author** — clarifications needed before judging certain findings.

For each finding include what is wrong and why it matters, a concrete fix or available options, and the relevant upstream how-to URL.
