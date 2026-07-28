# Integration Review: gdacs

**PR:** https://github.com/elastic/integrations/pull/19290/
**Scope:** New package `gdacs` (version `0.0.1`, single changelog entry) — apply new-package standards.
**Domains reviewed:** manifest (1 root + 1 stream), changelog (1), build (1), input/CEL (1), pipeline (1), fields (3), tests (pipeline + system + mock), dashboard (1 + 1 search), docs (1)

---

## Automated Validation

- format: FAIL (`data_stream/events/fields/fields.yml` not formatted; `elastic-package format --fail-fast`)
- lint: PASS (SVR00004 skipped via `validation.yml`)
- check: PASS (SVR00004 skipped via `validation.yml`)
- test pipeline: SKIPPED (no elastic-package stack / Docker unavailable in this environment)
- test system: SKIPPED

---

## Package Root

### Manifest

**Issue 1: format_version too low for geo_shape**
**Severity:** 🟠 High
**Location:** `packages/gdacs/manifest.yml` line 1

**Problem:** Package declares `format_version: 3.5.8` but `gdacs.affected_area` is typed as `geo_shape` in fields. Per package-spec feature mapping, `geo_shape` requires `format_version` **>= 3.6.1**. `3.5.8` is both below that floor and not the current new-package standard (`3.4.2` when geo_shape is unused). At `3.6.0+`, pipeline `on_failure` structure is also enforced by `elastic-package check`.
**Recommendation:**
```yaml
format_version: 3.6.1
```
Then fix pipeline `on_failure` to the enforced 3-step structure (see Pipeline Issue 2) before re-running `elastic-package check`.

**Issue 2: Kibana version constraint not at new-package standard**
**Severity:** 🟠 High
**Location:** `packages/gdacs/manifest.yml` line 13

**Problem:** `conditions.kibana.version` is `"^9.3.1"` only. New packages should use `"^8.19.0 || ^9.1.0"` unless a CEL function or config option requires a higher floor. No CEL feature in this program was verified to require 9.3.1; the constraint unnecessarily excludes 8.19/9.1 agents.
**Recommendation:**
```yaml
conditions:
  kibana:
    version: "^8.19.0 || ^9.1.0"
```
If a real dependency on 9.3.1 is discovered during version matrix review, document it and set the minimum to that floor only.

**Issue 3: Icon title is placeholder text**
**Severity:** 🔵 Low
**Location:** `packages/gdacs/manifest.yml` line 23

**Problem:** Icon title is still `"Sample logo"`.
**Recommendation:**
```yaml
icons:
  - src: /img/gdacs-logo.svg
    title: GDACS logo
    size: 32x32
    type: image/svg+xml
```

### Changelog

✅ *Reviewed — No actionable issues found.*

### Build Configuration

**Issue 1: ECS pin below new-package standard**
**Severity:** 🟠 High
**Location:** `packages/gdacs/_dev/build/build.yml` line 3

**Problem:** ECS dependency is `git@v8.11.0`. New packages must pin `git@v9.3.0`, matching pipeline `ecs.version: 9.3.0`.
**Recommendation:**
```yaml
dependencies:
  ecs:
    reference: "git@v9.3.0"
```

---

## Data Stream: `events`

### Manifest

**Issue 1: Missing enable_request_tracer variable**
**Severity:** 🟡 Medium
**Location:** `packages/gdacs/data_stream/events/manifest.yml` line 10

**Problem:** CEL streams should expose a data-stream-level `enable_request_tracer` variable (default `false`) and wire it in `cel.yml.hbs`. It is absent, so operators cannot enable HTTP tracing for debugging.
**Recommendation:**
```yaml
      - name: enable_request_tracer
        type: bool
        title: Enable request tracing
        multi: false
        required: false
        show_user: false
        default: false
        description: >-
          The request tracer logs requests and responses to the agent's local
          file-system for debugging configurations. Enabling this request
          tracing disables system testing. For security reasons, we recommend
          that you disable this option after you finish debugging.
```

### Input

**Issue 1: Handlebars inside CEL program block**
**Severity:** 🔴 Critical
**Location:** `packages/gdacs/data_stream/events/agent/stream/cel.yml.hbs` line 27

**Problem:** The `program:` block contains `{{#if country}}` / `{{/if}}`. Handlebars inside `program` is prohibited — it breaks CEL compilation predictability and must be expressed as CEL over `state`.
**Recommendation:** Always pass `country` into `state` (empty string when unset), and branch in CEL:
```yaml
state:
  event_types: '{{event_types}}'
  alert_levels: '{{alert_levels}}'
  page_size: {{page_size}}
  lookback_hours: {{lookback_hours}}
  country: '{{country}}'

program: |
  (
    state.?country.orValue("") != "" ?
      {"country": [state.country]}
    :
      {}
  ).as(countryParams,
    request(
      "GET",
      state.url.trim_right("/") + "/events/geteventlist/SEARCH?" + {
        "eventlist": [state.event_types],
        "alertlevel": [state.alert_levels],
        "pageSize": [string(state.page_size)],
        "pageNumber": [string(state.?cursor.page_number.orValue(1))],
        "fromDate": [state.?cursor.from_date.orValue(
          (now - duration(string(state.lookback_hours) + "h")).format("01/02/2006")
        )],
        "toDate": [state.?cursor.to_date.orValue(now.format("01/02/2006"))],
      }.with(countryParams).format_query()
    ).do_request().as(resp,
      // ... rest of program unchanged ...
    )
  )
```

**Issue 2: Cursor writes last_poll_date but never reads it**
**Severity:** 🟠 High
**Location:** `packages/gdacs/data_stream/events/agent/stream/cel.yml.hbs` line 131

**Problem:** Empty and 204 paths set `cursor.last_poll_date`, but the next request always falls back to `lookback_hours` for `fromDate` because nothing reads `last_poll_date`. After a full page walk, the next interval also keeps an advanced `page_number` until an empty page clears the cursor. Net effect: repeated full-lookback refetches (duplicates papered over by fingerprint) and wasted empty page requests. Concrete dead field + broken incremental windowing.
**Recommendation:** On pagination complete / empty / 204, advance the date window and reset page number:
```cel
state.with({
  "events": [],
  "want_more": false,
  "cursor": {
    "page_number": 1,
    "from_date": state.?cursor.to_date.orValue(now.format("01/02/2006")),
    "to_date": now.format("01/02/2006"),
  },
})
```
(Adjust if the API’s `fromDate`/`toDate` semantics need an exclusive lower bound or lag buffer.)

**Issue 3: Missing redact.fields**
**Severity:** 🟡 Medium
**Location:** `packages/gdacs/data_stream/events/agent/stream/cel.yml.hbs` line 5

**Problem:** No `redact.fields` key. Even with no secrets, CEL templates should set `redact.fields: ~`.
**Recommendation:**
```yaml
resource.url: {{url}}
resource.timeout: 120s
redact.fields: ~
```

**Issue 4: Missing request tracer wiring**
**Severity:** 🟡 Medium
**Location:** `packages/gdacs/data_stream/events/agent/stream/cel.yml.hbs` line 1

**Problem:** No `resource.tracer` / `enable_request_tracer` block at data-stream level.
**Recommendation:**
```yaml
resource.tracer:
  enabled: {{enable_request_tracer}}
  filename: "../../logs/cel/http-request-trace-*.ndjson"
  maxsize: 5
  maxbackups: 5
```

### Pipeline

**Issue 1: Trailing remove of event.original**
**Severity:** 🟠 High
**Location:** `packages/gdacs/data_stream/events/elasticsearch/ingest_pipeline/default.yml` line 20

**Problem:** Pipeline removes `event.original` when `preserve_original_event` is absent. This pattern is prohibited for new packages; storage optimization is handled by a separate final pipeline.
**Recommendation:** Delete this processor entirely:
```yaml
  # DELETE the following processor block (lines 20-24):
  # - remove:
  #     tag: remove_event_original
  #     field: event.original
  #     if: "!ctx.tags.contains('preserve_original_event')"
  #     ignore_missing: true
```

**Issue 2: on_failure structure wrong for new packages**
**Severity:** 🟠 High
**Location:** `packages/gdacs/data_stream/events/elasticsearch/ingest_pipeline/default.yml` line 506

**Problem:** Pipeline-level `on_failure` sets `event.kind` before appending `error.message`, uses double-brace Mustache, and omits appending `preserve_original_event` to `tags`. New packages require the exact 3-step structure (error.message → event.kind → tags), and `format_version` 3.6.1 will enforce it.
**Recommendation:**
```yaml
on_failure:
  - append:
      field: error.message
      value: >-
        Processor '{{{ _ingest.on_failure_processor_type }}}'
        {{{#_ingest.on_failure_processor_tag}}}with tag '{{{ _ingest.on_failure_processor_tag }}}'
        {{{/_ingest.on_failure_processor_tag}}}failed with message '{{{ _ingest.on_failure_message }}}'
  - set:
      field: event.kind
      value: pipeline_error
  - append:
      field: tags
      value: preserve_original_event
      allow_duplicates: false
```

**Issue 3: ecs.version pinned to 8.11.0**
**Severity:** 🟠 High
**Location:** `packages/gdacs/data_stream/events/elasticsearch/ingest_pipeline/default.yml` line 422

**Problem:** New packages must set `ecs.version: 9.3.0` (and match `build.yml`).
**Recommendation:**
```yaml
  - set:
      tag: set_ecs_version
      field: ecs.version
      value: "9.3.0"
```

**Issue 4: event.category and event.type use set instead of append**
**Severity:** 🟠 High
**Location:** `packages/gdacs/data_stream/events/elasticsearch/ingest_pipeline/default.yml` line 436

**Problem:** `event.category` and `event.type` must be arrays populated with `append`, not `set`.
**Recommendation:**
```yaml
  - append:
      tag: append_event_category
      field: event.category
      value: threat
      allow_duplicates: false
  - append:
      tag: append_event_type
      field: event.type
      value: indicator
      allow_duplicates: false
```

**Issue 5: Missing CEL Agentless opening processors**
**Severity:** 🟡 Medium
**Location:** `packages/gdacs/data_stream/events/elasticsearch/ingest_pipeline/default.yml` line 3

**Problem:** CEL streams should start with Agentless metadata `remove` + collector-error `terminate` before JSE00001.
**Recommendation:**
```yaml
processors:
  - remove:
      tag: remove_agentless_metadata
      field:
        - organization
        - division
        - team
      ignore_missing: true
      if: >-
        ctx.organization instanceof String &&
        ctx.division instanceof String &&
        ctx.team instanceof String
  - terminate:
      tag: terminate_collector_error
      if: ctx.error?.message != null && ctx.message == null && ctx.event?.original == null
  - rename:
      tag: rename_message_to_event_original
      # ... existing JSE00001 ...
```

**Issue 6: Threat/indicator categorization is a poor semantic fit**
**Severity:** 🟡 Medium
**Location:** `packages/gdacs/data_stream/events/elasticsearch/ingest_pipeline/default.yml` line 436

**Problem:** Natural-disaster alerts are mapped to `event.category: threat` and `event.type: indicator`, which are threat-intel semantics. Values are ECS-legal but misleading for GDACS content.
**Recommendation:** Prefer `event.kind: event` (or keep `alert`) with types such as `info`, and drop `threat`/`indicator` unless product explicitly wants threat-intel framing:
```yaml
  - set:
      tag: set_event_kind
      field: event.kind
      value: event
  - append:
      tag: append_event_type
      field: event.type
      value: info
      allow_duplicates: false
```
(Omit `event.category` if no allowed value fits; do not force `threat`.)

### Field Mapping

**Issue 1: base-fields.yml missing required ECS constant entries**
**Severity:** 🟠 High
**Location:** `packages/gdacs/data_stream/events/fields/base-fields.yml` line 1

**Problem:** New packages require exactly six `external: ecs` entries: `data_stream.type`, `data_stream.dataset`, `data_stream.namespace`, `event.module`, `event.dataset`, `@timestamp`, with constant values on `event.module` / `event.dataset`. Current file uses plain types/descriptions, omits `event.module`/`event.dataset`, and places `input.type` here (belongs in `agent.yml` for CEL).
**Recommendation:**
```yaml
- name: data_stream.type
  external: ecs
- name: data_stream.dataset
  external: ecs
- name: data_stream.namespace
  external: ecs
- name: event.module
  external: ecs
  type: constant_keyword
  value: gdacs
- name: event.dataset
  external: ecs
  type: constant_keyword
  value: gdacs.events
- name: '@timestamp'
  external: ecs
```
Add `packages/gdacs/data_stream/events/fields/agent.yml` for `input.type` if needed.

**Issue 2: ECS geo and event.modified declared as custom fields**
**Severity:** 🟠 High
**Location:** `packages/gdacs/data_stream/events/fields/fields.yml` line 1

**Problem:** `event.modified`, `geo.country_iso_code`, `geo.country_name`, `geo.location`, and `geo.name` are ECS fields but declared in `fields.yml` without `external: ecs`. `geo.location` is a `geo_point` and must be declared correctly as ECS.
**Recommendation:** Move to `ecs.yml`:
```yaml
- external: ecs
  name: event.modified
- external: ecs
  name: geo.country_iso_code
- external: ecs
  name: geo.country_name
- external: ecs
  name: geo.location
- external: ecs
  name: geo.name
```
Remove the hand-rolled `geo.location.coordinates` / `geo.location.type` object fields unless a concrete mapping failure requires them.

**Issue 3: fields.yml fails elastic-package format**
**Severity:** 🟡 Medium
**Location:** `packages/gdacs/data_stream/events/fields/fields.yml` line 34

**Problem:** `elastic-package format --fail-fast` fails on folded description wrapping in this file (and related manifest description folding).
**Recommendation:** Run:
```bash
cd packages/gdacs && elastic-package format
```

### Tests

**Issue 1: test-common-config missing preserve_original_event tag**
**Severity:** 🟠 High
**Location:** `packages/gdacs/data_stream/events/_dev/test/pipeline/test-common-config.yml` line 1

**Problem:** Pipeline test common config must include `fields.tags: [preserve_original_event]` so fixtures exercise `event.original` retention.
**Recommendation:**
```yaml
fields:
  tags:
    - forwarded
    - gdacs-events
    - preserve_original_event
```

**Suggestions**
1. After fixing the cursor windowing bug, re-run system tests and regenerate `sample_event.json` / expected pipeline output under ECS 9.3.0.

---

## Dashboards

✅ *Reviewed — No actionable issues found.*
(Dataset filter `data_stream.dataset = gdacs.events` present; Lens panels used. By-reference saved search is excluded via `validation.yml` SVR00004 — not flagged per review rules.)

---

## Documentation

**Issue 1: Docs understate fingerprint identity for geometry child docs**
**Severity:** 🟡 Medium
**Location:** `packages/gdacs/_dev/build/docs/README.md` line 22

**Problem:** Docs say dedup uses `{event_id}-{episode_id}`, but the pipeline includes `geometry_id` for TC geometry child documents.
**Recommendation:**
```markdown
- Deduplicates events using a fingerprint of `{event_id}-{episode_id}` (and `{geometry_id}` for tropical-cyclone geometry child documents)
```

**Issue 2: Field descriptions use Latinisms flagged by Vale**
**Severity:** 🔵 Low
**Location:** `packages/gdacs/data_stream/events/fields/fields.yml` line 47

**Problem:** Vale reports `e.g.` / `etc.` in field and manifest descriptions (CI style checker).
**Recommendation:** Replace with "for example" / "and so on" in affected descriptions, e.g.:
```yaml
      description: Human-readable event name (for example, "Earthquake in Myanmar").
```

---

## Cross-Domain Consistency

**Issue 1: build.yml ECS pin and pipeline ecs.version are aligned to each other but both stale**
**Severity:** 🟠 High
**Location:** `packages/gdacs/_dev/build/build.yml` line 3

**Problem:** Both use 8.11.0, so they are mutually consistent, but new-package standard requires 9.3.0 on both sides. Covered above; listed here as the cross-file requirement to update together.
**Recommendation:**
```yaml
# build.yml
dependencies:
  ecs:
    reference: "git@v9.3.0"

# default.yml
- set:
    tag: set_ecs_version
    field: ecs.version
    value: "9.3.0"
```

**Issue 2: Manifest preserve_original_event text contradicts prohibited pipeline remove**
**Severity:** 🟡 Medium
**Location:** `packages/gdacs/data_stream/events/manifest.yml` line 58

**Problem:** Variable description says if disabled, `event.original` is not included. That matches the prohibited pipeline remove. After removing that processor, update the description to match final-pipeline behavior.
**Recommendation:**
```yaml
        description: >-
          Preserves a raw copy of the original event in `event.original`.
```

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 12 |
| 🟡 Medium | 8 |
| 🔵 Low | 2 |

**Total Actionable Items:** 23

**Verdict:** NEEDS_CHANGES
