# Integration Review: trivy

Reviewed as a **new package** (single changelog entry, version 0.1.0) with the `cloudsecurity_cdr` category — CDR field/pipeline/transform requirements apply.

## Automated Validation

- format: FAIL — `elastic-package format --fail-fast` reports `data_stream/vulnerability/_dev/test/pipeline/test-image-findings.log-expected.json` is not formatted. This is a generated snapshot; regenerate with `elastic-package format` before pushing (CI-owned artifact, not a source finding).
- lint: PASS
- check: PASS (package builds)
- test pipeline: SKIPPED (snapshot validation left to CI per review policy)
- test system: SKIPPED

---

## Package Root

### Manifest

**Issue 1: format_version below new-package standard**
**Severity:** 🟠 High
**Location:** `packages/trivy/manifest.yml` line 1

**Problem:** New packages must declare `format_version: "3.6.5"` (structure rubric / consistency rules `stream_manifest_root_duplication`). 3.4.2 predates the current spec baseline for new integrations.

**Recommendation:**
```yaml
format_version: "3.6.5"
```

**Issue 2: kibana.version admits versions below 9.4**
**Severity:** 🟠 High
**Location:** `packages/trivy/manifest.yml` line 16

**Problem:** New integrations must require Kibana 9.4 or later; `"^8.19.0 || ^9.1.0"` admits 8.19 and 9.1 installs. It also violates the repo constraint convention (caret on an intermediate range — `^8.19.0` makes the later range redundant; intermediate ranges use tilde). Nothing in this package requires an 8.x floor.

**Recommendation:**
```yaml
conditions:
  kibana:
    version: "^9.4.0"
```
Update the README line "Elastic Agent 8.19 or 9.1 and later" to match (see Documentation).

**Issue 3: owner.type community with an Elastic team owner**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/manifest.yml` line 36

**Problem:** `owner.github: elastic/security-service-integrations` is an Elastic team; repo convention (elastic/integrations#20381) requires `owner.type: elastic` for Elastic-owned packages. `community` mislabels published package metadata.

**Recommendation:**
```yaml
owner:
  github: elastic/security-service-integrations
  type: elastic
```

### Changelog

✅ *Reviewed — No actionable issues found.* (Single entry, `/pull/` link, version matches manifest.)

### Build Configuration

✅ *Reviewed — No actionable issues found.* (`git@v9.3.0` is the current standard pin; the pipeline-side counterpart is flagged under Pipeline.)

---

## Data Stream: `vulnerability`

### Manifest

✅ *Reviewed — No actionable issues found.* (All six vars are referenced by the stream template; no root-manifest duplication.)

Suggestion: `elasticsearch.index_template.mappings.subobjects: false` (line 93-96) is a non-standard data-stream setting used by only a handful of packages and is unexplained. If it exists to preserve the dotted vendor field names, add a comment; otherwise drop it — dotted names in `fields.yml` map fine with default settings.

### Input

✅ *Reviewed — No actionable issues found.* (Conditional `preserve_original_event` tag, `{{#each tags}}`, `forwarded`/`publisher_pipeline.disable_host` coupling, and processors passthrough all follow common input patterns.)

### Pipeline

**Issue 1: event.kind set to `event` instead of `state`**
**Severity:** 🟠 High
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 34

**Problem:** CDR vulnerability findings require `event.kind: state` (CDR pipeline requirements; the Kibana Findings page filters on the `state`/`vulnerability`/`info` combination). `event` breaks the Findings page classification.

**Recommendation:**
```yaml
  - set:
      tag: set_event_kind
      field: event.kind
      value: state
```

**Issue 2: observer.vendor never set**
**Severity:** 🟠 High
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 48

**Problem:** `observer.vendor` is a CDR Must-Have field for vulnerability findings (and required `constant_keyword` in the latest index for performance). Nothing in the pipeline or field files populates it; the Findings page and the latest index lose the vendor attribution.

**Recommendation:**
```yaml
  - set:
      tag: set_observer_vendor
      field: observer.vendor
      value: Trivy
```
and in `fields/ecs.yml`:
```yaml
- name: observer.vendor
  external: ecs
  type: constant_keyword
  value: Trivy
```

**Issue 3: resource.name missing for image scans**
**Severity:** 🟠 High
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 184

**Problem:** `resource.name` is a CDR Must-Have (default data-grid column). The pipeline copies it only from `resource.Name`, which image-scan reports emit as `resource: null` — those findings get `resource.id` (from `artifact.Reference`) but no `resource.name`.

**Recommendation:**
```yaml
  - set:
      tag: copy_resource_name
      copy_from: resource.Name
      field: resource.name
      ignore_empty_value: true
  - set:
      tag: set_resource_name_fallback
      copy_from: artifact.Reference
      field: resource.name
      ignore_empty_value: true
      if: ctx.resource?.name == null
```

**Issue 4: preserve_original_event option never produces event.original**
**Severity:** 🟠 High
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 26

**Problem:** The pipeline removes `message` unconditionally and never renames it to `event.original` (JSE00001). The final pipeline only *removes* `event.original` when the tag is absent — it does not create it. So the documented `preserve_original_event` option (and the system test that enables it) silently yields no `event.original`.

**Recommendation:**
```yaml
  - rename:
      tag: rename_message_to_event_original
      field: message
      target_field: event.original
      ignore_missing: true
      if: 'ctx.event?.original == null'
      description: >-
        Preserves the raw NDJSON finding line in event.original. The storage
        optimization final pipeline removes it when the preserve_original_event
        tag is not set.

  - remove:
      tag: remove_message
      field: message
      ignore_missing: true
```
(Place the rename before the `json` processor's merge step, parsing from `event.original` or keeping `message` as the json source until after the rename.)

**Issue 5: event.category and event.type set with `set` instead of `append`**
**Severity:** 🟠 High
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 38

**Problem:** `event.category` and `event.type` are ECS arrays; the standard (and CDR reference pattern) is `append`, not `set`.

**Recommendation:**
```yaml
  - append:
      tag: append_event_category
      field: event.category
      value: vulnerability
  - append:
      tag: append_event_type
      field: event.type
      value: info
```

**Issue 6: pipeline does not set ecs.version**
**Severity:** 🟠 High
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 3

**Problem:** New packages must set `ecs.version` in the pipeline matching the `build.yml` pin (`git@v9.3.0`); 44 of 47 comparable filestream packages do this. Without it, events carry the agent's own ECS version instead of the pinned 9.3.0.

**Recommendation:**
```yaml
processors:
  - set:
      tag: set_ecs_version
      field: ecs.version
      value: 9.3.0
      description: >-
        Sets the ECS version to the one pinned in _dev/build/build.yml.
```

**Issue 7: on_failure does not append preserve_original_event tag**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 270

**Problem:** The required three-step pipeline-level `on_failure` structure is error.message → event.kind → append `preserve_original_event` to `tags`. The third step is missing, so failed documents can lose the raw line.

**Recommendation:**
```yaml
on_failure:
  - set:
      tag: append_error_message
      field: error.message
      value: >-
        Processor '{{{ _ingest.on_failure_processor_type }}}'
        with tag '{{{ _ingest.on_failure_processor_tag }}}'
        in pipeline '{{{ _ingest.pipeline }}}'
        failed with message '{{{ _ingest.on_failure_message }}}'
  - set:
      tag: set_pipeline_error_to_event_kind
      field: event.kind
      value: pipeline_error
  - append:
      tag: append_preserve_original_event
      field: tags
      value: preserve_original_event
```

**Issue 8: UNKNOWN severity maps outside the CDR value set**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 239

**Problem:** Trivy emits `UNKNOWN` (present in the k8s fixture); lowercasing yields `unknown`, which is not one of the CDR-allowed `low|medium|high|critical|none`. The Findings page severity grouping mis-buckets these findings.

**Recommendation:**
```painless
if (ctx.vulnerability.Severity != null) {
  def sev = ctx.vulnerability.Severity.toLowerCase();
  if (sev == 'unknown') {
    sev = 'none';
  }
  ctx.vulnerability.severity = sev;
}
```

**Issue 9: related.* correlation fields not populated**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 188

**Problem:** CDR integrations must populate `related.*` for threat hunting. The pipeline sets nothing even though image digests are available in the data.

**Recommendation:**
```yaml
  - append:
      tag: append_related_hash
      field: related.hash
      copy_from: artifact.RepoDigests
      allow_duplicates: false
      if: ctx.artifact?.RepoDigests != null
```

**Issue 10: vulnerability.published_date (CDR UI field) not set**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 140

**Problem:** The CDR spec uses `vulnerability.published_date` (explicit `date` mapping required — not covered by `ecs@mappings`) for the Findings page. The package maps only `vulnerability.timeline.published`, so the UI field stays empty.

**Recommendation:**
```yaml
  - set:
      tag: copy_vulnerability_published_date
      copy_from: vulnerability.PublishedDate
      field: vulnerability.published_date
      ignore_empty_value: true
```
plus in `fields/fields.yml`:
```yaml
- name: vulnerability.published_date
  type: date
  description: Date the vulnerability was published.
```

**Issue 11: host.name not populated for entity correlation**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/data_stream/vulnerability/elasticsearch/ingest_pipeline/default.yml` line 160

**Problem:** `host.name` is a CDR Must-Have for entity correlation on vulnerability findings; the pipeline maps only `host.os.*`. The flattened report format defined in the README carries no host attribution.

**Recommendation:** extend the README's jq flattening example to include the scanning host and map it:
```yaml
  - set:
      tag: copy_host_name
      copy_from: scan.hostname
      field: host.name
      ignore_empty_value: true
```

### Field Mapping

**Issue 1: vulnerability.scanner.vendor not constant_keyword**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/data_stream/vulnerability/fields/ecs.yml` line 34

**Problem:** `vulnerability.scanner.vendor` is constant per integration; CDR requires `constant_keyword` for performance (also in the latest index).

**Recommendation:**
```yaml
- name: vulnerability.scanner.vendor
  external: ecs
  type: constant_keyword
  value: trivy
```

**Issue 2: non-ECS fields declared in ecs.yml**
**Severity:** 🔵 Low
**Location:** `packages/trivy/data_stream/vulnerability/fields/ecs.yml` line 20

**Problem:** `vulnerability.cve`, `vulnerability.title`, `vulnerability.status`, `vulnerability.package.*`, `vulnerability.timeline.*`, `k8s.namespace.name`, `k8s.deployment.name` are not ECS fields (verified against ECS v9.3.0 generated schema — none of these exist there, so `external: ecs` is correctly absent), but `ecs.yml` is reserved for ECS fields; custom definitions belong in `fields.yml`.

**Recommendation:** move those entries to `fields/fields.yml`, keeping the existing types and descriptions.

### Tests

**Issue 1: test-common-config.yml missing**
**Severity:** 🟠 High
**Location:** `packages/trivy/data_stream/vulnerability/_dev/test/pipeline/test-common-config.yml` line 1

**Problem:** Required by the tests rubric; it must carry `fields.tags: [preserve_original_event]` so pipeline tests exercise the preserved-original path.

**Recommendation:**
```yaml
fields:
  tags:
    - preserve_original_event
```

**Issue 2: no failure-scenario fixture**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/data_stream/vulnerability/_dev/test/pipeline/test-image-findings.log` line 1

**Problem:** Fixtures cover image and k8s branches, non-CVE IDs (GHSA, DSA), and severity variety — but no malformed-JSON line exercises the `on_failure` path (`error.message` + `event.kind: pipeline_error`), and no line exercises a missing `scan.time` (date-processor skip).

**Recommendation:** add a third fixture file `test-error-findings.log`:
```
not-a-json-line
{"scan":{},"artifact":{"Reference":"registry.example.com/team-a/webapp:13"},"vulnerability":{"VulnerabilityID":"CVE-2026-00001","Severity":"UNKNOWN","PkgName":"demo","InstalledVersion":"1.0"}}
```

---

## Transforms

✅ *Reviewed — No actionable issues found.* Destination index/alias, unique key (`vulnerability.id` + `resource.id` + `package.name` + `package.version` + `data_stream.namespace`), sort, 5m frequency, `event.ingested` sync, 90d retention on `@timestamp`, `unattended`, `fleet_transform_version`, and `data_stream.namespace: keyword` in the destination fields all match the CDR transform requirements.

Suggestions:
1. Once `event.kind: state` is set, add `filter: [{term: {event.kind: state}}]` to the transform source query per the CDR pattern, so non-state documents never enter the latest view.
2. After the `observer.vendor` fix, it flows into the destination index via the linked field files; keep the `constant_keyword` override there.

---

## Documentation

**Issue 1: unresolved TODO placeholder in README**
**Severity:** 🟡 Medium
**Location:** `packages/trivy/_dev/build/docs/README.md` line 10

**Problem:** `This integration is tested to be compatible with Trivy 0.68 #TODO: Check Version and later ...` — a literal build TODO ships into the rendered `docs/README.md` and the Kibana package page.

**Recommendation:**
```markdown
This integration is tested to be compatible with Trivy 0.68 and later scan reports in JSON format (`schema_version: 2`).
```
Also update line 37 (`Elastic Agent 8.19 or 9.1 and later`) to `Elastic Agent 9.4 and later` after the manifest constraint fix.

---

## Data Anonymization

✅ *Reviewed — No actionable issues found.* Fixtures use `registry.example.com`, `example-cluster`, `team-a-dev`; no real IPs, hostnames, or credentials.

---

## Cross-Domain Consistency

✅ *Reviewed — No additional issues beyond those listed.* `build.yml` pin vs missing pipeline `ecs.version` is covered under Pipeline Issue 6; README-to-package alignment under Documentation; all manifest vars are used by the template.

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 9 |
| 🟡 Medium | 9 |
| 🔵 Low | 1 |

**Total Actionable Items:** 19

**Verdict:** NEEDS_CHANGES
