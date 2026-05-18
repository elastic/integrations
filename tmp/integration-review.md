# Integration review — `packages/hackerone`

**Scope:** Full package review (new package, `version: 0.1.0`, single `report` data stream, CEL input, transform `latest_report`, single dashboard).

**Validation run:**
- `elastic-package format --fail-fast` — clean
- `elastic-package lint` — `SVR00002` skipped via `validation.yml` (excluded by package author; not a review concern)
- `elastic-package check` — clean (build succeeds)

---

## Pipeline (`data_stream/report/elasticsearch/ingest_pipeline/default.yml`)

### Repeated `foreach` over the same array — `domain:pipeline`
- **Severity:** LOW
- **Location:** `data_stream/report/elasticsearch/ingest_pipeline/default.yml:383-426`
- **Problem:** Four sequential `foreach` processors iterate `hackerone.report.relationships.bounties.data` to convert `amount`, `bonus_amount`, `awarded_amount`, and `awarded_bonus_amount` to `double`. Each pass walks the array again. With many bounties this multiplies the pipeline cost unnecessarily, and the four blocks make this section harder to maintain.
- **Recommendation:** Collapse into a single `foreach` whose inner processor is a `script` (or chained `convert`s by reusing one foreach with multiple sub-processors via a small Painless script):

```yaml
- script:
    lang: painless
    tag: convert_bounty_amounts
    if: ctx.hackerone?.report?.relationships?.bounties?.data instanceof List
    description: Convert bounty numeric attributes to double in a single pass.
    source: |-
      List rows = (List) ctx.hackerone.report.relationships.bounties.data;
      for (def row : rows) {
        if (!(row instanceof Map)) continue;
        Map a = row.attributes instanceof Map ? (Map) row.attributes : null;
        if (a == null) continue;
        for (String k : ['amount','bonus_amount','awarded_amount','awarded_bonus_amount']) {
          if (a.get(k) != null) {
            a[k] = Double.parseDouble(String.valueOf(a[k]));
          }
        }
      }
```

---

## Fields (`data_stream/report/fields/fields.yml`, `elasticsearch/transform/latest_report/fields/fields.yml`)

### `custom_remediation_guidance.author.created_at` typed as `keyword` instead of `date` — `domain:fields`
- **Severity:** HIGH
- **Location:** `data_stream/report/fields/fields.yml:723-724` and `elasticsearch/transform/latest_report/fields/fields.yml:723-724`
- **Problem:** Every other `created_at` in this schema (50+ occurrences) is `type: date`. This single occurrence — author of the `custom_remediation_guidance` block — is declared as `keyword`. The HackerOne API returns ISO‑8601 timestamps in this field (sample: `"2020-10-22T11:22:05.402Z"`). Storing it as `keyword` breaks date sorting, range queries, and Lens/ES|QL date semantics, and creates an inconsistent type for a field with the same role across the schema. Both the data stream and the transform copy of `fields.yml` carry the bug.
- **Recommendation:**

```yaml
- name: created_at
  type: date
```

Apply identically in both files. The two `fields.yml` files are duplicates today, so any divergence between them is also a `domain:consistency` concern.

### Orphan field declaration `hackerone.report.attributes.weaknesses` — `domain:fields`
- **Severity:** MEDIUM
- **Location:** `data_stream/report/fields/fields.yml:39-41` and `elasticsearch/transform/latest_report/fields/fields.yml:39-41`
- **Problem:** `weaknesses` is declared on `hackerone.report.attributes` but no processor in `default.yml` reads or writes it; weakness data is sourced from `relationships.weakness.data.attributes.*`. Field declarations should describe data the pipeline actually produces. The vague description ("Alternate weakness identifiers as delivered on certain payloads") suggests speculation, not observed payload content.
- **Recommendation:** Remove the field from both `fields.yml` copies until a payload is shown to populate it; if a payload variant truly exists, add a pipeline processor that lifts it into a normalised location and keep the declaration.

```yaml
# delete the following from both fields.yml files
- name: weaknesses
  type: keyword
  description: Alternate weakness identifiers as delivered on certain payloads.
```

### `hackerone.report.attributes.title` description is misleading — `domain:fields`
- **Severity:** LOW
- **Location:** `data_stream/report/fields/fields.yml:18-20` and the transform copy at the same line
- **Problem:** Description reads "Report title mirrored alongside ECS message", but the pipeline copies the title into `message` (line 96-99 of the pipeline). The current wording suggests an external mirror; users grepping for the field have no hint it is also surfaced as `message`.
- **Recommendation:**

```yaml
- name: title
  type: keyword
  description: Report title. Also copied to ECS `message`.
```

---

## Input (`data_stream/report/agent/stream/cel.yml.hbs`)

### Error message conflates "non-object body" with "JSON parse failure" — `domain:input`
- **Severity:** MEDIUM
- **Location:** `data_stream/report/agent/stream/cel.yml.hbs:115-128`
- **Problem:** The decode chain wraps the parse in `try(resp.Body.decode_json())` and binds the result to `body`, then probes object-ness with `is_error(body.with({}))`. When parsing fails, `body` is itself an error value, the probe is true, and the same single-object error event is emitted with message `"GET /v1/reports: Response is not a JSON object"`. That phrasing misleads operators investigating an outage where HackerOne returns truncated bytes or a transient HTML 5xx. The agent's request tracer and pipeline `error.message` are the only diagnostic surface here, so wording matters.
- **Recommendation:** Distinguish the two cases at the bind site:

```cel
try(resp.Body.decode_json()).as(body,
  is_error(body) ?
    {
      "events": {
        "error": {
          "message": "GET /v1/reports: failed to decode JSON response body",
        },
      },
      "want_more": false,
      "next_link": "",
      "url": state.url,
    }
  : !(type(body) == map) ?
    {
      "events": {
        "error": {
          "message": "GET /v1/reports: Response is not a JSON object",
        },
      },
      "want_more": false,
      "next_link": "",
      "url": state.url,
    }
  :
    // existing success branch
)
```

The `is_error(body.with({}))` idiom is functionally correct but shadows the parse-error case, which deserves its own branch.

### `preserve_original_event` manifest variable does not gate preservation — `domain:input` (cross-cuts `domain:pipeline`)
- **Severity:** MEDIUM
- **Location:** `data_stream/report/manifest.yml:106-112`, `data_stream/report/agent/stream/cel.yml.hbs:202-204`, `data_stream/report/elasticsearch/ingest_pipeline/default.yml:23-35`
- **Problem:** The manifest exposes `preserve_original_event` (default `false`) and the CEL template adds the `preserve_original_event` tag only when the user toggles it on. However, the pipeline unconditionally renames `message` → `event.original` (line 23-29) and never has a trailing `remove` keyed off the tag. As a result, `event.original` is always preserved on every document, regardless of the manifest setting, and the manifest variable's only effect is to add a tag. Users who set it to `false` to reduce index size or sensitive content exposure will be surprised to find the raw payload still present.
- **Recommendation:** Pick one of:
  1. Honour the toggle by adding a final pipeline cleanup processor that removes `event.original` when the tag is absent:

```yaml
- remove:
    field: event.original
    tag: remove_original_when_not_preserved
    ignore_missing: true
    if: ctx.tags == null || !(ctx.tags.contains('preserve_original_event'))
```

  Make sure this runs after every consumer of `event.original` (the JSON parse step at line 36-45 already happened, so end-of-pipeline is safe).

  2. Remove the `preserve_original_event` manifest variable and its tag emission from `cel.yml.hbs`, and document that the raw report is always retained on `event.original`.

Either path is acceptable; the current state lies to the user.

---

## Tests (`data_stream/report/_dev/test`)

✅ *Reviewed — No actionable issues found.*

(Pipeline fixture covers the four meaningful state buckets — `new`, `triaged`, `informative`, `resolved` — exercises the empty-array, single-CVE, and multi-CVE `cve_ids` branches, and the `URL`/`DOWNLOADABLE_EXECUTABLES`/missing structured-scope paths. System test asserts hit count 4 across pagination + cursor-resume against the stream mock. Anonymisation: synthetic researcher names, `acme*` program handles, sample CVE references, and dummy token values.)

---

## Manifest & changelog (`manifest.yml`, `data_stream/report/manifest.yml`, `changelog.yml`)

✅ *Reviewed — No actionable issues found.*

(`format_version: "3.4.2"` and `conditions.kibana.version: "^8.19.0 || ^9.1.0"` are the new-package targets. Variable surface in the data stream manifest matches the CEL template, secrets are correctly scoped (`api_token_value: secret: true`), categories and policy template metadata are valid. Changelog has a single 0.1.0 entry consistent with `version` in the root manifest.)

---

## Build (`_dev/build/build.yml`)

✅ *Reviewed — No actionable issues found.*

(`ecs.reference: git@v9.3.0` matches the pipeline's `set: ecs.version: 9.3.0`.)

---

## Transform (`elasticsearch/transform/latest_report/`)

### Source query missing tier exclusion for cold/frozen indices — `domain:transform`
- **Severity:** MEDIUM
- **Location:** `elasticsearch/transform/latest_report/transform.yml:1-9`
- **Problem:** The transform queries `logs-hackerone.report-*` and only excludes `error.message`. Once the integration has been running long enough for ILM to roll backing indices to `data_cold` / `data_frozen`, the latest transform will keep paying I/O cost to scan those tiers every 5 minutes. Per the transform-guide, all non-trivial transforms should explicitly skip cold/frozen tiers in the source query.
- **Recommendation:**

```yaml
source:
  index:
    - "logs-hackerone.report-*"
  query:
    bool:
      must_not:
        - exists:
            field: error.message
        - terms:
            _tier:
              - data_frozen
              - data_cold
```

### `dest.index` versioning — `domain:transform`
- **Severity:** LOW
- **Location:** `elasticsearch/transform/latest_report/transform.yml:9-13`
- **Problem:** Destination is `logs-hackerone_latest.dest_report-v1`. The `_meta.fleet_transform_version` is independently tracked; bumping it does not change the destination index name. That is the standard for non-CDR transforms (CDR uses `<integration>.<type>_latest-<version>` because the version is part of the index name). The `move_on_creation` alias at `logs-hackerone_latest.report` gives consumers a stable read target. No issue with the current setup, but the `-v1` suffix is unusual and adds friction if the schema ever needs to be reset; document the upgrade procedure in code comments or be ready to bump to `-v2` consciously.
- **Recommendation (optional):** Add a comment near `dest.index` clarifying that the suffix is part of the destination naming contract and requires coordinated changes to be bumped:

```yaml
dest:
  # NOTE: a destination index version bump (e.g. v1 -> v2) requires the
  # transform to be reinstalled. Bump _meta.fleet_transform_version in lockstep.
  index: "logs-hackerone_latest.dest_report-v1"
```

---

## Dashboard (`kibana/dashboard/hackerone-5a10ec73-e781-4842-9a5e-93da0502f42b.json`)

✅ *Reviewed — No actionable issues found.*

(All panels are ES|QL-based against the bounded transform alias `logs-hackerone_latest.report`, which is why `validation.yml` excludes `SVR00002` — a documented exclusion that this review does not flag. Panel queries handle null severity via `CASE`, sort severity buckets by an explicit ordering column, and use `MV_SUM` correctly when summing the multi-valued bounty arrays.)

---

## Docs (`_dev/build/docs/README.md`)

✅ *Reviewed — No actionable issues found.*

(Compatibility, onboarding, troubleshooting, and reference sections are present and accurate. API endpoint reference matches the implementation.)

---

## Cross-domain consistency

- The two `fields.yml` files (data stream and transform) are byte-for-byte duplicates today; both carry the `created_at` HIGH typo above and the orphan `weaknesses` MEDIUM. Fix in lockstep.
- `build.yml` ECS pin (`git@v9.3.0`) matches the pipeline `set: ecs.version: 9.3.0`. ✓
- Manifest variables (`url`, `api_token_identifier`, `api_token_value`, `program_handles`, `inbox_ids`, `interval`, `initial_interval`, `page_size`, `state_filter`, `severity_filter`, `enable_request_tracer`, `tags`, `preserve_original_event`, `processors`, `http_client_timeout`, `proxy_url`, `ssl`) are all referenced in `cel.yml.hbs`. ✓
- `redact.fields` covers both secret keys placed into `state` (`api_token_identifier`, `api_token_value`). ✓

---

## Summary

| Severity | Domain | Title | File |
|----------|--------|-------|------|
| HIGH | fields | `custom_remediation_guidance.author.created_at` typed as `keyword` | `data_stream/report/fields/fields.yml`, `elasticsearch/transform/latest_report/fields/fields.yml` |
| MEDIUM | fields | Orphan field `hackerone.report.attributes.weaknesses` | `data_stream/report/fields/fields.yml`, `elasticsearch/transform/latest_report/fields/fields.yml` |
| MEDIUM | input | CEL conflates JSON parse failure with non-object body | `data_stream/report/agent/stream/cel.yml.hbs` |
| MEDIUM | input | `preserve_original_event` toggle does not gate preservation | `data_stream/report/manifest.yml`, `data_stream/report/agent/stream/cel.yml.hbs`, `data_stream/report/elasticsearch/ingest_pipeline/default.yml` |
| MEDIUM | transform | Source query missing `_tier` cold/frozen exclusion | `elasticsearch/transform/latest_report/transform.yml` |
| LOW | pipeline | Four sequential `foreach` over `bounties.data` | `data_stream/report/elasticsearch/ingest_pipeline/default.yml` |
| LOW | fields | `attributes.title` description does not mention `message` mirror | `data_stream/report/fields/fields.yml`, `elasticsearch/transform/latest_report/fields/fields.yml` |
| LOW | transform | Destination `-v1` suffix lacks an in-file note about bump procedure | `elasticsearch/transform/latest_report/transform.yml` |

## Verdict

**NEEDS_CHANGES** — one HIGH finding (`created_at` typed as `keyword`) blocks merge until corrected. Address the four MEDIUM findings before declaring the package GA; LOW findings are nice-to-have improvements.
