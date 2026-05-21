# Integration Review: cisco_asa

**Scope:** cisco_asa — pipeline fix for 725007 unidirectional SSL termination message
**Package type:** existing
**Validation:** elastic-package format / build / lint / check / test pipeline — all PASS

---

## domain:pipeline

### [LOW] New grok pattern not anchored at end

**File:** `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:1101`

**Problem:** The added pattern `'^SSL session with ... terminated'` has a `^` start anchor but no `$` end anchor. The ingest-pipelines skill requires both `^` and `$` anchors on grok patterns to prevent partial-match scanning.

**Note:** The existing 725007 pattern on line 1100 also lacks a `$` anchor, as do all 725001 patterns (lines 1087-1088). This is a pre-existing consistency issue, and the new pattern deliberately mirrors the existing style. Severity is LOW for an existing package where all sibling patterns follow the same convention.

**Recommendation:** In a follow-up pass on the entire 725xxx block, add `$` anchors to all unanchored patterns. For the new pattern specifically:
```yaml
        - '^SSL session with %{NOTSPACE:_temp_.cisco.peer_type} %{DATA:_temp_.cisco.source_interface}:%{NOTSPACE:source.address}/%{NOTSPACE:source.port} terminated$'
```

---

## domain:changelog

### [LOW] Changelog uses placeholder PR link

**File:** `packages/cisco_asa/CHANGELOG.yml:6`

**Problem:** `link: https://github.com/elastic/integrations/pull/99999` is a development placeholder. `elastic-package lint` accepts it, but it must be replaced with the real PR number before merge.

**Recommendation:** Replace with the actual PR URL once the pull request is opened.

---

## domain:manifest

✅ *Reviewed — No actionable issues found.* Version correctly bumped 2.45.1 → 2.45.2 (patch, bugfix). `format_version: "3.0.3"` is acceptable for this existing package; no features in scope require a higher version.

---

## domain:tests

✅ *Reviewed — No actionable issues found.* New fixture line uses RFC 5737 documentation IP (198.51.100.10) and a synthetic `.internal` hostname. Expected output generated via `elastic-package test pipeline --generate` and verified passing.

---

## Summary

| Severity | Count | Addressed |
|----------|-------|-----------|
| CRITICAL | 0 | — |
| HIGH | 0 | — |
| MEDIUM | 0 | — |
| LOW | 2 | No (both deferred — pre-existing style consistency and placeholder PR link) |

## Verdict: APPROVED_WITH_SUGGESTIONS

Both LOW findings are cosmetic / pre-existing-style issues that do not affect correctness. The fix correctly addresses the root cause (missing grok pattern for unidirectional 725007 messages), is tested, and passes all automated validation.
