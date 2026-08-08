# Vendor / integration `*target*` special cases

- **git HEAD:** `d43ff234d21161ef4cbbc25d56415e4aa72680d9`
- **generated (UTC):** 2026-05-13T15:48:54Z
- **deduplicated field hits:** 1953
- **unique packages with any hit:** 114
- **unique packages with vendor-namespaced `*target*` paths:** 60

## What was scanned

| Surface | Scope |
| --- | --- |
| `fields/**/*.yml` | Flat `- name: a.b.target...` and nested `- name:` stack paths containing `target`. |
| `elasticsearch/ingest_pipeline/*.{yml,yaml}` | `target_field`, `field`, `copy_from` values containing `target`. |
| `*_dev/test/pipeline/*expected.json` | Quoted dotted JSON keys containing `target` (truncated read). |

## Namespace classification

| `namespace_class` | Meaning |
| --- | --- |
| `vendor_root` / `vendor_namespaced` | First path segment matches the integration package slug (e.g. `okta.target`). |
| `ecs_top_level` | Starts with common ECS top-level field (e.g. `file.target_path`). |
| `other_vendor_or_nested` | Other dotted paths (nested vendor, transforms, rare shapes). |

## `suggest_bucket` (heuristic only)

Keyword-based guess for runtime `CASE` prioritisation — **not** a product mapping decision.

## Counts by namespace_class

- **other_vendor_or_nested:** 1323
- **vendor_root:** 531
- **ecs_top_level:** 99

## Machine-readable outputs

- All hits: [`vendor_target_special_cases.csv`](vendor_target_special_cases.csv)
- Triage playbook: [`../VENDOR_TARGET_ANALYSIS_PLAN.md`](../VENDOR_TARGET_ANALYSIS_PLAN.md)

## Packages with most distinct `field_path` values (top 25)

| package | distinct_field_paths |
| --- | ---: |
| google_secops | 67 |
| canva | 63 |
| sentinel_one | 62 |
| azure | 50 |
| aws | 48 |
| crowdstrike | 42 |
| jamf_protect | 37 |
| windows | 32 |
| jamf_pro | 31 |
| gcp | 27 |
| google_workspace | 27 |
| system | 26 |
| eset_protect | 22 |
| trellix_epo_cloud | 22 |
| o365 | 19 |
| osquery_manager | 19 |
| spycloud | 19 |
| cyberark_epm | 18 |
| m365_defender | 17 |
| cisco_duo | 16 |
| mongodb_atlas | 16 |
| tenable_io | 16 |
| microsoft_intune | 14 |
| okta | 13 |
| tanium | 13 |