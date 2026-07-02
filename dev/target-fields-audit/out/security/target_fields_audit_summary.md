# ECS `*.target.*` audit summary

- **git HEAD:** `d43ff234d21161ef4cbbc25d56415e4aa72680d9`
- **generated (UTC):** 2026-05-14T09:24:15Z
- **integration packages scanned:** 273
- **evidence rows (matches):** 1793

- **filter:** Only integrations whose root `packages/<name>/manifest.yml` includes the `security` category (Elastic catalog tag).

Prefixes scanned: `host.target.`, `user.target.`, `service.target.`, `entity.target.`

## Confidence labels

| Label | Meaning |
| --- | --- |
| **high** | At least one hit under **Tier A** (ingest pipeline YAML). Strongest signal that documents may receive these fields at ingest. |
| **medium** | Hits only under **Tier B** (field YAML). Declared schema; not proof the pipeline populates it. |
| **low** | Hits only under **Tier C** (Kibana JSON). Saved objects referencing field names; not ingest. |

If a package has multiple tiers, the label reflects the **strongest** tier present.

## Unique packages by tier and prefix

### Tier A — Pipeline

| matched_prefix | unique_packages |
| --- | --- |
| host.target. | 2 |
| user.target. | 27 |
| service.target. | 3 |
| entity.target. | 2 |

### Tier B — Fields

| matched_prefix | unique_packages |
| --- | --- |
| host.target. | 3 |
| user.target. | 11 |
| service.target. | 4 |
| entity.target. | 2 |

### Tier C — Kibana JSON

| matched_prefix | unique_packages |
| --- | --- |
| host.target. | 1 |
| user.target. | 7 |
| service.target. | 1 |
| entity.target. | 1 |

## Tier A — unique (package, data_stream) pairs

35

## Integrations with hits — full list

Every package under `packages/` that produced at least one evidence row, sorted by package name.

| package | confidence | tiers | rows_A | rows_B | rows_C | prefixes_seen |
| --- | --- | --- | --- | --- | --- | --- |
| amazon_security_lake | high | A+C | 14 | 0 | 3 | user.target |
| atlassian_bitbucket | high | A | 7 | 0 | 0 | user.target |
| atlassian_confluence | high | A | 16 | 0 | 0 | user.target |
| atlassian_jira | high | A | 10 | 0 | 0 | user.target |
| auditd | medium | B | 0 | 4 | 0 | user.target |
| auditd_manager | medium | B | 0 | 4 | 0 | user.target |
| aws | high | A+B | 6 | 4 | 0 | host.target, user.target, service.target, entity.target |
| box_events | high | A | 9 | 0 | 0 | user.target |
| canva | high | A+C | 6 | 0 | 1 | user.target |
| cisco_duo | high | A | 1 | 0 | 0 | user.target |
| crowdstrike | high | A | 7 | 0 | 0 | user.target |
| cyberarkpas | high | A | 14 | 0 | 0 | user.target |
| fim | medium | B | 0 | 4 | 0 | user.target |
| gcp | high | A+B | 5 | 4 | 0 | host.target, user.target, service.target, entity.target |
| github | high | A+C | 8 | 0 | 9 | user.target |
| google_workspace | high | A | 27 | 0 | 0 | user.target |
| hid_bravura_monitor | medium | B | 0 | 4 | 0 | user.target |
| hpe_aruba_cx | high | A+B | 1 | 1 | 0 | service.target |
| keycloak | high | A | 2 | 0 | 0 | user.target |
| mattermost | high | A+C | 13 | 0 | 1 | user.target |
| microsoft_sqlserver | high | A | 2 | 0 | 0 | user.target |
| mysql_enterprise | high | A+B | 2 | 2 | 0 | user.target |
| netskope | high | A | 1 | 0 | 0 | user.target |
| o365 | high | A | 11 | 0 | 0 | user.target |
| okta | high | A | 6 | 0 | 0 | user.target |
| osquery_manager | medium | B | 0 | 19 | 0 | host.target, user.target, service.target |
| pad | low | C | 0 | 0 | 11 | user.target |
| qnap_nas | high | A+B | 1 | 1 | 0 | user.target |
| security_detection_engine | low | C | 0 | 0 | 1466 | host.target, user.target, service.target, entity.target |
| sysmon_linux | medium | B | 0 | 4 | 0 | user.target |
| tenable_io | high | A | 9 | 0 | 0 | user.target |
| trend_micro_vision_one | high | A | 1 | 0 | 0 | user.target |
| vectra_detect | high | A+C | 13 | 0 | 4 | user.target |
| windows | high | A+B | 22 | 8 | 0 | user.target |
| zoom | high | A | 19 | 0 | 0 | user.target |
| zscaler_zpa | high | A | 6 | 0 | 0 | user.target |

## Totals

- **integration packages scanned:** 273
- **unique packages with any hit:** 36
- **unique packages with Tier A hit:** 28
