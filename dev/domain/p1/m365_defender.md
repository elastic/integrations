# m365_defender

## Product Domain

Microsoft Defender XDR (Extended Detection and Response) is a unified pre- and post-breach enterprise defense suite that coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications. Formerly known as Microsoft 365 Defender, it natively integrates signals from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Identity, Microsoft Defender for Cloud Apps, and Microsoft Purview Data Loss Prevention into a single cross-domain security platform.

At the operational level, Defender XDR correlates alerts from these workloads into incidents that represent attack stories spanning multiple stages and surfaces. Security analysts investigate incidents in the Defender portal, pivoting across device telemetry, identity sign-ins, email threats, cloud app activity, and automated response actions. Advanced Hunting and the Streaming API expose raw event tables for threat hunting and custom analytics, while the Microsoft Graph Security API surfaces normalized alerts and incidents for SIEM integration.

The platform's data model spans endpoint process, file, network, and registry events; identity authentication and directory queries; email delivery, attachment, and post-delivery security events; cloud app and audit activity; and vulnerability assessments from Defender for Endpoint. Organizations deploy Defender XDR as part of Microsoft 365 E5 or standalone licensing to gain centralized visibility, automated investigation and remediation, and cross-workload threat correlation.

The Elastic Microsoft Defender XDR integration ingests alerts, incidents, streaming events, and vulnerability assessments via Microsoft Graph Security API, Azure Event Hub, and the Defender for Endpoint API. Events are normalized to ECS-aligned fields for SIEM correlation, incident response, vulnerability management, and threat hunting in Elastic Security.

## Data Collected (brief)

- **Incidents** (`m365_defender.incident`): Correlated attack stories from Microsoft Graph Security API `/security/incidents`, including severity, status, classification, associated alerts, and evidence from Defender XDR, Endpoint, Office 365, Identity, Cloud Apps, and Purview DLP.
- **Alerts** (`m365_defender.alert`): Individual detections from Microsoft Graph Security API `/security/alerts_v2`, with threat categorization, severity, service source, and entity context (users, devices, files, IPs, URLs).
- **Events** (`m365_defender.event`): Advanced Hunting events streamed via Azure Event Hub from the Defender XDR Streaming API—covering alert evidence and info, device process/file/network/registry/logon events, email and Teams message events, identity logon and directory events, cloud app and audit activity, and UEBA behavior entities.
- **Vulnerabilities** (`m365_defender.vulnerability`): Software vulnerability assessments exported from Microsoft Defender for Endpoint API `/api/machines/SoftwareVulnerabilitiesExport`, with CVE details, affected software, device context, and risk scoring for vulnerability management workflows.

## Expected Audit Log Entities

Microsoft Defender XDR is a detection and telemetry platform, not a single audit-log product. The four data streams differ in audit semantics:

- **`event`** — Advanced Hunting tables streamed via Azure Event Hub; includes true audit-adjacent activity (`CloudAuditEvents`, `CloudAppEvents`, identity logon/query) plus endpoint, email, and behavior telemetry.
- **`alert`** — individual Graph Security API detections with typed `evidence[]` arrays and role metadata.
- **`incident`** — correlated attack stories embedding nested alert evidence plus SOC workflow fields (`assignedTo`, comments).
- **`vulnerability`** — Defender for Endpoint software-vulnerability inventory sync; actor/target audit semantics do not apply.

There is no unified vendor `actor`/`target` pair. Initiating principals map to ECS `user.*`, `process.*`, and `source.*`; acted-upon entities map to ECS `host.*`, `file.*`, `process.*`, `destination.*`, vendor `m365_defender.event.target.*`, or alert/incident `evidence.*`. **No ECS `user.target.*`, `host.target.*`, `service.target.*`, or `entity.target.*` fields are populated** (`dev/target-fields-audit/out/security/target_fields_audit.csv` — no rows). Target-fields audit classifies this package as **`strong_candidate`** with **`pipeline_actor=true`**, **`pipeline_entity_other=true`**, **`pipeline_dest_network=true`**, and **`pipeline_dest_identity=false`** (`dev/target-fields-audit/out/security/target_enhancement_packages.csv`).

**`event.action` coverage varies by stream.** The **`event`** stream maps vendor `ActionType` → `m365_defender.event.action.type` → ECS `event.action` on device, identity/cloud-app, and email/message sub-pipelines, with category-aware normalization (e.g. file `creation`/`deletion`, process `start`). Alert/behavior hunting tables and inventory snapshots (`DeviceInfo`, `IdentityInfo`) retain vendor action type without ECS mapping. **`alert`** and **`incident`** populate `event.action` as an array from nested evidence `detectionStatus` (`detected`, `prevented`) — detection outcome, not the alert title or MITRE category. **`vulnerability`** has no per-event action (posture inventory sync).

### Event action (semantic)

Defender XDR uses **`ActionType`** (Advanced Hunting) and **`detectionStatus`** (Graph alerts/incidents) as the primary operation verbs. The integration normalizes hunting `ActionType` values to lowercase hyphenated ECS `event.action` where sub-pipelines copy from `m365_defender.event.action.type`.

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| `logonsuccess`, `logonfailed` | authentication | high | `event.action` in `test-app-and-identity.log-expected.json`, `test-device.log-expected.json` | **`event`** — identity/device logon tables |
| `samr-query`, `dns-query`, `write-deployments` | data_access / administration | high | `samr-query`, `write-deployments`, `dns-query` fixtures (`test-app-and-identity.log-expected.json`) | **`event`** — identity query, cloud app activity |
| `update` | configuration_change | high | Cloud audit `ActionType: Update` → `event.action: update` (`test-cloud.log-expected.json`) | **`event`** — `CloudAuditEvents`; alternate ARM op in `m365_defender.event.properties_operation_name` (`Microsoft.Storage/storageAccounts/write`) unmapped |
| `processcreated`, `start`, `creation`, `deletion`, `modification`, `rename`, `load` | process / file / registry | high | Device pipeline normalizes file/registry/process `ActionType` to ECS-friendly verbs; `ProcessCreated` → `start` on cloud process (`test-cloud.log-expected.json`) | **`event`** — device + `CloudProcessEvents` (via `pipeline_device.yml`) |
| `dpapiaccessed`, `readprocessmemoryapicall`, `createremotethreadapicall`, `powershellcommand`, `dnsconnectioninspected`, … | detection / api_call | high | Raw vendor `ActionType` copied when not file/registry/process-normalized (`test-device.log-expected.json`) | **`event`** — endpoint telemetry and API-call events |
| `phish-zap`, `dpapiaccessed` (post-delivery) | detection / email | high | `ActionType: Phish ZAP` → `phish-zap` (`test-message.log-expected.json`); email post-delivery (`test-email.log-expected.json`) | **`event`** — email/message tables; vendor also retains `m365_defender.event.action.value`/`trigger`/`result` |
| `dataaggregation` | data_access | high | `CloudStorageAggregatedEvents` fixture (`test-cloud.log-expected.json`) | **`event`** — aggregated cloud storage metrics, not per-object CRUD |
| `SuspiciousPowerShellCommand` (vendor) | detection | high (vendor) | `ActionType` on `BehaviorInfo` → `m365_defender.event.action.type` only (`test-behavior.log-expected.json`) | **`event`** — UEBA behavior; **no** ECS `event.action` |
| Alert title / category (vendor) | detection | high (vendor) | `Title`, `Category` on `AlertInfo` (`test-alert.log-expected.json`); no `event.action` | **`event`** — hunting alert metadata |
| `detected`, `prevented` | detection | high | `event.action: ["detected"]` on alert fixtures; `prevented` on incident fixtures | **`alert`**, **`incident`** — evidence `detectionStatus`, not hunting `ActionType` |
| — | — | — | No `event.action` in `sample_event.json` or vulnerability fixtures | **`vulnerability`** — inventory sync; no meaningful per-event verb |

Inventory tables (`DeviceInfo`, `IdentityInfo`, `event.kind: asset`) and alert/behavior hunting metadata rows have **no per-event action** — they describe entity state or detection context, not an operation performed at ingest time.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `json.properties.ActionType` → `m365_defender.event.action.type` → `event.action` | yes (**device**, **app/identity**, **email/message**) | yes | `logonsuccess`, `samr-query`, `update`, `dpapiaccessed`, `phish-zap`, `start`, `creation`, … | no | `pipeline_device.yml:676-677`, `:2638-2694`; `pipeline_app_and_identity.yml:414-415`, `:1019-1032`; `pipeline_email.yml:264-265`, `:557-570`; fixtures above |
| Category-normalized overrides (`creation`, `deletion`, `modification`, `start`, `load`) | yes (**device** file/registry/process/driver) | yes | `creation`, `deletion`, `modification`, `rename`, `start`, `load` | no | `pipeline_device.yml:2638-2677` — maps vendor `FileCreated`/`ProcessCreated`/… to ECS-friendly verbs before lowercase/gsub |
| `json.properties.ActionType` → `m365_defender.event.action.type` (**alert/behavior** sub-pipeline) | **no** (vendor only) | n/a | `SuspiciousPowerShellCommand`, `ProcessCreated` (AlertEvidence) | **yes** | `pipeline_alert.yml:340-342` renames only; `test-behavior.log-expected.json`, `test-alert.log-expected.json` (AlertEvidence has `event.action: start` when routed through device pipeline for process events, but AlertInfo/BehaviorInfo lack ECS action) |
| `json.properties.OperationName` / `m365_defender.event.properties_operation_name` | no | n/a | `Microsoft.Storage/storageAccounts/write` | **yes** | Cloud audit fixture (`test-cloud.log-expected.json`); richer ARM API name than `ActionType: Update` |
| `json.properties.ActivityType` → `m365_defender.event.activity.type` | no | n/a | — | partial | Renamed in `pipeline_app_and_identity.yml:562-564`; parallel activity label, not copied to `event.action` |
| `m365_defender.event.action.value`, `.trigger`, `.result` | no | n/a | `Moved to quarantine`, `Automatic ZAP`, `Quarantined successfully` | partial | Email/message post-delivery (`pipeline_email.yml:410-420`); remediation detail, not primary verb |
| `json.evidence[].detectionStatus` → `event.action` | yes (**alert**, **incident**) | partial | `detected`, `prevented` | partial | `alert/default.yml:1475-1478`, `incident/default.yml` (same pattern); detection **outcome** per evidence item, not alert title (`m365_defender.alert.title`) or category |
| `m365_defender.alert.title` / `m365_defender.alert.category` | no | n/a | `Suspicious PowerShell command line`, `Execution` | **yes** | Alert/incident fixtures; title is human-readable detection name; category maps to `threat.tactic.name`, not `event.action` |
| `m365_defender.event.operation_name` (Event Hub envelope) | no | n/a | `Publish` | no | Streaming transport metadata on all hunting tables — not the security operation |
| — (**vulnerability**) | no | n/a | — | no | `vulnerability/default.yml` sets `event.category: vulnerability` only; `sample_event.json` has no `event.action` |

**Step 2b — per-stream check:**

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `event` | yes (device, identity, cloud, email, message); **no** (DeviceInfo, IdentityInfo, AlertInfo, BehaviorInfo) | yes (device/app_identity/email); **no** (alert/behavior sub-pipeline) | `m365_defender.event.action.type` ← `ActionType` | high | `test-device.log-expected.json`, `test-app-and-identity.log-expected.json`, `test-cloud.log-expected.json`, `test-message.log-expected.json`; gap: `test-behavior.log-expected.json`, AlertInfo rows in `test-alert.log-expected.json` |
| `alert` | yes (array) | yes | `evidence[].detectionStatus` | medium | `test-alert.log-expected.json`: `["detected"]`; alternate: `m365_defender.alert.title` |
| `incident` | yes (array) | yes | nested alert `evidence[].detectionStatus` | medium | `test-incident.log-expected.json`: `detected`, `prevented` |
| `vulnerability` | **no** | **no** | n/a — inventory sync | n/a | `sample_event.json`, `vulnerability/default.yml`; no vendor action field |

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| Endpoint initiating user | user | — | high | `InitiatingProcessAccountName` / `AccountName` / `RequestAccountName` → `user.name`, `user.domain`, `user.id` (SID); vendor `m365_defender.event.initiating_process.account_*` | **`event`** (device tables) — `administrator1` in `test-device.log-expected.json` |
| Identity / directory principal | user | — | high | `AccountName`, `AccountSid`, `AccountUpn`, `AccountObjectId` → `user.*` on `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents` | **`event`** — machine account `D2WXA1303R$` as actor on SAMR query (`test-app-and-identity.log-expected.json`) |
| Cloud app actor | user | — | high | `AccountId` / `AccountDisplayName` → `user.id`, `user.name` on `CloudAppEvents` | **`event`** — `Write Deployments` / Teams activity in `test-app-and-identity.log-expected.json` |
| Email / Teams sender | user | — | high | Sender fields → `email.from.address`, `user.email`, `user.name`; vendor `m365_defender.event.sender.*` | **`event`** — `test-email.log-expected.json`, `test-message.log-expected.json` |
| UEBA behavior subject | user | — | high | `AccountName` / `AccountSid` / `AccountObjectId` → `user.*` on `BehaviorEntities` | **`event`** — `test-behavior.log-expected.json` |
| Cloud workload process owner | user | — | high | `AccountName` → `user.name` (e.g. `root`) | **`event`** (cloud process) — `test-cloud.log-expected.json` |
| Initiating process | general | process | high | `InitiatingProcess*` → `process.*` and `m365_defender.event.initiating_process.*` (command line, hashes, parent) | **`event`** (device) — process actor alongside account when both present |
| Sensor / source host | host | — | high | `DeviceId` / `DeviceName` → `host.id`, `host.name`; identity events also set actor-side `host.ip` | **`event`** — sensor context, not the remote target on identity queries |
| Threat actor label | user | threat_group | medium | `actorDisplayName` → `m365_defender.alert.actor_display_name` / `m365_defender.incident.alert.actor_display_name` | **`alert`**, **`incident`** — adversary/threat-group name; null in most fixtures |
| SOC incident assignee | user | soc_analyst | medium | `assignedTo` → `source.user.name`, `source.user.email`, `related.user` | **`alert`**, **`incident`** — analyst owner, not attack actor (`test-incident.log-expected.json`: `KaiC@contoso.onmicrosoft.com`) |
| Alert/incident evidence user | user | — | high | `userEvidence`, `mailboxEvidence`, `processEvidence.userAccount`, device `loggedOnUsers` → `user.*`, `process.user.*`, `related.user` | **`alert`**, **`incident`** — `CDPUserIS-38411` in `test-alert.log-expected.json`; role (actor vs impacted) ambiguous without `roles` |
| Email alert sender | user | — | high | `p1_sender` / `p2_sender` / `senderIp` → `email.from.address`, `email.sender.address`, `source.ip` | **`alert`**, **`incident`** — Office 365 / MCAS email alerts in `test-incident.log-expected.json` |
| Identity asset snapshot | user | — | high | `IdentityInfo` rows (`event.kind: asset`) populate `user.*` / `m365_defender.event.account.*` | **`event`** — inventory snapshot, not an action actor |
| Vulnerability scanner | service | — | low | No human actor; `observer.vendor` / `vulnerability.scanner.vendor: Microsoft` | **`vulnerability`** — automated assessment only |

**`CloudAuditEvents`** fixtures expose client `source.ip` and `user_agent.original` but often lack an explicit user principal — actor is network-context only on those rows.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `user.name`, `user.id`, `user.domain`, `user.email`, `user.full_name` | Endpoint, identity, cloud-app, behavior principal | yes | yes | high | `pipeline_device.yml`, `pipeline_app_and_identity.yml`, `pipeline_cloud.yml`, `pipeline_behavior.yml`; `test-device.log-expected.json`, `test-app-and-identity.log-expected.json` |
| `process.*`, `process.parent.*`, `process.hash.*` | Initiating or evidence process | yes | yes | high | `pipeline_device.yml` ← `InitiatingProcess*`; alert/incident evidence script → `process.*` (`test-alert.log-expected.json`) |
| `process.user.name`, `process.user.id` | Process owner from evidence | yes | yes | high | Alert/incident pipeline from `processEvidence.userAccount` |
| `host.id`, `host.name`, `host.ip`, `host.hostname` | Sensor device / evidence device | yes | partial | high | ← `DeviceId`/`DeviceName`; evidence `deviceEvidence` → `host.*`; on identity events `host.*` is source sensor, not query target |
| `email.from.address`, `email.sender.address` | Email/Teams sender | yes | yes | high | Email/message pipelines; alert email evidence |
| `source.ip`, `source.geo.*` | Client IP on cloud audit, email sender, alert evidence | yes | yes | high | `CloudAuditEvents` fixture (`81.2.69.142`); `senderIp` on alert evidence |
| `source.user.name`, `source.user.email`, `source.user.domain` | SOC assignee (not threat actor) | yes | partial | high | ← `assignedTo` dissect (`incident/default.yml`, `alert/default.yml`); semantically analyst workflow, not attacker |
| `application.name` | SaaS workload label (Office 365, Active Directory, Microsoft Azure) | yes | n/a | high | ← `m365_defender.event.application` (`event/default.yml`); scope/context, not caller identity |
| `cloud.account.id`, `cloud.provider` | Tenant / cloud scope | yes | n/a | high | Alert/incident `tenantId`; device VM metadata; tenancy context, not actor |
| `related.user`, `related.hosts`, `related.ip`, `related.hash` | Correlation arrays | yes | partial | high | Aggregates users/hosts/IPs from evidence and events; does not distinguish actor vs target role |
| `m365_defender.event.initiating_process.*` | Rich initiating-process identity | yes (vendor) | n/a | high | Full vendor tree when ECS `process.*` is trimmed; `test-device.log-expected.json` |
| `m365_defender.event.account.*` | Identity account vendor copy | yes (vendor) | n/a | high | Parallel to ECS `user.*` on identity/cloud-app tables |
| `m365_defender.alert.actor_display_name` | Threat-group display name | yes (vendor) | n/a | medium | ← `actorDisplayName`; rarely populated in fixtures |
| `m365_defender.alert.evidence[].user_account.*` | Evidence user detail | yes (vendor) | n/a | high | Canonical Graph evidence; ECS `user.*` is flattened array from all evidence types |
| `observer.vendor`, `vulnerability.scanner.vendor` | Scanner identity | yes | n/a | low | **`vulnerability`** only — `default.yml` sets `Microsoft` |

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Platform / cloud service | SaaS or cloud workload invoked | Microsoft Azure, Office 365, Active Directory, Microsoft Teams | service | — | high | `application.name` ← `Application` property; `event.provider` / `m365_defender.alert.service_source` on alerts | **`event`** cloud/identity tables; **`alert`**, **`incident`** via `productName` / `serviceSource` |
| 2 — Resource / object | Onboarded endpoint (sensor or evidence) | Endpoint device | host | — | high | `host.*`, `device.id` ← `DeviceId`/`DeviceName`; evidence `deviceEvidence` | All streams except pure cloud-audit rows |
| 2 — Resource / object | Remote or created process | Process | general | process | high | `process.*`; non-ECS `Target.process.*` on remote API calls (`pipeline_device.yml`) | **`event`** device; **`alert`**, **`incident`** `processEvidence` |
| 2 — Resource / object | File / attachment / registry key | File or registry object | general | file | high | `file.*`; registry vendor fields on device/alert evidence | **`event`** device/email; **`alert`**, **`incident`** `fileEvidence` |
| 2 — Resource / object | Identity query / logon target host | Remote domain controller or queried device | host | — | high | `m365_defender.event.target.device_name`, `m365_defender.event.destination.device_name`, `destination.ip`/`destination.port` | **`event`** identity — SAMR to `d2win02r` (`test-app-and-identity.log-expected.json`) |
| 2 — Resource / object | Identity query target account | Directory user | user | — | medium | `m365_defender.event.target.account_upn`, `target.account_display_name`, `query.target` | **`event`** identity — pipeline support; empty in most fixtures |
| 2 — Resource / object | Cloud ARM / K8s / storage resource | Cloud resource | general | cloud_resource | high | `m365_defender.event.resource_id`, `azure_resource_id`, `object.type`, `resource.*` | **`event`** `CloudAuditEvents`, `CloudAppEvents`, `CloudProcessEvents`, `CloudStorageAggregatedEvents` |
| 2 — Resource / object | Email / Teams recipient | Mailbox user | user | — | high | `email.to.address`, `m365_defender.event.recipient.*` | **`event`** email/message tables |
| 2 — Resource / object | SaaS app instance (alert evidence) | Cloud application | service | — | high | `cloudApplicationEvidence` → vendor `m365_defender.alert.evidence` app fields | **`alert`**, **`incident`** — Skype exfiltration in `test-incident.log-expected.json` |
| 2 — Resource / object | Vulnerable software on endpoint | Installed package | general | software_package | high | `package.name`, `package.version`, `m365_defender.vulnerability.software_*` | **`vulnerability`** — host is impacted asset; software+CVE is finding target |
| 2 — Resource / object | CVE finding | Vulnerability record | general | cve | high | `vulnerability.id`, `vulnerability.cve`, `vulnerability.severity` | **`vulnerability`** |
| 3 — Content / artifact | Embedded or malicious URL | URL | general | url | high | `url.*`, `m365_defender.event.url*`, alert `urlEvidence` | **`event`** email/message/behavior; **`alert`**, **`incident`** |
| 3 — Content / artifact | Email message cluster / analyzed message | Email message | general | email_message | high | `email.*`, `m365_defender.alert.evidence.subject`, network/message IDs | **`alert`**, **`incident`** mail evidence |

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `application.name` | 1 | service | yes | yes | `service.target.name` | yes | ← `m365_defender.event.application` (`event/default.yml`); e.g. `Microsoft Azure`, `Office 365`, `Active Directory` in fixtures — Layer 1 invoked SaaS/cloud workload |
| `event.provider`, `m365_defender.alert.service_source`, `m365_defender.alert.product_name` | 1 | service | yes | yes | `service.target.name` | yes | Defender workload that generated the detection (Endpoint, Office 365, Cloud Apps) |
| `host.id`, `host.name`, `host.hostname`, `host.ip`, `host.os.*`, `device.id` | 2 | host | yes | partial | `host.target.*` | yes | Sensor host and evidence `deviceEvidence`; on identity events same fields describe source sensor — distinguish from query target below |
| `process.*` (non-`Target`) | 2 | general | yes | partial | `entity.target.id` | yes | Created/affected process on sensor; alert `processEvidence` — target process, but same ECS field family as actor initiating process |
| `Target.process.name`, `Target.process.command_line`, `Target.process.executable` | 2 | general | yes | partial | `entity.target.id` | yes | Non-standard ECS prefix; remote API call targets (`pipeline_device.yml`); pipeline-proven, sparse fixture coverage |
| `file.*` | 2/3 | general | yes | yes | context-only | no | Device files, email attachments, alert `fileEvidence` |
| `m365_defender.event.target.device_name` | 2 | host | yes (vendor) | yes | `host.target.name` | **yes** | ← `TargetDeviceName`/`DestinationDeviceName` (`pipeline_app_and_identity.yml`); identity query target — not migrated to ECS |
| `m365_defender.event.destination.device_name` | 2 | host | yes (vendor) | yes | `host.target.name` | **yes** | Vendor copy parallel to `target.device_name`; SAMR fixture `d2win02r.d300b.cenlar.com` |
| `destination.ip`, `destination.port` | 2 | host | yes | partial | context-only | partial | Identity query remote endpoint (`10.180.100.81:445`); network peer on device network events — verify table/action |
| `destination.domain` | 2 | host | yes | partial | `host.target.name` | yes | DNS query target domain in identity fixtures (`_grpc_config.useast-comms.dgsecure.com`) |
| `m365_defender.event.target.account_upn`, `target.account_display_name` | 2 | user | yes (vendor) | yes | `user.target.*` | **yes** | ← `TargetAccountUpn`/`TargetAccountDisplayName`; pipeline/fields support, empty in most fixtures |
| `m365_defender.event.query.target` | 2 | user | yes (vendor) | yes | `user.target.name` | **yes** | SAMR query target `Server_Admin` (`test-app-and-identity.log-expected.json`) |
| `m365_defender.event.resource_id`, `azure_resource_id`, `object.type` | 2 | general | yes (vendor) | yes | `entity.target.id` | yes | Cloud audit/app resource ARN or ARM ID; not promoted to ECS `resource.*` on all tables |
| `resource.id`, `resource.name` | 2 | general | yes | partial | `entity.target.id` | yes | Cloud process events; vulnerability `resource.id` ← device ID |
| `email.to.address`, `m365_defender.event.recipient.*` | 2 | user | yes | yes | `user.target.email` | yes | Mail recipient — de-facto user target, not `user.target.*` |
| `user.*` from evidence | 2 | user | yes | partial | `user.target.*` | yes | Flattened from all evidence types; `roles`/`detailed_roles` (e.g. `compromised`) imply target relationship but are not mapped to ECS target fields |
| `url.original`, `url.domain` | 3 | general | yes | yes | context-only | no | Email/message URLs; alert `urlEvidence` |
| `package.name`, `package.version`, `vulnerability.*` | 2 | general | yes | yes | context-only | no | **`vulnerability`** finding tuple |
| `cloud.account.id` | — | — | yes | n/a | context-only | no | Tenant scope on alerts/incidents/cloud rows — not a target |

### Gaps and mapping notes

- **No official ECS `*.target.*` fields** — target-fields audit confirms zero mapped target-tier fields; package is **`strong_candidate`** for enhancement (`target_enhancement_packages.csv`).
- **Vendor `m365_defender.event.target.*` and `query.target`** are the best source of truth for identity audit targets (`TargetAccountUpn`, `TargetDeviceName`, `QueryTarget`) — retained vendor-only; should migrate to `user.target.*` / `host.target.*`.
- **`destination.ip` / `destination.port` / `destination.domain`** on identity events are de-facto remote-host/query targets (`pipeline_app_and_identity.yml`), not `destination.user.*` (this package has **`pipeline_dest_identity=false`**). Network-context `destination.*` on device network tables may be flow peers — verify `network_direction` per action.
- **`Target.process.*`** uses a non-standard top-level ECS prefix (capital `Target`) — enhancement candidate for `process` target entity or ECS `process.target.*` when remote API calls are the acted-upon process.
- **`user.*` conflation** — the same ECS `user.name` array on alerts/incidents merges evidence users, logged-on users, and email senders without role separation; `roles`/`detailed_roles` stay vendor-only under `m365_defender.alert.evidence`.
- **`source.user.*` from `assignedTo`** is the SOC analyst assignee — correct workflow mapping but must not be interpreted as the threat actor (distinct from `m365_defender.alert.actor_display_name`).
- **`host.*` on identity events** describes the **source sensor** (`DeviceName`/`IPAddress`); the queried target is under vendor `target.device_name` / `destination.*`, not `host.target.*`.
- **`application.name`** identifies the invoked Microsoft workload (Layer 1 target) but is not mapped to `service.target.name` or `cloud.service.name`.
- **`CloudAuditEvents`** sample lacks explicit caller user — only `source.ip` and `user_agent.original`; principal identity may be absent in vendor payload.
- **`IdentityInfo`** (`event.kind: asset`) and **`vulnerability`** are inventory/state sync — describe entity subjects, not per-action actor/target pairs.
- **Alignment with target-fields audit:** `pipeline_actor=true`, `pipeline_entity_other=true` (vendor `*target*` paths and `Target.process.*`), `fixture_strong=true`; no `destination.user.*` pipeline mappings.
- **`event.action` gaps:**
  - **`pipeline_alert.yml`** (BehaviorInfo/BehaviorEntities, AlertInfo/AlertEvidence hunting tables) copies `ActionType` to `m365_defender.event.action.type` but never to ECS `event.action` — `SuspiciousPowerShellCommand` and alert metadata rows lack ECS verb (`test-behavior.log-expected.json`, AlertInfo in `test-alert.log-expected.json`).
  - **Cloud audit** maps coarse `ActionType` (`Update`) while richer ARM operation name (`Microsoft.Storage/storageAccounts/write`) stays in `m365_defender.event.properties_operation_name` — consider as primary or secondary `event.action`.
  - **`alert`/`incident`** use evidence `detectionStatus` (`detected`/`prevented`) as `event.action` — semantically detection outcome, not the operation that triggered the alert; `m365_defender.alert.title` and `.category` are better human-readable action candidates but unmapped.
  - **Inventory hunting tables** (`DeviceInfo`, `IdentityInfo`) and **`vulnerability`** stream correctly have no per-event action.
  - **Email/message** retains parallel remediation fields (`m365_defender.event.action.value`/`trigger`/`result`) vendor-only alongside normalized `event.action` from `ActionType`.

### Per-stream notes

#### `event`

Advanced Hunting tables routed by `category` to sub-pipelines (`pipeline_device.yml`, `pipeline_app_and_identity.yml`, `pipeline_email.yml`, `pipeline_alert.yml`). True audit-adjacent tables include `CloudAuditEvents`, `CloudAppEvents`, and identity logon/query/directory events; endpoint/device tables are telemetry with clear initiating-process actors. **`event.action`** ← `ActionType` on device, identity/cloud-app, and email/message pipelines (lowercased, spaces → hyphens; file/registry/process categories get ECS-friendly verbs). **Gaps:** `pipeline_alert.yml` (behavior/alert hunting) and inventory tables (`DeviceInfo`, `IdentityInfo`) retain vendor action type without ECS mapping. Target semantics are action-specific: files/processes/registry on the sensor host, remote peers via `destination.*` on network/identity events, cloud resources on audit/app tables, and email/file/url entities on messaging tables. Layer 1 service is `application.name` (e.g. `Microsoft Azure`, `Active Directory`).

#### `alert`

Graph Security API `/security/alerts_v2` via `alert/default.yml`. **`event.action`** is an array aggregated from evidence `detectionStatus` (`detected` in fixtures) — not hunting `ActionType` or alert title. No attack actor field when `actorDisplayName` is null; evidence drives both actor and target ECS fields. Each evidence `@odata.type` maps to ECS categories while full graph context (including `roles`, `detailed_roles`, `verdict`) remains in `m365_defender.alert.evidence`. Distinguish threat actor (`actor_display_name`), SOC assignee (`source.user` from `assignedTo`), and evidence users/processes/devices.

#### `incident`

Graph Security API `/security/incidents` with embedded alert evidence — same evidence mapping as **`alert`**, plus incident-level `assignedTo` → `source.user.*`, comment authors in `related.user`, and nested `m365_defender.incident.alert.evidence`. **`event.action`** mirrors nested evidence `detectionStatus` (`detected`, `prevented` in fixtures). Targets are evidence-driven across the correlated attack story; `roles: compromised` on device evidence indicates target relationship (`test-incident.log-expected.json`).

#### `vulnerability`

Defender for Endpoint `/api/machines/SoftwareVulnerabilitiesExport` — inventory sync, not audit. **No human actor.** **No `event.action`** — posture snapshot, not an operation verb. Target is the **host + software + CVE** tuple: `host.*`, `package.*`, `vulnerability.*`, with scanner context under `observer.*` / `vulnerability.scanner.vendor`. Actor/target audit enhancement does not apply; entity-analytics use case is vulnerability posture on endpoints.

## Example Event Graph

These examples come from the **`event`** (Advanced Hunting) and **`alert`** (Graph Security API) streams. Hunting identity and device tables are audit-adjacent telemetry with mapped `event.action`; alerts use evidence `detectionStatus` as the action verb. The **`vulnerability`** stream is inventory-only — no per-event actor/action/target graph applies.

### Example 1: Active Directory SAMR group query

**Stream:** `m365_defender.event` · **Fixture:** `packages/m365_defender/data_stream/event/_dev/test/pipeline/test-app-and-identity.log-expected.json`

```
Actor (user, D2WXA1303R$) → samr-query → Target (host, d2win02r.d300b.cenlar.com)
```

#### Actor

| Field | Value |
| --- | --- |
| id | S-1-5-21-621940831-1238047941-1264475144-86894 |
| name | D2WXA1303R$ |
| type | user |
| sub_type | service_account |
| ip | 10.180.101.20 |

**Field sources:**
- `id` ← `m365_defender.event.additional_fields.SourceAccountSid` (vendor-only in fixture; not promoted to ECS `user.id`)
- `name` ← `user.name` ← `AccountDisplayName`
- `ip` ← `host.ip` (source sensor IP on identity query events)

#### Event action

| Field | Value |
| --- | --- |
| action | samr-query |
| source_field | `event.action` |
| source_value | samr-query |

#### Target

| Field | Value |
| --- | --- |
| id | 370f6773-bfd8-4356-8e83-e65a1a9b3469 |
| name | d2win02r.d300b.cenlar.com |
| type | host |
| ip | 10.180.100.81 |

**Field sources:**
- `id` ← `m365_defender.event.additional_fields.DestinationComputerObjectGuid`
- `name` ← `m365_defender.event.destination.device_name` ← `DestinationDeviceName`
- `ip` ← `destination.ip` ← `DestinationIPAddress`
- Queried group `Server_Admin` is in `m365_defender.event.query.target` (vendor-only; not mapped to `user.target.*`)

#### Mermaid

```mermaid
flowchart LR
  A["Actor: D2WXA1303R$"] --> E["samr-query"]
  E --> T["Target: d2win02r.d300b.cenlar.com"]
```

### Example 2: Endpoint DPAPI access

**Stream:** `m365_defender.event` · **Fixture:** `packages/m365_defender/data_stream/event/_dev/test/pipeline/test-device.log-expected.json`

```
Actor (user, administrator1) → dpapiaccessed → Target (host, testmachine5)
```

#### Actor

| Field | Value |
| --- | --- |
| id | S-1-5-21-375308137-164487297-2828222098-111 |
| name | administrator1 |
| type | user |

**Field sources:**
- `id` ← `m365_defender.event.initiating_process.account_sid` (vendor-only; ECS `user.*` not populated on this fixture row)
- `name` ← `m365_defender.event.initiating_process.account_name` ← `InitiatingProcessAccountName`

#### Event action

| Field | Value |
| --- | --- |
| action | dpapiaccessed |
| source_field | `event.action` |
| source_value | dpapiaccessed |

#### Target

| Field | Value |
| --- | --- |
| id | de6509d550e605faf3bbeac0905ab9590fe12345 |
| name | testmachine5 |
| type | host |

**Field sources:**
- `id` ← `host.id` ← `DeviceId`
- `name` ← `host.name` ← `DeviceName`

#### Mermaid

```mermaid
flowchart LR
  A["Actor: administrator1"] --> E["dpapiaccessed"]
  E --> T["Target: testmachine5"]
```

### Example 3: Suspicious PowerShell detection alert

**Stream:** `m365_defender.alert` · **Fixture:** `packages/m365_defender/data_stream/alert/_dev/test/pipeline/test-alert.log-expected.json`

```
Actor (user, CDPUserIS-38411) → detected → Target (host, clw555test)
```

#### Actor

| Field | Value |
| --- | --- |
| id | S-1-12-1-1485667349-1150190949-4065799612-2328216759 |
| name | CDPUserIS-38411 |
| type | user |

**Field sources:**
- `id` ← `related.user` / `m365_defender.alert.evidence[].user_account.user_sid` ← evidence `userAccount.userSid`
- `name` ← `process.user.name` ← `processEvidence.userAccount.accountName`

#### Event action

| Field | Value |
| --- | --- |
| action | detected |
| source_field | `event.action` |
| source_value | detected |

Note: `event.action` reflects evidence `detectionStatus` (detection outcome), not the alert title (`Suspicious PowerShell command line`).

#### Target

| Field | Value |
| --- | --- |
| id | 505d70d89cfa3428f7aac7d2eb3a64c60fd3d843 |
| name | clw555test |
| type | host |
| ip | 192.168.5.65 |

**Field sources:**
- `id` ← `host.id` ← evidence `deviceEvidence.mdeDeviceId`
- `name` ← `host.hostname` ← evidence `deviceEvidence.deviceDnsName`
- `ip` ← `host.ip[0]` ← evidence `deviceEvidence.ipInterfaces`
- Suspicious process `powershell.exe` (pid 8224) is flattened to ECS `process.*` from `processEvidence`; same field family as initiating process on hunting events

#### Mermaid

```mermaid
flowchart LR
  A["Actor: CDPUserIS-38411"] --> E["detected"]
  E --> T["Target: clw555test"]
```

## ES|QL Entity Extraction

**Package type: agent-backed** (Elastic Agent / httpjson / Event Hub). Route primarily by **`data_stream.dataset`** (`m365_defender.event`, `m365_defender.alert`, `m365_defender.incident`, `m365_defender.vulnerability` per `manifest.yml`). Pass 4 is **fill-gaps-only**: detection flags (`actor_exists`, `target_exists`, `action_exists`) are query-time helpers; mapped columns use **column-level** `CASE(<col> IS NOT NULL, <col>, fallback, null)` — not `CASE(target_exists, <col>, …)` / `CASE(action_exists, event.action, …)` — so one populated sibling (e.g. `service.target.name` from `application.name`) does not block `host.target.*` / `user.target.*` fallbacks on empty columns (Pass 4 §10). Fallback branches promote vendor/de-facto fields to `user.target.*`, `host.target.*`, and `service.target.*` where ECS target tiers are empty today. **`m365_defender.vulnerability`** is excluded (inventory sync). Secondary routing uses **`event.action`** to separate identity-query targets (`samr-query`, `dns-query`) from onboarded-device targets (`dpapiaccessed`, alert evidence).

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `m365_defender.event` | Device / endpoint telemetry | user, general (process) | host, general (file/process) | partial |
| `m365_defender.event` | Identity / cloud audit | user | host, user, service | partial |
| `m365_defender.event` | Email / message | user | user, general (url/file) | partial |
| `m365_defender.alert` | Graph Security alert | user | host, general (process/file) | partial |
| `m365_defender.incident` | Correlated incident | user | host, service | partial |
| `m365_defender.vulnerability` | Vuln inventory sync | — | — | none |

### Field mapping plan

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `user.id` | `user.id` | `user.id IS NOT NULL` | high | **preserve existing** — column-level; do not gate on `actor_exists` (alerts can have `process.user.name` while `user.id` is empty) |
| `user.id` | `m365_defender.event.additional_fields.SourceAccountSid` | `data_stream.dataset == "m365_defender.event" AND user.id IS NULL` | high | **vendor fallback** (SAMR fixture) |
| `user.id` | `m365_defender.event.initiating_process.account_sid` | `data_stream.dataset == "m365_defender.event" AND user.id IS NULL` | high | **vendor fallback** (device telemetry) |
| `user.name` | `user.name` | `user.name IS NOT NULL` | high | **preserve existing** — column-level |
| `user.name` | `m365_defender.event.initiating_process.account_name` | `data_stream.dataset == "m365_defender.event" AND user.name IS NULL` | high | **vendor fallback** (`test-device.log-expected.json`) |
| `user.name` | `process.user.name` | `data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND user.name IS NULL` | high | **vendor fallback** — evidence process owner (`test-alert.log-expected.json`) |
| `user.email` | — | — | high | **ingest-only — no ES\|QL** — pipelines set `user.email` / `AccountUpn`; no alternate query-time path |
| `user.domain` | — | — | high | **ingest-only — no ES\|QL** — pipelines set `user.domain`; no alternate query-time path |
| `host.ip` | `host.ip` | `host.ip IS NOT NULL` | high | **preserve existing** — column-level |
| `host.ip` | `source.ip` | `data_stream.dataset == "m365_defender.event" AND user.name IS NULL AND source.ip IS NOT NULL` | medium | **vendor fallback** — weak actor context when principal absent (cloud audit) |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `host.target.id` | `host.target.id` | `host.target.id IS NOT NULL` | high | **preserve existing** (none today) |
| `host.target.id` | `m365_defender.event.additional_fields.DestinationComputerObjectGuid` | `data_stream.dataset == "m365_defender.event" AND event.action IN ("samr-query", "dns-query")` | high | **vendor fallback** — SAMR fixture GUID |
| `host.target.id` | `host.id` | `data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND host.id IS NOT NULL` | high | **de-facto** evidence device (`test-alert.log-expected.json`) |
| `host.target.id` | `host.id` | `data_stream.dataset == "m365_defender.event" AND event.action NOT IN ("samr-query", "dns-query", "logonsuccess", "logonfailed") AND host.id IS NOT NULL` | high | **de-facto** onboarded sensor host (e.g. `dpapiaccessed`) |
| `host.target.name` | `host.target.name` | `host.target.name IS NOT NULL` | high | **preserve existing** |
| `host.target.name` | `m365_defender.event.destination.device_name` | `data_stream.dataset == "m365_defender.event" AND m365_defender.event.destination.device_name IS NOT NULL` | high | **de-facto** identity query target |
| `host.target.name` | `host.name` | `data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND host.name IS NOT NULL` | high | **de-facto** evidence hostname |
| `host.target.name` | `host.name` | `data_stream.dataset == "m365_defender.event" AND event.action NOT IN ("samr-query", "dns-query", "logonsuccess", "logonfailed") AND host.name IS NOT NULL` | high | **de-facto** device telemetry target host |
| `host.target.ip` | `host.target.ip` | `host.target.ip IS NOT NULL` | high | **preserve existing** |
| `host.target.ip` | `destination.ip` | `data_stream.dataset == "m365_defender.event" AND destination.ip IS NOT NULL` | high | **de-facto** remote peer (`test-app-and-identity.log-expected.json`) |
| `user.target.name` | `user.target.name` | `user.target.name IS NOT NULL` | high | **preserve existing** |
| `user.target.name` | `m365_defender.event.query.target` | `data_stream.dataset == "m365_defender.event" AND m365_defender.event.query.target IS NOT NULL` | high | **vendor fallback** — SAMR queried group (`Server_Admin`) |
| `user.target.email` | `user.target.email` | `user.target.email IS NOT NULL` | high | **preserve existing** |
| `user.target.email` | `email.to.address` | `data_stream.dataset == "m365_defender.event" AND email.to.address IS NOT NULL` | high | **de-facto** mail recipient |
| `service.target.name` | `service.target.name` | `service.target.name IS NOT NULL` | high | **preserve existing** |
| `service.target.name` | `application.name` | `data_stream.dataset == "m365_defender.event" AND application.name IS NOT NULL` | high | **vendor fallback** — Layer 1 workload (`Active Directory`, `Office 365`) |
| `service.target.name` | `m365_defender.alert.service_source` | `data_stream.dataset == "m365_defender.alert" AND m365_defender.alert.service_source IS NOT NULL` | high | **vendor fallback** — Defender workload source |
| `service.target.name` | `m365_defender.incident.alert.service_source` | `data_stream.dataset == "m365_defender.incident" AND m365_defender.incident.alert.service_source IS NOT NULL` | high | **vendor fallback** — nested alert workload |
| `entity.target.id` | `entity.target.id` | `entity.target.id IS NOT NULL` | high | **preserve existing** |
| `entity.target.id` | `file.hash.sha256` | `data_stream.dataset IN ("m365_defender.event", "m365_defender.alert") AND file.hash.sha256 IS NOT NULL` | high | **vendor fallback** — file artifact target |
| `entity.target.type` | literal `"service"` / `"host"` / `"user"` | fallback branch by `event.action` / populated fields | medium | classification helper in fallback only |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | `event.action` | `event.action IS NOT NULL` | high | **preserve existing** (arrays on alert/incident) |
| `event.action` | `m365_defender.event.action.type` | `data_stream.dataset == "m365_defender.event" AND event.action IS NULL AND m365_defender.event.action.type IS NOT NULL` | medium | **vendor fallback** — BehaviorInfo/AlertInfo hunting gap; raw vendor verb |

### Detection flags (mandatory — run first)

Predicate tuned for Defender: actors include **`process.name`** / **`process.user.name`** (endpoint and alert evidence); targets check **`user.target.*`**, **`host.target.*`**, **`service.target.*`**, **`entity.target.*`** only (no `target.*` prefix). **`user.id` / `user.name` / `host.ip` actor EVAL** and **target / action / `entity.target.type` EVAL** use **column-level** `IS NOT NULL` preserve — not `actor_exists` / `target_exists` / `action_exists` as the first `CASE` pair — so vendor SID/name paths and empty sibling target columns still receive fallbacks when another target tier is populated (Pass 4 §10).

```esql
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL OR user.domain IS NOT NULL
    OR process.name IS NOT NULL OR process.user.name IS NOT NULL OR process.user.id IS NOT NULL
    OR host.id IS NOT NULL OR host.name IS NOT NULL OR host.ip IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

### Optional classification helpers (when needed)

Set **`entity.target.type`** only in the fallback branch (correct ECS name — not `target.entity.type`):

```esql
| EVAL
  entity.target.type = CASE(
    entity.target.type IS NOT NULL, entity.target.type,
    data_stream.dataset == "m365_defender.event" AND application.name IS NOT NULL, "service",
    data_stream.dataset == "m365_defender.event" AND m365_defender.event.query.target IS NOT NULL, "user",
    data_stream.dataset == "m365_defender.event" AND m365_defender.event.destination.device_name IS NOT NULL, "host",
    data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND host.id IS NOT NULL, "host",
    data_stream.dataset == "m365_defender.event" AND email.to.address IS NOT NULL, "user",
    null
  )
```

### Combined ES|QL — actor fields

```esql
| EVAL
  user.id = CASE(
    user.id IS NOT NULL, user.id,
    data_stream.dataset == "m365_defender.event" AND m365_defender.event.additional_fields.SourceAccountSid IS NOT NULL, m365_defender.event.additional_fields.SourceAccountSid,
    data_stream.dataset == "m365_defender.event" AND m365_defender.event.initiating_process.account_sid IS NOT NULL, m365_defender.event.initiating_process.account_sid,
    null
  ),
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "m365_defender.event" AND m365_defender.event.initiating_process.account_name IS NOT NULL, m365_defender.event.initiating_process.account_name,
    data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND process.user.name IS NOT NULL, process.user.name,
    null
  ),
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "m365_defender.event" AND user.name IS NULL AND source.ip IS NOT NULL, source.ip,
    null
  )
```

`user.email` and `user.domain` are **not** listed — ingest populates them on identity/email/cloud-app rows; `CASE(actor_exists, user.email, null)` would be a no-op. `user.id` / `user.name` omit `actor_exists` so alert `process.user.name` does not block vendor SID promotion.

### Combined ES|QL — event action

```esql
| EVAL
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "m365_defender.event" AND m365_defender.event.action.type IS NOT NULL, m365_defender.event.action.type,
    null
  )
```

### Combined ES|QL — target fields

```esql
| EVAL
  host.target.id = CASE(
    host.target.id IS NOT NULL, host.target.id,
    data_stream.dataset == "m365_defender.event" AND event.action IN ("samr-query", "dns-query") AND m365_defender.event.additional_fields.DestinationComputerObjectGuid IS NOT NULL, m365_defender.event.additional_fields.DestinationComputerObjectGuid,
    data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND host.id IS NOT NULL, host.id,
    data_stream.dataset == "m365_defender.event" AND event.action NOT IN ("samr-query", "dns-query", "logonsuccess", "logonfailed") AND host.id IS NOT NULL, host.id,
    null
  ),
  host.target.name = CASE(
    host.target.name IS NOT NULL, host.target.name,
    data_stream.dataset == "m365_defender.event" AND m365_defender.event.destination.device_name IS NOT NULL, m365_defender.event.destination.device_name,
    data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND host.name IS NOT NULL, host.name,
    data_stream.dataset == "m365_defender.event" AND event.action NOT IN ("samr-query", "dns-query", "logonsuccess", "logonfailed") AND host.name IS NOT NULL, host.name,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "m365_defender.event" AND destination.ip IS NOT NULL, destination.ip,
    null
  ),
  user.target.name = CASE(
    user.target.name IS NOT NULL, user.target.name,
    data_stream.dataset == "m365_defender.event" AND m365_defender.event.query.target IS NOT NULL, m365_defender.event.query.target,
    null
  ),
  user.target.email = CASE(
    user.target.email IS NOT NULL, user.target.email,
    data_stream.dataset == "m365_defender.event" AND email.to.address IS NOT NULL, email.to.address,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "m365_defender.event" AND application.name IS NOT NULL, application.name,
    data_stream.dataset == "m365_defender.alert" AND m365_defender.alert.service_source IS NOT NULL, m365_defender.alert.service_source,
    data_stream.dataset == "m365_defender.incident" AND m365_defender.incident.alert.service_source IS NOT NULL, m365_defender.incident.alert.service_source,
    null
  ),
  entity.target.id = CASE(
    entity.target.id IS NOT NULL, entity.target.id,
    data_stream.dataset IN ("m365_defender.event", "m365_defender.alert") AND file.hash.sha256 IS NOT NULL, file.hash.sha256,
    null
  )
```

### Full pipeline fragment (optional)

```esql
FROM logs-*
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL OR user.domain IS NOT NULL
    OR process.name IS NOT NULL OR process.user.name IS NOT NULL OR process.user.id IS NOT NULL
    OR host.id IS NOT NULL OR host.name IS NOT NULL OR host.ip IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  user.id = CASE(user.id IS NOT NULL, user.id, data_stream.dataset == "m365_defender.event" AND m365_defender.event.additional_fields.SourceAccountSid IS NOT NULL, m365_defender.event.additional_fields.SourceAccountSid, data_stream.dataset == "m365_defender.event" AND m365_defender.event.initiating_process.account_sid IS NOT NULL, m365_defender.event.initiating_process.account_sid, null),
  user.name = CASE(user.name IS NOT NULL, user.name, data_stream.dataset == "m365_defender.event" AND m365_defender.event.initiating_process.account_name IS NOT NULL, m365_defender.event.initiating_process.account_name, data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND process.user.name IS NOT NULL, process.user.name, null),
  host.ip = CASE(host.ip IS NOT NULL, host.ip, data_stream.dataset == "m365_defender.event" AND user.name IS NULL AND source.ip IS NOT NULL, source.ip, null)
| EVAL
  event.action = CASE(event.action IS NOT NULL, event.action, data_stream.dataset == "m365_defender.event" AND m365_defender.event.action.type IS NOT NULL, m365_defender.event.action.type, null)
| EVAL
  host.target.id = CASE(host.target.id IS NOT NULL, host.target.id, data_stream.dataset == "m365_defender.event" AND event.action IN ("samr-query", "dns-query") AND m365_defender.event.additional_fields.DestinationComputerObjectGuid IS NOT NULL, m365_defender.event.additional_fields.DestinationComputerObjectGuid, data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND host.id IS NOT NULL, host.id, data_stream.dataset == "m365_defender.event" AND event.action NOT IN ("samr-query", "dns-query", "logonsuccess", "logonfailed") AND host.id IS NOT NULL, host.id, null),
  host.target.name = CASE(host.target.name IS NOT NULL, host.target.name, data_stream.dataset == "m365_defender.event" AND m365_defender.event.destination.device_name IS NOT NULL, m365_defender.event.destination.device_name, data_stream.dataset IN ("m365_defender.alert", "m365_defender.incident") AND host.name IS NOT NULL, host.name, data_stream.dataset == "m365_defender.event" AND event.action NOT IN ("samr-query", "dns-query", "logonsuccess", "logonfailed") AND host.name IS NOT NULL, host.name, null),
  host.target.ip = CASE(host.target.ip IS NOT NULL, host.target.ip, data_stream.dataset == "m365_defender.event" AND destination.ip IS NOT NULL, destination.ip, null),
  user.target.name = CASE(user.target.name IS NOT NULL, user.target.name, data_stream.dataset == "m365_defender.event" AND m365_defender.event.query.target IS NOT NULL, m365_defender.event.query.target, null),
  user.target.email = CASE(user.target.email IS NOT NULL, user.target.email, data_stream.dataset == "m365_defender.event" AND email.to.address IS NOT NULL, email.to.address, null),
  service.target.name = CASE(service.target.name IS NOT NULL, service.target.name, data_stream.dataset == "m365_defender.event" AND application.name IS NOT NULL, application.name, data_stream.dataset == "m365_defender.alert" AND m365_defender.alert.service_source IS NOT NULL, m365_defender.alert.service_source, data_stream.dataset == "m365_defender.incident" AND m365_defender.incident.alert.service_source IS NOT NULL, m365_defender.incident.alert.service_source, null),
  entity.target.id = CASE(entity.target.id IS NOT NULL, entity.target.id, data_stream.dataset IN ("m365_defender.event", "m365_defender.alert") AND file.hash.sha256 IS NOT NULL, file.hash.sha256, null)
| KEEP @timestamp, data_stream.dataset, event.action, user.id, user.name, host.ip, host.target.id, host.target.name, host.target.ip, user.target.name, user.target.email, service.target.name, entity.target.id
```

### Streams excluded

- **`m365_defender.vulnerability`** — software vulnerability inventory sync (`event.category: vulnerability`); no per-event actor/target audit semantics. Host/package/CVE describe posture state, not an auditable action pair.
- **`m365_defender.event`** inventory hunting tables (`DeviceInfo`, `IdentityInfo`, `event.kind: asset`) — entity snapshots without a coherent action pair; skip dedicated target EVAL unless Pass 3 fields are populated.

### Gaps and limitations

- **Pass 4 tautology cleanup (§10)** — target / action / `entity.target.type` use per-column `IS NOT NULL` preserve (not `CASE(target_exists, host.target.name, …)` when `service.target.name` alone is set); actor `user.id` / `user.name` / `host.ip` already column-level; no `CASE(col, col, …)` identity branches.
- **`user.email` / `user.domain` ES|QL** — **ingest-only**; do not emit `CASE(actor_exists, user.email, null)` (3-arg no-op) or 4-arg `CASE(actor_exists, user.email, <field>, null)` (bare field parsed as condition).
- **`user.id` / `user.name` gating** — use column-level `IS NOT NULL` preserve, not `actor_exists`, when vendor SID/name paths must apply alongside `process.user.name` on alerts.
- **No indexed `*.target.*` today** — all target-tier columns are query-time fallbacks until ingest enhancement (`strong_candidate` in target-fields audit).
- **`user.*` conflation on alerts/incidents** — evidence users, logged-on users, and email senders merge into flat `user.*` without `roles` guard; ES|QL cannot disambiguate without vendor `m365_defender.alert.evidence[].roles`.
- **`source.user.*` from `assignedTo`** — SOC analyst assignee; intentionally omitted from actor EVAL to avoid threat-actor confusion.
- **`Target.process.*`** — non-standard ECS prefix for remote API call targets; not mapped (requires ingest normalization).
- **`m365_defender.event.target.account_upn`** — pipeline-supported but empty in most fixtures; omitted until populated.
- **BehaviorInfo / AlertInfo hunting rows** — `event.action` fallback copies raw `m365_defender.event.action.type` (not normalized like device pipeline).
- **Multi-valued `host.*` on alerts/incidents** — arrays from evidence flattening; consumers may need `MV_FIRST()` when scalar host targets are required.
- **Identity logon (`logonsuccess`/`logonfailed`)** — `host.*` is source sensor; prefer `service.target.name` ← `application.name`, not `host.target.*` from `host.id`.
- **Cloud audit rows** — may lack user principal; only `source.ip` available as weak actor context.
- **`event.action` on alert/incident** — array of `detectionStatus` values (`detected`, `prevented`); semantically detection outcome, not hunting `ActionType` or alert title.
