# microsoft_intune

## Product Domain (Microsoft Intune MDM/UEM)

Microsoft Intune is a cloud-based Unified Endpoint Management (UEM) platform and a core component of Microsoft Endpoint Manager. Organizations use Intune to enroll, configure, secure, and maintain mobile and desktop endpoints across iOS, Android, Windows, and macOS. It provides Mobile Device Management (MDM) for full device control and Mobile Application Management (MAM) for application-level policies on personal and corporate devices, integrated with Microsoft Entra ID (Azure AD) for identity, conditional access, and compliance enforcement.

Core concepts in the Intune domain include managed devices (identified by Intune device ID, Entra device ID, serial number, and hardware identifiers), compliance policies and configuration profiles, app protection and deployment, device enrollment methods (Autopilot, Apple ADE, Android Enterprise, BYOD), and ownership models (corporate vs. personal). Devices report inventory and compliance state on check-in; administrators assign policies, deploy applications, initiate remote actions (wipe, retire, sync), and monitor fleet posture through the Microsoft Intune admin center and Microsoft Graph APIs.

From a security and operations perspective, Intune generates two primary telemetry types exported via Azure Monitor: audit logs of administrative and system actions, and managed device inventory snapshots. Audit events capture who performed an operation (user or application actor), what Intune resources were targeted, property changes, and success or failure outcomes. Managed device records capture hardware and OS attributes, compliance state, encryption and jailbreak/root status, enrollment and last-contact timestamps, primary user context, and storage and carrier details. Security teams use this data to monitor endpoint posture, track policy and configuration changes, investigate administrative activity, and correlate Intune-managed fleet state with broader SIEM investigations.

The Elastic Microsoft Intune integration ingests both streams via Elastic Agent consuming Azure Event Hub. Intune diagnostic logs (AuditLogs and IntuneDevices categories) are forwarded from Azure Monitor to Event Hub; the agent reads events in real time, processes them through ingest pipelines, and indexes ECS-aligned documents with Kibana dashboards for managed device inventory and audit activity.

## Data Collected (brief)

- **Managed Device** (`microsoft_intune.managed_device`): Device inventory records from the IntuneDevices diagnostic log category, including device identifiers (Intune device ID, Entra reference ID, serial, IMEI/MEID), hardware (manufacturer, model, SKU), OS platform and version, compliance state, encryption and supervised/jailbroken status, enrollment and registration state, last contact, ownership, primary user (UPN, email, display name), storage capacity, Wi-Fi MAC, and Android patch level.
- **Audit** (`microsoft_intune.audit`): Administrative and operational audit events from the AuditLogs category, including operation name, activity type and result (success/failure), actor context (user UPN, application name, object ID, actor type, delegated admin flag, permissions), target resources (display names, object IDs, modified property old/new values), correlation and relation IDs, additional contextual details, and tenant identifiers.
- **Host and user context**: ECS host fields derived from device inventory (name, OS, serial); user email and related user arrays from audit identity and managed device primary user; observer metadata identifying Microsoft Intune as the source.

## Expected Audit Log Entities

Two data streams: **`audit`** is a true administrative audit log (`event.category: configuration`, `event.type: change`) with explicit Actor and Target blocks from Azure Monitor AuditLogs; **`managed_device`** is periodic device inventory sync (`event.category: host`, `event.type: info`) — not an audit stream; actor/target audit semantics do not apply. **`event.action` is populated on both streams** — normalized from Azure Monitor `operationName` via ingest pipeline (lowercase, whitespace → hyphen). On **`audit`**, values name Intune admin operations (e.g. `delete-devicemanagementconfigurationpolicy`); on **`managed_device`**, the constant `devices` is a diagnostic category label, not a per-event admin verb. No ECS `user.target.*`, `host.target.*`, `service.target.*`, or `entity.target.*` fields are populated. The package is not in `destination_identity_hits.csv` (no `destination.user.*` / `destination.host.*`); audit maps target display names to `destination.domain` instead. Target-fields audit classifies `microsoft_intune` as **`strong_candidate`** with `pipeline_actor=true`, `fixture_strong=true`, and no tier-A ECS target mapping (`dev/target-fields-audit/out/target_enhancement_packages.csv`).

Evidence: `packages/microsoft_intune/data_stream/audit/` and `managed_device/` — `elasticsearch/ingest_pipeline/default.yml`, `fields/fields.yml`, `test-audit.log-expected.json`, `test-managed-device.log-expected.json`.

### Event action (semantic)

Azure Monitor AuditLogs carry a native **`operationName`** (PascalCase verb + resource, e.g. `Delete DeviceManagementConfigurationPolicy`). The pipeline normalizes this to ECS `event.action` (lowercase, hyphen-separated). Fixture-covered audit actions are configuration lifecycle operations on Intune device-management policies and assignments.

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| `delete-devicemanagementconfigurationpolicy` | configuration_change | high | `test-audit.log-expected.json` event 1; vendor `operationName: Delete DeviceManagementConfigurationPolicy` | **`audit`** — deletes policy `Testing1` (`AccountQuotaEntity: DeviceConfiguration`); `event.outcome: success`, `event.type: change` |
| `create-devicemanagementconfigurationpolicyassignment` | configuration_change | high | `test-audit.log-expected.json` events 2–3; vendor `operationName: Create DeviceManagementConfigurationPolicyAssignment` | **`audit`** — assigns policy to Entra group `3ac2074d-022f-42c3-9aa8-6b20d85fe2ca`; `AccountQuotaEntity: DeviceConfigurationAssignment` |
| `devices` | inventory_sync | high | `test-managed-device.log-expected.json` (all events); vendor `operationName: Devices`, `category: Devices` | **`managed_device`** — stream/category label for periodic inventory export; no meaningful per-event admin verb |

**`managed_device`** has no per-event administrative action — records are device posture snapshots keyed by `DeviceId` / `LastContact` fingerprint, not operator-initiated changes. Treat `event.action: devices` as diagnostic stream identity, not an audit verb.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `json.operationName` → `event.action` (via `microsoft_intune.*.operation_name`) | yes | yes | `delete-devicemanagementconfigurationpolicy`, `create-devicemanagementconfigurationpolicyassignment`, `devices` | no | `audit/default.yml` L77–85, L86–108 (`set_event_action_from_audit_operationName`, lowercase/split/join); `managed_device/default.yml` L408–439 |
| `microsoft_intune.audit.operation_name` / `microsoft_intune.managed_device.operation_name` | yes (vendor duplicate) | yes | Raw PascalCase values preserved when `preserve_duplicate_custom_fields` tag set | no | Removed by default (`remove_custom_duplicate_fields`); fixtures retain vendor copy |
| `microsoft_intune.audit.properties.activity_type` | no | n/a | `0` (create assignment), `1` (delete policy) — numeric activity discriminator | partial | Converted to string in pipeline L127–131; complements `operationName` but not copied to `event.action` |
| `microsoft_intune.audit.properties.activity_result_status` | no | n/a | `1` (success in fixtures) | no | Numeric result code; `event.outcome` already mapped from `resultType: Success` |
| `event.type` / `event.category` / `event.outcome` | n/a (downstream) | yes | `change` + `configuration` on audit; `info` + `host` on managed_device; `success` on audit | partial | Static appends / `resultType` copy — enrichments keyed on stream type, not independent action sources; do not substitute for `event.action` |

**Step 2b — per-stream check:**

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `audit` | yes (all 3 events) | yes | `json.operationName` → `event.action` (normalized) | high | `audit/default.yml` L77–108; fixtures: `delete-devicemanagementconfigurationpolicy`, `create-devicemanagementconfigurationpolicyassignment` |
| `managed_device` | yes (all 3 events) | yes | `json.operationName` (`Devices` → `devices`) | high (mapping) / n/a (audit semantics) | `managed_device/default.yml` L408–439; constant `devices` — inventory category, not admin operation |

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| Entra ID administrator (user actor) | user | — | high | `json.identity` → `user.email`; `properties.Actor.ObjectId` → `user.id`; `properties.Actor.UPN` → `related.user`; `properties.Actor.Name` → `user.name` when present (`audit/default.yml`); fixtures: `john.doe@example.com`, `dan.robert@example.com`, `john.isk@example.com` with object ID `1ce0bf0b-1a79-4caf-b932-4658cf273074`; `ActorType: 1` | **`audit`** — human admin performing policy create/delete/assign |
| Application client (portal/API) | service | — | high | `properties.Actor.ApplicationName` → `service.name`; `properties.Actor.Application` (app ID GUID) retained under `microsoft_intune.audit.properties.actor.application` (`audit/default.yml`); fixture: `Microsoft Intune portal extension` (`5926fc8e-304e-4f59-8bed-58ca97cc39a4`) | **`audit`** — client application acting on behalf of the signed-in user; pairs with user actor fields |
| Delegated partner administrator | user | — | moderate | `properties.Actor.IsDelegatedAdmin`, `properties.Actor.PartnerTenantId` → `microsoft_intune.audit.properties.actor.is_delegated_admin`, `partner_tenant_id` (`fields.yml`, `audit/default.yml`); `false` / zero GUID in all fixtures | **`audit`** — MSP/partner scenario; schema present, not exercised in fixtures |

**No actor identity:** **`managed_device`** — inventory snapshots have no initiating principal; `user.*` fields describe the device's primary user association, not who performed an action.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `user.email` | Admin UPN / audit identity | yes | yes | high | `json.identity` copy (`set_user_email_from_audit_identity`); fixtures match `Actor.UPN` |
| `user.id` | Entra object ID of actor | yes | yes | high | `properties.Actor.ObjectId` → `user.id` copy; fixture `1ce0bf0b-1a79-4caf-b932-4658cf273074` |
| `user.name` | Actor display name | yes | n/a | low | `properties.Actor.Name` copy; null in all audit fixtures |
| `service.name` | Client application name | yes | yes | high | `properties.Actor.ApplicationName` → `service.name`; fixture `Microsoft Intune portal extension` |
| `related.user` | Actor UPN enrichment | yes | yes | high | Appends `identity` and `Actor.UPN` (`append_audit_identity_into_related_user`, `append_audit_properties_Actor_UPN_into_related_user`) |
| `microsoft_intune.audit.properties.actor.*` | Full actor block (type, app ID, permissions, delegation) | no (vendor-only after dedup) | n/a | high | `application`, `actor_type`, `is_delegated_admin`, `partner_tenant_id`, `user_permissions` retained when `preserve_duplicate_custom_fields` tag set |
| `event.provider` | Logging service name | yes | yes (context) | medium | `properties.loggedByService` → `event.provider` when present; not in fixtures |
| `cloud.account.id` | Entra tenant scope | yes | yes (scope) | high | `tenantId` → `cloud.account.id`; fixture `3adb963c-8e61-48e8-a06d-6dbb0dacea39` — organizational scope, not an actor |
| `observer.product` / `observer.vendor` | Source platform constant | yes | yes (context) | high | Static `Microsoft Intune` / `Microsoft` (`ecs.yml` both streams) — collector/source metadata, not event actor |

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Platform / cloud service | UEM platform whose API was invoked | Microsoft Intune / Device Management | service | — | high | `observer.product: Microsoft Intune`; `event.action` values `delete-devicemanagementconfigurationpolicy`, `create-devicemanagementconfigurationpolicyassignment`; `AccountQuotaEntity` in `additional_detail.parsed` | **`audit`** — invoked Intune admin/Graph surface; no `cloud.service.name` set |
| 2 — Resource / object | Intune configuration object acted upon | Device management configuration policy | general | intune-policy | high | `target_display_names`, `target_object_ids`, `properties.targets[].name`; fixture policy `Testing1` / ID `916dc511-df99-45da-8eb6-1ac55579e16f` on delete | **`audit`** — `AccountQuotaEntity: DeviceConfiguration` |
| 2 — Resource / object | Assignment linking policy to scope | Policy assignment | general | intune-assignment | high | `operation_name: Create DeviceManagementConfigurationPolicyAssignment`; `AccountQuotaEntity: DeviceConfigurationAssignment`; composite assignment IDs in `target_object_ids` | **`audit`** — assignment create fixtures |
| 2 — Resource / object | Entra group receiving policy | Entra ID group | general | entra-group | high | `modified_properties` entry `Target.GroupId` → `3ac2074d-022f-42c3-9aa8-6b20d85fe2ca`; `Target.Type: GroupAssignmentTarget` | **`audit`** — policy assignment target group |
| 2 — Resource / object | Optional assignment filter | Assignment filter | general | intune-filter | moderate | `Target.DeviceAndAppManagementAssignmentFilterId`, `Target.DeviceAndAppManagementAssignmentFilterType` in `modified_properties`; `<null>` / `None` in fixtures | **`audit`** — schema present, null in fixtures |
| 2 — Resource / object | Managed endpoint (inventory subject) | Enrolled device | host | — | high | `DeviceName` → `host.name`; `DeviceId` → `device.id`; `ReferenceId` (Entra device ID); fixtures: `CLW555TEST`, `C-LAB-14`, `DESKTOP-13TAS32` | **`managed_device`** — inventory subject, not an admin-action target |
| 3 — Content / artifact | Before/after property changes | Modified policy properties | general | configuration-delta | high | `properties.targets[].modified_properties[]` with `name`, `old`, `new`; fixture: `Name` old→new on delete; assignment fields (`Id`, `Source`, `SourceId`, `DeviceManagementAPIVersion`) on create | **`audit`** — granular change evidence |
| 3 — Content / artifact | Evaluated posture attributes | Device compliance state | general | compliance-state | high | `CompliantState`, `DeviceState`, `EncryptionStatusString`, `JailBroken`, `SupervisedStatusString` (`managed_device/fields.yml`, fixtures) | **`managed_device`** — posture snapshot on inventory subject |

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observer.product` | 1 | service | yes | yes (context) | context-only | no | Static `Microsoft Intune` — platform identity; pipeline does not set `cloud.service.name` |
| `destination.domain` | 2 | general | yes | **partial** | `entity.target.name` | yes | `properties.Targets[].Name` appended via foreach (`append_properties_Targets_Name_into_destination_domain`); fixture `["Testing1"]` — policy display name, not a DNS domain |
| `microsoft_intune.audit.properties.target_object_ids` | 2 | general | no | n/a | `entity.target.id` | yes | GUIDs e.g. `916dc511-df99-45da-8eb6-1ac55579e16f`; canonical resource IDs, vendor-only |
| `microsoft_intune.audit.properties.target_display_names` | 2 | general | no | n/a | `entity.target.name` | yes | Parallel to `destination.domain`; vendor-only duplicate of display names |
| `microsoft_intune.audit.properties.targets[]` | 2 / 3 | general | no | n/a | `entity.target.*` | yes | Full target array with `modified_properties`; richest target structure; vendor-only |
| `microsoft_intune.audit.properties.additional_detail.parsed` | 2 | general | no | n/a | context-only | no | `AccountQuotaEntity`, `GroupPropertyNames` — entity type hints |
| `host.name` / `device.id` / `device.serial_number` | 2 | host | yes | yes (inventory subject) | `host.target.*` | yes | **`managed_device`** — endpoint identity; inventory semantics, not audit target |
| `microsoft_intune.managed_device.properties.reference_id` | 2 | host | no | n/a | `host.target.id` | yes | Entra device object ID (e.g. `f18bd540-d5e4-46e0-8ddd-3d03a59e4e14`); cross-link to Entra |
| `user.id` / `user.email` / `user.name` | 2 | user | yes | partial | context-only | no | **`managed_device`** — primary user on endpoint; association context, not audit target user |
| `cloud.account.id` | 1 | general | yes | yes (scope) | context-only | no | Tenant ID on both streams — organizational scope |

### Gaps and mapping notes

- **`event.action` well-mapped on audit** — `operationName` → normalized `event.action` is correct and populated in all audit fixtures. Optional enhancement: also expose raw PascalCase `operationName` in ECS when dedup tag absent, or map `activity_type` as supplementary context (not a replacement for `event.action`).
- **`event.action: devices` on managed_device is weak semantically** — technically mapped but reflects Azure diagnostic category, not an operator action; document as inventory stream label when correlating with audit events.
- **No ECS `*.target.*` today** — audit target identity lives in vendor `microsoft_intune.audit.properties.target_*` and a misapplied `destination.domain`. Enhancement: map `target_object_ids` → `entity.target.id`, display names → `entity.target.name`, and typed resources (policy, group, assignment) by `AccountQuotaEntity` / `modified_properties`.
- **`destination.domain` is a partial de-facto target mapping** — pipeline appends Intune resource display names (`Targets[].Name`) to `destination.domain`, which ECS defines for network destination hostnames. Semantically an audit target name, not a network peer; should migrate to `entity.target.name`.
- **Vendor target fields are canonical but unmapped to ECS** — `target_object_ids`, `targets[].modified_properties` (including `Target.GroupId`) are the best source of truth for Layer 2/3 targets; only display names partially surface via `destination.domain`.
- **`user.*` on managed_device is not actor or audit target** — primary user fields describe device ownership/assignment on inventory records; do not conflate with admin actor or acted-upon user in audit events.
- **No `destination.user.*` / `destination.host.*`** — package absent from `destination_identity_hits.csv`; no de-facto user/host target pattern beyond the `destination.domain` misuse.
- **Layer 1 gap: no `cloud.service.name`** — platform service inferred from `observer.product` and audit `event.action` operation prefixes only; static `cloud.service.name: intune` would improve Layer 1 target consistency.
- **Target-fields audit alignment** — `strong_candidate`: explicit audit Actor block with ECS actor mappings (`pipeline_actor=true`, `fixture_strong=true`), rich vendor target paths (`vendor_target_special_cases.csv`: 14 `*target*` hits on audit stream), but zero tier-A ECS target fields.

### Per-stream notes

#### `audit`

True administrative audit log from Azure Monitor AuditLogs. **`event.action`** names the Intune admin operation (normalized from `operationName`). Actor: Entra user (`user.email`, `user.id`) plus client application (`service.name`). Target Layer 1: Microsoft Intune Device Management API. Layer 2: configuration policies, assignments, and Entra groups (via `modified_properties`). Layer 3: property deltas in `targets[].modified_properties`. Correlate with fleet state via `target_object_ids` and group IDs against **`managed_device`** `device.id` / `reference_id`.

#### `managed_device`

Periodic inventory sync from IntuneDevices category — not an audit event. **`event.action: devices`** is a diagnostic stream label, not an admin verb. No actor. The managed endpoint (`host.*`, `device.*`) is the inventory subject; primary user fields provide association context only. Compliance and hardware attributes are evaluated state on the subject, not admin-action targets. Use alongside **`audit`** for posture and change correlation.

## Example Event Graph

Examples below come from the **`audit`** stream — true Azure Monitor AuditLogs with explicit Actor and Target blocks. The **`managed_device`** stream is periodic inventory sync (`event.action: devices` is a diagnostic category label, not an admin verb); it has no initiating operator, so no meaningful Actor → action → Target chain applies.

### Example 1: Delete configuration policy

**Stream:** `microsoft_intune.audit` · **Fixture:** `packages/microsoft_intune/data_stream/audit/_dev/test/pipeline/test-audit.log-expected.json` (event 1)

```
Entra admin (john.doe@example.com) → delete-devicemanagementconfigurationpolicy → Device configuration policy Testing1
```

#### Actor

| Field | Value |
| --- | --- |
| id | `1ce0bf0b-1a79-4caf-b932-4658cf273074` |
| name | john.doe@example.com |
| type | user |

**Field sources:**

- `id` ← `user.id` (`properties.Actor.ObjectId`)
- `name` ← `user.email` (`properties.Actor.UPN`)
- Client application context (not primary actor): `service.name` ← `properties.Actor.ApplicationName` → `Microsoft Intune portal extension`

#### Event action

| Field | Value |
| --- | --- |
| action | `delete-devicemanagementconfigurationpolicy` |
| source_field | `event.action` |
| source_value | `delete-devicemanagementconfigurationpolicy` |

#### Target

| Field | Value |
| --- | --- |
| id | `916dc511-df99-45da-8eb6-1ac55579e16f` |
| name | `Testing1` |
| type | general |
| sub_type | intune-policy |

**Field sources:**

- `id` ← `microsoft_intune.audit.properties.target_object_ids[0]`
- `name` ← `destination.domain[0]` (de-facto mapping from `properties.Targets[].Name`; semantically a policy display name, not a DNS domain)

#### Mermaid

```mermaid
flowchart LR
  A["Actor: john.doe@example.com"] --> E["delete-devicemanagementconfigurationpolicy"]
  E --> T["Target: Testing1 (intune-policy)"]
```

### Example 2: Assign configuration policy to Entra group

**Stream:** `microsoft_intune.audit` · **Fixture:** `packages/microsoft_intune/data_stream/audit/_dev/test/pipeline/test-audit.log-expected.json` (event 2)

```
Entra admin (dan.robert@example.com) → create-devicemanagementconfigurationpolicyassignment → Policy assignment to Entra group 3ac2074d-022f-42c3-9aa8-6b20d85fe2ca
```

#### Actor

| Field | Value |
| --- | --- |
| id | `1ce0bf0b-1a79-4caf-b932-4658cf273074` |
| type | user |

**Field sources:**

- `id` ← `user.id` (`properties.Actor.ObjectId`)
- Actor UPN also in `user.email` / `related.user` → `dan.robert@example.com`

#### Event action

| Field | Value |
| --- | --- |
| action | `create-devicemanagementconfigurationpolicyassignment` |
| source_field | `event.action` |
| source_value | `create-devicemanagementconfigurationpolicyassignment` |

#### Target

| Field | Value |
| --- | --- |
| id | `3ac2074d-022f-42c3-9aa8-6b20d85fe2ca` |
| type | general |
| sub_type | entra-group |

**Field sources:**

- `id` ← `microsoft_intune.audit.properties.targets[].modified_properties` where `name: Target.GroupId` → `new: 3ac2074d-022f-42c3-9aa8-6b20d85fe2ca`
- Policy display name `Testing` at `microsoft_intune.audit.properties.target_display_names[0]` — assignment context, not the group name (group display name absent in fixture)
- Assignment composite ID also available: `microsoft_intune.audit.properties.target_object_ids[1]` → `54d05a58-d055-423d-8d51-593688f81f84_3ac2074d-022f-42c3-9aa8-6b20d85fe2ca`

#### Mermaid

```mermaid
flowchart LR
  A["Actor: dan.robert@example.com"] --> E["create-devicemanagementconfigurationpolicyassignment"]
  E --> T["Target: Entra group 3ac2074d…"]
```

## ES|QL Entity Extraction

**Package type: agent-backed.** Router: `data_stream.dataset` (`microsoft_intune.audit`, `microsoft_intune.managed_device` from `manifest.yml` policy template). **Full extraction on `microsoft_intune.audit` only** — fixtures populate ECS actor fields; target identity is vendor-backed with a de-facto `destination.domain` name. **`microsoft_intune.managed_device` excluded** — inventory sync, not audit semantics. All fallback sources are Tier A (`test-audit.log-expected.json`, `audit/default.yml`). Every `CASE` uses column-level preserve: `CASE(col IS NOT NULL, col, cond AND src IS NOT NULL, src, null)` — never `field[n]` indexing.

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `microsoft_intune.audit` | administrative audit | user, service | general (policy, assignment, group), service (platform) | full |
| `microsoft_intune.managed_device` | device inventory sync | — | — | none |

### Field mapping plan

#### Actor mappings

| Output column | Source field(s) | Condition | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `user.id` | — | — | high | **ingest-only** — `properties.Actor.ObjectId` → `user.id` (`audit/default.yml` L178–182); omit from ES\|QL |
| `user.name` | `user.name`, `user.email` | `user.name IS NOT NULL` → preserve; else `data_stream.dataset == "microsoft_intune.audit"` | high | Column-level preserve — do not gate on `actor_exists` (`user.email` is set while `Actor.Name` → `user.name` is null in all fixtures) |
| `user.email` | — | — | high | **ingest-only** — `json.identity` → `user.email` (L65–69); omit from ES\|QL |
| `service.name` | — | — | high | **ingest-only** — `ApplicationName` → `service.name` (L148–152); omit from ES\|QL |

#### Target mappings

| Output column | Source field(s) | Condition | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `entity.target.id` | `entity.target.id` | preserve if not null | high | Column-level preserve |
| `entity.target.id` | `MV_FIRST(microsoft_intune.audit.properties.target_object_ids)` | `data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy"` | high | Fixture: array has exactly 1 element (`["916dc511-…"]`); `MV_FIRST` is safe |
| `entity.target.id` | — | `data_stream.dataset == "microsoft_intune.audit" AND event.action == "create-devicemanagementconfigurationpolicyassignment"` | — | **ingest-only** — `target_object_ids` has 2 elements: index 0 = policy ID, index 1 = composite assignment ID (`policyId_groupId`); index 1 has semantic meaning (specific element), cannot be reliably extracted at query time; ingest should normalize bare group GUID to `entity.target.id` |
| `entity.target.name` | `entity.target.name` | preserve if not null | high | Column-level preserve |
| `entity.target.name` | `MV_FIRST(destination.domain)` | `data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy"` | high | Fixture: `destination.domain` has exactly 1 element (`["Testing1"]`); `MV_FIRST` is safe |
| `entity.target.name` | `MV_FIRST(microsoft_intune.audit.properties.target_display_names)` | `data_stream.dataset == "microsoft_intune.audit" AND event.action == "create-devicemanagementconfigurationpolicyassignment"` | moderate | Fixture: array has 2 elements (`["Testing", "<null>"]`); index 0 is the policy name — first element is meaningful but ordering not guaranteed; `MV_FIRST` acceptable for policy context |
| `entity.target.type` | `entity.target.type` | preserve if not null | high | Column-level preserve |
| `entity.target.type` | `"general"` | `data_stream.dataset == "microsoft_intune.audit"` | low | Semantic literal — Pass 3 Layer 2 |
| `entity.target.sub_type` | `entity.target.sub_type` | preserve if not null | high | Column-level preserve |
| `entity.target.sub_type` | `"intune-policy"` | `data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy"` | high | Semantic literal — Pass 3 Example 1 |
| `entity.target.sub_type` | `"entra-group"` | `data_stream.dataset == "microsoft_intune.audit" AND event.action == "create-devicemanagementconfigurationpolicyassignment"` | high | Semantic literal — Pass 3 Example 2 (group ID in `modified_properties`, not indexed as ECS) |
| `service.target.name` | `service.target.name` | preserve if not null | high | Column-level preserve |
| `service.target.name` | `"Microsoft Intune"` | `data_stream.dataset == "microsoft_intune.audit"` | low | Semantic literal — Layer 1 platform (`observer.product` not copied) |

### Detection flags (mandatory)

`actor_exists` includes `service.*` because audit events pair Entra user actor with client application (`service.name`). `target_exists` checks all four target namespaces; audit fixtures have no pre-indexed `*.target.*` today, so flags are typically false until enrichment runs.

```esql
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

### Combined ES|QL — actor fields

Column-level preserve: `CASE(col IS NOT NULL, col, cond AND src IS NOT NULL, src, null)`.

Only `user.name` needs query-time fill — ingest copies `Actor.Name` (null in all fixtures); UPN lives in `user.email`. Do not gate on `actor_exists` (true when `user.email` is set while `user.name` is still empty).

```esql
| EVAL
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "microsoft_intune.audit" AND user.email IS NOT NULL, user.email,
    null
  )
```

### Combined ES|QL — target fields

Column-level preserve. `MV_FIRST()` used only where field is effectively single-valued in fixtures. `target_object_ids[1]` for assignment creates is ingest-only (see gaps).

```esql
| EVAL
  entity.target.id = CASE(
    entity.target.id IS NOT NULL, entity.target.id,
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy" AND microsoft_intune.audit.properties.target_object_ids IS NOT NULL, MV_FIRST(microsoft_intune.audit.properties.target_object_ids),
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy" AND destination.domain IS NOT NULL, MV_FIRST(destination.domain),
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "create-devicemanagementconfigurationpolicyassignment" AND microsoft_intune.audit.properties.target_display_names IS NOT NULL, MV_FIRST(microsoft_intune.audit.properties.target_display_names),
    null
  ),
  entity.target.type = CASE(
    entity.target.type IS NOT NULL, entity.target.type,
    data_stream.dataset == "microsoft_intune.audit", "general",
    null
  ),
  entity.target.sub_type = CASE(
    entity.target.sub_type IS NOT NULL, entity.target.sub_type,
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy", "intune-policy",
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "create-devicemanagementconfigurationpolicyassignment", "entra-group",
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "microsoft_intune.audit", "Microsoft Intune",
    null
  )
```

### Full pipeline fragment (optional)

```esql
FROM logs-*
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "microsoft_intune.audit" AND user.email IS NOT NULL, user.email,
    null
  )
| EVAL
  entity.target.id = CASE(
    entity.target.id IS NOT NULL, entity.target.id,
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy" AND microsoft_intune.audit.properties.target_object_ids IS NOT NULL, MV_FIRST(microsoft_intune.audit.properties.target_object_ids),
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy" AND destination.domain IS NOT NULL, MV_FIRST(destination.domain),
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "create-devicemanagementconfigurationpolicyassignment" AND microsoft_intune.audit.properties.target_display_names IS NOT NULL, MV_FIRST(microsoft_intune.audit.properties.target_display_names),
    null
  ),
  entity.target.type = CASE(
    entity.target.type IS NOT NULL, entity.target.type,
    data_stream.dataset == "microsoft_intune.audit", "general",
    null
  ),
  entity.target.sub_type = CASE(
    entity.target.sub_type IS NOT NULL, entity.target.sub_type,
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "delete-devicemanagementconfigurationpolicy", "intune-policy",
    data_stream.dataset == "microsoft_intune.audit" AND event.action == "create-devicemanagementconfigurationpolicyassignment", "entra-group",
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "microsoft_intune.audit", "Microsoft Intune",
    null
  )
| KEEP @timestamp, data_stream.dataset, event.action, user.id, user.name, user.email, service.name, entity.target.id, entity.target.name, entity.target.sub_type, service.target.name
```

### Streams excluded

- **`microsoft_intune.managed_device`** — periodic IntuneDevices inventory export (`event.action: devices` is a diagnostic category label, not an admin verb); `host.*` / `device.*` / `user.*` describe the managed endpoint subject and primary user association, not audit actor/target.

### Gaps and limitations

- **`target_object_ids[1]` for `create-devicemanagementconfigurationpolicyassignment` — ingest-only**: Fixture confirms `target_object_ids` has 2 elements: index 0 = policy GUID (`54d05a58-…` or `916dc511-…`), index 1 = composite assignment ID (`policyId_groupId`). Index 1 has specific semantic meaning (the assignment record ID). ES|QL array indexing (`field[n]`) is invalid syntax; `MV_FIRST` returns the first element (index 0), not index 1. Ingest pipeline should normalize the bare group GUID (`Target.GroupId` from `modified_properties`) or the composite ID to a flat `entity.target.id` field for assignment creates.
- **`destination.domain` for `create-devicemanagementconfigurationpolicyassignment` — multi-valued**: Fixture shows `["Testing", "<null>"]` (2 elements). `MV_FIRST` would return `"Testing"` (policy name), but this field is semantically misused (ECS DNS domain used for policy display name). `entity.target.name` fallback uses `MV_FIRST(target_display_names)` instead, which carries the same first element. Both are acceptable for policy-name context only.
- **`target_display_names` for assignment creates — first element only**: Fixture: `["Testing", "<null>"]`. `MV_FIRST` returns the policy context name (`Testing`/`Testing1`). The second element `"<null>"` is a literal null-string placeholder for the unnamed assignment target; discarding it is correct.
- **`destination.domain` — semantic mismatch**: ECS `destination.domain` is for network DNS hostnames; pipeline appends Intune resource display names. Query-time fill maps to `entity.target.name` in fallback only; long-term fix is ingest-level migration to `entity.target.name`.
- **`user.id` / `user.email` / `service.name` — ingest-only**: Do not emit tautological `CASE` wrapping already-populated ingest fields.
- **`event.action` — ingest-only**: `operationName` normalized at ingest; omit action `EVAL` block.
- **`user.name` on audit**: `properties.Actor.Name` is null in all three audit fixtures; `user.name` column-level preserve falls back to `user.email` (always populated from `json.identity`).
- **`user.target.*` / `host.target.*`**: No tier-A sources; audit targets are `entity.target.*` (policy, assignment, group), not user/host ECS targets.
- **Entra group GUID**: Bare group GUID `3ac2074d-…` lives only in `targets[].modified_properties` (`Target.GroupId`); not a flat indexed ECS field. Cannot be extracted at query time. Ingest enhancement needed.
- **`event.action: devices` on managed_device**: Constant stream/category label; excluded from action enrichment semantics.
