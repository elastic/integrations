# Microsoft Intune Integration for Elastic

## Overview

[Microsoft Intune](https://www.microsoft.com/en-in/security/business/microsoft-intune) is a cloud-based endpoint management solution that helps organizations manage and secure their devices, applications, and data. It provides comprehensive mobile device management (MDM) and mobile application management (MAM) capabilities for iOS, Android, Windows, and macOS devices.

The Microsoft Intune integration for Elastic allows you to collect audit and managed device logs using [Azure Event Hub](https://docs.microsoft.com/en-us/azure/event-hubs/), then visualize the data in Kibana. This integration provides visibility into device management activities, policy compliance, application deployments, and security events across your Intune-managed environment.

### Compatibility

The Microsoft Intune integration uses Azure Event Hub to collect audit and managed device logs from Microsoft Intune.

### How it works

This integration collects audit and managed device logs from Microsoft Intune by consuming events from an Azure Event Hub. Intune sends all its log categories to the Event Hub, and the Elastic Agent reads the Event Hub once with a single input. The events arrive in the `microsoft_intune.events` data stream, and the ingest pipeline routes each event by its log category:

| Log category | Data stream |
| --- | --- |
| `AuditLogs` | `microsoft_intune.audit` |
| `Devices`, `DeviceComplianceOrg` | `microsoft_intune.managed_device` |
| Any other category | `microsoft_intune.events` (not parsed) |

The `audit` and `managed_device` data streams have no input of their own. They only receive events routed from `microsoft_intune.events`.

### Proxy support

When the Elastic Agent must reach Azure Event Hubs through an HTTP/HTTPS proxy, set the **Event Hubs transport protocol** to **AMQP-over-WebSockets**. This routes Event Hub traffic over HTTPS (port 443) instead of AMQP (port 5671), which allows the proxy to handle it. Selecting AMQP-over-WebSockets automatically sets the processor version to v2.

**Requirements:**

- Elastic Agent 8.19.10, 9.1.10, 9.2.4, or later.
- Set `HTTPS_PROXY` and, if needed, `NO_PROXY` in the Elastic Agent process environment (for example, a systemd drop-in file or container environment variable). These variables apply to the entire agent process, not just this integration. Use `NO_PROXY` to exclude traffic that should bypass the proxy.

**Proxy allowlist:** the proxy must allow HTTPS (port 443) connections to:

- `*.servicebus.windows.net` — Event Hub traffic. Sovereign clouds use a different suffix (for example, `*.servicebus.usgovcloudapi.net` for Azure Government).
- `*.blob.core.windows.net` — checkpoint storage. Sovereign clouds use the storage suffix derived from **Authority Host** (for example, `*.blob.core.usgovcloudapi.net` for Azure Government).
- The authority host (default `login.microsoftonline.com`) — required for credential-based authentication.

**TLS-intercepting proxies:** if the proxy performs TLS interception, the corporate CA certificate must be present in the system trust store on the agent host.

**Sovereign clouds:** users on Azure Government, Azure China, or Azure Germany must set the **Authority Host** to the correct login endpoint. Processor v2 derives the storage endpoint suffix from this setting. The **Resource Manager Endpoint** setting is used only by processor v1 and is ignored by v2.

**Note on processor version:** selecting AMQP-over-WebSockets moves the processor from v1 to v2 if the agent was previously running v1. Existing checkpoints are migrated automatically. However, switching back to v1 afterwards resumes from stale v1 checkpoints and may cause duplicate events.

## What data does this integration collect?

This integration collects Microsoft Intune audit and managed device logs.

### Supported use cases

Integrating device inventory data and Microsoft Intune audit logs into SIEM dashboards provides a unified view of endpoint posture and administrative activity. It highlights device attributes like OS, ownership, and compliance status alongside audit insights such as total events, success vs. failure trends, top operations, and active actors. Combined breakdowns by actor type and context, along with detailed inventory and audit records, enable quick assessment, efficient investigation, and improved governance and security monitoring.

## What do I need to use this integration?

### Collect data from Microsoft Azure Event Hub

- Set up an Azure Event Hub and add an Intune diagnostic setting that sends the logs to it. For more detail, refer to [Send Intune log data to Azure Storage, Event Hubs, or Log Analytics](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/review-logs-using-azure-monitor).
- In the diagnostic setting, select the log categories to collect. All categories can go to the same Event Hub:
   - Audit: Select LOG → AuditLogs.
   - Managed Device: Select LOG → IntuneDevices, and LOG → DeviceComplianceOrg to also collect device compliance records.

## How do I deploy this integration?

This integration supports Agent-based installations.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### configure

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Microsoft Intune**.
3. Select the **Microsoft Intune** integration and add it.
4. While adding the integration, enter the following Event Hub settings. They apply to the whole integration:
   - Azure Event Hub
   - Consumer Group
   - Connection String
   - Storage Account
   - Storage Account Key
   - Resource Manager Endpoint (optional)
5. Under **Collect Microsoft Intune logs via Azure Event Hub**, optionally set the **Storage Account Container**.
6. Select **Save and continue** to save the integration.

### Upgrading from version 0.3.x

Version 0.4.0 replaces the two Event Hub inputs (one for `audit` and one for `managed_device`) with a single input, and moves the Event Hub settings from the inputs to the integration settings. Fleet cannot carry the old values over, so existing integration policies are not upgraded automatically. They keep running version 0.3.x until you edit them.

To upgrade an integration policy:

1. In Kibana, go to **Management** → **Integrations** → **Installed integrations** → **Microsoft Intune** → **Integration policies**.
2. Select **Upgrade** for the policy.
3. Enter the **Azure Event Hub**, **Consumer Group**, **Connection String**, **Storage Account** and **Storage Account Key** again, and any advanced Event Hub settings you had changed. **Consumer Group** resets to `$Default`, so enter your own consumer group again if you used one.
4. Under **Collect Microsoft Intune logs via Azure Event Hub**, reapply any options you had changed on the old inputs, such as **Preserve original event**, **Tags** or **Processors**. These options now apply to all log categories. If the old Audit and Managed Device inputs had different custom tags, enter the combined list. Keep the default `forwarded` and `microsoft_intune-events` tags, and do not add `microsoft_intune-audit` or `microsoft_intune-managed_device`. The integration replaces `microsoft_intune-events` with the tag of the data stream that each event is routed to.

   For example, if the old inputs had these tags:

   ```
   Audit:          forwarded, microsoft_intune-audit, team-secops
   Managed Device: forwarded, microsoft_intune-managed_device, cmdb
   ```

   enter this list on the new input:

   ```
   forwarded
   microsoft_intune-events
   team-secops
   cmdb
   ```

   Audit events are then tagged `forwarded`, `microsoft_intune-audit`, `team-secops` and `cmdb`, and managed device events `forwarded`, `microsoft_intune-managed_device`, `team-secops` and `cmdb`.
5. Select **Upgrade integration**.

The default checkpoint container name (`azure-eventhub-input-<eventhub>`) has not changed. If you set a custom **Storage Account Container** on one of the old inputs, set the same value on the new input. With the same consumer group and container, the agent continues from the existing checkpoints.

If the agent finds no checkpoints, for example because the consumer group or container is different, it starts reading from the earliest event still retained in the Event Hub. Events that were already collected are then read again. Both the `audit` and `managed_device` pipelines set a document ID from the event contents, so most of these events are not indexed twice. Events whose earlier copy is in an older backing index of the data stream, after a rollover, are indexed again as duplicates. To avoid reading old events, set **Processor start position** to **latest** before you upgrade the policy. The agent then starts from new events only, and events that arrive while the policy is being upgraded are not collected. **Processor start position** applies only to processor v2.

If the old Audit and Managed Device inputs read from different Event Hubs, the upgraded policy reads only the Event Hub you enter, and the log category sent to the other Event Hub is no longer collected. To keep collecting it, either change the Intune diagnostic settings so that both log categories go to the same Event Hub, or add a second Microsoft Intune integration policy for the second Event Hub. Events are routed by log category, so both policies deliver events to the correct data streams.

Version 0.4.0 also removes the **Preserve duplicate custom fields** setting. Vendor fields that are copied to ECS fields, such as `microsoft_intune.audit.identity` (copied to `user.email`), are now always removed from the event. Update saved searches, visualizations and rules that use these vendor fields to use the ECS fields instead.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Microsoft Intune**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

The **Managed Device** dashboard shows the device inventory (`Devices` log category). Its **Category** control selects `Devices` by default, so that device compliance records are not counted as devices. To look at the compliance records, change the **Category** control to `DeviceComplianceOrg`, or search the `microsoft_intune.managed_device` data stream in Discover.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

- **Events are missing from `audit` or `managed_device`:** check the `logs-microsoft_intune.events-*` data stream. Events whose log category is not `AuditLogs`, `Devices` or `DeviceComplianceOrg` stay there, with the category in `microsoft_intune.events.category`. Events that are not valid JSON also stay there, with `event.kind` set to `pipeline_error`.

## Reference

### events

The `events` data stream receives all events from the Event Hub and routes them to the other data streams. It keeps the events whose log category is not routed.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| microsoft_intune.events.category | Azure Monitor log category of an event that is not routed to another data stream of this package. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| tags | User defined tags. | keyword |


### managed_device

The `managed_device` data stream holds two kinds of records, which you can tell apart by `microsoft_intune.managed_device.category`:

- `Devices`: the device inventory, with fields such as `properties.compliant_state`, `properties.ownership` and `properties.manufacturer`.
- `DeviceComplianceOrg`: device compliance records, with fields such as `properties.compliance_state`, `properties.owner_type` and `properties.device_health_threat_level`.

Both kinds have the common device and user fields, such as `device.id`, `host.name`, `host.os.name` and `user.email`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| microsoft_intune.managed_device.category | Diagnostic category indicating the type of Intune data (Devices or DeviceComplianceOrg). | keyword |
| microsoft_intune.managed_device.properties.aad_tenant_id | Azure Active Directory tenant identifier associated with the device. | keyword |
| microsoft_intune.managed_device.properties.account_id | Identifier of the Intune account, as reported in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.android_patch_level | Android security patch level installed on the device. | keyword |
| microsoft_intune.managed_device.properties.batch_id | Identifier of the batch in which the device record was exported. | keyword |
| microsoft_intune.managed_device.properties.category_name | Category name assigned to the device in Intune. | keyword |
| microsoft_intune.managed_device.properties.compliance_state | Compliance state of the device as reported in device compliance records (DeviceComplianceOrg), for example Compliant. | keyword |
| microsoft_intune.managed_device.properties.compliance_state_code | Numeric code of the compliance state in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.compliant_state | Compliance status of the device as evaluated by Intune. | keyword |
| microsoft_intune.managed_device.properties.device_health_threat_level | Device health threat level as reported in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.device_health_threat_level_code | Numeric code of the device health threat level in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.device_registration_state | Registration state of the device with Intune. | keyword |
| microsoft_intune.managed_device.properties.device_state | Current management state of the device. | keyword |
| microsoft_intune.managed_device.properties.device_type | Numeric code of the device type in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.eas_id | Exchange ActiveSync identifier associated with the device. | keyword |
| microsoft_intune.managed_device.properties.encryption_status_string | Indicates whether the device storage is encrypted. | keyword |
| microsoft_intune.managed_device.properties.graph_device_is_managed | Indicates whether the device is managed according to Microsoft Graph. | boolean |
| microsoft_intune.managed_device.properties.imei | International Mobile Equipment Identity of the device, if applicable. | keyword |
| microsoft_intune.managed_device.properties.in_grace_period_until | Date and time until which the device remains in compliance grace period. | date |
| microsoft_intune.managed_device.properties.intune_account_id | Identifier of the Intune account managing the device. | keyword |
| microsoft_intune.managed_device.properties.jail_broken | Indicates whether the device is jail-broken or rooted. | keyword |
| microsoft_intune.managed_device.properties.join_type | Join type indicating how the device is joined to Azure AD. | keyword |
| microsoft_intune.managed_device.properties.last_contact | Date and time when the device last communicated with Intune. | date |
| microsoft_intune.managed_device.properties.managed_by | Management authority responsible for the device. | keyword |
| microsoft_intune.managed_device.properties.managed_device_name | Managed device name generated by Intune. | keyword |
| microsoft_intune.managed_device.properties.management_agents | Management agents of the device as reported in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.management_agents_code | Numeric code of the management agents in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.manufacturer | Name of the device manufacturer. | keyword |
| microsoft_intune.managed_device.properties.meid | Mobile Equipment Identifier of the device, if applicable. | keyword |
| microsoft_intune.managed_device.properties.os_description | Operating system description as reported in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.owner_type | Ownership type of the device as reported in device compliance records, for example Company or Personal. | keyword |
| microsoft_intune.managed_device.properties.owner_type_code | Numeric code of the ownership type in device compliance records. | keyword |
| microsoft_intune.managed_device.properties.ownership | Ownership type of the device (Corporate or Personal). | keyword |
| microsoft_intune.managed_device.properties.phone_number | Phone number associated with the device, if available. | keyword |
| microsoft_intune.managed_device.properties.reference_id | Azure Active Directory device identifier. | keyword |
| microsoft_intune.managed_device.properties.retire_after_datetime | Date and time after which the device is retired, as reported in device compliance records. | date |
| microsoft_intune.managed_device.properties.sku_family | Stock-keeping unit family associated with the device. | keyword |
| microsoft_intune.managed_device.properties.storage_free | Available free storage capacity on the device. | long |
| microsoft_intune.managed_device.properties.storage_total | Total storage capacity available on the device. | long |
| microsoft_intune.managed_device.properties.subscriber_carrier_network | Subscriber carrier network information for cellular devices. | keyword |
| microsoft_intune.managed_device.properties.supervised_status_string | Indicates whether the device is supervised. | keyword |
| microsoft_intune.managed_device.properties.wifi_mac_address | Wi-Fi MAC address of the device network interface. | keyword |
| microsoft_intune.managed_device.result_type | Result of the operation associated with the device record. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| tags | User defined tags. | keyword |


### audit

This is the `audit` dataset.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| microsoft_intune.audit.category | Log category indicating the type of diagnostic data (always AuditLogs for Intune audit events). | keyword |
| microsoft_intune.audit.correlation_id | Correlation identifier used to link related operations across services. | keyword |
| microsoft_intune.audit.properties.activity_date | Date and time when the audited Intune activity occurred. | date |
| microsoft_intune.audit.properties.activity_result_status | Numeric status code representing the outcome of the activity. | keyword |
| microsoft_intune.audit.properties.activity_type | Numeric code representing the type of activity performed. | keyword |
| microsoft_intune.audit.properties.actor.actor_type | Numeric code indicating the type of actor that initiated the action (user or application). | keyword |
| microsoft_intune.audit.properties.actor.application | Application (client) identifier used when the action was initiated by an app. | keyword |
| microsoft_intune.audit.properties.actor.is_delegated_admin | Indicates whether the action was performed by a delegated administrator. | boolean |
| microsoft_intune.audit.properties.actor.partner_tenant_id | Tenant ID of the partner tenant if the action was performed by a delegated partner. | keyword |
| microsoft_intune.audit.properties.actor.upn | User Principal Name (UPN) of the user who initiated the operation. | keyword |
| microsoft_intune.audit.properties.actor.user_permissions | List of permissions associated with the actor at the time of the operation. | keyword |
| microsoft_intune.audit.properties.additional_detail.original | Additional descriptive details related to the audit event provided as a formatted string. | keyword |
| microsoft_intune.audit.properties.additional_detail.parsed |  | flattened |
| microsoft_intune.audit.properties.additional_details.key | Key name of additional contextual information associated with the audit event. | keyword |
| microsoft_intune.audit.properties.additional_details.value | Value corresponding to the additional contextual information key. | keyword |
| microsoft_intune.audit.properties.category | Numeric category code used internally by Intune for audit classification. | keyword |
| microsoft_intune.audit.properties.relation_id | Identifier used to relate multiple audit events generated as part of a single operation. | keyword |
| microsoft_intune.audit.properties.target_display_names | Display names of the Intune resources that were targeted by the operation. | keyword |
| microsoft_intune.audit.properties.target_object_ids | Object IDs of the Intune resources that were targeted by the operation. | keyword |
| microsoft_intune.audit.properties.targets.modified_properties.name | Name of the property that was modified on the target resource. | keyword |
| microsoft_intune.audit.properties.targets.modified_properties.new | New value of the modified property after the change. | keyword |
| microsoft_intune.audit.properties.targets.modified_properties.old | Previous value of the modified property before the change. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| tags | User defined tags. | keyword |


### Inputs used

These inputs can be used in this integration:

- [Azure Event Hub](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-eventhub)
