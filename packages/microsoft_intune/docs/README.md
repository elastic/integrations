# Microsoft Intune Integration for Elastic

## Overview

[Microsoft Intune](https://www.microsoft.com/en-in/security/business/microsoft-intune) is a cloud-based endpoint management solution that helps organizations manage and secure their devices, applications, and data. It provides comprehensive mobile device management (MDM) and mobile application management (MAM) capabilities for iOS, Android, Windows, and macOS devices.

The Microsoft Intune integration for Elastic allows you to collect audit logs using [Azure Event Hub](https://docs.microsoft.com/en-us/azure/event-hubs/), then visualize the data in Kibana. This integration provides visibility into device management activities, policy compliance, application deployments, and security events across your Intune-managed environment.

### Compatibility

The Microsoft Intune integration uses Azure Event Hub to collect audit logs from Microsoft Intune.

### How it works

This integration collects audit logs from Microsoft Intune by consuming events from an Azure Event Hub. Intune audit logs are forwarded to the Event Hub, and the Elastic Agent reads these events in real-time, processes them through ingest pipelines, and indexes them in Elasticsearch.

## What data does this integration collect?

This integration collects Microsoft Intune audit logs.

### Supported use cases

Integrating Microsoft Intune audit logs into SIEM dashboards provides centralized visibility into administrative actions and operational changes. The dashboard highlights total events, success vs. failure trends, top operations, and active actors. Breakdowns by actor type, delegated activity, and application context clarify who performed actions and under what authority. Detailed audit views, including modified properties and key event fields, support efficient investigation, governance, and compliance monitoring.

## What do I need to use this integration?

### Collect data from Microsoft Azure Event Hub

-  Set up Azure Event Hub for Intune Audit Logs and send audit logs from Intune to Azure Event Hub. For more detail, refer to the link [here](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/review-logs-using-azure-monitor).
- **Note:** Select LOG > AuditLogs.

## How do I deploy this integration?

This integration supports Agent-based installations.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### configure

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Microsoft Intune**.
3. Select the **Microsoft Intune** integration and add it.
4. While adding the integration, to collect logs via **Azure Event Hub**, enter the following details:
   - eventhub
   - consumer_group
   - connection_string
   - storage_account
   - storage_account_key
   - storage_account_container (optional)
   - resource_manager_endpoint (optional)
5. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Microsoft Intune**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

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
| microsoft_intune.audit.identity | Identity (UPN or app identity) that initiated the Intune operation. | keyword |
| microsoft_intune.audit.operation_name | Name of the Intune operation that was performed. | keyword |
| microsoft_intune.audit.properties.activity_date | Date and time when the audited Intune activity occurred. | date |
| microsoft_intune.audit.properties.activity_result_status | Numeric status code representing the outcome of the activity. | keyword |
| microsoft_intune.audit.properties.activity_type | Numeric code representing the type of activity performed. | keyword |
| microsoft_intune.audit.properties.actor.actor_type | Numeric code indicating the type of actor that initiated the action (user or application). | keyword |
| microsoft_intune.audit.properties.actor.application | Application (client) identifier used when the action was initiated by an app. | keyword |
| microsoft_intune.audit.properties.actor.application_name | Human-readable name of the application that initiated the action. | keyword |
| microsoft_intune.audit.properties.actor.is_delegated_admin | Indicates whether the action was performed by a delegated administrator. | boolean |
| microsoft_intune.audit.properties.actor.name | Display name of the actor who initiated the operation, if available. | keyword |
| microsoft_intune.audit.properties.actor.object_id | Object ID of the user or application that initiated the action. | keyword |
| microsoft_intune.audit.properties.actor.partner_tenant_id | Tenant ID of the partner tenant if the action was performed by a delegated partner. | keyword |
| microsoft_intune.audit.properties.actor.upn | User Principal Name (UPN) of the user who initiated the operation. | keyword |
| microsoft_intune.audit.properties.actor.user_permissions | List of permissions associated with the actor at the time of the operation. | keyword |
| microsoft_intune.audit.properties.additional_detail.original | Additional descriptive details related to the audit event provided as a formatted string. | keyword |
| microsoft_intune.audit.properties.additional_detail.parsed |  | flattened |
| microsoft_intune.audit.properties.additional_details.key | Key name of additional contextual information associated with the audit event. | keyword |
| microsoft_intune.audit.properties.additional_details.value | Value corresponding to the additional contextual information key. | keyword |
| microsoft_intune.audit.properties.audit_event_id | Unique identifier of the audit event generated by Intune. | keyword |
| microsoft_intune.audit.properties.category | Numeric category code used internally by Intune for audit classification. | keyword |
| microsoft_intune.audit.properties.logged_by_service | Name of the Microsoft service that generated the audit log entry. | keyword |
| microsoft_intune.audit.properties.relation_id | Identifier used to relate multiple audit events generated as part of a single operation. | keyword |
| microsoft_intune.audit.properties.target_display_names | Display names of the Intune resources that were targeted by the operation. | keyword |
| microsoft_intune.audit.properties.target_object_ids | Object IDs of the Intune resources that were targeted by the operation. | keyword |
| microsoft_intune.audit.properties.targets.modified_properties.name | Name of the property that was modified on the target resource. | keyword |
| microsoft_intune.audit.properties.targets.modified_properties.new | New value of the modified property after the change. | keyword |
| microsoft_intune.audit.properties.targets.modified_properties.old | Previous value of the modified property before the change. | keyword |
| microsoft_intune.audit.properties.targets.name | Name of the individual target resource affected by the operation. | keyword |
| microsoft_intune.audit.result_description | Textual description of the operation result, if available. | keyword |
| microsoft_intune.audit.result_type | High-level result status of the operation (Success or Failure). | keyword |
| microsoft_intune.audit.tenant_id | Unique identifier of the Microsoft Entra tenant where the Intune action occurred. | keyword |
| microsoft_intune.audit.time | Timestamp when the audit event was generated and emitted to Azure Monitor / Event Hub. | date |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| tags | User defined tags. | keyword |


### Inputs used

These inputs can be used in this integration:

- [Azure Event Hub](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-eventhub)
