# Microsoft Intune Integration for Elastic

## Overview

[Microsoft Intune](https://www.microsoft.com/en-in/security/business/microsoft-intune) is a cloud-based endpoint management solution that helps organizations manage and secure their devices, applications, and data. It provides comprehensive mobile device management (MDM) and mobile application management (MAM) capabilities for iOS, Android, Windows, and macOS devices.

The Microsoft Intune integration for Elastic allows you to collect managed device logs using [Azure Event Hub](https://docs.microsoft.com/en-us/azure/event-hubs/), then visualize the data in Kibana. This integration provides visibility into device management activities, policy compliance, application deployments, and security events across your Intune-managed environment.

### Compatibility

The Microsoft Intune integration uses Azure Event Hub to collect managed device logs from Microsoft Intune.

### How it works

This integration collects managed device logs from Microsoft Intune by consuming events from an Azure Event Hub. Intune managed device logs are forwarded to the Event Hub, and the Elastic Agent reads these events in real-time, processes them through ingest pipelines, and indexes them in Elasticsearch.

## What data does this integration collect?

This integration collects Microsoft Intune managed device logs.

### Supported use cases

Integrating device inventory data into SIEM dashboards delivers centralized visibility into endpoint posture, compliance status, and hardware distribution. The dashboard highlights OS, ownership, manufacturer, and model trends, along with enrollment and activity patterns over time. Compliance insights and status breakdowns help quickly assess policy adherence, while detailed inventory tables provide key device attributes for operational and investigative context. Together, these views support effective endpoint monitoring, compliance management, and governance.

## What do I need to use this integration?

### Collect data from Microsoft Azure Event Hub

-  Set up Azure Event Hub for Intune managed device logs and send managed device logs from Intune to Azure Event Hub. For more detail, refer to the link [here](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/review-logs-using-azure-monitor).
- **Note:** Select LOG > IntuneDevices.

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

### managed_device

This is the `managed_device` dataset.

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
| microsoft_intune.managed_device.category | Diagnostic category indicating the type of Intune data (Devices). | keyword |
| microsoft_intune.managed_device.operation_name | Name of the operation producing the device record. | keyword |
| microsoft_intune.managed_device.properties.aad_tenant_id | Azure Active Directory tenant identifier associated with the device. | keyword |
| microsoft_intune.managed_device.properties.android_patch_level | Android security patch level installed on the device. | keyword |
| microsoft_intune.managed_device.properties.batch_id | Identifier of the batch in which the device record was exported. | keyword |
| microsoft_intune.managed_device.properties.category_name | Category name assigned to the device in Intune. | keyword |
| microsoft_intune.managed_device.properties.compliant_state | Compliance status of the device as evaluated by Intune. | keyword |
| microsoft_intune.managed_device.properties.created_date | Date and time when the device object was created in Intune. | date |
| microsoft_intune.managed_device.properties.device_id | Unique identifier of the managed device in Intune. | keyword |
| microsoft_intune.managed_device.properties.device_name | Human-readable name assigned to the device. | keyword |
| microsoft_intune.managed_device.properties.device_registration_state | Registration state of the device with Intune. | keyword |
| microsoft_intune.managed_device.properties.device_state | Current management state of the device. | keyword |
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
| microsoft_intune.managed_device.properties.manufacturer | Name of the device manufacturer. | keyword |
| microsoft_intune.managed_device.properties.meid | Mobile Equipment Identifier of the device, if applicable. | keyword |
| microsoft_intune.managed_device.properties.model | Hardware model identifier reported by the device. | keyword |
| microsoft_intune.managed_device.properties.os | Operating system platform of the device. | keyword |
| microsoft_intune.managed_device.properties.os_version | Version of the operating system installed on the device. | keyword |
| microsoft_intune.managed_device.properties.ownership | Ownership type of the device (Corporate or Personal). | keyword |
| microsoft_intune.managed_device.properties.phone_number | Phone number associated with the device, if available. | keyword |
| microsoft_intune.managed_device.properties.primary_user | Identifier of the primary user object linked to the device. | keyword |
| microsoft_intune.managed_device.properties.reference_id | Azure Active Directory device identifier. | keyword |
| microsoft_intune.managed_device.properties.serial_number | Serial number assigned by the device manufacturer. | keyword |
| microsoft_intune.managed_device.properties.sku_family | Stock-keeping unit family associated with the device. | keyword |
| microsoft_intune.managed_device.properties.storage_free | Available free storage capacity on the device. | long |
| microsoft_intune.managed_device.properties.storage_total | Total storage capacity available on the device. | long |
| microsoft_intune.managed_device.properties.subscriber_carrier_network | Subscriber carrier network information for cellular devices. | keyword |
| microsoft_intune.managed_device.properties.supervised_status_string | Indicates whether the device is supervised. | keyword |
| microsoft_intune.managed_device.properties.upn | User Principal Name of the user associated with the device. | keyword |
| microsoft_intune.managed_device.properties.user_email | Email address of the primary user associated with the device. | keyword |
| microsoft_intune.managed_device.properties.user_name | Display name of the primary user associated with the device. | keyword |
| microsoft_intune.managed_device.properties.wifi_mac_address | Wi-Fi MAC address of the device network interface. | keyword |
| microsoft_intune.managed_device.result_type | Result of the operation associated with the device record. | keyword |
| microsoft_intune.managed_device.tenant_id | Unique identifier of the Microsoft Entra tenant associated with the device. | keyword |
| microsoft_intune.managed_device.time | Timestamp when the device record was emitted to Azure Event Hub. | date |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| tags | User defined tags. | keyword |


### Inputs used

These inputs can be used in this integration:

- [Azure Event Hub](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-eventhub)
