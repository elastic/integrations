# Microsoft Intune Integration for Elastic

## Overview

[Microsoft Intune](https://www.microsoft.com/en-in/security/business/microsoft-intune) is a cloud-based endpoint management solution that helps organizations manage and secure their devices, applications, and data. It provides comprehensive mobile device management (MDM) and mobile application management (MAM) capabilities for iOS, Android, Windows, and macOS devices.

The Microsoft Intune integration for Elastic allows you to collect audit and managed device logs using [Azure Event Hub](https://docs.microsoft.com/en-us/azure/event-hubs/), then visualize the data in Kibana. This integration provides visibility into device management activities, policy compliance, application deployments, and security events across your Intune-managed environment.

### Compatibility

The Microsoft Intune integration uses Azure Event Hub to collect audit and managed device logs from Microsoft Intune.

### How it works

This integration collects audit and managed device logs from Microsoft Intune by consuming events from an Azure Event Hub. Intune audit and managed device logs are forwarded to the Event Hub, and the Elastic Agent reads these events in real-time, processes them through ingest pipelines, and indexes them in Elasticsearch.

## What data does this integration collect?

This integration collects Microsoft Intune audit and managed device logs.

### Supported use cases

Integrating device inventory data and Microsoft Intune audit logs into SIEM dashboards provides a unified view of endpoint posture and administrative activity. It highlights device attributes like OS, ownership, and compliance status alongside audit insights such as total events, success vs. failure trends, top operations, and active actors. Combined breakdowns by actor type and context, along with detailed inventory and audit records, enable quick assessment, efficient investigation, and improved governance and security monitoring.

## What do I need to use this integration?

### Collect data from Microsoft Azure Event Hub

-  Set up Azure Event Hub for Intune Audit Logs and Managed device logs and send audit logs and managed device logs from Intune to Azure Event Hub. For more detail, refer to the link [here](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/review-logs-using-azure-monitor).
- **Note:**
   - Audit: Select LOG > AuditLogs.
   - Managed Device: Select LOG > IntuneDevices.

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

{{fields "managed_device"}}

### audit

This is the `audit` dataset.

{{fields "audit"}}

### Inputs used

These inputs can be used in this integration:

- [Azure Event Hub](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-eventhub)
