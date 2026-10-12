# Microsoft Intune Integration for Elastic

## Overview

[Microsoft Intune](https://www.microsoft.com/en-in/security/business/microsoft-intune) is a cloud-based endpoint management solution that helps organizations manage and secure their devices, applications, and data. It provides comprehensive mobile device management (MDM) and mobile application management (MAM) capabilities for iOS, Android, Windows, and macOS devices.

The Microsoft Intune integration for Elastic allows you to collect audit and managed device logs using [Azure Event Hub](https://docs.microsoft.com/en-us/azure/event-hubs/), then visualize the data in Kibana. This integration provides visibility into device management activities, policy compliance, application deployments, and security events across your Intune-managed environment.

### Compatibility

The Microsoft Intune integration uses Azure Event Hub to collect audit and managed device logs from Microsoft Intune.

### How it works

This integration collects audit and managed device logs from Microsoft Intune by consuming events from an Azure Event Hub. Intune audit and managed device logs are forwarded to the Event Hub, and the Elastic Agent reads these events in real-time, processes them through ingest pipelines, and indexes them in Elasticsearch.

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
