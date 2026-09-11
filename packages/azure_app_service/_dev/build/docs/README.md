# Azure App Service Integration

## Overview

Azure App Service provides different logging to help you track, monitor, and debug your web application.

## What data does this integration collect?

This integration currently collects one data stream: App Service Logs.

The Azure App Service logs integration retrieves different types of logs categories from Azure App Service:

- HTTPLogs help monitor application health, performance and usage patterns.
- AuditLogs provide insights when publishing users successfully log on via one of the App Service publishing protocols.
- IPSecAuditLogs are generated through your application and pushed to Azure Monitoring.
- PlatformLogs are generated through AppService platform for your application.
- ConsoleLogs are generated from application or container.
- AppLogs are generated through your application (for example, logging capabilities).

## What do I need to use this integration?

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information on requirements and setup instructions.

**Authentication (Event Hub):** The Event Hub input supports two authentication methods: **connection string** (default) and **client secret** (Microsoft Entra ID). For setup steps, required RBAC roles (Azure Event Hubs Data Receiver, Storage Blob Data Contributor), and configuration options, see the [Azure Logs integration](https://docs.elastic.co/integrations/azure) or [Filebeat azure-eventhub input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) documentation.

### AMQP-over-WebSockets

By default, the integration uses AMQP ports `5671` and `5672` to communicate with Event Hubs. If these ports are blocked, set **Event Hubs transport protocol** to **AMQP-over-WebSockets** in the advanced options. This tunnels AMQP over HTTPS on port `443`.

This option requires the Event Hub processor v2 (**Processor version** set to `v2`, which is the default) and Elastic Agent 8.19.10, 9.1.10, 9.2.4, or later.

### Proxy support

Proxy support is optional and requires **Event Hubs transport protocol** set to **AMQP-over-WebSockets**.

To enable it:

1. In the advanced options, set **Event Hubs transport protocol** to **AMQP-over-WebSockets**.
2. Define the `HTTPS_PROXY` environment variable for the Elastic Agent process, for example `HTTPS_PROXY=http://proxy.example.com:8080`. Elastic Agent routes both Event Hubs and Storage Account traffic through the proxy.

This requires processor v2 and Elastic Agent 8.19.10, 9.1.10, 9.2.4, or later.

## App Service Logs

Collects different types of logs from Azure App Service via Event Hub.

{{event "app_service_logs"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "app_service_logs"}}
