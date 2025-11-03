# Azure App Service Integration

The Azure App Service logs integration retrieves different types of logs categories from Azure App Service.
Azure App Service provides different logging to help you track, monitor, and debug your web application.

- HTTPLogs help monitor application health, performance and usage patterns.
- AuditLogs provide insights when publishing users successfully log on via one of the App Service publishing protocols.
- IPSecAuditLogs are generated through your application and pushed to Azure Monitoring.
- PlatformLogs are generated through AppService platform for your application.
- ConsoleLogs are generated from application or container.
- AppLogs are generated through your application (ex. logging capabilities)

## Data streams

This integration currently collects one data stream:

- App Service Logs

## Requirements and setup
Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information on how to set up and use this integration.

## App Service Logs
Collects different types of logs from Azure App Service via Event Hub.

{{event "app_service_logs"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "app_service_logs"}}
