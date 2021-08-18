## Logs

The Azure Spring Cloud logs integration provides system and application information for Azure Spring Cloud resources.
There are several requirements before using the integration since the logs will have to be read from an azure event hub.

   * the logs have to be exported first to the event hub https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled
   * to export activity logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export
   * to export audit and sign-in logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub

Users opting for Elastic Cloud native Azure integration can stream the Azure Spring Cloud logs directly to their partner solution clusters, more information and steps can be found here https://www.elastic.co/guide/en/observability/current/monitor-azure.html



The integration brings the following benefits:

### springcloudlogs

This is the `springcloudlogs` data stream of the Azure Logs package. It will collect any Spring Cloud logs that have been streamed through an azure event hub.

{{event "springcloudlogs"}}

{{fields "springcloudlogs"}}