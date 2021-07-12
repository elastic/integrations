## Logs

The azure logs integration retrieves different types of log data from Azure.
There are several requirements before using the integration since the logs will actually be read from azure event hubs.

   * the logs have to be exported first to the event hub https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled
   * to export activity logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export
   * to export audit and sign-in logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub



Activity logs provide insight into the operations that were performed on resources in your subscription.


### activitylogs

This is the `activitylogs` data stream of the Azure Logs package. It will collect any activity events that have been streamed through an azure event hub.

{{event "activitylogs"}}

{{fields "activitylogs"}}