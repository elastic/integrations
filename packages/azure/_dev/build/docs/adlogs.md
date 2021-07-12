## Logs

The azure logs integration retrieves different types of log data from Azure.
There are several requirements before using the integration since the logs will actually be read from azure event hubs.

   * the logs have to be exported first to the event hub https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled
   * to export activity logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export
   * to export audit and sign-in logs to event hubs users can follow the steps here https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub


Azure Active Directory logs contain:

Sign-in logs – Information about sign-ins and how your resources are used by your users.

Audit logs – Information about changes applied to your tenant such as users and group management or updates applied to your tenant’s resources.

### auditlogs

This is the `auditlogs` dataset of the Azure Logs package. It will collect any audit events that have been streamed through an azure event hub.

{{event "auditlogs"}}

{{fields "auditlogs"}}

### signinlogs

This is the `signinlogs` dataset of the Kubernetes package. It will collect any sign-in events that have been streamed through an azure event hub.

{{event "signinlogs"}}

{{fields "signinlogs"}}