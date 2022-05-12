# Azure Logs Integration

The Azure Logs integration retrieves different types of log data from Azure.

There are several requirements before using the integration since the logs will actually be read from azure event hubs.

- The logs have to be [exported first to the event hub](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled).
- To export activity logs to event hubs users can follow the steps [here](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export).
- To export audit and sign-in logs to event hubs users can follow the steps [here](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub).

The package contains the following data streams:

## activitylogs

Will retrieve Azure Activity Logs. Control-plane events on Azure Resource Manager resources. Activity Logs provide insight into the operations that were performed on resources in your subscription.

## platformlogs

Will retrieve Azure Platform Logs. Platform Logs provide detailed diagnostic and auditing information for Azure resources and the Azure platform they depend on.

## signinlogs

Will retrieve azure Active Directory sign-in logs. The sign-ins report provides information about the usage of managed applications and user sign-in activities.

## auditlogs

Will retrieve azure Active Directory Audit Logs. The audit logs provide traceability through logs for all changes done by various features within Azure Active Directory (AD). Examples of Audit Logs include changes made to any resources within Azure AD like adding or removing users, apps, groups, roles and policies.

## springcloudlogs

Will retrieve Azure Spring Cloud system and application logs.

## Settings

`eventhub` :
_string_
It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets).
Default value `insights-operational-logs`.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string required to communicate with Event Hubs, steps [here](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string).

A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping the filebeat azure module it can start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key, this key will be used to authorize access to data in your storage account.

`resource_manager_endpoint` :
_string_
Optional, by default we are using the azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different azure environment.

Resource manager endpoints:

```text
# Azure ChinaCloud
https://management.chinacloudapi.cn/

# Azure GermanCloud
https://management.microsoftazure.de/

# Azure PublicCloud 
https://management.azure.com/

# Azure USGovernmentCloud
https://management.usgovcloudapi.net/
```

Users can also use this in case of a Hybrid Cloud model, where one may define their own endpoints.

## Sample Event and Exported Fields

For sample event and exported fields, review documentation provided for each integration:

- Azure Activity Logs
- Active Directory Logs (contains sign-in and audit logs)
- Azure Platform Logs
- Azure Spring Cloud Logs
