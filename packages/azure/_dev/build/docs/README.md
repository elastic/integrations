# Azure Logs Integration
The azure logs integration retrieves activity, platform, sign-in, audit, and Spring Cloud data from [Azure](https://docs.microsoft.com/en-us/azure/?product=popular).

Use the Azure Logs integration to collect logs from Azure.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference data when troubleshooting an issue.

For example, if you wanted to detect possible brute force sign-in attacks, you
could install the Azure Logs integration to send Azure sign-in logs to Elastic.
Then, set up a new rule in the Elastic Observability Logs app to alert you when the number of failed sign-in attempts exceeds a certain threshold.
Or, perhaps you want to better plan your Azure capacity.
Send Azure activity logs to Elastic to track and visualize when your virtual machines
fail to start due to an exceed quota limit.

## Data streams

The Azure Logs integration collects logs.

**Logs** help you keep a record of events that happen on your machine.
Log data streams collected by the Azure Logs integration include activity, platform, sign-in, audit, and Spring Cloud logs.
See more details in the [Logs reference](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

Before adding the integration, you must complete the following tasks as logs are read from Azure Event Hubs:

* Your logs have to first be exported to the [Event Hub](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create-kafka-enabled)
 * To export activity logs to event hubs, follow the steps in Microsoft's [Legacy collection methods documentation](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export)
* To export audit and sign-in logs to event hubs, follow the steps in Microsoft's [Stream Azure Active Directory logs to an Azure Event Hub tutorial](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/tutorial-azure-monitor-stream-logs-to-event-hub)

## Settings

Use the following settings to configure the Azure Logs integration when you add it to Fleet.

`eventhub` :
_string_
A fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets).
Default value `insights-operational-logs`.

`consumer_group` :
_string_
Enable the publish/subscribe mechanism of Event Hubs with consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_

The connection string required to communicate with Event Hubs. See [Get an Event Hubs connection string](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string) for more information.

A Blob Storage account is required to store/retrieve/update the offset or state of the Event Hub messages. This allows the integration to start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account that the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key. Used to authorize access to data in your storage account.

`resource_manager_endpoint` :
_string_
Optional. By default, the integration uses the Azure public environment. To override this and use a different Azure environment, users can provide a specific resource manager endpoint

Examples:

* Azure ChinaCloud: `https://management.chinacloudapi.cn/`
* Azure GermanCloud: `https://management.microsoftazure.de/`
* Azure PublicCloud: `https://management.azure.com/`
* Azure USGovernmentCloud: `https://management.usgovcloudapi.net/`

This setting can also be used to define your own endpoints, like for hybrid cloud models.

## Logs reference

### Activity logs
Retrieves Azure activity logs. Activity logs provide insight into the operations that were performed on resources in your subscription.

{{event "activitylogs"}}

{{fields "activitylogs"}}

### Platform logs
Retrieves Azure platform logs. Platform logs provide detailed diagnostic and auditing information for Azure resources and the Azure platform they depend on.

{{event "platformlogs"}}

{{fields "platformlogs"}}

### Sign-in logs
Retrieves Azure Active Directory sign-in logs. The sign-ins report provides information about the usage of managed applications and user sign-in activities.

{{event "signinlogs"}}

{{fields "signinlogs"}}

### Audit logs
Retrieves Azure Active Directory audit logs. The audit logs provide traceability through logs for all changes done by various features within Azure AD. Examples of audit logs include changes made to any resources within Azure AD like adding or removing users, apps, groups, roles and policies.

{{event "auditlogs"}}

{{fields "auditlogs"}}

### Spring Cloud logs

Retrieves Azure Spring Cloud system and application logs.

{{event "springcloudlogs"}}

{{fields "springcloudlogs"}}
