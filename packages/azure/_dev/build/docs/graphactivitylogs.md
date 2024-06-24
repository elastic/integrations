# Microsoft Graph Activity Logs

Microsoft Graph Activity Logs provide an audit trail of all HTTP requests that the Microsoft Graph service has received and processed for a tenant. Microsoft Graph Activity Logs gives full visibility into all transactions made by applications and other API clients that you have consented to in the tenant. Refer to [Microsoft Graph Activity Common Usecases](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#common-use-cases-for-microsoft-graph-activity-logs) for more use cases.

Tenant administrators can configure the collection and storage destinations of Microsoft Graph Activity Logs through Diagnostic Setting in the Entra Portal. This integration uses Azure Event Hubs destination to stream Microsoft Graph Activity Logs to Elastic.

## Requirements and Setup

### Prerequisites

Following privileges are required to collect Microsoft Graph Activity Logs:
- A Microsoft Entra ID P1 or P2 tenant license in your tenant.
- A `Security Administrator` or `Global Administrator` Microsoft Entra ID role to configure the diagnostic settings.
Refer to [Microsoft Graph Prerequisites](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#prerequisites) for more information on required privileges.

### Setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

### Limitations

- Activities of multi-tenant applications belonging to another tenant are not available.
- In few rare cases, events might take up to 2 hours to be delivered to Event Hubs.
Refer to [Microsoft Graph Activity Limitations](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#limitations) for more information.

## Settings

`eventhub` :
  _string_
It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You _can_ use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
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

`storage_account_container` :
_string_
The storage account container where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You MUST use a dedicated storage account container for each Azure log type (activity, sign-in, audit logs, and others). DO NOT REUSE the same container name for more than one Azure log type. See [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name if not specified. 

`resource_manager_endpoint` :
_string_
Optional, by default we are using the azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different Azure environment.

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

## Logs

### graphactivitylogs

The `graphactivitylogs` data stream of the Azure Logs package will collect Microsoft Graph activity events that have been streamed through an azure event hub.

{{event "graphactivitylogs"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "graphactivitylogs"}}
