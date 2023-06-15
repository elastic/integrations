# Azure Functions

The Azure Functions integration allows you to monitor Azure Functions. Azure Functions is an event-driven, serverless compute platform that helps you develop more efficiently using the programming language of your choice. Triggers cause a function to run. A trigger defines how a function is invoked and a function must have exactly one trigger. 

Use this integration to build web APIs, respond to database changes, process IoT streams, manage message queues, and more. Refer common [Azure Functions scenarios](https://learn.microsoft.com/en-us/azure/azure-functions/functions-scenarios?pivots=programming-language-csharp) for more information.


## Data streams
Supported log categories:

| Log Category                 | Description                                                                                                                          |
|:----------------------------:|:------------------------------------------------------------------------------------------------------------------------------------:|
| Functionapplogs | Function app logs.        |


[ref](https://learn.microsoft.com/en-us/azure/azure-functions/monitor-functions-reference#resource-logs)


## Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

## Settings

`eventhub` :
  _string_
An Event Hub is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string is required to communicate with Event Hubs, see steps [here](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string).

A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping the Azure logs package it can start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account where the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key, this key will be used to authorize access to data in your storage account.

`storage_account_container` :
_string_
The storage account container where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You MUST use a dedicated storage account container for each Azure log type (activity, sign-in, audit logs, and others). DO NOT REUSE the same container name for more than one Azure log type. See [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name if not specified.

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

## Logs
An example event for `functionapplogs` datastream looks as follows:

```json
        {
            "@timestamp": "2023-05-23T20:11:59.000Z",
            "azure": {
                "category": "FunctionAppLogs",
                "function": {
                    "app_name": "test-function",
                    "category": "Function.hello",
                    "event_name": "FunctionStarted",
                    "function_invocation_id": "d878e365-b3d6-4796-9292-7500acd0c677",
                    "function_name": "Functions.hello",
                    "host_instance_id": "bb84c437-4c26-4d0b-a06d-7fc2f16976e3",
                    "host_version": "4.19.2.2",
                    "level": "Information",
                    "level_id": 2,
                    "message": "Executing Functions.hello (Reason=This function was programmatically called via the host APIs., Id=d878e365-b3d6-4796-9292-7500acd0c677)",
                    "process_id": 67,
                    "role_instance": "54108609-638204200593759681"
                },
                "operation_name": "Microsoft.Web/sites/functions/log",
                "resource": {
                    "group": "TEST-RG",
                    "id": "/SUBSCRIPTIONS/12CABCB4-86E8-404F-A3D2-1DC9982F45CA/RESOURCEGROUPS/TEST-RG/PROVIDERS/MICROSOFT.WEB/SITES/TEST-FUNCTION",
                    "name": "TEST-FUNCTION",
                    "provider": "MICROSOFT.WEB/SITES"
                },
                "subscription_id": "12CABCB4-86E8-404F-A3D2-1DC9982F45CA"
            },
            "cloud": {
                "account": {
                    "id": "12CABCB4-86E8-404F-A3D2-1DC9982F45CA"
                },
                "provider": "azure"
            },
            "ecs": {
                "version": "8.8.0"
            },
            "event": {
                "original": "{\"time\":\"2023-05-23T20:11:59Z\",\"resourceId\":\"/SUBSCRIPTIONS/12CABCB4-86E8-404F-A3D2-1DC9982F45CA/RESOURCEGROUPS/TEST-RG/PROVIDERS/MICROSOFT.WEB/SITES/TEST-FUNCTION\",\"category\":\"FunctionAppLogs\",\"operationName\":\"Microsoft.Web/sites/functions/log\",\"level\":\"Informational\",\"location\":\"East US\",\"properties\":{\"appName\":\"test-function\",\"roleInstance\":\"54108609-638204200593759681\",\"message\":\"Executing Functions.hello (Reason=This function was programmatically called via the host APIs., Id=d878e365-b3d6-4796-9292-7500acd0c677)\",\"category\":\"Function.hello\",\"hostVersion\":\"4.19.2.2\",\"functionInvocationId\":\"d878e365-b3d6-4796-9292-7500acd0c677\",\"functionName\":\"Functions.hello\",\"hostInstanceId\":\"bb84c437-4c26-4d0b-a06d-7fc2f16976e3\",\"level\":\"Information\",\"levelId\":2,\"processId\":67,\"eventId\":1,\"eventName\":\"FunctionStarted\"}}"
            },
            "observer": {
                "product": "Azure Functions",
                "type": "functions",
                "vendor": "Azure"
            },
            "tags": [
                "preserve_original_event"
            ]
        }
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.function.app_name | The Function application name. | keyword |
| azure.function.category | Category | keyword |
| azure.function.event_name | The event name. | keyword |
| azure.function.function_invocation_id | The invocation ID that logged the message | keyword |
| azure.function.function_name_ | The name of the Azure function that logged the message | keyword |
| azure.function.host_instance_id | The host instance ID. | keyword |
| azure.function.host_version | The functions host version | keyword |
| azure.function.level | The log level. Valid values are Trace, Debug, Information, Warning, Error, or Critical. | keyword |
| azure.function.level_id | The integer value of the log level. Valid values are 0 (Trace), 1 (Debug), 2 (Information), 3 (Warning), 4 (Error), or 5 (Critical). | long |
| azure.function.message | The log message specific to the function | keyword |
| azure.function.process_id | The process ID | long |
| azure.function.role_instance | The role instance ID | keyword |
| azure.resource.group | Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
