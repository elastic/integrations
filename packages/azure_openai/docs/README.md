# Azure OpenAI Integration

The Azure OpenAI service provides flexibility to build your own copilot and AI applications. The Azure OpenAI integration collects and aggregates OpenAI related logs, such as audit and request-response logs and metrics from Microsoft.CognitiveServices type resources for analysis, visualization, and alerting.
Additional Azure API calls will be executed to retrieve information regarding the resources targeted by the user.

## Data streams

### Logs

The Azure OpenAI logs data stream captures the audit events and the request-response events.

Supported Azure log categories:

| Data Stream |  Log Category   |
|:-----------:|:---------------:|
|    logs     |      audit      |
|    logs     | requestresponse |


## Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

## Settings

`eventhub` :
_string_
It is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value: `insights-operational-logs`.

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

An example event for `logs` looks as following:

```json
{
    "@timestamp": "2024-04-08T12:23:02.435Z",
    "azure": {
        "open_ai": {
            "caller_ip_address": "81.2.69.144",
            "category": "RequestResponse",
            "correlation_id": "9d3a6e98-fc11-48d0-82cf-4de065c1a1f8",
            "event": "ShoeboxCallResult",
            "location": "eastus",
            "operation_name": "Create_Thread",
            "properties": {
                "api_name": "Azure OpenAI API version 2024-02-15-preview",
                "object_id": "",
                "request_length": 2,
                "request_time": 638481757794854611,
                "response_length": 113,
                "response_time": 638481757795877942
            },
            "result_signature": "200",
            "tenant": "eastus"
        },
        "resource": {
            "group": "obs-openai-service-rs",
            "id": "/subscriptions/12cabcb4-86e8-404f-a3d2-1dc9982f45ca/resourcegroups/obs-openai-service-rs/providers/microsoft.cognitiveservices/accounts/obs-openai-test-01",
            "name": "obs-openai-test-01",
            "provider": "microsoft.cognitiveservices/accounts"
        }
    },
    "cloud": {
        "provider": "azure"
    },
    "event": {
        "duration": 102000000,
        "original": "{\"Tenant\":\"eastus\",\"callerIpAddress\":\"81.2.69.144\",\"category\":\"RequestResponse\",\"correlationId\":\"9d3a6e98-fc11-48d0-82cf-4de065c1a1f8\",\"durationMs\":102,\"event\":\"ShoeboxCallResult\",\"location\":\"eastus\",\"operationName\":\"Create_Thread\",\"properties\":\"{\\\"apiName\\\":\\\"Azure OpenAI API version 2024-02-15-preview\\\",\\\"requestTime\\\":638481757794854611,\\\"requestLength\\\":2,\\\"responseTime\\\":638481757795877942,\\\"responseLength\\\":113,\\\"objectId\\\":\\\"\\\"}\",\"resourceId\":\"/SUBSCRIPTIONS/12CABCB4-86E8-404F-A3D2-1DC9982F45CA/RESOURCEGROUPS/OBS-OPENAI-SERVICE-RS/PROVIDERS/MICROSOFT.COGNITIVESERVICES/ACCOUNTS/OBS-OPENAI-TEST-01\",\"resultSignature\":\"200\",\"time\":\"2024-04-08T12:23:02.4350000Z\"}"
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
| azure.open_ai.asset_identity | The asset identity key. | keyword |
| azure.open_ai.caller_ip_address | The client IP address. (x - last octet masked). | keyword |
| azure.open_ai.category | The log category name. | keyword |
| azure.open_ai.correlation_id | The correlation id as key. | keyword |
| azure.open_ai.event | The event type of the service request. | keyword |
| azure.open_ai.location | The location. | keyword |
| azure.open_ai.operation_name | The log action performed. | keyword |
| azure.open_ai.properties.api_name | The API name of the request. | keyword |
| azure.open_ai.properties.object_id | The object id of the request. | keyword |
| azure.open_ai.properties.request_length | Length of the request. | double |
| azure.open_ai.properties.request_time | Request time taken. | long |
| azure.open_ai.properties.response_length | Length of the response. | double |
| azure.open_ai.properties.response_time | Response time taken. | long |
| azure.open_ai.result_signature | The response status. | keyword |
| azure.open_ai.tenant | The tenant location. | keyword |
| azure.resource.authorization_rule | Authorization rule | keyword |
| azure.resource.group | The resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | The name of the resource | keyword |
| azure.resource.namespace | Resource type/namespace | keyword |
| azure.resource.provider | The resource group | keyword |
| azure.resource.type | The type of the resource | keyword |
| azure.subscription_id | The subscription ID | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |


### Metrics

## Requirements

Before you start, check the [Authentication and costs](https://docs.elastic.co/integrations/azure_metrics#authentication-and-costs) section.

## Setup

Follow these [step-by-step instructions](https://docs.elastic.co/integrations/azure_metrics#setup) on how to set up an Azure metrics integration.

## Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `azure_openai` should have a value of `300s` or multiple of `300s`for relevant results.

`Resource IDs`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
Should return a list of resources.

`Resource Groups`:: (_[]string_) This option will return all Azure OpenAI services inside the resource group.

If no resource filter is specified, then all Azure OpenAI services inside the entire subscription will be considered.

The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

An example event for `metrics` looks as following:

```json
{
    "cloud": {
        "provider": "azure",
        "region": "eastus"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "0c09f097-dc30-44c5-b3e7-083f1a14873c",
        "ephemeral_id": "dcff0e53-fadb-4e97-86a2-1e611f12fc34",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "@timestamp": "2024-04-11T01:46:00.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "azure.open_ai"
    },
    "service": {
        "type": "azure"
    },
    "elastic_agent": {
        "id": "0c09f097-dc30-44c5-b3e7-083f1a14873c",
        "version": "8.13.0",
        "snapshot": false
    },
    "metricset": {
        "period": 300000,
        "name": "monitor"
    },
    "event": {
        "duration": 2216811793,
        "agent_id_status": "verified",
        "ingested": "2024-04-11T01:52:30Z",
        "module": "azure",
        "dataset": "azure.open_ai"
    },
    "azure": {
        "subscription_id": "12cabcb4-86e8-404f-a3d2-1dc9982f45ca",
        "timegrain": "PT1M",
        "resource": {
            "name": "obs-openai-test-01",
            "id": "/subscriptions/12cabcb4-86e8-404f-a3d2-1dc9982f45ca/resourceGroups/obs-openai-service-rs/providers/Microsoft.CognitiveServices/accounts/obs-openai-test-01",
            "type": "Microsoft.CognitiveServices/accounts",
            "group": "obs-openai-service-rs"
        },
        "namespace": "Microsoft.CognitiveServices/accounts",
        "open_ai": {
            "requests": {
                "total": 1
            }
        },
        "dimensions": {
            "operation_name": "ChatCompletions_Create",
            "model_version": "0301",
            "status_code": "200",
            "model_name": "gpt-35-turbo",
            "api_name": "Azure OpenAI API version 2024-04-01-preview",
            "stream_type": "Streaming",
            "model_deployment_name": "gpt-chat-pilot",
            "region": "East US"
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| azure.application_id | The application ID | keyword |  |  |
| azure.dimensions.\* | Azure metric dimensions. | object |  |  |
| azure.dimensions.fingerprint | Autogenerated ID representing the fingerprint of the azure.dimensions object | keyword |  |  |
| azure.namespace | The namespace selected | keyword |  |  |
| azure.open_ai.active_tokens.total | Total tokens minus cached tokens over a period of time. | float |  | gauge |
| azure.open_ai.fine_tuned_training_hours.total | Number of Training Hours Processed on an OpenAI FineTuned Model. | float |  | gauge |
| azure.open_ai.generated_tokens.total | Number of tokens generated (output) from an OpenAI model. | float |  | gauge |
| azure.open_ai.processed_prompt_tokens.total | Number of prompt tokens processed (input) on an OpenAI model. | float |  | gauge |
| azure.open_ai.provisioned_managed_utilization_v2.avg | Utilization % for a provisoned-managed deployment, calculated as (PTUs consumed / PTUs deployed) x 100. When utilization is greater than or equal to 100%, calls are throttled and error code 429 returned. | float | percent | gauge |
| azure.open_ai.raiharmful_requests.total | ContentSafety - Risks&Safety. Number of calls made to Azure OpenAI API and detected as harmful(both block model and annotate mode) by content filter applied over a period of time. | float |  | gauge |
| azure.open_ai.rairejected_requests.total | ContentSafety - Risks&Safety. Number of calls made to Azure OpenAI API and rejected by content filter applied over a period of time. | float |  | gauge |
| azure.open_ai.raitotal_requests.total | ContentSafety - Risks&Safety. Number of calls made to Azure OpenAI API and detected by content filter applied over a period of time. | float |  | gauge |
| azure.open_ai.requests.total | Number of calls made to the Azure OpenAI API over a period of time. | float |  | gauge |
| azure.open_ai.token_transaction.total | Number of inference tokens processed on an OpenAI model. | float |  | gauge |
| azure.resource.group | The resource group | keyword |  |  |
| azure.resource.id | The id of the resource | keyword |  |  |
| azure.resource.name | The name of the resource | keyword |  |  |
| azure.resource.tags.\* | Azure resource tags. | object |  |  |
| azure.resource.type | The type of the resource | keyword |  |  |
| azure.subscription_id | The subscription ID | keyword |  |  |
| azure.timegrain | The Azure metric timegrain | keyword |  |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| dataset.name | Dataset name. | constant_keyword |  |  |
| dataset.namespace | Dataset namespace. | constant_keyword |  |  |
| dataset.type | Dataset type. | constant_keyword |  |  |

