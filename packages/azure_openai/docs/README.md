# Azure OpenAI Integration

The Azure OpenAI service provides flexibility to build your own copilot and AI applications. The Azure OpenAI integration collects metrics and logs through [azure-monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/metrics-index) and Azure [event hub](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/stream-monitoring-data-event-hubs) respectively.

## Data streams

### Logs

The Azure OpenAI logs data stream captures the audit events and the request-response events.

Supported Azure log categories:

| Data Stream |       Log Category       |
|:-----------:|:------------------------:|
|    logs     |          Audit           |
|    logs     |     RequestResponse      |
|    logs     | ApiManagementGatewayLogs |


#### Note: 
> The logs data stream fetches the default cognitive services log listed [here](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai#:~:text=Metric-,Default%20Azure%20OpenAI%20logging,-This%20solution). This data stream also collect the API Management Gateway logs for the enterprise customer of the Azure OpenAI services API mentioned [here](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai#:~:text=Azure%20OpenAI%20logging-,This%20solution,-Request%20count). This records the inputs and outputs of the request, like prompts, tokens, and model usage.

#### Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

#### Settings

Refer to the [settings](https://docs.elastic.co/integrations/azure#:~:text=*.cloudapp.net-,Settings,-Use%20the%20following) section for more details on the configuration.

#### Logs Reference

An example event for `logs` looks as following:

```json
{
    "@timestamp": "2024-04-08T12:23:02.435Z",
    "azure": {
        "open_ai": {
            "caller_ip_address": "81.2.69.***",
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
        "original": "{\"Tenant\":\"eastus\",\"callerIpAddress\":\"81.2.69.***\",\"category\":\"RequestResponse\",\"correlationId\":\"9d3a6e98-fc11-48d0-82cf-4de065c1a1f8\",\"durationMs\":102,\"event\":\"ShoeboxCallResult\",\"location\":\"eastus\",\"operationName\":\"Create_Thread\",\"properties\":\"{\\\"apiName\\\":\\\"Azure OpenAI API version 2024-02-15-preview\\\",\\\"requestTime\\\":638481757794854611,\\\"requestLength\\\":2,\\\"responseTime\\\":638481757795877942,\\\"responseLength\\\":113,\\\"objectId\\\":\\\"\\\"}\",\"resourceId\":\"/SUBSCRIPTIONS/12CABCB4-86E8-404F-A3D2-1DC9982F45CA/RESOURCEGROUPS/OBS-OPENAI-SERVICE-RS/PROVIDERS/MICROSOFT.COGNITIVESERVICES/ACCOUNTS/OBS-OPENAI-TEST-01\",\"resultSignature\":\"200\",\"time\":\"2024-04-08T12:23:02.4350000Z\"}"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.open_ai.asset_identity | The asset identity key. | keyword |
| azure.open_ai.caller_ip_address | The client IP address. (x - last octet masked). | keyword |
| azure.open_ai.category | The log category name. | keyword |
| azure.open_ai.correlation_id | The correlation id as key. | keyword |
| azure.open_ai.deployment_version | The deployment version. | keyword |
| azure.open_ai.event | The event type of the service request. | keyword |
| azure.open_ai.is_request_success | True if the request is success else return false. | boolean |
| azure.open_ai.location | The location. | keyword |
| azure.open_ai.operation_name | The log action performed. | keyword |
| azure.open_ai.properties.api_id | The request API Id. | keyword |
| azure.open_ai.properties.api_name | The API name of the request. | keyword |
| azure.open_ai.properties.api_revision | The request API revision. | keyword |
| azure.open_ai.properties.backend_method | The backend request method. | keyword |
| azure.open_ai.properties.backend_protocol | The backend protocol. | keyword |
| azure.open_ai.properties.backend_request_body.messages.content | The prompt input. | keyword |
| azure.open_ai.properties.backend_request_body.messages.role | The API access role. | keyword |
| azure.open_ai.properties.backend_request_body.model | The model name. | keyword |
| azure.open_ai.properties.backend_response_body.choices.content_filter_results | Content filtered by custom content filter. | flattened |
| azure.open_ai.properties.backend_response_body.choices.finish_reason | A string indicating the reason why the response was generated (e.g., "max_tokens"). | keyword |
| azure.open_ai.properties.backend_response_body.choices.index | The index of the response in the array. | long |
| azure.open_ai.properties.backend_response_body.choices.logprobs | An object containing information about the probability distribution over possible responses. | flattened |
| azure.open_ai.properties.backend_response_body.choices.message.content | The response text content. | keyword |
| azure.open_ai.properties.backend_response_body.choices.message.role | The API access role. | keyword |
| azure.open_ai.properties.backend_response_body.created | The timestamp when the request was created. | long |
| azure.open_ai.properties.backend_response_body.error.code | The error code. | keyword |
| azure.open_ai.properties.backend_response_body.error.innererror.code | The error code. | keyword |
| azure.open_ai.properties.backend_response_body.error.innererror.content_filter_result | Content filtered by custom content filter. | flattened |
| azure.open_ai.properties.backend_response_body.error.message | The error message. | text |
| azure.open_ai.properties.backend_response_body.error.param | Parameter passed to the API. | keyword |
| azure.open_ai.properties.backend_response_body.error.status | The response status code. | long |
| azure.open_ai.properties.backend_response_body.id | A unique identifier for the request. | keyword |
| azure.open_ai.properties.backend_response_body.model | The ID of the OpenAI model used to generate the response. | keyword |
| azure.open_ai.properties.backend_response_body.object | The operation type. | keyword |
| azure.open_ai.properties.backend_response_body.prompt_filter_results.content_filter_results | Content filtered by custom content filter. | flattened |
| azure.open_ai.properties.backend_response_body.prompt_filter_results.prompt_index | Index of the prompt used to generate response. | long |
| azure.open_ai.properties.backend_response_body.system_fingerprint | The fingerprint is generated by Azure API Management and is used to track the performance and usage of the backend service. | keyword |
| azure.open_ai.properties.backend_response_body.usage.input_tokens | the total input tokens. | long |
| azure.open_ai.properties.backend_response_body.usage.output_tokens | The total output tokens. | long |
| azure.open_ai.properties.backend_response_body.usage.total_tokens | The sum of input and output tokens. | long |
| azure.open_ai.properties.backend_response_code | The backend HTTP response code. | long |
| azure.open_ai.properties.backend_time | The backend response time. | long |
| azure.open_ai.properties.backend_url | The backend URL connects to the Azure OpenAI model. | keyword |
| azure.open_ai.properties.cache | The request cache. | keyword |
| azure.open_ai.properties.client_protocol | The client HTTP protocol. | keyword |
| azure.open_ai.properties.client_tls_version | The client TLS version. | keyword |
| azure.open_ai.properties.model_deployment_name | The deployed model name. | keyword |
| azure.open_ai.properties.model_name | The OpenAI model. | keyword |
| azure.open_ai.properties.model_version | The OpenAI model version. | keyword |
| azure.open_ai.properties.object_id | The object id of the request. | keyword |
| azure.open_ai.properties.operation_id | The operation performed. | keyword |
| azure.open_ai.properties.request_length | Length of the request. | double |
| azure.open_ai.properties.request_time | Request time taken. | long |
| azure.open_ai.properties.response_length | Length of the response. | double |
| azure.open_ai.properties.response_time | Response time taken. | long |
| azure.open_ai.properties.stream_type | The stream type of the request. | keyword |
| azure.open_ai.result_signature | The response status. | keyword |
| azure.open_ai.sku | Stock Keeping Unit that is associated with a particular API Management instance. | keyword |
| azure.open_ai.tenant | The tenant location. | keyword |
| azure.open_ai.truncated | Condition where the response message is too large to fit in a single packet, so it is truncated or cut off. | long |
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

The metrics data stream collects the cognitive service metrics that is specific to the Azure OpenAI service. The metrics that are specific to PTUs will only be available with the provisioned deployments.

Refer [here](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/monitoring#:~:text=Applies%20to%20PTU%2C%20and%20PTU%2Dmanaged%20deployments) to find more details on the metrics applicable to PTU only deployment.

#### Requirements

Before you start, check the [Authentication and costs](https://docs.elastic.co/integrations/azure_metrics#authentication-and-costs) section.

#### Setup

Follow these [step-by-step instructions](https://docs.elastic.co/integrations/azure_metrics#setup) on how to set up an Azure metrics integration.

#### Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `azure_openai` should have a value of `300s` or multiple of `300s`for relevant results.

`Resource IDs`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
Should return a list of resources.

`Resource Groups`:: (_[]string_) This option will return all Azure OpenAI services inside the resource group.

If no resource filter is specified, then all Azure OpenAI services inside the entire subscription will be considered.

The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

#### Metrics Reference

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2024-04-11T01:46:00.000Z",
    "agent": {
        "ephemeral_id": "dcff0e53-fadb-4e97-86a2-1e611f12fc34",
        "id": "0c09f097-dc30-44c5-b3e7-083f1a14873c",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.13.0"
    },
    "azure": {
        "dimensions": {
            "api_name": "Azure OpenAI API version 2024-04-01-preview",
            "model_deployment_name": "gpt-chat-pilot",
            "model_name": "gpt-35-turbo",
            "model_version": "0301",
            "operation_name": "ChatCompletions_Create",
            "region": "East US",
            "status_code": "200",
            "stream_type": "Streaming"
        },
        "namespace": "Microsoft.CognitiveServices/accounts",
        "open_ai": {
            "requests": {
                "total": 1
            }
        },
        "resource": {
            "group": "obs-openai-service-rs",
            "id": "/subscriptions/12cabcb4-86e8-404f-a3d2-1dc9982f45ca/resourceGroups/obs-openai-service-rs/providers/Microsoft.CognitiveServices/accounts/obs-openai-test-01",
            "name": "obs-openai-test-01",
            "type": "Microsoft.CognitiveServices/accounts"
        },
        "subscription_id": "12cabcb4-86e8-404f-a3d2-1dc9982f45ca",
        "timegrain": "PT1M"
    },
    "cloud": {
        "provider": "azure",
        "region": "eastus"
    },
    "data_stream": {
        "dataset": "azure.open_ai",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0c09f097-dc30-44c5-b3e7-083f1a14873c",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "azure.open_ai",
        "duration": 2216811793,
        "ingested": "2024-04-11T01:52:30Z",
        "module": "azure"
    },
    "metricset": {
        "name": "monitor",
        "period": 300000
    },
    "service": {
        "type": "azure"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| azure.application_id | The application ID | keyword |  |  |
| azure.dimensions.\* | Azure metric dimensions. | object |  |  |
| azure.dimensions.fingerprint | Autogenerated ID representing the fingerprint of the azure.dimensions object | keyword |  |  |
| azure.namespace | The namespace selected | keyword |  |  |
| azure.open_ai.active_tokens.total | Total tokens minus cached tokens over a period of time. | long |  | gauge |
| azure.open_ai.context_tokens_cache_match_rate.avg | Percentage of the prompt tokens hit the cache (Avaiable for PTU-managed). | float |  | gauge |
| azure.open_ai.fine_tuned_training_hours.total | Number of Training Hours Processed on an OpenAI FineTuned Model. | float |  | gauge |
| azure.open_ai.generated_tokens.total | Number of tokens generated (output) from an OpenAI model. | long |  | gauge |
| azure.open_ai.processed_prompt_tokens.total | Number of prompt tokens processed (input) on an OpenAI model. | long |  | gauge |
| azure.open_ai.provisioned_managed_utilization_v2.avg | Utilization % for a provisoned-managed deployment, calculated as (PTUs consumed / PTUs deployed) x 100. When utilization is greater than or equal to 100%, calls are throttled and error code 429 returned. | float | percent | gauge |
| azure.open_ai.requests.total | Number of calls made to the Azure OpenAI API over a period of time. | long |  | gauge |
| azure.open_ai.time_to_response.avg | Recommended latency (responsiveness) measure for streaming requests. Applies to PTU and PTU-managed deployments. Calculated as time taken for the first response to appear after a user sends a prompt, as measured by the API gateway. This number increases as the prompt size increases and/or cache hit size reduces. | float |  | gauge |
| azure.open_ai.token_transaction.total | Number of inference tokens processed on an OpenAI model. | long |  | gauge |
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

