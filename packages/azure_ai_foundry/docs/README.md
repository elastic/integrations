# Azure AI Foundry Integration

Azure AI Foundry provides a comprehensive suite of AI services that enable developers to build, deploy, and manage AI solutions efficiently. The Azure AI Foundry integration collects metrics through Azure Monitor, facilitating robust monitoring and operational insights.

## Data streams

### Logs

The Azure AI Foundry logs data stream captures the gateway log events.

These are the supported Azure log categories:

| Data Stream |       Log Category       |
|:-----------:|:------------------------:|
|    logs     |          Audit           |
|    logs     |     RequestResponse      |
|    logs     | ApiManagementGatewayLogs |

#### Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information on how to set up and use this integration.

#### Native Logging

The Azure AI Foundry provides native logging and monitoring to track the telemetry of the service. The Audit and RequestResponse log categories come under the native logging. However, the default logging doesn't log the inputs and outputs of the service. This is useful to ensure that the services operates as expected.

#### API Gateway Logs

The API Management services provide the advanced logging capabilities. The `ApiManagementGatewayLogs` category comes under the advanced logging. This is not directly available in the Azure AI Foundry service itself. You have to set up the API Management services in Azure to access the Azure AI Foundry models. When the setup is complete, add the diagnostic setting for the API Management service.

For more information on how to implement the comprehensive solution using API Management services to monitor the Azure AI Foundry services, check the [AI Foundry API](https://learn.microsoft.com/en-us/azure/api-management/azure-ai-foundry-api) page.

**Diagnostic settings**

- Enable the category `Logs related to ApiManagement Gateway` to stream the logs to the event hub.

```text
   ┌──────────────────┐      ┌──────────────┐     ┌─────────────────┐
   │   APIM service   │      │  Diagnostic  │     │    Event Hub    │
   │    <<source>>    │─────▶│   settings   │────▶│ <<destination>> │
   └──────────────────┘      └──────────────┘     └─────────────────┘
```

### Metrics

The metrics data stream collects the cognitive service metrics that is specific to the Azure AI Foundry service.

#### Key Metrics

**Model HTTP Request Metrics:**
- `Requests`: Total number of calls made to the model API over a period of time.

**Model HTTP Latency Metrics:**
- `Latency`: Measures time taken to process the first byte of response, last byte of response and the request latency.

**Model Usage Metrics:**
- `Token Usage`: Number of prompt tokens processed (input), generated completion tokens (output) and the total tokens of a model.

#### Requirements

Before you start, check the [Authentication and costs](https://docs.elastic.co/integrations/azure_metrics#authentication-and-costs) section.

#### Setup

Follow these [step-by-step instructions](https://docs.elastic.co/integrations/azure_metrics#setup) on how to set up an Azure metrics integration.

#### Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option  for `azure_ai_foundry` should have a value of `300s` or multiple of `300s`for relevant results.

`Resource IDs`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`.
Should return a list of resources.

`Resource Groups`:: (_[]string_) This option will return all Azure AI Foundry services inside the resource group.

If no resource filter is specified, then all Azure AI Foundry services inside the entire subscription will be considered.

The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

### Logs Reference

An example event for `logs` looks as following:

```json
{
    "@timestamp": "2024-07-02T06:31:31.446Z",
    "azure": {
        "ai_foundry": {
            "category": "GatewayLogs",
            "correlation_id": "99789635-18d0-480f-8182-a3a3c477a6a4",
            "deployment_version": "0.44.18652.0",
            "duration_ms": 176,
            "is_request_success": true,
            "location": "East US",
            "operation_name": "Microsoft.ApiManagement/GatewayLogs",
            "properties": {
                "api_id": "azure-ai-foundry-apim-api",
                "api_revision": "1",
                "backend_method": "POST",
                "backend_protocol": "HTTP/1.1",
                "backend_request_body": {
                    "messages": [
                        {
                            "content": "Suggest me a book to read this week?",
                            "role": "user"
                        }
                    ],
                    "model": "gpt-chat-pilot"
                },
                "backend_response_body": {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "index": 0,
                            "message": {
                                "content": "Of course! Here are a few varied suggestions, depending on what you’re in the mood for:\n\n**1. Fiction:**  \n*“The Night Circus”* by Erin Morgenstern – A magical, imaginative, and beautifully written novel with a captivating atmosphere.\n\n**2. Mystery/Thriller:**  \n*“The Thursday Murder Club”* by Richard Osman – A witty and clever mystery set in a quiet English retirement village.\n\n**3. Non-Fiction:**  \n*“Atomic Habits”* by James Clear – A practical and engaging guide to building better habits and making positive changes.\n\n**4. Science Fiction:**  \n*“Project Hail Mary”* by Andy Weir – Fast-paced, humorous, and inventive, from the author of *The Martian*.\n\nIf you tell me a bit about your interests, I can make a more personalized recommendation!",
                                "role": "assistant"
                            }
                        }
                    ],
                    "created": 1719901891,
                    "id": "chatcmpl-9gRL14hGa8nQstOJKvLjh7EyulsnT",
                    "model": "gpt-35-turbo",
                    "object": "chat.completion",
                    "usage": {
                        "input_tokens": 16,
                        "output_tokens": 176,
                        "total_tokens": 192
                    }
                },
                "backend_response_code": 200,
                "backend_time": 176,
                "backend_url": "https://obs-aifoundry-test-01.aifoundry.azure.com/aifoundry/deployments/gpt-chat-pilot/chat/completions?api-version=2024-02-15-preview",
                "cache": "none",
                "client_protocol": "HTTP/1.1",
                "client_tls_version": "1.3",
                "operation_id": "ChatCompletions_Create",
                "request_length": 536,
                "response_length": 1604
            },
            "sku": "Basic",
            "truncated": 0
        },
        "resource": {
            "id": "/subscriptions/12345cabcb4-86e8-404f-a3d2-1dc9982f45ca/resourcegroups/obs-aifoundry-apim-test/providers/microsoft.apimanagement/service/azure-aifoundry-apm"
        }
    },
    "cloud": {
        "provider": "azure"
    },
    "event": {
        "duration": 176000000,
        "outcome": "success"
    },
    "http": {
        "request": {
            "method": "POST"
        },
        "response": {
            "status_code": 200
        }
    },
    "log": {
        "level": "4"
    },
    "source": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156"
    },
    "url": {
        "domain": "azure-aifoundry-apm.azure-api.net",
        "original": "https://azure-aifoundry-apm.azure-api.net/deployments/gpt-chat-pilot/chat/completions?api-version=2024-02-15-preview",
        "path": "/deployments/gpt-chat-pilot/chat/completions",
        "query": "api-version=2024-02-15-preview",
        "scheme": "https"
    }
}
```

**ECS Field Reference**

For more details on ECS fields, check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) documentation.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.ai_foundry.asset_identity | The asset identity key. | keyword |
| azure.ai_foundry.caller_ip_address | The client IP address. (x - last octet masked). | keyword |
| azure.ai_foundry.category | The log category name. | keyword |
| azure.ai_foundry.correlation_id | The correlation id as key. | keyword |
| azure.ai_foundry.deployment_version | The deployment version. | keyword |
| azure.ai_foundry.duration_ms | Time taken to process the request in milliseconds. | long |
| azure.ai_foundry.event | The event type of the service request. | keyword |
| azure.ai_foundry.is_request_success | True if the request is success else return false. | boolean |
| azure.ai_foundry.location | The location. | keyword |
| azure.ai_foundry.operation_name | The log action performed. | keyword |
| azure.ai_foundry.properties.api_id | The request API Id. | keyword |
| azure.ai_foundry.properties.api_name | The API name of the request. | keyword |
| azure.ai_foundry.properties.api_revision | The request API revision. | keyword |
| azure.ai_foundry.properties.backend_id | Backend id. | keyword |
| azure.ai_foundry.properties.backend_method | The backend request method. | keyword |
| azure.ai_foundry.properties.backend_protocol | The backend protocol. | keyword |
| azure.ai_foundry.properties.backend_request_body.messages.content | The prompt input. | keyword |
| azure.ai_foundry.properties.backend_request_body.messages.role | The API access role. | keyword |
| azure.ai_foundry.properties.backend_request_body.model | The model name. | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.custom_blocklists.filtered | Request filtered by custom blocklist. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.custom_blocklists.id | The custom blocklist id. | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.hate.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.hate.severity | The severity levels (safe, low, medium, and high) for hate category. | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.jailbreak.detected | True if the jailbreak risk detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.jailbreak.filtered | True if the content filtered for jailbreak category. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.profanity.detected | The profanity detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.profanity.filtered | Filtered by profanity. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.protected_material_code.citation.license | The license of the repository | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.protected_material_code.citation.url | Example citation of public GitHub repository where code snippet was found. | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.protected_material_code.detected | The protected material code detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.protected_material_code.filtered | Filtered by protected material code. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.protected_material_text.detected | The protected material text detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.protected_material_text.filtered | Filtered by protected material text. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.self_harm.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.self_harm.severity | The severity levels (safe, low, medium, and high) for self-harm category. | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.sexual.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.sexual.severity | The severity levels (safe, low, medium, and high) for sexual category. | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.ungrounded_material.details.completion_end_offset | End offset of the ungrounded completion content. | long |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.ungrounded_material.details.completion_start_offset | Start offset of the ungrounded completion content. | long |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.ungrounded_material.detected | Ungrounded completion content was detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.ungrounded_material.filtered | Filtered by ungrounded completion content. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.violence.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.choices.content_filter_results.violence.severity | The severity levels (safe, low, medium, and high) for violence category. | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.finish_reason | A string indicating the reason why the response was generated (e.g., "max_tokens"). | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.index | The index of the response in the array. | long |
| azure.ai_foundry.properties.backend_response_body.choices.logprobs | An object containing information about the probability distribution over possible responses. | flattened |
| azure.ai_foundry.properties.backend_response_body.choices.message.content | The response text content. | keyword |
| azure.ai_foundry.properties.backend_response_body.choices.message.role | The API access role. | keyword |
| azure.ai_foundry.properties.backend_response_body.content_filtered_categories.category_name | The categories (self-harm, hate, sexual, violence). | keyword |
| azure.ai_foundry.properties.backend_response_body.content_filtered_categories.severity | The severity levels (safe, low, medium, and high). | keyword |
| azure.ai_foundry.properties.backend_response_body.created | The timestamp when the request was created. | long |
| azure.ai_foundry.properties.backend_response_body.error.code | The error code. | keyword |
| azure.ai_foundry.properties.backend_response_body.error.innererror.code | The error code. | keyword |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.custom_blocklists.filtered | Request filtered by custom blocklist. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.custom_blocklists.id | The custom blocklist id. | keyword |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.hate.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.hate.severity | The severity levels (safe, low, medium, and high) for hate category. | keyword |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.jailbreak.detected | True if jailbreak risk is detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.jailbreak.filtered | True if the content filtered for jailbreak category. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.profanity.detected | The profanity detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.profanity.filtered | Filtered by profanity. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.self_harm.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.self_harm.severity | The severity levels (safe, low, medium, and high) for self-harm category. | keyword |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.sexual.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.sexual.severity | The severity levels (safe, low, medium, and high) for sexual category. | keyword |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.violence.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filter_result.violence.severity | The severity levels (safe, low, medium, and high) for violence category. | keyword |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filtered_categories.category_name | The categories (self-harm, hate, sexual, violence). | keyword |
| azure.ai_foundry.properties.backend_response_body.error.innererror.content_filtered_categories.severity | The severity levels (safe, low, medium, and high). | keyword |
| azure.ai_foundry.properties.backend_response_body.error.message | The error message. | text |
| azure.ai_foundry.properties.backend_response_body.error.param | Parameter passed to the API. | keyword |
| azure.ai_foundry.properties.backend_response_body.error.status | The response status code. | long |
| azure.ai_foundry.properties.backend_response_body.id | A unique identifier for the request. | keyword |
| azure.ai_foundry.properties.backend_response_body.model | The ID of the Azure AI Foundry model used to generate the response. | keyword |
| azure.ai_foundry.properties.backend_response_body.object | The operation type. | keyword |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.hate.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.hate.severity | The severity levels (safe, low, medium, and high) for hate category. | keyword |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.jailbreak.detected | True if the jailbreak risk detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.jailbreak.filtered | True if the content filtered for jailbreak category. | boolean |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.profanity.detected | The profanity detected. | boolean |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.profanity.filtered | Filtered by profanity. | boolean |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.self_harm.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.self_harm.severity | The severity levels (safe, low, medium, and high) for self-harm category. | keyword |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.sexual.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.sexual.severity | The severity levels (safe, low, medium, and high) for sexual category. | keyword |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.violence.filtered | True if the content filtered based on severity level. | boolean |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.content_filter_results.violence.severity | The severity levels (safe, low, medium, and high) for violence category. | keyword |
| azure.ai_foundry.properties.backend_response_body.prompt_filter_results.prompt_index | Index of the prompt used to generate response. | long |
| azure.ai_foundry.properties.backend_response_body.system_fingerprint | The fingerprint is generated by Azure API Management and is used to track the performance and usage of the backend service. | keyword |
| azure.ai_foundry.properties.backend_response_body.usage.input_tokens | the total input tokens. | long |
| azure.ai_foundry.properties.backend_response_body.usage.output_tokens | The total output tokens. | long |
| azure.ai_foundry.properties.backend_response_body.usage.total_tokens | The sum of input and output tokens. | long |
| azure.ai_foundry.properties.backend_response_code | The backend HTTP response code. | long |
| azure.ai_foundry.properties.backend_time | The backend response time. | long |
| azure.ai_foundry.properties.backend_url | The backend URL connects to the Azure AI Foundry model. | keyword |
| azure.ai_foundry.properties.cache | The request cache. | keyword |
| azure.ai_foundry.properties.client_protocol | The client HTTP protocol. | keyword |
| azure.ai_foundry.properties.client_tls_cipher_suite | The client TLS Cipher Suite. | keyword |
| azure.ai_foundry.properties.client_tls_version | The client TLS version. | keyword |
| azure.ai_foundry.properties.model_deployment_name | The deployed model name. | keyword |
| azure.ai_foundry.properties.model_name | The Azure AI Foundry model. | keyword |
| azure.ai_foundry.properties.model_version | The Azure AI Foundry model version. | keyword |
| azure.ai_foundry.properties.object_id | The object id of the request. | keyword |
| azure.ai_foundry.properties.operation_id | The operation performed. | keyword |
| azure.ai_foundry.properties.request_length | Length of the request. | double |
| azure.ai_foundry.properties.request_time | Request time taken. | long |
| azure.ai_foundry.properties.response_length | Length of the response. | double |
| azure.ai_foundry.properties.response_time | Response time taken. | long |
| azure.ai_foundry.properties.stream_type | The stream type of the request. | keyword |
| azure.ai_foundry.result_signature | The response status. | keyword |
| azure.ai_foundry.service_name | The service name. | keyword |
| azure.ai_foundry.sku | Stock Keeping Unit that is associated with a particular API Management instance. | keyword |
| azure.ai_foundry.tenant | The tenant location. | keyword |
| azure.ai_foundry.truncated | Condition where the response message is too large to fit in a single packet, so it is truncated or cut off. | long |
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


### Metrics Reference

The Azure AI Foundry metrics provide insights into the performance and usage of your AI resources. These metrics help in monitoring and optimizing your deployments.

An example event for `metrics` looks as following:

```json
{
    "cloud": {
        "provider": "azure",
        "region": "eastus2"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "dd5751b2-98ee-4abe-a555-617ae627e4e2",
        "type": "metricbeat",
        "ephemeral_id": "7359ff11-9479-4b9c-83c4-b0ff8ce0d6ee",
        "version": "8.18.1"
    },
    "@timestamp": "2025-06-16T09:59:00.000Z",
    "ecs": {
        "version": "8.17.0"
    },
    "service": {
        "type": "azure"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "azure.ai_foundry"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "6.10.14-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "family": "",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "EE-87-F8-35-CB-E5"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "dd5751b2-98ee-4abe-a555-617ae627e4e2",
        "version": "8.18.1",
        "snapshot": false
    },
    "metricset": {
        "period": 300000,
        "name": "monitor"
    },
    "event": {
        "duration": 30818990806,
        "agent_id_status": "verified",
        "ingested": "2025-06-16T10:02:45Z",
        "module": "azure",
        "dataset": "azure.ai_foundry"
    },
    "azure": {
        "subscription_id": "12cabcb4-86e8-404f-a3d2-1dc9982f45ca",
        "timegrain": "PT1M",
        "resource": {
            "name": "ai-muthuhub687016784742",
            "id": "/subscriptions/12cabcb4-86e8-404f-a3d2-1dc9982f45ca/resourceGroups/rg-muthukumarparamasivam-0034_ai/providers/Microsoft.CognitiveServices/accounts/ai-muthuhub687016784742",
            "type": "Microsoft.CognitiveServices/accounts",
            "group": "rg-muthukumarparamasivam-0034_ai"
        },
        "namespace": "Microsoft.CognitiveServices/accounts",
        "ai_foundry": {
            "total_tokens": {
                "total": 78
            },
            "output_tokens": {
                "total": 31
            },
            "input_tokens": {
                "total": 47
            }
        },
        "dimensions": {
            "model_version": "1",
            "model_name": "Meta-Llama-3.1-405B-Instruct",
            "api_name": "AIServices",
            "model_deployment_name": "Meta-Llama-3.1-405B-Instruct",
            "region": "eastus2"
        }
    }
}
```

**ECS Field Reference**

For more details on ECS fields, check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) documentation.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| azure.ai_foundry.input_tokens.total | Number of prompt tokens processed (input) on a model. Applies to PTU, PTU-Managed and Pay-as-you-go deployments. | long |  | gauge |
| azure.ai_foundry.model_availability_rate.avg | Availability percentage with the following calculation - (Total Calls - Server Errors)/Total Calls. Server Errors include any HTTP responses \>=500. | float | percent | gauge |
| azure.ai_foundry.model_requests.total | Number of calls made to the model API over a period of time. Applies to PTU, PTU-Managed and Pay-as-you-go deployments. | long |  | gauge |
| azure.ai_foundry.normalized_time_between_tokens.avg | For streaming requests; Model token generation rate, measured in milliseconds. Applies to PTU and PTU-managed deployments. | float |  | gauge |
| azure.ai_foundry.normalized_time_to_first_token.avg | For streaming and non-streaming requests; time it takes for first byte of response data to be received after request is made by model, normalized by token. Applies to PTU, PTU-managed, and Pay-as-you-go deployments. | float |  | gauge |
| azure.ai_foundry.output_tokens.total | Number of tokens generated (output) from an OpenAI and Non-OpenAI models. Applies to PTU, PTU-Managed and Pay-as-you-go deployments. | long |  | gauge |
| azure.ai_foundry.provisioned_utilization.avg | Utilization % for a provisoned-managed deployment, calculated as (PTUs consumed / PTUs deployed) x 100. When utilization is greater than or equal to 100%, calls are throttled and error code 429 returned. | float | percent | gauge |
| azure.ai_foundry.time_to_last_byte.avg | For streaming and non-streaming requests; time it takes for last byte of response data to be received after request is made by model. Applies to PTU, PTU-managed, and Pay-as-you-go deployments. | float |  | gauge |
| azure.ai_foundry.time_to_response.avg | Recommended latency (responsiveness) measure for streaming requests. Applies to PTU and PTU-managed deployments. Calculated as time taken for the first response to appear after a user sends a prompt, as measured by the API gateway. This number increases as the prompt size increases and/or cache hit size reduces. | float |  | gauge |
| azure.ai_foundry.tokens_per_second.avg | Enumerates the generation speed for a given model response. The total tokens generated is divided by the time to generate the tokens, in seconds. Applies to PTU and PTU-managed deployments. | float |  | gauge |
| azure.ai_foundry.total_tokens.total | Number of inference tokens processed on a model. Calculated as prompt tokens (input) plus generated tokens (output). Applies to PTU, PTU-Managed and Pay-as-you-go deployments. | long |  | gauge |
| azure.application_id | The application ID | keyword |  |  |
| azure.dimensions.\* | Azure metric dimensions. | object |  |  |
| azure.dimensions.fingerprint | Autogenerated ID representing the fingerprint of the azure.dimensions object | keyword |  |  |
| azure.namespace | The namespace selected | keyword |  |  |
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

