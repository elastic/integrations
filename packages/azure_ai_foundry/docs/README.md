# Azure AI Foundry Integration

Azure AI Foundry provides a comprehensive suite of AI services that enable developers to build, deploy, and manage AI solutions efficiently. The Azure AI Foundry integration collects metrics through Azure Monitor, facilitating robust monitoring and operational insights.

## Data streams

### Metrics

The metrics data stream collects the cognitive service metrics that is specific to the Azure AI Foundry service.

#### Key Metrics

**Model HTTP Request Metrics:**
- `Requests`: Total number of calls made to the model API over a period of time.

**Model HTTP Request Metrics:**
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

#### Metrics Reference

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

