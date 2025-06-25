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

{{event "metrics"}}

**ECS Field Reference**

For more details on ECS fields, check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) documentation.

{{fields "metrics"}}
