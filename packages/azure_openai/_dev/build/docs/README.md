# Azure OpenAI Integration

The Azure OpenAI service provides flexibility to build your own copilot and AI applications. The Azure OpenAI integration collects metrics and logs through [azure-monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/metrics-index) and Azure [event hub](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/stream-monitoring-data-event-hubs) respectively.

## Data streams

### Logs

The Azure OpenAI logs data stream captures the audit events and the request-response events.

Supported Azure log categories:

| Data Stream |  Log Category   |
|:-----------:|:---------------:|
|    logs     |      audit      |
|    logs     | requestresponse |


**Note**:

The logs data stream fetches the default cognitive services log listed [here](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai#:~:text=Metric-,Default%20Azure%20OpenAI%20logging,-This%20solution). This doesn't record the inputs and outputs of the service, like prompts, tokens, and models.

#### Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

#### Settings

Refer to the [settings](https://docs.elastic.co/integrations/azure#:~:text=*.cloudapp.net-,Settings,-Use%20the%20following) section for more details on the configuration.

#### Logs Reference

{{event "logs"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "logs"}}

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

{{event "metrics"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "metrics"}}
