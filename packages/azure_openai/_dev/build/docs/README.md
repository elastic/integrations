# Azure OpenAI Integration

The Azure OpenAI service provides flexibility to build your own copilot and AI applications. The Azure OpenAI integration collects metrics and logs through [azure-monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/metrics-index) and Azure [event hub](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/stream-monitoring-data-event-hubs) respectively.

To fully populate the Azure OpenAI dashboard lenses, enabling both logs and metrics data streams and setting up the Azure Billing integration in advance is necessary.

## Data streams

### Logs

The Azure OpenAI logs data stream captures the audit events and the request-response events.

Supported Azure log categories:

| Data Stream |       Log Category       |
|:-----------:|:------------------------:|
|    logs     |          Audit           |
|    logs     |     RequestResponse      |
|    logs     | ApiManagementGatewayLogs |


#### Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

#### Default Logging

The Azure OpenAI provides native logging and monitoring with which you can track the telemetry of the service. The Audit and the RequestResponse log categories comes under the native logging. But the default logging doesn't log the inputs and outputs of the service. These are the useful to ensure that the services operates as expected.

The logs collected using the default cognitive services is listed [here](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai#:~:text=Metric-,Default%20Azure%20OpenAI%20logging,-This%20solution).

#### Advance Logging

The API Management services provides the advance logging capabilities. The ApiManagementGatewayLogs category comes under the advance logging. This is not directly available in the Azure OpenAI service itself. You have to setup the API Management services in the Azure to access the Azure OpenAI. Once the setup is done add the diagnostic setting for the API Management service.

You can find information on how to implement the comprehensive solution using API Management services to monitor the Azure OpenAI services [here](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai). 

**Diagnostic settings**

- Enable the category `Logs related to ApiManagement Gateway` to stream the logs to the event hub.

```text
   ┌──────────────────┐      ┌──────────────┐     ┌─────────────────┐
   │   APIM service   │      │  Diagnostic  │     │    Event Hub    │
   │    <<source>>    │─────▶│   settings   │────▶│ <<destination>> │
   └──────────────────┘      └──────────────┘     └─────────────────┘
```

The logs collected using the API Management services for the enterprise customer of the Azure OpenAI services is listed [here](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai#:~:text=Azure%20OpenAI%20logging-,This%20solution,-Request%20count). This records the inputs and outputs of the request, like prompts, tokens, and model usage.

#### Settings

Refer to the [settings](https://docs.elastic.co/integrations/azure#:~:text=*.cloudapp.net-,Settings,-Use%20the%20following) section for more details on the configuration.

#### Logs Reference

{{event "logs"}}

**ECS Field Reference**

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

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "metrics"}}
