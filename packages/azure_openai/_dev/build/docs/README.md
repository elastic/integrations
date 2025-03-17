# Azure OpenAI Integration

The Azure OpenAI service provides flexibility to build your own copilot and AI applications. The Azure OpenAI integration collects metrics and logs through [azure-monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/metrics-index) and the Azure [event hub](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/stream-monitoring-data-event-hubs) respectively.

To fully populate the Azure OpenAI dashboard lenses, you have to enable both logs and metrics data streams and set up the Azure Billing integration in advance.

## Data streams

### Logs

The Azure OpenAI logs data stream captures the audit events and the request-response events.

These are the supported Azure log categories:

| Data Stream |       Log Category       |
|:-----------:|:------------------------:|
|    logs     |          Audit           |
|    logs     |     RequestResponse      |
|    logs     | ApiManagementGatewayLogs |


#### Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information on how to set up and use this integration.

#### Default Logging

The Azure OpenAI provides native logging and monitoring to track the telemetry of the service. The Audit and RequestResponse log categories come under the native logging. However, the default logging doesn't log the inputs and outputs of the service. This is useful to ensure that the services operates as expected.

The logs collected using the default cognitive services are listed on the [Monitor OpenAI models](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai#:~:text=Metric-,Default%20Azure%20OpenAI%20logging,-This%20solution) page.

#### Advance Logging

The API Management services provide the advanced logging capabilities. The `ApiManagementGatewayLogs` category comes under the advanced logging. This is not directly available in the Azure OpenAI service itself. You have to set up the API Management services in Azure to access the Azure OpenAI. When the setup is complete, add the diagnostic setting for the API Management service.

For more information on how to implement the comprehensive solution using API Management services to monitor the Azure OpenAI services, check the [Monitor OpenAI models](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai) page.

**Diagnostic settings**

- Enable the category `Logs related to ApiManagement Gateway` to stream the logs to the event hub.

```text
   ┌──────────────────┐      ┌──────────────┐     ┌─────────────────┐
   │   APIM service   │      │  Diagnostic  │     │    Event Hub    │
   │    <<source>>    │─────▶│   settings   │────▶│ <<destination>> │
   └──────────────────┘      └──────────────┘     └─────────────────┘
```

The logs collected using the API Management services for the enterprise customer of the Azure OpenAI services are listed on the [Monitor OpenAI models](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/openai/architecture/log-monitor-azure-openai#:~:text=Azure%20OpenAI%20logging-,This%20solution,-Request%20count) page. This records the inputs and outputs of the request, like prompts, tokens, and model usage.

##### Content Filtering

Azure OpenAI Content Filter's sophisticated algorithms analyze text and multimedia content to identify potential issues related to violence, explicit language, or other sensitive topics.
This process includes monitoring key metrics such as false positives, false negatives, precision, recall, and overall model performance. By continuously monitoring the content filtering data, organizations can identify any potential biases, errors, or gaps in the AI model's decision-making process and make necessary adjustments to improve the overall content filtering accuracy and compliance with regulatory requirements.

In Azure OpenAI content filtering, users can create a custom blocklist to specify specific words, phrases, or content that they want the AI model to filter out. Users can now monitor the custom blocklists by blocklist id.

It provides a robust system for filtering content based on predefined categories and severity levels such as safe, low, medium, and high.

Check [Azure OpenAI Content Filter's](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/content-filter?tabs=warning%2Cuser-prompt%2Cpython-new) for more details.

#### Settings

Refer to [Azure Logs Integration settings](https://docs.elastic.co/integrations/azure#:~:text=*.cloudapp.net-,Settings,-Use%20the%20following) for more details on the configuration.

#### Logs Reference

{{event "logs"}}

**ECS Field Reference**

For more details on ECS fields, check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) documentation.

{{fields "logs"}}

### Metrics

The metrics data stream collects the cognitive service metrics that is specific to the Azure OpenAI service. The metrics that are specific to PTUs will only be available with the provisioned deployments.

For more details on the metrics applicable to PTU only deployment, check the [Monitor Azure OpenAI](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/monitoring#:~:text=Applies%20to%20PTU%2C%20and%20PTU%2Dmanaged%20deployments) documentaiton.

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

For more details on ECS fields, check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) documentation.

{{fields "metrics"}}
