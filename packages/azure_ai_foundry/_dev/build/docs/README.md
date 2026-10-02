# Microsoft Foundry Integration

Microsoft Foundry provides a comprehensive suite of AI services that enable developers to build, deploy, and manage AI solutions efficiently. The Microsoft Foundry integration collects metrics through Azure Monitor, facilitating robust monitoring and operational insights.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). You can install only one Elastic Agent per host.

Elastic Agent is required to collect data from Azure and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Elastic Managed deployment

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

> **Note:** Elastic Managed deployment is currently supported for Microsoft Foundry metrics only. Log collection is not available via Elastic Managed Integration and requires a traditional Elastic Agent deployment.

## Data streams

### Logs

The Microsoft Foundry logs data stream captures the gateway log events. These are the supported Azure log categories:

| Data Stream |       Log Category       |
|:-----------:|:------------------------:|
|    logs     |          Audit           |
|    logs     |     RequestResponse      |
|    logs     | ApiManagementGatewayLogs |

#### Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information on how to set up and use this integration.

**Authentication (Event Hub):** The Event Hub input supports two authentication methods: **connection string** (default) and **client secret** (Microsoft Entra ID). For setup steps, required RBAC roles (Azure Event Hubs Data Receiver, Storage Blob Data Contributor), and configuration options, see the [Azure Logs integration](https://docs.elastic.co/integrations/azure) or [Filebeat azure-eventhub input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) documentation.

#### AMQP-over-WebSockets

By default, the integration uses AMQP ports `5671` and `5672` to communicate with Event Hubs. If these ports are blocked, set **Event Hubs transport protocol** to **AMQP-over-WebSockets** in the advanced options. This tunnels AMQP over HTTPS on port `443`.

This option requires the Event Hub processor v2 (**Processor version** set to `v2`, which is the default) and Elastic Agent 9.2.4 or later.

#### Proxy support

Proxy support is optional and requires **Event Hubs transport protocol** set to **AMQP-over-WebSockets**.

To enable it:

1. In the advanced options, set **Event Hubs transport protocol** to **AMQP-over-WebSockets**.
2. Define the `HTTPS_PROXY` environment variable for the Elastic Agent process, for example `HTTPS_PROXY=http://proxy.example.com:8080`. Elastic Agent routes both Event Hubs and Storage Account traffic through the proxy.

This requires processor v2 and Elastic Agent 9.2.4 or later.

#### Native logging

The Microsoft Foundry provides native logging and monitoring to track the telemetry of the service. The `Audit` and `RequestResponse` log categories come under the native logging. However, the default logging doesn't log the inputs and outputs of the service. This is useful to ensure that the services operates as expected.

#### API Gateway logs

The API Management services provide the advanced logging capabilities. The `ApiManagementGatewayLogs` category comes under the advanced logging. This is not directly available in the Microsoft Foundry service itself. You have to set up the API Management services in Azure to access the Microsoft Foundry models. When the setup is complete, add the diagnostic setting for the API Management service.

For more information on how to implement the comprehensive solution using API Management services to monitor the Microsoft Foundry services, check the [Microsoft Foundry API](https://learn.microsoft.com/en-us/azure/api-management/azure-ai-foundry-api) page.

**Diagnostic settings**

Enable the category `Logs related to ApiManagement Gateway` to stream the logs to the event hub.

```text
   ┌──────────────────┐      ┌──────────────┐     ┌─────────────────┐
   │   APIM service   │      │  Diagnostic  │     │    Event Hub    │
   │    <<source>>    │─────▶│   settings   │────▶│ <<destination>> │
   └──────────────────┘      └──────────────┘     └─────────────────┘
```

### Metrics

The metrics data stream collects the cognitive service metrics that is specific to the Microsoft Foundry service.

#### Key metrics

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

`Period`:: (_string_) Reporting interval. Metrics will have a timegrain of 5 minutes, so the `Period` configuration option for `azure_ai_foundry` should have a value of `300s` or multiple of `300s`for relevant results.

`Resource IDs`:: (_[]string_) The fully qualified ID's of the resource, including the resource name and resource type. Has the format `/subscriptions/{guid}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}`. Should return a list of resources.

`Resource Groups`:: (_[]string_) This option will return all Microsoft Foundry services inside the resource group.

If no resource filter is specified, then all Microsoft Foundry services inside the entire subscription will be considered.

The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

### Logs reference

{{event "logs"}}

**ECS Field Reference**

For more details on ECS fields, check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) documentation.

{{fields "logs"}}

### Metrics reference

The Microsoft Foundry metrics provide insights into the performance and usage of your AI resources. These metrics help in monitoring and optimizing your deployments.

{{event "metrics"}}

**ECS Field Reference**

For more details on ECS fields, check the [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) documentation.

{{fields "metrics"}}

## Alerting Rule Template
{{alertRuleTemplates}}
