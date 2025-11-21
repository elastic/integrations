{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# HTTP Check Integration for Elastic

## Overview
{{/* Complete this section with a short summary of what data this integration collects and what use cases it enables */}}
The HTTP Check integration for Elastic performs HTTP checks using the [HTTP check
receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/httpcheckreceiver/README.md) of the OTel Collector.

This integration can be used to monitor the availability of HTTP endpoints.

### How it works
{{/* Add a high level overview on how this integration works. For example, does it collect data from API calls or recieving data from a network or file.*/}}
This integration performs periodic HTTP checks to the configured endpoints.

Apart from the endpoints, it is also possible to select the HTTP method and
headers to use in the requests.

## What data does this integration collect?
{{/* Complete this section with information on what types of data the integration collects, and link to reference documentation if available */}}
This integration collects metrics with information about the
availability of the HTTP endpoints, and the status codes returned by requests.

Key metrics are stored under the metrics object, and they include:
| Metric Name | Description | Type |
|-------------|-------------|------|
| httpcheck.status | For each status class (1xx, 2xx, 3xx, 4xx or 5xx), it is set to 1 if the check returned an status of this class, to 0 otherwise. | Gauge |
| httpcheck.duration | Total duration of the request in milliseconds. | Gauge |

Documents for these metrics include attributes that follow [Semantic Conventions
for HTTP data](https://opentelemetry.io/docs/specs/semconv/http/).

### Supported use cases
{{/* Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. */}}
This integration can be used to monitor the availability of HTTP endpoints. In a
more general sense, it can be used to perform requests to specific endpoints.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to have network connectivity with the monitored
endpoints.

{{/* If agentless is available for this integration, we'll want to include that here as well.
### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html) 
*/}}

### Onboard / configure
{{/* List the steps that will need to be followed in order to completely set up a working integration.
For integrations that support multiple input types, be sure to add steps for all inputs.
*/}}
This integration needs to be configured with the list of endpoints to monitor,
and the HTTP method and headers that should be used on the requests.

With each policy you can monitor multiple endpoints that require the same method
and headers. For example you can use a single policy to monitor multiple
endpoints if you only need to check its availability with the `GET` method.

In cases where different headers or methods are required, multiple policies must
be created, one for each combination of configurations.

### Validation
{{/* How can the user test whether the integration is working? Including example commands or test files if applicable */}}
Once configured, you can find documents with information about the status code
of the requests done to the configured endpoints.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).
{{/*
Add any vendor specific troubleshooting here.

Are there common issues or “gotchas” for deploying this integration? If so, how can they be resolved?
If applicable, links to the third-party software’s troubleshooting documentation.
*/}}

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.
{{/* Add any vendor specific scaling information here */}}

## Reference

### Inputs used

This package uses the [HTTP Check Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/httpcheckreceiver/README.md) of the OTel collector.

{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

