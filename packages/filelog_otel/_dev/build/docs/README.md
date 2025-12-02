{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# File Log OpenTelemetry input

## Overview
{{/* Complete this section with a short summary of what data this integration collects and what use cases it enables */}}
The File Log OpenTelemetry input collects logs from files using the [File Log
Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/filelogreceiver/README.md)
of the OTel Collector.

This integration can be used to collect logs from files.

### How it works
{{/* Add a high level overview on how this integration works. For example, does it collect data from API calls or recieving data from a network or file.*/}}
This integration tails and parses logs from files. Observed files are the ones
matching the configured patterns.

## What data does this integration collect?
{{/* Complete this section with information on what types of data the integration collects, and link to reference documentation if available */}}

Key fields are stored following [Semantic Conventions for logs](https://opentelemetry.io/docs/specs/semconv/general/logs/), among them:
| Field Name | Description |
|-------------|-------------|
| message | Collected log line. |
| log.file.name | File name. |
| log.file.path | File path. |

### Supported use cases
{{/* Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. */}}
This integration can be used to collect custom log files.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to have permissions to read the monitored files.

{{/* If agentless is available for this integration, we'll want to include that here as well.
### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html) 
*/}}

### Onboard / configure
{{/* List the steps that will need to be followed in order to completely set up a working integration.
For integrations that support multiple input types, be sure to add steps for all inputs.
*/}}
This integration needs to be configured with the glob patterns of the files to
collect.

### Validation
{{/* How can the user test whether the integration is working? Including example commands or test files if applicable */}}
Once configured, you can find documents with the content of the collected log files.

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

This package uses the [File Log Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/filelogreceiver/README.md) of the OTel Collector.


{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

