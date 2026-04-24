{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# Wallix Bastion Integration for Elastic

## Overview
{{/* Complete this section with a short summary of what data this integration collects and what use cases it enables */}}
The Wallix Bastion integration for Elastic enables collection of Wallix Bastion syslog events covering authentication activity, audit changes, vault operations, SSH and RDP proxy sessions, session integrity checks, and supporting Linux system messages emitted by the appliance.
This integration facilitates privileged access monitoring, administrator audit trails, session investigation, and operational troubleshooting from a single normalized dataset.

### Compatibility
{{/* Complete this section with information on what 3rd party software or hardware versions this integration is compatible with */}}
This integration is compatible with Wallix Bastion appliances that emit the syslog formats handled by this package's ingest pipelines.

### How it works
{{/* Add a high level overview on how this integration works. For example, does it collect data from API calls or recieving data from a network or file.*/}}
Elastic Agent listens for Wallix Bastion logs over TCP or UDP syslog. The package ingest pipelines normalize the Wallix header, route events by family, parse the message body, and map the results to ECS while preserving the original vendor fields under `wallix_bastion.*`.

## What data does this integration collect?
{{/* Complete this section with information on what types of data the integration collects, and link to reference documentation if available */}}
The Wallix Bastion integration collects log messages of the following types:
* User and administrator authentication events.
* SSH and RDP proxy session lifecycle, command, process, and file-transfer activity.
* Vault credential checkout and checkin operations.
* Bastion audit trail events for configuration and object changes.
* Session integrity summaries and supporting Linux system or PAM events.

### Supported use cases
{{/* Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. */}}
* Track successful and failed authentication attempts to the bastion.
* Investigate user activity during SSH and RDP sessions, including session start and end, commands, processes, and file movement.
* Audit privileged account vault access and Bastion configuration changes.
* Correlate Wallix Bastion activity with other Elastic security and observability data.

## What do I need to use this integration?
{{/* List any vendor-specific prerequisites needed before starting to install the integration. */}}
You need a Wallix Bastion appliance configured to forward syslog messages to the host running Elastic Agent. The agent host must be reachable from the appliance on the configured TCP or UDP listener.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

{{/* If agentless is available for this integration, we'll want to include that here as well.
### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html)
*/}}

### Onboard / configure
{{/* List the steps that will need to be followed in order to completely set up a working integration.
For integrations that support multiple input types, be sure to add steps for all inputs.
*/}}
1. In Kibana, open **Management > Integrations** and add the **Wallix Bastion** integration.
2. Choose the input that matches your deployment: `UDP` for lightweight syslog delivery or `TCP` for connection-oriented delivery.
3. Configure the listening host and port in the integration policy.
4. On the Wallix Bastion appliance, configure remote syslog forwarding to the Elastic Agent host and port.
5. Enable the Wallix event categories you want to ingest, such as authentication, audit, vault, SSH proxy, RDP proxy, and session integrity events.
6. Save the policy and assign it to the Elastic Agent that will receive the logs.

### Validation
{{/* How can the user test whether the integration is working? Including example commands or test files if applicable */}}
1. Trigger a few representative Wallix events, such as a login, an SSH session, or a vault checkout.
2. In Kibana Discover, filter on `data_stream.dataset : "wallix_bastion.log"`.
3. Confirm that events arrive with fields such as `event.action`, `observer.hostname`, `user.name`, `source.ip`, and `wallix_bastion.type` populated.
4. If original event preservation is enabled, verify that `event.original` contains the raw Wallix log line.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).
{{/*
Add any vendor specific troubleshooting here.

Are there common issues or “gotchas” for deploying this integration? If so, how can they be resolved?
If applicable, links to the third-party software’s troubleshooting documentation.
*/}}
Common Wallix Bastion troubleshooting topics include:
* Syslog target host or port mismatches between the appliance and the Elastic Agent listener.
* Missing events because the Bastion is only forwarding a subset of categories.
* Unexpected timestamps caused by appliance timezone settings or mixed syslog timestamp formats.
* Unparsed fields when the appliance emits a log variation that is not yet handled by this package.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.
{{/* Add any vendor specific scaling information here */}}
For higher event rates, prefer TCP delivery, deploy dedicated Elastic Agent listeners for heavily used bastions, and reduce noise at the appliance if high-volume session telemetry is not required.

## Reference
{{/* Repeat for each data stream of the current type
### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}.

For each data_stream_name, include an optional summary of the datastream, the exported fields reference table and the sample event.

The fields template function will be replaced by a generated list of all fields from the `fields/` directory of the data stream when building the integration.

#### {data stream name} fields

To include a generated list of fields from the `fields/` directory, uncomment and use:
{{ fields "data_stream_name" }}

The event template function will be replace by a sample event, taken from `sample_event.json`, when building this integration.

To include a sample event from `sample_event.json`, uncomment and use:
{{ event "data_stream_name" }}

*/}}

### log

The `log` data stream provides authentication, audit, vault, proxy session, session integrity, and supporting appliance system events from Wallix Bastion.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage
{{/* For integrations that use APIs to collect data, document all the APIs that are used, and link to relevent information */}}
This integration does not call vendor APIs. It collects Wallix Bastion data through syslog over TCP or UDP.
