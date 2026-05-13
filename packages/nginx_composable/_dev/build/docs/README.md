{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# nginx_composable Integration for Elastic

## Overview
{{/* Complete this section with a short summary of what data this integration collects and the service it integrates with.}}
The nginx_composable integration for Elastic enables collection of ...

### Compatibility
{{/* Complete this section with information on what 3rd party software or hardware versions this integration is compatible with */}}
This integration is compatible with ...

### How it works
{{/* Add a high level overview on how this integration works. For example, does it collect data from API calls or recieving data from a network or file.*/}}

## What data does this integration collect?
{{/* Complete this section with information on what types of data the integration collects, and link to reference documentation if available
*/}}
The nginx_composable integration collects log messages of the following types:
* ...

### Supported use cases
{{/* Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. */}}

## What do I need to use this integration?
{{/* List any Elastic or vendor-specific prerequisites needed before starting to install the integration. For example, Elastic self-managed or cloud deployment, or a vendor-specific credentials or accounts */}}

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

{{/* If agentless is available for this integration, Include the below section. You can determine if agentless is available for this integration by checking the `manifest.yml` file, and looking for the existance of "policy_templates.deployment_modes.agentless.enabled": "true".
### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html) 
*/}}

### Set up steps in nginx_composable
{{/* List the steps that are required to set up the 3rd party system to send data to Elastic. 
This should be specific to the steps needed to set up the 3rd party system to send data to Elastic. It should not include generic information about how to install or set up the 3rd party system itself.
*/}}

#### Vendor resources
{{/* Add vendor documentation links that are specific to the steps needed to set up the vendor system to send data to Elastic. Exclude this section if no vendor setup links are available. */}}
- [Vendor documentation link 1](https://www.vendor.com/documentation/link1)
- [Vendor documentation link 2](https://www.vendor.com/documentation/link2)
- [Vendor documentation link 3](https://www.vendor.com/documentation/link3)

### Set up steps in Kibana
{{/* List the steps that are required to set up the integration in Kibana.
This includes how to add the integration, and how to configure the integration, with descriptions of each available configuration option.

If multiple input types are supported, add instructions for each in a subsection.
*/}}

### Validation
{{/* In this section, describe the actions required to validate that the integration is working properly, and data is flowing into Elasticsearch.
If required, list the steps needed in the vendor product to start sending events or trigger alerts.
Then list how to validate that the data is in Elasticsearch, using Kibana. This could be which indices to check in the Discover table, or which built in dashboards to look at to see the data.
*/}}

## Troubleshooting
{{/* The troubleshooting section should contain troubleshooting for common issues specific to this integration. Do not include generic troubleshooting information. Where appropriate, include details specific to each input type.
Whenever possible, link to the troubleshooting documentation provided by the third-party software. 

IMPORTANT: Use plain text for issue descriptions, NOT bold. Example:
- No data is being collected: Verify network...
- TCP framing issues: Check that both...
Do NOT use **bold** for issue names like "**No data is being collected**:".
*/}}

## Performance and scaling
{{/* Add any vendor specific performance and scaling information to this section.
Performance and scaling information should be specific to sending data to Elasticsearch. It should not include information about the vendor product itself or generic information about performance and scaling.
*/}}
For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used
{{/* All inputs used by this package will be automatically listed here. Do not modify this section. */}}
{{ inputDocs }}

### API usage
{{/* For integrations that use APIs to collect data, document all the APIs that are used, and link to relevent information. For integrations that do not use APIs, do not include this section. */}}
These APIs are used with this integration:
* ...

### Vendor documentation links
{{/* Add vendor documentation links which provide useful general information about the integration.*/}}
- [Vendor documentation link 1](https://www.vendor.com/documentation/link1)
- [Vendor documentation link 2](https://www.vendor.com/documentation/link2)
- [Vendor documentation link 3](https://www.vendor.com/documentation/link3)

### Data streams
{{/* Repeat all information in this section for each data stream the package collects.*/}}

#### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}.

For each data_stream_name, include an optional summary of the datastream, the exported fields reference table and the sample event.

The fields template function will be replaced by a generated list of all fields from the `fields/` directory of the data stream when building the integration.

##### {data stream name} fields

To include a generated list of fields from the `fields/` directory, uncomment and use:
{{/* {{ fields "data_stream_name" }} */}}

##### {data stream name} sample event
The event template function will be replace by a sample event, taken from `sample_event.json`, when building this integration.

To include a sample event from `sample_event.json`, uncomment and use:
{{/* {{ event "data_stream_name" }}  */}}

{{/* Export ILM Policies
     This accepts a list of data stream names as arguments, and will export the ILM Policies
     for each given data stream name. If no arguments are provided, all ILM Policies will be
     exported.

     If there are no ILM Policies defined, this will be an empty string.
*/}}
{{ ilm }}

{{/* Export Transforms
     This will export the transforms used by this integration.
     If there are no transforms defined, this will be an empty string.
*/}}
{{ transform }}
