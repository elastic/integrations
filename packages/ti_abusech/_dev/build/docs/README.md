# AbuseCH Integration

## Overview

The AbuseCH integration is for [AbuseCH](https://urlhaus.abuse.ch/) logs. It includes the following datasets for retrieving indicators from the AbuseCH API:

- `url` dataset: Supports URL based indicators from AbuseCH API.
- `malware` dataset: Supports Malware based indicators from AbuseCH API.
- `malwarebazaar` dataset: Supports indicators from the MalwareBazaar from AbuseCH.
- `threatfox` dataset: Supports indicators from AbuseCH Threat Fox API.

This integration facilitates the ingestion of threat intelligence indicators to be used for threat detection and event enrichment.

### Compatibility
<!-- Complete this section with information on what 3rd party software or hardware versions this integration is compatible with -->

### How it works

This integration periodically queries the AbuseCH APIs to retrieve threat intelligence indicators.

#### Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## What data does this integration collect?

The AbuseCH integration collects threat intelligence indicators from the following datasets:
* `url`
* `malware`
* `malwarebazaar`
* `threatfox`

### Supported use cases
<!-- Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. -->

## What do I need to use this integration?

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

AbuseCH requires using an `Auth Key` (API Key) in the requests for authentication.
Requests without authentication will be denied by the API.

More details on this topic can be found [here](https://abuse.ch/blog/community-first/).

## How do I deploy this integration?

### Onboard / configure
<!-- List the steps that will need to be followed in order to completely set up a working inte completely set up a working integration.
For integrations that support multiple input types, be sure to add steps for all inputs.
-->

### Validation
<!-- How can the user test whether the integration is working? Including example commands or test files if applicable -->

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

<!-- Add any vendor specific troubleshooting here.

Are there common issues or “gotchas” for deploying this integration? If so, how can they be resolved?
If applicable, links to the third-party software’s troubleshooting documentation.
-->

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

<!-- Add any vendor specific scaling information here -->

## Reference

### Expiration of Indicators of Compromise (IOCs)
All AbuseCH datasets now support indicator expiration. For `URL` dataset, a full list of active indicators are ingested every interval. For other datasets namely `Malware`, `MalwareBazaar`, and `ThreatFox`, the indicators are expired after duration `IOC Expiration Duration` configured in the integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to facilitate only active indicators be available to the end users. Each transform creates a destination index named `logs-ti_abusech_latest.dest_*` which only contains active and unexpired indicators. The indiator match rules and dashboards are updated to list only active indicators.
Destinations indices are aliased to `logs-ti_abusech_latest.<datastream_name>`.

| Source Datastream                  | Destination Index Pattern                        | Destination Alias                       |
|:-----------------------------------|:-------------------------------------------------|-----------------------------------------|
| `logs-ti_abusech.url-*`            | `logs-ti_abusech_latest.dest_url-*`              | `logs-ti_abusech_latest.url`            |
| `logs-ti_abusech.malware-*`        | `logs-ti_abusech_latest.dest_malware-*`          | `logs-ti_abusech_latest.malware`        |
| `logs-ti_abusech.malwarebazaar-*`  | `logs-ti_abusech_latest.dest_malwarebazaar-*`    | `logs-ti_abusech_latest.malwarebazaar`  |
| `logs-ti_abusech.threatfox-*`      | `logs-ti_abusech_latest.dest_threatfox-*`        | `logs-ti_abusech_latest.threatfox`      |

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_abusech.<datastream_name>-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_abusech.<datastream_name>-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date.

### URL

The AbuseCH URL data_stream retrieves full list of active threat intelligence indicators every interval from the Active Indicators URL database dump `https://urlhaus.abuse.ch/downloads/json/`.

{{fields "url"}}

An example event for "url" looks as following:

{{event "url"}}

### Malware

The AbuseCH malware data_stream retrieves threat intelligence indicators from the payload API endpoint `https://urlhaus-api.abuse.ch/v1/payloads/recent/`.

{{fields "malware"}}

An example event for "malware" looks as following:

{{event "malware"}}

### MalwareBazaar

The AbuseCH malwarebazaar data_stream retrieves threat intelligence indicators from the MalwareBazaar API endpoint `https://mb-api.abuse.ch/api/v1/`.

{{fields "malwarebazaar"}}

An example event for "malwarebazaar" looks as following:

{{event "malwarebazaar"}}

### Threat Fox

The AbuseCH threatfox data_stream retrieves threat intelligence indicators from the Threat Fox API endpoint `https://threatfox-api.abuse.ch/api/v1/`.

{{fields "threatfox"}}

An example event for "threatfox" looks as following:

{{event "threatfox"}}

### Inputs used
<!-- List inputs used in this integration, and link to the documentation -->
These inputs can be used with this integration:
* <!-- Add inputs here -->

### API usage
<!-- For integrations that use APIs to collect data, document all the APIs that are used, and link to relevent information -->
These APIs are used with this integration:
* `https://urlhaus.abuse.ch/downloads/json/`
* `https://urlhaus-api.abuse.ch/v1/payloads/recent/`
* `https://mb-api.abuse.ch/api/v1/`
* `https://threatfox-api.abuse.ch/api/v1/`