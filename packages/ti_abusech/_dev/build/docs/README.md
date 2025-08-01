# AbuseCH Integration for Elastic

## Overview

The AbuseCH integration for Elastic enables collection of logs from [abuse.ch](https://abuse.ch/). This integration facilitates the ingestion of threat intelligence indicators to be used for threat detection and event enrichment.

### Compatibility
This integration is compatible with `v1` version of URLhaus, MalwareBazaar, and ThreatFox APIs.

### How it works

This integration periodically queries the abuse.ch APIs to retrieve threat intelligence indicators.

## What data does this integration collect?

This integration collects threat intelligence indicators into the following datasets:

- `malware`: Collects malware payloads from URLs tracked by URLhaus via [URLhaus Bulk API](https://urlhaus-api.abuse.ch/#payloads-recent).
- `malwarebazaar`: Collects malware payloads from MalwareBazaar via [MalwareBazaar API](https://bazaar.abuse.ch/api/#latest_additions).
- `threatfox`: Collects indicators from ThreatFox via [ThreatFox API](https://threatfox.abuse.ch/api/#recent-iocs).
- `url`: Collects malware URL-based indicators from URLhaus via [URLhaus API](https://urlhaus.abuse.ch/api/#csv).

### Supported use cases
<!-- Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. -->
Integrating abuse.ch with Elastic enables following use cases.

- [Prebuilt threat intel detection rules](https://www.elastic.co/docs/reference/security/prebuilt-rules)
- Real-time threat detection and hunting through [Elastic Security for Threat Intelligence](https://www.elastic.co/security/tip)
- Real-time dashboards

## What do I need to use this integration?

### From Elastic

This integration supports both Elastic Agentless-based and Agent-based installations.

#### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

#### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

#### Transform

As this integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview), the requirements of transform must be met. For more details, check the [Transform Setup](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup)

### From abuse.ch

abuse.ch requires using an `Auth-Key` (API Key) in the requests for authentication. Requests without authentication will be denied by the abuse.ch APIs.

#### Obtain `Auth-Key`:
1. Sign up for new account or login into [abuse.ch authentication portal](https://auth.abuse.ch).
2. Connect with atleast one authentication provider, namely Google, Github, X, or LinkedIn.
3. Select **Save profile**.
4. In the **Optional** section, click on **Generate Key** button to generate **Auth Key**.
5. Copy the generated **Auth Key**.

For more details, check the abuse.ch [Community First - New Authentication](https://abuse.ch/blog/community-first/) blog.

## How do I deploy this integration?

### Onboard / configure

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **AbuseCH**.
3. Select the **AbuseCH** integration from the search results.
4. Select **Add AbuseCH** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect AbuseCH logs via API**, you'll need to:
        - Configure **Auth Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the URL, Interval, etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In Kibana, navigate to **Dashboards**.
2. In the search bar, type **AbuseCH**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In Kibana, navigate to **Management** > **Stack Management**.
2. Under **Data**, select **Transforms**.
3. In the search bar, type **AbuseCH**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

- When creating **Auth Key** inside [abuse.ch authentication portal](https://auth.abuse.ch/), ensure that you connect at least one additional authentication provider to ensure seemless access to abuse.ch platform.
- Check for captured ingestion errors inside Kibana. Any ingestion errors, including API errors, are captured into `error.message` field.
    1. Navigate to **Analytics** > **Discover**.
    2. In **Search field names**, search and add fields `error.message` and `data_stream.dataset` into the **Discover** view. For more details on adding fields inside **Discover**, check [Discover getting started](https://www.elastic.co/docs/explore-analyze/discover/discover-get-started).
    3. Search for the dataset(s) that are enabled by this integration. For example, in the KQL query bar, use the KQL query `data_stream.dataset: ti_abusech.url` to search on specific dataset or KQL query `data_stream.dataset: ti_abusech.*` to search on all datasets.
    4. Search for presence of any errors that are captured into `error.message` field using KQL query `error.message: *`. You can combine queries using [KQL boolean expressions](https://www.elastic.co/docs/explore-analyze/query-filter/languages/kql#_combining_multiple_queries), such as `AND`. For example, to search for any errors inside `url` dataset, you can use KQL query: `data_stream.dataset: ti_abusech.url AND error.message: *`.

- Since this integration supports Expiration of Indicators of Compromise (IOCs) using Elastic latest transform, the indicators are present in both source and destination indices. While this seem like duplicate ingestion, it is an implmentation detail which is required to properly expire indicators.
- Because the latest copy of indicators is now indexed in two places, that is, in both source and destination indices, users must anticipate storage requirements accordingly. The ILM policies on source indices can be tuned to manage their data retention period. For more details, check the [Reference](#ilm-policy).
- For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

{{fields "url"}}

{{fields "malware"}}

{{fields "malwarebazaar"}}

{{fields "threatfox"}}

### Example event

{{event "url"}}

{{event "malware"}}

{{event "malwarebazaar"}}

{{event "threatfox"}}

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration datasets uses the following APIs:

- `malware`: [URLhaus Bulk API](https://urlhaus-api.abuse.ch/#payloads-recent).
- `malwarebazaar`: [MalwareBazaar API](https://bazaar.abuse.ch/api/#latest_additions).
- `threatfox`: [ThreatFox API](https://threatfox.abuse.ch/api/#recent-iocs).
- `url`: [URLhaus API](https://urlhaus.abuse.ch/api/#csv).

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
