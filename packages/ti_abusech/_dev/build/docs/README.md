# abuse.ch Integration for Elastic

## Overview

The abuse.ch integration for Elastic enables collection of logs from [abuse.ch](https://abuse.ch/). abuse.ch provides actionable, community-driven threat intelligence data and help identify, track, and mitigate against malware and botnet-related cyber threats. This integration facilitates the ingestion of threat intelligence indicators to be used for threat detection and event enrichment.

### Compatibility
This integration is compatible with `v1` version of abuse.ch URLhaus, MalwareBazaar, ThreatFox, and SSLBL APIs.

### How it works

This integration periodically queries the abuse.ch APIs to retrieve threat intelligence indicators.

## What data does this integration collect?

This integration collects threat intelligence indicators into the following datasets:

- `ja3_fingerprints`: Collects JA3 fingerprint based threat indicators identified by SSLBL via [SSLBL API endpoint](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv).
- `malware`: Collects malware payloads from URLs tracked by URLhaus via [URLhaus Bulk API](https://urlhaus-api.abuse.ch/#payloads-recent).
- `malwarebazaar`: Collects malware payloads from MalwareBazaar via [MalwareBazaar API](https://bazaar.abuse.ch/api/#latest_additions).
- `sslblacklist`: Collects SSL certificate based threat indicators blacklisted on SSLBL via [SSLBL API endpoint](https://sslbl.abuse.ch/blacklist/sslblacklist.csv).
- `threatfox`: Collects threat indicators from ThreatFox via [ThreatFox API](https://threatfox.abuse.ch/api/#recent-iocs).
- `url`: Collects malware URL based threat indicators from URLhaus via [URLhaus API](https://urlhaus.abuse.ch/api/#csv).

### Supported use cases

The abuse.ch integration brings threat intel into Elastic Security, enabling detection alerts when indicators of compromise (IoCs) like malicious [IPs](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/threat_intel/threat_intel_indicator_match_address), [domains](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/threat_intel/threat_intel_indicator_match_url), or [hashes](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/threat_intel/threat_intel_indicator_match_hash) match your event or alert data. This data can also support threat hunting, enrich alerts with threat context, and power dashboards to track known threats in your environment.

## What do I need to use this integration?

### From Elastic

#### Transform

As this integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview), the requirements of transform must be met. For more details, check the [Transform Setup](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup)

### From abuse.ch

abuse.ch requires using an `Auth Key` (API Key) in the requests for authentication. Requests without authentication will be denied by the abuse.ch APIs.

#### Obtain `Auth Key`

1. Sign up for new account or login into [abuse.ch authentication portal](https://auth.abuse.ch).
2. Connect with atleast one authentication provider, namely Google, Github, X, or LinkedIn.
3. Select **Save profile**.
4. In the **Optional** section, click on **Generate Key** button to generate **Auth Key**.
5. Copy the generated **Auth Key**.

For more details, check the abuse.ch [Community First - New Authentication](https://abuse.ch/blog/community-first/) blog.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

#### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

#### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard / configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **abuse.ch**.
3. Select the **abuse.ch** integration from the search results.
4. Select **Add abuse.ch** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect abuse.ch logs via API**, you'll need to:

        - Configure **Auth Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the URL, Interval, etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In Kibana, navigate to **Dashboards**.
2. In the search bar, type **abuse.ch**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In Kibana, navigate to **Management** > **Stack Management**.
2. Under **Data**, select **Transforms**.
3. In the search bar, type **abuse.ch**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

- When creating the **Auth Key** inside [abuse.ch authentication portal](https://auth.abuse.ch/), ensure that you connect at least one additional authentication provider to ensure seemless access to abuse.ch platform.
- Check for captured ingestion errors inside Kibana. Any ingestion errors, including API errors, are captured into `error.message` field.
    1. Navigate to **Analytics** > **Discover**.
    2. In **Search field names**, search and add fields `error.message` and `data_stream.dataset` into the **Discover** view. For more details on adding fields inside **Discover**, check [Discover getting started](https://www.elastic.co/docs/explore-analyze/discover/discover-get-started).
    3. Search for the dataset(s) that are enabled by this integration. For example, in the KQL query bar, use the KQL query `data_stream.dataset: ti_abusech.url` to search on specific dataset or KQL query `data_stream.dataset: ti_abusech.*` to search on all datasets.
    4. Search for presence of any errors that are captured into `error.message` field using KQL query `error.message: *`. You can combine queries using [KQL boolean expressions](https://www.elastic.co/docs/explore-analyze/query-filter/languages/kql#_combining_multiple_queries), such as `AND`. For example, to search for any errors inside `url` dataset, you can use KQL query: `data_stream.dataset: ti_abusech.url AND error.message: *`.
- Common API errors:
    All the abusec.ch API errors are captured inside the `error` fields.
    1. abuse.ch APIs return HTTP status `403 Forbidden` when the Auth Key is invalid. In such case, `error.message` field is populated with message `query_status: unknown_auth_key` and `error.id` with `403 Forbidden`. To fix this, you need to regenerate the Auth Key in the [abuse.ch authentication portal](https://auth.abuse.ch/) and update the integration policy with newly generated Auth Key.
    2. abuse.ch APIs return HTTP status `500 Internal Server Error` when experiencing problem on the abuse.ch service. In such case, `error.message` field is populated with message `POST:500 Internal Server Error (500)` and `error.id` with `500 Internal Server Error`. This is likely a one-off scenario and the ingestion should resume normally in the subsequent request.
- Since this integration supports Expiration of Indicators of Compromise (IOCs) using Elastic latest transform, the threat indicators are present in both source and destination indices. While this seem like duplicate ingestion, it is an implmentation detail which is required to properly expire threat indicators.
- Because the latest copy of threat indicators is now indexed in two places, that is, in both source and destination indices, users must anticipate storage requirements accordingly. The ILM policies on source indices can be tuned to manage their data retention period.
- For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### JA3 Fingerprint Blacklist

{{fields "ja3_fingerprints"}}

#### Malware

{{fields "malware"}}

#### MalwareBazaar

{{fields "malwarebazaar"}}

#### SSL Certificate Blacklist

{{fields "sslblacklist"}}

#### ThreatFox

{{fields "threatfox"}}

#### URL

{{fields "url"}}

### Example event

#### JA3 Fingerprint Blacklist

{{event "ja3_fingerprints"}}

#### Malware

{{event "malware"}}

#### MalwareBazaar

{{event "malwarebazaar"}}

#### SSL Certificate Blacklist

{{event "sslblacklist"}}

#### ThreatFox

{{event "threatfox"}}

#### URL

{{event "url"}}

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration datasets uses the following APIs:

- `ja3_fingerprints`: [SSLBL API](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv).
- `malware`: [URLhaus Bulk API](https://urlhaus-api.abuse.ch/#payloads-recent).
- `malwarebazaar`: [MalwareBazaar API](https://bazaar.abuse.ch/api/#latest_additions).
- `sslblacklist`: [SSLBL API](https://sslbl.abuse.ch/blacklist/sslblacklist.csv).
- `threatfox`: [ThreatFox API](https://threatfox.abuse.ch/api/#recent-iocs).
- `url`: [URLhaus API](https://urlhaus.abuse.ch/api/#csv).

### Expiration of Indicators of Compromise (IOCs)

All abuse.ch datasets now support indicator expiration. For the `URL` dataset, a full list of active threat indicators are ingested every interval. For other datasets namely `Malware`, `MalwareBazaar`, and `ThreatFox`, the threat indicators are expired after duration `IOC Expiration Duration` configured in the integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to facilitate only active threat indicators be available to the end users. Each transform creates a destination index named `logs-ti_abusech_latest.dest_*` which only contains active and unexpired threat indicators. The indicator match rules and dashboards are updated to list only active threat indicators.
Destinations indices are aliased to `logs-ti_abusech_latest.<data_stream_name>`.

| Source Data stream                  | Destination Index Pattern                        | Destination Alias                       |
|:-----------------------------------|:-------------------------------------------------|-----------------------------------------|
| `logs-ti_abusech.url-*`            | `logs-ti_abusech_latest.dest_url-*`              | `logs-ti_abusech_latest.url`            |
| `logs-ti_abusech.malware-*`        | `logs-ti_abusech_latest.dest_malware-*`          | `logs-ti_abusech_latest.malware`        |
| `logs-ti_abusech.malwarebazaar-*`  | `logs-ti_abusech_latest.dest_malwarebazaar-*`    | `logs-ti_abusech_latest.malwarebazaar`  |
| `logs-ti_abusech.threatfox-*`      | `logs-ti_abusech_latest.dest_threatfox-*`        | `logs-ti_abusech_latest.threatfox`      |

#### ILM Policy

To facilitate IOC expiration, source data stream-backed indices `.ds-logs-ti_abusech.<data_stream_name>-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_abusech.<data_stream_name>-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date.
