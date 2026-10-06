# Cyware Intel Exchange Integration for Elastic

## Overview

[Cyware Intel Exchange](https://www.cyware.com/products/intel-exchange) is an intelligent client-server exchange that leverages advanced technologies like Artificial Intelligence and Machine Learning to automatically ingest, analyze, correlate and act upon the threat data ingested from multiple external sources and internally deployed security tools.

The Cyware Intel Exchange integration for Elastic allows you to collect logs using [CTIX API v3](https://ctixapiv3.cyware.com/intel-exchange-api-reference), then visualise the data in Kibana.

### Compatibility

The Cyware Intel Exchange integration is compatible with CTIX API version `v3`.

### How it works

This integration periodically queries the [CTIX API](https://ctixapiv3.cyware.com/intel-exchange-api-reference) to retrieve Indicators of Compromise (IOCs).

## What data does this integration collect?

This integration collects threat intelligence indicators into the following datasets:

- `Indicator`: This fetches all the saved result set data for conditional IOCs present in the application via [Indicator endpoint](https://ctixapiv3.cyware.com/rules/save-result-set/retrieve-saved-result-set-data).


### Supported use cases
Integrating Cyware Intel Exchange Indicator data streams with Elastic SIEM provides centralized visibility into threat intelligence indicators such as malicious IPs, domains, URLs, and file hashes. By correlating indicator metadata (including source, type, TLP markings, revocation/deprecation status, and provider context) within Elastic analytics, security teams can strengthen threat detection, accelerate incident triage, and enrich investigations. Dashboards in Kibana present breakdowns by indicator type, source, TLP, score, and trends over time — enabling faster detection of emerging threats, improved prioritization of high-risk indicators, and enhanced accountability across the threat intelligence lifecycle.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Cyware Intel Exchange

To collect data from the CTIX APIs, ensure that you have `Create` and `Update` permissions for `CTIX Integrators`.

#### Generate Open API `Credentials`:

1. Go to **Administration** > **Integration Management**.
2. In **Third Party Developers**, click **CTIX Integrators**.
3. Click **Add New**. Enter the following details:
   - **Name**: Enter a unique name for the API credentials up to 50 characters long.
   - **Description**: Enter a description for the credentials up to 1000 characters long.
   - **Expiry Date**: Select an expiry date for open API keys. To apply an expiration date for the credentials, you can select **Expires On** and select the date. To ensure the credentials never expire, you can select **Never Expire**.
4. Click **Add New**.
5. Click **Download** to download the API credentials in CSV format. You can also click **Copy** to copy the endpoint URL, secret key, and access ID.

For more details, refer to the [Authentication](https://ctixapiv3.cyware.com/authentication) documentation and the guide on how to [Generate Open API Credentials](https://techdocs.cyware.com/en/299670-447852-configure-open-api.html).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Cyware Intel Exchange**.
3. Select the **Cyware Intel Exchange** integration from the search results.
4. Select **Add Cyware Intel Exchange** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Cyware Intel Exchange logs via API**, you'll need to:

        - Configure **URL**, **Access ID**, and **Secret Key**.
        - Enable the `Indicator` dataset.
        - Adjust the integration configuration parameters if required, including the Initial Interval, Interval, Batch Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In Kibana, navigate to **Dashboards**.
2. In the search bar, type **Cyware Intel Exchange**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In Kibana, navigate to **Management** > **Stack Management**.
2. Under **Data**, select **Transforms**.
3. In the search bar, type **Cyware Intel Exchange**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

### Indicator

{{fields "indicator"}}

#### Example event

{{event "indicator"}}

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following API:

- `Indicator`: [CTIX API](https://ctixapiv3.cyware.com/rules/save-result-set/retrieve-saved-result-set-data).

### Expiration of Indicators of Compromise (IOCs)

Cyware Intel Exchange now support indicator expiration. The threat indicators are expired after the duration `IOC Expiration Duration` is configured in the integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to make sure only active threat indicators are available to the end users. Each transform creates a destination index named `logs-ti_cyware_intel_exchange_latest.dest_indicator-2*` which only contains active and unexpired threat indicators. The indicator match rules and dashboards are updated to list only active threat indicators.
Destination index is aliased to `logs-ti_cyware_intel_exchange_latest.indicator`.

#### Data retention

Threat indicators are re-collected across polling intervals, and the latest transform keeps the active, deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_cyware_intel_exchange.indicator-*` | `logs-ti_cyware_intel_exchange.indicator-default_policy`: roll over after 2d, delete 3d after rollover | delete 5d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_cyware_intel_exchange.indicator-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.
