# Cyware Intel Exchange Integration for Elastic

## Overview

[Cyware Intel Exchange](https://www.cyware.com/products/intel-exchange) is an intelligent client-server exchange that leverages advanced technologies like Artificial Intelligence and Machine Learning to automatically ingest, analyze, correlate and act upon the threat data ingested from multiple external sources and internally deployed security tools.

The Cyware Intel Exchange integration for Elastic allows you to collect logs using [CTIX API v3](https://ctixapiv3.cyware.com/intel-exchange-api-reference), then visualise the data in Kibana.

### Compatibility

The Cyware Intel Exchange integration is compatible with `v3` version.

### How it works

This integration periodically queries the CTIX API to retrieve IOC indicators.

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
   - **Name**: Enter a unique name for the API credentials within 50 characters.
   - **Description**: Enter a description for the credentials within 1000 characters.
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

Cyware Intel Exchange now support indicator expiration. The threat indicators are expired after the duration `IOC Expiration Duration` is configured in the integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to make sure only active threat indicators are available to the end users. Each transform creates a destination index named `logs-ti_cyware_intel_exchange_latest.dest_indicator-1*` which only contains active and unexpired threat indicators. The indicator match rules and dashboards are updated to list only active threat indicators.
Destination index is aliased to `logs-ti_cyware_intel_exchange_latest.indicator`.

#### ILM Policy

To facilitate IoC expiration, source data stream-backed indices `.ds-logs-ti_cyware_intel_exchange.indicator-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_cyware_intel_exchange.indicator-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `5 days` from ingested date.

