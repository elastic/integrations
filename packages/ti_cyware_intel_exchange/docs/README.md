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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |
| ti_cyware_intel_exchange.indicator.analyst_description |  | keyword |
| ti_cyware_intel_exchange.indicator.analyst_score |  | long |
| ti_cyware_intel_exchange.indicator.analyst_tlp |  | keyword |
| ti_cyware_intel_exchange.indicator.country |  | keyword |
| ti_cyware_intel_exchange.indicator.created |  | date |
| ti_cyware_intel_exchange.indicator.ctix_created |  | date |
| ti_cyware_intel_exchange.indicator.ctix_modified |  | date |
| ti_cyware_intel_exchange.indicator.ctix_score |  | long |
| ti_cyware_intel_exchange.indicator.ctix_tlp |  | keyword |
| ti_cyware_intel_exchange.indicator.custom_attributes |  | flattened |
| ti_cyware_intel_exchange.indicator.custom_scores |  | long |
| ti_cyware_intel_exchange.indicator.external_references |  | flattened |
| ti_cyware_intel_exchange.indicator.id |  | keyword |
| ti_cyware_intel_exchange.indicator.indicator_type.attribute_field |  | keyword |
| ti_cyware_intel_exchange.indicator.indicator_type.type |  | keyword |
| ti_cyware_intel_exchange.indicator.ioc_type |  | keyword |
| ti_cyware_intel_exchange.indicator.ip |  | ip |
| ti_cyware_intel_exchange.indicator.is_actioned |  | boolean |
| ti_cyware_intel_exchange.indicator.is_deprecated | Returns a value to indicate if the threat data object is deprecated. | boolean |
| ti_cyware_intel_exchange.indicator.is_false_positive | Returns a value to indicate if the object is false positive. | boolean |
| ti_cyware_intel_exchange.indicator.is_reviewed |  | boolean |
| ti_cyware_intel_exchange.indicator.is_revoked |  | boolean |
| ti_cyware_intel_exchange.indicator.is_whitelist | Returns a value to indicate if the threat data object is whitelisted. | boolean |
| ti_cyware_intel_exchange.indicator.modified |  | date |
| ti_cyware_intel_exchange.indicator.name |  | keyword |
| ti_cyware_intel_exchange.indicator.report_types |  | keyword |
| ti_cyware_intel_exchange.indicator.sdo_ip |  | ip |
| ti_cyware_intel_exchange.indicator.sdo_name |  | keyword |
| ti_cyware_intel_exchange.indicator.sdo_type |  | keyword |
| ti_cyware_intel_exchange.indicator.severity |  | keyword |
| ti_cyware_intel_exchange.indicator.source_description |  | keyword |
| ti_cyware_intel_exchange.indicator.source_tlp |  | keyword |
| ti_cyware_intel_exchange.indicator.sources.first_seen |  | date |
| ti_cyware_intel_exchange.indicator.sources.last_seen |  | date |
| ti_cyware_intel_exchange.indicator.sources.name |  | keyword |
| ti_cyware_intel_exchange.indicator.sources.score |  | long |
| ti_cyware_intel_exchange.indicator.sources.tlp |  | keyword |
| ti_cyware_intel_exchange.indicator.tags_list |  | keyword |
| ti_cyware_intel_exchange.indicator.tags_object |  | flattened |
| ti_cyware_intel_exchange.indicator.tlp_value | Returns the TLP value associated with the threat data object. | keyword |
| ti_cyware_intel_exchange.indicator.valid_from |  | date |
| ti_cyware_intel_exchange.indicator.valid_until |  | date |


#### Example event

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2025-06-30T10:28:16.273Z",
    "agent": {
        "ephemeral_id": "6c6552ad-4fea-4d30-aa23-f6aeb211a68f",
        "id": "04ab876b-1b34-4bc0-a7f5-17b04d7187c7",
        "name": "elastic-agent-30715",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_cyware_intel_exchange.indicator",
        "namespace": "96186",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "04ab876b-1b34-4bc0-a7f5-17b04d7187c7",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-05-27T14:04:51.651Z",
        "dataset": "ti_cyware_intel_exchange.indicator",
        "id": "f36749f2-776f-4153-b840-08bad5fb18b1",
        "ingested": "2025-08-04T09:19:52Z",
        "kind": "enrichment",
        "original": "{\"analyst_score\":null,\"analyst_tlp\":null,\"country\":null,\"created\":1746812972,\"ctix_created\":1748354691.651628,\"ctix_modified\":1751279296.273555,\"ctix_score\":90,\"ctix_tlp\":null,\"custom_scores\":null,\"id\":\"f36749f2-776f-4153-b840-08bad5fb18b1\",\"indicator_type\":{\"attribute_field\":\"MD5\",\"type\":\"file\"},\"ioc_type\":\"file\",\"is_actioned\":false,\"is_deprecated\":false,\"is_false_positive\":false,\"is_reviewed\":false,\"is_revoked\":false,\"is_whitelist\":false,\"modified\":1748354676.716103,\"name\":\"e8c5c5829b630dcf61b55f271ac6c085\",\"sdo_name\":\"e8c5c5829b630dcf61b55f271ac6c085\",\"sdo_type\":\"indicator\",\"severity\":\"UNKNOWN\",\"source_tlp\":\"NONE\",\"sources\":[{\"first_seen\":1746812972,\"last_seen\":null,\"name\":\"Vault\",\"score\":100,\"tlp\":\"WHITE\"}],\"tags\":[\"brand impersonation\",\"cryptocurrency\",\"Apple\"],\"valid_from\":1746812972,\"valid_until\":null}",
        "severity": 99,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Threat Intelligence Management",
        "vendor": "Cyware"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_cyware_intel_exchange-indicator",
        "brand impersonation",
        "cryptocurrency",
        "Apple"
    ],
    "threat": {
        "indicator": {
            "first_seen": [
                "2025-05-09T17:49:32.000Z"
            ],
            "marking": {
                "tlp": [
                    "WHITE"
                ]
            },
            "modified_at": "2025-05-27T14:04:36.716Z",
            "name": [
                "e8c5c5829b630dcf61b55f271ac6c085"
            ],
            "provider": [
                "Vault"
            ],
            "type": "file"
        }
    },
    "ti_cyware_intel_exchange": {
        "indicator": {
            "created": "2025-05-09T17:49:32.000Z",
            "ctix_score": 90,
            "indicator_type": {
                "attribute_field": "MD5",
                "type": "file"
            },
            "is_actioned": false,
            "is_deprecated": false,
            "is_false_positive": false,
            "is_reviewed": false,
            "is_revoked": false,
            "is_whitelist": false,
            "name": "e8c5c5829b630dcf61b55f271ac6c085",
            "sdo_name": "e8c5c5829b630dcf61b55f271ac6c085",
            "sdo_type": "indicator",
            "source_tlp": "NONE",
            "sources": [
                {
                    "score": 100
                }
            ],
            "tags_list": [
                "brand impersonation",
                "cryptocurrency",
                "Apple"
            ],
            "valid_from": "2025-05-09T17:49:32.000Z"
        }
    }
}
```

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

