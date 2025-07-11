# Cyware Threat Intelligence Exchange (CTIX)

## Overview

[Cyware Threat Intelligence Exchange](https://www.cyware.com/products/intel-exchange) is an intelligent client-server exchange that leverages advanced technologies like Artificial Intelligence and Machine Learning to automatically ingest, analyze, correlate and act upon the threat data ingested from multiple external sources and internally deployed security tools.

## Data streams

The Cyware Threat Intelligence Exchange integration collects the following events:
- **[Indicator](https://ctixapiv3.cyware.com/rules/save-result-set/retrieve-saved-result-set-data)** - This fetches all the saved result set data for conditional IOCs present in the application..

## Requirements

### Agentless-enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For Rest API, this module has been tested against the **[CTIX API v3](https://ctixapiv3.cyware.com/intel-exchange-api-reference)** version.

## Setup

**Note** - Before you start the setup, ensure that you have **Create** and **Update** permissions for **CTIX Integrators**.

### Follow below steps to generate Open API credentials for collecting data from the CTIX API:

1. Go to **Administration** > **Integration Management**.
2. In **Third Party Developers**, click **CTIX Integrators**.
3. Click **Add New**. Enter the following details:
   - **Name**: Enter a unique name for the API credentials in 50 characters.
   - **Description**: Enter a description for the credentials within 1000 characters.
   - **Expiry Date**: Select an expiry date for open API keys. To apply an expiration date for the credentials, you can select **Expires On** and select the date. To ensure the credentials never expire, you can select **Never Expire**.
4. Click **Add New**.
5. Click **Download** to download the API credentials in CSV format. You can also click **Copy** to copy the endpoint URL, secret key, and access ID.

For more details, refer to the [Authentication](https://ctixapiv3.cyware.com/authentication) documentation and the guide on how to [Generate Open API Credentials](https://techdocs.cyware.com/en/299670-447852-configure-open-api.html).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Cyware Threat Intelligence**.
3. Select the **Cyware Threat Intelligence** integration afrom the search results.
4. Click on the "Add Cyware Threat Intelligence" button to add the integration.
5. Add all the required integration configuration parameters: URL, Access ID and Secret Key.
6. Save the integration.

## Logs reference

### Indicator

This is the `Indicator` dataset.

#### Example

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2025-06-30T10:28:16.273Z",
    "agent": {
        "ephemeral_id": "9db7130d-ebbc-4ee1-9e72-81862f080692",
        "id": "70ea6ed2-6115-45bb-a549-f96eb7402441",
        "name": "elastic-agent-34198",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_cyware_threat_intelligence.indicator",
        "namespace": "40778",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "70ea6ed2-6115-45bb-a549-f96eb7402441",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-05-27T14:04:51.651Z",
        "dataset": "ti_cyware_threat_intelligence.indicator",
        "id": "f36749f2-776f-4153-b840-08bad5fb18b1",
        "ingested": "2025-07-10T16:22:06Z",
        "kind": "enrichment",
        "original": "{\"analyst_score\":null,\"analyst_tlp\":null,\"country\":null,\"created\":1746812972,\"ctix_created\":1748354691.651628,\"ctix_modified\":1751279296.273555,\"ctix_score\":90,\"ctix_tlp\":null,\"custom_scores\":null,\"id\":\"f36749f2-776f-4153-b840-08bad5fb18b1\",\"indicator_type\":{\"attribute_field\":\"MD5\",\"type\":\"file\"},\"ioc_type\":\"file\",\"is_actioned\":false,\"is_deprecated\":false,\"is_false_positive\":false,\"is_reviewed\":false,\"is_revoked\":false,\"is_whitelist\":false,\"modified\":1748354676.716103,\"name\":\"e8c5c5829b630dcf61b55f271ac6c085\",\"sdo_name\":\"e8c5c5829b630dcf61b55f271ac6c085\",\"sdo_type\":\"indicator\",\"severity\":\"UNKNOWN\",\"source_tlp\":\"NONE\",\"sources\":[{\"first_seen\":1746812972,\"last_seen\":null,\"name\":\"Vault\",\"score\":100,\"tlp\":\"WHITE\"}],\"tags\":[\"brand impersonation\",\"cryptocurrency\",\"Apple\"],\"valid_from\":1746812972,\"valid_until\":null}",
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
        "ti_cyware_threat_intelligence-indicator",
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
    "ti_cyware_threat_intelligence": {
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
            "severity": "UNKNOWN",
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
| ti_cyware_threat_intelligence.indicator.analyst_description |  | keyword |
| ti_cyware_threat_intelligence.indicator.analyst_score |  | long |
| ti_cyware_threat_intelligence.indicator.analyst_tlp |  | keyword |
| ti_cyware_threat_intelligence.indicator.country |  | keyword |
| ti_cyware_threat_intelligence.indicator.created |  | date |
| ti_cyware_threat_intelligence.indicator.ctix_created |  | date |
| ti_cyware_threat_intelligence.indicator.ctix_modified |  | date |
| ti_cyware_threat_intelligence.indicator.ctix_score |  | long |
| ti_cyware_threat_intelligence.indicator.ctix_tlp |  | keyword |
| ti_cyware_threat_intelligence.indicator.custom_attributes |  | flattened |
| ti_cyware_threat_intelligence.indicator.custom_scores |  | long |
| ti_cyware_threat_intelligence.indicator.external_references |  | flattened |
| ti_cyware_threat_intelligence.indicator.id |  | keyword |
| ti_cyware_threat_intelligence.indicator.indicator_type.attribute_field |  | keyword |
| ti_cyware_threat_intelligence.indicator.indicator_type.type |  | keyword |
| ti_cyware_threat_intelligence.indicator.ioc_type |  | keyword |
| ti_cyware_threat_intelligence.indicator.ip |  | ip |
| ti_cyware_threat_intelligence.indicator.is_actioned |  | boolean |
| ti_cyware_threat_intelligence.indicator.is_deprecated | Returns a value to indicate if the threat data object is deprecated. | boolean |
| ti_cyware_threat_intelligence.indicator.is_false_positive | Returns a value to indicate if the object is false positive. | boolean |
| ti_cyware_threat_intelligence.indicator.is_reviewed |  | boolean |
| ti_cyware_threat_intelligence.indicator.is_revoked |  | boolean |
| ti_cyware_threat_intelligence.indicator.is_whitelist | Returns a value to indicate if the threat data object is whitelisted. | boolean |
| ti_cyware_threat_intelligence.indicator.modified |  | date |
| ti_cyware_threat_intelligence.indicator.name |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.created |  | date |
| ti_cyware_threat_intelligence.indicator.relations.field_name |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.id |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.modified |  | date |
| ti_cyware_threat_intelligence.indicator.relations.relationship_type |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.source_name |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.source_ref |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.source_sub_type |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.source_type |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.target_name |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.target_ref |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.target_sub_type |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.target_type |  | keyword |
| ti_cyware_threat_intelligence.indicator.relations.unique_hash |  | keyword |
| ti_cyware_threat_intelligence.indicator.report_types |  | keyword |
| ti_cyware_threat_intelligence.indicator.sdo_ip |  | ip |
| ti_cyware_threat_intelligence.indicator.sdo_name |  | keyword |
| ti_cyware_threat_intelligence.indicator.sdo_type |  | keyword |
| ti_cyware_threat_intelligence.indicator.severity |  | keyword |
| ti_cyware_threat_intelligence.indicator.source_description |  | keyword |
| ti_cyware_threat_intelligence.indicator.source_tlp |  | keyword |
| ti_cyware_threat_intelligence.indicator.sources.first_seen |  | date |
| ti_cyware_threat_intelligence.indicator.sources.last_seen |  | date |
| ti_cyware_threat_intelligence.indicator.sources.name |  | keyword |
| ti_cyware_threat_intelligence.indicator.sources.score |  | long |
| ti_cyware_threat_intelligence.indicator.sources.tlp |  | keyword |
| ti_cyware_threat_intelligence.indicator.tags_list |  | keyword |
| ti_cyware_threat_intelligence.indicator.tags_object |  | flattened |
| ti_cyware_threat_intelligence.indicator.tlp_value | Returns the TLP value associated with the threat data object. | keyword |
| ti_cyware_threat_intelligence.indicator.valid_from |  | date |
| ti_cyware_threat_intelligence.indicator.valid_until |  | date |

