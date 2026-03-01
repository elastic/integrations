# Anomali ThreatStream Integration

 
## Overview

The Anomali ThreatStream integration allows you to monitor threat intelligence indicators from [Anomali ThreatStream](https://www.anomali.com/products/threatstream), a commercial Threat Intelligence service. When integrated with Elastic Security, this valuable threat intelligence data can be leveraged within Elastic for analyzing and detecting potential security threats.
 
Use the Anomali ThreatStream integration to collect and parse threat intelligence indicators from the Anomali ThreatStream API, and then visualize that data in Kibana.

### Compatibility

The Anomali ThreatStream integration is compatible with Anomali ThreatStream REST API V2. This integration also supports Anomali ThreatStream Elastic Extension. But it is **DEPRECATED** and not recommended to use.

### How it works

The integration periodically query the Anomali ThreatStream REST API V2 intelligence endpoint. It authenticates using your username and API key, then retrieves the latest threat indicators.

**NOTE:** The Anomali ThreatStream API's intelligence endpoint is the preferred source of indicators. This data will be accessible using the alias `logs-ti_anomali_latest.intelligence`.

## What Data Does This Integration Collect?

This integration collects log messages of the following types:

- **`Intelligence`** Threat Indicators retrieved from the Anomali ThreatStream API's intelligence endpoint. 
- **`Threatstream`** DEPRECATED: Threat Indicators retrieved from the Anomali ThreatStream Elastic Extension. 

### Supported use cases

Use this integration to collect and store threat intelligence indicators from Anomali ThreatStream, providing centralized access to threat data. Users can view and analyze threat intelligence data through pre-built Kibana dashboards to understand the threat landscape and identify indicator trends over time.

## What do I need to use this integration?

### From Elastic

This integration uses [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Anomali ThreatStream

#### Collect data from Anomali ThreatStream API
To collect data from Anomali ThreatStream API, you need to have following:
- Anomali ThreatStream username
- Anomali ThreatStream API key

#### DEPRECATED: Collect data from Anomali ThreatStream using the Elastic Extension
This source of indicators is deprecated. New users should instead use the API source above. This source requires additional software, the _Elastic_ _Extension,_ to connect Anomali ThreatStream to this integration. It's available on the [ThreatStream download page](https://ui.threatstream.com/downloads).

Refer to the documentation included with the extension for a detailed explanation on how to configure Anomali ThreatStream to send indicators to this integration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Anomali ThreatStream**.
3. Select the **Anomali ThreatStream** integration from the search results.
4. Select **Add Anomali ThreatStream** to add the integration.
5. Enable and configure only the collection methods which you will use.
   * To **Collect Anomali events from ThreatStream API**, you need to:
       - Configure **Username** and **API key**.
6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **ti_anomali**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **ti_anomali**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

### Expiration of Indicators of Compromise (IOCs)

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to provide a view of active indicators for end users. The transform creates destination indices that are accessible using the alias of the form `logs-ti_anomali_latest.<datastreamname>`. When querying for active indicators or setting up indicator match rules, use the alias to avoid false positives from expired indicators. The dashboards show only the latest indicators.

#### Handling Orphaned IOCs

Indicator data from Anomali ThreatStream can contain information about deletion or expiry times. However, some Anomali ThreatStream IOCs might never expire and will continue to stay in the latest destination index. To avoid any false positives from such orphaned IOCs, users are allowed to configure an "IOC Expiration Duration" or "IOC Duration Before Deletion" parameter while setting up a policy. The value set there will limit the time that indicators are retained before deletion, but indicators might be removed earlier based on information from Anomali ThreatStream.

### Destination index versioning and deleting older versions

The destination indices created by the transform are versioned with an integer suffix such as `-1`, `-2`, for example, `logs-ti_anomali_latest.intelligence-1`.

Due to schema changes in the destination index, its version number may be incremented.

When this happens, the transform does not have the functionality to auto-delete the old index, so users must delete this old index manually. This is to ensure that duplicates are not present when using wildcard queries such as `logs-ti_anomali_latest.intelligence-*`. To delete an old index, follow the steps below (either for `intelligence` as below, or for the older `threatstream` equivalents):

1. After upgrading the integration to the latest version, check the current transform's destination index version by navigating to: `Stack Management -> Transforms -> logs-ti_anomali.latest_intelligence-default -> Details`. Check the `destination_index` value.
2. Run `GET _cat/indices?v` and check if any older versions exist. Such as `logs-ti_anomali_latest.intelligence-1`
3. Run `DELETE logs-ti_anomali_latest.intelligence-<OLDVERSION>` to delete the old index.

#### Alert severity mapping

The values used in `event.severity` are consistent with Elastic Detection Rules.

| Severity Name | `event.severity` |
| --------------|------------------|
| Low           | 21               |
| Medium        | 47               |
| High          | 73               |
| Very High     | 99               |

If the severity name is not available from the original document, it is determined from the numeric severity value according to the following table.

| Anomali `severity` | Severity Name | `event.severity` |
| -------------------|---------------|------------------|
| 0 - 19             | info          | 21               |
| 20 - 39            | low           | 21               |
| 40 - 59            | medium        | 47               |
| 60 - 79            | high          | 73               |
| 80 - 100           | critical      | 99               |

### ILM Policies

To prevent unbounded growth of the source data streams `logs-ti_opencti.<datastreamname>-*`, index lifecycle management (ILM) policies will deletes records 5 days after ingestion.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Intelligence

{{fields "intelligence"}}

#### **DEPRECATED:** Threatstream

{{fields "threatstream"}}

### Example Event

#### Intelligence

{{event "intelligence"}}

#### **DEPRECATED:** Threatstream

{{event "threatstream"}}

### Inputs used

These inputs are used in this integration:

- [HTTP Endpoint](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-http_endpoint)
- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following APIs:
- Anomali ThreatStream API
