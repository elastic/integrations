# Anomali Integration

The Anomali integration can fetch indicators from [Anomali ThreatStream](https://www.anomali.com/products/threatstream), a commercial Threat Intelligence service.

It has the following data streams:

- **`intelligence`** Indicators retrieved from the Anomali ThreatStream API's intelligence endpoint.
- **`threatstream`** Indicators received from the Anomali ThreatStream Elastic Extension, which is additional software. This is deprecated.

## Requirements

### Agentless enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).
You can install only one Elastic Agent per host.
Elastic Agent is required to stream data from the REST API or webhook and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.
## Logs

### Expiration of Indicators of Compromise (IOCs)

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to provide a view of active indicators for end users. The transform creates destination indices that are accessible via the alias of the form `logs-ti_anomali_latest.<datastreamname>`. When querying for active indicators or setting up indicator match rules, use the alias to avoid false positives from expired indicators. The dashboards show only the latest indicators.

#### Handling Orphaned IOCs

Indicator data from Anomali can contain information about deletion or expiry times. However, some Anomali IOCs may never expire and will continue to stay in the latest destination index. To avoid any false positives from such orphaned IOCs, users are allowed to configure an "IOC Expiration Duration" or "IOC Duration Before Deletion" parameter while setting up a policy. The value set there will limit the time that indicators are retained before deletion, but indicators may be removed earlier based on information from Anomali.

### Destination index versioning and deleting older versions

The destination indices created by the transform are versioned with an integer suffix such as `-1`, `-2`, for example, `logs-ti_anomali_latest.intelligence-1`.

Due to schema changes in the destination index, its version number may be incremented.

When this happens, the transform does not have the functionality to auto-delete the old index, so users must delete this old index manually. This is to ensure that duplicates are not present when using wildcard queries such as `logs-ti_anomali_latest.intelligence-*`. To delete an old index, follow the steps below (either for `intelligence` as below, or for the older `threatstream` equivalents):

1. After upgrading the integration to the latest version, check the current transform's destination index version by navigating to: `Stack Management -> Transforms -> logs-ti_anomali.latest_intelligence-default -> Details`. Check the `destination_index` value.
2. Run `GET _cat/indices?v` and check if any older versions exist. Such as `logs-ti_anomali_latest.intelligence-1`
3. Run `DELETE logs-ti_anomali_latest.intelligence-<OLDVERSION>` to delete the old index.

### ILM Policies

To prevent unbounded growth of the source data streams `logs-ti_opencti.<datastreamname>-*`, index lifecycle management (ILM) policies will deletes records 5 days after ingestion.

### Anomali ThreatStream API

The Anomali ThreatStream API's intelligence endpoint is the preferred source of indicators. This data will be be accessible using the alias `logs-ti_anomali_latest.intelligence`.

{{event "intelligence"}}

{{fields "intelligence"}}

### Anomali ThreatStream via the Elastic Extension

This source of indicators is deprecated. New users should instead use the API source above. This source requires additional software, the _Elastic_ _Extension,_ to connect Anomali ThreatStream to this integration. It's available on the [ThreatStream download page](https://ui.threatstream.com/downloads).

Please refer to the documentation included with the extension for a detailed explanation on how to configure Anomali ThreatStream to send indicators to this integration.

Indicators ingested in this way will become accessible using the alias `logs-ti_anomali_latest.threatstream`.

{{event "threatstream"}}

{{fields "threatstream"}}
