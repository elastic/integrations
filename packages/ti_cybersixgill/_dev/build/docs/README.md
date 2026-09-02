# Cybersixgill Darkfeed TAXII Integration

This integration connects with the commercial [Cybersixgill Darkfeed](https://cybersixgill.com/products/cyber-threat-intelligence/darkfeed) TAXII server.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Logs

### Threat

The Cybersixgill Darkfeed integration collects threat intelligence from the Darkfeed TAXII service available using the credentials provided from Cybersixgill.

#### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs are expired after the duration configured by `IOC Expiration Duration` integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_cybersixgill_latest.dest_threat-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_cybersixgill_latest.threat`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards are also pointing to the latest destination indices containing active IOC. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source datastream `.ds-logs-ti_cybersixgill.threat-*` indices.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_cybersixgill.threat-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_cybersixgill.threat-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

{{fields "threat"}}

{{event "threat"}}