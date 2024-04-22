# Anomali Integration

The Anomali integration supports the following datasets.

- `threatstream` dataset: Support for [Anomali ThreatStream](https://www.anomali.com/products/threatstream), a commercial Threat Intelligence service.

## Logs

### Anomali Threatstream

This integration requires additional software, the _Elastic_ _Extension,_
to connect the Anomali ThreatStream with this integration. It's available
at the [ThreatStream download page.](https://ui.threatstream.com/downloads)

Please refer to the documentation included with the Extension for a detailed
explanation on how to configure the Anomali ThreatStream to send indicator
to this integration.

### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates a destination index named `logs-ti_anomali_latest.threatstream-2` which only contains active and unexpired IOCs. The destination index also has an alias `logs-ti_anomali_latest.threatstream`. When setting up indicator match rules, use this latest destination index to avoid false positives from expired IOCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source `.ds-logs-ti_anomali.threatstream-*` indices.

#### Handling Orphaned IOCs
When an IOC expires, Anomali feed contains information about all IOCs that got `deleted`. However, some Anomali IOCs may never expire and will continue to stay in the latest destination index `logs-ti_anomali_latest.threatstream`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes all data inside the destination index `logs-ti_anomali_latest.threatstream` after this specified duration is reached. Users must pull entire feed instead of incremental feed when this expiration happens so that the IOCs get reset. 

**NOTE:** `IOC Expiration Duration` parameter does not override the expiration provided by the Anomali for their IOCs. So, if Anomali IOC is expired and subsequently such `deleted` IOCs are sent into the feed, they are deleted immediately. `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case Anomali IOCs never expire.

### Destination index versioning and deleting older versions
The destination indices created by the transform are versioned with an integer suffix such as `-1`, `-2`. Example index name - `logs-ti_anomali_latest.threatstream-1`. 

Due to schema changes on destination index, the versioning on it could be bumped. For example, in integration version `1.15.1`, the destination index  is changed to `logs-ti_anomali_latest.threatstream-2` from `logs-ti_anomali_latest.threatstream-1`. 

Since the transform does not have the functionality to auto-delete the old index, users must to delete this old index manually. This is to ensure duplicates are not present when using wildcard queries such as `logs-ti_anomali_latest.threatstream-*`. Please follow below steps:
1. After upgrading the integration to latest, check the current transform's destination index version by navigating via: `Stack Management -> Transforms -> logs-ti_anomali.latest_ioc-default -> Details`. Check `destination_index` value.
2. Run `GET _cat/indices?v` and check if any older versions exist. Such as `logs-ti_anomali_latest.threatstream-1`
3. Run `DELETE logs-ti_anomali_latest.threatstream-<OLDVERSION>` to delete the old index.

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_anomali.threat-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 


{{event "threatstream"}}

{{fields "threatstream"}}
