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


An example event for `threatstream` looks as following:

```json
{
    "@timestamp": "2020-10-08T12:22:11.000Z",
    "agent": {
        "ephemeral_id": "2f4f6445-5077-4a66-8582-2c74e071b6dd",
        "id": "36b03887-7783-4bc4-b8c5-6f8997e4cd1a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "anomali": {
        "threatstream": {
            "added_at": "2020-10-08T12:22:11.000Z",
            "classification": "public",
            "confidence": 20,
            "deleted_at": "2020-10-13T12:22:11.000Z",
            "detail2": "imported by user 184",
            "id": "3135167627",
            "import_session_id": "1400",
            "itype": "mal_domain",
            "resource_uri": "/api/v1/intelligence/P46279656657/",
            "severity": "high",
            "source_feed_id": "3143",
            "state": "active",
            "trusted_circle_ids": [
                "122"
            ],
            "update_id": "3786618776",
            "value_type": "domain"
        }
    },
    "data_stream": {
        "dataset": "ti_anomali.threatstream",
        "namespace": "44735",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "36b03887-7783-4bc4-b8c5-6f8997e4cd1a",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_anomali.threatstream",
        "ingested": "2024-08-01T07:49:22Z",
        "kind": "enrichment",
        "original": "{\"added_at\":\"2020-10-08T12:22:11\",\"classification\":\"public\",\"confidence\":20,\"country\":\"FR\",\"date_first\":\"2020-10-08T12:21:50\",\"date_last\":\"2020-10-08T12:24:42\",\"detail2\":\"imported by user 184\",\"domain\":\"d4xgfj.example.net\",\"id\":3135167627,\"import_session_id\":1400,\"itype\":\"mal_domain\",\"lat\":-49.1,\"lon\":94.4,\"org\":\"OVH Hosting\",\"resource_uri\":\"/api/v1/intelligence/P46279656657/\",\"severity\":\"high\",\"source\":\"Default Organization\",\"source_feed_id\":3143,\"srcip\":\"89.160.20.156\",\"state\":\"active\",\"trusted_circle_ids\":\"122\",\"update_id\":3786618776,\"value_type\":\"domain\"}",
        "severity": 7,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "anomali-threatstream"
    ],
    "threat": {
        "indicator": {
            "as": {
                "organization": {
                    "name": "OVH Hosting"
                }
            },
            "confidence": "Low",
            "first_seen": "2020-10-08T12:21:50.000Z",
            "geo": {
                "country_iso_code": "FR",
                "location": {
                    "lat": -49.1,
                    "lon": 94.4
                }
            },
            "ip": "89.160.20.156",
            "last_seen": "2020-10-08T12:24:42.000Z",
            "marking": {
                "tlp": [
                    "WHITE"
                ]
            },
            "provider": "Default Organization",
            "type": "domain-name",
            "url": {
                "domain": "d4xgfj.example.net"
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| anomali.threatstream.added_at | Date when IOC was added. | date |
| anomali.threatstream.classification | Indicates whether an indicator is private or from a public feed and available publicly. Possible values: private, public. | keyword |
| anomali.threatstream.confidence | The measure of the accuracy (from 0 to 100) assigned by ThreatStream's predictive analytics technology to indicators. | short |
| anomali.threatstream.deleted_at | Date when IOC was deleted/expired. | date |
| anomali.threatstream.detail2 | Detail text for indicator. | text |
| anomali.threatstream.id | The ID of the indicator. | keyword |
| anomali.threatstream.import_session_id | ID of the import session that created the indicator on ThreatStream. | keyword |
| anomali.threatstream.itype | Indicator type. Possible values: "apt_domain", "apt_email", "apt_ip", "apt_url", "bot_ip", "c2_domain", "c2_ip", "c2_url", "i2p_ip", "mal_domain", "mal_email", "mal_ip", "mal_md5", "mal_url", "parked_ip", "phish_email", "phish_ip", "phish_url", "scan_ip", "spam_domain", "ssh_ip", "suspicious_domain", "tor_ip" and "torrent_tracker_url". | keyword |
| anomali.threatstream.maltype | Information regarding a malware family, a CVE ID, or another attack or threat, associated with the indicator. | wildcard |
| anomali.threatstream.md5 | Hash for the indicator. | keyword |
| anomali.threatstream.resource_uri | Relative URI for the indicator details. | keyword |
| anomali.threatstream.severity | Criticality associated with the threat feed that supplied the indicator. Possible values: low, medium, high, very-high. | keyword |
| anomali.threatstream.source | Source for the indicator. | keyword |
| anomali.threatstream.source_feed_id | ID for the integrator source. | keyword |
| anomali.threatstream.state | State for this indicator. | keyword |
| anomali.threatstream.trusted_circle_ids | ID of the trusted circle that imported the indicator. | keyword |
| anomali.threatstream.update_id | Update ID. | keyword |
| anomali.threatstream.url | URL for the indicator. | keyword |
| anomali.threatstream.value_type | Data type of the indicator. Possible values: ip, domain, url, email, md5. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |

