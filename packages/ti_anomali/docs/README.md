# Anomali Integration

The Anomali integration can fetch indicators from [Anomali ThreatStream](https://www.anomali.com/products/threatstream), a commercial Threat Intelligence service.

It has the following data streams:

- **`intelligence`** Indicators retrieved from the Anomali ThreatStream API's intelligence endpoint.
- **`threatstream`** Indicators received from the Anomali ThreatStream Elastic Extension, which is additional software. This is deprecated.

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

An example event for `intelligence` looks as following:

```json
{
    "@timestamp": "2025-05-15T05:41:39.529550940Z",
    "agent": {
        "ephemeral_id": "c4e3038f-6797-46c3-b082-cbd123c7cbe3",
        "id": "1c061faa-0b6d-43fe-b1d8-93ca2ddea2de",
        "name": "elastic-agent-51370",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "anomali": {
        "threatstream": {
            "can_add_public_tags": true,
            "confidence": 60,
            "deletion_scheduled_at": "2025-05-22T05:41:39.52955094Z",
            "expiration_ts": "9999-12-31T00:00:00.000Z",
            "feed_id": 0,
            "id": "232020126",
            "is_anonymous": false,
            "is_editable": false,
            "is_public": true,
            "itype": "apt_domain",
            "meta": {
                "severity": "very-high"
            },
            "owner_organization_id": 67,
            "retina_confidence": -1,
            "source_reported_confidence": 60,
            "status": "active",
            "threat_type": "apt",
            "type": "domain",
            "update_id": "100000001",
            "uuid": "0921be47-9cc2-4265-b896-c62a7cb91042",
            "value": "gen1xyz.com"
        }
    },
    "data_stream": {
        "dataset": "ti_anomali.intelligence",
        "namespace": "27115",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "1c061faa-0b6d-43fe-b1d8-93ca2ddea2de",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2021-04-06T09:56:22.915Z",
        "dataset": "ti_anomali.intelligence",
        "ingested": "2025-05-15T05:41:39Z",
        "kind": "enrichment",
        "original": "{\"asn\":\"\",\"can_add_public_tags\":true,\"confidence\":60,\"created_by\":null,\"created_ts\":\"2021-04-06T09:56:22.915Z\",\"description\":null,\"expiration_ts\":\"9999-12-31T00:00:00.000Z\",\"feed_id\":0,\"id\":232020126,\"is_anonymous\":false,\"is_editable\":false,\"is_public\":true,\"itype\":\"apt_domain\",\"locations\":[],\"meta\":{\"detail2\":\"imported by user 136\",\"severity\":\"very-high\"},\"modified_ts\":\"2021-04-06T09:56:22.915Z\",\"org\":\"\",\"owner_organization_id\":67,\"rdns\":null,\"resource_uri\":\"/api/v2/intelligence/232020126/\",\"retina_confidence\":-1,\"sort\":[455403032],\"source\":\"Analyst\",\"source_locations\":[],\"source_reported_confidence\":60,\"status\":\"active\",\"subtype\":null,\"tags\":null,\"target_industry\":[],\"threat_type\":\"apt\",\"threatscore\":54,\"tlp\":null,\"trusted_circle_ids\":null,\"type\":\"domain\",\"update_id\":100000001,\"uuid\":\"0921be47-9cc2-4265-b896-c62a7cb91042\",\"value\":\"gen1xyz.com\",\"workgroups\":[]}",
        "severity": 9,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "anomali-intelligence"
    ],
    "threat": {
        "indicator": {
            "confidence": "Medium",
            "marking": {
                "tlp": "WHITE"
            },
            "modified_at": "2021-04-06T09:56:22.915Z",
            "provider": "Analyst",
            "type": "domain-name",
            "url": {
                "domain": "gen1xyz.com"
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| anomali.threatstream.can_add_public_tags | Indicates whether a user can add public tags to a Threat Model entity. | boolean |
| anomali.threatstream.confidence | Level of certainty that an observable is of the reported indicator type. Confidence scores range from 0-100, in increasing order of confidence, and is assigned by ThreatStream based on several factors. | long |
| anomali.threatstream.deletion_scheduled_at | At this time the IOC will be deleted by the transform. | date |
| anomali.threatstream.expiration_ts | Time stamp of when intelligence will expire on ThreatStream, in UTC time. Note: expiration_ts can only be specified in an advanced search query. | date |
| anomali.threatstream.feed_id | Numeric ID of the threat feed that generated the indicator. feed_id = 0 for user-created indicators. | long |
| anomali.threatstream.id | Unique ID for the indicator. This identifier is assigned to the indicator when it is first created on ThreatStream. Unlike update_id, this identifier never changes as long as the indicator is available on ThreatStream. | keyword |
| anomali.threatstream.import_session_id | ID of import session in which the indicator was imported. import_session_id=0 if the indicator came in through a threat feed. | keyword |
| anomali.threatstream.is_anonymous | Whether the organization and user information is anonymized when the observable is accessed by users outside of the owner organization. | boolean |
| anomali.threatstream.is_editable | Indicates whether the imported entity can be updated by an intelligence source. This attribute is reserved for intelligence source providers and can be ignored. | boolean |
| anomali.threatstream.is_public | Visibility of the indicator—public or private. 0/False—if the indicator is private or belongs to a Trusted Circle 1/True—if the indicator is public Default: 0/False | boolean |
| anomali.threatstream.itype | Indicator type. | keyword |
| anomali.threatstream.meta.maltype | Tag that specifies the malware associated with an indicator. | keyword |
| anomali.threatstream.meta.registrant.address | Indicator domain WHOIS registrant address. | keyword |
| anomali.threatstream.meta.registrant.email | Indicator domain WHOIS registrant email. | keyword |
| anomali.threatstream.meta.registrant.name | Indicator domain WHOIS registrant name. | keyword |
| anomali.threatstream.meta.registrant.org | Indicator domain WHOIS registrant org. | keyword |
| anomali.threatstream.meta.registrant.phone | Indicator domain WHOIS registrant phone. | keyword |
| anomali.threatstream.meta.registration_created | Registration created. | date |
| anomali.threatstream.meta.registration_updated | Registration updated. | date |
| anomali.threatstream.meta.severity | Severity assigned to the indicator through machine-learning algorithms ThreatStream deploys. Possible values: low, medium, high, very-high | keyword |
| anomali.threatstream.owner_organization_id | ID of the (ThreatStream) organization that brought in the indicator, either through a threat feed or through the import process. | long |
| anomali.threatstream.rdns | Domain name (obtained through reverse domain name lookup) associated with the IP address that is associated with the indicator. | keyword |
| anomali.threatstream.retina_confidence | Confidence score assigned to the observable by Anomali machine learning algorithms. | long |
| anomali.threatstream.source_created | Time stamp of when the entity was created by its original source. | date |
| anomali.threatstream.source_modified | Time stamp of when the entity was last updated by its original source. | date |
| anomali.threatstream.source_reported_confidence | A risk score from 0 to 100, provided by the source of the indicator. | long |
| anomali.threatstream.status | Status assigned to the indicator. For example, active, inactive, falsepos. | keyword |
| anomali.threatstream.threat_type | Summarized threat type of the indicator. For example, malware, compromised, apt, c2, and so on. | keyword |
| anomali.threatstream.threatscore | Deprecated. | keyword |
| anomali.threatstream.trusted_circle_ids | IDs of the trusted circles with which the indicator is shared. | keyword |
| anomali.threatstream.type | Type of indicator—domain, email, ip, md5, string, url. | keyword |
| anomali.threatstream.update_id | An incrementing numeric identifier associated with each update to intelligence on ThreatStream. | keyword |
| anomali.threatstream.uuid | UUID (universally unique identifier) assigned to the observable for STIX compliance. | keyword |
| anomali.threatstream.value | Value of the observable. For example, 192.168.0.10 or http://www.google.com. | keyword |
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
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


### Anomali ThreatStream via the Elastic Extension

This source of indicators is deprecated. New users should instead use the API source above. This source requires additional software, the _Elastic_ _Extension,_ to connect Anomali ThreatStream to this integration. It's available on the [ThreatStream download page](https://ui.threatstream.com/downloads).

Please refer to the documentation included with the extension for a detailed explanation on how to configure Anomali ThreatStream to send indicators to this integration.

Indicators ingested in this way will become accessible using the alias `logs-ti_anomali_latest.threatstream`.

An example event for `threatstream` looks as following:

```json
{
    "@timestamp": "2020-10-08T12:22:11.000Z",
    "agent": {
        "ephemeral_id": "5b173eb1-b99b-41b7-8bd8-aee3a5e52c58",
        "id": "574058b5-688b-43f0-ac43-68a85476b2fa",
        "name": "elastic-agent-42471",
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
        "namespace": "11488",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "574058b5-688b-43f0-ac43-68a85476b2fa",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_anomali.threatstream",
        "ingested": "2025-05-14T08:28:29Z",
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
| anomali.threatstream.confidence | The measure of the accuracy (from 0 to 100) assigned by ThreatStream's predictive analytics technology to indicators. | long |
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
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |

