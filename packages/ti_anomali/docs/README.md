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
        "ephemeral_id": "5f5fdd12-5b96-4370-aae2-3f4ca99136eb",
        "id": "8130bdff-3530-4540-8c03-ba091c47a24f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.0"
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
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8130bdff-3530-4540-8c03-ba091c47a24f",
        "snapshot": false,
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_anomali.threatstream",
        "ingested": "2023-12-22T11:03:22Z",
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
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.as.organization.name.text | Multi-field of `threat.indicator.as.organization.name`. | match_only_text |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.full.text | Multi-field of `threat.indicator.url.full`. | match_only_text |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.port | Port of the request, such as 443. | long |
| threat.indicator.url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |

