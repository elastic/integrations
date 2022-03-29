# Recorded Future Integration

The Recorded Future integration fetches _risklists_ from the Recorded Future API.
It supports `domain`, `hash`, `ip` and `url` entities.

In order to use it you need to define the `entity` and `list` to fetch. Check with
Recorded Future for the available lists for each entity. To fetch indicators
from multiple entities, it's necessary to define one integration for each.

Alternatively, it's also possible to use the integration to fetch custom Fusion files
by supplying the URL to the CSV file as the _Custom_ _URL_ configuration option.

An example event for `threat` looks as following:

```json
{
    "@timestamp": "2022-03-01T16:27:26.282Z",
    "agent": {
        "ephemeral_id": "92b83568-e480-4476-bd67-d72a81fb5d55",
        "id": "40cd5b73-5aea-4844-81e1-b15f9c60172e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "ti_recordedfuture.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0"
    },
    "elastic_agent": {
        "id": "40cd5b73-5aea-4844-81e1-b15f9c60172e",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "threat",
        "created": "2022-03-01T16:27:26.282Z",
        "dataset": "ti_recordedfuture.threat",
        "ingested": "2022-03-01T16:27:29Z",
        "kind": "enrichment",
        "original": "{\"EvidenceDetails\":\"{\\\"EvidenceDetails\\\": [{\\\"Rule\\\": \\\"Historically Reported as a Defanged DNS Name\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"EvidenceString\\\": \\\"21 sightings on 4 sources: Proofpoint, PasteBin, The Daily Advance, @DGAFeedAlerts. Most recent tweet: New ramnit Dom: xohrikvjhiu[.]eu IP: 13[.]90[.]196[.]81 NS: https://t.co/nTqEOuAW2E https://t.co/QdrtFSplyz. Most recent link (Nov 16, 2019): https://twitter.com/DGAFeedAlerts/statuses/1195824847915491329\\\", \\\"Sources\\\": [\\\"QQA438\\\", \\\"Jv_xrR\\\", \\\"SlNfa3\\\", \\\"KvPSaU\\\"], \\\"Timestamp\\\": \\\"2019-11-16T22:03:55.000Z\\\", \\\"Name\\\": \\\"defanged\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Criticality\\\": 1.0}, {\\\"Rule\\\": \\\"Historical Threat Researcher\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"EvidenceString\\\": \\\"18 sightings on 2 sources: Proofpoint, The Daily Advance. Most recent link (Nov 12, 2018): https://www.proofpoint.com/us/threat-insight/post/sload-and-ramnit-pairing-sustained-campaigns-against-uk-and-italy#.W-nmxyGcuiY.twitter\\\", \\\"Sources\\\": [\\\"QQA438\\\", \\\"KvPSaU\\\"], \\\"Timestamp\\\": \\\"2018-11-12T20:48:08.675Z\\\", \\\"Name\\\": \\\"threatResearcher\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Criticality\\\": 1.0}, {\\\"Rule\\\": \\\"Historically Referenced by Insikt Group\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: Insikt Group. 1 report: Proofpoint Researchers Observe sLoad and Ramnit in Campaigns Against The U.K. and Italy. Most recent link (Oct 23, 2018): https://app.recordedfuture.com/live/sc/4KSWum2M6Lx7\\\", \\\"Sources\\\": [\\\"VKz42X\\\"], \\\"Timestamp\\\": \\\"2018-10-23T00:00:00.000Z\\\", \\\"Name\\\": \\\"relatedNote\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Criticality\\\": 1.0}, {\\\"Rule\\\": \\\"Historically Detected Malware Operation\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: Bitdefender. Detected malicious behavior from an endpoint agent via global telemetry. Last observed on Mar 23, 2021.\\\", \\\"Sources\\\": [\\\"d3Awkm\\\"], \\\"Timestamp\\\": \\\"2021-03-23T00:00:00.000Z\\\", \\\"Name\\\": \\\"malwareSiteDetected\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Criticality\\\": 1.0}, {\\\"Rule\\\": \\\"Recent C\\u0026C DNS Name\\\", \\\"CriticalityLabel\\\": \\\"Very Malicious\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: Bambenek Consulting C\\u0026C Blocklist.\\\", \\\"Sources\\\": [\\\"report:QhR8Qs\\\"], \\\"Timestamp\\\": \\\"2021-12-29T07:12:02.455Z\\\", \\\"Name\\\": \\\"recentCncSite\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Criticality\\\": 4.0}]}\",\"Name\":\"xohrikvjhiu.eu\",\"Risk\":\"96\",\"RiskString\":\"5/45\"}",
        "risk_score": 96,
        "type": "indicator"
    },
    "input": {
        "type": "httpjson"
    },
    "recordedfuture": {
        "evidence_details": [
            {
                "Criticality": 1,
                "CriticalityLabel": "Unusual",
                "EvidenceString": "21 sightings on 4 sources: Proofpoint, PasteBin, The Daily Advance, @DGAFeedAlerts. Most recent tweet: New ramnit Dom: xohrikvjhiu[.]eu IP: 13[.]90[.]196[.]81 NS: https://t.co/nTqEOuAW2E https://t.co/QdrtFSplyz. Most recent link (Nov 16, 2019): https://twitter.com/DGAFeedAlerts/statuses/1195824847915491329",
                "MitigationString": "",
                "Name": "defanged",
                "Rule": "Historically Reported as a Defanged DNS Name",
                "Sources": [
                    "QQA438",
                    "Jv_xrR",
                    "SlNfa3",
                    "KvPSaU"
                ],
                "Timestamp": "2019-11-16T22:03:55.000Z"
            },
            {
                "Criticality": 1,
                "CriticalityLabel": "Unusual",
                "EvidenceString": "18 sightings on 2 sources: Proofpoint, The Daily Advance. Most recent link (Nov 12, 2018): https://www.proofpoint.com/us/threat-insight/post/sload-and-ramnit-pairing-sustained-campaigns-against-uk-and-italy#.W-nmxyGcuiY.twitter",
                "MitigationString": "",
                "Name": "threatResearcher",
                "Rule": "Historical Threat Researcher",
                "Sources": [
                    "QQA438",
                    "KvPSaU"
                ],
                "Timestamp": "2018-11-12T20:48:08.675Z"
            },
            {
                "Criticality": 1,
                "CriticalityLabel": "Unusual",
                "EvidenceString": "1 sighting on 1 source: Insikt Group. 1 report: Proofpoint Researchers Observe sLoad and Ramnit in Campaigns Against The U.K. and Italy. Most recent link (Oct 23, 2018): https://app.recordedfuture.com/live/sc/4KSWum2M6Lx7",
                "MitigationString": "",
                "Name": "relatedNote",
                "Rule": "Historically Referenced by Insikt Group",
                "Sources": [
                    "VKz42X"
                ],
                "Timestamp": "2018-10-23T00:00:00.000Z"
            },
            {
                "Criticality": 1,
                "CriticalityLabel": "Unusual",
                "EvidenceString": "1 sighting on 1 source: Bitdefender. Detected malicious behavior from an endpoint agent via global telemetry. Last observed on Mar 23, 2021.",
                "MitigationString": "",
                "Name": "malwareSiteDetected",
                "Rule": "Historically Detected Malware Operation",
                "Sources": [
                    "d3Awkm"
                ],
                "Timestamp": "2021-03-23T00:00:00.000Z"
            },
            {
                "Criticality": 4,
                "CriticalityLabel": "Very Malicious",
                "EvidenceString": "1 sighting on 1 source: Bambenek Consulting C\u0026C Blocklist.",
                "MitigationString": "",
                "Name": "recentCncSite",
                "Rule": "Recent C\u0026C DNS Name",
                "Sources": [
                    "report:QhR8Qs"
                ],
                "Timestamp": "2021-12-29T07:12:02.455Z"
            }
        ],
        "risk_string": "5/45"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "recordedfuture"
    ],
    "threat": {
        "feed": {
            "name": "Recorded Future"
        },
        "indicator": {
            "type": "domain-name",
            "url": {
                "domain": "xohrikvjhiu.eu"
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| recordedfuture.evidence_details | List of sightings used as evidence for this indicator. | flattened |
| recordedfuture.name | Indicator value. | keyword |
| recordedfuture.risk_string | Details of risk rules observed. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. Expected values are:   \* Not Specified   \* None   \* Low   \* Medium   \* High | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.location.lat | Longitude and latitude. | geo_point |
| threat.indicator.geo.location.lon | Longitude and latitude. | geo_point |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. Recommended values are:   \* WHITE   \* GREEN   \* AMBER   \* RED | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. Recommended values:   \* autonomous-system   \* artifact   \* directory   \* domain-name   \* email-addr   \* file   \* ipv4-addr   \* ipv6-addr   \* mac-addr   \* mutex   \* port   \* process   \* software   \* url   \* user-account   \* windows-registry-key   \* x509-certificate | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.port | Port of the request, such as 443. | long |
| threat.indicator.url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |

