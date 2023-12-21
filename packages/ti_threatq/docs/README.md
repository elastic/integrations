# ThreatQuotient Integration

The ThreatQuotient integration uses the available [ThreatQuotient](https://www.threatq.com/integrations/) REST API to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The ThreatQ integration requires you to set a valid URL, combination of Oauth2 credentials and the ID of the collection to retrieve
indicators from.
By default the indicators will be collected every 1 minute, and deduplication is handled by the API itself. This datastream supports expiration of indicators of compromise (IOC).

### Expiration of Indicators of Compromise (IOCs)
The ThreatQ's `Threat` datastream supports IOC expiration. The ingested IOCs expire after certain duration. In ThreatQ feed, this can happen in 3 ways: 
- When the value of `threatq.status` is `Expired`.
- When either of the fields `threatq.expires_at` or `threatq.expired_at` reaches current `now()` timestamp.
- When the indicator is not updated in a long time leading to default expiration set by `IOC Expiration Duration` configuration parameter. For more details, see [Handling Orphaned IOCs](#handling-orphaned-iocs).

The field `threatq.ioc_expiration_reason` indicates which among the 3 methods stated above is the reason for indicator expiration.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_threatq_latest.dest_threat-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_threatq_latest.threat`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards for the `Threat` datastream are also pointing to the latest destination indices containing active IoCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source datastream `.ds-logs-ti_threatq.threat-*` indices.

#### Handling Orphaned IOCs
Some IOCs may never expire and will continue to stay in the latest destination indices `logs-ti_threatq_latest.dest_threat-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes any indicator ingested into destination indices `logs-ti_threatq_latest.dest_threat-*` after this specified duration is reached, defaults to `90d` from source's `@timestamp` field. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_threatq.threat-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

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
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| threat.feed.name |  | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
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
| threatq.adversaries | Adversaries that are linked to the object | keyword |
| threatq.attributes | These provide additional context about an object | flattened |
| threatq.created_at | Object creation time | date |
| threatq.expired_at | Expiration time given by the API. Either `expires_at` or `expired_at` are present in the data. | date |
| threatq.expires_at | Expiration time given by the API. Either `expires_at` or `expired_at` are present in the data. | date |
| threatq.expires_calculated_at | Expiration calculation time | date |
| threatq.id | Indicator ID. `id`, `indicator_id` or both could be present in the dataset. | long |
| threatq.indicator_id | Indicator ID. `id`, `indicator_id` or both could be present in the dataset. | long |
| threatq.indicator_value | Original indicator value | keyword |
| threatq.ioc_expiration_reason | Reason why the indicator is expired. Set inside the ingest pipeline. | keyword |
| threatq.ioc_expired_at | Expiration time calculated by the integration needed for the transform. | date |
| threatq.published_at | Object publication time | date |
| threatq.status | Object status within the Threat Library | keyword |
| threatq.updated_at | Last modification time | date |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2020-11-15T00:00:02.000Z",
    "agent": {
        "ephemeral_id": "c6981148-4ce9-455f-9dbc-c26ed00d2688",
        "id": "66ac1e7c-a879-4591-b25e-82962b1a71c9",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.0"
    },
    "data_stream": {
        "dataset": "ti_threatq.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "66ac1e7c-a879-4591-b25e-82962b1a71c9",
        "snapshot": false,
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2023-12-11T12:43:43.800Z",
        "dataset": "ti_threatq.threat",
        "ingested": "2023-12-11T12:43:44Z",
        "kind": "enrichment",
        "original": "{\"adversaries\":[],\"attributes\":[{\"attribute_id\":7,\"created_at\":\"2020-09-11 14:35:53\",\"id\":1889,\"indicator_id\":338,\"name\":\"AlienVault Threat Level\",\"touched_at\":\"2020-10-15 14:36:00\",\"updated_at\":\"2020-10-15 14:36:00\",\"value\":\"2\"},{\"attribute_id\":4,\"created_at\":\"2020-09-11 14:35:53\",\"id\":1890,\"indicator_id\":338,\"name\":\"Country\",\"touched_at\":\"2020-10-15 14:36:00\",\"updated_at\":\"2020-10-15 14:36:00\",\"value\":\"US\"},{\"attribute_id\":3,\"created_at\":\"2020-09-11 14:35:53\",\"id\":1891,\"indicator_id\":338,\"name\":\"Description\",\"touched_at\":\"2020-10-15 14:36:00\",\"updated_at\":\"2020-10-15 14:36:00\",\"value\":\"Malicious Host\"},{\"attribute_id\":6,\"created_at\":\"2020-09-11 14:35:53\",\"id\":1892,\"indicator_id\":338,\"name\":\"AlienVault Revision\",\"touched_at\":\"2020-10-15 14:36:00\",\"updated_at\":\"2020-10-15 14:36:00\",\"value\":\"3\"},{\"attribute_id\":5,\"created_at\":\"2020-09-11 14:35:53\",\"id\":1893,\"indicator_id\":338,\"name\":\"City\",\"touched_at\":\"2020-10-15 14:36:00\",\"updated_at\":\"2020-10-15 14:36:00\",\"value\":\"New York\"},{\"attribute_id\":8,\"created_at\":\"2020-09-11 14:35:53\",\"id\":1894,\"indicator_id\":338,\"name\":\"AlienVault Reliability\",\"touched_at\":\"2020-10-15 14:36:00\",\"updated_at\":\"2020-10-15 14:36:00\",\"value\":\"4\"}],\"class\":\"network\",\"created_at\":\"2020-09-11 14:35:51\",\"expired_at\":\"2020-11-15 00:00:02\",\"expires_calculated_at\":\"2020-10-15 14:40:03\",\"hash\":\"a9c6773919112627495d87c51fe89b15\",\"id\":338,\"published_at\":\"2020-09-11 14:35:51\",\"score\":4,\"sources\":[{\"created_at\":\"2020-09-11 14:35:53\",\"creator_source_id\":12,\"id\":338,\"indicator_id\":338,\"indicator_status_id\":2,\"indicator_type_id\":15,\"name\":\"AlienVault OTX\",\"published_at\":\"2020-09-11 14:35:53\",\"reference_id\":1,\"source_expire_days\":\"30\",\"source_id\":12,\"source_score\":1,\"source_type\":\"connectors\",\"updated_at\":\"2020-10-15 14:36:00\"}],\"status\":{\"description\":\"No longer poses a serious threat.\",\"id\":2,\"name\":\"Expired\"},\"status_id\":2,\"touched_at\":\"2021-06-07 19:47:27\",\"type\":{\"class\":\"network\",\"id\":15,\"name\":\"IP Address\"},\"type_id\":15,\"updated_at\":\"2020-11-15 00:00:02\",\"value\":\"89.160.20.156\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "threatq-threat"
    ],
    "threat": {
        "indicator": {
            "confidence": "Low",
            "ip": "89.160.20.156",
            "type": "ipv4-addr"
        }
    },
    "threatq": {
        "attributes": {
            "alienvault_reliability": [
                "4"
            ],
            "alienvault_revision": [
                "3"
            ],
            "alienvault_threat_level": [
                "2"
            ],
            "city": [
                "New York"
            ],
            "country": [
                "US"
            ],
            "description": [
                "Malicious Host"
            ]
        },
        "created_at": "2020-09-11T14:35:51.000Z",
        "expired_at": "2020-11-15T00:00:02.000Z",
        "expires_calculated_at": "2020-10-15T14:40:03.000Z",
        "id": 338,
        "indicator_value": "89.160.20.156",
        "ioc_expiration_reason": "Expiration set by ThreatQ from expired_at field",
        "ioc_expired_at": "2020-11-15T00:00:02.000Z",
        "published_at": "2020-09-11T14:35:51.000Z",
        "status": "Expired"
    }
}
```