# ThreatQuotient Integration

The ThreatQuotient integration uses the available [ThreatQuotient](https://www.threatq.com/integrations/) REST API to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The ThreatQ integration requires you to set a valid URL, combination of Oauth2 credentials and the ID of the collection to retrieve
indicators from.
By default the indicators will be collected every 1 minute, and deduplication is handled by the API itself.

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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
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
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name |  | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. Expected values are:   \* Not Specified   \* None   \* Low   \* Medium   \* High | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. Recommended values are:   \* WHITE   \* GREEN   \* AMBER   \* RED | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. Recommended values:   \* autonomous-system   \* artifact   \* directory   \* domain-name   \* email-addr   \* file   \* ipv4-addr   \* ipv6-addr   \* mac-addr   \* mutex   \* port   \* process   \* software   \* url   \* user-account   \* windows-registry-key   \* x509-certificate | keyword |
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
| threatq.expires_at | Expiration time | date |
| threatq.expires_calculated_at | Expiration calculation time | date |
| threatq.indicator_value | Original indicator value | keyword |
| threatq.published_at | Object publication time | date |
| threatq.status | Object status within the Threat Library | keyword |
| threatq.updated_at | Last modification time | date |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2021-10-01T18:36:03.000Z",
    "agent": {
        "ephemeral_id": "12c946b4-2bf4-4d07-8aec-d28310ed16c8",
        "id": "394964aa-5974-455c-bea7-5c0b89b470bd",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "ti_threatq.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "394964aa-5974-455c-bea7-5c0b89b470bd",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "threat",
        "created": "2022-04-11T09:27:35.244Z",
        "dataset": "ti_threatq.threat",
        "ingested": "2022-04-11T09:27:36Z",
        "kind": "enrichment",
        "original": "{\"adversaries\":[],\"attributes\":[{\"attribute_id\":5,\"created_at\":\"2021-10-01 18:36:06\",\"id\":4893068,\"indicator_id\":106767,\"name\":\"Contact\",\"touched_at\":\"2021-10-24 18:36:10\",\"updated_at\":\"2021-10-24 18:36:10\",\"value\":\"email:Quetzalcoatl_relays[]protonmail.com url:https://quetzalcoatl-relays.org proof:uri-rsa hoster:frantech.ca\"},{\"attribute_id\":9,\"created_at\":\"2021-10-01 18:36:06\",\"id\":4893069,\"indicator_id\":106767,\"name\":\"Router Port\",\"touched_at\":\"2021-10-24 18:36:10\",\"updated_at\":\"2021-10-24 18:36:10\",\"value\":\"9000\"},{\"attribute_id\":6,\"created_at\":\"2021-10-01 18:36:06\",\"id\":4893070,\"indicator_id\":106767,\"name\":\"Flags\",\"touched_at\":\"2021-10-02 18:36:08\",\"updated_at\":\"2021-10-02 18:36:08\",\"value\":\"ERDV\"}],\"class\":\"network\",\"created_at\":\"2021-10-01 18:36:03\",\"expires_calculated_at\":\"2021-10-23 18:40:17\",\"hash\":\"69beef49fdbd1f54eef3cab324c7b6cf\",\"id\":106767,\"published_at\":\"2021-10-01 18:36:03\",\"score\":0,\"sources\":[{\"created_at\":\"2021-10-01 18:36:06\",\"creator_source_id\":12,\"id\":3699669,\"indicator_id\":106767,\"indicator_status_id\":1,\"indicator_type_id\":15,\"name\":\"www.dan.me.uk Tor Node List\",\"published_at\":\"2021-10-01 18:36:06\",\"reference_id\":37,\"source_id\":12,\"source_type\":\"connectors\",\"updated_at\":\"2021-10-24 18:36:10\"}],\"status\":{\"description\":\"Poses a threat and is being exported to detection tools.\",\"id\":1,\"name\":\"Active\"},\"status_id\":1,\"touched_at\":\"2021-10-24 18:36:10\",\"type\":{\"class\":\"network\",\"id\":15,\"name\":\"IP Address\"},\"type_id\":15,\"updated_at\":\"2021-10-01 18:36:03\",\"value\":\"107.189.1.90\"}",
        "type": "indicator"
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
            "confidence": "None",
            "ip": "107.189.1.90",
            "type": "ipv4-addr"
        }
    },
    "threatq": {
        "attributes": {
            "contact": [
                "email:Quetzalcoatl_relays[]protonmail.com url:https://quetzalcoatl-relays.org proof:uri-rsa hoster:frantech.ca"
            ],
            "flags": [
                "ERDV"
            ],
            "router_port": [
                "9000"
            ]
        },
        "created_at": "2021-10-01T18:36:03.000Z",
        "expires_calculated_at": "2021-10-23T18:40:17.000Z",
        "indicator_value": "107.189.1.90",
        "published_at": "2021-10-01T18:36:03.000Z",
        "status": "Active"
    }
}
```