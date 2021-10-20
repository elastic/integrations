# MISP Integration

The MISP integration uses the REST API from the running MISP instance to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The MISP integration configuration allows to set the polling interval, how far back it
should look initially, and optionally any filters used to filter the results.

The filters themselves are based on the [MISP API documentation](https://www.circl.lu/doc/misp/automation/#search) and should support all documented fields.

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
| misp.attribute.category | The category of the attribute related to the event object. For example "Network Activity". | keyword |
| misp.attribute.comment | Comments made to the attribute itself. | keyword |
| misp.attribute.deleted | If the attribute has been removed from the event object. | boolean |
| misp.attribute.disable_correlation | If correlation has been enabled on the attribute related to the event object. | boolean |
| misp.attribute.distribution | How the attribute has been distributed, represented by integer numbers. | long |
| misp.attribute.event_id | The local event ID of the attribute related to the event. | keyword |
| misp.attribute.id | The ID of the attribute related to the event object. | keyword |
| misp.attribute.object_id | The ID of the Object in which the attribute is attached. | keyword |
| misp.attribute.object_relation | The type of relation the attribute has with the event object itself. | keyword |
| misp.attribute.sharing_group_id | The group ID of the sharing group related to the specific attribute. | keyword |
| misp.attribute.timestamp | The timestamp in which the attribute was attached to the event object. | date |
| misp.attribute.to_ids | If the attribute should be automatically synced with an IDS. | boolean |
| misp.attribute.type | The type of the attribute related to the event object. For example email, ipv4, sha1 and such. | keyword |
| misp.attribute.uuid | The UUID of the attribute related to the event. | keyword |
| misp.attribute.value | The value of the attribute, depending on the type like "url, sha1, email-src". | keyword |
| misp.attribute_count | How many attributes are included in a single event object. | long |
| misp.context.attribute.category | The category of the secondary attribute related to the event object. For example "Network Activity". | keyword |
| misp.context.attribute.comment | Comments made to the secondary attribute itself. | keyword |
| misp.context.attribute.deleted | If the secondary attribute has been removed from the event object. | boolean |
| misp.context.attribute.disable_correlation | If correlation has been enabled on the secondary attribute related to the event object. | boolean |
| misp.context.attribute.distribution | How the secondary attribute has been distributed, represented by integer numbers. | long |
| misp.context.attribute.event_id | The local event ID of the secondary attribute related to the event. | keyword |
| misp.context.attribute.first_seen | The first time the indicator was seen. | keyword |
| misp.context.attribute.id | The ID of the secondary attribute related to the event object. | keyword |
| misp.context.attribute.last_seen | The last time the indicator was seen. | keyword |
| misp.context.attribute.object_id | The ID of the Object in which the secondary attribute is attached. | keyword |
| misp.context.attribute.object_relation | The type of relation the secondary attribute has with the event object itself. | keyword |
| misp.context.attribute.sharing_group_id | The group ID of the sharing group related to the specific secondary attribute. | keyword |
| misp.context.attribute.timestamp | The timestamp in which the secondary attribute was attached to the event object. | date |
| misp.context.attribute.to_ids | If the secondary attribute should be automatically synced with an IDS. | boolean |
| misp.context.attribute.type | The type of the secondary attribute related to the event object. For example email, ipv4, sha1 and such. | keyword |
| misp.context.attribute.uuid | The UUID of the secondary attribute related to the event. | keyword |
| misp.context.attribute.value | The value of the attribute, depending on the type like "url, sha1, email-src". | keyword |
| misp.date | The date of when the event object was created. | date |
| misp.disable_correlation | If correlation is disabled on the MISP event object. | boolean |
| misp.distribution | Distribution type related to MISP. | keyword |
| misp.extends_uuid | The UUID of the event object it might extend. | keyword |
| misp.id | Attribute ID. | keyword |
| misp.info | Additional text or information related to the event. | keyword |
| misp.locked | If the current MISP event object is locked or not. | boolean |
| misp.org.id | The organization ID related to the event object. | keyword |
| misp.org.local | If the event object is local or from a remote source. | boolean |
| misp.org.name | The organization name related to the event object. | keyword |
| misp.org.uuid | The UUID of the organization related to the event object. | keyword |
| misp.org_id | Organization ID of the event. | keyword |
| misp.orgc.id | The Organization Community ID in which the event object was reported from. | keyword |
| misp.orgc.local | If the Organization Community was local or synced from a remote source. | boolean |
| misp.orgc.name | The Organization Community name in which the event object was reported from. | keyword |
| misp.orgc.uuid | The Organization Community UUID in which the event object was reported from. | keyword |
| misp.orgc_id | Organization Community ID of the event. | keyword |
| misp.proposal_email_lock | Settings configured on MISP for email lock on this event object. | boolean |
| misp.publish_timestamp | At what time the event object was published | date |
| misp.published | When the event was published. | boolean |
| misp.sharing_group_id | The ID of the grouped events or sources of the event. | keyword |
| misp.threat_level_id | Threat level from 5 to 1, where 1 is the most critical. | long |
| misp.timestamp | The timestamp of when the event object was created. | date |
| misp.uuid | The UUID of the event object. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name |  | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.name | Name of the file including the extension, without the directory. | keyword |
| threat.indicator.file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| threat.indicator.file.type | File type (file, dir, or symlink). | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. Recommended values are:   \* WHITE   \* GREEN   \* AMBER   \* RED | keyword |
| threat.indicator.port | Identifies a threat indicator as a port number (irrespective of direction). | long |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.registry.key | Hive-relative path of keys. | keyword |
| threat.indicator.registry.value | Name of the value written. | keyword |
| threat.indicator.scanner_stats | Count of AV/EDR vendors that successfully detected malicious file or URL. | long |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. Recommended values:   \* autonomous-system   \* artifact   \* directory   \* domain-name   \* email-addr   \* file   \* ipv4-addr   \* ipv6-addr   \* mac-addr   \* mutex   \* port   \* process   \* software   \* url   \* user-account   \* windows-registry-key   \* x509-certificate | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.port | Port of the request, such as 443. | long |
| threat.indicator.url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.email | User email address. | keyword |
| user.roles | Array of user roles at the time of the event. | keyword |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2014-10-06T07:12:57.000Z",
    "agent": {
        "ephemeral_id": "1a21a200-bfd3-4320-8c4e-3174f215f902",
        "hostname": "docker-fleet-agent",
        "id": "798c7d2d-cc42-42e0-9397-f8613ee0bd2f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "data_stream": {
        "dataset": "ti_misp.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12"
    },
    "elastic_agent": {
        "id": "798c7d2d-cc42-42e0-9397-f8613ee0bd2f",
        "snapshot": true,
        "version": "7.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "threat",
        "created": "2021-10-19T15:40:09.765Z",
        "dataset": "ti_misp.threat",
        "ingested": "2021-10-19T15:40:10Z",
        "kind": "enrichment",
        "original": "{\"Event\":{\"Attribute\":{\"Galaxy\":[],\"ShadowAttribute\":[],\"category\":\"Network activity\",\"comment\":\"\",\"deleted\":false,\"disable_correlation\":false,\"distribution\":\"5\",\"event_id\":\"22\",\"first_seen\":null,\"id\":\"12394\",\"last_seen\":null,\"object_id\":\"0\",\"object_relation\":null,\"sharing_group_id\":\"0\",\"timestamp\":\"1462454963\",\"to_ids\":false,\"type\":\"domain\",\"uuid\":\"572b4ab3-1af0-4d91-9cd5-07a1c0a8ab16\",\"value\":\"whatsapp.com\"},\"EventReport\":[],\"Galaxy\":[],\"Object\":[],\"Org\":{\"id\":\"1\",\"local\":true,\"name\":\"ORGNAME\",\"uuid\":\"5877549f-ea76-4b91-91fb-c72ad682b4a5\"},\"Orgc\":{\"id\":\"2\",\"local\":false,\"name\":\"CthulhuSPRL.be\",\"uuid\":\"55f6ea5f-fd34-43b8-ac1d-40cb950d210f\"},\"RelatedEvent\":[],\"ShadowAttribute\":[],\"Tag\":[{\"colour\":\"#004646\",\"exportable\":true,\"hide_tag\":false,\"id\":\"1\",\"is_custom_galaxy\":false,\"is_galaxy\":false,\"local\":0,\"name\":\"type:OSINT\",\"numerical_value\":null,\"user_id\":\"0\"},{\"colour\":\"#339900\",\"exportable\":true,\"hide_tag\":false,\"id\":\"2\",\"is_custom_galaxy\":false,\"is_galaxy\":false,\"local\":0,\"name\":\"tlp:green\",\"numerical_value\":null,\"user_id\":\"0\"}],\"analysis\":\"2\",\"attribute_count\":\"29\",\"date\":\"2014-10-03\",\"disable_correlation\":false,\"distribution\":\"3\",\"extends_uuid\":\"\",\"id\":\"2\",\"info\":\"OSINT New Indicators of Compromise for APT Group Nitro Uncovered blog post by Palo Alto Networks\",\"locked\":false,\"org_id\":\"1\",\"orgc_id\":\"2\",\"proposal_email_lock\":false,\"publish_timestamp\":\"1610622316\",\"published\":true,\"sharing_group_id\":\"0\",\"threat_level_id\":\"2\",\"timestamp\":\"1412579577\",\"uuid\":\"54323f2c-e50c-4268-896c-4867950d210b\"}}",
        "type": "indicator"
    },
    "input": {
        "type": "httpjson"
    },
    "misp": {
        "attribute": {
            "category": "Network activity",
            "comment": "",
            "deleted": false,
            "disable_correlation": false,
            "distribution": 5,
            "event_id": "22",
            "id": "12394",
            "object_id": "0",
            "sharing_group_id": "0",
            "timestamp": "1462454963",
            "to_ids": false,
            "type": "domain",
            "uuid": "572b4ab3-1af0-4d91-9cd5-07a1c0a8ab16"
        },
        "attribute_count": 29,
        "date": "2014-10-03",
        "disable_correlation": false,
        "distribution": "3",
        "extends_uuid": "",
        "id": "2",
        "info": "OSINT New Indicators of Compromise for APT Group Nitro Uncovered blog post by Palo Alto Networks",
        "locked": false,
        "org_id": "1",
        "orgc": {
            "id": "2",
            "local": false,
            "name": "CthulhuSPRL.be",
            "uuid": "55f6ea5f-fd34-43b8-ac1d-40cb950d210f"
        },
        "orgc_id": "2",
        "proposal_email_lock": false,
        "publish_timestamp": "1610622316",
        "published": true,
        "sharing_group_id": "0",
        "threat_level_id": 2,
        "uuid": "54323f2c-e50c-4268-896c-4867950d210b"
    },
    "tags": [
        "type:OSINT",
        "tlp:green"
    ],
    "threat": {
        "feed": {
            "name": "MISP"
        },
        "indicator": {
            "marking": {
                "tlp": [
                    "green"
                ]
            },
            "provider": "misp",
            "scanner_stats": 2,
            "type": "domain-name",
            "url": {
                "domain": "whatsapp.com"
            }
        }
    }
}
```