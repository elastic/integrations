# Alienvault OTX Integration

This integration is for Alienvault OTX. It retrieves indicators for all pulses subscribed to a specific user account on OTX

## Configuration

To use this package, it is required to have an account on [Alienvault OTX](https://otx.alienvault.com/). Once an account has been created, and at least 1 pulse has been subscribed to, the API key can be retrieved from your [user profile dashboard](https://otx.alienvault.com/api). In the top right corner there should be an OTX KEY.

## Logs

### Threat

Retrieves all the related indicators over time, related to your pulse subscriptions on OTX.

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
| otx.content | Extra text or descriptive content related to the indicator. | keyword |
| otx.description | A description of the indicator. | keyword |
| otx.id | The ID of the indicator. | keyword |
| otx.indicator | The value of the indicator, for example if the type is domain, this would be the value. | keyword |
| otx.title | Title describing the indicator. | keyword |
| otx.type | The indicator type, can for example be "domain, email, FileHash-SHA256". | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.pehash | The file's pehash, if available. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| threat.indicator.file.type | File type (file, dir, or symlink). | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
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


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2022-04-11T09:14:18.594Z",
    "agent": {
        "ephemeral_id": "26518763-fc35-4393-a414-ab320e780eee",
        "id": "93ca38c5-fdea-4af2-acab-27edbc2b3434",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "ti_otx.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "93ca38c5-fdea-4af2-acab-27edbc2b3434",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "threat",
        "created": "2022-04-11T09:14:18.594Z",
        "dataset": "ti_otx.threat",
        "ingested": "2022-04-11T09:14:19Z",
        "kind": "enrichment",
        "original": "{\"content\":\"\",\"description\":null,\"id\":1251,\"indicator\":\"info.3000uc.com\",\"title\":null,\"type\":\"hostname\"}",
        "type": "indicator"
    },
    "input": {
        "type": "httpjson"
    },
    "otx": {},
    "tags": [
        "preserve_original_event",
        "forwarded",
        "otx-threat"
    ],
    "threat": {
        "indicator": {
            "type": "domain-name",
            "url": {
                "domain": "info.3000uc.com"
            }
        }
    }
}
```
