# SOCRadar Threat Feeds integration

The SOCRadar Threat Feeds integration collects threat intelligence indicators from SOCRadar's feed collections API. It supports IP addresses, domain names, file hashes, URLs, and email address indicators.

## Data streams

- **feed**: Collects indicators from SOCRadar feed collections.

## Logs reference

### Feed

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| socradar.feed.collection_id | SOCRadar feed collection UUID. | keyword |
| socradar.feed.collection_name | SOCRadar feed collection display name. | keyword |
| socradar.feed.extra_info | Additional metadata from the feed. | flattened |
| socradar.feed.first_seen_date | First seen date from SOCRadar feed. | date |
| socradar.feed.ioc_expiration_date | Calculated indicator expiration date. | date |
| socradar.feed.ioc_expiration_duration | Configured IOC expiration duration. | keyword |
| socradar.feed.ioc_expiration_reason | Reason for IOC expiration setting. | keyword |
| socradar.feed.latest_seen_date | Latest seen date from SOCRadar feed. | date |
| socradar.feed.maintainer_name | Feed maintainer identifier. | keyword |
| socradar.feed.type | Feed indicator type from SOCRadar (ip, hostname, hash, url, email). | keyword |
| socradar.feed.value | The indicator value (IP, domain, hash, URL, email). | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.reference | Feed reference URL. | keyword |
| threat.indicator.confidence | Indicator confidence level. | keyword |
| threat.indicator.description | Indicator description. | keyword |
| threat.indicator.email.address | Email address indicator. | keyword |
| threat.indicator.file.hash.md5 | MD5 file hash indicator. | keyword |
| threat.indicator.file.hash.sha1 | SHA-1 file hash indicator. | keyword |
| threat.indicator.file.hash.sha256 | SHA-256 file hash indicator. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.ip | IPv4 or IPv6 address indicator. | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.provider | Indicator provider name. | keyword |
| threat.indicator.type | Type of indicator (ipv4-addr, domain-name, file, url, email-addr). | keyword |
| threat.indicator.url.domain | Domain name indicator. | keyword |
| threat.indicator.url.full | Full URL indicator. | wildcard |
| threat.indicator.url.original | Original URL indicator value. | wildcard |


An example event for `feed` looks as following:

```json
{
    "@timestamp": "2026-02-20T08:30:00.000Z",
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "created": "2026-02-20T08:30:00.000Z",
        "kind": "enrichment",
        "type": [
            "indicator"
        ]
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "related": {
        "ip": [
            "203.0.113.50"
        ]
    },
    "socradar": {
        "feed": {
            "collection_id": "4d7a69ce6e7c49ff8c916da5d7343916",
            "collection_name": "SOCRadar-APT-Recommended-Block-IP",
            "extra_info": null,
            "first_seen_date": "2026-02-19T10:00:00.000Z",
            "ioc_expiration_date": "2026-05-27T08:30:00.000Z",
            "ioc_expiration_duration": "90d",
            "ioc_expiration_reason": "Expiration set by configuration",
            "latest_seen_date": "2026-02-20T08:30:00.000Z",
            "maintainer_name": "SOCRadar",
            "type": "ip",
            "value": "203.0.113.50"
        }
    },
    "tags": [
        "forwarded",
        "ti_socradar_feeds-feed"
    ],
    "threat": {
        "feed": {
            "name": "SOCRadar Threat Feeds",
            "reference": "https://platform.socradar.com"
        },
        "indicator": {
            "confidence": "High",
            "description": "SOCRadar feed: SOCRadar-APT-Recommended-Block-IP",
            "first_seen": "2026-02-19T10:00:00.000Z",
            "ip": "203.0.113.50",
            "last_seen": "2026-02-20T08:30:00.000Z",
            "modified_at": "2026-02-20T08:30:00.000Z",
            "provider": "SOCRadar",
            "type": "ipv4-addr"
        }
    }
}
```
