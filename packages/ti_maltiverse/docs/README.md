# Maltiverse Integration

[Maltiverse](https://maltiverse.com) is a threat intelligence platform. It works as a broker for Threat intelligence sources that are aggregated from more than a hundred different Public, Private and Community sources. Once the data is ingested, the IoC Scoring Algorithm applies a qualitative classification to the IoC that changes. Finally this data can be queried in a Threat Intelligence feed that can be delivered to your Firewalls, SOAR, SIEM, EDR or any other technology.

This integration fetches Maltiverse Threat Intelligence feeds and add them into Elastic Threat Intelligence. It supports `hostname`, `hash`, `ipv4` and `url` indicators.

In order to download feed you need to [register](https://maltiverse.com/auth/register) and generate an API key on you profile page.

## IoCs Expiration
Since we want to retain only valuable information and avoid duplicated data, the Maltiverse Elastic integration forces the indicators to rotate into a custom index called: `logs-ti_maltiverse_latest.indicator`.
**Please, refer to this index in order to set alerts and so on.**

### How it works
This is possible thanks to a transform rule installed along with the integration. The transform rule parses the data_stream content that is pulled from Maltiverse and only adds new indicators.

Both, the data_stream and the _latest index have applied expiration through ILM and a retention policy in the transform respectively._

## Logs

### Indicator

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Input type. | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| maltiverse.address | registered address | keyword |
| maltiverse.address.address | Multi-field of `maltiverse.address`. | match_only_text |
| maltiverse.as_name | AS registered name | keyword |
| maltiverse.as_name.as_name | Multi-field of `maltiverse.as_name`. | match_only_text |
| maltiverse.asn_cidr | CIDR associated | keyword |
| maltiverse.asn_country_code | Country code asociated with ASN | keyword |
| maltiverse.asn_date | date when asn registered | date |
| maltiverse.asn_registry | ASN registry | keyword |
| maltiverse.blacklist.count | number of reports for the indicator | long |
| maltiverse.blacklist.description | what we saw | keyword |
| maltiverse.blacklist.description.description | Multi-field of `maltiverse.blacklist.description`. | match_only_text |
| maltiverse.blacklist.external_references |  | flattened |
| maltiverse.blacklist.first_seen | first sighting | date |
| maltiverse.blacklist.labels |  | keyword |
| maltiverse.blacklist.last_seen | last sighting | date |
| maltiverse.blacklist.source | reporter of the activity | keyword |
| maltiverse.cidr | CIDR associated | keyword |
| maltiverse.city | City | keyword |
| maltiverse.classification | Classification of the threat | keyword |
| maltiverse.country_code | Country code of the threat | keyword |
| maltiverse.creation_time | creation date | date |
| maltiverse.domain_consonants |  | long |
| maltiverse.domain_length |  | long |
| maltiverse.email | email address | keyword |
| maltiverse.entropy |  | double |
| maltiverse.feed | Origin of the IoC | keyword |
| maltiverse.hostname |  | keyword |
| maltiverse.ip_addr | IP address | ip |
| maltiverse.is_alive |  | boolean |
| maltiverse.is_cdn | boolean description tag | boolean |
| maltiverse.is_cnc | boolean description tag | boolean |
| maltiverse.is_distributing_malware | boolean description tag | boolean |
| maltiverse.is_hosting | boolean description tag | boolean |
| maltiverse.is_iot_threat | boolean description tag | boolean |
| maltiverse.is_known_attacker | boolean description tag | boolean |
| maltiverse.is_known_scanner | boolean description tag | boolean |
| maltiverse.is_mining_pool | boolean description tag | boolean |
| maltiverse.is_open_proxy | boolean description tag | boolean |
| maltiverse.is_phishing |  | boolean |
| maltiverse.is_sinkhole | boolean description tag | boolean |
| maltiverse.is_storing_phishing |  | boolean |
| maltiverse.is_tor_node | boolean description tag | boolean |
| maltiverse.is_vpn_node | boolean description tag | boolean |
| maltiverse.last_online_time |  | keyword |
| maltiverse.location | Longitude and latitude. | geo_point |
| maltiverse.modification_time | Last modification date | date |
| maltiverse.number_of_blacklisted_domains_resolving | Blacklisted domains resolving associated | long |
| maltiverse.number_of_domains_resolving | Domains resolving associated | long |
| maltiverse.number_of_offline_malicious_urls_allocated | URLs allocated | long |
| maltiverse.number_of_online_malicious_urls_allocated | URLs allocated | long |
| maltiverse.number_of_whitelisted_domains_resolving | Whitelisted domains resolving associated | long |
| maltiverse.postal_code |  | keyword |
| maltiverse.registrant_name | Registrant name | keyword |
| maltiverse.registrant_name.registrant_name | Multi-field of `maltiverse.registrant_name`. | match_only_text |
| maltiverse.resolved_ip |  | flattened |
| maltiverse.tag | Tags of the threat | keyword |
| maltiverse.type | Type of the threat | keyword |
| maltiverse.urlchecksum |  | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.reference | Reference information for the threat feed in a UI friendly format. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.as.organization.name.text | Multi-field of `threat.indicator.as.organization.name`. | match_only_text |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.city_name | City name. | keyword |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.reference | Reference URL linking to additional information about this indicator. | keyword |
| threat.indicator.sightings | Number of times this indicator was observed conducting threat activity. | long |
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
| threat.indicator.url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| threat.indicator.url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |


An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2022-11-05T05:37:57.000Z",
    "agent": {
        "ephemeral_id": "b5733e23-446c-4102-952c-66874de0414e",
        "id": "0b6be6e3-4e8a-4084-942d-124b48dc67d5",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "ti_maltiverse.indicator",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0b6be6e3-4e8a-4084-942d-124b48dc67d5",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2023-09-21T20:46:55.738Z",
        "dataset": "ti_maltiverse.indicator",
        "id": "NsHdp9tZZtzo6Kzlv6Z1TmPP47U=",
        "ingested": "2023-09-21T20:46:58Z",
        "kind": "enrichment",
        "original": "{\"blacklist\":{\"count\":1,\"description\":\"QakBot\",\"first_seen\":\"2022-11-03 06:23:53\",\"labels\":[\"malicious-activity\"],\"last_seen\":\"2022-11-05 05:37:57\",\"source\":\"ThreatFox Abuse.ch\"},\"classification\":\"malicious\",\"creation_time\":\"2022-11-03 06:23:53\",\"domain\":\"autooutletllc.com\",\"hostname\":\"autooutletllc.com\",\"is_alive\":false,\"is_cnc\":true,\"is_distributing_malware\":false,\"is_iot_threat\":false,\"is_phishing\":false,\"last_online_time\":\"2022-11-05 05:37:57\",\"modification_time\":\"2022-11-05 05:37:57\",\"tag\":[\"bb05\",\"iso\",\"qakbot\",\"qbot\",\"quakbot\",\"tr\",\"w19\",\"zip\",\"oakboat\",\"pinkslipbot\"],\"tld\":\"com\",\"type\":\"url\",\"url\":\"https://autooutletllc.com/spares.php\",\"urlchecksum\":\"4aa7a29969dc1dffa5cad5af6cb343b9a9b40ea9646fed619d4c8d6472629128\"}",
        "severity": 9,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "maltiverse": {
        "blacklist": {
            "labels": [
                "malicious-activity"
            ]
        },
        "classification": "malicious",
        "creation_time": "2022-11-03T06:23:53.000Z",
        "feed": "test",
        "hostname": "autooutletllc.com",
        "is_alive": false,
        "is_cnc": true,
        "is_distributing_malware": false,
        "is_iot_threat": false,
        "is_phishing": false,
        "last_online_time": "2022-11-05T05:37:57.000Z",
        "modification_time": "2022-11-05T05:37:57.000Z",
        "type": "url",
        "urlchecksum": "4aa7a29969dc1dffa5cad5af6cb343b9a9b40ea9646fed619d4c8d6472629128"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_maltiverse-indicator",
        "bb05",
        "iso",
        "qakbot",
        "qbot",
        "quakbot",
        "tr",
        "w19",
        "zip",
        "oakboat",
        "pinkslipbot"
    ],
    "threat": {
        "feed": {
            "reference": "https://maltiverse.com/feed/test"
        },
        "indicator": {
            "confidence": "High",
            "description": "QakBot",
            "first_seen": "2022-11-03T06:23:53.000Z",
            "last_seen": "2022-11-05T05:37:57.000Z",
            "marking": {
                "tlp": "WHITE"
            },
            "provider": "ThreatFox Abuse.ch",
            "reference": "https://maltiverse.com/url/4aa7a29969dc1dffa5cad5af6cb343b9a9b40ea9646fed619d4c8d6472629128",
            "sightings": 1,
            "type": "url",
            "url": {
                "full": "https://autooutletllc.com/spares.php",
                "registered_domain": "autooutletllc.com",
                "top_level_domain": "com"
            }
        }
    }
}

```