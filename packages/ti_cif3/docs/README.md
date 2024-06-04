# Collective Intelligence Framework v3 Integration

This integration connects with the [REST API from the running CIFv3 instance](https://github.com/csirtgadgets/bearded-avenger-deploymentkit/wiki/REST-API) to retrieve indicators.

## Expiration of Indicators of Compromise (IOCs)
Indicators are expired after a certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for a source index to allow only active indicators to be available to the end users. The transform creates a destination index named `logs-ti_cif3_latest.dest_feed*` which only contains active and unexpired indicators. Destination indices are aliased to `logs-ti_cif3_latest.feed`. The indicator match rules and dashboards are updated to show only active indicators.

| Indicator Type    | Indicator Expiration Duration                  |
|:------------------|:------------------------------------------------|
| `ipv4-addr`       | `45d`                                           |
| `ipv6-addr`       | `45d`                                           |
| `domain-name`     | `90d`                                           |
| `url`             | `365d`                                          |
| `file`            | `365d`                                          |
| All Other Types   | Derived from `IOC Expiration Duration` setting  |

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_cif3.feed-*` are allowed to contain duplicates. ILM policy `logs-ti_cif3.feed-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

## Data Streams

### Feed

The CIFv3 integration collects threat indicators based on user-defined configuration including a polling interval, how far back in time it should look, and other filters like indicator type and tags.

CIFv3 `confidence` field values (0..10) are converted to ECS confidence (None, Low, Medium, High) in the following way:

| CIFv3 Confidence | ECS Conversion |
| ---------------- | -------------- |
| Beyond Range     | None           |
| 0 - \<3          | Low            |
| 3 - \<7          | Medium         |
| 7 - 10           | High           |

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cif3.application | The application used by the indicator, such as telnet or ssh. | keyword |
| cif3.asn | AS Number of IP. | integer |
| cif3.asn_desc | AS Number org name. | keyword |
| cif3.cc | Country code of GeoIP. | keyword |
| cif3.city | GeoIP city information. | keyword |
| cif3.confidence | The confidence on a scale of 0-10 that the tags appropriately contextualize the indicator. | float |
| cif3.count | The number of times the same indicator has been reported with the same metadata by the same provider. | integer |
| cif3.deleted_at | The indicator expiration timestamp. | date |
| cif3.description | A description of the indicator. | keyword |
| cif3.expiration_duration | The configured expiration duration. | keyword |
| cif3.indicator | The value of the indicator, for example if the type is fqdn, this would be the value. | keyword |
| cif3.indicator_iprange | IPv4 or IPv6 IP Range. | ip_range |
| cif3.indicator_ipv4 | IPv4 address. | ip |
| cif3.indicator_ipv4_mask | subnet mask of IPv4 CIDR. | integer |
| cif3.indicator_ipv6 | singleton IPv6 address. | keyword |
| cif3.indicator_ipv6_mask | subnet mask of IPv6 CIDR. | integer |
| cif3.indicator_ssdeep_chunk | SSDEEP hash chunk. | text |
| cif3.indicator_ssdeep_chunksize | SSDEEP hash chunk size. | integer |
| cif3.indicator_ssdeep_double_chunk | SSDEEP hash double chunk. | text |
| cif3.itype | The indicator type, can for example be "ipv4, fqdn, email, url, sha256". | keyword |
| cif3.latitude | Latitude of GeoIP. | keyword |
| cif3.location | Lat/Long of GeoIP. | geo_point |
| cif3.longitude | Longitude of GeoIP. | keyword |
| cif3.portlist | The port or range of ports used by the indicator. | text |
| cif3.protocol | The protocol used by the indicator. | text |
| cif3.provider | The source of the indicator information. | keyword |
| cif3.rdata | Extra text or descriptive content related to the indicator such as OS, reverse lookup, etc. | keyword |
| cif3.reference | A reference URL with further info related to the indicator. | keyword |
| cif3.region | GeoIP region information. | keyword |
| cif3.tags | Comma-separated list of words describing the indicator such as "malware,exploit". | keyword |
| cif3.timezone | Timezone of GeoIP. | text |
| cif3.uuid | The ID of the indicator. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
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
| threat.indicator.file.hash.ssdeep | SSDEEP hash. | keyword |
| threat.indicator.file.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| threat.indicator.file.type | File type (file, dir, or symlink). | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.indicator.geo.region_name | Region name. | keyword |
| threat.indicator.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.reference | Reference URL linking to additional information about this indicator. | keyword |
| threat.indicator.sightings | Number of times this indicator was observed conducting threat activity. | long |
| threat.indicator.tls.client.ja3 | An md5 hash that identifies clients based on their TLS handshake. | keyword |
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


An example event for `feed` looks as following:

```json
{
    "@timestamp": "2024-04-10T04:46:58.281Z",
    "agent": {
        "ephemeral_id": "94c530db-5c8f-407c-939b-cd1d21d547fc",
        "id": "28f0e936-c71c-4f75-8919-506fed4d20e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "cif3": {
        "deleted_at": "2022-09-03T20:25:53.000Z",
        "expiration_duration": "45d",
        "indicator": "20.206.75.106",
        "itype": "ipv4",
        "portlist": "443",
        "uuid": "ac240898-1443-4d7e-a98a-1daed220c162"
    },
    "data_stream": {
        "dataset": "ti_cif3.feed",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "28f0e936-c71c-4f75-8919-506fed4d20e7",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-04-10T04:46:58.281Z",
        "dataset": "ti_cif3.feed",
        "ingested": "2024-04-10T04:47:10Z",
        "kind": "enrichment",
        "original": "{\"application\":\"https\",\"asn\":8075,\"asn_desc\":\"microsoft-corp-msn-as-block\",\"cc\":\"br\",\"city\":\"campinas\",\"confidence\":10,\"count\":1,\"firsttime\":\"2022-07-20T20:25:53.000000Z\",\"group\":[\"everyone\"],\"indicator\":\"20.206.75.106\",\"indicator_ipv4\":\"20.206.75.106\",\"itype\":\"ipv4\",\"lasttime\":\"2022-07-20T20:25:53.000000Z\",\"latitude\":-22.9035,\"location\":[-47.0565,-22.9035],\"longitude\":-47.0565,\"portlist\":\"443\",\"protocol\":\"tcp\",\"provider\":\"sslbl.abuse.ch\",\"reference\":\"https://sslbl.abuse.ch/blacklist/sslipblacklist.csv\",\"region\":\"sao paulo\",\"reporttime\":\"2022-07-21T20:33:26.585967Z\",\"tags\":[\"botnet\"],\"timezone\":\"america/sao_paulo\",\"tlp\":\"white\",\"uuid\":\"ac240898-1443-4d7e-a98a-1daed220c162\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "network": {
        "protocol": "https",
        "transport": "tcp"
    },
    "related": {
        "ip": [
            "20.206.75.106"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cif3-indicator",
        "botnet"
    ],
    "threat": {
        "indicator": {
            "as": {
                "number": 8075,
                "organization": {
                    "name": "microsoft-corp-msn-as-block"
                }
            },
            "confidence": "High",
            "first_seen": "2022-07-20T20:25:53.000Z",
            "geo": {
                "country_iso_code": "br",
                "location": {
                    "lat": -22.9035,
                    "lon": -47.0565
                },
                "region_name": "sao paulo",
                "timezone": "america/sao_paulo"
            },
            "ip": "20.206.75.106",
            "last_seen": "2022-07-20T20:25:53.000Z",
            "marking": {
                "tlp": "WHITE"
            },
            "modified_at": "2022-07-21T20:33:26.585967Z",
            "name": "20.206.75.106",
            "provider": "sslbl.abuse.ch",
            "reference": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
            "sightings": 1,
            "type": "ipv4-addr"
        }
    }
}
```
