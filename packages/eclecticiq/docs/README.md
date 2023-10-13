<!-- Use this template language as a starting point, replacing {placeholder text} with details about the integration. -->
<!-- Find more detailed documentation guidelines in https://github.com/elastic/integrations/blob/main/docs/documentation_guidelines.md -->

# EclecticIQ Outgoing Feeds Integration

<!-- The EclecticIQ Outgoing Feeds Integration integration allows you to monitor {name of service}. {name of service} is {describe service}.

Use the EclecticIQ Outgoing Feeds Integration integration to {purpose}. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference {data stream type} when troubleshooting an issue.

For example, if you wanted to {sample use case} you could {action}. Then you can {visualize|alert|troubleshoot} by {action}. -->

## Data streams

<!-- The EclecticIQ Outgoing Feeds Integration integration collects {one|two} type{s} of data streams: {logs and/or metrics}. -->

<!-- If applicable -->
<!-- **Logs** help you keep a record of events happening in {service}.
Log data streams collected by the {name} integration include {sample data stream(s)} and more. See more details in the [Logs](#logs-reference). -->

<!-- If applicable -->
<!-- **Metrics** give you insight into the state of {service}.
Metric data streams collected by the {name} integration include {sample data stream(s)} and more. See more details in the [Metrics](#metrics-reference). -->

<!-- Optional: Any additional notes on data streams -->

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

<!--
	Optional: Other requirements including:
	* System compatibility
	* Supported versions of third-party products
	* Permissions needed
	* Anything else that could block a user from successfully using the integration
-->

## Setup

<!-- Any prerequisite instructions -->

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Additional set up instructions -->

<!-- If applicable -->
<!-- ## Logs reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

#### Example

An example event for `outgoing_feed` looks as following:

```json
{
    "@timestamp": "2023-06-20T18:06:10.126Z",
    "ecs": {
        "version": "8.9.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "created": "2023-06-08T12:00:30.187Z",
        "id": "AyGp2BbK9uP5CeLPYv/uuQlDxC8=",
        "kind": "enrichment",
        "original": "{\"calculated.relevancy\": \"0.68\", \"calculated.source_reliability\": \"A\", \"calculated.tlp\": \"GREEN\", \"diff\": \"add\", \"entity.id\": \"5e814485-012d-423d-b769-026bfed0f451\", \"entity.title\": \"HyperBro\", \"entity.type\": \"malware\", \"meta.classification\": \"\", \"meta.confidence\": \"\", \"meta.entity_url\": \"https://test.com/entity/5e814485-012d-423d-b769-026bfed0f451\", \"meta.estimated_observed_time\": \"2019-07-09T17:42:44.777000+00:00\", \"meta.estimated_threat_end_time\": \"\", \"meta.estimated_threat_start_time\": \"2022-05-11T14:00:00.188000+00:00\", \"meta.ingest_time\": \"2023-06-08T12:00:30.187097+00:00\", \"meta.relevancy\": \"0.68\", \"meta.source_reliability\": \"A\", \"meta.tags\": \"\", \"meta.taxonomy\": \"\", \"meta.terms_of_use\": \"\", \"meta.tlp\": \"GREEN\", \"source.ids\": \"47ec245c-9e7b-467e-a016-77a22ff12dd5\", \"source.names\": \"Elemendar\", \"timestamp\": \"2023-06-20 18:06:10.126780+00:00\", \"type\": \"domain\", \"value\": \"unit42.test.com\", \"value_url\": \"https://test.com/main/extracts/domain/test\"}",
        "provider": "Elemendar",
        "start": "2022-05-11T14:00:00.188Z",
        "type": [
            "indicator"
        ],
        "url": "https://test.com/main/extracts/domain/test"
    },
    "threat": {
        "indicator": {
            "first_seen": "2019-07-09T17:42:44.777Z",
            "marking": {
                "tlp": "GREEN"
            },
            "name": "unit42.test.com",
            "type": "domain-name",
            "url": {
                "domain": "unit42.test.com"
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| input.type | Input type | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.name | The name of the rule or signature generating the event. | keyword |
| server.mac | MAC address of the server. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha384 | SHA384 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.file.hash.ssdeep | SSDEEP hash. | keyword |
| threat.indicator.file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| threat.indicator.file.path.text | Multi-field of `threat.indicator.file.path`. | match_only_text |
| threat.indicator.file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.city_name | City name. | keyword |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.country_name | Country name. | keyword |
| threat.indicator.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| threat.indicator.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| threat.indicator.geo.region_name | Region name. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.name | The display name indicator in an UI friendly format | keyword |
| threat.indicator.registry.value | Name of the value written. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.full.text | Multi-field of `threat.indicator.url.full`. | match_only_text |
| threat.indicator.url.port | Port of the request, such as 443. | long |
| threat.indicator.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| threat.software.name | The name of the software used by this threat to conduct behavior commonly modeled using MITRE ATT&CK®. While not required, you can use a MITRE ATT&CK® software name. | keyword |
| threat.software.type | The type of software used by this threat to conduct behavior commonly modeled using MITRE ATT&CK®. While not required, you can use a MITRE ATT&CK® software type. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |

