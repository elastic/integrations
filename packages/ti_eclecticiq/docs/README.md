# EclecticIQ Integration

The EclecticIQ integration
allows you to ingest threat intelligence
[observables](https://docs.eclecticiq.com/ic/current/work-with-intelligence/observables/)
from an outgoing feeds on your
[EclecticIQ Intelligence Center](https://docs.eclecticiq.com/ic/current/)
instance.

Observables ingested from an EclecticIQ Intelligence Center outgoing feed
can be monitored and explored on
[Intelligence → Indicators](https://www.elastic.co/guide/en/security/current/indicators-of-compromise.html)
in Kibana.

## Data streams

The EclecticIQ integration
collects one type of data streams: logs.

**Logs** collected from this integration
are collections of threat intelligence observables
ingested from the connected EclecticIQ Intelligence Center outgoing feed.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You must also set up your EclecticIQ Intelligence Center
for Elasticsearch to connect to it. See [Set up EclecticIQ Intelligence Center](#set-up-eclecticiq-intelligence-center).


## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

You must create one integration instance per
EclecticIQ Intelligence Center outgoing feed
you want to retrieve intelligence from.

### Set up EclecticIQ Intelligence Center

Before using the integration, you must:

- Set up outgoing feeds on EclecticIQ Intelligence Center.
- Connect the integration to the EclectiCIQ Intelligence Center instance.

### Set up outgoing feeds on EclecticIQ Intelligence Center

Set up an outgoing feed on EclecticIQ Intelligence Center:
[Create and configure outgoing feeds](https://docs.eclecticiq.com/ic/current/integrations/extensions/outgoing-feeds/configure-outgoing-feeds-general-options/).

These outgoing feeds must have these properties:

- **Transport type:** _HTTP download_
- **Content type:** _EclecticIQ Observables CSV_
- **Update strategy:** _Append_, _Diff_ or _Replace_.
  This must match the update strategy set for the integration instance.
  See [Update strategies](#update-strategies).
- **Authorized groups:**
  Must set one or more groups. Feed must be authenticated.
  See [EclecticIQ Intelligence Center permissions](https://docs.eclecticiq.com/ic/current/get-to-know-the-ic/permissions/ic-permissions/).


Only observables packed by this outgoing feed are fetched.

> To find the ID of an EclecticIQ Intelligence Center outgoing feed:
> 
> 1.  Log in to EclecticIQ Intelligence Center.
> 1.  Navigate to **Data configuration > Outgoing feeds**.
> 1.  Select an outgoing feed to open it.
> 1.  Inspect the address bar of your browser.
> 1.  The ID of this outgoing feed is the
>     value of the `?detail=` query parameter.
>
>    For example: For an outgoing feed that displays
>    `https://ic-playground.eclecticiq.com/main/configuration/outgoing-feeds?detail=6`
>    in the address bar, its ID is `6`.

### Index name

This integration retrieves and makes available the latest version of the
threat intelligence retrieved from EclecticIQ Intelligence Center
in the following index:
`logs-ti_eclecticiq_latest.observables-1`

When threat intelligence is deleted from datasets used by the configured
outgoing feed, these are removed from that index.

In the Intelligence dashboard, to see only the latest
threat intelligence from EclecticIQ Intelligence Center,
filter results with:

```
_index : logs-ti_eclecticiq_latest.observables-1 and threat.indicator.type : *
```

Or

```
NOT labels.is_ioc_transform_source: * AND and threat.feed.name: "EclecticIQ"
```

### Update strategies

You must set the **same** _Update strategy_ for
both the EclecticIQ Integration instance
and the EclecticIQ Intelligence Center outgoing feed it retrieves data from.

Update strategies are how a feed decides to pack data from
its configured datasets when it runs:

- **(Recommended)**
  _Diff_ only packs data that has been deleted from or added to the feed's datasets
  since the last run.
- _Append_ only packs data that has been added to the feed's datasets
  since the last run.
- **(Not recommended)**
  _Replace_ packs _all_ the data currently in the feed's datasets
  each time it runs. Records that already exist on Elasticsearch are
  de-duplicated, but records that are outdated or removed from the feeds' datasets
  will not be correspondingly removed from Elasticsearch.

  **Known issue with _Replace_:**
  _Replace_ usually removes _all_ the data
  from a given destination before replacing it
  with all the data packed from a given feed's datasets.
  Currently, this is not supported by the integration.

### Supported EclecticIQ observables

The following is a list of EclecticIQ observables supported by this integration.
For information about how these observables are mapped, see [Exported fields](#exported-fields).

- `asn`
- `domain`
- `email`
- `file`
- `file-size`
- `hash-md5`
- `hash-md5`
- `hash-sha1`
- `hash-sha256`
- `hash-sha384`
- `hash-sha512`
- `hash-ssdeep`
- `ipv4`
- `ipv4-cidr`
- `ipv6`
- `ipv6-cidr`
- `mac-48`
- `mutex`
- `port`
- `process`
- `process-name`
- `uri`
- `winregistry`
- `certificate-serial-number`
- `malware`
- `rule`
- `user-agent`
- `organization`
- `email-subject`
- `host`
- `cve`

### Known issues

Certain threat intelligence observables in the
Elastic Indicator Intelligence dashboard are
displayed with a `-`.
That data is not displayed, but retained in the JSON 
body of the event.

## Example

An example event for `threat` looks as following:

```json
{
    "@timestamp": "2023-06-20T18:06:10.126Z",
    "eclecticiq": {
        "threat": {
            "observable_id": "AyGp2BbK9uP5CeLPYv/uuQlDxC8="
        }
    },
    "ecs": {
        "version": "8.10.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "dataset": "ti_eclecticiq.threat",
        "created": "2023-06-08T12:00:30.187Z",
        "id": "XugasX/Bvu/150lNyQjzIGR0zZ8=",
        "kind": "enrichment",
        "original": "{\"calculated.relevancy\": \"0.68\", \"calculated.source_reliability\": \"A\", \"calculated.tlp\": \"GREEN\", \"diff\": \"add\", \"entity.id\": \"5e814485-012d-423d-b769-026bfed0f451\", \"entity.title\": \"Example\", \"entity.type\": \"malware\", \"meta.classification\": \"\", \"meta.confidence\": \"\", \"meta.entity_url\": \"https://test.com/entity/5e814485-012d-423d-b769-026bfed0f451\", \"meta.estimated_observed_time\": \"2019-07-09T17:42:44.777000+00:00\", \"meta.estimated_threat_end_time\": \"\", \"meta.estimated_threat_start_time\": \"2022-05-11T14:00:00.188000+00:00\", \"meta.ingest_time\": \"2023-06-08T12:00:30.187097+00:00\", \"meta.relevancy\": \"0.68\", \"meta.source_reliability\": \"A\", \"meta.tags\": \"tag1;tag2\", \"meta.taxonomy\": \"\", \"meta.terms_of_use\": \"\", \"meta.tlp\": \"GREEN\", \"source.ids\": \"47ec245c-9e7b-467e-a016-77a22ff12dd5\", \"source.names\": \"Test Source\", \"timestamp\": \"2023-06-20 18:06:10.126780+00:00\", \"type\": \"domain\", \"value\": \"example.com\", \"value_url\": \"https://test.com/main/extracts/domain/test\"}",
        "provider": "Test Source",
        "start": "2022-05-11T14:00:00.188Z",
        "type": [
            "indicator"
        ],
        "url": "https://www.test.com/"
    },
    "tags": [
        "tag1",
        "tag2"
    ],
    "threat": {
        "indicator": {
            "first_seen": "2019-07-09T17:42:44.777Z",
            "marking": {
                "tlp": "GREEN"
            },
            "name": "example.com",
            "type": "domain-name",
            "url": {
                "domain": "example.com"
            }
        }
    }
}
```

## Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eclecticiq.threat.deleted_at | Date when observable was removed from dataset | date |
| eclecticiq.threat.observable_id | The ID of the observable, based on kind and value. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
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
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
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
| threat.feed.name | Display friendly feed name | constant_keyword |
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

