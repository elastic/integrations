# Forcepoint Web Security

This integration allows you to ingest log and event data from Forcepoint Web Security.

NOTE: At present it is limited to ingestion of files exported using the offical Forcepoint Log Export SIEM tool, refer to [this page](https://www.websense.com/content/support/library/web/hosted/admin_guide/siem_script.aspx)

## Data streams

The Forcepoint Web Security integration collects one type of data stream: logs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.

You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

Start by reading [this page](https://www.websense.com/content/support/library/web/hosted/admin_guide/siem_integration_explain.aspx).

While it is possible to use AWS S3 as BYO storage that Forcepoint Web Security can export logs to, at this point the integration does not support connection to an S3 bucket directly.

Configuration of storage type is [described here](https://www.websense.com/content/support/library/web/hosted/admin_guide/siem_storage.aspx).

A Perl script is provided by Forcepoint to "pull" logs from "Forcepoint" storage and is [described here](https://www.websense.com/content/support/library/web/hosted/admin_guide/siem_script.aspx).

A containerised version of the Forcepoint Log Export SIEM tool is available via this [GitHub repository](https://github.com/colin-stubbs/docker-forcepoint-log_export_siem).

The format of the gzip compressed CSV files that Forcepoint Web Security spits out is configurable, ensure you read and understand [this page](https://www.websense.com/content/support/library/web/hosted/siem_guide/siem_format.aspx).

The default format assumed by this integration is:
```
"%{date}","%{time}","%{user}","%{workstation}","%{category}","%{action}","%{risk_class}","%{policy_name}","%{url}","%{connection_ip}","%{destination_ip}","%{source_ip}","%{threat_type}","%{threat_name}","%{user_agent_string}","%{http_status_code}","%{http_request_method}"
```

The field names (encapsulated in %{}) used in this format will wind up under the `forcepoint_web` field object.

If you choose to export additional fields you may need to expand or change this entirely if you order things differently. It can be customised as part of each integration policy instance. Ensure you escape the double quotes (") in the string as per the default string.

At present those fields are currently mapped as follows,

| Field (under forcepoint_web) | Fields (ECS where possible)                   |
|------------------------------|-----------------------------------------------|
| date + time                  | @timestamp                                    |
| user                         | user.id, user.name, user.domain, related.user |
| workstation                  | host.name, related.hosts                      |
| category                     | -                                             |
| action                       | event.action (lowercase)                      |
| risk_class                   | -                                             |
| policy_name                  | rule.name                                     |
| url                          | url.*                                         |
| connection_ip                | source.nat.ip, related.ip                     |
| destination_ip               | destination.ip, related.ip                    |
| source_ip                    | source.ip, related.ip                         |
| threat_type                  | -                                             |
| threat_name                  | -                                             |
| user_agent_string            | user_agent.*                                  |
| http_status_code             | http.response.status_code                     |
| http_request_method          | http.request.method                           |

## Compatibility

This integration has been tested against Forcepoint Web Security using the Log Export SIEM tool version v2.0.1

Versions above this are expected to work but have not been tested.

## Debugging

If the "Preserve original event" is enabled, this will add the tag `preserve_original_event` to the event. `event.original` will be set with the *original* message contents, which is pre-KV and pre-syslog parsing.

If the "preserve_log" tag is added to an integration input, the `log` object and all fields under it will be preserved.

## Logs reference

### forcepoint_web.logs

The `forcepoint_web.logs` data stream provides events from Forcepoint Web Security.

#### Example

An example event for `forcepoint_web.logs` looks as following:

An example event for `logs` looks as following:

```json
{
    "@timestamp": "2023-01-13T00:30:45.891Z",
    "agent": {
        "ephemeral_id": "07b2ae81-8fca-461c-aba7-9331c2aabc5e",
        "id": "8cc7367b-4069-4535-8545-a477b8c273af",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "data_stream": {
        "dataset": "forcepoint_web.logs",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "3.24.198.68"
    },
    "ecs": {
        "version": "8.10.0"
    },
    "elastic_agent": {
        "id": "8cc7367b-4069-4535-8545-a477b8c273af",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "action": "allowed",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "forcepoint_web.logs",
        "ingested": "2023-01-13T00:30:46Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "forcepoint_web": {
        "action": "Allowed",
        "category": [
            "Reference Materials",
            "Trusted Server Downloads"
        ],
        "connection_ip": "202.4.188.96",
        "date": "16/12/2022",
        "destination_ip": "3.24.198.68",
        "http_request_method": "Connect",
        "http_status_code": "200",
        "policy_name": "Org Internal Server Policy",
        "risk_class": [
            "Business Usage",
            "None"
        ],
        "time": "07:05:25",
        "timestamp": "2022-12-16T07:05:25.000Z",
        "user": "anonymous",
        "user_agent_string": "Java/11.0.6"
    },
    "http": {
        "request": {
            "method": "CONNECT"
        },
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "log"
    },
    "message": "\"16/12/2022\",\"07:05:25\",\"anonymous\",\"Not available\",\"Reference Materials,Trusted Server Downloads\",\"Allowed\",\"Business Usage,None\",\"Org Internal Server Policy\",\"aom-au.nearmap.com:443/\",\"202.4.188.96\",\"3.24.198.68\",\"Not available\",\"None\",\"None\",\"Java/11.0.6\",\"200\",\"Connect\"",
    "related": {
        "ip": [
            "3.24.198.68",
            "202.4.188.96"
        ],
        "user": [
            "anonymous"
        ]
    },
    "rule": {
        "name": "Org Internal Server Policy"
    },
    "source": {
        "nat": {
            "ip": "202.4.188.96"
        }
    },
    "tags": [
        "forwarded"
    ],
    "url": {
        "domain": "aom-au.nearmap.com",
        "original": "https://aom-au.nearmap.com:443/",
        "path": "/",
        "port": 443,
        "registered_domain": "nearmap.com",
        "scheme": "https",
        "subdomain": "aom-au",
        "top_level_domain": "com"
    },
    "user": {
        "id": "anonymous",
        "name": "anonymous"
    },
    "user_agent": {
        "device": {
            "name": "Spider"
        },
        "name": "Java",
        "original": "Java/11.0.6",
        "version": "0.6."
    }
}
```

The following fields may be used by the package:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| container.id | Unique container id. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| destination.user.email | User email address. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reference | Reference URL linking to additional information about this event. This URL links to a static definition of this event. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| forcepoint_web.action |  | keyword |
| forcepoint_web.category |  | keyword |
| forcepoint_web.connection_ip |  | keyword |
| forcepoint_web.date |  | keyword |
| forcepoint_web.destination_ip |  | keyword |
| forcepoint_web.http_request_method |  | keyword |
| forcepoint_web.http_status_code |  | keyword |
| forcepoint_web.policy_name |  | keyword |
| forcepoint_web.risk_class |  | keyword |
| forcepoint_web.source_ip |  | keyword |
| forcepoint_web.time |  | keyword |
| forcepoint_web.timestamp |  | date |
| forcepoint_web.user |  | keyword |
| forcepoint_web.user_agent_string |  | keyword |
| forcepoint_web.workstation |  | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.status_code | HTTP response status code. | long |
| input.type |  | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| rule.uuid | A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| tls.client.issuer | Distinguished name of subject of the issuer of the x.509 certificate presented by the client. | keyword |
| tls.client.server_name | Also called an SNI, this tells the server which hostname to which the client is attempting to connect to. When this value is available, it should get copied to `destination.domain`. | keyword |
| tls.client.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.server.issuer | Subject of the issuer of the x.509 certificate presented by the server. | keyword |
| tls.server.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.server.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.version | Version of the user agent. | keyword |
| vulnerability.category | The type of system or architecture that the vulnerability affects. These may be platform-specific (for example, Debian or SUSE) or general (for example, Database or Firewall). For example (https://qualysguard.qualys.com/qwebhelp/fo_portal/knowledgebase/vulnerability_categories.htm[Qualys vulnerability categories]) This field must be an array. | keyword |

