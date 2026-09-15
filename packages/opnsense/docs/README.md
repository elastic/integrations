# OPNsense

[OPNsense](https://opnsense.org/) is an open-source firewall and routing
platform based on FreeBSD and HardenedBSD.

This integration collects OPNsense's **filterlog** events — the packet filter
decisions made by `pf` — over syslog, and maps them to the Elastic Common Schema.

## Compatibility

Tested against OPNsense 26.7. The filterlog format is stable across recent
releases.

## Data collection

Configure OPNsense to forward its logs:

1. In the OPNsense UI, go to **System → Settings → Logging / targets**.
2. Add a target with the address and port of the host running Elastic Agent,
   the transport matching the input you enable below (UDP by default), and
   **Applications** set to include `filter`.
3. Ensure the rules you want to observe have logging enabled. The default deny
   rule logs by default.

Then add this integration to an agent policy and pick an input:

- **UDP**, the usual choice and OPNsense's default transport.
- **TCP**, for delivery guarantees or messages larger than the network MTU.
- **File**, to read messages already written to disk.

The agent needs permission to bind the listening port. Ports below 1024 require
extra privileges, so the default is `9525`.

## The log format

A filterlog line is an RFC 5424 syslog message wrapping a CSV body whose layout
changes with the IP version and then with the transport protocol:

- IPv4 carries `tos, ecn, ttl, id, offset, flags` and reports the protocol as
  `number, name`; IPv6 carries `class, flow, hoplimit` and reverses those two
  columns to `name, number`.
- TCP lines end with ports, payload length, flags, sequence and acknowledgement
  numbers, window, urgent pointer and options.
- UDP lines end after ports and payload length.
- ICMP lines end with `key=value` pairs rather than positional columns.

The pipeline parses all of these into `opnsense.log.*` alongside the ECS fields.
`opnsense.log.tcp.flags` is worth knowing about: it distinguishes an ordinary
SYN connection attempt from FIN, NULL and Xmas scans.

## Dashboard

The **[Logs OPNsense] Firewall Activity** dashboard covers traffic volume and
block rate, activity over time by action and interface, the ports being targeted
over time, TCP flag distribution, which rules are firing, top talkers and
destinations, protocol and direction breakdowns, and a source map.

## Logs

### Log

The `log` data stream collects OPNsense firewall events.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2026-09-07T02:05:17.000Z",
    "destination": {
        "geo": {
            "city_name": "Las Vegas",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 36.17497,
                "lon": -115.13722
            },
            "region_iso_code": "US-NV",
            "region_name": "Nevada"
        },
        "ip": "192.0.2.10",
        "port": 22
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "block",
        "category": [
            "network"
        ],
        "kind": "event",
        "outcome": "failure",
        "reason": "match",
        "type": [
            "connection",
            "denied"
        ],
        "dataset": "opnsense.log",
        "module": "opnsense"
    },
    "host": {
        "name": "OPNsense.internal"
    },
    "log": {
        "syslog": {
            "facility": {
                "code": 16
            },
            "priority": 134,
            "severity": {
                "code": 6
            }
        }
    },
    "network": {
        "bytes": 60,
        "direction": "inbound",
        "transport": "tcp",
        "type": "ipv4"
    },
    "observer": {
        "ingress": {
            "interface": {
                "name": "vtnet1"
            }
        },
        "name": "OPNsense.internal",
        "product": "OPNsense",
        "type": "firewall",
        "vendor": "OPNsense"
    },
    "opnsense": {
        "log": {
            "action": "block",
            "data_length": 0,
            "destination_ip": "192.0.2.10",
            "destination_port": 22,
            "direction": "in",
            "interface": "vtnet1",
            "ip": {
                "flags": "DF",
                "id": 10370,
                "offset": 0,
                "protocol_number": 6,
                "tos": "0x0",
                "ttl": 64
            },
            "ip_version": "4",
            "length": 60,
            "protocol": "tcp",
            "reason": "match",
            "rule": {
                "id": "71",
                "uuid": "3d399f8f89b68d684701badb48eab085"
            },
            "source_ip": "192.0.2.1",
            "source_port": 53170,
            "tcp": {
                "flags": "S",
                "options": "mss;sackOK;TS;nop;wscale",
                "sequence_number": "879339721",
                "window": "64240"
            }
        }
    },
    "process": {
        "name": "filterlog",
        "pid": 54555
    },
    "related": {
        "ip": [
            "192.0.2.1",
            "192.0.2.10"
        ]
    },
    "rule": {
        "id": "71",
        "uuid": "3d399f8f89b68d684701badb48eab085"
    },
    "source": {
        "as": {
            "number": 64500,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Las Vegas",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 36.17497,
                "lon": -115.13722
            },
            "region_iso_code": "US-NV",
            "region_name": "Nevada"
        },
        "ip": "192.0.2.1",
        "port": 53170
    },
    "data_stream": {
        "type": "logs",
        "dataset": "opnsense.log",
        "namespace": "default"
    },
    "tags": [
        "opnsense",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| opnsense.log.action | What the firewall did with the packet, for example `block`, `pass` or `rdr`. | keyword |
| opnsense.log.data_length | Payload length in bytes, for TCP and UDP. | long |
| opnsense.log.destination_ip | Raw destination address as logged. Also parsed into `destination.ip`. | keyword |
| opnsense.log.destination_port | Destination port, for TCP and UDP. | long |
| opnsense.log.direction | Direction relative to the interface, `in` or `out`. | keyword |
| opnsense.log.icmp.datalength | ICMP payload length. | keyword |
| opnsense.log.icmp.id | ICMP echo identifier. | keyword |
| opnsense.log.icmp.seq | ICMP echo sequence number. | keyword |
| opnsense.log.icmp.type | ICMP type as logged, when OPNsense reports it as a bare token. | keyword |
| opnsense.log.interface | The interface the packet was seen on, for example `vtnet0` or `igb0`. | keyword |
| opnsense.log.ip.class | IPv6 traffic class. | keyword |
| opnsense.log.ip.ecn | IPv4 explicit congestion notification. | keyword |
| opnsense.log.ip.flags | IPv4 flags, for example `DF`. | keyword |
| opnsense.log.ip.flow_label | IPv6 flow label. | keyword |
| opnsense.log.ip.hop_limit | IPv6 hop limit. | long |
| opnsense.log.ip.id | IPv4 identification field. | long |
| opnsense.log.ip.offset | IPv4 fragment offset. | long |
| opnsense.log.ip.protocol_number | Numeric protocol identifier. | long |
| opnsense.log.ip.tos | IPv4 type of service. | keyword |
| opnsense.log.ip.ttl | IPv4 time to live. | long |
| opnsense.log.ip_version | IP version of the packet, `4` or `6`. The remaining fields of the log line differ between the two. | keyword |
| opnsense.log.length | Total packet length in bytes. | long |
| opnsense.log.protocol | Transport protocol name as OPNsense reports it, for example `tcp`, `udp`, `icmp` or `ipv6-icmp`. | keyword |
| opnsense.log.reason | Why the packet was logged, for example `match` for a rule match or `ip-option` for a rejected IP option. | keyword |
| opnsense.log.rule.anchor | Name of the pf anchor the rule belongs to. | keyword |
| opnsense.log.rule.id | Number of the rule that matched. | keyword |
| opnsense.log.rule.subrule | Sub-rule number, when the matching rule is part of a group. | keyword |
| opnsense.log.rule.uuid | Identifier of the matching rule, which is stable across reloads and links the event back to the rule in the OPNsense UI. | keyword |
| opnsense.log.source_ip | Raw source address as logged. Also parsed into `source.ip`. | keyword |
| opnsense.log.source_port | Source port, for TCP and UDP. | long |
| opnsense.log.tcp.ack_number | TCP acknowledgement number. | keyword |
| opnsense.log.tcp.flags | TCP flags on the packet, for example `S` for SYN or `FA` for FIN+ACK. Useful for telling scan techniques apart. | keyword |
| opnsense.log.tcp.options | TCP options present on the packet, for example `mss;sackOK;TS;nop;wscale`. | keyword |
| opnsense.log.tcp.sequence_number | TCP sequence number. | keyword |
| opnsense.log.tcp.urg | TCP urgent pointer. | keyword |
| opnsense.log.tcp.window | TCP window size. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.ip | All of the IPs seen on your event. | ip |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.uuid | A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |

