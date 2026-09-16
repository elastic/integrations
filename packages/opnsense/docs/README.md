# OPNsense

## Overview

[OPNsense](https://opnsense.org/) is an open-source firewall and routing platform
based on FreeBSD and HardenedBSD, developed by Deciso B.V. It provides stateful
packet filtering, VPN, intrusion detection and traffic shaping through the `pf`
packet filter.

This integration collects OPNsense **filterlog** events — the accept and block
decisions `pf` makes on every packet that matches a logging rule — over syslog,
and maps them to the Elastic Common Schema.

### Compatibility

This integration has been tested against OPNsense **26.7**. The filterlog format
is stable across recent releases, so earlier versions are expected to work.

The same format is produced by pfSense and by FreeBSD's `pf` directly, but only
OPNsense has been verified. For pfSense, use the dedicated `pfsense` integration.

### How it works

OPNsense forwards its logs over syslog. The Elastic Agent listens on a UDP or TCP
port and receives the messages as OPNsense emits them; a third input reads
messages already written to a file.

Each filterlog message is an RFC 5424 syslog envelope wrapping a CSV body. The
pipeline parses the envelope, then parses the body positionally — its column
layout changes with the IP version and again with the transport protocol, so a
single script handles the variants rather than a stack of alternative patterns.

## What data does this integration collect?

The integration collects one data stream:

| Data stream | Type | Description |
|---|---|---|
| `log` | logs | OPNsense firewall events from the `filterlog` process, plus other syslog messages forwarded from the same host. |

Filterlog events are mapped to ECS: the action becomes `event.action` and
`event.type` (`allowed` or `denied`), addresses and ports become `source.*` and
`destination.*`, the matching rule becomes `rule.id`, and the interface becomes
`observer.ingress.interface.name`. Protocol-specific detail with no ECS
equivalent is kept under `opnsense.log.*`.

Messages from the same syslog stream that are not filterlog events are retained
with their text in `message` and their program name in `process.name`, rather
than being dropped.

### Supported use cases

- See what the firewall is blocking, which rules are responsible, and whether a
  rule change had the intended effect.
- Identify port scans from the TCP flag combination — `opnsense.log.tcp.flags`
  distinguishes an ordinary `S` connection attempt from FIN, NULL and Xmas scans.
- Track which internal hosts generate the most outbound traffic and where it goes.
- Correlate firewall decisions with events from other integrations through
  `source.ip`, `destination.ip` and `related.ip`.

## What do I need to use this integration?

- An Elastic Stack deployment — self-managed, Elastic Cloud or Elastic Cloud
  Serverless — and an Elastic Agent enrolled in Fleet.
- An OPNsense installation you can administer, to configure a remote syslog
  target and to enable logging on the rules you want to observe.
- Network reachability from OPNsense to the Elastic Agent on the chosen port.
- Permission for the Agent to bind the listening port. Ports below 1024 require
  additional privileges, so the default is `9525`.

No credentials or API access to OPNsense are required — OPNsense pushes syslog to
the Agent.

## How do I deploy this integration?

For step-by-step instructions on installing the Elastic Agent and adding an
integration, refer to the
[Getting started guide](https://www.elastic.co/guide/en/observability/current/observability-get-started.html).

### Onboard and configure

Fleet-managed and standalone Elastic Agent deployments are both supported.
Agentless deployment is **not** supported: OPNsense pushes syslog to a listener,
which requires an Agent reachable from the firewall.

1. In Kibana, go to **Management > Integrations**, search for **OPNsense**, and
   click **Add OPNsense**.
2. Enable one input and configure it:
   - **UDP** (default) — OPNsense's normal syslog transport. Set the listen
     address to `0.0.0.0` unless the Agent has a single relevant interface.
   - **TCP** — use when delivery guarantees matter or when messages can exceed
     the network MTU.
   - **File** — use to read messages already written to disk by another collector.
3. Select or create an agent policy and save.

Then configure OPNsense to forward to it:

1. In the OPNsense web interface, go to
   **System > Settings > Logging / targets**.
2. Add a target:
   - **Transport** — matching the input enabled above, `UDP(4)` by default.
   - **Applications** — include `filter` to send packet filter events.
   - **Hostname** and **Port** — the Elastic Agent's address and listen port.
   - **Level** — `Informational` or lower; filterlog events are logged at
     `Informational`.
3. Apply the change.
4. Confirm the rules you want to observe have logging enabled under
   **Firewall > Rules**. The default deny rule logs by default.

Refer to the
[OPNsense logging documentation](https://docs.opnsense.org/manual/settingsmenu.html)
for the authoritative configuration reference.

### Validation

1. Generate traffic the firewall will block, for example by connecting to a
   closed port on the firewall's WAN address.
2. Confirm OPNsense logged it under **Firewall > Log Files > Live View**.
3. On the Agent host, confirm the packets arrive:

   ```bash
   sudo tcpdump -n -i any udp port 9525
   ```

4. In Kibana, open **Discover** and query `data_stream.dataset: "opnsense.log"`,
   or open the **[Logs OPNsense] Firewall activity** dashboard.

## Troubleshooting

**`tcpdump` shows packets but no documents appear.**
A host firewall on the Agent machine is dropping the port before the listener
sees it. `tcpdump` captures below the filter, so traffic is visible even when the
socket never receives it. Add an accept rule for the listen port.

**Documents appear but every filterlog field is missing.**
The syslog target is not sending the `filter` application, so the messages are
other OPNsense logs. These are retained with their text in `message`; check
`process.name` to see what is actually being forwarded.

**`destination.port` or `source.port` is missing on some events.**
ICMP and protocols without ports do not carry them. This is expected — check
`network.transport` before reading the port fields.

**Events are truncated or malformed under load.**
UDP syslog has no delivery guarantee and messages larger than the MTU are
truncated. Switch the target and the integration to TCP.

**`event.action` is present but `rule.id` is not.**
The rule that matched has no tracker id, which happens for some automatically
generated rules. The action and interface are still recorded.

For OPNsense-side issues, refer to the
[OPNsense troubleshooting documentation](https://docs.opnsense.org/troubleshooting/).

## Performance and scaling

The UDP and TCP inputs are push-based, so throughput is bounded by how much the
firewall logs rather than by a polling interval. A busy firewall with logging
enabled on permissive rules can produce a very high event rate; log only the
rules that matter rather than logging everything and filtering later.

UDP drops messages silently under load, at the kernel receive buffer. If events
are missing during traffic peaks, either raise the receive buffer on the Agent
host or switch to TCP, which applies back-pressure instead of discarding.

For several firewalls, point them at one Agent listener; events carry
`observer.name` and `host.name` to tell them apart. Scale out to multiple Agents
only when a single listener saturates.

For guidance on sizing the Elastic Stack itself, refer to
[Elastic Agent scaling](https://www.elastic.co/guide/en/fleet/current/fleet-agent-scaling.html).

## Reference

### Inputs used in this integration

| Input | Purpose | Enabled by default |
|---|---|---|
| `udp` | Receives syslog over UDP, OPNsense's default transport. | yes |
| `tcp` | Receives syslog over TCP. | no |
| `logfile` | Reads syslog messages from a file. | no |

### The filterlog format

A filterlog body is CSV whose layout changes with the IP version and then with
the transport protocol:

- IPv4 carries `tos, ecn, ttl, id, offset, flags` and reports the protocol as
  `number, name`; IPv6 carries `class, flow, hoplimit` and reverses those two
  columns to `name, number`.
- TCP lines end with ports, payload length, flags, sequence and acknowledgement
  numbers, window, urgent pointer and options.
- UDP lines end after ports and payload length.
- ICMP lines end with `key=value` pairs rather than positional columns.

### Log

The `log` data stream collects OPNsense firewall events.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2026-09-07T02:06:04.000Z",
    "data_stream": {
        "dataset": "opnsense.log",
        "namespace": "default",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": "198.51.100.1",
        "port": 22
    },
    "ecs": {
        "version": "9.3.0"
    },
    "event": {
        "action": "pass",
        "category": [
            "network"
        ],
        "kind": "event",
        "outcome": "success",
        "reason": "match",
        "type": [
            "connection",
            "allowed"
        ]
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
                "name": "vtnet0"
            }
        },
        "name": "OPNsense.internal",
        "product": "OPNsense",
        "type": "firewall",
        "vendor": "OPNsense"
    },
    "opnsense": {
        "log": {
            "action": "pass",
            "data_length": 0,
            "destination_ip": "198.51.100.1",
            "destination_port": 22,
            "direction": "in",
            "interface": "vtnet0",
            "ip": {
                "flags": "DF",
                "id": 15873,
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
                "id": "81",
                "uuid": "60533d555322b9f6a009f71c1c471480"
            },
            "source_ip": "198.51.100.2",
            "source_port": 47048,
            "tcp": {
                "flags": "S",
                "options": "mss;sackOK;TS;nop;wscale",
                "sequence_number": "2012195821",
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
            "198.51.100.2",
            "198.51.100.1"
        ]
    },
    "rule": {
        "id": "81",
        "uuid": "60533d555322b9f6a009f71c1c471480"
    },
    "source": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": "198.51.100.2",
        "port": 47048
    },
    "tags": [
        "opnsense-log",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| log.file.path | Path to the log file the event was read from. | keyword |
| log.offset | Log offset. | long |
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

