# Stormshield SNS

Stormshield Network Security (SNS) firewalls are a stable and efficient security solution to protect corporate networks from cyberattacks. Real-time protection (intrusion prevention and detection, application control, antivirus, etc.), control and supervision (URL filtering, IP geolocation, vulnerability detection, etc.) and content filtering (antispam, antispyware, antiphishing, etc.) all guarantee secure communications. All Stormshield Network Security firewalls are based on the same firmware, and with their core features, Stormshield Network Security firewalls give you comprehensive security and high performance network protection.

Use the Stormshield SNS integration to ingest log data into Elastic Security and leverage the data for threat detection, incident response, and visualization.


## Data streams

The Stormshield SNS integration collects audit, traffic, and connection (including NAT) logs. Available log types are available here: https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Configure_logs.htm .


**Logs** help you keep a record of events happening in your firewalls.
The SNS integration handles activity logs and firewall (filter and NAT) logs. See more details in the [Logs](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

The SNS integration ingests logs via a syslog parser, so the SNS appliance needs to be configured to send syslogs to a listening Agent. This is configured in the `CONFIGURATION` tab, in the `NOTIFICATIONS` / `LOGS-SYSLOG-IPFIX` section. Please review the Stormshield documentation for details on how to configure syslog: https://documentation.stormshield.eu/SNS/v4/en/Content/Description_of_Audit_logs/Configure_logs.htm.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Log

SNS can be configured to store all its logs locally, or to send them through the syslog protocol to a configured listener, such as the Elastic Agent via policy update.

An example event for `log` looks as following:

```json
{
    "agent": {
        "name": "ubuntu",
        "id": "00b10fd1-01e6-4c9c-bd93-33451ccce64c",
        "ephemeral_id": "8b08b69d-9e8f-413f-beb5-f0799b611cad",
        "type": "filebeat",
        "version": "8.11.4"
    },
    "process": {
        "name": "serverd"
    },
    "log": {
        "source": {
            "address": "192.168.197.134:2747"
        },
        "syslog": {
            "severity": {
                "code": 5,
                "name": "Notice"
            },
            "hostname": "stormy-1",
            "appname": "serverd",
            "priority": 13,
            "version": "1",
            "facility": {
                "code": 1,
                "name": "user-level"
            }
        }
    },
    "elastic_agent": {
        "id": "00b10fd1-01e6-4c9c-bd93-33451ccce64c",
        "version": "8.11.4",
        "snapshot": false
    },
    "tags": [
        "forwarded"
    ],
    "input": {
        "type": "tcp"
    },
    "@timestamp": "2024-05-08T17:18:57.000Z",
    "ecs": {
        "version": "8.11.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "stormshield.log"
    },
    "stormshield": {
        "startime": "2024-05-08 17:18:57",
        "tz": "+0000",
        "Pvm": "0,0,0,0,0,0,0,0,0,0,0",
        "device_stats": {
            "ipsec": [
                {
                    "original": "ipsec",
                    "packets_blocked": 0,
                    "name": "ipsec",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                }
            ],
            "Ethernet": [
                {
                    "original": "Ethernet0",
                    "packets_blocked": 0,
                    "name": "out",
                    "incoming_throughput": 134,
                    "maximum_outgoing_throughput": 656,
                    "outgoing_throughput": 185,
                    "packets_accepted": 48,
                    "maximum_incoming_throughput": 480
                },
                {
                    "original": "Ethernet1",
                    "packets_blocked": 0,
                    "name": "segment0",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                },
                {
                    "original": "Ethernet2",
                    "packets_blocked": 0,
                    "name": "segment1",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                },
                {
                    "original": "Ethernet3",
                    "packets_blocked": 0,
                    "name": "dmz2",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                }
            ],
            "CPU": {
                "kernel_time": 1,
                "system_disruption": 1,
                "user_time": 0
            },
            "sslvpn": [
                {
                    "original": "sslvpn0",
                    "packets_blocked": 0,
                    "name": "sslvpn",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                },
                {
                    "original": "sslvpn1",
                    "packets_blocked": 0,
                    "name": "sslvpn_udp",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                }
            ],
            "Qid": [
                {
                    "original": "Qid0",
                    "packets_blocked": 0,
                    "name": "BYPASS_out",
                    "incoming_throughput": 22,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 49,
                    "maximum_incoming_throughput": 9064
                },
                {
                    "original": "Qid1",
                    "packets_blocked": 0,
                    "name": "BYPASS_segment0",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                },
                {
                    "original": "Qid2",
                    "packets_blocked": 0,
                    "name": "BYPASS_ipsec",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                },
                {
                    "original": "Qid3",
                    "packets_blocked": 0,
                    "name": "BYPASS_segment1",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                },
                {
                    "original": "Qid4",
                    "packets_blocked": 0,
                    "name": "BYPASS_dmz2",
                    "incoming_throughput": 0,
                    "maximum_outgoing_throughput": 0,
                    "outgoing_throughput": 0,
                    "packets_accepted": 0,
                    "maximum_incoming_throughput": 0
                }
            ]
        },
        "fw": "stormy-1",
        "security": "0",
        "logtype": "monitor",
        "system": "0",
        "mem": "0,0,0,0,0,0,15,0",
        "id": "firewall",
        "time": "2024-05-08 17:18:57"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-05-08T17:18:58Z",
        "timezone": "+00:00",
        "created": "2024-05-08T17:18:57.000Z",
        "dataset": "stormshield.log"
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
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
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
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| input.type | Type of input. | keyword |
| log.source.address | Source address for the log. | keyword |
| log.syslog.appname | The device or application that originated the Syslog message, if available. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.facility.name | The Syslog text-based facility of the log event, if available. | keyword |
| log.syslog.hostname | The hostname, FQDN, or IP of the machine that originally sent the Syslog message. This is sourced from the hostname field of the syslog header. Depending on the environment, this value may be different from the host that handled the event, especially if the host handling the events is acting as a collector. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| log.syslog.severity.name | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different severity value (e.g. firewall, IDS), your source's text severity should go to `log.level`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `log.level`. | keyword |
| log.syslog.version | The version of the Syslog protocol specification. Only applicable for RFC 5424 messages. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
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
| source.port | Port of the source. | long |
| stormshield.dstif | Name of the destination interface. String of characters in UTF-8 format. Example: Ethernet 1 Available from: SNS v1.0.0. | keyword |
| stormshield.dstifname | Name of the object representing the traffics destination interface. String of characters in UTF-8 format. Example: dmz1 Available from: SNS v1.0.0. | keyword |
| stormshield.duration | Duration of the connection in seconds. Decimal format.  Example: "173.15" | keyword |
| stormshield.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.in_bytes | Count of bytes coming into the firewall | long |
| stormshield.logtype | The specific type of log this is from. | keyword |
| stormshield.metadata | Flattened metadata | flattened |
| stormshield.msg | Text message explaining the alarm.  String of characters in UTF-8 format. Example: Port probe | keyword |
| stormshield.origdst | Original IP address of the destination host (before translation or the application of a virtual connection).  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.out_bytes | Count of bytes leaving the firewall | long |
| stormshield.ports | The network ports found on the device | keyword |
| stormshield.service | Service (product with a dedicated port) on which the vulnerability was detected.  String of characters in UTF-8 format. Example: OpenSSH_5.4 | keyword |
| stormshield.srcif | Internal name of the interface at the source of the traffic. String of characters in UTF-8 format. Example: Ethernet0 Available from: SNS v1.0.0. | keyword |
| stormshield.srcifname | Name of the object representing the interface at the source of the traffic. String of characters in UTF-8 format. Example: out Available from: SNS v1.0.0. | keyword |
| stormshield.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.system | Indicator of the Firewalls system status.  This value is used by the fleet management tool (Stormshield Network Unified Manager) to provide information on the system status (available RAM, CPU use, bandwidth, interfaces, fullness of audit logs, etc). Decimal format representing a percentage. | keyword |
| stormshield.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

