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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.continent_code | Two-letter code representing continent's name. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
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
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.port | Port of the source. | long |
| stormshield.Accepted | Number of packets corresponding to the application of Pass rules. Example: Accepted=2430. | long |
| stormshield.AssocMem | The memory used for ... | long |
| stormshield.Blocked | Number of packets corresponding to the application of Block rules. Example: Blocked=1254. | long |
| stormshield.Byte.in_count | Number of bytes that have passed through the firewall (incoming) | long |
| stormshield.Byte.out_count | Number of bytes that have passed through the firewall (outgoing) | long |
| stormshield.ConnMem | Percentage of memory allocated to connections. Value from 0 to 100. | long |
| stormshield.DTrackMem | The memory used for ... | long |
| stormshield.DtrackMem | Percentage of memory used for data tracking (TCP/UDP packets). Value from 0 to 100. | keyword |
| stormshield.DynamicMem | Percentage of the ASQs dynamic memory in use. Value from 0 to 100. | long |
| stormshield.EtherStateByte.in_count | Number of bytes that have passed through the firewall (incoming) | long |
| stormshield.EtherStateByte.out_count | Number of bytes that have passed through the firewall (outgoing) | long |
| stormshield.EtherStateConn | Number of stateful statuses for Ethernet exchanges without IP layer. Digital format. Example: EtherStateConn=0 Available from: SNS v4.0.0. | long |
| stormshield.EtherStateMem | The memory used for ... | long |
| stormshield.EtherStatePacket | Number of packets for Ethernet traffic without IP layer. Digital format. Example: EtherStatePacket=128 Available from: SNS v4.0.0. | long |
| stormshield.FragMem | Percentage of memory allocated to the treatment of fragmented packets. Value from 0 to 100. | long |
| stormshield.Fragmented | Number of fragmented packets that have passed through the Firewall. | long |
| stormshield.HostMem | Percentage of memory allocated to a host processed by the Firewall. Value from 0 to 100. | long |
| stormshield.HostrepMax | Highest reputation score of monitored hosts. Value: decimal integer between 0 and 65535. Example: HostrepMax=6540 Available from: SNS v3.0.0. | long |
| stormshield.HostrepRequests | Number of reputation score requests submitted. Value: unrestricted decimal integer. Example: HostrepRequests=445 Available from: SNS v3.0.0. | long |
| stormshield.HostrepScore | Average reputation score of monitored hosts. Value: decimal integer between 0 and 65535. Example: HostrepScore=1234 Available from: SNS v3.0.0. | long |
| stormshield.ICMPByte.in_count | Number of bytes that have passed through the firewall (incoming) | long |
| stormshield.ICMPByte.out_count | Number of bytes that have passed through the firewall (outgoing) | long |
| stormshield.ICMPMem | Percentage of memory allocated to ICMP. Value from 0 to 100. | long |
| stormshield.ICMPPacket | Number of ICMP packets that have passed through the Firewall. | long |
| stormshield.IPStateByte.in_count | Number of bytes that have passed through the firewall (incoming) | long |
| stormshield.IPStateByte.out_count | Number of bytes that have passed through the firewall (outgoing) | long |
| stormshield.IPStateConn | Number of active pseudo-connections relating to protocols other than TCP, UDP or ICMP (e.g.: GRE). | long |
| stormshield.IPStateConnNatDst | Number of active pseudo-connections with address translation on the destination. | long |
| stormshield.IPStateConnNatSrc | Number of active pseudo-connections with address translation on the source. | long |
| stormshield.IPStateConnNoNatDst | Number of active pseudo-connections that explicitly include "No NAT" instructions on the destination. | long |
| stormshield.IPStateConnNoNatSrc | Number of active pseudo-connections that explicitly include "No NAT" instructions on the source. | long |
| stormshield.IPStateMem | Percentage of memory allocated to processing pseudo-connections relating to protocols other than TCP, UDP or ICMP (e.g.: GRE) that have passed through the firewall. | long |
| stormshield.IPStatePacket | Number of network packets originating from protocols other than TCP, UDP or ICMP (e.g.: GRE) that have passed through the firewall. | long |
| stormshield.LogOverflow | Number of log lines that could not be generated by the intrusion prevention engine. | long |
| stormshield.Logged | Number of log lines generated by the intrusion prevention engine. | long |
| stormshield.Pvm | All indicators regarding vulnerability management:  Total number of vulnerabilities detected, number of vulnerabilities that can be exploited remotely, number of vulnerabilities requiring the installation of a server on the vulnerable host in order to be exploited, number of vulnerabilities classified as critical, number of vulnerabilities classified as minor, number of vulnerabilities classified as major, number of vulnerabilities that have a bug fix, total amount of information (all levels), number of minor data, number of major data, number of hosts for which PVM has gathered information,  Format: 11 numeric values separated by commas. Example: 0,0,0,0,0,0,0,2,0,0,2 | keyword |
| stormshield.PvmFacts | Number of events sent by ASQ to the vulnerability management process. | long |
| stormshield.PvmOverflow | Number of events intended for the vulnerability management process that were ignored by ASQ. | long |
| stormshield.Rule.byte_count | The number of bytes that have passed through the designated rule | long |
| stormshield.Rule.category | Rule Category | keyword |
| stormshield.Rule.original | Original Rule Identifier | keyword |
| stormshield.Rule.rule_number | Original Rule Number | long |
| stormshield.SCTPAssoc | Number of SCTP associations. Digital format. Example: SCTPAssoc=2. Available from: SNS v3.9.0. | long |
| stormshield.SCTPAssocByte.in_count | Number of bytes that have passed through the firewall (incoming) | long |
| stormshield.SCTPAssocByte.out_count | Number of bytes that have passed through the firewall (outgoing) | long |
| stormshield.SCTPAssocPacket | Number of packets exchanged for an SCTP association. Digital format. Example: SCTPAssocPacket=128 Available from: SNS v3.9.0. | long |
| stormshield.SavedEvaluation | Number of rule evaluations that did not use intrusion prevention technology. | long |
| stormshield.TCPByte.in_count | Number of bytes that have passed through the firewall (incoming) | long |
| stormshield.TCPByte.out_count | Number of bytes that have passed through the firewall (outgoing) | long |
| stormshield.TCPConn | Number of TCP connections that have passed through the Firewall. | long |
| stormshield.TCPConnNatDst | Number of TCP connections with a translated destination. | long |
| stormshield.TCPConnNatSrc | Number of TCP connections with a translated source. | long |
| stormshield.TCPConnNoNatDst | Number of TCP connections with a translated destination. | long |
| stormshield.TCPConnNoNatSrc | Number of TCP connections with a translated source. | long |
| stormshield.TCPPacket | Number of TCP packets that have passed through the Firewall. | long |
| stormshield.TLSCertCacheEntriesNb | Number of entries currently in the TLS certificate cache. Digital format. Example: TLSCertCacheEntriesNb=3456 Available from: SNS v4.3.0 | long |
| stormshield.TLSCertCacheExpiredNb | Number of entries deleted from the TLS certificate cache after a TTL expired. Digital format. Example: TLSCertCacheExpiredNb=789 Available from: SNS v4.3.0 | long |
| stormshield.TLSCertCacheFlushOp | Number of "flush" operations (manual deletion of entries, or after reloading signatures) performed on the TLS certificate cache. Digital format. Example: TLSCertCacheFlushOp=7 Available from: SNS v4.3.0 | long |
| stormshield.TLSCertCacheFlushedNb | Number of entries deleted from the TLS certificate cache after a "flush operation. Digital format. Example: TLSCertCacheFlushedNb=123 Available from: SNS v4.3.0 | long |
| stormshield.TLSCertCacheInsert | Number of entries inserted in the TLS certificate cache. Digital format. Example: TLSCertCacheInsert=789 Available from: SNS v4.3.0 | long |
| stormshield.TLSCertCacheLookup.miss | Number of lookups missed in the TLS certificate cache. | long |
| stormshield.TLSCertCacheLookup.total | Number of total TLS certificate cache lookups | long |
| stormshield.TLSCertCachePurgeOp | Number of "purge" operations (automatic deletion of a percentage of entries when the cache reaches full capacity) performed on the TLS certificate cache. Digital format. Example: TLSCertCachePurgeOp=4 Available from: SNS v4.3.0 | long |
| stormshield.TLSCertCachePurgedNb | Number of entries deleted from the TLS certificate cache after a "purge operation. Digital format. Example: TLSCertCachePurgedNb=456 Available from: SNS v4.3.0 | long |
| stormshield.UDPByte.in_count | Number of bytes that have passed through the firewall (incoming) | long |
| stormshield.UDPByte.out_count | Number of bytes that have passed through the firewall (outgoing) | long |
| stormshield.UDPConn | Number of UDP connections that have passed through the Firewall. | long |
| stormshield.UDPConnNatDst | Number of UDP connections with a translated destination. | long |
| stormshield.UDPConnNatSrc | Number of UDP connections with a translated source. | long |
| stormshield.UDPConnNoNatDst | Number of UDP connections with a translated destination. | long |
| stormshield.UDPConnNoNatSrc | Number of UDP connections with a translated source. | long |
| stormshield.UDPPacket | Number of UDP packets that have passed through the Firewall. | long |
| stormshield.UI | Sofbus/Lacbus information unit  String of characters in UTF-8 format. Example: UI=Instruction Available from: SNS v4.3.0 | keyword |
| stormshield.action | Behavior associated with the filter rule. Value: "pass". | keyword |
| stormshield.address | IP address of the client workstation that initiated the connection. Decimal format.  Example: address=192.168.0.2 | keyword |
| stormshield.ads | Indicates whether the antispam has detected an e-mail as an advertisement. Values:  0 or1. | keyword |
| stormshield.agentid | SSO agent ID. Value: from 0 to 5. Example: agentid=0 Available from: SNS v3.0.0. | keyword |
| stormshield.alarmid | Stormshield Network alarm ID Decimal format. Example: "85" | keyword |
| stormshield.arg | Details of the detected vulnerability (version of service, operating system concerned, etc). String of characters in UTF-8 format. Example: Samba_3.6.3 | keyword |
| stormshield.auth | Not documented | keyword |
| stormshield.authcaptive | Not documented | keyword |
| stormshield.authconsole | Not documented | keyword |
| stormshield.authipsec | Not documented | keyword |
| stormshield.authsslvpn | Not documented | keyword |
| stormshield.authtotp | Not documented | keyword |
| stormshield.authwebadmin | Not documented | keyword |
| stormshield.cat_site | Category (URL filtering) of the website visited. String of characters in UTF-8 format.  Example: \{bank\}, \{news\}, etc. Available from: SNS v1.0.0. | keyword |
| stormshield.cipclassid | Value of the "Class ID" field in the CIP message. String of characters in UTF-8 format. Example: cipclassid=Connection_Manager_Object Available from: SNS v3.5.0 | keyword |
| stormshield.cipservicecode | Value of the "Service Code" field in the CIP message. String of characters in UTF-8 format. Example: cipservicecode=Get_Attribute_List Available from: SNS v3.5.0 | keyword |
| stormshield.class | Information about the alarms category. String of characters in UTF-8 format. Example: protocol, system, filter | keyword |
| stormshield.classification | Code number indicating alarm category. Example: "0" | keyword |
| stormshield.clientappid | Last client application detected on the connection. Character string. Example: clientappid=firefox Available from: SNS v3.2.0 | keyword |
| stormshield.cnruleid | Number of the SSL filter rule applied. Digital format. Example: cnruleid=3 Available from: SNS v3.2.0. | keyword |
| stormshield.confid | Index of the security inspection profile used. Value from 0 to 9. Available from: SNS v1.0.0. | keyword |
| stormshield.contentpolicy | Number of the SSL filter policy used. String of characters in UTF-8 format. Example: "3" Available from: SNS v1.0.0. | keyword |
| stormshield.cookie_i | Temporary identity marker of the initiator of the negotiation. Character string in hexadecimal. Example: 0xae34785945ae3cbf | keyword |
| stormshield.cookie_r | Temporary identity marker of the peer of the negotiation.  Character string in hexadecimal. Example: "0x56201508549a6526". | keyword |
| stormshield.detail | Additional information on the vulnerable software version.  String of characters in UTF-8 format. Example: PHP_5.2.3 | keyword |
| stormshield.device_stats.CPU.kernel_time | Time consumed by the kernel | long |
| stormshield.device_stats.CPU.system_disruption | Time allocated to system disruptions | long |
| stormshield.device_stats.CPU.user_time | Time allocated to the management of user processes | long |
| stormshield.device_stats.Ethernet.incoming_throughput | Incoming throughput (bits/second) | long |
| stormshield.device_stats.Ethernet.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | long |
| stormshield.device_stats.Ethernet.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | long |
| stormshield.device_stats.Ethernet.name | Name of the interface | keyword |
| stormshield.device_stats.Ethernet.original | Original name of this field | keyword |
| stormshield.device_stats.Ethernet.outgoing_throughput | Outgoing throughput (bits/second) | long |
| stormshield.device_stats.Ethernet.packets_accepted | Number of packets accepted | long |
| stormshield.device_stats.Ethernet.packets_blocked | Number of packets blocked | long |
| stormshield.device_stats.Qid.incoming_throughput | Incoming throughput (bits/second) | long |
| stormshield.device_stats.Qid.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | long |
| stormshield.device_stats.Qid.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | long |
| stormshield.device_stats.Qid.name | Name of the interface | keyword |
| stormshield.device_stats.Qid.original | Original name of this field | keyword |
| stormshield.device_stats.Qid.outgoing_throughput | Outgoing throughput (bits/second) | long |
| stormshield.device_stats.Qid.packets_accepted | Number of packets accepted | long |
| stormshield.device_stats.Qid.packets_blocked | Number of packets blocked | long |
| stormshield.device_stats.Vlan.incoming_throughput | Incoming throughput (bits/second) | long |
| stormshield.device_stats.Vlan.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | long |
| stormshield.device_stats.Vlan.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | long |
| stormshield.device_stats.Vlan.name | Name of the interface | keyword |
| stormshield.device_stats.Vlan.original | Original name of this field | keyword |
| stormshield.device_stats.Vlan.outgoing_throughput | Outgoing throughput (bits/second) | long |
| stormshield.device_stats.Vlan.packets_accepted | Number of packets accepted | long |
| stormshield.device_stats.Vlan.packets_blocked | Number of packets blocked | long |
| stormshield.device_stats.Wifi.incoming_throughput | Incoming throughput (bits/second) | long |
| stormshield.device_stats.Wifi.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | long |
| stormshield.device_stats.Wifi.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | long |
| stormshield.device_stats.Wifi.name | Name of the interface | keyword |
| stormshield.device_stats.Wifi.original | Original name of this field | keyword |
| stormshield.device_stats.Wifi.outgoing_throughput | Outgoing throughput (bits/second) | long |
| stormshield.device_stats.Wifi.packets_accepted | Number of packets accepted | long |
| stormshield.device_stats.Wifi.packets_blocked | Number of packets blocked | long |
| stormshield.device_stats.agg.incoming_throughput | Incoming throughput (bits/second) | long |
| stormshield.device_stats.agg.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | long |
| stormshield.device_stats.agg.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | long |
| stormshield.device_stats.agg.name | Name of the interface | keyword |
| stormshield.device_stats.agg.original | Original name of this field | keyword |
| stormshield.device_stats.agg.outgoing_throughput | Outgoing throughput (bits/second) | long |
| stormshield.device_stats.agg.packets_accepted | Number of packets accepted | long |
| stormshield.device_stats.agg.packets_blocked | Number of packets blocked | long |
| stormshield.device_stats.ipsec.incoming_throughput | Incoming throughput (bits/second) | long |
| stormshield.device_stats.ipsec.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | long |
| stormshield.device_stats.ipsec.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | long |
| stormshield.device_stats.ipsec.name | Name of the interface | keyword |
| stormshield.device_stats.ipsec.native | Indication that these statistics are from the native IPSec interface | boolean |
| stormshield.device_stats.ipsec.original | Original name of this field | keyword |
| stormshield.device_stats.ipsec.outgoing_throughput | Outgoing throughput (bits/second) | long |
| stormshield.device_stats.ipsec.packets_accepted | Number of packets accepted | long |
| stormshield.device_stats.ipsec.packets_blocked | Number of packets blocked | long |
| stormshield.device_stats.sslvpn.incoming_throughput | Incoming throughput (bits/second) | long |
| stormshield.device_stats.sslvpn.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | long |
| stormshield.device_stats.sslvpn.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | long |
| stormshield.device_stats.sslvpn.name | Name of the interface | keyword |
| stormshield.device_stats.sslvpn.original | Original name of this field | keyword |
| stormshield.device_stats.sslvpn.outgoing_throughput | Outgoing throughput (bits/second) | long |
| stormshield.device_stats.sslvpn.packets_accepted | Number of packets accepted | long |
| stormshield.device_stats.sslvpn.packets_blocked | Number of packets blocked | long |
| stormshield.discovery | Date on which the security watch team published the vulnerability (only if the level of severity is higher than 0) String in YYYY-MM-DD format. | keyword |
| stormshield.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain=documentation.stormshield.eu Available from: SNS v3.0.0 | keyword |
| stormshield.downrate | Indicates the percentage of time the gateway could not be reached over the last 15 minutes. String of characters in UTF-8 format. Example: downrate=0. Available from: SNS v4.3.0. | keyword |
| stormshield.dst | IP address of the destination host Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.dsthostrep | Reputation of the connection's target host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.dstif | Name of the destination interface. String of characters in UTF-8 format. Example: Ethernet 1 Available from: SNS v1.0.0. | keyword |
| stormshield.dstifname | Name of the object representing the traffics destination interface. String of characters in UTF-8 format. Example: dmz1 Available from: SNS v1.0.0. | keyword |
| stormshield.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.dstmac | MAC address of the destination host. Format: Hexadecimal values separated by ":". Example: dstmac=00:25:90:01:ce:e7 Available from: SNS v4.0.0. | keyword |
| stormshield.dstname | Name of the object corresponding to the VPN tunnels remote endpoint. String of characters in UTF-8 format.  Example: fw_remote Available from: SNS v1.0.0. | keyword |
| stormshield.dstport | Destination port number. Decimal format. Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: http Available from: SNS v1.0.0. | keyword |
| stormshield.duration | Duration of the connection in seconds. Decimal format.  Example: "173.15" | keyword |
| stormshield.error | Commands return code number Example: 0, 3 | keyword |
| stormshield.error_class | Number of the error class in an S7 response. Digital format. Available from: SNS v2.3.0 | keyword |
| stormshield.error_code | Error code in the error class specified in the S7 response. Available from: SNS v2.3.0 | keyword |
| stormshield.etherproto | Type of Ethernet protocol. Format: String of characters in UTF-8 format. Example: etherproto="profinet-rt" Available from: SNS v4.0.0. | keyword |
| stormshield.family | Name of the vulnerability family (Web Client, Web Server, Mail Client...).  String of characters in UTF-8 format. Example: SSH, Web Client . | keyword |
| stormshield.filename | Name of the file scanned by the sandboxing option.  String of characters in UTF-8 format. Example: "mydocument.doc" | keyword |
| stormshield.filetype | Type of file scanned by the sandboxing option. This may be a document (word processing, table, presentation, etc), a Portable Document Format file (PDF - Adobe Acrobat), and executable file or an archive. Value: "document", "pdf", "executable", "archive". | keyword |
| stormshield.format | Type of message for IEC104 Available from: SNS v3.1.0 | keyword |
| stormshield.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.group | Code of the "userdata" group for an S7 message. Available from: SNS v2.3.4 | keyword |
| stormshield.groupid | ID number allowing the tracking of child connections. Example: 0, 1, 2 etc. | keyword |
| stormshield.gw | Name of the monitored gateway. String of characters in UTF-8 format. Example: gw=gw123. Available from: SNS v4.3.0. | keyword |
| stormshield.hash | Results of the file content hash (SHA2 method) String of characters in UTF-8 format.Example: "f4d1be410a6102b9ae7d1c32612bed4f12158df3cd1ab6440a9ac0cad417446d" | keyword |
| stormshield.icmpcode | Code number of the icmp message. Example: 1 (meaning Destination host unreachable). Available from: SNS v1.0.0. | keyword |
| stormshield.icmptype | Number of the type of icmp message. Example: 3 (meaning Destination unreachable). Available from: SNS v1.0.0. | keyword |
| stormshield.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.ike | Version of the IKE protocol used Values: 1, 2 | keyword |
| stormshield.ipproto | Type of network protocol (entered only if a vulnerability has been detected). String of characters in UTF-8 format. Example: tcp Available from: SNS v1.0.0. | keyword |
| stormshield.ipv | Version of the IP protocol used in the traffic Values: 4, 6 Available from: SNS v1.0.0. | keyword |
| stormshield.jitter | Indicates the average, minimum and maximum jitter (variation in latency) over a regular interval, depending on the configuration (ms). String of characters in UTF-8 format. Example: jitter=5,0,20. Available from: SNS v4.3.0. | keyword |
| stormshield.latency | Indicates the average, minimum and maximum latency over a regular interval, depending on the configuration (ms). String of characters in UTF-8 format. Example: latency=70,50,100. Available from: SNS v4.3.0. | keyword |
| stormshield.localnet | Local network negotiated in phase2. Decimal format. Example: 192.168.0.1 | keyword |
| stormshield.logtype | The specific type of log this is from. | keyword |
| stormshield.lossrate | Indicates the average rate of packet loss (%) over the last 15 minutes. String of characters in UTF-8 format. Example: lossrate=10. Available from: SNS v4.3.0. | keyword |
| stormshield.mailruleid | Number of the mail filter rule applied. Digital format Example: mailruleid=48 Available from: SNS v3.2.0. | keyword |
| stormshield.mem | Not documented | keyword |
| stormshield.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges.  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.modsrcport | Translated TCP/UDP source port number. Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.msg | Text message explaining the alarm.  String of characters in UTF-8 format. Example: Port probe | keyword |
| stormshield.op | Operation on the POP3 server (RETR, LIST, ...) Example: USER | keyword |
| stormshield.origdst | Original IP address of the destination host (before translation or the application of a virtual connection).  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.phase | Number of the IPSec VPN tunnel negotiation phase. Values: 0 (no phase), 1 (phase 1) or 2 (phase 2). | keyword |
| stormshield.pktdump | Network packet captured and encoded in hexadecimal for deeper analysis by a third-party tool. Example: 450000321fd240008011c2f50a00007b0a3c033d0035c | keyword |
| stormshield.pktdumplen | Size of the packet captured for deeper analysis by a third-party tool. This value may differ from the value of the pktlen field. Example: "133" | keyword |
| stormshield.pktlen | Size of the network packet that activated the alarm (in bytes). Example: "133" | keyword |
| stormshield.port | Port number (entered only if a vulnerability has been detected). Example: "22" | keyword |
| stormshield.portname | Standard service corresponding to the port number (entered only if a vulnerability has been detected). String of characters in UTF-8 format. Example: ssh | keyword |
| stormshield.pri | Alarm level (configurable by the administrator in certain cases). Values: 1 (major) or  4 (minor). Available from: SNS v1.0.0. | keyword |
| stormshield.product | Product on which the vulnerability was detected. String of characters in UTF-8 format. Example: JRE_1.6.0_27 | keyword |
| stormshield.proto | Name of the associated plugin. If this is not available, the name of the standard service corresponding to the port (entered only if a vulnerability has been detected). String of characters in UTF-8 format. Example: ssh Available from: SNS v1.0.0. | keyword |
| stormshield.rcvd | Number of bytes received. Decimal format.  Example: "23631" Available from: SNS v1.0.0 | keyword |
| stormshield.remote | Indicates whether the vulnerability can be exploited remotely Values: 0 (false) or 1 (true). | keyword |
| stormshield.remoteid | ID of the peer used during the negotiation of the IKE SA. This may be an e-mail address or IP address. | keyword |
| stormshield.remotenet | Remote network negotiated in phase2. Decimal format. Example: 192.168.1.1 | keyword |
| stormshield.repeat | Number of occurrences of the alarm over a given period. Decimal format. Example: "4" Available from: SNS v1.0.0. | keyword |
| stormshield.requestmode | Value of the "Mode" field for an NTP request. String of characters in UTF-8 format. Example: requestmode=client. Available from: SNS v3.8.0 | keyword |
| stormshield.responsemode | Value of the "Mode" field for an NTP response. String of characters in UTF-8 format. Example: responsemode=server. Available from: SNS v3.8.0 | keyword |
| stormshield.result | Return code of the HTTP server. Example: 403, 404 | keyword |
| stormshield.risk | Risk relating to the connection. This value contributes to the reputation score of the connection's source host. Value: between 1 (low risk) and 100 (very high risk). Example: risk=20 Available from: SNS v3.0.0. | keyword |
| stormshield.router | Name of the monitored router. String of characters in UTF-8 format. Example: router=routerICMP. Available from: SNS v4.3.0. | keyword |
| stormshield.rt | Name of the gateway used for the connection. Present only if the gateway does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.rtname | Name of the router object used for the connection. Present only if the router does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.ruleid | Number of the filter rule applied. Example: 1, 2  Available from: SNS v1.0.0. | keyword |
| stormshield.rulename | Name of the filter rule applied Character string Example: rulename="myrule" Available from: SNS v3.2.0. | keyword |
| stormshield.ruletype | Type of IPSec rule. Character string.  Values: mobile, gateway. Example: ruletype=mobile. Available from: SNS v4.2.1 | keyword |
| stormshield.sandboxing | Classification of the file according to the sandboxing option.  Value: "clean", "suspicious", "malicious", "unknown", forward", "failed".  The sandboxing option indicates a "clean", "suspicious" or "malicious" status if the file has already been scanned and classified. The "unknown" status is returned if sandboxing does not know the file concerned. In this case, the whole file will be sent to the firewall to be scanned. | keyword |
| stormshield.sandboxinglevel | Indicates the level of the file's infection on a scale of 0 to 100. Value: "0" (clean) to "100" (malicious). | keyword |
| stormshield.security | Indicator of the Firewalls security status. This value is used by the fleet management tool (Stormshield Network Unified Manager) to provide information on the security status (minor, major alarms, etc). Decimal format representing a percentage. | keyword |
| stormshield.sent | Number of bytes sent. Decimal format.  Example: "14623" Available from: SNS v1.0.0 | keyword |
| stormshield.serverappid | Last server application detected on the connection. Character string. Example: serverappid=google Available from: SNS v3.2.0 | keyword |
| stormshield.service | Service (product with a dedicated port) on which the vulnerability was detected.  String of characters in UTF-8 format. Example: OpenSSH_5.4 | keyword |
| stormshield.sessionid | Session ID number allowing simultaneous connections to be differentiated. Example: "18" | keyword |
| stormshield.severity | Vulnerabilitys intrinsic level of severity.  Values: 0 (Information), 1 (Weak), 2 (Moderate), 3 (High) or 4 (Critical). | keyword |
| stormshield.side | Role of the Firewall in the negotiation of the tunnel. Values: initiator or responder. | keyword |
| stormshield.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.solution | Indicates whether a fix is available in order to correct the detected vulnerability. Values: 0 (not available) or 1 (available). | keyword |
| stormshield.spamlevel | Results of antispam processing on the message. Values: "X": error while processing the message. "?": the nature of the message could not be determined. "0": non-spam message. "1", "2" or "3": criticality of the spam message, 3 being the most critical. Available from: SNS v1.0.0. | keyword |
| stormshield.spi_in | SPI (Security Parameter Index) number of the negotiated incoming SA (Security Association). Character string in hexadecimal. Example: 0x01ae58af | keyword |
| stormshield.spi_out | SPI number of the negotiated outgoing SA. Character string in hexadecimal. Example: 0x003d098c | keyword |
| stormshield.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.srchostrep | Reputation of the connection's source host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.srcif | Internal name of the interface at the source of the traffic. String of characters in UTF-8 format. Example: Ethernet0 Available from: SNS v1.0.0. | keyword |
| stormshield.srcifname | Name of the object representing the interface at the source of the traffic. String of characters in UTF-8 format. Example: out Available from: SNS v1.0.0. | keyword |
| stormshield.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.srcmac | MAC address of the source host.  May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.srcname | Name of the object corresponding to the IP address of the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.srcport | Source TCP/UDP port number. Example: "49753" Available from: SNS v1.0.0. | keyword |
| stormshield.srcportname | Source port name if it is known. String of characters in UTF-8 format. Example: http, ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.system | Indicator of the Firewalls system status.  This value is used by the fleet management tool (Stormshield Network Unified Manager) to provide information on the system status (available RAM, CPU use, bandwidth, interfaces, fullness of audit logs, etc). Decimal format representing a percentage. | keyword |
| stormshield.target | Shows whether the src or dst fields correspond to the target of the packet that had raised the alarm. Values: "src" or "dst" Available from: SNS v3.0.0. | keyword |
| stormshield.targetclient | Indicates whether the exploitation of the vulnerability requires the use of a client on the vulnerable host. Values: 0 (false) or 1 (true). | keyword |
| stormshield.targetserver | Indicates whether the exploitation of the vulnerability requires the installation of a server on the vulnerable host. Values: 0 (false) or 1 (true). | keyword |
| stormshield.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.totp | Indicates whether authentication required a TOTP Values: "yes" if a TOTP was used, "no" if no TOTP was used. Example: totp=yes Available from: SNS v4.5.0. | keyword |
| stormshield.tsagentname | Indicates the name of the TS agent used. String of characters in UTF-8 format. Example: tsagentname="agent_name_test" Available from: SNS v4.7.0. | keyword |
| stormshield.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.unit_id | Value of the "Unit Id" in a Modbus message. Example: "255". Available from: SNS v2.3.0 | keyword |
| stormshield.unreachrate | Indicates the percentage of time the gateway could not be accessed over the last 15 minutes. String of characters in UTF-8 format. Example: unreachrate=0. Available from: SNS v4.3.0. | keyword |
| stormshield.uprate | Indicates the percentage of time the status of the gateway was active over the last 15 minutes. String of characters in UTF-8 format. Example: uprate=0. Available from: SNS v4.3.0. | keyword |
| stormshield.urlruleid | Number of the URL filter rule applied. Digital format. Example: urlruleid=12 Available from: SNS v3.2.0. | keyword |
| stormshield.user | ID of the administrator who executed the command. String of characters in UTF-8 format. Example:admin May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.usergroup | The user that set up a tunnel belongs this group, defined in the VPN access privileges. String of characters in UTF-8 format. Example: usergroup="ipsec-group" Available from: SNS v3.3.0. | keyword |
| stormshield.version | Value of the "Version number" field for the NTP protocol. Digital format. Example: version=4. Available from: SNS v3.8.0 | keyword |
| stormshield.virus | Message indicating whether a virus has been detected (the antivirus has to be enabled) Example: clean | keyword |
| stormshield.vulnid | Unique Stormshield Network ID of the detected vulnerability. Example: "132710" | keyword |
| stormshield.wldev0 | Concerns only firewalls equipped with Wi-Fi antennas (W models). Indicators of bandwidth used for each physical interface that supports the firewall's Wi-Fi access points:   name of the interface. String of characters in UTF-8 format. incoming throughput (bits/second), maximum incoming throughput for a given period (bits/second), outgoing throughput (bits/second), maximum outgoing throughput for a given period (bits/second), number of packets accepted, number of packets blocked,  Format: 7 values separated by commas.  Example: "Physic_WiFi,61515,128648,788241,1890520,2130,21" | keyword |
| tags | List of keywords used to tag each event. | keyword |

