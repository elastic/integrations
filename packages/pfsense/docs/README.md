# Iptables Integration

This is an integration for `iptables` and `ip6tables` logs. It parses logs
received over the network via syslog (UDP) or from a file. Also, it understands
the prefix added by some Ubiquiti firewalls, which includes the rule set name,
rule number, and the action performed on the traffic (allow/deny).

The module is by default configured to run with the `udp` input on port `9001`.
However, it can also be configured to read from a file path.

## Logs

### Iptables log

This is the Iptables `log` dataset.

An example event for `log` looks as following:

```json
{
    "offset": "0",
    "log": {
        "syslog": {
            "priority": 134
        }
    },
    "ip": {
        "flags": "DF"
    },
    "destination": {
        "geo": {
            "continent_name": "Oceania",
            "country_name": "Australia",
            "location": {
                "lon": 143.2104,
                "lat": -33.494
            },
            "country_iso_code": "AU"
        },
        "as": {
            "number": 13335,
            "organization": {
                "name": "Cloudflare, Inc."
            }
        },
        "address": "1.1.1.1",
        "port": 853,
        "ip": "1.1.1.1"
    },
    "rule": {
        "id": "1535324496"
    },
    "source": {
        "port": 49724,
        "address": "10.170.12.50",
        "ip": "10.170.12.50"
    },
    "transport": {
        "data_length": "0"
    },
    "message": "146,,,1535324496,igb1.12,match,block,in,4,0x0,,63,12617,0,DF,6,tcp,60,10.170.12.50,1.1.1.1,49724,853,0,S,1891286705,,64240,,mss;sackOK;TS;nop;wscale",
    "packet": {
        "id": "12617"
    },
    "ttl": "63",
    "tcp_options": "mss;sackOK;TS;nop;wscale",
    "network": {
        "community_id": "1:sHss/MZhCpIXxOfJoM05khzrJ4k=",
        "transport": "tcp",
        "type": "ipv4",
        "bytes": 60,
        "iana_number": "6",
        "direction": "in"
    },
    "tags": [
        "preserve_original_event"
    ],
    "window_size": 64240,
    "observer": {
        "ingress": {
            "vlan": {
                "id": "12"
            },
            "interface": {
                "name": "igb1.12"
            }
        }
    },
    "@timestamp": "2021-07-03T19:10:30.000Z",
    "ecs": {
        "version": "1.10.0"
    },
    "related": {
        "ip": [
            "10.170.12.50",
            "1.1.1.1"
        ]
    },
    "tcp_flags": "S",
    "tos": "0x0",
    "event": {
        "reason": "match",
        "ingested": "2021-07-04T02:30:40.666947269Z",
        "original": "\u003c134\u003eJul  3 19:10:30 filterlog[72237]: 146,,,1535324496,igb1.12,match,block,in,4,0x0,,63,12617,0,DF,6,tcp,60,10.170.12.50,1.1.1.1,49724,853,0,S,1891286705,,64240,,mss;sackOK;TS;nop;wscale",
        "provider": "filterlog",
        "kind": "event",
        "action": "block",
        "id": "72237",
        "category": [
            "network"
        ],
        "type": [
            "connection",
            "denied"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.address | address of the client (IP or Hostname). | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.mac | MAC address of the client. | keyword |
| client.port | Port of the client. | long |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | address of the destination (IP or Hostname). | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version | keyword |
| event.created |  | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested |  | date |
| event.module | Event module | constant_keyword |
| event.outcome |  | keyword |
| event.provider |  | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| hostname | Hostname from syslog header. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. | keyword |
| log.offset | Log offset | long |
| log.original | This is the original log message and contains the full log message before splitting it up in multiple parts. | keyword |
| log.source.address | Source address of the syslog message. | keyword |
| log.syslog.priority | Syslog priority of the event. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| network.bytes | Total bytes transferred in both directions. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. | keyword |
| network.direction | Direction of the network traffic. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.iana_number | IANA Protocol Number | keyword |
| network.packets | Total packets transferred in both directions. | long |
| network.protocol | L7 Network protocol name. ex. http, lumberjack, transport protocol. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.vlan.id | VLAN ID as reported by the observer. | keyword |
| observer.name | Custom name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from | constant_keyword |
| observer.vendor | Vendor name of the observer | constant_keyword |
| pfsense.dhcp.hostname | Hostname of DHCP client | keyword |
| pfsense.icmp.code | ICMP code. | long |
| pfsense.icmp.destination.ip | Original destination address of the connection that caused this notification | ip |
| pfsense.icmp.id | ID of the echo request/reply | long |
| pfsense.icmp.mtu | MTU to use for subsequent data to this destination | long |
| pfsense.icmp.otime | Originate Timestamp | date |
| pfsense.icmp.parameter | ICMP parameter. | long |
| pfsense.icmp.redirect | ICMP redirect address. | ip |
| pfsense.icmp.rtime | Receive Timestamp | date |
| pfsense.icmp.seq | ICMP sequence number. | long |
| pfsense.icmp.ttime | Transmit Timestamp | date |
| pfsense.icmp.type | ICMP type. | keyword |
| pfsense.icmp.unreachable.iana_number | Protocol ID number that was unreachable | long |
| pfsense.icmp.unreachable.other | Other unreachable information | keyword |
| pfsense.icmp.unreachable.port | Port number that was unreachable | long |
| pfsense.ip.ecn | Explicit Congestion Notification. | keyword |
| pfsense.ip.flags | IP flags. | keyword |
| pfsense.ip.flow_label | Flow label | keyword |
| pfsense.ip.id | ID of the packet | long |
| pfsense.ip.offset | Fragment offset | long |
| pfsense.ip.tos | IP Type of Service identification. | keyword |
| pfsense.ip.ttl | Time To Live (TTL) of the packet | long |
| pfsense.openvpn.peer_info | Information about the Open VPN client | keyword |
| pfsense.tcp.ack | TCP Acknowledgment number. | long |
| pfsense.tcp.flags | TCP flags. | keyword |
| pfsense.tcp.length | Length of the TCP header and payload. | long |
| pfsense.tcp.options | TCP Options. | array |
| pfsense.tcp.seq | TCP sequence number. | long |
| pfsense.tcp.urg | Urgent pointer data. | keyword |
| pfsense.tcp.window | Advertised TCP window size. | long |
| pfsense.udp.length | Length of the UDP header and payload. | long |
| process.program | Process from syslog header. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| server.address | address of the server (IP or Hostname). | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| source.address | address of the source (IP or Hostname). | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. | keyword |
| source.nat.ip | NAT'd IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |

