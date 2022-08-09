# SonicWall Firewall Integration

This integration collects syslog messages from SonicWall firewalls. It has been tested with Enhanced
Syslog logs from SonicOS 6.5 and 7.0 as described in the [Log Events reference guide.](https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-4-log-events-reference-guide.pdf)

## Configuration

Configure a Syslog Server in your firewall using the following options:
 - **Name or IP Address:** The address where your Elastic Agent running this integration is reachable.
 - **Port:** The Syslog port (UDP) configured in this integration.
 - **Server Type:** Syslog Server.
 - **Syslog Format:** Enhanced Syslog.
 - **Syslog ID:** Change this default (`firewall`) if you need to differentiate between multiple firewalls.
                  This value will be stored in the `observer.name` field. 

It's recommended to enable the **Display UTC in logs (instead of local time)** setting under the
_Device > Settings > Time_ configuration menu. Otherwise you'll have to configure the **Timezone Offset**
setting of this integration to match the timezone configured in your firewall.

Ensure proper connectivity between your firewall and Elastic Agent.

## Supported messages

This integration features generic support for enhanced syslog messages produced by SonicOS and features
more detailed ECS enrichment for the following messages:

| Category | Subcategory | Message IDs |
|----------|-------------|-------------|
| Firewall | Access Rules | 440-442, 646, 647, 734, 735 |
| Firewall | Application Firewall | 793, 1654 |
| Firewall Settings | Advanced | 428, 1473, 1573, 1576, 1590 |
| Firewall Settings | Checksum Enforcement | 883-886, 1448, 1449 |
| Firewall Settings | FTP | 446, 527, 528, 538 |
| Firewall Settings | Flood Protection | 25, 856-860, 862-864, 897, 898, 901, 904, 905, 1180, 1213, 1214, 1366, 1369, 1450-1452 |
| Firewall Settings | Multicast | 683, 690, 694, 1233 |
| Firewall Settings | SSL Control | 999, 1001-1006, 1081 |
| High Availability | Cluster | 1149, 1152 |
| Log | Configuration Auditing | 1382, 1383, 1674 |
| Network | ARP | 45, 815, 1316 |
| Network | DNS | 1098, 1099 |
| Network | DNS Security | 1593 |
| Network | ICMP | 38, 63, 175, 182, 188, 523, 597, 598, 1254-1257, 1431, 1433, 1458 |
| Network | IP | 28, 522, 910, 1301-1303, 1429, 1430 |
| Network | IPcomp | 651-653 |
| Network | IPv6 Tunneling | 1253 |
| Network | Interfaces | 58 |
| Network | NAT | 339, 1197, 1436 |
| Network | NAT Policy | 1313-1315 |
| Network | Network Access | 41, 46, 98, 347, 524, 537, 590, 714, 1304 |
| Network | TCP | 36, 48, 173, 181, 580, 708, 709, 712, 713, 760, 887-896, 1029-1031, 1384, 1385, 1628, 1629 |
| Security Services | Anti-Spyware | 794-796 |
| Security Services | Anti-Virus | 123-125, 159, 408, 482 |
| Security Services | Application Control | 1154, 1155 |
| Security Services | Attacks | 22, 23, 27, 81-83, 177-179, 267, 606, 1373-1376, 1387, 1471 |
| Security Services | Botnet Filter | 1195, 1200, 1201, 1476, 1477, 1518, 1519 |
| Security Services | Content Filter | 14, 16, 1599-1601 |
| Security Services | Geo-IP Filter | 1198, 1199, 1474, 1475 |
| Security Services | IDP | 789, 790 |
| Security Services | IPS | 608, 609 |
| Security Services | Next-Gen Anti-Virus | 1559-1562 |
| Security Services | RBL Filter | 797, 798 |
| System | Administration | 340, 341 |
| System | Cloud Backup | 1511-1516 |
| System | Restart | 93-95, 164, 599-601, 1046, 1047, 1392, 1393 |
| System | Settings | 573, 574, 1049, 1065, 1066, 1160, 1161, 1268, 1269, 1336-1340, 1432, 1494, 1520, 1521, 1565-1568, 1636, 1637 |
| System | Status | 4, 53, 521, 1107, 1196, 1332, 1495, 1496 |
| Users | Authentication Access | 24, 29-35, 199, 200, 235-238, 246, 261-265, 328, 329, 438, 439, 486, 506-509, 520, 549-551, 557-562, 564, 583, 728, 729, 759, 986, 987, 994-998, 1008, 1035, 1048, 1080, 1117-1124, 1157, 1158, 1243, 1333-1335, 1341, 1342, 1517, 1570-1572, 1585, 1627, 1655, 1672 |
| Users | Radius Authentication | 243-245, 744-751, 753-757, 1011 |
| Users | SSO Agent Authentication | 988-991 |
| VPN | DHCP Relay | 229 |
| Wireless | RF Monitoring | 879 |
| Wireless | WLAN | 1363 |
| Wireless | WLAN IDS | 546, 548 |

## Logs

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-05-16T08:18:39.000+02:00",
    "agent": {
        "ephemeral_id": "6cc3228b-d89c-4104-b750-d9cb44ed5513",
        "id": "08a5caf6-a717-4f5f-90e2-0f4eb7c59b00",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "sonicwall_firewall.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.193",
        "mac": "00-17-C5-30-F9-D9",
        "port": 64889
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "08a5caf6-a717-4f5f-90e2-0f4eb7c59b00",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "action": "connection-denied",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "code": "713",
        "dataset": "sonicwall_firewall.log",
        "ingested": "2022-05-23T13:47:58Z",
        "kind": "event",
        "outcome": "success",
        "sequence": "692",
        "severity": "7",
        "timezone": "+02:00",
        "type": [
            "connection",
            "denied"
        ]
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "level": "debug",
        "source": {
            "address": "172.24.0.4:47831"
        }
    },
    "message": "� (TCP Flag(s): RST)",
    "network": {
        "bytes": 46,
        "protocol": "https",
        "transport": "tcp"
    },
    "observer": {
        "egress": {
            "interface": {
                "name": "X1"
            },
            "zone": "Untrusted"
        },
        "ingress": {
            "interface": {
                "name": "X1"
            },
            "zone": "Untrusted"
        },
        "ip": "10.0.0.96",
        "name": "firewall",
        "product": "SonicOS",
        "serial_number": "0040103CE114",
        "type": "firewall",
        "vendor": "SonicWall"
    },
    "related": {
        "ip": [
            "10.0.0.96",
            "81.2.69.193"
        ],
        "user": [
            "admin"
        ]
    },
    "rule": {
        "id": "15 (WAN-\u003eWAN)"
    },
    "sonicwall": {
        "firewall": {
            "app": "12",
            "event_group_category": "Firewall Settings",
            "gcat": "6",
            "sess": "Web"
        }
    },
    "source": {
        "bytes": 46,
        "ip": "10.0.0.96",
        "mac": "00-06-B1-DD-4F-D4",
        "port": 443
    },
    "tags": [
        "sonicwall-firewall",
        "forwarded"
    ],
    "user": {
        "name": "admin"
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
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.egress.zone | Network zone of outbound traffic as reported by the observer to categorize the destination area of egress traffic, e.g. Internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.zone | Network zone of incoming traffic as reported by the observer to categorize the source area of ingress traffic. e.g. internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| sonicwall.firewall.Category | Category of CFS blocked content. | keyword |
| sonicwall.firewall.af_polid | Displays the Application Filter Policy ID. | keyword |
| sonicwall.firewall.app | Numeric application ID. | keyword |
| sonicwall.firewall.appName | Non-Signature Application Name. | keyword |
| sonicwall.firewall.appcat | Application control category. | keyword |
| sonicwall.firewall.appid | Application ID. | keyword |
| sonicwall.firewall.auditId |  | keyword |
| sonicwall.firewall.code | CFS blocking code. | keyword |
| sonicwall.firewall.dpi | Indicates wether a flow underwent Deep Packet Inspection. | boolean |
| sonicwall.firewall.event_group_category | Event group category. | keyword |
| sonicwall.firewall.gcat | Event group category (numeric identifier). | keyword |
| sonicwall.firewall.ipscat | IPS category. | keyword |
| sonicwall.firewall.ipspri | IPS priority. | keyword |
| sonicwall.firewall.oldValue |  | keyword |
| sonicwall.firewall.sess | User session type. | keyword |
| sonicwall.firewall.sid | IPS or Anti-Spyware signature ID. | keyword |
| sonicwall.firewall.tranxId |  | keyword |
| sonicwall.firewall.type | ICMP type. | keyword |
| sonicwall.firewall.userMode |  | keyword |
| sonicwall.firewall.uuid | Object UUID. | keyword |
| sonicwall.firewall.vpnpolicy | source VPN policy name. | keyword |
| sonicwall.firewall.vpnpolicyDst | destination VPN policy name. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

