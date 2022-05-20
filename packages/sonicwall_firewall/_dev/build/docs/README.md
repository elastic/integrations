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

{{event "log"}}

{{fields "log"}}
