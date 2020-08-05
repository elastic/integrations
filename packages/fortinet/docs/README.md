# Fortinet Integration

This integration is for Fortinet FortiOS logs sent in the syslog format. It includes the following datasets for receiving logs:

- `firewall` dataset: consists of Fortinet FortiGate logs.

## Compatibility

This integration has been tested against FortiOS version 6.0.x and 6.2.x. Versions above this are expected to work but have not been tested.

## Logs

### Firewall

Contains log entries from Fortinet FortiGate applicances.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| container.id | Unique container id. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Destination network address. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination. | ip |
| destination.nat.ip | Destination NAT ip | ip |
| destination.nat.port | Destination NAT Port | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| destination.user.email | User email address. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| dns.id | DNS packet identifier. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in answers.data | ip |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | text |
| event.category | Event category. The second categorization field in the hierarchy. | keyword |
| event.code | Identification code for this event. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.duration | Duration of the event in nanoseconds. | long |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.message | Log message optimized for viewing in a log viewer. | text |
| event.module | Name of the module this data is coming from. | keyword |
| event.outcome | The outcome of the event. | keyword |
| event.reference | Event reference URL | keyword |
| event.start | Contains the date when the event started. | date |
| event.timezone | Event time zone. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| file.extension | File extension. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.size | File size in bytes. | long |
| fortinet.file.hash.crc32 | CRC32 Hash of file | keyword |
| fortinet.firewall.acct_stat | Accounting state (RADIUS) | keyword |
| fortinet.firewall.acktime | Alarm Acknowledge Time | keyword |
| fortinet.firewall.act | Action | keyword |
| fortinet.firewall.action | Status of the session | keyword |
| fortinet.firewall.activity | HA activity message | keyword |
| fortinet.firewall.addr | IP Address | ip |
| fortinet.firewall.addr_type | Address Type | keyword |
| fortinet.firewall.addrgrp | Address Group | keyword |
| fortinet.firewall.adgroup | AD Group Name | keyword |
| fortinet.firewall.admin | Admin User | keyword |
| fortinet.firewall.age | Time in seconds - time passed since last seen | integer |
| fortinet.firewall.agent | User agent - eg. agent="Mozilla/5.0" | keyword |
| fortinet.firewall.alarmid | Alarm ID | integer |
| fortinet.firewall.alert | Alert | keyword |
| fortinet.firewall.analyticscksum | The checksum of the file submitted for analytics | keyword |
| fortinet.firewall.analyticssubmit | The flag for analytics submission | keyword |
| fortinet.firewall.ap | Access Point | keyword |
| fortinet.firewall.app-type | Address Type | keyword |
| fortinet.firewall.appact | The security action from app control | keyword |
| fortinet.firewall.appid | Application ID | integer |
| fortinet.firewall.applist | Application Control profile | keyword |
| fortinet.firewall.apprisk | Application Risk Level | keyword |
| fortinet.firewall.apscan | The name of the AP, which scanned and detected the rogue AP | keyword |
| fortinet.firewall.apsn | Access Point | keyword |
| fortinet.firewall.apstatus | Access Point status | keyword |
| fortinet.firewall.aptype | Access Point type | keyword |
| fortinet.firewall.assigned | Assigned IP Address | ip |
| fortinet.firewall.assignip | Assigned IP Address | ip |
| fortinet.firewall.attachment | The flag for email attachement | keyword |
| fortinet.firewall.attack | Attack Name | keyword |
| fortinet.firewall.attackcontext | The trigger patterns and the packetdata with base64 encoding | keyword |
| fortinet.firewall.attackcontextid | Attack context id / total | keyword |
| fortinet.firewall.attackid | Attack ID | integer |
| fortinet.firewall.auditid | Audit ID | long |
| fortinet.firewall.auditscore | The Audit Score | keyword |
| fortinet.firewall.audittime | The time of the audit | long |
| fortinet.firewall.authgrp | Authorization Group | keyword |
| fortinet.firewall.authid | Authentication ID | keyword |
| fortinet.firewall.authproto | The protocol that initiated the authentication | keyword |
| fortinet.firewall.authserver | Authentication server | keyword |
| fortinet.firewall.bandwidth | Bandwidth | keyword |
| fortinet.firewall.banned_rule | NAC quarantine Banned Rule Name | keyword |
| fortinet.firewall.banned_src | NAC quarantine Banned Source IP | keyword |
| fortinet.firewall.banword | Banned word | keyword |
| fortinet.firewall.botnetdomain | Botnet Domain Name | keyword |
| fortinet.firewall.botnetip | Botnet IP Address | ip |
| fortinet.firewall.bssid | Service Set ID | keyword |
| fortinet.firewall.call_id | Caller ID | keyword |
| fortinet.firewall.carrier_ep | The FortiOS Carrier end-point identification | keyword |
| fortinet.firewall.cat | DNS category ID | integer |
| fortinet.firewall.category | Authentication category | keyword |
| fortinet.firewall.cc | CC Email Address | keyword |
| fortinet.firewall.cdrcontent | Cdrcontent | keyword |
| fortinet.firewall.centralnatid | Central NAT ID | integer |
| fortinet.firewall.cert | Certificate | keyword |
| fortinet.firewall.cert-type | Certificate type | keyword |
| fortinet.firewall.certhash | Certificate hash | keyword |
| fortinet.firewall.cfgattr | Configuration attribute | keyword |
| fortinet.firewall.cfgobj | Configuration object | keyword |
| fortinet.firewall.cfgpath | Configuration path | keyword |
| fortinet.firewall.cfgtid | Configuration transaction ID | keyword |
| fortinet.firewall.cfgtxpower | Configuration TX power | integer |
| fortinet.firewall.channel | Wireless Channel | integer |
| fortinet.firewall.channeltype | SSH channel type | keyword |
| fortinet.firewall.chassisid | Chassis ID | integer |
| fortinet.firewall.checksum | The checksum of the scanned file | keyword |
| fortinet.firewall.chgheaders | HTTP Headers | keyword |
| fortinet.firewall.cldobjid | Connector object ID | keyword |
| fortinet.firewall.client_addr | Wifi client address | keyword |
| fortinet.firewall.cloudaction | Cloud Action | keyword |
| fortinet.firewall.clouduser | Cloud User | keyword |
| fortinet.firewall.column | VOIP Column | integer |
| fortinet.firewall.command | CLI Command | keyword |
| fortinet.firewall.community | SNMP Community | keyword |
| fortinet.firewall.configcountry | Configuration country | keyword |
| fortinet.firewall.connection_type | FortiClient Connection Type | keyword |
| fortinet.firewall.conserve | Flag for conserve mode | keyword |
| fortinet.firewall.constraint | WAF http protocol restrictions | keyword |
| fortinet.firewall.contentdisarmed | Email scanned content | keyword |
| fortinet.firewall.contenttype | Content Type from HTTP header | keyword |
| fortinet.firewall.cookies | VPN Cookie | keyword |
| fortinet.firewall.count | Counts of action type | integer |
| fortinet.firewall.countapp | Number of App Ctrl logs associated with the session | integer |
| fortinet.firewall.countav | Number of AV logs associated with the session | integer |
| fortinet.firewall.countcifs | Number of CIFS logs associated with the session | integer |
| fortinet.firewall.countdlp | Number of DLP logs associated with the session | integer |
| fortinet.firewall.countdns | Number of DNS logs associated with the session | integer |
| fortinet.firewall.countemail | Number of email logs associated with the session | integer |
| fortinet.firewall.countff | Number of ff logs associated with the session | integer |
| fortinet.firewall.countips | Number of IPS logs associated with the session | integer |
| fortinet.firewall.countssh | Number of SSH logs associated with the session | integer |
| fortinet.firewall.countssl | Number of SSL logs associated with the session | integer |
| fortinet.firewall.countwaf | Number of WAF logs associated with the session | integer |
| fortinet.firewall.countweb | Number of Web filter logs associated with the session | integer |
| fortinet.firewall.cpu | CPU Usage | integer |
| fortinet.firewall.craction | Client Reputation Action | integer |
| fortinet.firewall.criticalcount | Number of critical ratings | integer |
| fortinet.firewall.crl | Client Reputation Level | keyword |
| fortinet.firewall.crlevel | Client Reputation Level | keyword |
| fortinet.firewall.crscore | Some description | integer |
| fortinet.firewall.cveid | CVE ID | keyword |
| fortinet.firewall.daemon | Daemon name | keyword |
| fortinet.firewall.datarange | Data range for reports | keyword |
| fortinet.firewall.date | Date | keyword |
| fortinet.firewall.ddnsserver | DDNS server | ip |
| fortinet.firewall.desc | Description | keyword |
| fortinet.firewall.detectionmethod | Detection method | keyword |
| fortinet.firewall.devcategory | Device category | keyword |
| fortinet.firewall.devintfname | HA device Interface Name | keyword |
| fortinet.firewall.devtype | Device type | keyword |
| fortinet.firewall.dhcp_msg | DHCP Message | keyword |
| fortinet.firewall.dintf | Destination interface | keyword |
| fortinet.firewall.disk | Assosciated disk | keyword |
| fortinet.firewall.disklograte | Disk logging rate | long |
| fortinet.firewall.dlpextra | DLP extra information | keyword |
| fortinet.firewall.docsource | DLP fingerprint document source | keyword |
| fortinet.firewall.domainctrlauthstate | CIFS domain auth state | integer |
| fortinet.firewall.domainctrlauthtype | CIFS domain auth type | integer |
| fortinet.firewall.domainctrldomain | CIFS domain auth domain | keyword |
| fortinet.firewall.domainctrlip | CIFS Domain IP | ip |
| fortinet.firewall.domainctrlname | CIFS Domain name | keyword |
| fortinet.firewall.domainctrlprotocoltype | CIFS Domain connection protocol | integer |
| fortinet.firewall.domainctrlusername | CIFS Domain username | keyword |
| fortinet.firewall.domainfilteridx | Domain filter ID | integer |
| fortinet.firewall.domainfilterlist | Domain filter name | keyword |
| fortinet.firewall.ds | Direction with distribution system | keyword |
| fortinet.firewall.dst_int | Destination interface | keyword |
| fortinet.firewall.dstcountry | Destination country | keyword |
| fortinet.firewall.dstdevcategory | Destination device category | keyword |
| fortinet.firewall.dstdevtype | Destination device type | keyword |
| fortinet.firewall.dstfamily | Destination OS family | keyword |
| fortinet.firewall.dsthwvendor | Destination HW vendor | keyword |
| fortinet.firewall.dsthwversion | Destination HW version | keyword |
| fortinet.firewall.dstinetsvc | Destination interface service | keyword |
| fortinet.firewall.dstintfrole | Destination interface role | keyword |
| fortinet.firewall.dstosname | Destination OS name | keyword |
| fortinet.firewall.dstosversion | Destination OS version | keyword |
| fortinet.firewall.dstserver | Destination server | integer |
| fortinet.firewall.dstssid | Destination SSID | keyword |
| fortinet.firewall.dstswversion | Destination software version | keyword |
| fortinet.firewall.dstunauthusersource | Destination unauthenticated source | keyword |
| fortinet.firewall.dstuuid | UUID of the Destination IP address | keyword |
| fortinet.firewall.duid | DHCP UID | keyword |
| fortinet.firewall.eapolcnt | EAPOL packet count | integer |
| fortinet.firewall.eapoltype | EAPOL packet type | keyword |
| fortinet.firewall.encrypt | Whether the packet is encrypted or not | integer |
| fortinet.firewall.encryption | Encryption method | keyword |
| fortinet.firewall.epoch | Epoch used for locating file | integer |
| fortinet.firewall.espauth | ESP Authentication | keyword |
| fortinet.firewall.esptransform | ESP Transform | keyword |
| fortinet.firewall.exch | Mail Exchanges from DNS response answer section | keyword |
| fortinet.firewall.exchange | Mail Exchanges from DNS response answer section | keyword |
| fortinet.firewall.expectedsignature | Expected SSL signature | keyword |
| fortinet.firewall.expiry | FortiGuard override expiry timestamp | keyword |
| fortinet.firewall.fams_pause | Fortinet Analysis and Management Service Pause | integer |
| fortinet.firewall.fazlograte | FortiAnalyzer Logging Rate | long |
| fortinet.firewall.fctemssn | FortiClient Endpoint SSN | keyword |
| fortinet.firewall.fctuid | FortiClient UID | keyword |
| fortinet.firewall.field | NTP status field | keyword |
| fortinet.firewall.filefilter | The filter used to identify the affected file | keyword |
| fortinet.firewall.filehashsrc | Filehash source | keyword |
| fortinet.firewall.filtercat | DLP filter category | keyword |
| fortinet.firewall.filteridx | DLP filter ID | integer |
| fortinet.firewall.filtername | DLP rule name | keyword |
| fortinet.firewall.filtertype | DLP filter type | keyword |
| fortinet.firewall.fortiguardresp | Antispam ESP value | keyword |
| fortinet.firewall.forwardedfor | Email address forwarded | keyword |
| fortinet.firewall.fqdn | FQDN | keyword |
| fortinet.firewall.frametype | Wireless frametype | keyword |
| fortinet.firewall.freediskstorage | Free disk integer | integer |
| fortinet.firewall.from | From email address | keyword |
| fortinet.firewall.from_vcluster | Source virtual cluster number | integer |
| fortinet.firewall.fsaverdict | FSA verdict | keyword |
| fortinet.firewall.fwserver_name | Web proxy server name | keyword |
| fortinet.firewall.gateway | Gateway ip address for PPPoE status report | ip |
| fortinet.firewall.green | Memory status | keyword |
| fortinet.firewall.groupid | User Group ID | integer |
| fortinet.firewall.ha-prio | HA Priority | integer |
| fortinet.firewall.ha_group | HA Group | keyword |
| fortinet.firewall.ha_role | HA Role | keyword |
| fortinet.firewall.handshake | SSL Handshake | keyword |
| fortinet.firewall.hash | Hash value of downloaded file | keyword |
| fortinet.firewall.hbdn_reason | Heartbeat down reason | keyword |
| fortinet.firewall.highcount | Highcount fabric summary | integer |
| fortinet.firewall.host | Hostname | keyword |
| fortinet.firewall.iaid | DHCPv6 id | keyword |
| fortinet.firewall.icmpcode | Destination Port of the ICMP message | keyword |
| fortinet.firewall.icmpid | Source port of the ICMP message | keyword |
| fortinet.firewall.icmptype | The type of ICMP message | keyword |
| fortinet.firewall.identifier | Network traffic identifier | integer |
| fortinet.firewall.in_spi | IPSEC inbound SPI | keyword |
| fortinet.firewall.incidentserialno | Incident serial number | integer |
| fortinet.firewall.infected | Infected MMS | integer |
| fortinet.firewall.infectedfilelevel | DLP infected file level | integer |
| fortinet.firewall.informationsource | Information source | keyword |
| fortinet.firewall.init | IPSEC init stage | keyword |
| fortinet.firewall.initiator | Original login user name for Fortiguard override | keyword |
| fortinet.firewall.interface | Related interface | keyword |
| fortinet.firewall.intf | Related interface | keyword |
| fortinet.firewall.invalidmac | The MAC address with invalid OUI | keyword |
| fortinet.firewall.ip | Related IP | ip |
| fortinet.firewall.iptype | Related IP type | keyword |
| fortinet.firewall.keyword | Keyword used for search | keyword |
| fortinet.firewall.kind | VOIP kind | keyword |
| fortinet.firewall.lanin | LAN incoming traffic in bytes | long |
| fortinet.firewall.lanout | LAN outbound traffic in bytes | long |
| fortinet.firewall.lease | DHCP lease | integer |
| fortinet.firewall.license_limit | Maximum Number of FortiClients for the License | keyword |
| fortinet.firewall.limit | Virtual Domain Resource Limit | integer |
| fortinet.firewall.line | VOIP line | keyword |
| fortinet.firewall.live | Time in seconds | integer |
| fortinet.firewall.local | Local IP for a PPPD Connection | ip |
| fortinet.firewall.log | Log message | keyword |
| fortinet.firewall.login | SSH login | keyword |
| fortinet.firewall.lowcount | Fabric lowcount | integer |
| fortinet.firewall.mac | DHCP mac address | keyword |
| fortinet.firewall.malform_data | VOIP malformed data | integer |
| fortinet.firewall.malform_desc | VOIP malformed data description | keyword |
| fortinet.firewall.manuf | Manufacturer name | keyword |
| fortinet.firewall.masterdstmac | Master mac address for a host with multiple network interfaces | keyword |
| fortinet.firewall.mastersrcmac | The master MAC address for a host that has multiple network interfaces | keyword |
| fortinet.firewall.mediumcount | Fabric medium count | integer |
| fortinet.firewall.mem | Memory usage system statistics | keyword |
| fortinet.firewall.meshmode | Wireless mesh mode | keyword |
| fortinet.firewall.message_type | VOIP message type | keyword |
| fortinet.firewall.method | HTTP method | keyword |
| fortinet.firewall.mgmtcnt | The number of unauthorized client flooding managemet frames | integer |
| fortinet.firewall.mode | IPSEC mode | keyword |
| fortinet.firewall.module | PCI-DSS module | keyword |
| fortinet.firewall.monitor-name | Health Monitor Name | keyword |
| fortinet.firewall.monitor-type | Health Monitor Type | keyword |
| fortinet.firewall.mpsk | Wireless MPSK | keyword |
| fortinet.firewall.msgproto | Message Protocol Number | keyword |
| fortinet.firewall.mtu | Max Transmission Unit Value | integer |
| fortinet.firewall.name | Name | keyword |
| fortinet.firewall.nat | NAT IP Address | keyword |
| fortinet.firewall.netid | Connector NetID | keyword |
| fortinet.firewall.new_status | New status on user change | keyword |
| fortinet.firewall.new_value | New Virtual Domain Name | keyword |
| fortinet.firewall.newchannel | New Channel Number | integer |
| fortinet.firewall.newchassisid | New Chassis ID | integer |
| fortinet.firewall.newslot | New Slot Number | integer |
| fortinet.firewall.nextstat | Time interval in seconds for the next statistics. | integer |
| fortinet.firewall.nf_type | Notification Type | keyword |
| fortinet.firewall.noise | Wifi Noise | integer |
| fortinet.firewall.old_status | Original Status | keyword |
| fortinet.firewall.old_value | Original Virtual Domain name | keyword |
| fortinet.firewall.oldchannel | Original channel | integer |
| fortinet.firewall.oldchassisid | Original Chassis Number | integer |
| fortinet.firewall.oldslot | Original Slot Number | integer |
| fortinet.firewall.oldsn | Old Serial number | keyword |
| fortinet.firewall.oldwprof | Old Web Filter Profile | keyword |
| fortinet.firewall.onwire | A flag to indicate if the AP is onwire or not | keyword |
| fortinet.firewall.opercountry | Operating Country | keyword |
| fortinet.firewall.opertxpower | Operating TX power | integer |
| fortinet.firewall.osname | Operating System name | keyword |
| fortinet.firewall.osversion | Operating System version | keyword |
| fortinet.firewall.out_spi | Out SPI | keyword |
| fortinet.firewall.outintf | Out interface | keyword |
| fortinet.firewall.passedcount | Fabric passed count | integer |
| fortinet.firewall.passwd | Changed user password information | keyword |
| fortinet.firewall.path | Path of looped configuration for security fabric | keyword |
| fortinet.firewall.peer | WAN optimization peer | keyword |
| fortinet.firewall.peer_notif | VPN peer notification | keyword |
| fortinet.firewall.phase2_name | VPN phase2 name | keyword |
| fortinet.firewall.phone | VOIP Phone | keyword |
| fortinet.firewall.pid | Process ID | integer |
| fortinet.firewall.policytype | Policy Type | keyword |
| fortinet.firewall.poolname | IP Pool name | keyword |
| fortinet.firewall.port | Log upload error port | integer |
| fortinet.firewall.portbegin | IP Pool port number to begin | integer |
| fortinet.firewall.portend | IP Pool port number to end | integer |
| fortinet.firewall.probeproto | Link Monitor Probe Protocol | keyword |
| fortinet.firewall.process | URL Filter process | keyword |
| fortinet.firewall.processtime | Process time for reports | integer |
| fortinet.firewall.profile | Profile Name | keyword |
| fortinet.firewall.profile_vd | Virtual Domain Name | keyword |
| fortinet.firewall.profilegroup | Profile Group Name | keyword |
| fortinet.firewall.profiletype | Profile Type | keyword |
| fortinet.firewall.qtypeval | DNS question type value | integer |
| fortinet.firewall.quarskip | Quarantine skip explanation | keyword |
| fortinet.firewall.quotaexceeded | If quota has been exceeded | keyword |
| fortinet.firewall.quotamax | Maximum quota allowed - in seconds if time-based - in bytes if traffic-based | long |
| fortinet.firewall.quotatype | Quota type | keyword |
| fortinet.firewall.quotaused | Quota used - in seconds if time-based - in bytes if trafficbased) | long |
| fortinet.firewall.radioband | Radio band | keyword |
| fortinet.firewall.radioid | Radio ID | integer |
| fortinet.firewall.radioidclosest | Radio ID on the AP closest the rogue AP | integer |
| fortinet.firewall.radioiddetected | Radio ID on the AP which detected the rogue AP | integer |
| fortinet.firewall.rate | Wireless rogue rate value | keyword |
| fortinet.firewall.rawdata | Raw data value | keyword |
| fortinet.firewall.rawdataid | Raw data ID | keyword |
| fortinet.firewall.rcvddelta | Received bytes delta | keyword |
| fortinet.firewall.reason | Alert reason | keyword |
| fortinet.firewall.received | Server key exchange received | integer |
| fortinet.firewall.receivedsignature | Server key exchange received signature | keyword |
| fortinet.firewall.red | Memory information in red | keyword |
| fortinet.firewall.referralurl | Web filter referralurl | keyword |
| fortinet.firewall.remote | Remote PPP IP address | ip |
| fortinet.firewall.remotewtptime | Remote Wifi Radius authentication time | keyword |
| fortinet.firewall.reporttype | Report type | keyword |
| fortinet.firewall.reqtype | Request type | keyword |
| fortinet.firewall.request_name | VOIP request name | keyword |
| fortinet.firewall.result | VPN phase result | keyword |
| fortinet.firewall.role | VPN Phase 2 role | keyword |
| fortinet.firewall.rssi | Received signal strength indicator | integer |
| fortinet.firewall.rsso_key | RADIUS SSO attribute value | keyword |
| fortinet.firewall.ruledata | Rule data | keyword |
| fortinet.firewall.ruletype | Rule type | keyword |
| fortinet.firewall.scanned | Number of Scanned MMSs | integer |
| fortinet.firewall.scantime | Scanned time | long |
| fortinet.firewall.scope | FortiGuard Override Scope | keyword |
| fortinet.firewall.security | Wireless rogue security | keyword |
| fortinet.firewall.sensitivity | Sensitivity for document fingerprint | keyword |
| fortinet.firewall.sensor | NAC Sensor Name | keyword |
| fortinet.firewall.sentdelta | Sent bytes delta | keyword |
| fortinet.firewall.seq | Sequence number | keyword |
| fortinet.firewall.serial | WAN optimisation serial | keyword |
| fortinet.firewall.serialno | Serial number | keyword |
| fortinet.firewall.server | AD server FQDN or IP | keyword |
| fortinet.firewall.session_id | Session ID | keyword |
| fortinet.firewall.sessionid | WAD Session ID | integer |
| fortinet.firewall.setuprate | Session Setup Rate | long |
| fortinet.firewall.severity | Severity | keyword |
| fortinet.firewall.shaperdroprcvdbyte | Received bytes dropped by shaper | integer |
| fortinet.firewall.shaperdropsentbyte | Sent bytes dropped by shaper | integer |
| fortinet.firewall.shaperperipdropbyte | Dropped bytes per IP by shaper | integer |
| fortinet.firewall.shaperperipname | Traffic shaper name (per IP) | keyword |
| fortinet.firewall.shaperrcvdname | Traffic shaper name for received traffic | keyword |
| fortinet.firewall.shapersentname | Traffic shaper name for sent traffic | keyword |
| fortinet.firewall.shapingpolicyid | Traffic shaper policy ID | integer |
| fortinet.firewall.signal | Wireless rogue API signal | integer |
| fortinet.firewall.size | Email size in bytes | long |
| fortinet.firewall.slot | Slot number | integer |
| fortinet.firewall.sn | Security fabric serial number | keyword |
| fortinet.firewall.snclosest | SN of the AP closest to the rogue AP | keyword |
| fortinet.firewall.sndetected | SN of the AP which detected the rogue AP | keyword |
| fortinet.firewall.snmeshparent | SN of the mesh parent | keyword |
| fortinet.firewall.spi | IPSEC SPI | keyword |
| fortinet.firewall.src_int | Source interface | keyword |
| fortinet.firewall.srccountry | Source country | keyword |
| fortinet.firewall.srcfamily | Source family | keyword |
| fortinet.firewall.srchwvendor | Source hardware vendor | keyword |
| fortinet.firewall.srchwversion | Source hardware version | keyword |
| fortinet.firewall.srcinetsvc | Source interface service | keyword |
| fortinet.firewall.srcintfrole | Source interface role | keyword |
| fortinet.firewall.srcname | Source name | keyword |
| fortinet.firewall.srcserver | Source server | integer |
| fortinet.firewall.srcssid | Source SSID | keyword |
| fortinet.firewall.srcswversion | Source software version | keyword |
| fortinet.firewall.srcuuid | Source UUID | keyword |
| fortinet.firewall.sscname | SSC name | keyword |
| fortinet.firewall.ssid | Base Service Set ID | keyword |
| fortinet.firewall.sslaction | SSL Action | keyword |
| fortinet.firewall.ssllocal | WAD SSL local | keyword |
| fortinet.firewall.sslremote | WAD SSL remote | keyword |
| fortinet.firewall.stacount | Number of stations/clients | integer |
| fortinet.firewall.stage | IPSEC stage | keyword |
| fortinet.firewall.stamac | 802.1x station mac | keyword |
| fortinet.firewall.state | Admin login state | keyword |
| fortinet.firewall.status | Status | keyword |
| fortinet.firewall.stitch | Automation stitch triggered | keyword |
| fortinet.firewall.subject | Email subject | keyword |
| fortinet.firewall.submodule | Configuration Sub-Module Name | keyword |
| fortinet.firewall.subservice | AV subservice | keyword |
| fortinet.firewall.subtype | Log subtype | keyword |
| fortinet.firewall.suspicious | Number of Suspicious MMSs | integer |
| fortinet.firewall.switchproto | Protocol change information | keyword |
| fortinet.firewall.sync_status | The sync status with the master | keyword |
| fortinet.firewall.sync_type | The sync type with the master | keyword |
| fortinet.firewall.sysuptime | System uptime | keyword |
| fortinet.firewall.tamac | the MAC address of Transmitter, if none, then Receiver | keyword |
| fortinet.firewall.threattype | WIDS threat type | keyword |
| fortinet.firewall.time | Time of the event | keyword |
| fortinet.firewall.to | Email to field | keyword |
| fortinet.firewall.to_vcluster | destination virtual cluster number | integer |
| fortinet.firewall.total | Total memory | integer |
| fortinet.firewall.totalsession | Total Number of Sessions | integer |
| fortinet.firewall.trace_id | Session clash trace ID | keyword |
| fortinet.firewall.trandisp | NAT translation type | keyword |
| fortinet.firewall.transid | HTTP transaction ID | integer |
| fortinet.firewall.translationid | DNS filter transaltion ID | keyword |
| fortinet.firewall.trigger | Automation stitch trigger | keyword |
| fortinet.firewall.trueclntip | File filter true client IP | ip |
| fortinet.firewall.tunnelid | IPSEC tunnel ID | integer |
| fortinet.firewall.tunnelip | IPSEC tunnel IP | ip |
| fortinet.firewall.tunneltype | IPSEC tunnel type | keyword |
| fortinet.firewall.type | Module type | keyword |
| fortinet.firewall.ui | Admin authentication UI type | keyword |
| fortinet.firewall.unauthusersource | Unauthenticated user source | keyword |
| fortinet.firewall.unit | Power supply unit | integer |
| fortinet.firewall.urlfilteridx | URL filter ID | integer |
| fortinet.firewall.urlfilterlist | URL filter list | keyword |
| fortinet.firewall.urlsource | URL filter source | keyword |
| fortinet.firewall.urltype | URL filter type | keyword |
| fortinet.firewall.used | Number of Used IPs | integer |
| fortinet.firewall.used_for_type | Connection for the type | integer |
| fortinet.firewall.utmaction | Security action performed by UTM | keyword |
| fortinet.firewall.vap | Virtual AP | keyword |
| fortinet.firewall.vapmode | Virtual AP mode | keyword |
| fortinet.firewall.vcluster | virtual cluster id | integer |
| fortinet.firewall.vcluster_member | Virtual cluster member | integer |
| fortinet.firewall.vcluster_state | Virtual cluster state | keyword |
| fortinet.firewall.vd | Virtual Domain Name | keyword |
| fortinet.firewall.vdname | Virtual Domain Name | keyword |
| fortinet.firewall.vendorurl | Vulnerability scan vendor name | keyword |
| fortinet.firewall.version | Version | keyword |
| fortinet.firewall.vip | Virtual IP | keyword |
| fortinet.firewall.virus | Virus name | keyword |
| fortinet.firewall.virusid | Virus ID (unique virus identifier) | integer |
| fortinet.firewall.voip_proto | VOIP protocol | keyword |
| fortinet.firewall.vpn | VPN description | keyword |
| fortinet.firewall.vpntunnel | IPsec Vpn Tunnel Name | keyword |
| fortinet.firewall.vpntype | The type of the VPN tunnel | keyword |
| fortinet.firewall.vrf | VRF number | integer |
| fortinet.firewall.vulncat | Vulnerability Category | keyword |
| fortinet.firewall.vulnid | Vulnerability ID | integer |
| fortinet.firewall.vulnname | Vulnerability name | keyword |
| fortinet.firewall.vwlid | VWL ID | integer |
| fortinet.firewall.vwlquality | VWL quality | keyword |
| fortinet.firewall.vwlservice | VWL service | keyword |
| fortinet.firewall.vwpvlanid | VWP VLAN ID | integer |
| fortinet.firewall.wanin | WAN incoming traffic in bytes | long |
| fortinet.firewall.wanoptapptype | WAN Optimization Application type | keyword |
| fortinet.firewall.wanout | WAN outgoing traffic in bytes | long |
| fortinet.firewall.weakwepiv | Weak Wep Initiation Vector | keyword |
| fortinet.firewall.xauthgroup | XAuth Group Name | keyword |
| fortinet.firewall.xauthuser | XAuth User Name | keyword |
| fortinet.firewall.xid | Wireless X ID | integer |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Log level of the log event. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| network.application | Application level protocol name. | keyword |
| network.bytes | Total bytes transferred in both directions. | long |
| network.direction | Direction of the network traffic. | keyword |
| network.iana_number | IANA Protocol Number. | keyword |
| network.packets | Total packets transferred in both directions. | long |
| network.protocol | L7 Network protocol name. | keyword |
| observer.egress.interface.name | Interface name | keyword |
| observer.ingress.interface.name | Interface name | keyword |
| observer.name | Custom name of the observer. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.hash | All the hashes seen on your event. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| rule.category | Rule category | keyword |
| rule.description | Rule description | keyword |
| rule.id | Rule ID | keyword |
| rule.name | Rule name | keyword |
| rule.ruleset | Rule ruleset | keyword |
| rule.uuid | Rule UUID | keyword |
| source.address | Source network address. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.mac | MAC address of the source. | keyword |
| source.nat.ip | Source NAT ip | ip |
| source.nat.port | Source NAT port | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tls.client.issuer | Distinguished name of subject of the issuer. | keyword |
| tls.client.server_name | Hostname the client is trying to connect to. Also called the SNI. | keyword |
| tls.server.issuer | Subject of the issuer of the x.509 certificate presented by the server. | keyword |
| url.domain | Domain of the url. | keyword |
| url.path | Path of the request, such as "/search". | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| vulnerability.category | Category of a vulnerability. | keyword |

