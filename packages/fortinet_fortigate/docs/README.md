# Fortinet FortiGate Integration

This integration is for Fortinet FortiGate logs sent in the syslog format.

## Compatibility

This integration has been tested against FortiOS version 6.0.x and 6.2.x. Versions above this are expected to work but have not been tested.

### Log

The `log` dataset collects JFortinet FortiGate logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2019-05-15T18:03:36.000Z",
    "agent": {
        "ephemeral_id": "74b27709-c288-4314-b386-659dbc5a62ea",
        "hostname": "docker-fleet-agent",
        "id": "2164018d-05cd-45b4-979d-4032bdd775f6",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "fortinet_fortigate.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 41690,
            "organization": {
                "name": "Dailymotion S.A."
            }
        },
        "geo": {
            "continent_name": "Europe",
            "country_iso_code": "FR",
            "country_name": "France",
            "location": {
                "lat": 48.8582,
                "lon": 2.3387
            }
        },
        "ip": "195.8.215.136",
        "port": 443
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "7cc48d16-ebf0-44b1-9094-fe2082d8f5a4",
        "snapshot": true,
        "version": "7.14.0"
    },
    "event": {
        "action": "app-ctrl-all",
        "category": [
            "network"
        ],
        "code": "1059028704",
        "dataset": "fortinet_fortigate.log",
        "ingested": "2021-06-03T12:38:44.458586716Z",
        "kind": "event",
        "module": "fortinet",
        "original": "\u003c190\u003edate=2019-05-15 time=18:03:36 logid=\"1059028704\" type=\"utm\" subtype=\"app-ctrl\" eventtype=\"app-ctrl-all\" level=\"information\" vd=\"root\" eventtime=1557968615 appid=40568 srcip=10.1.100.22 dstip=195.8.215.136 srcport=50798 dstport=443 srcintf=\"port10\" srcintfrole=\"lan\" dstintf=\"port9\" dstintfrole=\"wan\" proto=6 service=\"HTTPS\" direction=\"outgoing\" policyid=1 sessionid=4414 applist=\"block-social.media\" appcat=\"Web.Client\" app=\"HTTPS.BROWSER\" action=\"pass\" hostname=\"www.dailymotion.com\" incidentserialno=1962906680 url=\"/\" msg=\"Web.Client: HTTPS.BROWSER,\" apprisk=\"medium\" scertcname=\"*.dailymotion.com\" scertissuer=\"DigiCert SHA2 High Assurance Server CA\"\n",
        "outcome": "success",
        "start": "2019-05-16T01:03:35.000Z",
        "type": [
            "allowed"
        ]
    },
    "fortinet": {
        "firewall": {
            "action": "pass",
            "appid": "40568",
            "apprisk": "medium",
            "dstintfrole": "wan",
            "incidentserialno": "1962906680",
            "sessionid": "4414",
            "srcintfrole": "lan",
            "subtype": "app-ctrl",
            "type": "utm",
            "vd": "root"
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "level": "information",
        "source": {
            "address": "192.168.240.4:54617"
        }
    },
    "message": "Web.Client: HTTPS.BROWSER,",
    "network": {
        "application": "HTTPS.BROWSER",
        "direction": "outbound",
        "iana_number": "6",
        "transport": "tcp",
        "protocol": "https"
    },
    "observer": {
        "egress": {
            "interface": {
                "name": "port9"
            }
        },
        "ingress": {
            "interface": {
                "name": "port10"
            }
        },
        "product": "Fortigate",
        "type": "firewall",
        "vendor": "Fortinet"
    },
    "related": {
        "ip": [
            "10.1.100.22",
            "195.8.215.136"
        ]
    },
    "rule": {
        "category": "Web-Client",
        "id": "1",
        "ruleset": "block-social.media"
    },
    "source": {
        "ip": "10.1.100.22",
        "port": 50798
    },
    "tags": [
        "fortinet-firewall",
        "forwarded",
        "preserve_original_event"
    ],
    "tls": {
        "server": {
            "issuer": "DigiCert SHA2 High Assurance Server CA",
            "x509": {
                "issuer": {
                    "common_name": "DigiCert SHA2 High Assurance Server CA"
                },
                "subject": {
                    "common_name": "*.dailymotion.com"
                }
            }
        }
    },
    "url": {
        "domain": "www.dailymotion.com",
        "path": "/"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. The `answers` array can be difficult to use, because of the variety of data formats it can contain. Extracting all IP addresses seen in there to `dns.resolved_ip` makes it possible to index them as IP addresses, and makes them easier to visualize and query for. | ip |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.cc.address | The email address of CC recipient | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.sender.address | Per RFC 5322, specifies the address responsible for the actual transmission of the message. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.message | Log message optimized for viewing in a log viewer. | text |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reference | Reference URL linking to additional information about this event. This URL links to a static definition of this event. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
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
| fortinet.firewall.mem | Memory usage system statistics | integer |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
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
| url.path | Path of the request, such as "/search". | wildcard |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| vulnerability.category | The type of system or architecture that the vulnerability affects. These may be platform-specific (for example, Debian or SUSE) or general (for example, Database or Firewall). For example (https://qualysguard.qualys.com/qwebhelp/fo_portal/knowledgebase/vulnerability_categories.htm[Qualys vulnerability categories]) This field must be an array. | keyword |
