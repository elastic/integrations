# Fortinet Integration (Deprecated)

_This integration is deprecated. Please use one of the other Fortinet integrations
that are specific to a Fortinet product._

This integration is for Fortinet [FortiOS](https://docs.fortinet.com/product/fortigate/6.2) and [FortiClient](https://docs.fortinet.com/product/forticlient/) Endpoint logs sent in the syslog format. It includes the following datasets for receiving logs:

- `firewall` dataset: consists of Fortinet FortiGate logs.
- `clientendpoint` dataset: supports Fortinet FortiClient Endpoint Security logs.
- `fortimail` dataset: supports Fortinet FortiMail logs.
- `fortimanager` dataset: supports Fortinet Manager/Analyzer logs.

## Compatibility

This integration has been tested against FortiOS version 6.0.x and 6.2.x. Versions above this are expected to work but have not been tested.

## Logs

### Firewall

Contains log entries from Fortinet FortiGate applicances.

An example event for `firewall` looks as following:

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
        "dataset": "fortinet.firewall",
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
        "version": "8.3.0"
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
        "dataset": "fortinet.firewall",
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
| url.path | Path of the request, such as "/search". | wildcard |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| vulnerability.category | The type of system or architecture that the vulnerability affects. These may be platform-specific (for example, Debian or SUSE) or general (for example, Database or Firewall). For example (https://qualysguard.qualys.com/qwebhelp/fo_portal/knowledgebase/vulnerability_categories.htm[Qualys vulnerability categories]) This field must be an array. | keyword |


### Clientendpoint

The `clientendpoint` dataset collects Fortinet FortiClient Endpoint Security logs.

An example event for `clientendpoint` looks as following:

```json
{
    "@timestamp": "2021-01-29T06:09:59.000Z",
    "agent": {
        "ephemeral_id": "e212d683-d4b4-42ac-ba98-c8414ff62188",
        "id": "4e3f135a-d5f9-40b6-ae01-2c834ecbead0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "fortinet.clientendpoint",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": [
            "10.102.123.34"
        ],
        "port": 3994
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "4e3f135a-d5f9-40b6-ae01-2c834ecbead0",
        "snapshot": true,
        "version": "8.0.0"
    },
    "event": {
        "action": "deny",
        "agent_id_status": "verified",
        "code": "http",
        "dataset": "fortinet.clientendpoint",
        "ingested": "2022-01-25T12:25:45Z",
        "original": "January 29 06:09:59 boNemoe4402.www.invalid proto=udp service=http status=deny src=10.150.92.220 dst=10.102.123.34 src_port=7178 dst_port=3994 server_app=reeufugi pid=7880 app_name=enderitq traff_direct=external block_count=5286 logon_user=sumdo@litesse6379.api.domain msg=failure\n",
        "outcome": "failure",
        "timezone": "+00:00"
    },
    "host": {
        "name": "boNemoe4402.www.invalid"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.30.0.4:54478"
        }
    },
    "network": {
        "direction": "external",
        "protocol": "udp"
    },
    "observer": {
        "product": "FortiClient",
        "type": "Anti-Virus",
        "vendor": "Fortinet"
    },
    "process": {
        "pid": 7880
    },
    "related": {
        "hosts": [
            "litesse6379.api.domain",
            "boNemoe4402.www.invalid"
        ],
        "ip": [
            "10.150.92.220",
            "10.102.123.34"
        ],
        "user": [
            "sumdo"
        ]
    },
    "rsa": {
        "counters": {
            "dclass_c1": 5286,
            "dclass_c1_str": "block_count"
        },
        "internal": {
            "messageid": "http"
        },
        "investigations": {
            "ec_outcome": "Failure",
            "ec_subject": "NetworkComm",
            "ec_theme": "ALM"
        },
        "misc": {
            "action": [
                "deny"
            ],
            "result": "failure\n"
        },
        "network": {
            "alias_host": [
                "boNemoe4402.www.invalid"
            ],
            "domain": "litesse6379.api.domain",
            "network_service": "http"
        },
        "time": {
            "event_time": "2021-01-29T06:09:59.000Z"
        }
    },
    "server": {
        "domain": "litesse6379.api.domain",
        "registered_domain": "api.domain",
        "subdomain": "litesse6379",
        "top_level_domain": "domain"
    },
    "source": {
        "ip": [
            "10.150.92.220"
        ],
        "port": 7178
    },
    "tags": [
        "preserve_original_event",
        "fortinet-clientendpoint",
        "forwarded"
    ],
    "user": {
        "name": "sumdo"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.registered_domain | The highest registered client domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| client.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| client.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
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
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.port | Port of the destination. | long |
| destination.registered_domain | The highest registered destination domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| destination.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| destination.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.question.domain | Server domain. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| file.attributes | Array of file attributes. Attributes names will vary by platform. Here's a non-exhaustive list of values that are expected in this field: archive, compressed, directory, encrypted, execute, hidden, read, readonly, system, write. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.type | File type (file, dir, or symlink). | keyword |
| geo.city_name | City name. | keyword |
| geo.country_name | Country name. | keyword |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| geo.region_name | Region name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.interface.name |  | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.parent.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.parent.title.text | Multi-field of `process.parent.title`. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rsa.counters.dclass_c1 | This is a generic counter key that should be used with the label dclass.c1.str only | long |
| rsa.counters.dclass_c1_str | This is a generic counter string key that should be used with the label dclass.c1 only | keyword |
| rsa.counters.dclass_c2 | This is a generic counter key that should be used with the label dclass.c2.str only | long |
| rsa.counters.dclass_c2_str | This is a generic counter string key that should be used with the label dclass.c2 only | keyword |
| rsa.counters.dclass_c3 | This is a generic counter key that should be used with the label dclass.c3.str only | long |
| rsa.counters.dclass_c3_str | This is a generic counter string key that should be used with the label dclass.c3 only | keyword |
| rsa.counters.dclass_r1 | This is a generic ratio key that should be used with the label dclass.r1.str only | keyword |
| rsa.counters.dclass_r1_str | This is a generic ratio string key that should be used with the label dclass.r1 only | keyword |
| rsa.counters.dclass_r2 | This is a generic ratio key that should be used with the label dclass.r2.str only | keyword |
| rsa.counters.dclass_r2_str | This is a generic ratio string key that should be used with the label dclass.r2 only | keyword |
| rsa.counters.dclass_r3 | This is a generic ratio key that should be used with the label dclass.r3.str only | keyword |
| rsa.counters.dclass_r3_str | This is a generic ratio string key that should be used with the label dclass.r3 only | keyword |
| rsa.counters.event_counter | This is used to capture the number of times an event repeated | long |
| rsa.crypto.cert_ca | This key is used to capture the Certificate signing authority only | keyword |
| rsa.crypto.cert_checksum |  | keyword |
| rsa.crypto.cert_common | This key is used to capture the Certificate common name only | keyword |
| rsa.crypto.cert_error | This key captures the Certificate Error String | keyword |
| rsa.crypto.cert_host_cat | This key is used for the hostname category value of a certificate | keyword |
| rsa.crypto.cert_host_name | Deprecated key defined only in table map. | keyword |
| rsa.crypto.cert_issuer |  | keyword |
| rsa.crypto.cert_keysize |  | keyword |
| rsa.crypto.cert_serial | This key is used to capture the Certificate serial number only | keyword |
| rsa.crypto.cert_status | This key captures Certificate validation status | keyword |
| rsa.crypto.cert_subject | This key is used to capture the Certificate organization only | keyword |
| rsa.crypto.cert_username |  | keyword |
| rsa.crypto.cipher_dst | This key is for Destination (Server) Cipher | keyword |
| rsa.crypto.cipher_size_dst | This key captures Destination (Server) Cipher Size | long |
| rsa.crypto.cipher_size_src | This key captures Source (Client) Cipher Size | long |
| rsa.crypto.cipher_src | This key is for Source (Client) Cipher | keyword |
| rsa.crypto.crypto | This key is used to capture the Encryption Type or Encryption Key only | keyword |
| rsa.crypto.d_certauth |  | keyword |
| rsa.crypto.https_insact |  | keyword |
| rsa.crypto.https_valid |  | keyword |
| rsa.crypto.ike | IKE negotiation phase. | keyword |
| rsa.crypto.ike_cookie1 | ID of the negotiation — sent for ISAKMP Phase One | keyword |
| rsa.crypto.ike_cookie2 | ID of the negotiation — sent for ISAKMP Phase Two | keyword |
| rsa.crypto.peer | This key is for Encryption peer's IP Address | keyword |
| rsa.crypto.peer_id | This key is for Encryption peer’s identity | keyword |
| rsa.crypto.s_certauth |  | keyword |
| rsa.crypto.scheme | This key captures the Encryption scheme used | keyword |
| rsa.crypto.sig_type | This key captures the Signature Type | keyword |
| rsa.crypto.ssl_ver_dst | Deprecated, use version | keyword |
| rsa.crypto.ssl_ver_src | Deprecated, use version | keyword |
| rsa.db.database | This key is used to capture the name of a database or an instance as seen in a session | keyword |
| rsa.db.db_id | This key is used to capture the unique identifier for a database | keyword |
| rsa.db.db_pid | This key captures the process id of a connection with database server | long |
| rsa.db.index | This key captures IndexID of the index. | keyword |
| rsa.db.instance | This key is used to capture the database server instance name | keyword |
| rsa.db.lread | This key is used for the number of logical reads | long |
| rsa.db.lwrite | This key is used for the number of logical writes | long |
| rsa.db.permissions | This key captures permission or privilege level assigned to a resource. | keyword |
| rsa.db.pread | This key is used for the number of physical writes | long |
| rsa.db.table_name | This key is used to capture the table name | keyword |
| rsa.db.transact_id | This key captures the SQL transantion ID of the current session | keyword |
| rsa.email.email | This key is used to capture a generic email address where the source or destination context is not clear | keyword |
| rsa.email.email_dst | This key is used to capture the Destination email address only, when the destination context is not clear use email | keyword |
| rsa.email.email_src | This key is used to capture the source email address only, when the source context is not clear use email | keyword |
| rsa.email.subject | This key is used to capture the subject string from an Email only. | keyword |
| rsa.email.trans_from | Deprecated key defined only in table map. | keyword |
| rsa.email.trans_to | Deprecated key defined only in table map. | keyword |
| rsa.endpoint.host_state | This key is used to capture the current state of the machine, such as \<strong\>blacklisted\</strong\>, \<strong\>infected\</strong\>, \<strong\>firewall disabled\</strong\> and so on | keyword |
| rsa.endpoint.registry_key | This key captures the path to the registry key | keyword |
| rsa.endpoint.registry_value | This key captures values or decorators used within a registry entry | keyword |
| rsa.file.attachment | This key captures the attachment file name | keyword |
| rsa.file.binary | Deprecated key defined only in table map. | keyword |
| rsa.file.directory_dst | \<span\>This key is used to capture the directory of the target process or file\</span\> | keyword |
| rsa.file.directory_src | This key is used to capture the directory of the source process or file | keyword |
| rsa.file.file_entropy | This is used to capture entropy vale of a file | double |
| rsa.file.file_vendor | This is used to capture Company name of file located in version_info | keyword |
| rsa.file.filename_dst | This is used to capture name of the file targeted by the action | keyword |
| rsa.file.filename_src | This is used to capture name of the parent filename, the file which performed the action | keyword |
| rsa.file.filename_tmp |  | keyword |
| rsa.file.filesystem |  | keyword |
| rsa.file.privilege | Deprecated, use permissions | keyword |
| rsa.file.task_name | This is used to capture name of the task | keyword |
| rsa.healthcare.patient_fname | This key is for First Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.healthcare.patient_id | This key captures the unique ID for a patient | keyword |
| rsa.healthcare.patient_lname | This key is for Last Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.healthcare.patient_mname | This key is for Middle Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.accesses | This key is used to capture actual privileges used in accessing an object | keyword |
| rsa.identity.auth_method | This key is used to capture authentication methods used only | keyword |
| rsa.identity.dn | X.500 (LDAP) Distinguished Name | keyword |
| rsa.identity.dn_dst | An X.500 (LDAP) Distinguished name that used in a context that indicates a Destination dn | keyword |
| rsa.identity.dn_src | An X.500 (LDAP) Distinguished name that is used in a context that indicates a Source dn | keyword |
| rsa.identity.federated_idp | This key is the federated Identity Provider. This is the server providing the authentication. | keyword |
| rsa.identity.federated_sp | This key is the Federated Service Provider. This is the application requesting authentication. | keyword |
| rsa.identity.firstname | This key is for First Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.host_role | This key should only be used to capture the role of a Host Machine | keyword |
| rsa.identity.lastname | This key is for Last Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.ldap | This key is for Uninterpreted LDAP values. Ldap Values that don’t have a clear query or response context | keyword |
| rsa.identity.ldap_query | This key is the Search criteria from an LDAP search | keyword |
| rsa.identity.ldap_response | This key is to capture Results from an LDAP search | keyword |
| rsa.identity.logon_type | This key is used to capture the type of logon method used. | keyword |
| rsa.identity.logon_type_desc | This key is used to capture the textual description of an integer logon type as stored in the meta key 'logon.type'. | keyword |
| rsa.identity.middlename | This key is for Middle Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.org | This key captures the User organization | keyword |
| rsa.identity.owner | This is used to capture username the process or service is running as, the author of the task | keyword |
| rsa.identity.password | This key is for Passwords seen in any session, plain text or encrypted | keyword |
| rsa.identity.profile | This key is used to capture the user profile | keyword |
| rsa.identity.realm | Radius realm or similar grouping of accounts | keyword |
| rsa.identity.service_account | This key is a windows specific key, used for capturing name of the account a service (referenced in the event) is running under. Legacy Usage | keyword |
| rsa.identity.user_dept | User's Department Names only | keyword |
| rsa.identity.user_role | This key is used to capture the Role of a user only | keyword |
| rsa.identity.user_sid_dst | This key captures Destination User Session ID | keyword |
| rsa.identity.user_sid_src | This key captures Source User Session ID | keyword |
| rsa.internal.audit_class | Deprecated key defined only in table map. | keyword |
| rsa.internal.cid | This is the unique identifier used to identify a NetWitness Concentrator. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.data | Deprecated key defined only in table map. | keyword |
| rsa.internal.dead | Deprecated key defined only in table map. | long |
| rsa.internal.device_class | This is the Classification of the Log Event Source under a predefined fixed set of Event Source Classifications. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_group | This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_host | This is the Hostname of the log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_ip | This is the IPv4 address of the Log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.device_ipv6 | This is the IPv6 address of the Log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.device_type | This is the name of the log parser which parsed a given session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_type_id | Deprecated key defined only in table map. | long |
| rsa.internal.did | This is the unique identifier used to identify a NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.entropy_req | This key is only used by the Entropy Parser, the Meta Type can be either UInt16 or Float32 based on the configuration | long |
| rsa.internal.entropy_res | This key is only used by the Entropy Parser, the Meta Type can be either UInt16 or Float32 based on the configuration | long |
| rsa.internal.entry | Deprecated key defined only in table map. | keyword |
| rsa.internal.event_desc |  | keyword |
| rsa.internal.event_name | Deprecated key defined only in table map. | keyword |
| rsa.internal.feed_category | This is used to capture the category of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.feed_desc | This is used to capture the description of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.feed_name | This is used to capture the name of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.forward_ip | This key should be used to capture the IPV4 address of a relay system which forwarded the events from the original system to NetWitness. | ip |
| rsa.internal.forward_ipv6 | This key is used to capture the IPV6 address of a relay system which forwarded the events from the original system to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.hcode | Deprecated key defined only in table map. | keyword |
| rsa.internal.header_id | This is the Header ID value that identifies the exact log parser header definition that parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.inode | Deprecated key defined only in table map. | long |
| rsa.internal.lc_cid | This is a unique Identifier of a Log Collector. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.lc_ctime | This is the time at which a log is collected in a NetWitness Log Collector. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | date |
| rsa.internal.level | Deprecated key defined only in table map. | long |
| rsa.internal.mcb_req | This key is only used by the Entropy Parser, the most common byte request is simply which byte for each side (0 thru 255) was seen the most | long |
| rsa.internal.mcb_res | This key is only used by the Entropy Parser, the most common byte response is simply which byte for each side (0 thru 255) was seen the most | long |
| rsa.internal.mcbc_req | This key is only used by the Entropy Parser, the most common byte count is the number of times the most common byte (above) was seen in the session streams | long |
| rsa.internal.mcbc_res | This key is only used by the Entropy Parser, the most common byte count is the number of times the most common byte (above) was seen in the session streams | long |
| rsa.internal.medium | This key is used to identify if it’s a log/packet session or Layer 2 Encapsulation Type. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness. 32 = log, 33 = correlation session, &lt; 32 is packet session | long |
| rsa.internal.message | This key captures the contents of instant messages | keyword |
| rsa.internal.messageid |  | keyword |
| rsa.internal.msg | This key is used to capture the raw message that comes into the Log Decoder | keyword |
| rsa.internal.msg_id | This is the Message ID1 value that identifies the exact log parser definition which parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.msg_vid | This is the Message ID2 value that identifies the exact log parser definition which parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.node_name | Deprecated key defined only in table map. | keyword |
| rsa.internal.nwe_callback_id | This key denotes that event is endpoint related | keyword |
| rsa.internal.obj_id | Deprecated key defined only in table map. | keyword |
| rsa.internal.obj_server | Deprecated key defined only in table map. | keyword |
| rsa.internal.obj_val | Deprecated key defined only in table map. | keyword |
| rsa.internal.parse_error | This is a special key that stores any Meta key validation error found while parsing a log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.payload_req | This key is only used by the Entropy Parser, the payload size metrics are the payload sizes of each session side at the time of parsing. However, in order to keep | long |
| rsa.internal.payload_res | This key is only used by the Entropy Parser, the payload size metrics are the payload sizes of each session side at the time of parsing. However, in order to keep | long |
| rsa.internal.process_vid_dst | Endpoint generates and uses a unique virtual ID to identify any similar group of process. This ID represents the target process. | keyword |
| rsa.internal.process_vid_src | Endpoint generates and uses a unique virtual ID to identify any similar group of process. This ID represents the source process. | keyword |
| rsa.internal.resource | Deprecated key defined only in table map. | keyword |
| rsa.internal.resource_class | Deprecated key defined only in table map. | keyword |
| rsa.internal.rid | This is a special ID of the Remote Session created by NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | long |
| rsa.internal.session_split | This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.site | Deprecated key defined only in table map. | keyword |
| rsa.internal.size | This is the size of the session as seen by the NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | long |
| rsa.internal.sourcefile | This is the name of the log file or PCAPs that can be imported into NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.statement | Deprecated key defined only in table map. | keyword |
| rsa.internal.time | This is the time at which a session hits a NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness. | date |
| rsa.internal.ubc_req | This key is only used by the Entropy Parser, Unique byte count is the number of unique bytes seen in each stream. 256 would mean all byte values of 0 thru 255 were seen at least once | long |
| rsa.internal.ubc_res | This key is only used by the Entropy Parser, Unique byte count is the number of unique bytes seen in each stream. 256 would mean all byte values of 0 thru 255 were seen at least once | long |
| rsa.internal.word | This is used by the Word Parsing technology to capture the first 5 character of every word in an unparsed log | keyword |
| rsa.investigations.analysis_file | This is used to capture all indicators used in a File Analysis. This key should be used to capture an analysis of a file | keyword |
| rsa.investigations.analysis_service | This is used to capture all indicators used in a Service Analysis. This key should be used to capture an analysis of a service | keyword |
| rsa.investigations.analysis_session | This is used to capture all indicators used for a Session Analysis. This key should be used to capture an analysis of a session | keyword |
| rsa.investigations.boc | This is used to capture behaviour of compromise | keyword |
| rsa.investigations.ec_activity | This key captures the particular event activity(Ex:Logoff) | keyword |
| rsa.investigations.ec_outcome | This key captures the outcome of a particular Event(Ex:Success) | keyword |
| rsa.investigations.ec_subject | This key captures the Subject of a particular Event(Ex:User) | keyword |
| rsa.investigations.ec_theme | This key captures the Theme of a particular Event(Ex:Authentication) | keyword |
| rsa.investigations.eoc | This is used to capture Enablers of Compromise | keyword |
| rsa.investigations.event_cat | This key captures the Event category number | long |
| rsa.investigations.event_cat_name | This key captures the event category name corresponding to the event cat code | keyword |
| rsa.investigations.event_vcat | This is a vendor supplied category. This should be used in situations where the vendor has adopted their own event_category taxonomy. | keyword |
| rsa.investigations.inv_category | This used to capture investigation category | keyword |
| rsa.investigations.inv_context | This used to capture investigation context | keyword |
| rsa.investigations.ioc | This is key capture indicator of compromise | keyword |
| rsa.misc.OS | This key captures the Name of the Operating System | keyword |
| rsa.misc.acl_id |  | keyword |
| rsa.misc.acl_op |  | keyword |
| rsa.misc.acl_pos |  | keyword |
| rsa.misc.acl_table |  | keyword |
| rsa.misc.action |  | keyword |
| rsa.misc.admin |  | keyword |
| rsa.misc.agent_id | This key is used to capture agent id | keyword |
| rsa.misc.alarm_id |  | keyword |
| rsa.misc.alarmname |  | keyword |
| rsa.misc.alert_id | Deprecated, New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.app_id |  | keyword |
| rsa.misc.audit |  | keyword |
| rsa.misc.audit_object |  | keyword |
| rsa.misc.auditdata |  | keyword |
| rsa.misc.autorun_type | This is used to capture Auto Run type | keyword |
| rsa.misc.benchmark |  | keyword |
| rsa.misc.bypass |  | keyword |
| rsa.misc.cache |  | keyword |
| rsa.misc.cache_hit |  | keyword |
| rsa.misc.category | This key is used to capture the category of an event given by the vendor in the session | keyword |
| rsa.misc.cc_number | Valid Credit Card Numbers only | long |
| rsa.misc.cefversion |  | keyword |
| rsa.misc.cfg_attr |  | keyword |
| rsa.misc.cfg_obj |  | keyword |
| rsa.misc.cfg_path |  | keyword |
| rsa.misc.change_attrib | This key is used to capture the name of the attribute that’s changing in a session | keyword |
| rsa.misc.change_new | This key is used to capture the new values of the attribute that’s changing in a session | keyword |
| rsa.misc.change_old | This key is used to capture the old value of the attribute that’s changing in a session | keyword |
| rsa.misc.changes |  | keyword |
| rsa.misc.checksum | This key is used to capture the checksum or hash of the entity such as a file or process. Checksum should be used over checksum.src or checksum.dst when it is unclear whether the entity is a source or target of an action. | keyword |
| rsa.misc.checksum_dst | This key is used to capture the checksum or hash of the the target entity such as a process or file. | keyword |
| rsa.misc.checksum_src | This key is used to capture the checksum or hash of the source entity such as a file or process. | keyword |
| rsa.misc.client | This key is used to capture only the name of the client application requesting resources of the server. See the user.agent meta key for capture of the specific user agent identifier or browser identification string. | keyword |
| rsa.misc.client_ip |  | keyword |
| rsa.misc.clustermembers |  | keyword |
| rsa.misc.cmd |  | keyword |
| rsa.misc.cn_acttimeout |  | keyword |
| rsa.misc.cn_asn_src |  | keyword |
| rsa.misc.cn_bgpv4nxthop |  | keyword |
| rsa.misc.cn_ctr_dst_code |  | keyword |
| rsa.misc.cn_dst_tos |  | keyword |
| rsa.misc.cn_dst_vlan |  | keyword |
| rsa.misc.cn_engine_id |  | keyword |
| rsa.misc.cn_engine_type |  | keyword |
| rsa.misc.cn_f_switch |  | keyword |
| rsa.misc.cn_flowsampid |  | keyword |
| rsa.misc.cn_flowsampintv |  | keyword |
| rsa.misc.cn_flowsampmode |  | keyword |
| rsa.misc.cn_inacttimeout |  | keyword |
| rsa.misc.cn_inpermbyts |  | keyword |
| rsa.misc.cn_inpermpckts |  | keyword |
| rsa.misc.cn_invalid |  | keyword |
| rsa.misc.cn_ip_proto_ver |  | keyword |
| rsa.misc.cn_ipv4_ident |  | keyword |
| rsa.misc.cn_l_switch |  | keyword |
| rsa.misc.cn_log_did |  | keyword |
| rsa.misc.cn_log_rid |  | keyword |
| rsa.misc.cn_max_ttl |  | keyword |
| rsa.misc.cn_maxpcktlen |  | keyword |
| rsa.misc.cn_min_ttl |  | keyword |
| rsa.misc.cn_minpcktlen |  | keyword |
| rsa.misc.cn_mpls_lbl_1 |  | keyword |
| rsa.misc.cn_mpls_lbl_10 |  | keyword |
| rsa.misc.cn_mpls_lbl_2 |  | keyword |
| rsa.misc.cn_mpls_lbl_3 |  | keyword |
| rsa.misc.cn_mpls_lbl_4 |  | keyword |
| rsa.misc.cn_mpls_lbl_5 |  | keyword |
| rsa.misc.cn_mpls_lbl_6 |  | keyword |
| rsa.misc.cn_mpls_lbl_7 |  | keyword |
| rsa.misc.cn_mpls_lbl_8 |  | keyword |
| rsa.misc.cn_mpls_lbl_9 |  | keyword |
| rsa.misc.cn_mplstoplabel |  | keyword |
| rsa.misc.cn_mplstoplabip |  | keyword |
| rsa.misc.cn_mul_dst_byt |  | keyword |
| rsa.misc.cn_mul_dst_pks |  | keyword |
| rsa.misc.cn_muligmptype |  | keyword |
| rsa.misc.cn_sampalgo |  | keyword |
| rsa.misc.cn_sampint |  | keyword |
| rsa.misc.cn_seqctr |  | keyword |
| rsa.misc.cn_spackets |  | keyword |
| rsa.misc.cn_src_tos |  | keyword |
| rsa.misc.cn_src_vlan |  | keyword |
| rsa.misc.cn_sysuptime |  | keyword |
| rsa.misc.cn_template_id |  | keyword |
| rsa.misc.cn_totbytsexp |  | keyword |
| rsa.misc.cn_totflowexp |  | keyword |
| rsa.misc.cn_totpcktsexp |  | keyword |
| rsa.misc.cn_unixnanosecs |  | keyword |
| rsa.misc.cn_v6flowlabel |  | keyword |
| rsa.misc.cn_v6optheaders |  | keyword |
| rsa.misc.code |  | keyword |
| rsa.misc.command |  | keyword |
| rsa.misc.comments | Comment information provided in the log message | keyword |
| rsa.misc.comp_class |  | keyword |
| rsa.misc.comp_name |  | keyword |
| rsa.misc.comp_rbytes |  | keyword |
| rsa.misc.comp_sbytes |  | keyword |
| rsa.misc.comp_version | This key captures the Version level of a sub-component of a product. | keyword |
| rsa.misc.connection_id | This key captures the Connection ID | keyword |
| rsa.misc.content | This key captures the content type from protocol headers | keyword |
| rsa.misc.content_type | This key is used to capture Content Type only. | keyword |
| rsa.misc.content_version | This key captures Version level of a signature or database content. | keyword |
| rsa.misc.context | This key captures Information which adds additional context to the event. | keyword |
| rsa.misc.context_subject | This key is to be used in an audit context where the subject is the object being identified | keyword |
| rsa.misc.context_target |  | keyword |
| rsa.misc.count |  | keyword |
| rsa.misc.cpu | This key is the CPU time used in the execution of the event being recorded. | long |
| rsa.misc.cpu_data |  | keyword |
| rsa.misc.criticality |  | keyword |
| rsa.misc.cs_agency_dst |  | keyword |
| rsa.misc.cs_analyzedby |  | keyword |
| rsa.misc.cs_av_other |  | keyword |
| rsa.misc.cs_av_primary |  | keyword |
| rsa.misc.cs_av_secondary |  | keyword |
| rsa.misc.cs_bgpv6nxthop |  | keyword |
| rsa.misc.cs_bit9status |  | keyword |
| rsa.misc.cs_context |  | keyword |
| rsa.misc.cs_control |  | keyword |
| rsa.misc.cs_data |  | keyword |
| rsa.misc.cs_datecret |  | keyword |
| rsa.misc.cs_dst_tld |  | keyword |
| rsa.misc.cs_eth_dst_ven |  | keyword |
| rsa.misc.cs_eth_src_ven |  | keyword |
| rsa.misc.cs_event_uuid |  | keyword |
| rsa.misc.cs_filetype |  | keyword |
| rsa.misc.cs_fld |  | keyword |
| rsa.misc.cs_if_desc |  | keyword |
| rsa.misc.cs_if_name |  | keyword |
| rsa.misc.cs_ip_next_hop |  | keyword |
| rsa.misc.cs_ipv4dstpre |  | keyword |
| rsa.misc.cs_ipv4srcpre |  | keyword |
| rsa.misc.cs_lifetime |  | keyword |
| rsa.misc.cs_log_medium |  | keyword |
| rsa.misc.cs_loginname |  | keyword |
| rsa.misc.cs_modulescore |  | keyword |
| rsa.misc.cs_modulesign |  | keyword |
| rsa.misc.cs_opswatresult |  | keyword |
| rsa.misc.cs_payload |  | keyword |
| rsa.misc.cs_registrant |  | keyword |
| rsa.misc.cs_registrar |  | keyword |
| rsa.misc.cs_represult |  | keyword |
| rsa.misc.cs_rpayload |  | keyword |
| rsa.misc.cs_sampler_name |  | keyword |
| rsa.misc.cs_sourcemodule |  | keyword |
| rsa.misc.cs_streams |  | keyword |
| rsa.misc.cs_targetmodule |  | keyword |
| rsa.misc.cs_v6nxthop |  | keyword |
| rsa.misc.cs_whois_server |  | keyword |
| rsa.misc.cs_yararesult |  | keyword |
| rsa.misc.cve | This key captures CVE (Common Vulnerabilities and Exposures) - an identifier for known information security vulnerabilities. | keyword |
| rsa.misc.data_type |  | keyword |
| rsa.misc.description |  | keyword |
| rsa.misc.device_name | This is used to capture name of the Device associated with the node Like: a physical disk, printer, etc | keyword |
| rsa.misc.devvendor |  | keyword |
| rsa.misc.disposition | This key captures the The end state of an action. | keyword |
| rsa.misc.distance |  | keyword |
| rsa.misc.doc_number | This key captures File Identification number | long |
| rsa.misc.dstburb |  | keyword |
| rsa.misc.edomain |  | keyword |
| rsa.misc.edomaub |  | keyword |
| rsa.misc.ein_number | Employee Identification Numbers only | long |
| rsa.misc.error | This key captures All non successful Error codes or responses | keyword |
| rsa.misc.euid |  | keyword |
| rsa.misc.event_category |  | keyword |
| rsa.misc.event_computer | This key is a windows only concept, where this key is used to capture fully qualified domain name in a windows log. | keyword |
| rsa.misc.event_desc | This key is used to capture a description of an event available directly or inferred | keyword |
| rsa.misc.event_id |  | keyword |
| rsa.misc.event_log | This key captures the Name of the event log | keyword |
| rsa.misc.event_source | This key captures Source of the event that’s not a hostname | keyword |
| rsa.misc.event_state | This key captures the current state of the object/item referenced within the event. Describing an on-going event. | keyword |
| rsa.misc.event_type | This key captures the event category type as specified by the event source. | keyword |
| rsa.misc.event_user | This key is a windows only concept, where this key is used to capture combination of domain name and username in a windows log. | keyword |
| rsa.misc.expected_val | This key captures the Value expected (from the perspective of the device generating the log). | keyword |
| rsa.misc.facility |  | keyword |
| rsa.misc.facilityname |  | keyword |
| rsa.misc.fcatnum | This key captures Filter Category Number. Legacy Usage | keyword |
| rsa.misc.filter | This key captures Filter used to reduce result set | keyword |
| rsa.misc.finterface |  | keyword |
| rsa.misc.flags |  | keyword |
| rsa.misc.forensic_info |  | keyword |
| rsa.misc.found | This is used to capture the results of regex match | keyword |
| rsa.misc.fresult | This key captures the Filter Result | long |
| rsa.misc.gaddr |  | keyword |
| rsa.misc.group | This key captures the Group Name value | keyword |
| rsa.misc.group_id | This key captures Group ID Number (related to the group name) | keyword |
| rsa.misc.group_object | This key captures a collection/grouping of entities. Specific usage | keyword |
| rsa.misc.hardware_id | This key is used to capture unique identifier for a device or system (NOT a Mac address) | keyword |
| rsa.misc.id3 |  | keyword |
| rsa.misc.im_buddyid |  | keyword |
| rsa.misc.im_buddyname |  | keyword |
| rsa.misc.im_client |  | keyword |
| rsa.misc.im_croomid |  | keyword |
| rsa.misc.im_croomtype |  | keyword |
| rsa.misc.im_members |  | keyword |
| rsa.misc.im_userid |  | keyword |
| rsa.misc.im_username |  | keyword |
| rsa.misc.index |  | keyword |
| rsa.misc.inout |  | keyword |
| rsa.misc.ipkt |  | keyword |
| rsa.misc.ipscat |  | keyword |
| rsa.misc.ipspri |  | keyword |
| rsa.misc.job_num | This key captures the Job Number | keyword |
| rsa.misc.jobname |  | keyword |
| rsa.misc.language | This is used to capture list of languages the client support and what it prefers | keyword |
| rsa.misc.latitude |  | keyword |
| rsa.misc.library | This key is used to capture library information in mainframe devices | keyword |
| rsa.misc.lifetime | This key is used to capture the session lifetime in seconds. | long |
| rsa.misc.linenum |  | keyword |
| rsa.misc.link | This key is used to link the sessions together. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.misc.list_name |  | keyword |
| rsa.misc.listnum | This key is used to capture listname or listnumber, primarily for collecting access-list | keyword |
| rsa.misc.load_data |  | keyword |
| rsa.misc.location_floor |  | keyword |
| rsa.misc.location_mark |  | keyword |
| rsa.misc.log_id |  | keyword |
| rsa.misc.log_session_id | This key is used to capture a sessionid from the session directly | keyword |
| rsa.misc.log_session_id1 | This key is used to capture a Linked (Related) Session ID from the session directly | keyword |
| rsa.misc.log_type |  | keyword |
| rsa.misc.logid |  | keyword |
| rsa.misc.logip |  | keyword |
| rsa.misc.logname |  | keyword |
| rsa.misc.longitude |  | keyword |
| rsa.misc.lport |  | keyword |
| rsa.misc.mail_id | This key is used to capture the mailbox id/name | keyword |
| rsa.misc.match | This key is for regex match name from search.ini | keyword |
| rsa.misc.mbug_data |  | keyword |
| rsa.misc.message_body | This key captures the The contents of the message body. | keyword |
| rsa.misc.misc |  | keyword |
| rsa.misc.misc_name |  | keyword |
| rsa.misc.mode |  | keyword |
| rsa.misc.msgIdPart1 |  | keyword |
| rsa.misc.msgIdPart2 |  | keyword |
| rsa.misc.msgIdPart3 |  | keyword |
| rsa.misc.msgIdPart4 |  | keyword |
| rsa.misc.msg_type |  | keyword |
| rsa.misc.msgid |  | keyword |
| rsa.misc.name |  | keyword |
| rsa.misc.netsessid |  | keyword |
| rsa.misc.node | Common use case is the node name within a cluster. The cluster name is reflected by the host name. | keyword |
| rsa.misc.ntype |  | keyword |
| rsa.misc.num |  | keyword |
| rsa.misc.number |  | keyword |
| rsa.misc.number1 |  | keyword |
| rsa.misc.number2 |  | keyword |
| rsa.misc.nwwn |  | keyword |
| rsa.misc.obj_name | This is used to capture name of object | keyword |
| rsa.misc.obj_type | This is used to capture type of object | keyword |
| rsa.misc.object |  | keyword |
| rsa.misc.observed_val | This key captures the Value observed (from the perspective of the device generating the log). | keyword |
| rsa.misc.operation |  | keyword |
| rsa.misc.operation_id | An alert number or operation number. The values should be unique and non-repeating. | keyword |
| rsa.misc.opkt |  | keyword |
| rsa.misc.orig_from |  | keyword |
| rsa.misc.owner_id |  | keyword |
| rsa.misc.p_action |  | keyword |
| rsa.misc.p_filter |  | keyword |
| rsa.misc.p_group_object |  | keyword |
| rsa.misc.p_id |  | keyword |
| rsa.misc.p_msgid |  | keyword |
| rsa.misc.p_msgid1 |  | keyword |
| rsa.misc.p_msgid2 |  | keyword |
| rsa.misc.p_result1 |  | keyword |
| rsa.misc.param | This key is the parameters passed as part of a command or application, etc. | keyword |
| rsa.misc.param_dst | This key captures the command line/launch argument of the target process or file | keyword |
| rsa.misc.param_src | This key captures source parameter | keyword |
| rsa.misc.parent_node | This key captures the Parent Node Name. Must be related to node variable. | keyword |
| rsa.misc.password_chg |  | keyword |
| rsa.misc.password_expire |  | keyword |
| rsa.misc.payload_dst | This key is used to capture destination payload | keyword |
| rsa.misc.payload_src | This key is used to capture source payload | keyword |
| rsa.misc.permgranted |  | keyword |
| rsa.misc.permwanted |  | keyword |
| rsa.misc.pgid |  | keyword |
| rsa.misc.phone |  | keyword |
| rsa.misc.pid |  | keyword |
| rsa.misc.policy |  | keyword |
| rsa.misc.policyUUID |  | keyword |
| rsa.misc.policy_id | This key is used to capture the Policy ID only, this should be a numeric value, use policy.name otherwise | keyword |
| rsa.misc.policy_name | This key is used to capture the Policy Name only. | keyword |
| rsa.misc.policy_value | This key captures the contents of the policy. This contains details about the policy | keyword |
| rsa.misc.policy_waiver |  | keyword |
| rsa.misc.pool_id | This key captures the identifier (typically numeric field) of a resource pool | keyword |
| rsa.misc.pool_name | This key captures the name of a resource pool | keyword |
| rsa.misc.port_name | This key is used for Physical or logical port connection but does NOT include a network port. (Example: Printer port name). | keyword |
| rsa.misc.priority |  | keyword |
| rsa.misc.process_id_val | This key is a failure key for Process ID when it is not an integer value | keyword |
| rsa.misc.prog_asp_num |  | keyword |
| rsa.misc.program |  | keyword |
| rsa.misc.real_data |  | keyword |
| rsa.misc.reason |  | keyword |
| rsa.misc.rec_asp_device |  | keyword |
| rsa.misc.rec_asp_num |  | keyword |
| rsa.misc.rec_library |  | keyword |
| rsa.misc.recordnum |  | keyword |
| rsa.misc.reference_id | This key is used to capture an event id from the session directly | keyword |
| rsa.misc.reference_id1 | This key is for Linked ID to be used as an addition to "reference.id" | keyword |
| rsa.misc.reference_id2 | This key is for the 2nd Linked ID. Can be either linked to "reference.id" or "reference.id1" value but should not be used unless the other two variables are in play. | keyword |
| rsa.misc.result | This key is used to capture the outcome/result string value of an action in a session. | keyword |
| rsa.misc.result_code | This key is used to capture the outcome/result numeric value of an action in a session | keyword |
| rsa.misc.risk | This key captures the non-numeric risk value | keyword |
| rsa.misc.risk_info | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.risk_num | This key captures a Numeric Risk value | double |
| rsa.misc.risk_num_comm | This key captures Risk Number Community | double |
| rsa.misc.risk_num_next | This key captures Risk Number NextGen | double |
| rsa.misc.risk_num_sand | This key captures Risk Number SandBox | double |
| rsa.misc.risk_num_static | This key captures Risk Number Static | double |
| rsa.misc.risk_suspicious | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.risk_warning | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.ruid |  | keyword |
| rsa.misc.rule | This key captures the Rule number | keyword |
| rsa.misc.rule_group | This key captures the Rule group name | keyword |
| rsa.misc.rule_name | This key captures the Rule Name | keyword |
| rsa.misc.rule_template | A default set of parameters which are overlayed onto a rule (or rulename) which efffectively constitutes a template | keyword |
| rsa.misc.rule_uid | This key is the Unique Identifier for a rule. | keyword |
| rsa.misc.sburb |  | keyword |
| rsa.misc.sdomain_fld |  | keyword |
| rsa.misc.search_text | This key captures the Search Text used | keyword |
| rsa.misc.sec |  | keyword |
| rsa.misc.second |  | keyword |
| rsa.misc.sensor | This key captures Name of the sensor. Typically used in IDS/IPS based devices | keyword |
| rsa.misc.sensorname |  | keyword |
| rsa.misc.seqnum |  | keyword |
| rsa.misc.serial_number | This key is the Serial number associated with a physical asset. | keyword |
| rsa.misc.session |  | keyword |
| rsa.misc.sessiontype |  | keyword |
| rsa.misc.severity | This key is used to capture the severity given the session | keyword |
| rsa.misc.sigUUID |  | keyword |
| rsa.misc.sig_id | This key captures IDS/IPS Int Signature ID | long |
| rsa.misc.sig_id1 | This key captures IDS/IPS Int Signature ID. This must be linked to the sig.id | long |
| rsa.misc.sig_id_str | This key captures a string object of the sigid variable. | keyword |
| rsa.misc.sig_name | This key is used to capture the Signature Name only. | keyword |
| rsa.misc.sigcat |  | keyword |
| rsa.misc.snmp_oid | SNMP Object Identifier | keyword |
| rsa.misc.snmp_value | SNMP set request value | keyword |
| rsa.misc.space |  | keyword |
| rsa.misc.space1 |  | keyword |
| rsa.misc.spi |  | keyword |
| rsa.misc.spi_dst | Destination SPI Index | keyword |
| rsa.misc.spi_src | Source SPI Index | keyword |
| rsa.misc.sql | This key captures the SQL query | keyword |
| rsa.misc.srcburb |  | keyword |
| rsa.misc.srcdom |  | keyword |
| rsa.misc.srcservice |  | keyword |
| rsa.misc.state |  | keyword |
| rsa.misc.status |  | keyword |
| rsa.misc.status1 |  | keyword |
| rsa.misc.streams | This key captures number of streams in session | long |
| rsa.misc.subcategory |  | keyword |
| rsa.misc.svcno |  | keyword |
| rsa.misc.system |  | keyword |
| rsa.misc.tbdstr1 |  | keyword |
| rsa.misc.tbdstr2 |  | keyword |
| rsa.misc.tcp_flags | This key is captures the TCP flags set in any packet of session | long |
| rsa.misc.terminal | This key captures the Terminal Names only | keyword |
| rsa.misc.tgtdom |  | keyword |
| rsa.misc.tgtdomain |  | keyword |
| rsa.misc.threshold |  | keyword |
| rsa.misc.tos | This key describes the type of service | long |
| rsa.misc.trigger_desc | This key captures the Description of the trigger or threshold condition. | keyword |
| rsa.misc.trigger_val | This key captures the Value of the trigger or threshold condition. | keyword |
| rsa.misc.type |  | keyword |
| rsa.misc.type1 |  | keyword |
| rsa.misc.udb_class |  | keyword |
| rsa.misc.url_fld |  | keyword |
| rsa.misc.user_div |  | keyword |
| rsa.misc.userid |  | keyword |
| rsa.misc.username_fld |  | keyword |
| rsa.misc.utcstamp |  | keyword |
| rsa.misc.v_instafname |  | keyword |
| rsa.misc.version | This key captures Version of the application or OS which is generating the event. | keyword |
| rsa.misc.virt_data |  | keyword |
| rsa.misc.virusname | This key captures the name of the virus | keyword |
| rsa.misc.vm_target | VMWare Target \*\*VMWARE\*\* only varaible. | keyword |
| rsa.misc.vpnid |  | keyword |
| rsa.misc.vsys | This key captures Virtual System Name | keyword |
| rsa.misc.vuln_ref | This key captures the Vulnerability Reference details | keyword |
| rsa.misc.workspace | This key captures Workspace Description | keyword |
| rsa.network.ad_computer_dst | Deprecated, use host.dst | keyword |
| rsa.network.addr |  | keyword |
| rsa.network.alias_host | This key should be used when the source or destination context of a hostname is not clear.Also it captures the Device Hostname. Any Hostname that isnt ad.computer. | keyword |
| rsa.network.dinterface | This key should only be used when it’s a Destination Interface | keyword |
| rsa.network.dmask | This key is used for Destionation Device network mask | keyword |
| rsa.network.dns_a_record |  | keyword |
| rsa.network.dns_cname_record |  | keyword |
| rsa.network.dns_id |  | keyword |
| rsa.network.dns_opcode |  | keyword |
| rsa.network.dns_ptr_record |  | keyword |
| rsa.network.dns_resp |  | keyword |
| rsa.network.dns_type |  | keyword |
| rsa.network.domain |  | keyword |
| rsa.network.domain1 |  | keyword |
| rsa.network.eth_host | Deprecated, use alias.mac | keyword |
| rsa.network.eth_type | This key is used to capture Ethernet Type, Used for Layer 3 Protocols Only | long |
| rsa.network.faddr |  | keyword |
| rsa.network.fhost |  | keyword |
| rsa.network.fport |  | keyword |
| rsa.network.gateway | This key is used to capture the IP Address of the gateway | keyword |
| rsa.network.host_dst | This key should only be used when it’s a Destination Hostname | keyword |
| rsa.network.host_orig | This is used to capture the original hostname in case of a Forwarding Agent or a Proxy in between. | keyword |
| rsa.network.host_type |  | keyword |
| rsa.network.icmp_code | This key is used to capture the ICMP code only | long |
| rsa.network.icmp_type | This key is used to capture the ICMP type only | long |
| rsa.network.interface | This key should be used when the source or destination context of an interface is not clear | keyword |
| rsa.network.ip_proto | This key should be used to capture the Protocol number, all the protocol nubers are converted into string in UI | long |
| rsa.network.laddr |  | keyword |
| rsa.network.lhost |  | keyword |
| rsa.network.linterface |  | keyword |
| rsa.network.mask | This key is used to capture the device network IPmask. | keyword |
| rsa.network.netname | This key is used to capture the network name associated with an IP range. This is configured by the end user. | keyword |
| rsa.network.network_port | Deprecated, use port. NOTE: There is a type discrepancy as currently used, TM: Int32, INDEX: UInt64 (why neither chose the correct UInt16?!) | long |
| rsa.network.network_service | This is used to capture layer 7 protocols/service names | keyword |
| rsa.network.origin |  | keyword |
| rsa.network.packet_length |  | keyword |
| rsa.network.paddr | Deprecated | ip |
| rsa.network.phost |  | keyword |
| rsa.network.port | This key should only be used to capture a Network Port when the directionality is not clear | long |
| rsa.network.protocol_detail | This key should be used to capture additional protocol information | keyword |
| rsa.network.remote_domain_id |  | keyword |
| rsa.network.rpayload | This key is used to capture the total number of payload bytes seen in the retransmitted packets. | keyword |
| rsa.network.sinterface | This key should only be used when it’s a Source Interface | keyword |
| rsa.network.smask | This key is used for capturing source Network Mask | keyword |
| rsa.network.vlan | This key should only be used to capture the ID of the Virtual LAN | long |
| rsa.network.vlan_name | This key should only be used to capture the name of the Virtual LAN | keyword |
| rsa.network.zone | This key should be used when the source or destination context of a Zone is not clear | keyword |
| rsa.network.zone_dst | This key should only be used when it’s a Destination Zone. | keyword |
| rsa.network.zone_src | This key should only be used when it’s a Source Zone. | keyword |
| rsa.physical.org_dst | This is used to capture the destination organization based on the GEOPIP Maxmind database. | keyword |
| rsa.physical.org_src | This is used to capture the source organization based on the GEOPIP Maxmind database. | keyword |
| rsa.storage.disk_volume | A unique name assigned to logical units (volumes) within a physical disk | keyword |
| rsa.storage.lun | Logical Unit Number.This key is a very useful concept in Storage. | keyword |
| rsa.storage.pwwn | This uniquely identifies a port on a HBA. | keyword |
| rsa.threat.alert | This key is used to capture name of the alert | keyword |
| rsa.threat.threat_category | This key captures Threat Name/Threat Category/Categorization of alert | keyword |
| rsa.threat.threat_desc | This key is used to capture the threat description from the session directly or inferred | keyword |
| rsa.threat.threat_source | This key is used to capture source of the threat | keyword |
| rsa.time.date |  | keyword |
| rsa.time.datetime |  | keyword |
| rsa.time.day |  | keyword |
| rsa.time.duration_str | A text string version of the duration | keyword |
| rsa.time.duration_time | This key is used to capture the normalized duration/lifetime in seconds. | double |
| rsa.time.effective_time | This key is the effective time referenced by an individual event in a Standard Timestamp format | date |
| rsa.time.endtime | This key is used to capture the End time mentioned in a session in a standard form | date |
| rsa.time.event_queue_time | This key is the Time that the event was queued. | date |
| rsa.time.event_time | This key is used to capture the time mentioned in a raw session that represents the actual time an event occured in a standard normalized form | date |
| rsa.time.event_time_str | This key is used to capture the incomplete time mentioned in a session as a string | keyword |
| rsa.time.eventtime |  | keyword |
| rsa.time.expire_time | This key is the timestamp that explicitly refers to an expiration. | date |
| rsa.time.expire_time_str | This key is used to capture incomplete timestamp that explicitly refers to an expiration. | keyword |
| rsa.time.gmtdate |  | keyword |
| rsa.time.gmttime |  | keyword |
| rsa.time.hour |  | keyword |
| rsa.time.min |  | keyword |
| rsa.time.month |  | keyword |
| rsa.time.p_date |  | keyword |
| rsa.time.p_month |  | keyword |
| rsa.time.p_time |  | keyword |
| rsa.time.p_time1 |  | keyword |
| rsa.time.p_time2 |  | keyword |
| rsa.time.p_year |  | keyword |
| rsa.time.process_time | Deprecated, use duration.time | keyword |
| rsa.time.recorded_time | The event time as recorded by the system the event is collected from. The usage scenario is a multi-tier application where the management layer of the system records it's own timestamp at the time of collection from its child nodes. Must be in timestamp format. | date |
| rsa.time.stamp | Deprecated key defined only in table map. | date |
| rsa.time.starttime | This key is used to capture the Start time mentioned in a session in a standard form | date |
| rsa.time.timestamp |  | keyword |
| rsa.time.timezone | This key is used to capture the timezone of the Event Time | keyword |
| rsa.time.tzone |  | keyword |
| rsa.time.year |  | keyword |
| rsa.web.alias_host |  | keyword |
| rsa.web.cn_asn_dst |  | keyword |
| rsa.web.cn_rpackets |  | keyword |
| rsa.web.fqdn | Fully Qualified Domain Names | keyword |
| rsa.web.p_url |  | keyword |
| rsa.web.p_user_agent |  | keyword |
| rsa.web.p_web_cookie |  | keyword |
| rsa.web.p_web_method |  | keyword |
| rsa.web.p_web_referer |  | keyword |
| rsa.web.remote_domain |  | keyword |
| rsa.web.reputation_num | Reputation Number of an entity. Typically used for Web Domains | double |
| rsa.web.urlpage |  | keyword |
| rsa.web.urlroot |  | keyword |
| rsa.web.web_cookie | This key is used to capture the Web cookies specifically. | keyword |
| rsa.web.web_extension_tmp |  | keyword |
| rsa.web.web_page |  | keyword |
| rsa.web.web_ref_domain | Web referer's domain | keyword |
| rsa.web.web_ref_page | This key captures Web referer's page information | keyword |
| rsa.web.web_ref_query | This key captures Web referer's query portion of the URL | keyword |
| rsa.web.web_ref_root | Web referer's root URL path | keyword |
| rsa.wireless.access_point | This key is used to capture the access point name. | keyword |
| rsa.wireless.wlan_channel | This is used to capture the channel names | long |
| rsa.wireless.wlan_name | This key captures either WLAN number/name | keyword |
| rsa.wireless.wlan_ssid | This key is used to capture the ssid of a Wireless Session | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.registered_domain | The highest registered server domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| server.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| server.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.port | Port of the source. | long |
| source.registered_domain | The highest registered source domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| source.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| source.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |


### Fortimail

The `fortimail` dataset collects Fortinet FortiMail logs.

An example event for `fortimail` looks as following:

```json
{
    "@timestamp": "2016-01-29T06:09:59.000Z",
    "agent": {
        "ephemeral_id": "821504b9-6e80-4572-aae7-c5bb3cf38906",
        "id": "4e3f135a-d5f9-40b6-ae01-2c834ecbead0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "fortinet.fortimail",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "4e3f135a-d5f9-40b6-ae01-2c834ecbead0",
        "snapshot": true,
        "version": "8.0.0"
    },
    "event": {
        "action": "event",
        "agent_id_status": "verified",
        "code": "nes",
        "dataset": "fortinet.fortimail",
        "ingested": "2022-01-25T12:29:32Z",
        "original": "date=2016-1-29 time=06:09:59 device_id=pexe log_id=nes log_part=eab type=event subtype=update pri=high msg=\"boNemoe\"\n",
        "timezone": "+00:00"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "level": "high",
        "source": {
            "address": "172.30.0.4:44540"
        }
    },
    "observer": {
        "product": "FortiMail",
        "type": "Firewall",
        "vendor": "Fortinet"
    },
    "rsa": {
        "internal": {
            "event_desc": "boNemoe",
            "messageid": "event_update"
        },
        "misc": {
            "category": "update",
            "event_type": "event",
            "hardware_id": "pexe",
            "msgIdPart1": "event",
            "msgIdPart2": "update",
            "reference_id": "nes",
            "reference_id1": "eab",
            "severity": "high"
        },
        "time": {
            "event_time": "2016-01-29T06:09:59.000Z"
        }
    },
    "tags": [
        "preserve_original_event",
        "fortinet-fortimail",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.registered_domain | The highest registered client domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| client.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| client.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
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
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.port | Port of the destination. | long |
| destination.registered_domain | The highest registered destination domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| destination.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| destination.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.question.domain | Server domain. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| file.attributes | Array of file attributes. Attributes names will vary by platform. Here's a non-exhaustive list of values that are expected in this field: archive, compressed, directory, encrypted, execute, hidden, read, readonly, system, write. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.type | File type (file, dir, or symlink). | keyword |
| geo.city_name | City name. | keyword |
| geo.country_name | Country name. | keyword |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| geo.region_name | Region name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.interface.name |  | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.parent.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.parent.title.text | Multi-field of `process.parent.title`. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rsa.counters.dclass_c1 | This is a generic counter key that should be used with the label dclass.c1.str only | long |
| rsa.counters.dclass_c1_str | This is a generic counter string key that should be used with the label dclass.c1 only | keyword |
| rsa.counters.dclass_c2 | This is a generic counter key that should be used with the label dclass.c2.str only | long |
| rsa.counters.dclass_c2_str | This is a generic counter string key that should be used with the label dclass.c2 only | keyword |
| rsa.counters.dclass_c3 | This is a generic counter key that should be used with the label dclass.c3.str only | long |
| rsa.counters.dclass_c3_str | This is a generic counter string key that should be used with the label dclass.c3 only | keyword |
| rsa.counters.dclass_r1 | This is a generic ratio key that should be used with the label dclass.r1.str only | keyword |
| rsa.counters.dclass_r1_str | This is a generic ratio string key that should be used with the label dclass.r1 only | keyword |
| rsa.counters.dclass_r2 | This is a generic ratio key that should be used with the label dclass.r2.str only | keyword |
| rsa.counters.dclass_r2_str | This is a generic ratio string key that should be used with the label dclass.r2 only | keyword |
| rsa.counters.dclass_r3 | This is a generic ratio key that should be used with the label dclass.r3.str only | keyword |
| rsa.counters.dclass_r3_str | This is a generic ratio string key that should be used with the label dclass.r3 only | keyword |
| rsa.counters.event_counter | This is used to capture the number of times an event repeated | long |
| rsa.crypto.cert_ca | This key is used to capture the Certificate signing authority only | keyword |
| rsa.crypto.cert_checksum |  | keyword |
| rsa.crypto.cert_common | This key is used to capture the Certificate common name only | keyword |
| rsa.crypto.cert_error | This key captures the Certificate Error String | keyword |
| rsa.crypto.cert_host_cat | This key is used for the hostname category value of a certificate | keyword |
| rsa.crypto.cert_host_name | Deprecated key defined only in table map. | keyword |
| rsa.crypto.cert_issuer |  | keyword |
| rsa.crypto.cert_keysize |  | keyword |
| rsa.crypto.cert_serial | This key is used to capture the Certificate serial number only | keyword |
| rsa.crypto.cert_status | This key captures Certificate validation status | keyword |
| rsa.crypto.cert_subject | This key is used to capture the Certificate organization only | keyword |
| rsa.crypto.cert_username |  | keyword |
| rsa.crypto.cipher_dst | This key is for Destination (Server) Cipher | keyword |
| rsa.crypto.cipher_size_dst | This key captures Destination (Server) Cipher Size | long |
| rsa.crypto.cipher_size_src | This key captures Source (Client) Cipher Size | long |
| rsa.crypto.cipher_src | This key is for Source (Client) Cipher | keyword |
| rsa.crypto.crypto | This key is used to capture the Encryption Type or Encryption Key only | keyword |
| rsa.crypto.d_certauth |  | keyword |
| rsa.crypto.https_insact |  | keyword |
| rsa.crypto.https_valid |  | keyword |
| rsa.crypto.ike | IKE negotiation phase. | keyword |
| rsa.crypto.ike_cookie1 | ID of the negotiation — sent for ISAKMP Phase One | keyword |
| rsa.crypto.ike_cookie2 | ID of the negotiation — sent for ISAKMP Phase Two | keyword |
| rsa.crypto.peer | This key is for Encryption peer's IP Address | keyword |
| rsa.crypto.peer_id | This key is for Encryption peer’s identity | keyword |
| rsa.crypto.s_certauth |  | keyword |
| rsa.crypto.scheme | This key captures the Encryption scheme used | keyword |
| rsa.crypto.sig_type | This key captures the Signature Type | keyword |
| rsa.crypto.ssl_ver_dst | Deprecated, use version | keyword |
| rsa.crypto.ssl_ver_src | Deprecated, use version | keyword |
| rsa.db.database | This key is used to capture the name of a database or an instance as seen in a session | keyword |
| rsa.db.db_id | This key is used to capture the unique identifier for a database | keyword |
| rsa.db.db_pid | This key captures the process id of a connection with database server | long |
| rsa.db.index | This key captures IndexID of the index. | keyword |
| rsa.db.instance | This key is used to capture the database server instance name | keyword |
| rsa.db.lread | This key is used for the number of logical reads | long |
| rsa.db.lwrite | This key is used for the number of logical writes | long |
| rsa.db.permissions | This key captures permission or privilege level assigned to a resource. | keyword |
| rsa.db.pread | This key is used for the number of physical writes | long |
| rsa.db.table_name | This key is used to capture the table name | keyword |
| rsa.db.transact_id | This key captures the SQL transantion ID of the current session | keyword |
| rsa.email.email | This key is used to capture a generic email address where the source or destination context is not clear | keyword |
| rsa.email.email_dst | This key is used to capture the Destination email address only, when the destination context is not clear use email | keyword |
| rsa.email.email_src | This key is used to capture the source email address only, when the source context is not clear use email | keyword |
| rsa.email.subject | This key is used to capture the subject string from an Email only. | keyword |
| rsa.email.trans_from | Deprecated key defined only in table map. | keyword |
| rsa.email.trans_to | Deprecated key defined only in table map. | keyword |
| rsa.endpoint.host_state | This key is used to capture the current state of the machine, such as \<strong\>blacklisted\</strong\>, \<strong\>infected\</strong\>, \<strong\>firewall disabled\</strong\> and so on | keyword |
| rsa.endpoint.registry_key | This key captures the path to the registry key | keyword |
| rsa.endpoint.registry_value | This key captures values or decorators used within a registry entry | keyword |
| rsa.file.attachment | This key captures the attachment file name | keyword |
| rsa.file.binary | Deprecated key defined only in table map. | keyword |
| rsa.file.directory_dst | \<span\>This key is used to capture the directory of the target process or file\</span\> | keyword |
| rsa.file.directory_src | This key is used to capture the directory of the source process or file | keyword |
| rsa.file.file_entropy | This is used to capture entropy vale of a file | double |
| rsa.file.file_vendor | This is used to capture Company name of file located in version_info | keyword |
| rsa.file.filename_dst | This is used to capture name of the file targeted by the action | keyword |
| rsa.file.filename_src | This is used to capture name of the parent filename, the file which performed the action | keyword |
| rsa.file.filename_tmp |  | keyword |
| rsa.file.filesystem |  | keyword |
| rsa.file.privilege | Deprecated, use permissions | keyword |
| rsa.file.task_name | This is used to capture name of the task | keyword |
| rsa.healthcare.patient_fname | This key is for First Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.healthcare.patient_id | This key captures the unique ID for a patient | keyword |
| rsa.healthcare.patient_lname | This key is for Last Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.healthcare.patient_mname | This key is for Middle Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.accesses | This key is used to capture actual privileges used in accessing an object | keyword |
| rsa.identity.auth_method | This key is used to capture authentication methods used only | keyword |
| rsa.identity.dn | X.500 (LDAP) Distinguished Name | keyword |
| rsa.identity.dn_dst | An X.500 (LDAP) Distinguished name that used in a context that indicates a Destination dn | keyword |
| rsa.identity.dn_src | An X.500 (LDAP) Distinguished name that is used in a context that indicates a Source dn | keyword |
| rsa.identity.federated_idp | This key is the federated Identity Provider. This is the server providing the authentication. | keyword |
| rsa.identity.federated_sp | This key is the Federated Service Provider. This is the application requesting authentication. | keyword |
| rsa.identity.firstname | This key is for First Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.host_role | This key should only be used to capture the role of a Host Machine | keyword |
| rsa.identity.lastname | This key is for Last Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.ldap | This key is for Uninterpreted LDAP values. Ldap Values that don’t have a clear query or response context | keyword |
| rsa.identity.ldap_query | This key is the Search criteria from an LDAP search | keyword |
| rsa.identity.ldap_response | This key is to capture Results from an LDAP search | keyword |
| rsa.identity.logon_type | This key is used to capture the type of logon method used. | keyword |
| rsa.identity.logon_type_desc | This key is used to capture the textual description of an integer logon type as stored in the meta key 'logon.type'. | keyword |
| rsa.identity.middlename | This key is for Middle Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.org | This key captures the User organization | keyword |
| rsa.identity.owner | This is used to capture username the process or service is running as, the author of the task | keyword |
| rsa.identity.password | This key is for Passwords seen in any session, plain text or encrypted | keyword |
| rsa.identity.profile | This key is used to capture the user profile | keyword |
| rsa.identity.realm | Radius realm or similar grouping of accounts | keyword |
| rsa.identity.service_account | This key is a windows specific key, used for capturing name of the account a service (referenced in the event) is running under. Legacy Usage | keyword |
| rsa.identity.user_dept | User's Department Names only | keyword |
| rsa.identity.user_role | This key is used to capture the Role of a user only | keyword |
| rsa.identity.user_sid_dst | This key captures Destination User Session ID | keyword |
| rsa.identity.user_sid_src | This key captures Source User Session ID | keyword |
| rsa.internal.audit_class | Deprecated key defined only in table map. | keyword |
| rsa.internal.cid | This is the unique identifier used to identify a NetWitness Concentrator. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.data | Deprecated key defined only in table map. | keyword |
| rsa.internal.dead | Deprecated key defined only in table map. | long |
| rsa.internal.device_class | This is the Classification of the Log Event Source under a predefined fixed set of Event Source Classifications. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_group | This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_host | This is the Hostname of the log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_ip | This is the IPv4 address of the Log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.device_ipv6 | This is the IPv6 address of the Log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.device_type | This is the name of the log parser which parsed a given session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_type_id | Deprecated key defined only in table map. | long |
| rsa.internal.did | This is the unique identifier used to identify a NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.entropy_req | This key is only used by the Entropy Parser, the Meta Type can be either UInt16 or Float32 based on the configuration | long |
| rsa.internal.entropy_res | This key is only used by the Entropy Parser, the Meta Type can be either UInt16 or Float32 based on the configuration | long |
| rsa.internal.entry | Deprecated key defined only in table map. | keyword |
| rsa.internal.event_desc |  | keyword |
| rsa.internal.event_name | Deprecated key defined only in table map. | keyword |
| rsa.internal.feed_category | This is used to capture the category of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.feed_desc | This is used to capture the description of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.feed_name | This is used to capture the name of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.forward_ip | This key should be used to capture the IPV4 address of a relay system which forwarded the events from the original system to NetWitness. | ip |
| rsa.internal.forward_ipv6 | This key is used to capture the IPV6 address of a relay system which forwarded the events from the original system to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.hcode | Deprecated key defined only in table map. | keyword |
| rsa.internal.header_id | This is the Header ID value that identifies the exact log parser header definition that parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.inode | Deprecated key defined only in table map. | long |
| rsa.internal.lc_cid | This is a unique Identifier of a Log Collector. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.lc_ctime | This is the time at which a log is collected in a NetWitness Log Collector. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | date |
| rsa.internal.level | Deprecated key defined only in table map. | long |
| rsa.internal.mcb_req | This key is only used by the Entropy Parser, the most common byte request is simply which byte for each side (0 thru 255) was seen the most | long |
| rsa.internal.mcb_res | This key is only used by the Entropy Parser, the most common byte response is simply which byte for each side (0 thru 255) was seen the most | long |
| rsa.internal.mcbc_req | This key is only used by the Entropy Parser, the most common byte count is the number of times the most common byte (above) was seen in the session streams | long |
| rsa.internal.mcbc_res | This key is only used by the Entropy Parser, the most common byte count is the number of times the most common byte (above) was seen in the session streams | long |
| rsa.internal.medium | This key is used to identify if it’s a log/packet session or Layer 2 Encapsulation Type. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness. 32 = log, 33 = correlation session, &lt; 32 is packet session | long |
| rsa.internal.message | This key captures the contents of instant messages | keyword |
| rsa.internal.messageid |  | keyword |
| rsa.internal.msg | This key is used to capture the raw message that comes into the Log Decoder | keyword |
| rsa.internal.msg_id | This is the Message ID1 value that identifies the exact log parser definition which parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.msg_vid | This is the Message ID2 value that identifies the exact log parser definition which parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.node_name | Deprecated key defined only in table map. | keyword |
| rsa.internal.nwe_callback_id | This key denotes that event is endpoint related | keyword |
| rsa.internal.obj_id | Deprecated key defined only in table map. | keyword |
| rsa.internal.obj_server | Deprecated key defined only in table map. | keyword |
| rsa.internal.obj_val | Deprecated key defined only in table map. | keyword |
| rsa.internal.parse_error | This is a special key that stores any Meta key validation error found while parsing a log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.payload_req | This key is only used by the Entropy Parser, the payload size metrics are the payload sizes of each session side at the time of parsing. However, in order to keep | long |
| rsa.internal.payload_res | This key is only used by the Entropy Parser, the payload size metrics are the payload sizes of each session side at the time of parsing. However, in order to keep | long |
| rsa.internal.process_vid_dst | Endpoint generates and uses a unique virtual ID to identify any similar group of process. This ID represents the target process. | keyword |
| rsa.internal.process_vid_src | Endpoint generates and uses a unique virtual ID to identify any similar group of process. This ID represents the source process. | keyword |
| rsa.internal.resource | Deprecated key defined only in table map. | keyword |
| rsa.internal.resource_class | Deprecated key defined only in table map. | keyword |
| rsa.internal.rid | This is a special ID of the Remote Session created by NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | long |
| rsa.internal.session_split | This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.site | Deprecated key defined only in table map. | keyword |
| rsa.internal.size | This is the size of the session as seen by the NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | long |
| rsa.internal.sourcefile | This is the name of the log file or PCAPs that can be imported into NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.statement | Deprecated key defined only in table map. | keyword |
| rsa.internal.time | This is the time at which a session hits a NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness. | date |
| rsa.internal.ubc_req | This key is only used by the Entropy Parser, Unique byte count is the number of unique bytes seen in each stream. 256 would mean all byte values of 0 thru 255 were seen at least once | long |
| rsa.internal.ubc_res | This key is only used by the Entropy Parser, Unique byte count is the number of unique bytes seen in each stream. 256 would mean all byte values of 0 thru 255 were seen at least once | long |
| rsa.internal.word | This is used by the Word Parsing technology to capture the first 5 character of every word in an unparsed log | keyword |
| rsa.investigations.analysis_file | This is used to capture all indicators used in a File Analysis. This key should be used to capture an analysis of a file | keyword |
| rsa.investigations.analysis_service | This is used to capture all indicators used in a Service Analysis. This key should be used to capture an analysis of a service | keyword |
| rsa.investigations.analysis_session | This is used to capture all indicators used for a Session Analysis. This key should be used to capture an analysis of a session | keyword |
| rsa.investigations.boc | This is used to capture behaviour of compromise | keyword |
| rsa.investigations.ec_activity | This key captures the particular event activity(Ex:Logoff) | keyword |
| rsa.investigations.ec_outcome | This key captures the outcome of a particular Event(Ex:Success) | keyword |
| rsa.investigations.ec_subject | This key captures the Subject of a particular Event(Ex:User) | keyword |
| rsa.investigations.ec_theme | This key captures the Theme of a particular Event(Ex:Authentication) | keyword |
| rsa.investigations.eoc | This is used to capture Enablers of Compromise | keyword |
| rsa.investigations.event_cat | This key captures the Event category number | long |
| rsa.investigations.event_cat_name | This key captures the event category name corresponding to the event cat code | keyword |
| rsa.investigations.event_vcat | This is a vendor supplied category. This should be used in situations where the vendor has adopted their own event_category taxonomy. | keyword |
| rsa.investigations.inv_category | This used to capture investigation category | keyword |
| rsa.investigations.inv_context | This used to capture investigation context | keyword |
| rsa.investigations.ioc | This is key capture indicator of compromise | keyword |
| rsa.misc.OS | This key captures the Name of the Operating System | keyword |
| rsa.misc.acl_id |  | keyword |
| rsa.misc.acl_op |  | keyword |
| rsa.misc.acl_pos |  | keyword |
| rsa.misc.acl_table |  | keyword |
| rsa.misc.action |  | keyword |
| rsa.misc.admin |  | keyword |
| rsa.misc.agent_id | This key is used to capture agent id | keyword |
| rsa.misc.alarm_id |  | keyword |
| rsa.misc.alarmname |  | keyword |
| rsa.misc.alert_id | Deprecated, New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.app_id |  | keyword |
| rsa.misc.audit |  | keyword |
| rsa.misc.audit_object |  | keyword |
| rsa.misc.auditdata |  | keyword |
| rsa.misc.autorun_type | This is used to capture Auto Run type | keyword |
| rsa.misc.benchmark |  | keyword |
| rsa.misc.bypass |  | keyword |
| rsa.misc.cache |  | keyword |
| rsa.misc.cache_hit |  | keyword |
| rsa.misc.category | This key is used to capture the category of an event given by the vendor in the session | keyword |
| rsa.misc.cc_number | Valid Credit Card Numbers only | long |
| rsa.misc.cefversion |  | keyword |
| rsa.misc.cfg_attr |  | keyword |
| rsa.misc.cfg_obj |  | keyword |
| rsa.misc.cfg_path |  | keyword |
| rsa.misc.change_attrib | This key is used to capture the name of the attribute that’s changing in a session | keyword |
| rsa.misc.change_new | This key is used to capture the new values of the attribute that’s changing in a session | keyword |
| rsa.misc.change_old | This key is used to capture the old value of the attribute that’s changing in a session | keyword |
| rsa.misc.changes |  | keyword |
| rsa.misc.checksum | This key is used to capture the checksum or hash of the entity such as a file or process. Checksum should be used over checksum.src or checksum.dst when it is unclear whether the entity is a source or target of an action. | keyword |
| rsa.misc.checksum_dst | This key is used to capture the checksum or hash of the the target entity such as a process or file. | keyword |
| rsa.misc.checksum_src | This key is used to capture the checksum or hash of the source entity such as a file or process. | keyword |
| rsa.misc.client | This key is used to capture only the name of the client application requesting resources of the server. See the user.agent meta key for capture of the specific user agent identifier or browser identification string. | keyword |
| rsa.misc.client_ip |  | keyword |
| rsa.misc.clustermembers |  | keyword |
| rsa.misc.cmd |  | keyword |
| rsa.misc.cn_acttimeout |  | keyword |
| rsa.misc.cn_asn_src |  | keyword |
| rsa.misc.cn_bgpv4nxthop |  | keyword |
| rsa.misc.cn_ctr_dst_code |  | keyword |
| rsa.misc.cn_dst_tos |  | keyword |
| rsa.misc.cn_dst_vlan |  | keyword |
| rsa.misc.cn_engine_id |  | keyword |
| rsa.misc.cn_engine_type |  | keyword |
| rsa.misc.cn_f_switch |  | keyword |
| rsa.misc.cn_flowsampid |  | keyword |
| rsa.misc.cn_flowsampintv |  | keyword |
| rsa.misc.cn_flowsampmode |  | keyword |
| rsa.misc.cn_inacttimeout |  | keyword |
| rsa.misc.cn_inpermbyts |  | keyword |
| rsa.misc.cn_inpermpckts |  | keyword |
| rsa.misc.cn_invalid |  | keyword |
| rsa.misc.cn_ip_proto_ver |  | keyword |
| rsa.misc.cn_ipv4_ident |  | keyword |
| rsa.misc.cn_l_switch |  | keyword |
| rsa.misc.cn_log_did |  | keyword |
| rsa.misc.cn_log_rid |  | keyword |
| rsa.misc.cn_max_ttl |  | keyword |
| rsa.misc.cn_maxpcktlen |  | keyword |
| rsa.misc.cn_min_ttl |  | keyword |
| rsa.misc.cn_minpcktlen |  | keyword |
| rsa.misc.cn_mpls_lbl_1 |  | keyword |
| rsa.misc.cn_mpls_lbl_10 |  | keyword |
| rsa.misc.cn_mpls_lbl_2 |  | keyword |
| rsa.misc.cn_mpls_lbl_3 |  | keyword |
| rsa.misc.cn_mpls_lbl_4 |  | keyword |
| rsa.misc.cn_mpls_lbl_5 |  | keyword |
| rsa.misc.cn_mpls_lbl_6 |  | keyword |
| rsa.misc.cn_mpls_lbl_7 |  | keyword |
| rsa.misc.cn_mpls_lbl_8 |  | keyword |
| rsa.misc.cn_mpls_lbl_9 |  | keyword |
| rsa.misc.cn_mplstoplabel |  | keyword |
| rsa.misc.cn_mplstoplabip |  | keyword |
| rsa.misc.cn_mul_dst_byt |  | keyword |
| rsa.misc.cn_mul_dst_pks |  | keyword |
| rsa.misc.cn_muligmptype |  | keyword |
| rsa.misc.cn_sampalgo |  | keyword |
| rsa.misc.cn_sampint |  | keyword |
| rsa.misc.cn_seqctr |  | keyword |
| rsa.misc.cn_spackets |  | keyword |
| rsa.misc.cn_src_tos |  | keyword |
| rsa.misc.cn_src_vlan |  | keyword |
| rsa.misc.cn_sysuptime |  | keyword |
| rsa.misc.cn_template_id |  | keyword |
| rsa.misc.cn_totbytsexp |  | keyword |
| rsa.misc.cn_totflowexp |  | keyword |
| rsa.misc.cn_totpcktsexp |  | keyword |
| rsa.misc.cn_unixnanosecs |  | keyword |
| rsa.misc.cn_v6flowlabel |  | keyword |
| rsa.misc.cn_v6optheaders |  | keyword |
| rsa.misc.code |  | keyword |
| rsa.misc.command |  | keyword |
| rsa.misc.comments | Comment information provided in the log message | keyword |
| rsa.misc.comp_class |  | keyword |
| rsa.misc.comp_name |  | keyword |
| rsa.misc.comp_rbytes |  | keyword |
| rsa.misc.comp_sbytes |  | keyword |
| rsa.misc.comp_version | This key captures the Version level of a sub-component of a product. | keyword |
| rsa.misc.connection_id | This key captures the Connection ID | keyword |
| rsa.misc.content | This key captures the content type from protocol headers | keyword |
| rsa.misc.content_type | This key is used to capture Content Type only. | keyword |
| rsa.misc.content_version | This key captures Version level of a signature or database content. | keyword |
| rsa.misc.context | This key captures Information which adds additional context to the event. | keyword |
| rsa.misc.context_subject | This key is to be used in an audit context where the subject is the object being identified | keyword |
| rsa.misc.context_target |  | keyword |
| rsa.misc.count |  | keyword |
| rsa.misc.cpu | This key is the CPU time used in the execution of the event being recorded. | long |
| rsa.misc.cpu_data |  | keyword |
| rsa.misc.criticality |  | keyword |
| rsa.misc.cs_agency_dst |  | keyword |
| rsa.misc.cs_analyzedby |  | keyword |
| rsa.misc.cs_av_other |  | keyword |
| rsa.misc.cs_av_primary |  | keyword |
| rsa.misc.cs_av_secondary |  | keyword |
| rsa.misc.cs_bgpv6nxthop |  | keyword |
| rsa.misc.cs_bit9status |  | keyword |
| rsa.misc.cs_context |  | keyword |
| rsa.misc.cs_control |  | keyword |
| rsa.misc.cs_data |  | keyword |
| rsa.misc.cs_datecret |  | keyword |
| rsa.misc.cs_dst_tld |  | keyword |
| rsa.misc.cs_eth_dst_ven |  | keyword |
| rsa.misc.cs_eth_src_ven |  | keyword |
| rsa.misc.cs_event_uuid |  | keyword |
| rsa.misc.cs_filetype |  | keyword |
| rsa.misc.cs_fld |  | keyword |
| rsa.misc.cs_if_desc |  | keyword |
| rsa.misc.cs_if_name |  | keyword |
| rsa.misc.cs_ip_next_hop |  | keyword |
| rsa.misc.cs_ipv4dstpre |  | keyword |
| rsa.misc.cs_ipv4srcpre |  | keyword |
| rsa.misc.cs_lifetime |  | keyword |
| rsa.misc.cs_log_medium |  | keyword |
| rsa.misc.cs_loginname |  | keyword |
| rsa.misc.cs_modulescore |  | keyword |
| rsa.misc.cs_modulesign |  | keyword |
| rsa.misc.cs_opswatresult |  | keyword |
| rsa.misc.cs_payload |  | keyword |
| rsa.misc.cs_registrant |  | keyword |
| rsa.misc.cs_registrar |  | keyword |
| rsa.misc.cs_represult |  | keyword |
| rsa.misc.cs_rpayload |  | keyword |
| rsa.misc.cs_sampler_name |  | keyword |
| rsa.misc.cs_sourcemodule |  | keyword |
| rsa.misc.cs_streams |  | keyword |
| rsa.misc.cs_targetmodule |  | keyword |
| rsa.misc.cs_v6nxthop |  | keyword |
| rsa.misc.cs_whois_server |  | keyword |
| rsa.misc.cs_yararesult |  | keyword |
| rsa.misc.cve | This key captures CVE (Common Vulnerabilities and Exposures) - an identifier for known information security vulnerabilities. | keyword |
| rsa.misc.data_type |  | keyword |
| rsa.misc.description |  | keyword |
| rsa.misc.device_name | This is used to capture name of the Device associated with the node Like: a physical disk, printer, etc | keyword |
| rsa.misc.devvendor |  | keyword |
| rsa.misc.disposition | This key captures the The end state of an action. | keyword |
| rsa.misc.distance |  | keyword |
| rsa.misc.doc_number | This key captures File Identification number | long |
| rsa.misc.dstburb |  | keyword |
| rsa.misc.edomain |  | keyword |
| rsa.misc.edomaub |  | keyword |
| rsa.misc.ein_number | Employee Identification Numbers only | long |
| rsa.misc.error | This key captures All non successful Error codes or responses | keyword |
| rsa.misc.euid |  | keyword |
| rsa.misc.event_category |  | keyword |
| rsa.misc.event_computer | This key is a windows only concept, where this key is used to capture fully qualified domain name in a windows log. | keyword |
| rsa.misc.event_desc | This key is used to capture a description of an event available directly or inferred | keyword |
| rsa.misc.event_id |  | keyword |
| rsa.misc.event_log | This key captures the Name of the event log | keyword |
| rsa.misc.event_source | This key captures Source of the event that’s not a hostname | keyword |
| rsa.misc.event_state | This key captures the current state of the object/item referenced within the event. Describing an on-going event. | keyword |
| rsa.misc.event_type | This key captures the event category type as specified by the event source. | keyword |
| rsa.misc.event_user | This key is a windows only concept, where this key is used to capture combination of domain name and username in a windows log. | keyword |
| rsa.misc.expected_val | This key captures the Value expected (from the perspective of the device generating the log). | keyword |
| rsa.misc.facility |  | keyword |
| rsa.misc.facilityname |  | keyword |
| rsa.misc.fcatnum | This key captures Filter Category Number. Legacy Usage | keyword |
| rsa.misc.filter | This key captures Filter used to reduce result set | keyword |
| rsa.misc.finterface |  | keyword |
| rsa.misc.flags |  | keyword |
| rsa.misc.forensic_info |  | keyword |
| rsa.misc.found | This is used to capture the results of regex match | keyword |
| rsa.misc.fresult | This key captures the Filter Result | long |
| rsa.misc.gaddr |  | keyword |
| rsa.misc.group | This key captures the Group Name value | keyword |
| rsa.misc.group_id | This key captures Group ID Number (related to the group name) | keyword |
| rsa.misc.group_object | This key captures a collection/grouping of entities. Specific usage | keyword |
| rsa.misc.hardware_id | This key is used to capture unique identifier for a device or system (NOT a Mac address) | keyword |
| rsa.misc.id3 |  | keyword |
| rsa.misc.im_buddyid |  | keyword |
| rsa.misc.im_buddyname |  | keyword |
| rsa.misc.im_client |  | keyword |
| rsa.misc.im_croomid |  | keyword |
| rsa.misc.im_croomtype |  | keyword |
| rsa.misc.im_members |  | keyword |
| rsa.misc.im_userid |  | keyword |
| rsa.misc.im_username |  | keyword |
| rsa.misc.index |  | keyword |
| rsa.misc.inout |  | keyword |
| rsa.misc.ipkt |  | keyword |
| rsa.misc.ipscat |  | keyword |
| rsa.misc.ipspri |  | keyword |
| rsa.misc.job_num | This key captures the Job Number | keyword |
| rsa.misc.jobname |  | keyword |
| rsa.misc.language | This is used to capture list of languages the client support and what it prefers | keyword |
| rsa.misc.latitude |  | keyword |
| rsa.misc.library | This key is used to capture library information in mainframe devices | keyword |
| rsa.misc.lifetime | This key is used to capture the session lifetime in seconds. | long |
| rsa.misc.linenum |  | keyword |
| rsa.misc.link | This key is used to link the sessions together. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.misc.list_name |  | keyword |
| rsa.misc.listnum | This key is used to capture listname or listnumber, primarily for collecting access-list | keyword |
| rsa.misc.load_data |  | keyword |
| rsa.misc.location_floor |  | keyword |
| rsa.misc.location_mark |  | keyword |
| rsa.misc.log_id |  | keyword |
| rsa.misc.log_session_id | This key is used to capture a sessionid from the session directly | keyword |
| rsa.misc.log_session_id1 | This key is used to capture a Linked (Related) Session ID from the session directly | keyword |
| rsa.misc.log_type |  | keyword |
| rsa.misc.logid |  | keyword |
| rsa.misc.logip |  | keyword |
| rsa.misc.logname |  | keyword |
| rsa.misc.longitude |  | keyword |
| rsa.misc.lport |  | keyword |
| rsa.misc.mail_id | This key is used to capture the mailbox id/name | keyword |
| rsa.misc.match | This key is for regex match name from search.ini | keyword |
| rsa.misc.mbug_data |  | keyword |
| rsa.misc.message_body | This key captures the The contents of the message body. | keyword |
| rsa.misc.misc |  | keyword |
| rsa.misc.misc_name |  | keyword |
| rsa.misc.mode |  | keyword |
| rsa.misc.msgIdPart1 |  | keyword |
| rsa.misc.msgIdPart2 |  | keyword |
| rsa.misc.msgIdPart3 |  | keyword |
| rsa.misc.msgIdPart4 |  | keyword |
| rsa.misc.msg_type |  | keyword |
| rsa.misc.msgid |  | keyword |
| rsa.misc.name |  | keyword |
| rsa.misc.netsessid |  | keyword |
| rsa.misc.node | Common use case is the node name within a cluster. The cluster name is reflected by the host name. | keyword |
| rsa.misc.ntype |  | keyword |
| rsa.misc.num |  | keyword |
| rsa.misc.number |  | keyword |
| rsa.misc.number1 |  | keyword |
| rsa.misc.number2 |  | keyword |
| rsa.misc.nwwn |  | keyword |
| rsa.misc.obj_name | This is used to capture name of object | keyword |
| rsa.misc.obj_type | This is used to capture type of object | keyword |
| rsa.misc.object |  | keyword |
| rsa.misc.observed_val | This key captures the Value observed (from the perspective of the device generating the log). | keyword |
| rsa.misc.operation |  | keyword |
| rsa.misc.operation_id | An alert number or operation number. The values should be unique and non-repeating. | keyword |
| rsa.misc.opkt |  | keyword |
| rsa.misc.orig_from |  | keyword |
| rsa.misc.owner_id |  | keyword |
| rsa.misc.p_action |  | keyword |
| rsa.misc.p_filter |  | keyword |
| rsa.misc.p_group_object |  | keyword |
| rsa.misc.p_id |  | keyword |
| rsa.misc.p_msgid |  | keyword |
| rsa.misc.p_msgid1 |  | keyword |
| rsa.misc.p_msgid2 |  | keyword |
| rsa.misc.p_result1 |  | keyword |
| rsa.misc.param | This key is the parameters passed as part of a command or application, etc. | keyword |
| rsa.misc.param_dst | This key captures the command line/launch argument of the target process or file | keyword |
| rsa.misc.param_src | This key captures source parameter | keyword |
| rsa.misc.parent_node | This key captures the Parent Node Name. Must be related to node variable. | keyword |
| rsa.misc.password_chg |  | keyword |
| rsa.misc.password_expire |  | keyword |
| rsa.misc.payload_dst | This key is used to capture destination payload | keyword |
| rsa.misc.payload_src | This key is used to capture source payload | keyword |
| rsa.misc.permgranted |  | keyword |
| rsa.misc.permwanted |  | keyword |
| rsa.misc.pgid |  | keyword |
| rsa.misc.phone |  | keyword |
| rsa.misc.pid |  | keyword |
| rsa.misc.policy |  | keyword |
| rsa.misc.policyUUID |  | keyword |
| rsa.misc.policy_id | This key is used to capture the Policy ID only, this should be a numeric value, use policy.name otherwise | keyword |
| rsa.misc.policy_name | This key is used to capture the Policy Name only. | keyword |
| rsa.misc.policy_value | This key captures the contents of the policy. This contains details about the policy | keyword |
| rsa.misc.policy_waiver |  | keyword |
| rsa.misc.pool_id | This key captures the identifier (typically numeric field) of a resource pool | keyword |
| rsa.misc.pool_name | This key captures the name of a resource pool | keyword |
| rsa.misc.port_name | This key is used for Physical or logical port connection but does NOT include a network port. (Example: Printer port name). | keyword |
| rsa.misc.priority |  | keyword |
| rsa.misc.process_id_val | This key is a failure key for Process ID when it is not an integer value | keyword |
| rsa.misc.prog_asp_num |  | keyword |
| rsa.misc.program |  | keyword |
| rsa.misc.real_data |  | keyword |
| rsa.misc.reason |  | keyword |
| rsa.misc.rec_asp_device |  | keyword |
| rsa.misc.rec_asp_num |  | keyword |
| rsa.misc.rec_library |  | keyword |
| rsa.misc.recordnum |  | keyword |
| rsa.misc.reference_id | This key is used to capture an event id from the session directly | keyword |
| rsa.misc.reference_id1 | This key is for Linked ID to be used as an addition to "reference.id" | keyword |
| rsa.misc.reference_id2 | This key is for the 2nd Linked ID. Can be either linked to "reference.id" or "reference.id1" value but should not be used unless the other two variables are in play. | keyword |
| rsa.misc.result | This key is used to capture the outcome/result string value of an action in a session. | keyword |
| rsa.misc.result_code | This key is used to capture the outcome/result numeric value of an action in a session | keyword |
| rsa.misc.risk | This key captures the non-numeric risk value | keyword |
| rsa.misc.risk_info | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.risk_num | This key captures a Numeric Risk value | double |
| rsa.misc.risk_num_comm | This key captures Risk Number Community | double |
| rsa.misc.risk_num_next | This key captures Risk Number NextGen | double |
| rsa.misc.risk_num_sand | This key captures Risk Number SandBox | double |
| rsa.misc.risk_num_static | This key captures Risk Number Static | double |
| rsa.misc.risk_suspicious | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.risk_warning | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.ruid |  | keyword |
| rsa.misc.rule | This key captures the Rule number | keyword |
| rsa.misc.rule_group | This key captures the Rule group name | keyword |
| rsa.misc.rule_name | This key captures the Rule Name | keyword |
| rsa.misc.rule_template | A default set of parameters which are overlayed onto a rule (or rulename) which efffectively constitutes a template | keyword |
| rsa.misc.rule_uid | This key is the Unique Identifier for a rule. | keyword |
| rsa.misc.sburb |  | keyword |
| rsa.misc.sdomain_fld |  | keyword |
| rsa.misc.search_text | This key captures the Search Text used | keyword |
| rsa.misc.sec |  | keyword |
| rsa.misc.second |  | keyword |
| rsa.misc.sensor | This key captures Name of the sensor. Typically used in IDS/IPS based devices | keyword |
| rsa.misc.sensorname |  | keyword |
| rsa.misc.seqnum |  | keyword |
| rsa.misc.serial_number | This key is the Serial number associated with a physical asset. | keyword |
| rsa.misc.session |  | keyword |
| rsa.misc.sessiontype |  | keyword |
| rsa.misc.severity | This key is used to capture the severity given the session | keyword |
| rsa.misc.sigUUID |  | keyword |
| rsa.misc.sig_id | This key captures IDS/IPS Int Signature ID | long |
| rsa.misc.sig_id1 | This key captures IDS/IPS Int Signature ID. This must be linked to the sig.id | long |
| rsa.misc.sig_id_str | This key captures a string object of the sigid variable. | keyword |
| rsa.misc.sig_name | This key is used to capture the Signature Name only. | keyword |
| rsa.misc.sigcat |  | keyword |
| rsa.misc.snmp_oid | SNMP Object Identifier | keyword |
| rsa.misc.snmp_value | SNMP set request value | keyword |
| rsa.misc.space |  | keyword |
| rsa.misc.space1 |  | keyword |
| rsa.misc.spi |  | keyword |
| rsa.misc.spi_dst | Destination SPI Index | keyword |
| rsa.misc.spi_src | Source SPI Index | keyword |
| rsa.misc.sql | This key captures the SQL query | keyword |
| rsa.misc.srcburb |  | keyword |
| rsa.misc.srcdom |  | keyword |
| rsa.misc.srcservice |  | keyword |
| rsa.misc.state |  | keyword |
| rsa.misc.status |  | keyword |
| rsa.misc.status1 |  | keyword |
| rsa.misc.streams | This key captures number of streams in session | long |
| rsa.misc.subcategory |  | keyword |
| rsa.misc.svcno |  | keyword |
| rsa.misc.system |  | keyword |
| rsa.misc.tbdstr1 |  | keyword |
| rsa.misc.tbdstr2 |  | keyword |
| rsa.misc.tcp_flags | This key is captures the TCP flags set in any packet of session | long |
| rsa.misc.terminal | This key captures the Terminal Names only | keyword |
| rsa.misc.tgtdom |  | keyword |
| rsa.misc.tgtdomain |  | keyword |
| rsa.misc.threshold |  | keyword |
| rsa.misc.tos | This key describes the type of service | long |
| rsa.misc.trigger_desc | This key captures the Description of the trigger or threshold condition. | keyword |
| rsa.misc.trigger_val | This key captures the Value of the trigger or threshold condition. | keyword |
| rsa.misc.type |  | keyword |
| rsa.misc.type1 |  | keyword |
| rsa.misc.udb_class |  | keyword |
| rsa.misc.url_fld |  | keyword |
| rsa.misc.user_div |  | keyword |
| rsa.misc.userid |  | keyword |
| rsa.misc.username_fld |  | keyword |
| rsa.misc.utcstamp |  | keyword |
| rsa.misc.v_instafname |  | keyword |
| rsa.misc.version | This key captures Version of the application or OS which is generating the event. | keyword |
| rsa.misc.virt_data |  | keyword |
| rsa.misc.virusname | This key captures the name of the virus | keyword |
| rsa.misc.vm_target | VMWare Target \*\*VMWARE\*\* only varaible. | keyword |
| rsa.misc.vpnid |  | keyword |
| rsa.misc.vsys | This key captures Virtual System Name | keyword |
| rsa.misc.vuln_ref | This key captures the Vulnerability Reference details | keyword |
| rsa.misc.workspace | This key captures Workspace Description | keyword |
| rsa.network.ad_computer_dst | Deprecated, use host.dst | keyword |
| rsa.network.addr |  | keyword |
| rsa.network.alias_host | This key should be used when the source or destination context of a hostname is not clear.Also it captures the Device Hostname. Any Hostname that isnt ad.computer. | keyword |
| rsa.network.dinterface | This key should only be used when it’s a Destination Interface | keyword |
| rsa.network.dmask | This key is used for Destionation Device network mask | keyword |
| rsa.network.dns_a_record |  | keyword |
| rsa.network.dns_cname_record |  | keyword |
| rsa.network.dns_id |  | keyword |
| rsa.network.dns_opcode |  | keyword |
| rsa.network.dns_ptr_record |  | keyword |
| rsa.network.dns_resp |  | keyword |
| rsa.network.dns_type |  | keyword |
| rsa.network.domain |  | keyword |
| rsa.network.domain1 |  | keyword |
| rsa.network.eth_host | Deprecated, use alias.mac | keyword |
| rsa.network.eth_type | This key is used to capture Ethernet Type, Used for Layer 3 Protocols Only | long |
| rsa.network.faddr |  | keyword |
| rsa.network.fhost |  | keyword |
| rsa.network.fport |  | keyword |
| rsa.network.gateway | This key is used to capture the IP Address of the gateway | keyword |
| rsa.network.host_dst | This key should only be used when it’s a Destination Hostname | keyword |
| rsa.network.host_orig | This is used to capture the original hostname in case of a Forwarding Agent or a Proxy in between. | keyword |
| rsa.network.host_type |  | keyword |
| rsa.network.icmp_code | This key is used to capture the ICMP code only | long |
| rsa.network.icmp_type | This key is used to capture the ICMP type only | long |
| rsa.network.interface | This key should be used when the source or destination context of an interface is not clear | keyword |
| rsa.network.ip_proto | This key should be used to capture the Protocol number, all the protocol nubers are converted into string in UI | long |
| rsa.network.laddr |  | keyword |
| rsa.network.lhost |  | keyword |
| rsa.network.linterface |  | keyword |
| rsa.network.mask | This key is used to capture the device network IPmask. | keyword |
| rsa.network.netname | This key is used to capture the network name associated with an IP range. This is configured by the end user. | keyword |
| rsa.network.network_port | Deprecated, use port. NOTE: There is a type discrepancy as currently used, TM: Int32, INDEX: UInt64 (why neither chose the correct UInt16?!) | long |
| rsa.network.network_service | This is used to capture layer 7 protocols/service names | keyword |
| rsa.network.origin |  | keyword |
| rsa.network.packet_length |  | keyword |
| rsa.network.paddr | Deprecated | ip |
| rsa.network.phost |  | keyword |
| rsa.network.port | This key should only be used to capture a Network Port when the directionality is not clear | long |
| rsa.network.protocol_detail | This key should be used to capture additional protocol information | keyword |
| rsa.network.remote_domain_id |  | keyword |
| rsa.network.rpayload | This key is used to capture the total number of payload bytes seen in the retransmitted packets. | keyword |
| rsa.network.sinterface | This key should only be used when it’s a Source Interface | keyword |
| rsa.network.smask | This key is used for capturing source Network Mask | keyword |
| rsa.network.vlan | This key should only be used to capture the ID of the Virtual LAN | long |
| rsa.network.vlan_name | This key should only be used to capture the name of the Virtual LAN | keyword |
| rsa.network.zone | This key should be used when the source or destination context of a Zone is not clear | keyword |
| rsa.network.zone_dst | This key should only be used when it’s a Destination Zone. | keyword |
| rsa.network.zone_src | This key should only be used when it’s a Source Zone. | keyword |
| rsa.physical.org_dst | This is used to capture the destination organization based on the GEOPIP Maxmind database. | keyword |
| rsa.physical.org_src | This is used to capture the source organization based on the GEOPIP Maxmind database. | keyword |
| rsa.storage.disk_volume | A unique name assigned to logical units (volumes) within a physical disk | keyword |
| rsa.storage.lun | Logical Unit Number.This key is a very useful concept in Storage. | keyword |
| rsa.storage.pwwn | This uniquely identifies a port on a HBA. | keyword |
| rsa.threat.alert | This key is used to capture name of the alert | keyword |
| rsa.threat.threat_category | This key captures Threat Name/Threat Category/Categorization of alert | keyword |
| rsa.threat.threat_desc | This key is used to capture the threat description from the session directly or inferred | keyword |
| rsa.threat.threat_source | This key is used to capture source of the threat | keyword |
| rsa.time.date |  | keyword |
| rsa.time.datetime |  | keyword |
| rsa.time.day |  | keyword |
| rsa.time.duration_str | A text string version of the duration | keyword |
| rsa.time.duration_time | This key is used to capture the normalized duration/lifetime in seconds. | double |
| rsa.time.effective_time | This key is the effective time referenced by an individual event in a Standard Timestamp format | date |
| rsa.time.endtime | This key is used to capture the End time mentioned in a session in a standard form | date |
| rsa.time.event_queue_time | This key is the Time that the event was queued. | date |
| rsa.time.event_time | This key is used to capture the time mentioned in a raw session that represents the actual time an event occured in a standard normalized form | date |
| rsa.time.event_time_str | This key is used to capture the incomplete time mentioned in a session as a string | keyword |
| rsa.time.eventtime |  | keyword |
| rsa.time.expire_time | This key is the timestamp that explicitly refers to an expiration. | date |
| rsa.time.expire_time_str | This key is used to capture incomplete timestamp that explicitly refers to an expiration. | keyword |
| rsa.time.gmtdate |  | keyword |
| rsa.time.gmttime |  | keyword |
| rsa.time.hour |  | keyword |
| rsa.time.min |  | keyword |
| rsa.time.month |  | keyword |
| rsa.time.p_date |  | keyword |
| rsa.time.p_month |  | keyword |
| rsa.time.p_time |  | keyword |
| rsa.time.p_time1 |  | keyword |
| rsa.time.p_time2 |  | keyword |
| rsa.time.p_year |  | keyword |
| rsa.time.process_time | Deprecated, use duration.time | keyword |
| rsa.time.recorded_time | The event time as recorded by the system the event is collected from. The usage scenario is a multi-tier application where the management layer of the system records it's own timestamp at the time of collection from its child nodes. Must be in timestamp format. | date |
| rsa.time.stamp | Deprecated key defined only in table map. | date |
| rsa.time.starttime | This key is used to capture the Start time mentioned in a session in a standard form | date |
| rsa.time.timestamp |  | keyword |
| rsa.time.timezone | This key is used to capture the timezone of the Event Time | keyword |
| rsa.time.tzone |  | keyword |
| rsa.time.year |  | keyword |
| rsa.web.alias_host |  | keyword |
| rsa.web.cn_asn_dst |  | keyword |
| rsa.web.cn_rpackets |  | keyword |
| rsa.web.fqdn | Fully Qualified Domain Names | keyword |
| rsa.web.p_url |  | keyword |
| rsa.web.p_user_agent |  | keyword |
| rsa.web.p_web_cookie |  | keyword |
| rsa.web.p_web_method |  | keyword |
| rsa.web.p_web_referer |  | keyword |
| rsa.web.remote_domain |  | keyword |
| rsa.web.reputation_num | Reputation Number of an entity. Typically used for Web Domains | double |
| rsa.web.urlpage |  | keyword |
| rsa.web.urlroot |  | keyword |
| rsa.web.web_cookie | This key is used to capture the Web cookies specifically. | keyword |
| rsa.web.web_extension_tmp |  | keyword |
| rsa.web.web_page |  | keyword |
| rsa.web.web_ref_domain | Web referer's domain | keyword |
| rsa.web.web_ref_page | This key captures Web referer's page information | keyword |
| rsa.web.web_ref_query | This key captures Web referer's query portion of the URL | keyword |
| rsa.web.web_ref_root | Web referer's root URL path | keyword |
| rsa.wireless.access_point | This key is used to capture the access point name. | keyword |
| rsa.wireless.wlan_channel | This is used to capture the channel names | long |
| rsa.wireless.wlan_name | This key captures either WLAN number/name | keyword |
| rsa.wireless.wlan_ssid | This key is used to capture the ssid of a Wireless Session | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.registered_domain | The highest registered server domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| server.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| server.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.port | Port of the source. | long |
| source.registered_domain | The highest registered source domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| source.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| source.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |


### Fortimanager

The `fortimanager` dataset collects Fortinet Manager/Analyzer logs.

An example event for `fortimanager` looks as following:

```json
{
    "@timestamp": "2016-01-29T06:09:59.000Z",
    "agent": {
        "ephemeral_id": "607e3bda-a938-4637-8dd4-02613e9144ac",
        "id": "4e3f135a-d5f9-40b6-ae01-2c834ecbead0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "fortinet.fortimanager",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 449,
        "geo": {
            "country_name": "sequa"
        },
        "ip": [
            "10.44.173.44"
        ],
        "nat": {
            "ip": "10.189.58.145",
            "port": 5273
        },
        "port": 6125
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "4e3f135a-d5f9-40b6-ae01-2c834ecbead0",
        "snapshot": true,
        "version": "8.0.0"
    },
    "event": {
        "action": "allow",
        "agent_id_status": "verified",
        "code": "sse",
        "dataset": "fortinet.fortimanager",
        "ingested": "2022-01-25T12:33:50Z",
        "original": "logver=iusm devname=\"modtempo\" devid=\"olab\" vd=nto date=2016-1-29 time=6:09:59 logid=sse type=exercita subtype=der level=very-high eventtime=odoco logtime=ria srcip=10.20.234.169 srcport=1001 srcintf=eth5722 srcintfrole=vol dstip=10.44.173.44 dstport=6125 dstintf=enp0s3068 dstintfrole=nseq poluuid=itinvol sessionid=psa proto=21 action=allow policyid=ntium policytype=psaq crscore=13.800000 craction=eab crlevel=aliqu appcat=Ute service=lupt srccountry=dolore dstcountry=sequa trandisp=abo tranip=10.189.58.145 tranport=5273 duration=14.119000 sentbyte=7880 rcvdbyte=449 sentpkt=mqui app=nci\n",
        "timezone": "+00:00"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "level": "very-high",
        "source": {
            "address": "172.30.0.4:60997"
        }
    },
    "network": {
        "bytes": 8329
    },
    "observer": {
        "egress": {
            "interface": {
                "name": "enp0s3068"
            }
        },
        "ingress": {
            "interface": {
                "name": "eth5722"
            }
        },
        "product": "FortiManager",
        "type": "Configuration",
        "vendor": "Fortinet"
    },
    "related": {
        "hosts": [
            "modtempo"
        ],
        "ip": [
            "10.189.58.145",
            "10.20.234.169",
            "10.44.173.44"
        ]
    },
    "rsa": {
        "internal": {
            "messageid": "generic_fortinetmgr_1"
        },
        "misc": {
            "action": [
                "allow"
            ],
            "category": "der",
            "context": "abo",
            "event_source": "modtempo",
            "event_type": "exercita",
            "hardware_id": "olab",
            "log_session_id": "psa",
            "policy_id": "ntium",
            "reference_id": "sse",
            "severity": "very-high",
            "vsys": "nto"
        },
        "network": {
            "dinterface": "enp0s3068",
            "network_service": "lupt",
            "sinterface": "eth5722"
        },
        "time": {
            "duration_time": 14.119,
            "event_time": "2016-01-29T06:09:59.000Z",
            "event_time_str": "odoco"
        },
        "web": {
            "reputation_num": 13.8
        }
    },
    "source": {
        "bytes": 7880,
        "geo": {
            "country_name": "dolore"
        },
        "ip": [
            "10.20.234.169"
        ],
        "port": 1001
    },
    "tags": [
        "preserve_original_event",
        "fortinet-fortimanager",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.registered_domain | The highest registered client domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| client.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| client.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
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
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.port | Port of the destination. | long |
| destination.registered_domain | The highest registered destination domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| destination.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| destination.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.question.domain | Server domain. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| file.attributes | Array of file attributes. Attributes names will vary by platform. Here's a non-exhaustive list of values that are expected in this field: archive, compressed, directory, encrypted, execute, hidden, read, readonly, system, write. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.type | File type (file, dir, or symlink). | keyword |
| geo.city_name | City name. | keyword |
| geo.country_name | Country name. | keyword |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| geo.region_name | Region name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.interface.name |  | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.parent.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.parent.title.text | Multi-field of `process.parent.title`. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rsa.counters.dclass_c1 | This is a generic counter key that should be used with the label dclass.c1.str only | long |
| rsa.counters.dclass_c1_str | This is a generic counter string key that should be used with the label dclass.c1 only | keyword |
| rsa.counters.dclass_c2 | This is a generic counter key that should be used with the label dclass.c2.str only | long |
| rsa.counters.dclass_c2_str | This is a generic counter string key that should be used with the label dclass.c2 only | keyword |
| rsa.counters.dclass_c3 | This is a generic counter key that should be used with the label dclass.c3.str only | long |
| rsa.counters.dclass_c3_str | This is a generic counter string key that should be used with the label dclass.c3 only | keyword |
| rsa.counters.dclass_r1 | This is a generic ratio key that should be used with the label dclass.r1.str only | keyword |
| rsa.counters.dclass_r1_str | This is a generic ratio string key that should be used with the label dclass.r1 only | keyword |
| rsa.counters.dclass_r2 | This is a generic ratio key that should be used with the label dclass.r2.str only | keyword |
| rsa.counters.dclass_r2_str | This is a generic ratio string key that should be used with the label dclass.r2 only | keyword |
| rsa.counters.dclass_r3 | This is a generic ratio key that should be used with the label dclass.r3.str only | keyword |
| rsa.counters.dclass_r3_str | This is a generic ratio string key that should be used with the label dclass.r3 only | keyword |
| rsa.counters.event_counter | This is used to capture the number of times an event repeated | long |
| rsa.crypto.cert_ca | This key is used to capture the Certificate signing authority only | keyword |
| rsa.crypto.cert_checksum |  | keyword |
| rsa.crypto.cert_common | This key is used to capture the Certificate common name only | keyword |
| rsa.crypto.cert_error | This key captures the Certificate Error String | keyword |
| rsa.crypto.cert_host_cat | This key is used for the hostname category value of a certificate | keyword |
| rsa.crypto.cert_host_name | Deprecated key defined only in table map. | keyword |
| rsa.crypto.cert_issuer |  | keyword |
| rsa.crypto.cert_keysize |  | keyword |
| rsa.crypto.cert_serial | This key is used to capture the Certificate serial number only | keyword |
| rsa.crypto.cert_status | This key captures Certificate validation status | keyword |
| rsa.crypto.cert_subject | This key is used to capture the Certificate organization only | keyword |
| rsa.crypto.cert_username |  | keyword |
| rsa.crypto.cipher_dst | This key is for Destination (Server) Cipher | keyword |
| rsa.crypto.cipher_size_dst | This key captures Destination (Server) Cipher Size | long |
| rsa.crypto.cipher_size_src | This key captures Source (Client) Cipher Size | long |
| rsa.crypto.cipher_src | This key is for Source (Client) Cipher | keyword |
| rsa.crypto.crypto | This key is used to capture the Encryption Type or Encryption Key only | keyword |
| rsa.crypto.d_certauth |  | keyword |
| rsa.crypto.https_insact |  | keyword |
| rsa.crypto.https_valid |  | keyword |
| rsa.crypto.ike | IKE negotiation phase. | keyword |
| rsa.crypto.ike_cookie1 | ID of the negotiation — sent for ISAKMP Phase One | keyword |
| rsa.crypto.ike_cookie2 | ID of the negotiation — sent for ISAKMP Phase Two | keyword |
| rsa.crypto.peer | This key is for Encryption peer's IP Address | keyword |
| rsa.crypto.peer_id | This key is for Encryption peer’s identity | keyword |
| rsa.crypto.s_certauth |  | keyword |
| rsa.crypto.scheme | This key captures the Encryption scheme used | keyword |
| rsa.crypto.sig_type | This key captures the Signature Type | keyword |
| rsa.crypto.ssl_ver_dst | Deprecated, use version | keyword |
| rsa.crypto.ssl_ver_src | Deprecated, use version | keyword |
| rsa.db.database | This key is used to capture the name of a database or an instance as seen in a session | keyword |
| rsa.db.db_id | This key is used to capture the unique identifier for a database | keyword |
| rsa.db.db_pid | This key captures the process id of a connection with database server | long |
| rsa.db.index | This key captures IndexID of the index. | keyword |
| rsa.db.instance | This key is used to capture the database server instance name | keyword |
| rsa.db.lread | This key is used for the number of logical reads | long |
| rsa.db.lwrite | This key is used for the number of logical writes | long |
| rsa.db.permissions | This key captures permission or privilege level assigned to a resource. | keyword |
| rsa.db.pread | This key is used for the number of physical writes | long |
| rsa.db.table_name | This key is used to capture the table name | keyword |
| rsa.db.transact_id | This key captures the SQL transantion ID of the current session | keyword |
| rsa.email.email | This key is used to capture a generic email address where the source or destination context is not clear | keyword |
| rsa.email.email_dst | This key is used to capture the Destination email address only, when the destination context is not clear use email | keyword |
| rsa.email.email_src | This key is used to capture the source email address only, when the source context is not clear use email | keyword |
| rsa.email.subject | This key is used to capture the subject string from an Email only. | keyword |
| rsa.email.trans_from | Deprecated key defined only in table map. | keyword |
| rsa.email.trans_to | Deprecated key defined only in table map. | keyword |
| rsa.endpoint.host_state | This key is used to capture the current state of the machine, such as \<strong\>blacklisted\</strong\>, \<strong\>infected\</strong\>, \<strong\>firewall disabled\</strong\> and so on | keyword |
| rsa.endpoint.registry_key | This key captures the path to the registry key | keyword |
| rsa.endpoint.registry_value | This key captures values or decorators used within a registry entry | keyword |
| rsa.file.attachment | This key captures the attachment file name | keyword |
| rsa.file.binary | Deprecated key defined only in table map. | keyword |
| rsa.file.directory_dst | \<span\>This key is used to capture the directory of the target process or file\</span\> | keyword |
| rsa.file.directory_src | This key is used to capture the directory of the source process or file | keyword |
| rsa.file.file_entropy | This is used to capture entropy vale of a file | double |
| rsa.file.file_vendor | This is used to capture Company name of file located in version_info | keyword |
| rsa.file.filename_dst | This is used to capture name of the file targeted by the action | keyword |
| rsa.file.filename_src | This is used to capture name of the parent filename, the file which performed the action | keyword |
| rsa.file.filename_tmp |  | keyword |
| rsa.file.filesystem |  | keyword |
| rsa.file.privilege | Deprecated, use permissions | keyword |
| rsa.file.task_name | This is used to capture name of the task | keyword |
| rsa.healthcare.patient_fname | This key is for First Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.healthcare.patient_id | This key captures the unique ID for a patient | keyword |
| rsa.healthcare.patient_lname | This key is for Last Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.healthcare.patient_mname | This key is for Middle Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.accesses | This key is used to capture actual privileges used in accessing an object | keyword |
| rsa.identity.auth_method | This key is used to capture authentication methods used only | keyword |
| rsa.identity.dn | X.500 (LDAP) Distinguished Name | keyword |
| rsa.identity.dn_dst | An X.500 (LDAP) Distinguished name that used in a context that indicates a Destination dn | keyword |
| rsa.identity.dn_src | An X.500 (LDAP) Distinguished name that is used in a context that indicates a Source dn | keyword |
| rsa.identity.federated_idp | This key is the federated Identity Provider. This is the server providing the authentication. | keyword |
| rsa.identity.federated_sp | This key is the Federated Service Provider. This is the application requesting authentication. | keyword |
| rsa.identity.firstname | This key is for First Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.host_role | This key should only be used to capture the role of a Host Machine | keyword |
| rsa.identity.lastname | This key is for Last Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.ldap | This key is for Uninterpreted LDAP values. Ldap Values that don’t have a clear query or response context | keyword |
| rsa.identity.ldap_query | This key is the Search criteria from an LDAP search | keyword |
| rsa.identity.ldap_response | This key is to capture Results from an LDAP search | keyword |
| rsa.identity.logon_type | This key is used to capture the type of logon method used. | keyword |
| rsa.identity.logon_type_desc | This key is used to capture the textual description of an integer logon type as stored in the meta key 'logon.type'. | keyword |
| rsa.identity.middlename | This key is for Middle Names only, this is used for Healthcare predominantly to capture Patients information | keyword |
| rsa.identity.org | This key captures the User organization | keyword |
| rsa.identity.owner | This is used to capture username the process or service is running as, the author of the task | keyword |
| rsa.identity.password | This key is for Passwords seen in any session, plain text or encrypted | keyword |
| rsa.identity.profile | This key is used to capture the user profile | keyword |
| rsa.identity.realm | Radius realm or similar grouping of accounts | keyword |
| rsa.identity.service_account | This key is a windows specific key, used for capturing name of the account a service (referenced in the event) is running under. Legacy Usage | keyword |
| rsa.identity.user_dept | User's Department Names only | keyword |
| rsa.identity.user_role | This key is used to capture the Role of a user only | keyword |
| rsa.identity.user_sid_dst | This key captures Destination User Session ID | keyword |
| rsa.identity.user_sid_src | This key captures Source User Session ID | keyword |
| rsa.internal.audit_class | Deprecated key defined only in table map. | keyword |
| rsa.internal.cid | This is the unique identifier used to identify a NetWitness Concentrator. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.data | Deprecated key defined only in table map. | keyword |
| rsa.internal.dead | Deprecated key defined only in table map. | long |
| rsa.internal.device_class | This is the Classification of the Log Event Source under a predefined fixed set of Event Source Classifications. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_group | This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_host | This is the Hostname of the log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_ip | This is the IPv4 address of the Log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.device_ipv6 | This is the IPv6 address of the Log Event Source sending the logs to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.device_type | This is the name of the log parser which parsed a given session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.device_type_id | Deprecated key defined only in table map. | long |
| rsa.internal.did | This is the unique identifier used to identify a NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.entropy_req | This key is only used by the Entropy Parser, the Meta Type can be either UInt16 or Float32 based on the configuration | long |
| rsa.internal.entropy_res | This key is only used by the Entropy Parser, the Meta Type can be either UInt16 or Float32 based on the configuration | long |
| rsa.internal.entry | Deprecated key defined only in table map. | keyword |
| rsa.internal.event_desc |  | keyword |
| rsa.internal.event_name | Deprecated key defined only in table map. | keyword |
| rsa.internal.feed_category | This is used to capture the category of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.feed_desc | This is used to capture the description of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.feed_name | This is used to capture the name of the feed. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.forward_ip | This key should be used to capture the IPV4 address of a relay system which forwarded the events from the original system to NetWitness. | ip |
| rsa.internal.forward_ipv6 | This key is used to capture the IPV6 address of a relay system which forwarded the events from the original system to NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | ip |
| rsa.internal.hcode | Deprecated key defined only in table map. | keyword |
| rsa.internal.header_id | This is the Header ID value that identifies the exact log parser header definition that parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.inode | Deprecated key defined only in table map. | long |
| rsa.internal.lc_cid | This is a unique Identifier of a Log Collector. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.lc_ctime | This is the time at which a log is collected in a NetWitness Log Collector. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | date |
| rsa.internal.level | Deprecated key defined only in table map. | long |
| rsa.internal.mcb_req | This key is only used by the Entropy Parser, the most common byte request is simply which byte for each side (0 thru 255) was seen the most | long |
| rsa.internal.mcb_res | This key is only used by the Entropy Parser, the most common byte response is simply which byte for each side (0 thru 255) was seen the most | long |
| rsa.internal.mcbc_req | This key is only used by the Entropy Parser, the most common byte count is the number of times the most common byte (above) was seen in the session streams | long |
| rsa.internal.mcbc_res | This key is only used by the Entropy Parser, the most common byte count is the number of times the most common byte (above) was seen in the session streams | long |
| rsa.internal.medium | This key is used to identify if it’s a log/packet session or Layer 2 Encapsulation Type. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness. 32 = log, 33 = correlation session, &lt; 32 is packet session | long |
| rsa.internal.message | This key captures the contents of instant messages | keyword |
| rsa.internal.messageid |  | keyword |
| rsa.internal.msg | This key is used to capture the raw message that comes into the Log Decoder | keyword |
| rsa.internal.msg_id | This is the Message ID1 value that identifies the exact log parser definition which parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.msg_vid | This is the Message ID2 value that identifies the exact log parser definition which parses a particular log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.node_name | Deprecated key defined only in table map. | keyword |
| rsa.internal.nwe_callback_id | This key denotes that event is endpoint related | keyword |
| rsa.internal.obj_id | Deprecated key defined only in table map. | keyword |
| rsa.internal.obj_server | Deprecated key defined only in table map. | keyword |
| rsa.internal.obj_val | Deprecated key defined only in table map. | keyword |
| rsa.internal.parse_error | This is a special key that stores any Meta key validation error found while parsing a log session. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.payload_req | This key is only used by the Entropy Parser, the payload size metrics are the payload sizes of each session side at the time of parsing. However, in order to keep | long |
| rsa.internal.payload_res | This key is only used by the Entropy Parser, the payload size metrics are the payload sizes of each session side at the time of parsing. However, in order to keep | long |
| rsa.internal.process_vid_dst | Endpoint generates and uses a unique virtual ID to identify any similar group of process. This ID represents the target process. | keyword |
| rsa.internal.process_vid_src | Endpoint generates and uses a unique virtual ID to identify any similar group of process. This ID represents the source process. | keyword |
| rsa.internal.resource | Deprecated key defined only in table map. | keyword |
| rsa.internal.resource_class | Deprecated key defined only in table map. | keyword |
| rsa.internal.rid | This is a special ID of the Remote Session created by NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | long |
| rsa.internal.session_split | This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.site | Deprecated key defined only in table map. | keyword |
| rsa.internal.size | This is the size of the session as seen by the NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | long |
| rsa.internal.sourcefile | This is the name of the log file or PCAPs that can be imported into NetWitness. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.internal.statement | Deprecated key defined only in table map. | keyword |
| rsa.internal.time | This is the time at which a session hits a NetWitness Decoder. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness. | date |
| rsa.internal.ubc_req | This key is only used by the Entropy Parser, Unique byte count is the number of unique bytes seen in each stream. 256 would mean all byte values of 0 thru 255 were seen at least once | long |
| rsa.internal.ubc_res | This key is only used by the Entropy Parser, Unique byte count is the number of unique bytes seen in each stream. 256 would mean all byte values of 0 thru 255 were seen at least once | long |
| rsa.internal.word | This is used by the Word Parsing technology to capture the first 5 character of every word in an unparsed log | keyword |
| rsa.investigations.analysis_file | This is used to capture all indicators used in a File Analysis. This key should be used to capture an analysis of a file | keyword |
| rsa.investigations.analysis_service | This is used to capture all indicators used in a Service Analysis. This key should be used to capture an analysis of a service | keyword |
| rsa.investigations.analysis_session | This is used to capture all indicators used for a Session Analysis. This key should be used to capture an analysis of a session | keyword |
| rsa.investigations.boc | This is used to capture behaviour of compromise | keyword |
| rsa.investigations.ec_activity | This key captures the particular event activity(Ex:Logoff) | keyword |
| rsa.investigations.ec_outcome | This key captures the outcome of a particular Event(Ex:Success) | keyword |
| rsa.investigations.ec_subject | This key captures the Subject of a particular Event(Ex:User) | keyword |
| rsa.investigations.ec_theme | This key captures the Theme of a particular Event(Ex:Authentication) | keyword |
| rsa.investigations.eoc | This is used to capture Enablers of Compromise | keyword |
| rsa.investigations.event_cat | This key captures the Event category number | long |
| rsa.investigations.event_cat_name | This key captures the event category name corresponding to the event cat code | keyword |
| rsa.investigations.event_vcat | This is a vendor supplied category. This should be used in situations where the vendor has adopted their own event_category taxonomy. | keyword |
| rsa.investigations.inv_category | This used to capture investigation category | keyword |
| rsa.investigations.inv_context | This used to capture investigation context | keyword |
| rsa.investigations.ioc | This is key capture indicator of compromise | keyword |
| rsa.misc.OS | This key captures the Name of the Operating System | keyword |
| rsa.misc.acl_id |  | keyword |
| rsa.misc.acl_op |  | keyword |
| rsa.misc.acl_pos |  | keyword |
| rsa.misc.acl_table |  | keyword |
| rsa.misc.action |  | keyword |
| rsa.misc.admin |  | keyword |
| rsa.misc.agent_id | This key is used to capture agent id | keyword |
| rsa.misc.alarm_id |  | keyword |
| rsa.misc.alarmname |  | keyword |
| rsa.misc.alert_id | Deprecated, New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.app_id |  | keyword |
| rsa.misc.audit |  | keyword |
| rsa.misc.audit_object |  | keyword |
| rsa.misc.auditdata |  | keyword |
| rsa.misc.autorun_type | This is used to capture Auto Run type | keyword |
| rsa.misc.benchmark |  | keyword |
| rsa.misc.bypass |  | keyword |
| rsa.misc.cache |  | keyword |
| rsa.misc.cache_hit |  | keyword |
| rsa.misc.category | This key is used to capture the category of an event given by the vendor in the session | keyword |
| rsa.misc.cc_number | Valid Credit Card Numbers only | long |
| rsa.misc.cefversion |  | keyword |
| rsa.misc.cfg_attr |  | keyword |
| rsa.misc.cfg_obj |  | keyword |
| rsa.misc.cfg_path |  | keyword |
| rsa.misc.change_attrib | This key is used to capture the name of the attribute that’s changing in a session | keyword |
| rsa.misc.change_new | This key is used to capture the new values of the attribute that’s changing in a session | keyword |
| rsa.misc.change_old | This key is used to capture the old value of the attribute that’s changing in a session | keyword |
| rsa.misc.changes |  | keyword |
| rsa.misc.checksum | This key is used to capture the checksum or hash of the entity such as a file or process. Checksum should be used over checksum.src or checksum.dst when it is unclear whether the entity is a source or target of an action. | keyword |
| rsa.misc.checksum_dst | This key is used to capture the checksum or hash of the the target entity such as a process or file. | keyword |
| rsa.misc.checksum_src | This key is used to capture the checksum or hash of the source entity such as a file or process. | keyword |
| rsa.misc.client | This key is used to capture only the name of the client application requesting resources of the server. See the user.agent meta key for capture of the specific user agent identifier or browser identification string. | keyword |
| rsa.misc.client_ip |  | keyword |
| rsa.misc.clustermembers |  | keyword |
| rsa.misc.cmd |  | keyword |
| rsa.misc.cn_acttimeout |  | keyword |
| rsa.misc.cn_asn_src |  | keyword |
| rsa.misc.cn_bgpv4nxthop |  | keyword |
| rsa.misc.cn_ctr_dst_code |  | keyword |
| rsa.misc.cn_dst_tos |  | keyword |
| rsa.misc.cn_dst_vlan |  | keyword |
| rsa.misc.cn_engine_id |  | keyword |
| rsa.misc.cn_engine_type |  | keyword |
| rsa.misc.cn_f_switch |  | keyword |
| rsa.misc.cn_flowsampid |  | keyword |
| rsa.misc.cn_flowsampintv |  | keyword |
| rsa.misc.cn_flowsampmode |  | keyword |
| rsa.misc.cn_inacttimeout |  | keyword |
| rsa.misc.cn_inpermbyts |  | keyword |
| rsa.misc.cn_inpermpckts |  | keyword |
| rsa.misc.cn_invalid |  | keyword |
| rsa.misc.cn_ip_proto_ver |  | keyword |
| rsa.misc.cn_ipv4_ident |  | keyword |
| rsa.misc.cn_l_switch |  | keyword |
| rsa.misc.cn_log_did |  | keyword |
| rsa.misc.cn_log_rid |  | keyword |
| rsa.misc.cn_max_ttl |  | keyword |
| rsa.misc.cn_maxpcktlen |  | keyword |
| rsa.misc.cn_min_ttl |  | keyword |
| rsa.misc.cn_minpcktlen |  | keyword |
| rsa.misc.cn_mpls_lbl_1 |  | keyword |
| rsa.misc.cn_mpls_lbl_10 |  | keyword |
| rsa.misc.cn_mpls_lbl_2 |  | keyword |
| rsa.misc.cn_mpls_lbl_3 |  | keyword |
| rsa.misc.cn_mpls_lbl_4 |  | keyword |
| rsa.misc.cn_mpls_lbl_5 |  | keyword |
| rsa.misc.cn_mpls_lbl_6 |  | keyword |
| rsa.misc.cn_mpls_lbl_7 |  | keyword |
| rsa.misc.cn_mpls_lbl_8 |  | keyword |
| rsa.misc.cn_mpls_lbl_9 |  | keyword |
| rsa.misc.cn_mplstoplabel |  | keyword |
| rsa.misc.cn_mplstoplabip |  | keyword |
| rsa.misc.cn_mul_dst_byt |  | keyword |
| rsa.misc.cn_mul_dst_pks |  | keyword |
| rsa.misc.cn_muligmptype |  | keyword |
| rsa.misc.cn_sampalgo |  | keyword |
| rsa.misc.cn_sampint |  | keyword |
| rsa.misc.cn_seqctr |  | keyword |
| rsa.misc.cn_spackets |  | keyword |
| rsa.misc.cn_src_tos |  | keyword |
| rsa.misc.cn_src_vlan |  | keyword |
| rsa.misc.cn_sysuptime |  | keyword |
| rsa.misc.cn_template_id |  | keyword |
| rsa.misc.cn_totbytsexp |  | keyword |
| rsa.misc.cn_totflowexp |  | keyword |
| rsa.misc.cn_totpcktsexp |  | keyword |
| rsa.misc.cn_unixnanosecs |  | keyword |
| rsa.misc.cn_v6flowlabel |  | keyword |
| rsa.misc.cn_v6optheaders |  | keyword |
| rsa.misc.code |  | keyword |
| rsa.misc.command |  | keyword |
| rsa.misc.comments | Comment information provided in the log message | keyword |
| rsa.misc.comp_class |  | keyword |
| rsa.misc.comp_name |  | keyword |
| rsa.misc.comp_rbytes |  | keyword |
| rsa.misc.comp_sbytes |  | keyword |
| rsa.misc.comp_version | This key captures the Version level of a sub-component of a product. | keyword |
| rsa.misc.connection_id | This key captures the Connection ID | keyword |
| rsa.misc.content | This key captures the content type from protocol headers | keyword |
| rsa.misc.content_type | This key is used to capture Content Type only. | keyword |
| rsa.misc.content_version | This key captures Version level of a signature or database content. | keyword |
| rsa.misc.context | This key captures Information which adds additional context to the event. | keyword |
| rsa.misc.context_subject | This key is to be used in an audit context where the subject is the object being identified | keyword |
| rsa.misc.context_target |  | keyword |
| rsa.misc.count |  | keyword |
| rsa.misc.cpu | This key is the CPU time used in the execution of the event being recorded. | long |
| rsa.misc.cpu_data |  | keyword |
| rsa.misc.criticality |  | keyword |
| rsa.misc.cs_agency_dst |  | keyword |
| rsa.misc.cs_analyzedby |  | keyword |
| rsa.misc.cs_av_other |  | keyword |
| rsa.misc.cs_av_primary |  | keyword |
| rsa.misc.cs_av_secondary |  | keyword |
| rsa.misc.cs_bgpv6nxthop |  | keyword |
| rsa.misc.cs_bit9status |  | keyword |
| rsa.misc.cs_context |  | keyword |
| rsa.misc.cs_control |  | keyword |
| rsa.misc.cs_data |  | keyword |
| rsa.misc.cs_datecret |  | keyword |
| rsa.misc.cs_dst_tld |  | keyword |
| rsa.misc.cs_eth_dst_ven |  | keyword |
| rsa.misc.cs_eth_src_ven |  | keyword |
| rsa.misc.cs_event_uuid |  | keyword |
| rsa.misc.cs_filetype |  | keyword |
| rsa.misc.cs_fld |  | keyword |
| rsa.misc.cs_if_desc |  | keyword |
| rsa.misc.cs_if_name |  | keyword |
| rsa.misc.cs_ip_next_hop |  | keyword |
| rsa.misc.cs_ipv4dstpre |  | keyword |
| rsa.misc.cs_ipv4srcpre |  | keyword |
| rsa.misc.cs_lifetime |  | keyword |
| rsa.misc.cs_log_medium |  | keyword |
| rsa.misc.cs_loginname |  | keyword |
| rsa.misc.cs_modulescore |  | keyword |
| rsa.misc.cs_modulesign |  | keyword |
| rsa.misc.cs_opswatresult |  | keyword |
| rsa.misc.cs_payload |  | keyword |
| rsa.misc.cs_registrant |  | keyword |
| rsa.misc.cs_registrar |  | keyword |
| rsa.misc.cs_represult |  | keyword |
| rsa.misc.cs_rpayload |  | keyword |
| rsa.misc.cs_sampler_name |  | keyword |
| rsa.misc.cs_sourcemodule |  | keyword |
| rsa.misc.cs_streams |  | keyword |
| rsa.misc.cs_targetmodule |  | keyword |
| rsa.misc.cs_v6nxthop |  | keyword |
| rsa.misc.cs_whois_server |  | keyword |
| rsa.misc.cs_yararesult |  | keyword |
| rsa.misc.cve | This key captures CVE (Common Vulnerabilities and Exposures) - an identifier for known information security vulnerabilities. | keyword |
| rsa.misc.data_type |  | keyword |
| rsa.misc.description |  | keyword |
| rsa.misc.device_name | This is used to capture name of the Device associated with the node Like: a physical disk, printer, etc | keyword |
| rsa.misc.devvendor |  | keyword |
| rsa.misc.disposition | This key captures the The end state of an action. | keyword |
| rsa.misc.distance |  | keyword |
| rsa.misc.doc_number | This key captures File Identification number | long |
| rsa.misc.dstburb |  | keyword |
| rsa.misc.edomain |  | keyword |
| rsa.misc.edomaub |  | keyword |
| rsa.misc.ein_number | Employee Identification Numbers only | long |
| rsa.misc.error | This key captures All non successful Error codes or responses | keyword |
| rsa.misc.euid |  | keyword |
| rsa.misc.event_category |  | keyword |
| rsa.misc.event_computer | This key is a windows only concept, where this key is used to capture fully qualified domain name in a windows log. | keyword |
| rsa.misc.event_desc | This key is used to capture a description of an event available directly or inferred | keyword |
| rsa.misc.event_id |  | keyword |
| rsa.misc.event_log | This key captures the Name of the event log | keyword |
| rsa.misc.event_source | This key captures Source of the event that’s not a hostname | keyword |
| rsa.misc.event_state | This key captures the current state of the object/item referenced within the event. Describing an on-going event. | keyword |
| rsa.misc.event_type | This key captures the event category type as specified by the event source. | keyword |
| rsa.misc.event_user | This key is a windows only concept, where this key is used to capture combination of domain name and username in a windows log. | keyword |
| rsa.misc.expected_val | This key captures the Value expected (from the perspective of the device generating the log). | keyword |
| rsa.misc.facility |  | keyword |
| rsa.misc.facilityname |  | keyword |
| rsa.misc.fcatnum | This key captures Filter Category Number. Legacy Usage | keyword |
| rsa.misc.filter | This key captures Filter used to reduce result set | keyword |
| rsa.misc.finterface |  | keyword |
| rsa.misc.flags |  | keyword |
| rsa.misc.forensic_info |  | keyword |
| rsa.misc.found | This is used to capture the results of regex match | keyword |
| rsa.misc.fresult | This key captures the Filter Result | long |
| rsa.misc.gaddr |  | keyword |
| rsa.misc.group | This key captures the Group Name value | keyword |
| rsa.misc.group_id | This key captures Group ID Number (related to the group name) | keyword |
| rsa.misc.group_object | This key captures a collection/grouping of entities. Specific usage | keyword |
| rsa.misc.hardware_id | This key is used to capture unique identifier for a device or system (NOT a Mac address) | keyword |
| rsa.misc.id3 |  | keyword |
| rsa.misc.im_buddyid |  | keyword |
| rsa.misc.im_buddyname |  | keyword |
| rsa.misc.im_client |  | keyword |
| rsa.misc.im_croomid |  | keyword |
| rsa.misc.im_croomtype |  | keyword |
| rsa.misc.im_members |  | keyword |
| rsa.misc.im_userid |  | keyword |
| rsa.misc.im_username |  | keyword |
| rsa.misc.index |  | keyword |
| rsa.misc.inout |  | keyword |
| rsa.misc.ipkt |  | keyword |
| rsa.misc.ipscat |  | keyword |
| rsa.misc.ipspri |  | keyword |
| rsa.misc.job_num | This key captures the Job Number | keyword |
| rsa.misc.jobname |  | keyword |
| rsa.misc.language | This is used to capture list of languages the client support and what it prefers | keyword |
| rsa.misc.latitude |  | keyword |
| rsa.misc.library | This key is used to capture library information in mainframe devices | keyword |
| rsa.misc.lifetime | This key is used to capture the session lifetime in seconds. | long |
| rsa.misc.linenum |  | keyword |
| rsa.misc.link | This key is used to link the sessions together. This key should never be used to parse Meta data from a session (Logs/Packets) Directly, this is a Reserved key in NetWitness | keyword |
| rsa.misc.list_name |  | keyword |
| rsa.misc.listnum | This key is used to capture listname or listnumber, primarily for collecting access-list | keyword |
| rsa.misc.load_data |  | keyword |
| rsa.misc.location_floor |  | keyword |
| rsa.misc.location_mark |  | keyword |
| rsa.misc.log_id |  | keyword |
| rsa.misc.log_session_id | This key is used to capture a sessionid from the session directly | keyword |
| rsa.misc.log_session_id1 | This key is used to capture a Linked (Related) Session ID from the session directly | keyword |
| rsa.misc.log_type |  | keyword |
| rsa.misc.logid |  | keyword |
| rsa.misc.logip |  | keyword |
| rsa.misc.logname |  | keyword |
| rsa.misc.longitude |  | keyword |
| rsa.misc.lport |  | keyword |
| rsa.misc.mail_id | This key is used to capture the mailbox id/name | keyword |
| rsa.misc.match | This key is for regex match name from search.ini | keyword |
| rsa.misc.mbug_data |  | keyword |
| rsa.misc.message_body | This key captures the The contents of the message body. | keyword |
| rsa.misc.misc |  | keyword |
| rsa.misc.misc_name |  | keyword |
| rsa.misc.mode |  | keyword |
| rsa.misc.msgIdPart1 |  | keyword |
| rsa.misc.msgIdPart2 |  | keyword |
| rsa.misc.msgIdPart3 |  | keyword |
| rsa.misc.msgIdPart4 |  | keyword |
| rsa.misc.msg_type |  | keyword |
| rsa.misc.msgid |  | keyword |
| rsa.misc.name |  | keyword |
| rsa.misc.netsessid |  | keyword |
| rsa.misc.node | Common use case is the node name within a cluster. The cluster name is reflected by the host name. | keyword |
| rsa.misc.ntype |  | keyword |
| rsa.misc.num |  | keyword |
| rsa.misc.number |  | keyword |
| rsa.misc.number1 |  | keyword |
| rsa.misc.number2 |  | keyword |
| rsa.misc.nwwn |  | keyword |
| rsa.misc.obj_name | This is used to capture name of object | keyword |
| rsa.misc.obj_type | This is used to capture type of object | keyword |
| rsa.misc.object |  | keyword |
| rsa.misc.observed_val | This key captures the Value observed (from the perspective of the device generating the log). | keyword |
| rsa.misc.operation |  | keyword |
| rsa.misc.operation_id | An alert number or operation number. The values should be unique and non-repeating. | keyword |
| rsa.misc.opkt |  | keyword |
| rsa.misc.orig_from |  | keyword |
| rsa.misc.owner_id |  | keyword |
| rsa.misc.p_action |  | keyword |
| rsa.misc.p_filter |  | keyword |
| rsa.misc.p_group_object |  | keyword |
| rsa.misc.p_id |  | keyword |
| rsa.misc.p_msgid |  | keyword |
| rsa.misc.p_msgid1 |  | keyword |
| rsa.misc.p_msgid2 |  | keyword |
| rsa.misc.p_result1 |  | keyword |
| rsa.misc.param | This key is the parameters passed as part of a command or application, etc. | keyword |
| rsa.misc.param_dst | This key captures the command line/launch argument of the target process or file | keyword |
| rsa.misc.param_src | This key captures source parameter | keyword |
| rsa.misc.parent_node | This key captures the Parent Node Name. Must be related to node variable. | keyword |
| rsa.misc.password_chg |  | keyword |
| rsa.misc.password_expire |  | keyword |
| rsa.misc.payload_dst | This key is used to capture destination payload | keyword |
| rsa.misc.payload_src | This key is used to capture source payload | keyword |
| rsa.misc.permgranted |  | keyword |
| rsa.misc.permwanted |  | keyword |
| rsa.misc.pgid |  | keyword |
| rsa.misc.phone |  | keyword |
| rsa.misc.pid |  | keyword |
| rsa.misc.policy |  | keyword |
| rsa.misc.policyUUID |  | keyword |
| rsa.misc.policy_id | This key is used to capture the Policy ID only, this should be a numeric value, use policy.name otherwise | keyword |
| rsa.misc.policy_name | This key is used to capture the Policy Name only. | keyword |
| rsa.misc.policy_value | This key captures the contents of the policy. This contains details about the policy | keyword |
| rsa.misc.policy_waiver |  | keyword |
| rsa.misc.pool_id | This key captures the identifier (typically numeric field) of a resource pool | keyword |
| rsa.misc.pool_name | This key captures the name of a resource pool | keyword |
| rsa.misc.port_name | This key is used for Physical or logical port connection but does NOT include a network port. (Example: Printer port name). | keyword |
| rsa.misc.priority |  | keyword |
| rsa.misc.process_id_val | This key is a failure key for Process ID when it is not an integer value | keyword |
| rsa.misc.prog_asp_num |  | keyword |
| rsa.misc.program |  | keyword |
| rsa.misc.real_data |  | keyword |
| rsa.misc.reason |  | keyword |
| rsa.misc.rec_asp_device |  | keyword |
| rsa.misc.rec_asp_num |  | keyword |
| rsa.misc.rec_library |  | keyword |
| rsa.misc.recordnum |  | keyword |
| rsa.misc.reference_id | This key is used to capture an event id from the session directly | keyword |
| rsa.misc.reference_id1 | This key is for Linked ID to be used as an addition to "reference.id" | keyword |
| rsa.misc.reference_id2 | This key is for the 2nd Linked ID. Can be either linked to "reference.id" or "reference.id1" value but should not be used unless the other two variables are in play. | keyword |
| rsa.misc.result | This key is used to capture the outcome/result string value of an action in a session. | keyword |
| rsa.misc.result_code | This key is used to capture the outcome/result numeric value of an action in a session | keyword |
| rsa.misc.risk | This key captures the non-numeric risk value | keyword |
| rsa.misc.risk_info | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.risk_num | This key captures a Numeric Risk value | double |
| rsa.misc.risk_num_comm | This key captures Risk Number Community | double |
| rsa.misc.risk_num_next | This key captures Risk Number NextGen | double |
| rsa.misc.risk_num_sand | This key captures Risk Number SandBox | double |
| rsa.misc.risk_num_static | This key captures Risk Number Static | double |
| rsa.misc.risk_suspicious | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.risk_warning | Deprecated, use New Hunting Model (inv.\*, ioc, boc, eoc, analysis.\*) | keyword |
| rsa.misc.ruid |  | keyword |
| rsa.misc.rule | This key captures the Rule number | keyword |
| rsa.misc.rule_group | This key captures the Rule group name | keyword |
| rsa.misc.rule_name | This key captures the Rule Name | keyword |
| rsa.misc.rule_template | A default set of parameters which are overlayed onto a rule (or rulename) which efffectively constitutes a template | keyword |
| rsa.misc.rule_uid | This key is the Unique Identifier for a rule. | keyword |
| rsa.misc.sburb |  | keyword |
| rsa.misc.sdomain_fld |  | keyword |
| rsa.misc.search_text | This key captures the Search Text used | keyword |
| rsa.misc.sec |  | keyword |
| rsa.misc.second |  | keyword |
| rsa.misc.sensor | This key captures Name of the sensor. Typically used in IDS/IPS based devices | keyword |
| rsa.misc.sensorname |  | keyword |
| rsa.misc.seqnum |  | keyword |
| rsa.misc.serial_number | This key is the Serial number associated with a physical asset. | keyword |
| rsa.misc.session |  | keyword |
| rsa.misc.sessiontype |  | keyword |
| rsa.misc.severity | This key is used to capture the severity given the session | keyword |
| rsa.misc.sigUUID |  | keyword |
| rsa.misc.sig_id | This key captures IDS/IPS Int Signature ID | long |
| rsa.misc.sig_id1 | This key captures IDS/IPS Int Signature ID. This must be linked to the sig.id | long |
| rsa.misc.sig_id_str | This key captures a string object of the sigid variable. | keyword |
| rsa.misc.sig_name | This key is used to capture the Signature Name only. | keyword |
| rsa.misc.sigcat |  | keyword |
| rsa.misc.snmp_oid | SNMP Object Identifier | keyword |
| rsa.misc.snmp_value | SNMP set request value | keyword |
| rsa.misc.space |  | keyword |
| rsa.misc.space1 |  | keyword |
| rsa.misc.spi |  | keyword |
| rsa.misc.spi_dst | Destination SPI Index | keyword |
| rsa.misc.spi_src | Source SPI Index | keyword |
| rsa.misc.sql | This key captures the SQL query | keyword |
| rsa.misc.srcburb |  | keyword |
| rsa.misc.srcdom |  | keyword |
| rsa.misc.srcservice |  | keyword |
| rsa.misc.state |  | keyword |
| rsa.misc.status |  | keyword |
| rsa.misc.status1 |  | keyword |
| rsa.misc.streams | This key captures number of streams in session | long |
| rsa.misc.subcategory |  | keyword |
| rsa.misc.svcno |  | keyword |
| rsa.misc.system |  | keyword |
| rsa.misc.tbdstr1 |  | keyword |
| rsa.misc.tbdstr2 |  | keyword |
| rsa.misc.tcp_flags | This key is captures the TCP flags set in any packet of session | long |
| rsa.misc.terminal | This key captures the Terminal Names only | keyword |
| rsa.misc.tgtdom |  | keyword |
| rsa.misc.tgtdomain |  | keyword |
| rsa.misc.threshold |  | keyword |
| rsa.misc.tos | This key describes the type of service | long |
| rsa.misc.trigger_desc | This key captures the Description of the trigger or threshold condition. | keyword |
| rsa.misc.trigger_val | This key captures the Value of the trigger or threshold condition. | keyword |
| rsa.misc.type |  | keyword |
| rsa.misc.type1 |  | keyword |
| rsa.misc.udb_class |  | keyword |
| rsa.misc.url_fld |  | keyword |
| rsa.misc.user_div |  | keyword |
| rsa.misc.userid |  | keyword |
| rsa.misc.username_fld |  | keyword |
| rsa.misc.utcstamp |  | keyword |
| rsa.misc.v_instafname |  | keyword |
| rsa.misc.version | This key captures Version of the application or OS which is generating the event. | keyword |
| rsa.misc.virt_data |  | keyword |
| rsa.misc.virusname | This key captures the name of the virus | keyword |
| rsa.misc.vm_target | VMWare Target \*\*VMWARE\*\* only varaible. | keyword |
| rsa.misc.vpnid |  | keyword |
| rsa.misc.vsys | This key captures Virtual System Name | keyword |
| rsa.misc.vuln_ref | This key captures the Vulnerability Reference details | keyword |
| rsa.misc.workspace | This key captures Workspace Description | keyword |
| rsa.network.ad_computer_dst | Deprecated, use host.dst | keyword |
| rsa.network.addr |  | keyword |
| rsa.network.alias_host | This key should be used when the source or destination context of a hostname is not clear.Also it captures the Device Hostname. Any Hostname that isnt ad.computer. | keyword |
| rsa.network.dinterface | This key should only be used when it’s a Destination Interface | keyword |
| rsa.network.dmask | This key is used for Destionation Device network mask | keyword |
| rsa.network.dns_a_record |  | keyword |
| rsa.network.dns_cname_record |  | keyword |
| rsa.network.dns_id |  | keyword |
| rsa.network.dns_opcode |  | keyword |
| rsa.network.dns_ptr_record |  | keyword |
| rsa.network.dns_resp |  | keyword |
| rsa.network.dns_type |  | keyword |
| rsa.network.domain |  | keyword |
| rsa.network.domain1 |  | keyword |
| rsa.network.eth_host | Deprecated, use alias.mac | keyword |
| rsa.network.eth_type | This key is used to capture Ethernet Type, Used for Layer 3 Protocols Only | long |
| rsa.network.faddr |  | keyword |
| rsa.network.fhost |  | keyword |
| rsa.network.fport |  | keyword |
| rsa.network.gateway | This key is used to capture the IP Address of the gateway | keyword |
| rsa.network.host_dst | This key should only be used when it’s a Destination Hostname | keyword |
| rsa.network.host_orig | This is used to capture the original hostname in case of a Forwarding Agent or a Proxy in between. | keyword |
| rsa.network.host_type |  | keyword |
| rsa.network.icmp_code | This key is used to capture the ICMP code only | long |
| rsa.network.icmp_type | This key is used to capture the ICMP type only | long |
| rsa.network.interface | This key should be used when the source or destination context of an interface is not clear | keyword |
| rsa.network.ip_proto | This key should be used to capture the Protocol number, all the protocol nubers are converted into string in UI | long |
| rsa.network.laddr |  | keyword |
| rsa.network.lhost |  | keyword |
| rsa.network.linterface |  | keyword |
| rsa.network.mask | This key is used to capture the device network IPmask. | keyword |
| rsa.network.netname | This key is used to capture the network name associated with an IP range. This is configured by the end user. | keyword |
| rsa.network.network_port | Deprecated, use port. NOTE: There is a type discrepancy as currently used, TM: Int32, INDEX: UInt64 (why neither chose the correct UInt16?!) | long |
| rsa.network.network_service | This is used to capture layer 7 protocols/service names | keyword |
| rsa.network.origin |  | keyword |
| rsa.network.packet_length |  | keyword |
| rsa.network.paddr | Deprecated | ip |
| rsa.network.phost |  | keyword |
| rsa.network.port | This key should only be used to capture a Network Port when the directionality is not clear | long |
| rsa.network.protocol_detail | This key should be used to capture additional protocol information | keyword |
| rsa.network.remote_domain_id |  | keyword |
| rsa.network.rpayload | This key is used to capture the total number of payload bytes seen in the retransmitted packets. | keyword |
| rsa.network.sinterface | This key should only be used when it’s a Source Interface | keyword |
| rsa.network.smask | This key is used for capturing source Network Mask | keyword |
| rsa.network.vlan | This key should only be used to capture the ID of the Virtual LAN | long |
| rsa.network.vlan_name | This key should only be used to capture the name of the Virtual LAN | keyword |
| rsa.network.zone | This key should be used when the source or destination context of a Zone is not clear | keyword |
| rsa.network.zone_dst | This key should only be used when it’s a Destination Zone. | keyword |
| rsa.network.zone_src | This key should only be used when it’s a Source Zone. | keyword |
| rsa.physical.org_dst | This is used to capture the destination organization based on the GEOPIP Maxmind database. | keyword |
| rsa.physical.org_src | This is used to capture the source organization based on the GEOPIP Maxmind database. | keyword |
| rsa.storage.disk_volume | A unique name assigned to logical units (volumes) within a physical disk | keyword |
| rsa.storage.lun | Logical Unit Number.This key is a very useful concept in Storage. | keyword |
| rsa.storage.pwwn | This uniquely identifies a port on a HBA. | keyword |
| rsa.threat.alert | This key is used to capture name of the alert | keyword |
| rsa.threat.threat_category | This key captures Threat Name/Threat Category/Categorization of alert | keyword |
| rsa.threat.threat_desc | This key is used to capture the threat description from the session directly or inferred | keyword |
| rsa.threat.threat_source | This key is used to capture source of the threat | keyword |
| rsa.time.date |  | keyword |
| rsa.time.datetime |  | keyword |
| rsa.time.day |  | keyword |
| rsa.time.duration_str | A text string version of the duration | keyword |
| rsa.time.duration_time | This key is used to capture the normalized duration/lifetime in seconds. | double |
| rsa.time.effective_time | This key is the effective time referenced by an individual event in a Standard Timestamp format | date |
| rsa.time.endtime | This key is used to capture the End time mentioned in a session in a standard form | date |
| rsa.time.event_queue_time | This key is the Time that the event was queued. | date |
| rsa.time.event_time | This key is used to capture the time mentioned in a raw session that represents the actual time an event occured in a standard normalized form | date |
| rsa.time.event_time_str | This key is used to capture the incomplete time mentioned in a session as a string | keyword |
| rsa.time.eventtime |  | keyword |
| rsa.time.expire_time | This key is the timestamp that explicitly refers to an expiration. | date |
| rsa.time.expire_time_str | This key is used to capture incomplete timestamp that explicitly refers to an expiration. | keyword |
| rsa.time.gmtdate |  | keyword |
| rsa.time.gmttime |  | keyword |
| rsa.time.hour |  | keyword |
| rsa.time.min |  | keyword |
| rsa.time.month |  | keyword |
| rsa.time.p_date |  | keyword |
| rsa.time.p_month |  | keyword |
| rsa.time.p_time |  | keyword |
| rsa.time.p_time1 |  | keyword |
| rsa.time.p_time2 |  | keyword |
| rsa.time.p_year |  | keyword |
| rsa.time.process_time | Deprecated, use duration.time | keyword |
| rsa.time.recorded_time | The event time as recorded by the system the event is collected from. The usage scenario is a multi-tier application where the management layer of the system records it's own timestamp at the time of collection from its child nodes. Must be in timestamp format. | date |
| rsa.time.stamp | Deprecated key defined only in table map. | date |
| rsa.time.starttime | This key is used to capture the Start time mentioned in a session in a standard form | date |
| rsa.time.timestamp |  | keyword |
| rsa.time.timezone | This key is used to capture the timezone of the Event Time | keyword |
| rsa.time.tzone |  | keyword |
| rsa.time.year |  | keyword |
| rsa.web.alias_host |  | keyword |
| rsa.web.cn_asn_dst |  | keyword |
| rsa.web.cn_rpackets |  | keyword |
| rsa.web.fqdn | Fully Qualified Domain Names | keyword |
| rsa.web.p_url |  | keyword |
| rsa.web.p_user_agent |  | keyword |
| rsa.web.p_web_cookie |  | keyword |
| rsa.web.p_web_method |  | keyword |
| rsa.web.p_web_referer |  | keyword |
| rsa.web.remote_domain |  | keyword |
| rsa.web.reputation_num | Reputation Number of an entity. Typically used for Web Domains | double |
| rsa.web.urlpage |  | keyword |
| rsa.web.urlroot |  | keyword |
| rsa.web.web_cookie | This key is used to capture the Web cookies specifically. | keyword |
| rsa.web.web_extension_tmp |  | keyword |
| rsa.web.web_page |  | keyword |
| rsa.web.web_ref_domain | Web referer's domain | keyword |
| rsa.web.web_ref_page | This key captures Web referer's page information | keyword |
| rsa.web.web_ref_query | This key captures Web referer's query portion of the URL | keyword |
| rsa.web.web_ref_root | Web referer's root URL path | keyword |
| rsa.wireless.access_point | This key is used to capture the access point name. | keyword |
| rsa.wireless.wlan_channel | This is used to capture the channel names | long |
| rsa.wireless.wlan_name | This key captures either WLAN number/name | keyword |
| rsa.wireless.wlan_ssid | This key is used to capture the ssid of a Wireless Session | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.registered_domain | The highest registered server domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| server.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| server.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.port | Port of the source. | long |
| source.registered_domain | The highest registered source domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| source.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| source.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |

