# Common Event Format (CEF) Integration

This is an integration for receiving Common Event Format (CEF) data over Syslog. When messages are received over the syslog protocol the syslog input will parse the
header and set the timestamp value. Then the `decode_cef` processor is applied to parse the CEF encoded data. The decoded data is written into a `cef` object field. Lastly any
Elastic Common Schema (ECS) fields that can be populated with the CEF data are populated.

## Compatibility

### Forcepoint NGFW Security Management Center

This module will process CEF data from Forcepoint NGFW Security Management Center (SMC).  In the SMC configure the logs to be forwarded to the address set in `var.syslog_host` in format CEF and
service UDP on `var.syslog_port`.  Instructions can be found in [KB 15002](https://support.forcepoint.com/KBArticle?id=000015002) for
configuring the SMC.  

Testing was done with CEF logs from SMC version 6.6.1 and custom string mappings were taken from 'CEF Connector Configuration Guide' dated December 5, 2011.

### Check Point devices

This module will parse CEF data form Check Point devices as documented in
[Log Exporter CEF Field Mappings](https://community.checkpoint.com/t5/Logging-and-Reporting/Log-Exporter-CEF-Field-Mappings/td-p/41060).

Check Point CEF extensions are mapped as follows:


| CEF Extension              | CEF Label value             | ECS Fields               | Non-ECS Field                  |
|----------------------------|-----------------------------|--------------------------|--------------------------------|
| cp_app_risk                | -                           | event.risk_score         | checkpoint.app_risk            |
| cp_severity                | -                           | event.severity           | checkpoint.severity            |
| baseEventCount             | -                           | -                        | checkpoint.event_count         |
| deviceExternalId           | -                           | observer.type            | -                              |
| deviceFacility             | -                           | observer.type            | -                              |
| deviceInboundInterface     | -                           | observer.ingress.interface.name | -                       |
| deviceOutboundInterface    | -                           | observer.egress.interface.name | -                        |
| externalId                 | -                           | -                        | checkpoint.uuid                |
| fileHash                   | -                           | file.hash.{md5,sha1}     | -                              |
| reason                     | -                           | -                        | checkpoint.termination_reason  |
| requestCookies             | -                           | -                        | checkpoint.cookie              |
| sourceNtDomain             | -                           | dns.question.name        | -                              |
| Signature                  | -                           | vulnerability.id         | -                              |
| Recipient                  | -                           | destination.user.email   | -                              |
| Sender                     | -                           | source.user.email        | -                              |
| deviceCustomFloatingPoint1 | update version              | observer.version         | -                              |
| deviceCustomIPv6Address2   | source ipv6 address         | source.ip                | -                              |
| deviceCustomIPv6Address3   | destination ipv6 address    | destination.ip           | -                              |
| deviceCustomNumber1        | elapsed time in seconds     | event.duration           | -                              |
| deviceCustomNumber1        | email recipients number     | -                        | checkpoint.email_recipients_num |
| deviceCustomNumber1        | payload                     | network.bytes            | -                              |
| deviceCustomNumber2        | icmp type                   | -                        | checkpoint.icmp_type           |
| deviceCustomNumber2        | duration in seconds         | event.duration           | -                              |
| deviceCustomNumber3        | icmp code                   | -                        | checkpoint.icmp_code           |
| deviceCustomString1        | connectivity state          | -                        | checkpoint.connectivity_state  |
| deviceCustomString1        | application rule name       | rule.name                | -                              |
| deviceCustomString1        | threat prevention rule name | rule.name                | -                              |
| deviceCustomString1        | voip log type               | -                        | checkpoint.voip_log_type       |
| deviceCustomString1        | dlp rule name               | rule.name                | -                              |
| deviceCustomString1        | email id                    | -                        | checkpoint.email_id            |
| deviceCustomString2        | category                    | -                        | checkpoint.category            |
| deviceCustomString2        | email subject               | -                        | checkpoint.email_subject       |
| deviceCustomString2        | sensor mode                 | -                        | checkpoint.sensor_mode         |
| deviceCustomString2        | protection id               | -                        | checkpoint.protection_id       |
| deviceCustomString2        | scan invoke type            | -                        | checkpoint.integrity_av_invoke_type |
| deviceCustomString2        | update status               | -                        | checkpoint.update_status       |
| deviceCustomString2        | peer gateway                | -                        | checkpoint.peer_gateway        |
| deviceCustomString2        | categories                  | rule.category            | -                              |
| deviceCustomString6        | application name            | network.application      | -                              |
| deviceCustomString6        | virus name                  | -                        | checkpoint.virus_name          |
| deviceCustomString6        | malware name                | -                        | checkpoint.spyware_name        |
| deviceCustomString6        | malware family              | -                        | checkpoint.malware_family      |
| deviceCustomString3        | user group                  | group.name               | -                              |
| deviceCustomString3        | incident extension          | -                        | checkpoint.incident_extension  |
| deviceCustomString3        | protection type             | -                        | checkpoint.protection_type     |
| deviceCustomString3        | email spool id              | -                        | checkpoint.email_spool_id      |
| deviceCustomString3        | identity type               | -                        | checkpoint.identity_type       |
| deviceCustomString4        | malware status              | -                        | checkpoint.spyware_status      |
| deviceCustomString4        | threat prevention rule id   | rule.id                  | -                              |
| deviceCustomString4        | scan result                 | -                        | checkpoint.scan_result         |
| deviceCustomString4        | tcp flags                   | -                        | checkpoint.tcp_flags           |
| deviceCustomString4        | destination os              | os.name                  | -                              |
| deviceCustomString4        | protection name             | -                        | checkpoint.protection_name     |
| deviceCustomString4        | email control               | -                        | checkpoint.email_control       |
| deviceCustomString4        | frequency                   | -                        | checkpoint.frequency           |
| deviceCustomString4        | user response               | -                        | checkpoint.user_status         |
| deviceCustomString5        | matched category            | rule.category            | -                              |
| deviceCustomString5        | vlan id                     | network.vlan.id          | -                              |
| deviceCustomString5        | authentication method       | -                        | checkpoint.auth_method         |
| deviceCustomString5        | email session id            | -                        | checkpoint.email_session_id    |
| deviceCustomDate2          | subscription expiration     | -                        | checkpoint.subs_exp            |
| deviceFlexNumber1          | confidence                  | -                        | checkpoint.confidence_level    |
| deviceFlexNumber2          | performance impact          | -                        | checkpoint.performance_impact  |
| deviceFlexNumber2          | destination phone number    | -                        | checkpoint.dst_phone_number    |
| flexString1                | application signature id    | -                        | checkpoint.app_sig_id          |
| flexString2                | malware action              | rule.description         | -                              |
| flexString2                | attack information          | event.action             | -                              |
| rule_uid                   | -                           | rule.uuid                | -                              |
| ifname                     | -                           | observer.ingress.interface.name | -                       |
| inzone                     | -                           | observer.ingress.zone    | -                              |
| outzone                    | -                           | observer.egress.zone     | -                              |
| product                    | -                           | observer.product         | -                              |

## Logs

### CEF log

This is the CEF `log` dataset.

An example event for `log` looks as following:

```$json
{
    "agent": {
        "name": "mbp.local",
        "id": "99a900c1-965f-44d9-8b8f-021b83b2802b",
        "ephemeral_id": "decd3555-dec5-4df9-8631-ef294216f3a1",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "cef": {
        "severity": "low",
        "name": "Web request",
        "extensions": {
            "destinationPort": 443,
            "eventId": 3457,
            "sourcePort": 33876,
            "destinationAddress": "192.168.10.1",
            "sourceAddress": "6.7.8.9",
            "requestContext": "https://www.google.com",
            "sourceServiceName": "httpd",
            "requestUrl": "https://www.example.com/cart",
            "sourceGeoLatitude": 38.915,
            "sourceGeoLongitude": -77.511,
            "requestMethod": "POST",
            "transportProtocol": "TCP"
        },
        "device": {
            "product": "Vaporware",
            "event_class_id": "18",
            "version": "1.0.0-alpha",
            "vendor": "Elastic"
        },
        "version": "0"
    },
    "log": {
        "offset": 0,
        "file": {
            "path": "/var/log/cef.log"
        }
    },
    "destination": {
        "port": 443,
        "ip": "192.168.10.1"
    },
    "source": {
        "geo": {
            "continent_name": "North America",
            "country_name": "United States",
            "location": {
                "lon": -97.822,
                "lat": 37.751
            },
            "country_iso_code": "US"
        },
        "port": 33876,
        "service": {
            "name": "httpd"
        },
        "ip": "6.7.8.9"
    },
    "message": "Web request",
    "url": {
        "original": "https://www.example.com/cart"
    },
    "network": {
        "community_id": "1:e2rSLr3fJ93cIJDMtVABFxSH5zg=",
        "transport": "tcp"
    },
    "input": {
        "type": "log"
    },
    "observer": {
        "version": "1.0.0-alpha",
        "product": "Vaporware",
        "vendor": "Elastic"
    },
    "@timestamp": "2020-11-24T12:28:32.773Z",
    "ecs": {
        "version": "1.6.0"
    },
    "related": {
        "ip": [
            "192.168.10.1",
            "6.7.8.9"
        ]
    },
    "host": {
        "name": "mbp.local"
    },
    "http": {
        "request": {
            "method": "POST",
            "referrer": "https://www.google.com"
        }
    },
    "event": {
        "severity": 0,
        "ingested": "2020-12-01T14:15:45.961774100Z",
        "code": "18",
        "original": "CEF:0|Elastic|Vaporware|1.0.0-alpha|18|Web request|low|eventId=3457 requestMethod=POST slat=38.915 slong=-77.511 proto=TCP sourceServiceName=httpd requestContext=https://www.google.com src=6.7.8.9 spt=33876 dst=192.168.10.1 dpt=443 request=https://www.example.com/cart",
        "id": 3457
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cef.device.event_class_id |  | keyword |
| cef.device.product |  | keyword |
| cef.device.vendor |  | keyword |
| cef.device.version |  | keyword |
| cef.extensions.applicationProtocol |  | keyword |
| cef.extensions.baseEventCount |  | keyword |
| cef.extensions.bytesIn |  | long |
| cef.extensions.bytesOut |  | long |
| cef.extensions.categoryBehavior |  | keyword |
| cef.extensions.categoryDeviceGroup |  | keyword |
| cef.extensions.categoryDeviceType |  | keyword |
| cef.extensions.categoryObject |  | keyword |
| cef.extensions.categoryOutcome |  | keyword |
| cef.extensions.categorySignificance |  | keyword |
| cef.extensions.categoryTechnique |  | keyword |
| cef.extensions.cp_app_risk |  | keyword |
| cef.extensions.cp_severity |  | keyword |
| cef.extensions.destinationAddress |  | ip |
| cef.extensions.destinationNtDomain |  | keyword |
| cef.extensions.destinationPort |  | long |
| cef.extensions.destinationServiceName |  | keyword |
| cef.extensions.destinationTranslatedAddress |  | ip |
| cef.extensions.destinationTranslatedPort |  | long |
| cef.extensions.destinationUserName |  | keyword |
| cef.extensions.destinationUserPrivileges |  | keyword |
| cef.extensions.deviceAction |  | keyword |
| cef.extensions.deviceAddress |  | ip |
| cef.extensions.deviceCustomDate2 |  | keyword |
| cef.extensions.deviceCustomDate2Label |  | keyword |
| cef.extensions.deviceCustomIPv6Address2 |  | ip |
| cef.extensions.deviceCustomIPv6Address2Label |  | keyword |
| cef.extensions.deviceCustomIPv6Address3 |  | ip |
| cef.extensions.deviceCustomIPv6Address3Label |  | keyword |
| cef.extensions.deviceCustomNumber1 |  | long |
| cef.extensions.deviceCustomNumber1Label |  | keyword |
| cef.extensions.deviceCustomNumber2 |  | long |
| cef.extensions.deviceCustomNumber2Label |  | keyword |
| cef.extensions.deviceCustomString1 |  | keyword |
| cef.extensions.deviceCustomString1Label |  | keyword |
| cef.extensions.deviceCustomString2 |  | keyword |
| cef.extensions.deviceCustomString2Label |  | keyword |
| cef.extensions.deviceCustomString3 |  | keyword |
| cef.extensions.deviceCustomString3Label |  | keyword |
| cef.extensions.deviceCustomString4 |  | keyword |
| cef.extensions.deviceCustomString4Label |  | keyword |
| cef.extensions.deviceCustomString5 |  | keyword |
| cef.extensions.deviceCustomString5Label |  | keyword |
| cef.extensions.deviceDirection |  | long |
| cef.extensions.deviceEventCategory |  | keyword |
| cef.extensions.deviceExternalId |  | keyword |
| cef.extensions.deviceFacility |  | keyword |
| cef.extensions.deviceHostName |  | keyword |
| cef.extensions.deviceOutboundInterface |  | keyword |
| cef.extensions.deviceReceiptTime |  | keyword |
| cef.extensions.eventId |  | long |
| cef.extensions.fileHash |  | keyword |
| cef.extensions.ifname |  | keyword |
| cef.extensions.inzone |  | keyword |
| cef.extensions.layer_name |  | keyword |
| cef.extensions.layer_uuid |  | keyword |
| cef.extensions.logid |  | keyword |
| cef.extensions.loguid |  | keyword |
| cef.extensions.match_id |  | keyword |
| cef.extensions.message |  | keyword |
| cef.extensions.nat_addtnl_rulenum |  | keyword |
| cef.extensions.nat_rulenum |  | keyword |
| cef.extensions.oldFileHash |  | keyword |
| cef.extensions.origin |  | keyword |
| cef.extensions.originsicname |  | keyword |
| cef.extensions.outzone |  | keyword |
| cef.extensions.parent_rule |  | keyword |
| cef.extensions.product |  | keyword |
| cef.extensions.requestContext |  | keyword |
| cef.extensions.requestMethod |  | keyword |
| cef.extensions.requestUrl |  | keyword |
| cef.extensions.rule_action |  | keyword |
| cef.extensions.rule_uid |  | keyword |
| cef.extensions.sequencenum |  | keyword |
| cef.extensions.service_id |  | keyword |
| cef.extensions.sourceAddress |  | ip |
| cef.extensions.sourceGeoLatitude |  | long |
| cef.extensions.sourceGeoLongitude |  | long |
| cef.extensions.sourceNtDomain |  | keyword |
| cef.extensions.sourcePort |  | long |
| cef.extensions.sourceServiceName |  | keyword |
| cef.extensions.sourceTranslatedAddress |  | ip |
| cef.extensions.sourceTranslatedPort |  | long |
| cef.extensions.sourceUserName |  | keyword |
| cef.extensions.sourceUserPrivileges |  | keyword |
| cef.extensions.transportProtocol |  | keyword |
| cef.extensions.version |  | keyword |
| cef.forcepoint.virus_id | Virus ID | keyword |
| cef.name |  | keyword |
| cef.severity |  | keyword |
| cef.version |  | keyword |
| checkpoint.app_risk | Application risk. | keyword |
| checkpoint.app_severity | Application threat severity. | keyword |
| checkpoint.app_sig_id | The signature ID which the application was detected by. | keyword |
| checkpoint.auth_method | Password authentication protocol used. | keyword |
| checkpoint.category | Category. | keyword |
| checkpoint.confidence_level | Confidence level determined. | integer |
| checkpoint.connectivity_state | Connectivity state. | keyword |
| checkpoint.cookie | IKE cookie. | keyword |
| checkpoint.dst_phone_number | Destination IP-Phone. | keyword |
| checkpoint.email_control | Engine name. | keyword |
| checkpoint.email_id | Internal email ID. | keyword |
| checkpoint.email_recipients_num | Number of recipients. | long |
| checkpoint.email_session_id | Internal email session ID. | keyword |
| checkpoint.email_spool_id | Internal email spool ID. | keyword |
| checkpoint.email_subject | Email subject. | keyword |
| checkpoint.event_count | Number of events associated with the log. | long |
| checkpoint.frequency | Scan frequency. | keyword |
| checkpoint.icmp_code | ICMP code. | long |
| checkpoint.icmp_type | ICMP type. | long |
| checkpoint.identity_type | Identity type. | keyword |
| checkpoint.incident_extension | Format of original data. | keyword |
| checkpoint.integrity_av_invoke_type | Scan invoke type. | keyword |
| checkpoint.malware_family | Malware family. | keyword |
| checkpoint.peer_gateway | Main IP of the peer Security Gateway. | ip |
| checkpoint.performance_impact | Protection performance impact. | integer |
| checkpoint.protection_id | Protection malware ID. | keyword |
| checkpoint.protection_name | Specific signature name of the attack. | keyword |
| checkpoint.protection_type | Type of protection used to detect the attack. | keyword |
| checkpoint.scan_result | Scan result. | keyword |
| checkpoint.sensor_mode | Sensor mode. | keyword |
| checkpoint.severity | Threat severity. | keyword |
| checkpoint.spyware_name | Spyware name. | keyword |
| checkpoint.spyware_status | Spyware status. | keyword |
| checkpoint.subs_exp | The expiration date of the subscription. | date |
| checkpoint.tcp_flags | TCP packet flags. | keyword |
| checkpoint.termination_reason | Termination reason. | keyword |
| checkpoint.update_status | Update status. | keyword |
| checkpoint.user_status | User response. | keyword |
| checkpoint.uuid | External ID. | keyword |
| checkpoint.virus_name | Virus name. | keyword |
| checkpoint.voip_log_type | VoIP log types. | keyword |
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
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the source (IPv4 or IPv6). | ip |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.port | Port of the destination. | long |
| destination.service.name |  | keyword |
| destination.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| destination.user.group.name | Name of the group. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| ecs.version | ECS version | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| file.group | Primary group name of the file. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.type | File type (file, dir, or symlink). | keyword |
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
| http.request.method | HTTP request method. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Input type | keyword |
| log.file.path | Log path | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| network.application | A name given to an application level protocol. | keyword |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. | keyword |
| network.direction | Direction of the network traffic. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) | keyword |
| observer.egress.zone | Network zone of outbound traffic as reported by the observer. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.zone | Network zone of incoming traffic as reported by the observer. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| related.hash | All the hashes seen on your event. | keyword |
| related.hosts | All the host names seen on your event. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.uuid | A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | Destination domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.port | Port of the source. | long |
| source.service.name |  | keyword |
| source.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.original | Unmodified original url as seen in the event source. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |

