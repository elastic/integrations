# Common Event Format (CEF) Integration

This is an integration for parsing Common Event Format (CEF) data. It can accept
data over syslog or read it from a file.

CEF data is a format like

`CEF:0|Elastic|Vaporware|1.0.0-alpha|18|Web request|low|eventId=3457 msg=hello`

When syslog is used as the transport the CEF data becomes the message that is
contained in the syslog envelope. This integration will parse the syslog
timestamp if it is present. Depending on the syslog RFC used the message will
have a format like one of these:

`<189> Jun 18 10:55:50 host CEF:0|Elastic|Vaporware|1.0.0-alpha|18|Web request|low|eventId=3457 msg=hello`

`<189>1 2021-06-18T10:55:50.000003Z host app - - - CEF:0|Elastic|Vaporware|1.0.0-alpha|18|Web request|low|eventId=3457 msg=hello`

In both cases the integration will use the syslog timestamp as the `@timestamp`
unless the CEF data contains a device receipt timestamp.

The Elastic Agent's `decode_cef` processor is applied to parse the CEF encoded
data. The decoded data is written into a `cef` object field. Lastly any Elastic
Common Schema (ECS) fields that can be populated with the CEF data are
populated.

## Compatibility

### Forcepoint NGFW Security Management Center

This module will process CEF data from Forcepoint NGFW Security Management
Center (SMC).  In the SMC configure the logs to be forwarded to the address set
in `var.syslog_host` in format CEF and service UDP on `var.syslog_port`.
Instructions can be found in [KB
15002](https://support.forcepoint.com/KBArticle?id=000015002) for configuring
the SMC.

Testing was done with CEF logs from SMC version 6.6.1 and custom string mappings
were taken from 'CEF Connector Configuration Guide' dated December 5, 2011.

### Check Point devices

This module will parse CEF data from Check Point devices as documented in [Log
Exporter CEF Field
Mappings](https://community.checkpoint.com/t5/Logging-and-Reporting/Log-Exporter-CEF-Field-Mappings/td-p/41060).

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
| fileHash                   | -                           | file.hash.\{md5,sha1\}   | -                              |
| reason                     | -                           | -                        | checkpoint.termination_reason  |
| requestCookies             | -                           | -                        | checkpoint.cookie              |
| sourceNtDomain             | -                           | dns.question.name        | -                              |
| Signature                  | -                           | vulnerability.id         | -                              |
| Recipient                  | -                           | email.to.address         | -                              |
| Sender                     | -                           | email.from.address       | -                              |
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
| deviceCustomString2        | email subject               | email.subject            | checkpoint.email_subject       |
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
| deviceCustomString5        | email session id            | email.message_id         | checkpoint.email_session_id    |
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

```json
{
    "@timestamp": "2023-04-19T09:52:39.939Z",
    "agent": {
        "ephemeral_id": "1e43410c-3849-4180-9c14-e3264e4a47e6",
        "id": "f1ee4a83-b99b-4611-925d-b83b001f8b86",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "cef": {
        "device": {
            "event_class_id": "18",
            "product": "Vaporware",
            "vendor": "Elastic",
            "version": "1.0.0-alpha"
        },
        "extensions": {
            "destinationAddress": "192.168.10.1",
            "destinationPort": 443,
            "eventId": 3457,
            "requestContext": "https://www.google.com",
            "requestMethod": "POST",
            "requestUrl": "https://www.example.com/cart",
            "sourceAddress": "89.160.20.156",
            "sourceGeoLatitude": 38.915,
            "sourceGeoLongitude": -77.511,
            "sourcePort": 33876,
            "sourceServiceName": "httpd",
            "transportProtocol": "TCP"
        },
        "name": "Web request",
        "severity": "low",
        "version": "0"
    },
    "data_stream": {
        "dataset": "cef.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "192.168.10.1",
        "port": 443
    },
    "ecs": {
        "version": "8.9.0"
    },
    "elastic_agent": {
        "id": "f1ee4a83-b99b-4611-925d-b83b001f8b86",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "code": "18",
        "dataset": "cef.log",
        "id": "3457",
        "ingested": "2023-04-19T09:52:40Z",
        "severity": 0
    },
    "http": {
        "request": {
            "method": "POST",
            "referrer": "https://www.google.com"
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.29.0.4:33227"
        }
    },
    "message": "Web request",
    "network": {
        "community_id": "1:UgazGyZMuRDtuImGjF+6GveZFw0=",
        "transport": "tcp"
    },
    "observer": {
        "product": "Vaporware",
        "vendor": "Elastic",
        "version": "1.0.0-alpha"
    },
    "related": {
        "ip": [
            "192.168.10.1",
            "89.160.20.156"
        ]
    },
    "source": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156",
        "port": 33876,
        "service": {
            "name": "httpd"
        }
    },
    "tags": [
        "cef",
        "forwarded"
    ],
    "url": {
        "original": "https://www.example.com/cart"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cef.device.event_class_id | Unique identifier of the event type. | keyword |
| cef.device.product | Product of the device that produced the message. | keyword |
| cef.device.vendor | Vendor of the device that produced the message. | keyword |
| cef.device.version | Version of the product that produced the message. | keyword |
| cef.extensions.TrendMicroDsDetectionConfidence |  | keyword |
| cef.extensions.TrendMicroDsFileMD5 |  | keyword |
| cef.extensions.TrendMicroDsFileSHA1 |  | keyword |
| cef.extensions.TrendMicroDsFileSHA256 |  | keyword |
| cef.extensions.TrendMicroDsFrameType |  | keyword |
| cef.extensions.TrendMicroDsMalwareTarget |  | keyword |
| cef.extensions.TrendMicroDsMalwareTargetType |  | keyword |
| cef.extensions.TrendMicroDsPacketData |  | keyword |
| cef.extensions.TrendMicroDsRelevantDetectionNames |  | keyword |
| cef.extensions.TrendMicroDsTenant |  | keyword |
| cef.extensions.TrendMicroDsTenantId |  | keyword |
| cef.extensions.ad |  | flattened |
| cef.extensions.agentAddress | The IP address of the ArcSight connector that processed the event. | ip |
| cef.extensions.agentHostName | The hostname of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentId | The agent ID of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentMacAddress | The MAC address of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentReceiptTime | The time at which information about the event was received by the ArcSight connector. | date |
| cef.extensions.agentTimeZone | The agent time zone of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentType | The agent type of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentVersion | The version of the ArcSight connector that processed the event. | keyword |
| cef.extensions.agentZoneURI |  | keyword |
| cef.extensions.aggregationType |  | keyword |
| cef.extensions.applicationProtocol | Application level protocol, example values are HTTP, HTTPS, SSHv2, Telnet, POP, IMPA, IMAPS, and so on. | keyword |
| cef.extensions.assetCriticality |  | keyword |
| cef.extensions.baseEventCount | A count associated with this event. How many times was this same event observed? Count can be omitted if it is 1. | long |
| cef.extensions.bytesIn | Number of bytes transferred inbound, relative to the source to destination relationship, meaning that data was flowing from source to destination. | long |
| cef.extensions.bytesOut | Number of bytes transferred outbound relative to the source to destination relationship. For example, the byte number of data flowing from the destination to the source. | long |
| cef.extensions.categoryBehavior | Action or a behavior associated with an event. It's what is being done to the object (ArcSight). | keyword |
| cef.extensions.categoryDeviceGroup | General device group like Firewall (ArcSight). | keyword |
| cef.extensions.categoryDeviceType | Device type. Examples - Proxy, IDS, Web Server (ArcSight). | keyword |
| cef.extensions.categoryObject | Object that the event is about. For example it can be an operating sytem, database, file, etc (ArcSight). | keyword |
| cef.extensions.categoryOutcome | Outcome of the event (e.g. sucess, failure, or attempt) (ArcSight). | keyword |
| cef.extensions.categorySignificance | Characterization of the importance of the event (ArcSight). | keyword |
| cef.extensions.categoryTechnique | Technique being used (e.g. /DoS) (ArcSight). | keyword |
| cef.extensions.cp_app_risk |  | keyword |
| cef.extensions.cp_severity |  | keyword |
| cef.extensions.destinationAddress | Identifies the destination address that the event refers to in an IP network. The format is an IPv4 address. | ip |
| cef.extensions.destinationHostName | Identifies the destination that an event refers to in an IP network. The format should be a fully qualified domain name (FQDN) associated with the destination node, when a node is available. | keyword |
| cef.extensions.destinationMacAddress | Six colon-separated hexadecimal numbers. | keyword |
| cef.extensions.destinationNtDomain | Outcome of the event (e.g. sucess, failure, or attempt) (ArcSight). | keyword |
| cef.extensions.destinationPort | The valid port numbers are between 0 and 65535. | long |
| cef.extensions.destinationServiceName | The service targeted by this event. | keyword |
| cef.extensions.destinationTranslatedAddress | Identifies the translated destination that the event refers to in an IP network. | ip |
| cef.extensions.destinationTranslatedPort | Port after it was translated; for example, a firewall. Valid port numbers are 0 to 65535. | long |
| cef.extensions.destinationUserName | Identifies the destination user by name. This is the user associated with the event's destination. Email addresses are often mapped into the UserName fields. The recipient is a candidate to put into this field. | keyword |
| cef.extensions.destinationUserPrivileges | The typical values are "Administrator", "User", and "Guest". This identifies the destination user's privileges. In UNIX, for example, activity executed on the root user would be identified with destinationUser Privileges of "Administrator". | keyword |
| cef.extensions.deviceAction | Action taken by the device. | keyword |
| cef.extensions.deviceAddress | Identifies the device address that an event refers to in an IP network. | ip |
| cef.extensions.deviceAssetId |  | keyword |
| cef.extensions.deviceCustomDate2 | One of two timestamp fields available to map fields that do not apply to any other in this dictionary. | keyword |
| cef.extensions.deviceCustomDate2Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomIPv6Address1 | One of four IPv6 address fields available to map fields that do not apply to any other in this dictionary. | ip |
| cef.extensions.deviceCustomIPv6Address1Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomIPv6Address2 | One of four IPv6 address fields available to map fields that do not apply to any other in this dictionary. | ip |
| cef.extensions.deviceCustomIPv6Address2Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomIPv6Address3 | One of four IPv6 address fields available to map fields that do not apply to any other in this dictionary. | ip |
| cef.extensions.deviceCustomIPv6Address3Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomIPv6Address4 | One of four IPv6 address fields available to map fields that do not apply to any other in this dictionary. | ip |
| cef.extensions.deviceCustomIPv6Address4Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomNumber1 | One of three number fields available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | long |
| cef.extensions.deviceCustomNumber1Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomNumber2 | One of three number fields available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | long |
| cef.extensions.deviceCustomNumber2Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomNumber3 | One of three number fields available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | long |
| cef.extensions.deviceCustomNumber3Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString1 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString1Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString2 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString2Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString3 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString3Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString4 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString4Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString5 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString5Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceCustomString6 | One of six strings available to map fields that do not apply to any other in this dictionary. Use sparingly and seek a more specific, dictionary supplied field when possible. | keyword |
| cef.extensions.deviceCustomString6Label | All custom fields have a corresponding label field. Each of these fields is a string and describes the purpose of the custom field. | keyword |
| cef.extensions.deviceDirection | Any information about what direction the observed communication has taken. The following values are supported - "0" for inbound or "1" for outbound. | long |
| cef.extensions.deviceEventCategory | Represents the category assigned by the originating device. Devices often use their own categorization schema to classify event. Example "/Monitor/Disk/Read". | keyword |
| cef.extensions.deviceExternalId | A name that uniquely identifies the device generating this event. | keyword |
| cef.extensions.deviceFacility | The facility generating this event. For example, Syslog has an explicit facility associated with every event. | keyword |
| cef.extensions.deviceHostName | The format should be a fully qualified domain name (FQDN) associated with the device node, when a node is available. | keyword |
| cef.extensions.deviceInboundInterface | Interface on which the packet or data entered the device. | keyword |
| cef.extensions.deviceOutboundInterface | Interface on which the packet or data left the device. | keyword |
| cef.extensions.deviceProcessName | Process name associated with the event. An example might be the process generating the syslog entry in UNIX. | keyword |
| cef.extensions.deviceReceiptTime | The time at which the event related to the activity was received. The format is MMM dd yyyy HH:mm:ss or milliseconds since epoch (Jan 1st 1970) | keyword |
| cef.extensions.deviceSeverity |  | keyword |
| cef.extensions.deviceTimeZone | The time zone for the device generating the event. | keyword |
| cef.extensions.deviceZoneID |  | keyword |
| cef.extensions.deviceZoneURI | Thee URI for the Zone that the device asset has been assigned to in ArcSight. | keyword |
| cef.extensions.dvc | This field is used by Trend Micro if the hostname is an IPv4 address. | ip |
| cef.extensions.dvchost | This field is used by Trend Micro for hostnames and IPv6 addresses. | keyword |
| cef.extensions.eventAnnotationAuditTrail |  | keyword |
| cef.extensions.eventAnnotationEndTime |  | date |
| cef.extensions.eventAnnotationFlags |  | keyword |
| cef.extensions.eventAnnotationManagerReceiptTime |  | date |
| cef.extensions.eventAnnotationModificationTime |  | date |
| cef.extensions.eventAnnotationStageUpdateTime |  | date |
| cef.extensions.eventAnnotationVersion |  | keyword |
| cef.extensions.eventId | This is a unique ID that ArcSight assigns to each event. | long |
| cef.extensions.fileHash | Hash of a file. | keyword |
| cef.extensions.filePath | Full path to the file, including file name itself. | keyword |
| cef.extensions.fileSize | Size of the file. | long |
| cef.extensions.fileType | Type of file (pipe, socket, etc.) | keyword |
| cef.extensions.filename | Name of the file only (without its path). | keyword |
| cef.extensions.ifname |  | keyword |
| cef.extensions.inzone |  | keyword |
| cef.extensions.layer_name |  | keyword |
| cef.extensions.layer_uuid |  | keyword |
| cef.extensions.locality |  | keyword |
| cef.extensions.logid |  | keyword |
| cef.extensions.loguid |  | keyword |
| cef.extensions.managerReceiptTime | When the Arcsight ESM received the event. | date |
| cef.extensions.match_id |  | keyword |
| cef.extensions.message | An arbitrary message giving more details about the event. Multi-line entries can be produced by using \n as the new line separator. | keyword |
| cef.extensions.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| cef.extensions.modelConfidence |  | keyword |
| cef.extensions.nat_addtnl_rulenum |  | keyword |
| cef.extensions.nat_rulenum |  | keyword |
| cef.extensions.oldFileHash | Hash of the old file. | keyword |
| cef.extensions.origin |  | keyword |
| cef.extensions.originalAgentAddress |  | keyword |
| cef.extensions.originalAgentHostName |  | keyword |
| cef.extensions.originalAgentId |  | keyword |
| cef.extensions.originalAgentType |  | keyword |
| cef.extensions.originalAgentVersion |  | keyword |
| cef.extensions.originalAgentZoneURI |  | keyword |
| cef.extensions.originsicname |  | keyword |
| cef.extensions.outzone |  | keyword |
| cef.extensions.parent_rule |  | keyword |
| cef.extensions.priority |  | keyword |
| cef.extensions.product |  | keyword |
| cef.extensions.relevance |  | keyword |
| cef.extensions.repeatCount |  | keyword |
| cef.extensions.requestContext | Description of the content from which the request originated (for example, HTTP Referrer). | keyword |
| cef.extensions.requestMethod | The HTTP method used to access a URL. | keyword |
| cef.extensions.requestUrl | In the case of an HTTP request, this field contains the URL accessed. The URL should contain the protocol as well. | keyword |
| cef.extensions.requestUrlFileName |  | keyword |
| cef.extensions.rule_action |  | keyword |
| cef.extensions.rule_uid |  | keyword |
| cef.extensions.sequencenum |  | keyword |
| cef.extensions.service_id |  | keyword |
| cef.extensions.severity |  | keyword |
| cef.extensions.sourceAddress | Identifies the source that an event refers to in an IP network. | ip |
| cef.extensions.sourceGeoLatitude |  | long |
| cef.extensions.sourceGeoLongitude |  | long |
| cef.extensions.sourceHostName | Identifies the source that an event refers to in an IP network. The format should be a fully qualified domain name (FQDN) associated with the source node, when a mode is available. | keyword |
| cef.extensions.sourceMacAddress | Six colon-separated hexadecimal numbers. | keyword |
| cef.extensions.sourceNtDomain | The Windows domain name for the source address. | keyword |
| cef.extensions.sourcePort | The valid port numbers are 0 to 65535. | long |
| cef.extensions.sourceServiceName | The service that is responsible for generating this event. | keyword |
| cef.extensions.sourceTranslatedAddress | Identifies the translated source that the event refers to in an IP network. | ip |
| cef.extensions.sourceTranslatedPort | A port number after being translated by, for example, a firewall. Valid port numbers are 0 to 65535. | long |
| cef.extensions.sourceTranslatedZoneID |  | keyword |
| cef.extensions.sourceTranslatedZoneURI | The URI for the Translated Zone that the destination asset has been assigned to in ArcSight. | keyword |
| cef.extensions.sourceUserId | Identifies the source user by ID. This is the user associated with the source of the event. For example, in UNIX, the root user is generally associated with user ID 0. | keyword |
| cef.extensions.sourceUserName | Identifies the source user by name. Email addresses are also mapped into the UserName fields. The sender is a candidate to put into this field. | keyword |
| cef.extensions.sourceUserPrivileges | The typical values are "Administrator", "User", and "Guest". It identifies the source user's privileges. In UNIX, for example, activity executed by the root user would be identified with "Administrator". | keyword |
| cef.extensions.sourceZoneID | Identifies the source user by ID. This is the user associated with the source of the event. For example, in UNIX, the root user is generally associated with user ID 0. | keyword |
| cef.extensions.sourceZoneURI | The URI for the Zone that the source asset has been assigned to in ArcSight. | keyword |
| cef.extensions.startTime | The time when the activity the event referred to started. The format is MMM dd yyyy HH:mm:ss or milliseconds since epoch (Jan 1st 1970). | date |
| cef.extensions.target |  | keyword |
| cef.extensions.transportProtocol | Identifies the Layer-4 protocol used. The possible values are protocols such as TCP or UDP. | keyword |
| cef.extensions.type | 0 means base event, 1 means aggregated, 2 means correlation, and 3 means action. This field can be omitted for base events (type 0). | long |
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.service.name |  | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| source.service.name |  | keyword |

