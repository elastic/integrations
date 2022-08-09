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
    "@timestamp": "2022-06-03T01:39:47.734Z",
    "agent": {
        "ephemeral_id": "167ce484-a1a1-4fac-aaff-607b859e3ddf",
        "id": "69f5d3be-c31a-4be6-adb6-cb3ed3e50817",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
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
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "69f5d3be-c31a-4be6-adb6-cb3ed3e50817",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "code": "18",
        "dataset": "cef.log",
        "id": "3457",
        "ingested": "2022-06-03T01:39:48Z",
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
            "address": "192.168.112.4:35889"
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
| cef.extensions.baseEventCount | A count associated with this event. How many times was this same event observed? Count can be omitted if it is 1. | keyword |
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
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
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
| destination.port | Port of the destination. | long |
| destination.service.name |  | keyword |
| destination.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| destination.user.group.name | Name of the group. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| file.group | Primary group name of the file. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.egress.zone | Network zone of outbound traffic as reported by the observer to categorize the destination area of egress traffic, e.g. Internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.zone | Network zone of incoming traffic as reported by the observer to categorize the source area of ingress traffic. e.g. internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.uuid | A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| source.port | Port of the source. | long |
| source.service.name |  | keyword |
| source.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |

