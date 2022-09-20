# Cisco Aironet

This integration is for Cisco Aironet WLC logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Cisco Aironet WLC logs.

## Logs

### Aironet

The `log` dataset collects the Cisco Aironet WLC logs. The descriptions of system messages can be obtained from the [Cisco documentation](https://www.cisco.com/c/en/us/support/wireless/wireless-lan-controller-software/products-system-message-guides-list.html).


An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-08-20T11:25:50.157Z",
    "agent": {
        "ephemeral_id": "df000191-6494-448e-9b24-396a3762094a",
        "id": "68e210ce-ee67-482a-8fb4-c45055e6f2b2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.3"
    },
    "cisco": {
        "interface": {
            "type": "wired"
        }
    },
    "client": {
        "ip": "fe80::aee2:d3ff:feba:56a4"
    },
    "data_stream": {
        "dataset": "cisco_aironet.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "elastic_agent": {
        "id": "68e210ce-ee67-482a-8fb4-c45055e6f2b2",
        "snapshot": false,
        "version": "8.3.3"
    },
    "event": {
        "action": "ENTRY_DELETED",
        "agent_id_status": "verified",
        "dataset": "cisco_aironet.log",
        "ingested": "2022-09-09T08:30:39Z",
        "original": "\u003c134\u003eWLC001: *SISF BT Process: Aug 20 11:25:50.157: %SISF-6-ENTRY_DELETED: sisf_shim_utils.c:482 Entry deleted A=fe80::aee2:d3ff:feba:56a4 V=0 I=wired:1 P=0000 M=",
        "provider": "SISF",
        "severity": "6",
        "timezone": "+00:00"
    },
    "host": {
        "name": "WLC001"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "level": "informational",
        "source": {
            "address": "172.26.0.5:45299"
        },
        "syslog": {
            "facility": {
                "code": 16
            },
            "priority": 134,
            "severity": {
                "code": 6
            }
        }
    },
    "message": "Entry deleted A=fe80::aee2:d3ff:feba:56a4 V=0 I=wired:1 P=0000 M=",
    "process": {
        "name": "SISF BT Process"
    },
    "tags": [
        "preserve_original_event",
        "cisco-aironet",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco.eapol.descriptor | Cisco eapol descriptor | short |
| cisco.eapol.type | Cisco eapol type | short |
| cisco.eapol.version | Cisco eapol version | short |
| cisco.interface.type | Cisco interface type | keyword |
| cisco.wps.channel | Cisco WPS channel | short |
| cisco.wps.hits | Cisco WPS hits | short |
| cisco.wps.preced | Cisco WPS precedence | short |
| cisco.wps.slot | Cisco WPS slot | short |
| cisco.wps.track | Cisco WPS track | keyword |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.as.organization.name.text | Multi-field of `client.as.organization.name`. | match_only_text |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.mac | MAC address of the client. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type. | keyword |
| interface.id | Interface ID as reported by an observer (typically SNMP interface ID). | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset |  | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
