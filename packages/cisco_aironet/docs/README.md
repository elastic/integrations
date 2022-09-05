# Cisco Aironet

This integration is for Cisco Aironet WLC logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Cisco Aironet WLC logs.

## Logs

### Aironet

The `log` dataset collects the Cisco Aironet WLC logs.

[Log Documentation](https://www.cisco.com/c/en/us/support/wireless/wireless-lan-controller-software/products-system-message-guides-list.html)


An example event for `log` looks as following:

```json
{
    "_index": ".ds-logs-cisco_aironet.log-ep-2022.09.05-000001",
    "_id": "V52IDoMB6b9fJQT6YFqW",
    "_version": 1,
    "_score": 0,
    "_source": {
        "agent": {
            "name": "docker-fleet-agent",
            "id": "cb015bb4-b2f0-42ec-a404-9e771349a3fb",
            "type": "filebeat",
            "ephemeral_id": "66f994cb-7042-4fd0-ae3c-6ee4fab317f5",
            "version": "8.3.3"
        },
        "process": {
            "name": "radiusTransportThread"
        },
        "log": {
            "level": "error",
            "source": {
                "address": "172.24.0.7:53668"
            },
            "syslog": {
                "severity": {
                    "code": 3
                },
                "priority": 131,
                "facility": {
                    "code": 16
                }
            }
        },
        "elastic_agent": {
            "id": "cb015bb4-b2f0-42ec-a404-9e771349a3fb",
            "version": "8.3.3",
            "snapshot": false
        },
        "message": "Invalid AAA request. unknown",
        "tags": [
            "preserve_original_event",
            "cisco-aironet",
            "forwarded"
        ],
        "input": {
            "type": "tcp"
        },
        "@timestamp": "2022-08-29T10:58:58.000Z",
        "ecs": {
            "version": "8.3.1"
        },
        "data_stream": {
            "namespace": "ep",
            "type": "logs",
            "dataset": "cisco_aironet.log"
        },
        "host": {
            "name": "WLC001"
        },
        "event": {
            "severity": "3",
            "agent_id_status": "verified",
            "reason": "The system has received an AAA request with a null or invalid payload.",
            "ingested": "2022-09-05T16:42:42Z",
            "original": "\u003c131\u003eWLC001: *radiusTransportThread: Aug 29 10:58:58.000: %AAA-3-INVALID_REQUEST: [PA]radius_db.c:3923 Invalid AAA request. unknown",
            "provider": "AAA",
            "timezone": "+00:00",
            "action": "INVALID_REQUEST",
            "dataset": "cisco_aironet.log"
        }
    },
    "fields": {
        "elastic_agent.version": [
            "8.3.3"
        ],
        "process.name.text": [
            "radiusTransportThread"
        ],
        "agent.type": [
            "filebeat"
        ],
        "event.module": [
            "cisco_aironet"
        ],
        "event.reason": [
            "The system has received an AAA request with a null or invalid payload."
        ],
        "log.level": [
            "error"
        ],
        "agent.name": [
            "docker-fleet-agent"
        ],
        "elastic_agent.snapshot": [
            false
        ],
        "host.name": [
            "WLC001"
        ],
        "log.syslog.priority": [
            131
        ],
        "event.agent_id_status": [
            "verified"
        ],
        "event.timezone": [
            "+00:00"
        ],
        "event.severity": [
            "3"
        ],
        "log.syslog.severity.code": [
            3
        ],
        "event.original": [
            "\u003c131\u003eWLC001: *radiusTransportThread: Aug 29 10:58:58.000: %AAA-3-INVALID_REQUEST: [PA]radius_db.c:3923 Invalid AAA request. unknown"
        ],
        "elastic_agent.id": [
            "cb015bb4-b2f0-42ec-a404-9e771349a3fb"
        ],
        "data_stream.namespace": [
            "ep"
        ],
        "input.type": [
            "tcp"
        ],
        "message": [
            "Invalid AAA request. unknown"
        ],
        "data_stream.type": [
            "logs"
        ],
        "tags": [
            "preserve_original_event",
            "cisco-aironet",
            "forwarded"
        ],
        "process.name": [
            "radiusTransportThread"
        ],
        "event.provider": [
            "AAA"
        ],
        "event.action": [
            "INVALID_REQUEST"
        ],
        "event.ingested": [
            "2022-09-05T16:42:42.000Z"
        ],
        "@timestamp": [
            "2022-08-29T10:58:58.000Z"
        ],
        "agent.id": [
            "cb015bb4-b2f0-42ec-a404-9e771349a3fb"
        ],
        "ecs.version": [
            "8.3.1"
        ],
        "log.source.address": [
            "172.24.0.7:53668"
        ],
        "data_stream.dataset": [
            "cisco_aironet.log"
        ],
        "agent.ephemeral_id": [
            "66f994cb-7042-4fd0-ae3c-6ee4fab317f5"
        ],
        "agent.version": [
            "8.3.3"
        ],
        "event.dataset": [
            "cisco_aironet.log"
        ],
        "log.syslog.facility.code": [
            16
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type. | keyword |
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
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
