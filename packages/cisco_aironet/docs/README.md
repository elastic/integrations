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
    "_index": "logs-cisco_aironet",
    "_id": "H5vg3YIBQlg6tLSWfDy2",
    "_version": 1,
    "_score": 0,
    "_source": {
        "process": {
            "name": "sisf_shim_utils.c",
            "pid": "482",
            "title": "SISF BT Process"
        },
        "@timestamp": "2022-08-27T05:57:32.461Z",
        "ecs": {
            "version": "8.3.1"
        },
        "log": {
            "level": "informational",
            "syslog": {
                "severity": {
                    "code": 6
                },
                "priority": 134,
                "facility": {
                    "code": 16
                }
            }
        },
        "@version": "1",
        "input_type": "syslog",
        "host": {
            "ip": "188.63.222.223",
            "name": "Home WLC"
        },
        "client": {
            "ip": "fe80::aee2:d3ff:feba:56a4"
        },
        "type": "syslog",
        "message": "Entry deleted A=fe80::aee2:d3ff:feba:56a4 V=0 I=wired:1 P=0000 M=",
        "event": {
            "severity": "6",
            "reason": "ENTRY_DELETED",
            "original": "\u003c134\u003eHome WLC: *SISF BT Process: Aug 27 05:57:32.461: %SISF-6-ENTRY_DELETED: sisf_shim_utils.c:482 Entry deleted A=fe80::aee2:d3ff:feba:56a4 V=0 I=wired:1 P=0000 M=",
            "provider": "SISF",
            "module": "aironet"
        }
    },
    "fields": {
        "log.level.keyword": [
            "informational"
        ],
        "host.name.keyword": [
            "Home WLC"
        ],
        "type": [
            "syslog"
        ],
        "process.pid": [
            "482"
        ],
        "host.ip": [
            "188.63.222.223"
        ],
        "host.ip.keyword": [
            "188.63.222.223"
        ],
        "ecs.version.keyword": [
            "8.3.1"
        ],
        "event.module": [
            "aironet"
        ],
        "process.title.keyword": [
            "SISF BT Process"
        ],
        "type.keyword": [
            "syslog"
        ],
        "event.reason": [
            "ENTRY_DELETED"
        ],
        "process.pid.keyword": [
            "482"
        ],
        "@version": [
            "1"
        ],
        "log.level": [
            "informational"
        ],
        "event.provider.keyword": [
            "SISF"
        ],
        "host.name": [
            "Home WLC"
        ],
        "log.syslog.priority": [
            134
        ],
        "event.severity": [
            "6"
        ],
        "event.original": [
            "\u003c134\u003eHome WLC: *SISF BT Process: Aug 27 05:57:32.461: %SISF-6-ENTRY_DELETED: sisf_shim_utils.c:482 Entry deleted A=fe80::aee2:d3ff:feba:56a4 V=0 I=wired:1 P=0000 M="
        ],
        "log.syslog.severity.code": [
            6
        ],
        "input_type.keyword": [
            "syslog"
        ],
        "event.severity.keyword": [
            "6"
        ],
        "input_type": [
            "syslog"
        ],
        "@version.keyword": [
            "1"
        ],
        "client.ip": [
            "fe80::aee2:d3ff:feba:56a4"
        ],
        "message": [
            "Entry deleted A=fe80::aee2:d3ff:feba:56a4 V=0 I=wired:1 P=0000 M="
        ],
        "process.name": [
            "sisf_shim_utils.c"
        ],
        "event.provider": [
            "SISF"
        ],
        "@timestamp": [
            "2022-08-27T05:57:32.461Z"
        ],
        "event.reason.keyword": [
            "ENTRY_DELETED"
        ],
        "process.name.keyword": [
            "sisf_shim_utils.c"
        ],
        "ecs.version": [
            "8.3.1"
        ],
        "message.keyword": [
            "Entry deleted A=fe80::aee2:d3ff:feba:56a4 V=0 I=wired:1 P=0000 M="
        ],
        "event.original.keyword": [
            "\u003c134\u003eHome WLC: *SISF BT Process: Aug 27 05:57:32.461: %SISF-6-ENTRY_DELETED: sisf_shim_utils.c:482 Entry deleted A=fe80::aee2:d3ff:feba:56a4 V=0 I=wired:1 P=0000 M="
        ],
        "event.module.keyword": [
            "aironet"
        ],
        "process.title": [
            "SISF BT Process"
        ],
        "client.ip.keyword": [
            "fe80::aee2:d3ff:feba:56a4"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
