# QNAP NAS

The QNAP NAS integration collects Event and Access logs from QNAP NAS devices.

## Log

The `log` dataset receives QNAP NAS Event and Access logs over the syslog protocol. This has been tested with QTS 4.5.4 but is expected to work with new versions.  This integration is only compatible with the "Send to Syslog Server" option which uses the RFC-3164 syslog format. Both Event and Access events are supported. All protocols; UDP, TCP, TLS are supported.

### Example event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-10-30T20:24:24.000Z",
    "agent": {
        "ephemeral_id": "b6db294f-f5fd-4570-9d9c-cd0a74001651",
        "id": "b1d83907-ff3e-464a-b79a-cf843f6f0bba",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "qnap_nas.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "b1d83907-ff3e-464a-b79a-cf843f6f0bba",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "create-directory",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "created": "2022-10-30T20:24:24.000Z",
        "dataset": "qnap_nas.log",
        "ingested": "2022-01-02T09:51:24Z",
        "kind": "event",
        "provider": "conn-log",
        "timezone": "+00:00",
        "type": [
            "creation"
        ]
    },
    "file": {
        "path": "path/to/files/New folder"
    },
    "host": {
        "name": "qnap-nas01"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.18.0.7:46086"
        },
        "syslog": {
            "priority": 30
        }
    },
    "observer": {
        "product": "NAS",
        "type": "nas",
        "vendor": "QNAP"
    },
    "process": {
        "name": "qulogd",
        "pid": 14629
    },
    "qnap": {
        "nas": {
            "connection_type": "Samba",
            "file": {
                "path": "path/to/files/New folder"
            }
        }
    },
    "related": {
        "hosts": [
            "user-laptop"
        ],
        "ip": [
            "10.50.36.33"
        ],
        "user": [
            "admin.user"
        ]
    },
    "source": {
        "address": "10.50.36.33",
        "domain": "user-laptop",
        "ip": "10.50.36.33"
    },
    "tags": [
        "qnap-nas",
        "forwarded"
    ],
    "user": {
        "name": "admin.user"
    }
}
```

**Exported fields**

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| group.name | Name of the group. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| qnap.nas.application | QNAP application that generated the event | keyword |
| qnap.nas.category | Sub-component of the QNAP application that generated the event | keyword |
| qnap.nas.connection_type | Connection type (ex. Samba) | keyword |
| qnap.nas.file.new_path | Renamed/Moved path of accessed resource | keyword |
| qnap.nas.file.path | Path of accessed resource | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |

