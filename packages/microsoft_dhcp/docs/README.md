# Microsoft DHCP

This integration collects logs and metrics from Microsoft DHCP logs.

## Compatibility

This integration has been made to support the DHCP log format from Windows Server 2008 and later.

### Logs

Ingest logs from Microsoft DHCP Server, by default logged with the filename format:
`%windir%\System32\DHCP\DhcpSrvLog-*.log`

Logs may also be ingested from Microsoft DHCPv6 Server, by default logged with the filename format:
`%windir%\System32\DHCP\DhcpV6SrvLog-*.log`

Relevant documentation for Microsoft DHCP can be found on [this]https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd183591(v=ws.10) location.

An example event for `log` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "ca0beb8d-9522-4450-8af7-3cb7f3d8c478",
        "type": "filebeat",
        "ephemeral_id": "adc79855-a07e-4f88-b14d-79d03400f73d",
        "version": "8.2.0"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/test-dhcpV6.log"
        },
        "offset": 1619
    },
    "elastic_agent": {
        "id": "ca0beb8d-9522-4450-8af7-3cb7f3d8c478",
        "version": "8.2.0",
        "snapshot": false
    },
    "message": "DHCPV6 Request",
    "microsoft": {
        "dhcp": {
            "duid": {
                "length": "18",
                "hex": "0004A34473BFC27FC55B25E86AF0E1761DAA"
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "microsoft_dhcp"
    ],
    "observer": {
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02-42-AC-12-00-07"
        ]
    },
    "input": {
        "type": "log"
    },
    "@timestamp": "2021-12-06T12:43:57.000-05:00",
    "ecs": {
        "version": "8.3.0"
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "microsoft_dhcp.log"
    },
    "host": {
        "ip": "2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6",
        "domain": "test-host"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2022-05-09T14:40:22Z",
        "original": "11002,12/06/21,12:43:57,DHCPV6 Request,2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6,test-host,,18,0004A34473BFC27FC55B25E86AF0E1761DAA,,,,,",
        "code": "11002",
        "timezone": "America/New_York",
        "kind": "event",
        "action": "dhcpv6-request",
        "category": [
            "network"
        ],
        "type": [
            "connection",
            "protocol"
        ],
        "dataset": "microsoft_dhcp.log",
        "outcome": "success"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset |  | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| microsoft.dhcp.correlation_id | The NAP correlation ID related to the client/server transaction. | keyword |
| microsoft.dhcp.dhc_id | The related DHCID (DHC DNS record). | keyword |
| microsoft.dhcp.dns_error_code | DNS error code communicated to client. | keyword |
| microsoft.dhcp.duid.hex | The related DHCP Unique Identifier (DUID) for the host (DHCPv6). | keyword |
| microsoft.dhcp.duid.length | The length of the DUID field. | keyword |
| microsoft.dhcp.error_code | DHCP server error code. | keyword |
| microsoft.dhcp.probation_time | The probation time before lease ends on specific IP. | keyword |
| microsoft.dhcp.relay_agent_info | Information about DHCP relay agent used for the DHCP request. | keyword |
| microsoft.dhcp.result | The DHCP result type, for example "NoQuarantine", "Drop Packet" etc. | keyword |
| microsoft.dhcp.subnet_prefix | The number of bits for the subnet prefix. | keyword |
| microsoft.dhcp.transaction_id | The DHCP transaction ID. | keyword |
| microsoft.dhcp.user.hex | Hex representation of the user. | keyword |
| microsoft.dhcp.user.string | String representation of the user. | keyword |
| microsoft.dhcp.vendor.hex | Hex representation of the vendor. | keyword |
| microsoft.dhcp.vendor.string | String representation of the vendor. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.mac | MAC addresses of the observer. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
