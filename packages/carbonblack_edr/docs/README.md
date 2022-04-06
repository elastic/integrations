# VMware Carbon Black EDR Integration

The VMware Carbon Black EDR integration collects EDR Server and raw Endpoint events exported by [Carbon Black EDR Event Forwarder.](https://github.com/carbonblack/cb-event-forwarder) The following output methods are supported: `http`, `tcp`, `udp` and `file`.

## Compatibility

This integration has been tested with the 3.7.4 version of EDR Event Forwarder.

## Configuration

The following configuration is necessary in `cb-event-forwarder.conf`:

- `output_format=json` (default)

For `http` output:
  - `output_type=http`
  - `http_post_template=[{{range .Events}}{{.EventText}}{{end}}]`
  - `content_type=application/json` (default)

For `tcp` output:
  - `output_type=tcp`
  - `tcpout=<Address of Elastic Agent>:<port>`

For `udp` output:
- `output_type=tcp`
- `tcpout=<Address of Elastic Agent>:<port>`

For `file` output:
- `output_type=file`
- `outfile=<path to a file readable by Elastic Agent>`

An example event for `log` looks as following:

```json
{
    "@timestamp": "2014-04-11T19:21:33.682Z",
    "agent": {
        "ephemeral_id": "7bb86a18-d262-4348-b206-131e38d2d1c8",
        "id": "9cb9fa70-f3e9-45d8-b1cb-61425bd93e1a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "carbonblack": {
        "edr": {
            "event_timestamp": 1397244093.682,
            "feed_id": 7,
            "feed_name": "dxmtest1",
            "ioc_attr": {},
            "md5": "506708142BC63DABA64F2D3AD1DCD5BF",
            "report_id": "dxmtest1_04",
            "sensor_id": 3321
        }
    },
    "data_stream": {
        "dataset": "carbonblack_edr.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "9cb9fa70-f3e9-45d8-b1cb-61425bd93e1a",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "unknown",
        "agent_id_status": "verified",
        "dataset": "carbonblack_edr.log",
        "ingested": "2022-01-25T07:45:03Z",
        "kind": "event",
        "original": "{\"md5\":\"506708142BC63DABA64F2D3AD1DCD5BF\",\"report_id\":\"dxmtest1_04\",\"ioc_type\":\"md5\",\"ioc_value\":\"506708142bc63daba64f2d3ad1dcd5bf\",\"ioc_attr\":{},\"feed_id\":7,\"hostname\":\"FS-SEA-529\",\"sensor_id\":3321,\"cb_version\":\"4.2.1.140808.1059\",\"server_name\":\"localhost.localdomain\",\"feed_name\":\"dxmtest1\",\"event_timestamp\":1397244093.682}\n"
    },
    "host": {
        "name": "FS-SEA-529"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.19.0.4:46263"
        }
    },
    "observer": {
        "name": "localhost.localdomain",
        "product": "Carbon Black EDR",
        "type": "edr",
        "vendor": "VMWare",
        "version": "4.2.1.140808.1059"
    },
    "tags": [
        "carbonblack_edr-log",
        "forwarded",
        "preserve_original_event"
    ],
    "threat": {
        "indicator": {
            "file": {
                "hash": {
                    "md5": "506708142bc63daba64f2d3ad1dcd5bf"
                }
            },
            "type": "file"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| carbonblack.edr.action |  | keyword |
| carbonblack.edr.actiontype |  | keyword |
| carbonblack.edr.alert_severity |  | double |
| carbonblack.edr.alert_type |  | keyword |
| carbonblack.edr.blocked |  | boolean |
| carbonblack.edr.blocked_event |  | keyword |
| carbonblack.edr.blocked_reason |  | keyword |
| carbonblack.edr.blocked_result |  | keyword |
| carbonblack.edr.cb_server |  | keyword |
| carbonblack.edr.cb_version |  | keyword |
| carbonblack.edr.child_command_line |  | keyword |
| carbonblack.edr.child_pid |  | long |
| carbonblack.edr.child_process_guid |  | keyword |
| carbonblack.edr.child_suppressed |  | boolean |
| carbonblack.edr.child_username |  | keyword |
| carbonblack.edr.childproc_count |  | long |
| carbonblack.edr.childproc_type |  | keyword |
| carbonblack.edr.command_line |  | keyword |
| carbonblack.edr.comms_ip |  | keyword |
| carbonblack.edr.compressed_size |  | long |
| carbonblack.edr.computer_name |  | keyword |
| carbonblack.edr.created |  | boolean |
| carbonblack.edr.created_time |  | keyword |
| carbonblack.edr.cross_process_type |  | keyword |
| carbonblack.edr.crossproc_count |  | long |
| carbonblack.edr.digsig.issuer_name |  | keyword |
| carbonblack.edr.digsig.program_name |  | keyword |
| carbonblack.edr.digsig.publisher |  | keyword |
| carbonblack.edr.digsig.result |  | keyword |
| carbonblack.edr.digsig.result_code |  | keyword |
| carbonblack.edr.digsig.sign_time |  | keyword |
| carbonblack.edr.digsig.subject_name |  | keyword |
| carbonblack.edr.direction |  | keyword |
| carbonblack.edr.doc |  | flattened |
| carbonblack.edr.domain |  | keyword |
| carbonblack.edr.emet_timestamp |  | long |
| carbonblack.edr.event_timestamp |  | double |
| carbonblack.edr.event_type |  | keyword |
| carbonblack.edr.expect_followon_w_md5 |  | boolean |
| carbonblack.edr.feed_id |  | keyword |
| carbonblack.edr.feed_name |  | keyword |
| carbonblack.edr.feed_rating |  | double |
| carbonblack.edr.file_md5 |  | keyword |
| carbonblack.edr.file_path |  | keyword |
| carbonblack.edr.file_sha256 |  | keyword |
| carbonblack.edr.filemod_count |  | long |
| carbonblack.edr.filetype |  | keyword |
| carbonblack.edr.filetype_name |  | keyword |
| carbonblack.edr.filtering_known_dlls |  | boolean |
| carbonblack.edr.group |  | keyword |
| carbonblack.edr.host |  | keyword |
| carbonblack.edr.hostname |  | keyword |
| carbonblack.edr.icon |  | keyword |
| carbonblack.edr.image_file_header |  | keyword |
| carbonblack.edr.interface_ip |  | keyword |
| carbonblack.edr.ioc_attr |  | flattened |
| carbonblack.edr.ioc_confidence |  | double |
| carbonblack.edr.ioc_type |  | keyword |
| carbonblack.edr.ioc_value |  | keyword |
| carbonblack.edr.ipv4 |  | keyword |
| carbonblack.edr.is_target |  | boolean |
| carbonblack.edr.ja3 |  | keyword |
| carbonblack.edr.ja3s |  | keyword |
| carbonblack.edr.link_child |  | keyword |
| carbonblack.edr.link_md5 |  | keyword |
| carbonblack.edr.link_parent |  | keyword |
| carbonblack.edr.link_process |  | keyword |
| carbonblack.edr.link_sensor |  | keyword |
| carbonblack.edr.link_target |  | keyword |
| carbonblack.edr.local_ip |  | keyword |
| carbonblack.edr.local_port |  | long |
| carbonblack.edr.log_id |  | keyword |
| carbonblack.edr.log_message |  | keyword |
| carbonblack.edr.md5 |  | keyword |
| carbonblack.edr.mitigation |  | keyword |
| carbonblack.edr.modload_count |  | long |
| carbonblack.edr.netconn_count |  | long |
| carbonblack.edr.os_type |  | keyword |
| carbonblack.edr.parent_create_time |  | long |
| carbonblack.edr.parent_guid |  | keyword |
| carbonblack.edr.parent_md5 |  | keyword |
| carbonblack.edr.parent_path |  | keyword |
| carbonblack.edr.parent_pid |  | long |
| carbonblack.edr.parent_process_guid |  | keyword |
| carbonblack.edr.parent_sha256 |  | keyword |
| carbonblack.edr.path |  | keyword |
| carbonblack.edr.pid |  | long |
| carbonblack.edr.port |  | long |
| carbonblack.edr.process_guid |  | keyword |
| carbonblack.edr.process_id |  | keyword |
| carbonblack.edr.process_name |  | keyword |
| carbonblack.edr.process_path |  | keyword |
| carbonblack.edr.process_unique_id |  | keyword |
| carbonblack.edr.protocol |  | keyword |
| carbonblack.edr.proxy |  | boolean |
| carbonblack.edr.regmod_count |  | long |
| carbonblack.edr.remote_ip |  | keyword |
| carbonblack.edr.remote_port |  | long |
| carbonblack.edr.report_id |  | keyword |
| carbonblack.edr.report_score |  | long |
| carbonblack.edr.requested_access |  | long |
| carbonblack.edr.scores.alliance_score_srstrust |  | long |
| carbonblack.edr.scores.alliance_score_virustotal |  | long |
| carbonblack.edr.script |  | keyword |
| carbonblack.edr.script_sha256 |  | keyword |
| carbonblack.edr.segment_id |  | keyword |
| carbonblack.edr.sensor_criticality |  | double |
| carbonblack.edr.sensor_id |  | keyword |
| carbonblack.edr.server_name |  | keyword |
| carbonblack.edr.sha256 |  | keyword |
| carbonblack.edr.size |  | long |
| carbonblack.edr.status |  | keyword |
| carbonblack.edr.tamper |  | boolean |
| carbonblack.edr.tamper_sent |  | boolean |
| carbonblack.edr.tamper_type |  | keyword |
| carbonblack.edr.target_create_time |  | long |
| carbonblack.edr.target_md5 |  | keyword |
| carbonblack.edr.target_path |  | keyword |
| carbonblack.edr.target_pid |  | long |
| carbonblack.edr.target_process_guid |  | keyword |
| carbonblack.edr.target_sha256 |  | keyword |
| carbonblack.edr.timestamp |  | double |
| carbonblack.edr.type |  | keyword |
| carbonblack.edr.uid |  | keyword |
| carbonblack.edr.unique_id |  | keyword |
| carbonblack.edr.username |  | keyword |
| carbonblack.edr.utf8_comments |  | keyword |
| carbonblack.edr.utf8_company_name |  | keyword |
| carbonblack.edr.utf8_copied_module_length |  | long |
| carbonblack.edr.utf8_file_description |  | keyword |
| carbonblack.edr.utf8_file_version |  | keyword |
| carbonblack.edr.utf8_internal_name |  | keyword |
| carbonblack.edr.utf8_legal_copyright |  | keyword |
| carbonblack.edr.utf8_legal_trademark |  | keyword |
| carbonblack.edr.utf8_on_disk_filename |  | keyword |
| carbonblack.edr.utf8_original_file_name |  | keyword |
| carbonblack.edr.utf8_private_build |  | keyword |
| carbonblack.edr.utf8_product_description |  | keyword |
| carbonblack.edr.utf8_product_name |  | keyword |
| carbonblack.edr.utf8_product_version |  | keyword |
| carbonblack.edr.utf8_special_build |  | keyword |
| carbonblack.edr.watchlist_id |  | keyword |
| carbonblack.edr.watchlist_name |  | keyword |
| carbonblack.edr.watchlists.watchlist_1 |  | keyword |
| carbonblack.edr.watchlists.watchlist_7 |  | keyword |
| carbonblack.edr.watchlists.watchlist_9 |  | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.attributes | Array of file attributes. Attributes names will vary by platform. Here's a non-exhaustive list of values that are expected in this field: archive, compressed, directory, encrypted, execute, hidden, read, readonly, system, write. | keyword |
| file.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| file.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| file.code_signature.subject_name | Subject name of the code signer | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.pe.architecture | CPU architecture target for the file. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
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
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. One of these following values should be used (lowercase): linux, macos, unix, windows. If the OS you're dealing with is not in the list, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. One of these following values should be used (lowercase): linux, macos, unix, windows. If the OS you're dealing with is not in the list, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.hash.md5 | MD5 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| registry.path | Full path, including hive, key and value | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.port | Identifies a threat indicator as a port number (irrespective of direction). | long |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. Recommended values:   \* autonomous-system   \* artifact   \* directory   \* domain-name   \* email-addr   \* file   \* ipv4-addr   \* ipv6-addr   \* mac-addr   \* mutex   \* port   \* process   \* software   \* url   \* user-account   \* windows-registry-key   \* x509-certificate | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |


