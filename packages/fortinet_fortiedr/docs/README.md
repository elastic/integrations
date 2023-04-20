# Fortinet FortiEDR Integration

This integration is for Fortinet FortiEDR logs sent in the syslog format.

## Configuration

The Fortinet FortiEDR integration requires that the **Send Syslog Notification** option be turned on in the FortiEDR Playbook policy that includes the devices that are to be monitored by the integration, and a syslog export must be defined.

### Define syslog export

1. In Fortinet console, navigate to Administration > Export Settings
2. Fill in details for the target syslog server. See the Administration Guide [syslog](https://docs.fortinet.com/document/fortiedr/5.0.0/administration-guide/109591/syslog) documentation for details.

### Set up syslog notifications

1. Navigate to Security Settings > Playbooks.
2. In notifications for the playbook being used, set appropriate Send Syslog Notification options for the events to be collected. See [Automated Incident Response - Playbooks Page](https://docs.fortinet.com/document/fortiedr/5.0.0/administration-guide/419440/automated-incident-response-playbooks-page).

### Log

The `log` dataset collects Fortinet FortiEDR logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2019-09-18T06:42:18.000Z",
    "agent": {
        "ephemeral_id": "a328c9b6-3f49-4e0a-bc08-181d13ad6b77",
        "id": "e2f57999-9659-45c8-a03c-c5bf85dc5124",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.3"
    },
    "data_stream": {
        "dataset": "fortinet_fortiedr.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "e2f57999-9659-45c8-a03c-c5bf85dc5124",
        "snapshot": false,
        "version": "8.3.3"
    },
    "event": {
        "action": "blocked",
        "agent_id_status": "verified",
        "category": "malware",
        "dataset": "fortinet_fortiedr.log",
        "end": "2019-09-18T02:42:18.000Z",
        "id": "458478",
        "ingested": "2022-08-26T07:24:21Z",
        "original": "\u003c133\u003e1 2019-09-18T06:42:18.000Z 1.1.1.1 enSilo - - - Organization: Demo;Organization ID: 156646;Event ID: 458478; Raw Data ID: 1270886879;Device Name: WIN10-VICTIM;Operating System: Windows 10 Pro N; Process Name: svchost.exe;Process Path: \\Device\\HarddiskVolume4\\Windows\\System32\\svchost.exe; Process Type: 64bit;Severity: Critical;Classification: Suspicious;Destination: File Creation; First Seen: 18-Sep-2019, 02:42:18;Last Seen: 18-Sep-2019, 02:42:18;Action: Blocked;Count: 1; Certificate: yes;Rules List: File Encryptor - Suspicious file modification;Users: WIN10-VICTIM\\U; MAC Address: 00-0C-29-D4-75-EC;Script: N/A;Script Path: N/A;Autonomous System: N/A;Country: N/A",
        "start": "2019-09-18T02:42:18.000Z",
        "timezone": "+00:00"
    },
    "fortinet": {
        "edr": {
            "action": "Blocked",
            "autonomous_system": "N/A",
            "certificate": "yes",
            "classification": "Suspicious",
            "count": "1",
            "country": "N/A",
            "destination": "File Creation",
            "device_name": "WIN10-VICTIM",
            "event_id": "458478",
            "first_seen": "2019-09-18T02:42:18.000Z",
            "last_seen": "2019-09-18T02:42:18.000Z",
            "mac_address": "00-0C-29-D4-75-EC",
            "operating_system": "Windows 10 Pro N",
            "organization": "Demo",
            "organization_id": "156646",
            "process_name": "svchost.exe",
            "process_path": "\\Device\\HarddiskVolume4\\Windows\\System32\\svchost.exe",
            "process_type": "64bit",
            "raw_data_id": "1270886879",
            "rules_list": "File Encryptor - Suspicious file modification",
            "script": "N/A",
            "script_path": "N/A",
            "severity": "Critical",
            "users": "WIN10-VICTIM\\U"
        }
    },
    "host": {
        "hostname": "WIN10-VICTIM",
        "mac": [
            "00-0C-29-D4-75-EC"
        ],
        "os": {
            "full": "Windows 10 Pro N"
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.48.4:47582"
        },
        "syslog": {
            "appname": "enSilo",
            "facility": {
                "code": 16
            },
            "hostname": "1.1.1.1",
            "priority": 133,
            "severity": {
                "code": 5
            },
            "version": "1"
        }
    },
    "observer": {
        "product": "FortiEDR",
        "type": "edr",
        "vendor": "Fortinet"
    },
    "process": {
        "executable": "\\Device\\HarddiskVolume4\\Windows\\System32\\svchost.exe",
        "name": "svchost.exe"
    },
    "related": {
        "hosts": [
            "WIN10-VICTIM",
            "1.1.1.1"
        ],
        "user": [
            "WIN10-VICTIM\\U"
        ]
    },
    "tags": [
        "preserve_original_event",
        "fortinet-fortiedr",
        "forwarded"
    ],
    "user": {
        "id": "WIN10-VICTIM\\U"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
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
| fortinet.edr.action |  | keyword |
| fortinet.edr.autonomous_system |  | keyword |
| fortinet.edr.certificate |  | keyword |
| fortinet.edr.classification |  | keyword |
| fortinet.edr.count |  | keyword |
| fortinet.edr.country |  | keyword |
| fortinet.edr.destination |  | keyword |
| fortinet.edr.device_name |  | keyword |
| fortinet.edr.event_id |  | keyword |
| fortinet.edr.first_seen |  | date |
| fortinet.edr.last_seen |  | date |
| fortinet.edr.mac_address |  | keyword |
| fortinet.edr.operating_system |  | keyword |
| fortinet.edr.organization |  | keyword |
| fortinet.edr.organization_id |  | keyword |
| fortinet.edr.process_name |  | keyword |
| fortinet.edr.process_path |  | keyword |
| fortinet.edr.process_type |  | keyword |
| fortinet.edr.raw_data_id |  | keyword |
| fortinet.edr.rules_list |  | keyword |
| fortinet.edr.script |  | keyword |
| fortinet.edr.script_path |  | keyword |
| fortinet.edr.severity |  | keyword |
| fortinet.edr.users |  | keyword |
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
| log.file.path | Full path to the log file this event came from. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.appname | The device or application that originated the Syslog message, if available. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.hostname | The hostname, FQDN, or IP of the machine that originally sent the Syslog message. This is sourced from the hostname field of the syslog header. Depending on the environment, this value may be different from the host that handled the event, especially if the host handling the events is acting as a collector. | keyword |
| log.syslog.msgid | An identifier for the type of Syslog message, if available. Only applicable for RFC 5424 messages. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.procid | The process name or ID that originated the Syslog message, if available. | keyword |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| log.syslog.version | The version of the Syslog protocol specification. Only applicable for RFC 5424 messages. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
