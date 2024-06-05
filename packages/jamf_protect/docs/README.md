# Jamf Protect

The Jamf Protect integration collects and parses data received from [Jamf Protect](https://learn.jamf.com/bundle/jamf-protect-documentation/page/About_Jamf_Protect.html) using the following methods.

- HTTP Endpoint mode - Jamf Protect streams logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode - Jamf Protect forwards data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Jamf Protect writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

Use the Jamf Protect integration to collect logs from your machines.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

## Data streams

The Jamf Protect integration collects 4 types of events: alerts, telemetry, web threat events, and web traffic events.

[**Alerts**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Alerts.html) help you keep a record of Alerts and Unified Logs happening on endpoints using Jamf Protect.

[**Telemetry**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html) help you keep a record of audit events happening on endpoints using Jamf Protect.

[**Web threat events**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Streams_Overview.html) help you keep a record of web threat events happening on endpoints using Jamf Protect.

[**Web traffic events**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Streams_Overview.html) help you keep a record of content filtering and network requests happening on endpoints using Jamf Protect.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

To use this integration, you will also need to:
- Enable the integration in Elastic
- Configure Jamf Protect (macOS Security) to send logs to AWS S3 or the Elastic Agent (HTTP Endpoint)
    - Alerts
    - Unified Logs
    - Telemetry
- Configure Jamf Protect (Jamf Security Cloud) to send logs to AWS S3 or the Elastic Agent (HTTP Endpoint)
    - Threat Event Stream 
    - Network Traffic Stream


### Enable the integration in Elastic

For step-by-step instructions on how to set up an new integration in Elastic, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.
When setting up the integration, you will choose to collect logs via either S3 or HTTP Endpoint.

### Configure Jamf Protect using HTTP Endpoint

After validating settings, you can configure Jamf Protect to send events to Elastic.
For more information on configuring Jamf Protect, see 
- [Creating an Action Configuration](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html)
- [Configure Threat Event Stream](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Configuring_the_Network_Threat_Events_Stream_to_send_HTTP_Events.html)
- [Configure Network Traffic Stream](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Configuring_the_Network_Threat_Events_Stream_to_send_HTTP_Events.html)

Then, depending on which events you want to send to Elastic, configure one or multiple HTTP endpoints:

**Remote Alert Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Unified Logs Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Telemetry Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Threats Event Stream**:
- In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Network Traffic Stream**:
- In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.


### Configure Jamf Protect using AWS S3

After validating settings, you can configure Jamf Protect to send events to AWS S3.
For more information on configuring Jamf Protect, see 
- [Creating an Action Configuration](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html)
- [Enabling Data Forwarding to AWS S3](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Forwarding_to_a_Third_Party_Storage_Solution.html#ariaid-title2)
- [Configure Threat Event Stream](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Configuring_the_Threat_Events_Stream_to_Send_Events_to_AWS_S3.html)


**Copyright (c) 2024, Jamf Software, LLC.  All rights reserved.**

## Logs reference

#### alerts

This is the `Alerts` dataset.

##### Example

An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2024-05-17T00:09:29.807Z",
    "agent": {
        "ephemeral_id": "dd1cb398-e758-40c0-87b6-4ce4fb3611b2",
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "jamf_protect.alerts",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "CustomURLHandlerCreation",
        "agent_id_status": "verified",
        "category": [
            "host",
            "file"
        ],
        "dataset": "jamf_protect.alerts",
        "id": "6bdb0697-6d07-47bc-a37d-6c3348a5d953",
        "ingested": "2024-05-17T00:09:39Z",
        "kind": "alert",
        "provider": "Jamf Protect",
        "reason": "Application that uses custom url handler created",
        "severity": 0,
        "start": "2023-11-21T11:32:44.184Z",
        "type": [
            "change"
        ]
    },
    "file": {
        "code_signature": {
            "status": "code object is not signed at all"
        },
        "gid": "0",
        "inode": "19478271",
        "mode": "16804",
        "path": "/Applications/.Microsoft Teams (work or school).app.installBackup",
        "size": 96,
        "uid": "0"
    },
    "group": {
        "id": "0",
        "name": "wheel"
    },
    "host": {
        "hostname": "LMAC-ZW0GTLVDL",
        "id": "32EC79C5-26DC-535A-85F7-986F063297E2",
        "ip": [
            "175.16.199.1"
        ],
        "os": {
            "family": "macos",
            "full": "Version 14.2 (Build 23C5030f)"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "observer": {
        "product": "Jamf Protect",
        "vendor": "Jamf"
    },
    "process": {
        "args": [
            "/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper",
            "XPC_SERVICE_NAME=com.microsoft.autoupdate.helper",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "XPC_FLAGS=1",
            "pfz=0x7ffffff12000",
            "stack_guard=0x94bec1a9eb9800ea",
            "malloc_entropy=0x7777a3bc060946c0,0x6f95455435250cbc",
            "ptr_munge=0x749c1515ccadfca",
            "main_stack=0x7ff7bf6da000,0x800000,0x7ff7bb6da000,0x4000000",
            "executable_file=0x1a01000009,0x12f5060",
            "dyld_file=0x1a01000009,0xfffffff000982f7",
            "executable_cdhash=262df85f4455ca182cb45671afb26c9ad9dff13b",
            "executable_boothash=1fc9ca7065a4d7a9c299cc51414c052e5d7025d7",
            "th_port=0x103"
        ],
        "code_signature": {
            "signing_id": "com.microsoft.autoupdate.helper",
            "status": "No error.",
            "team_id": "UBF8T346G9"
        },
        "entity_id": "b8cd6fa5-e8c3-4f05-88a0-68469d04806c",
        "executable": "/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper",
        "group_leader": {
            "executable": "/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper",
            "name": "com.microsoft.autoupdate.helper",
            "pid": 15910,
            "real_group": {
                "id": "0"
            },
            "real_user": {
                "id": "0"
            },
            "start": "2023-11-21T11:32:44Z",
            "user": {
                "id": "0"
            }
        },
        "hash": {
            "sha1": "5ddcd49004e66cead79ca82991f1b4d4a8ba52d9",
            "sha256": "8fd91d9d1ca53ef93921c8072e12ec082c9eba62bf93f0f900e71b6aa4fa0ed8"
        },
        "name": "com.microsoft.autoupdate.helper",
        "parent": {
            "pid": 15910
        },
        "pid": 15910,
        "real_group": {
            "id": "0"
        },
        "real_user": {
            "id": "0"
        },
        "start": "2023-11-21T11:32:44Z",
        "user": {
            "id": "0"
        }
    },
    "related": {
        "hash": [
            "5ddcd49004e66cead79ca82991f1b4d4a8ba52d9",
            "8fd91d9d1ca53ef93921c8072e12ec082c9eba62bf93f0f900e71b6aa4fa0ed8"
        ],
        "ip": [
            "175.16.199.1"
        ],
        "user": [
            "root"
        ]
    },
    "tags": [
        "Visibility"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.image.tag | Container image tags. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| file.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| file.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.gid | Primary group ID (GID) of the file. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.mode | Mode of the file in octal representation. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.uid | The user ID (UID) or security identifier (SID) of the file owner. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
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
| input.type | Input type | keyword |
| jamf_protect.alerts.timestamp_nanoseconds | The timestamp in Epoch nanoseconds. | date |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.group_leader.executable | Absolute path to the process executable. | keyword |
| process.group_leader.executable.text | Multi-field of `process.group_leader.executable`. | match_only_text |
| process.group_leader.group.id | Unique identifier for the group on the system/platform. | keyword |
| process.group_leader.name | Process name. Sometimes called program name or similar. | keyword |
| process.group_leader.name.text | Multi-field of `process.group_leader.name`. | match_only_text |
| process.group_leader.pid | Process id. | long |
| process.group_leader.real_group.id | Unique identifier for the group on the system/platform. | keyword |
| process.group_leader.real_user.id | Unique identifier of the user. | keyword |
| process.group_leader.start | The time the process started. | date |
| process.group_leader.user.id | Unique identifier of the user. | keyword |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.parent.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.parent.real_group.id | Unique identifier for the group on the system/platform. | keyword |
| process.parent.real_user.id | Unique identifier of the user. | keyword |
| process.parent.start | The time the process started. | date |
| process.parent.user.id | Unique identifier of the user. | keyword |
| process.pid | Process id. | long |
| process.real_group.id | Unique identifier for the group on the system/platform. | keyword |
| process.real_user.id | Unique identifier of the user. | keyword |
| process.start | The time the process started. | date |
| process.user.id | Unique identifier of the user. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.enrichments | A list of associated indicators objects enriching the event, and the context of that association/enrichment. | nested |
| threat.framework | Name of the threat framework used to further categorize and classify the tactic and technique of the reported threat. Framework classification can be provided by detecting systems, evaluated at ingest time, or retrospectively tagged to events. | keyword |
| threat.software.platforms | The platforms of the software used by this threat to conduct behavior commonly modeled using MITRE ATT&CK®. While not required, you can use MITRE ATT&CK® software platform values. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.tactic.reference | The reference url of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| threat.technique.reference | The reference url of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| volume.bus_type |  | keyword |
| volume.file_system_type |  | keyword |
| volume.nt_name |  | keyword |
| volume.product_id |  | keyword |
| volume.product_name |  | keyword |
| volume.removable |  | boolean |
| volume.serial_number |  | keyword |
| volume.size |  | long |
| volume.vendor_id |  | keyword |
| volume.vendor_name |  | keyword |
| volume.writable |  | boolean |


#### telemetry

This is the `Telemetry` dataset.

##### Example

An example event for `telemetry` looks as following:

```json
{
    "@timestamp": "2024-02-06T16:01:34.442Z",
    "agent": {
        "ephemeral_id": "a0a97e34-86ea-435f-8629-308f4c17a3b1",
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "jamf_protect.telemetry",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "error": {
        "code": "0"
    },
    "event": {
        "action": "aue_posix_spawn",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "code": "43190",
        "dataset": "jamf_protect.telemetry",
        "ingested": "2024-05-17T00:10:39Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "Mac mini",
        "id": "H2WGF2U9Q6NV",
        "ip": [
            "0.0.0.0"
        ],
        "os": {
            "version": "Version 14.2.1 (Build 23C71)"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "jamf_protect": {
        "telemetry": {
            "arguments": {
                "child": {
                    "pid": 70851
                }
            },
            "dataset": "audit",
            "exec_args": {
                "args_compiled": "/usr/bin/profiles,status,-type,enrollment"
            },
            "exec_chain_parent": {
                "uuid": "87F2E500-EDF1-4F12-A489-C5E05B0F523E"
            },
            "exec_env": {
                "env": {
                    "compiled": "PWD=/,PATH=/usr/bin:/bin:/usr/sbin:/sbin"
                }
            },
            "header": {
                "event_modifier": "0",
                "version": "11"
            },
            "host_info": {
                "host": {
                    "uuid": "AE2FA359-6AB0-5F54-9E4A-39EDCF015C91"
                }
            },
            "identity": {
                "cd_hash": "a2c787fe5e26ead7c68909e45a75edced4147c68",
                "signer": {
                    "id_truncated": "false",
                    "type": "0"
                }
            },
            "path": [
                "/usr/bin/profiles",
                "/usr/bin/profiles"
            ],
            "return": {
                "description": "success"
            },
            "subject": {
                "effective": {
                    "group": {
                        "id": "0",
                        "name": "wheel"
                    }
                },
                "process": {
                    "name": "/Library/Application Support/Microsoft/EdgeUpdater/118.0.2088.86/EdgeUpdater.app/Contents/MacOS/EdgeUpdater",
                    "pid": 70848
                },
                "session": {
                    "id": "100016"
                },
                "terminal_id": {
                    "port": 0,
                    "type": "4"
                }
            }
        }
    },
    "process": {
        "args": [
            "/usr/bin/profiles",
            "status",
            "-type",
            "enrollment"
        ],
        "code_signature": {
            "signing_id": "com.microsoft.EdgeUpdater",
            "team_id": "UBF8T346G9"
        },
        "exit_code": 0,
        "hash": {
            "sha1": "9cfc802baf45b74693d146686ebe9ec59ac6367f"
        },
        "real_group": {
            "id": "0",
            "name": "wheel"
        },
        "real_user": {
            "id": "4294967295"
        },
        "user": {
            "id": "0",
            "name": "root"
        }
    },
    "related": {
        "hash": [
            "9cfc802baf45b74693d146686ebe9ec59ac6367f"
        ],
        "hosts": [
            "Mac mini"
        ],
        "ip": [
            "0.0.0.0"
        ],
        "user": [
            "root"
        ]
    },
    "tags": [
        "forwarded",
        "jamf_protect-telemetry"
    ],
    "user": {
        "id": "0",
        "name": [
            "root"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| jamf_protect.telemetry.arguments.addr |  | keyword |
| jamf_protect.telemetry.arguments.am_failure |  | keyword |
| jamf_protect.telemetry.arguments.am_success |  | keyword |
| jamf_protect.telemetry.arguments.authenticated |  | flattened |
| jamf_protect.telemetry.arguments.child.pid |  | long |
| jamf_protect.telemetry.arguments.data |  | keyword |
| jamf_protect.telemetry.arguments.detail |  | keyword |
| jamf_protect.telemetry.arguments.domain |  | keyword |
| jamf_protect.telemetry.arguments.fd |  | keyword |
| jamf_protect.telemetry.arguments.flags |  | keyword |
| jamf_protect.telemetry.arguments.flattened |  | flattened |
| jamf_protect.telemetry.arguments.known_uid |  | keyword |
| jamf_protect.telemetry.arguments.pid |  | long |
| jamf_protect.telemetry.arguments.port |  | long |
| jamf_protect.telemetry.arguments.priority |  | long |
| jamf_protect.telemetry.arguments.process |  | keyword |
| jamf_protect.telemetry.arguments.protocol |  | keyword |
| jamf_protect.telemetry.arguments.request |  | keyword |
| jamf_protect.telemetry.arguments.sflags |  | keyword |
| jamf_protect.telemetry.arguments.signal |  | keyword |
| jamf_protect.telemetry.arguments.target.port |  | long |
| jamf_protect.telemetry.arguments.task.port |  | long |
| jamf_protect.telemetry.arguments.type |  | keyword |
| jamf_protect.telemetry.arguments.which |  | keyword |
| jamf_protect.telemetry.arguments.who |  | keyword |
| jamf_protect.telemetry.attributes.device |  | keyword |
| jamf_protect.telemetry.attributes.file.access_mode |  | keyword |
| jamf_protect.telemetry.attributes.file.system.id |  | keyword |
| jamf_protect.telemetry.attributes.node.id |  | keyword |
| jamf_protect.telemetry.attributes.owner.group.id |  | keyword |
| jamf_protect.telemetry.attributes.owner.group.name |  | keyword |
| jamf_protect.telemetry.dataset |  | keyword |
| jamf_protect.telemetry.event_attributes.activity_identifier |  | keyword |
| jamf_protect.telemetry.event_attributes.assessments_enabled |  | long |
| jamf_protect.telemetry.event_attributes.attributes.ctime |  | date |
| jamf_protect.telemetry.event_attributes.attributes.mtime |  | date |
| jamf_protect.telemetry.event_attributes.attributes.path |  | keyword |
| jamf_protect.telemetry.event_attributes.attributes.quarantine.agent_bundle_identifier |  | keyword |
| jamf_protect.telemetry.event_attributes.attributes.quarantine.agent_name |  | keyword |
| jamf_protect.telemetry.event_attributes.attributes.quarantine.data_url_string |  | keyword |
| jamf_protect.telemetry.event_attributes.attributes.quarantine.event_identifier |  | keyword |
| jamf_protect.telemetry.event_attributes.attributes.quarantine.origin_url_string |  | keyword |
| jamf_protect.telemetry.event_attributes.attributes.quarantine.timestamp |  | date |
| jamf_protect.telemetry.event_attributes.attributes.requirement |  | keyword |
| jamf_protect.telemetry.event_attributes.audit_event.excluded_processes |  | keyword |
| jamf_protect.telemetry.event_attributes.audit_event.excluded_users |  | keyword |
| jamf_protect.telemetry.event_attributes.audit_event_log_verbose_messages |  | keyword |
| jamf_protect.telemetry.event_attributes.audit_level |  | long |
| jamf_protect.telemetry.event_attributes.backtrace.frames.image_offset |  | long |
| jamf_protect.telemetry.event_attributes.backtrace.frames.image_uuid |  | keyword |
| jamf_protect.telemetry.event_attributes.build_alias_of |  | keyword |
| jamf_protect.telemetry.event_attributes.build_version |  | keyword |
| jamf_protect.telemetry.event_attributes.category |  | keyword |
| jamf_protect.telemetry.event_attributes.cf_bundle_short_version_string |  | keyword |
| jamf_protect.telemetry.event_attributes.cf_bundle_version |  | keyword |
| jamf_protect.telemetry.event_attributes.dev_id_enabled |  | long |
| jamf_protect.telemetry.event_attributes.event.message |  | keyword |
| jamf_protect.telemetry.event_attributes.event.type |  | keyword |
| jamf_protect.telemetry.event_attributes.file_event.exclusion_paths |  | keyword |
| jamf_protect.telemetry.event_attributes.file_event.inclusion_paths |  | keyword |
| jamf_protect.telemetry.event_attributes.file_event.use_fuzzy_match |  | long |
| jamf_protect.telemetry.event_attributes.file_license_info.license_expiration_date |  | date |
| jamf_protect.telemetry.event_attributes.file_license_info.license_key |  | keyword |
| jamf_protect.telemetry.event_attributes.file_license_info.license_type |  | keyword |
| jamf_protect.telemetry.event_attributes.file_license_info.license_version |  | keyword |
| jamf_protect.telemetry.event_attributes.format_string |  | keyword |
| jamf_protect.telemetry.event_attributes.job.completed_time |  | date |
| jamf_protect.telemetry.event_attributes.job.creation_time |  | date |
| jamf_protect.telemetry.event_attributes.job.destination |  | keyword |
| jamf_protect.telemetry.event_attributes.job.format |  | keyword |
| jamf_protect.telemetry.event_attributes.job.id |  | keyword |
| jamf_protect.telemetry.event_attributes.job.processing_time |  | date |
| jamf_protect.telemetry.event_attributes.job.size |  | keyword |
| jamf_protect.telemetry.event_attributes.job.state |  | keyword |
| jamf_protect.telemetry.event_attributes.job.title |  | keyword |
| jamf_protect.telemetry.event_attributes.job.user |  | keyword |
| jamf_protect.telemetry.event_attributes.log.file.location |  | keyword |
| jamf_protect.telemetry.event_attributes.log.file.max_number_backups |  | long |
| jamf_protect.telemetry.event_attributes.log.file.max_size_mega_bytes |  | long |
| jamf_protect.telemetry.event_attributes.log.file.ownership |  | keyword |
| jamf_protect.telemetry.event_attributes.log.file.permission |  | keyword |
| jamf_protect.telemetry.event_attributes.log.remote_endpoint_enabled |  | long |
| jamf_protect.telemetry.event_attributes.log.remote_endpoint_type |  | keyword |
| jamf_protect.telemetry.event_attributes.log.remote_endpoint_type_awskinesis.access_key_id |  | keyword |
| jamf_protect.telemetry.event_attributes.log.remote_endpoint_type_awskinesis.region |  | keyword |
| jamf_protect.telemetry.event_attributes.log.remote_endpoint_type_awskinesis.secret_key |  | keyword |
| jamf_protect.telemetry.event_attributes.log.remote_endpoint_type_awskinesis.stream_name |  | keyword |
| jamf_protect.telemetry.event_attributes.log.remote_endpoint_url |  | keyword |
| jamf_protect.telemetry.event_attributes.mach_timestamp |  | keyword |
| jamf_protect.telemetry.event_attributes.opaque_version |  | keyword |
| jamf_protect.telemetry.event_attributes.parent_activity_identifier |  | keyword |
| jamf_protect.telemetry.event_attributes.path |  | keyword |
| jamf_protect.telemetry.event_attributes.process.id |  | long |
| jamf_protect.telemetry.event_attributes.process.image.path |  | keyword |
| jamf_protect.telemetry.event_attributes.process.image.uuid |  | keyword |
| jamf_protect.telemetry.event_attributes.project_name |  | keyword |
| jamf_protect.telemetry.event_attributes.sender.id |  | long |
| jamf_protect.telemetry.event_attributes.sender.image.path |  | keyword |
| jamf_protect.telemetry.event_attributes.sender.image.uuid |  | keyword |
| jamf_protect.telemetry.event_attributes.sender.program_counter |  | long |
| jamf_protect.telemetry.event_attributes.source |  | keyword |
| jamf_protect.telemetry.event_attributes.source_version |  | keyword |
| jamf_protect.telemetry.event_attributes.subsystem |  | keyword |
| jamf_protect.telemetry.event_attributes.thread_id |  | keyword |
| jamf_protect.telemetry.event_attributes.timestamp |  | date |
| jamf_protect.telemetry.event_attributes.timezone_name |  | keyword |
| jamf_protect.telemetry.event_attributes.trace_id |  | keyword |
| jamf_protect.telemetry.event_attributes.unified_log_predicates |  | keyword |
| jamf_protect.telemetry.event_attributes.version |  | keyword |
| jamf_protect.telemetry.event_score |  | long |
| jamf_protect.telemetry.exec_args.args |  | flattened |
| jamf_protect.telemetry.exec_args.args_compiled |  | keyword |
| jamf_protect.telemetry.exec_chain_child.parent.path |  | text |
| jamf_protect.telemetry.exec_chain_child.parent.uuid |  | keyword |
| jamf_protect.telemetry.exec_chain_parent.uuid |  | keyword |
| jamf_protect.telemetry.exec_env.env.arch |  | keyword |
| jamf_protect.telemetry.exec_env.env.compiled |  | keyword |
| jamf_protect.telemetry.exec_env.env.malwarebytes_group |  | keyword |
| jamf_protect.telemetry.exec_env.env.path |  | text |
| jamf_protect.telemetry.exec_env.env.shell |  | keyword |
| jamf_protect.telemetry.exec_env.env.ssh_auth_sock |  | keyword |
| jamf_protect.telemetry.exec_env.env.tmpdir |  | keyword |
| jamf_protect.telemetry.exec_env.env.xpc.flags |  | keyword |
| jamf_protect.telemetry.exec_env.env.xpc.service_name |  | keyword |
| jamf_protect.telemetry.exec_env.env_compiled |  | keyword |
| jamf_protect.telemetry.exit.return.value |  | long |
| jamf_protect.telemetry.exit.status |  | keyword |
| jamf_protect.telemetry.file_event_info.eventid_wrapped |  | boolean |
| jamf_protect.telemetry.file_event_info.history_done |  | boolean |
| jamf_protect.telemetry.file_event_info.item.change_owner |  | boolean |
| jamf_protect.telemetry.file_event_info.item.cloned |  | boolean |
| jamf_protect.telemetry.file_event_info.item.created |  | boolean |
| jamf_protect.telemetry.file_event_info.item.extended_attribute_modified |  | boolean |
| jamf_protect.telemetry.file_event_info.item.finder_info_modified |  | boolean |
| jamf_protect.telemetry.file_event_info.item.inode_metadata_modified |  | boolean |
| jamf_protect.telemetry.file_event_info.item.is_directory |  | boolean |
| jamf_protect.telemetry.file_event_info.item.is_file |  | boolean |
| jamf_protect.telemetry.file_event_info.item.is_hard_link |  | boolean |
| jamf_protect.telemetry.file_event_info.item.is_last_hard_link |  | boolean |
| jamf_protect.telemetry.file_event_info.item.is_sym_link |  | boolean |
| jamf_protect.telemetry.file_event_info.item.removed |  | boolean |
| jamf_protect.telemetry.file_event_info.item.renamed |  | boolean |
| jamf_protect.telemetry.file_event_info.item.updated |  | boolean |
| jamf_protect.telemetry.file_event_info.kernel_dropped |  | boolean |
| jamf_protect.telemetry.file_event_info.mount |  | boolean |
| jamf_protect.telemetry.file_event_info.must_scan_sub_dir |  | boolean |
| jamf_protect.telemetry.file_event_info.none |  | boolean |
| jamf_protect.telemetry.file_event_info.own_event |  | boolean |
| jamf_protect.telemetry.file_event_info.root_changed |  | boolean |
| jamf_protect.telemetry.file_event_info.unmount |  | boolean |
| jamf_protect.telemetry.file_event_info.user_dropped |  | boolean |
| jamf_protect.telemetry.hardware_event_info.device.class |  | keyword |
| jamf_protect.telemetry.hardware_event_info.device.name |  | keyword |
| jamf_protect.telemetry.hardware_event_info.device.status |  | keyword |
| jamf_protect.telemetry.hardware_event_info.device_attributes.io.cf_plugin_types |  | flattened |
| jamf_protect.telemetry.hardware_event_info.device_attributes.io.class_name_override |  | keyword |
| jamf_protect.telemetry.hardware_event_info.device_attributes.io.power_management.capability_flags |  | keyword |
| jamf_protect.telemetry.hardware_event_info.device_attributes.io.power_management.current_power_state |  | long |
| jamf_protect.telemetry.hardware_event_info.device_attributes.io.power_management.device_power_state |  | long |
| jamf_protect.telemetry.hardware_event_info.device_attributes.io.power_management.driver_power_state |  | long |
| jamf_protect.telemetry.hardware_event_info.device_attributes.io.power_management.max_power_state |  | long |
| jamf_protect.telemetry.hardware_event_info.device_attributes.iserial_number |  | long |
| jamf_protect.telemetry.hardware_event_info.device_attributes.removable |  | keyword |
| jamf_protect.telemetry.hardware_event_info.device_attributes.usb.product_name |  | keyword |
| jamf_protect.telemetry.hardware_event_info.device_attributes.usb.vendor_name |  | keyword |
| jamf_protect.telemetry.header.action |  | keyword |
| jamf_protect.telemetry.header.event_modifier |  | keyword |
| jamf_protect.telemetry.header.time_milliseconds_offset |  | long |
| jamf_protect.telemetry.header.version |  | keyword |
| jamf_protect.telemetry.host_info.host.uuid |  | keyword |
| jamf_protect.telemetry.identity.cd_hash |  | keyword |
| jamf_protect.telemetry.identity.signer.id |  | keyword |
| jamf_protect.telemetry.identity.signer.id_truncated |  | keyword |
| jamf_protect.telemetry.identity.signer.type |  | keyword |
| jamf_protect.telemetry.identity.team.id |  | keyword |
| jamf_protect.telemetry.identity.team.id_truncated |  | keyword |
| jamf_protect.telemetry.path |  | keyword |
| jamf_protect.telemetry.process.effective.group.id |  | keyword |
| jamf_protect.telemetry.process.effective.group.name |  | keyword |
| jamf_protect.telemetry.process.effective.user.id |  | keyword |
| jamf_protect.telemetry.process.effective.user.name |  | keyword |
| jamf_protect.telemetry.process.group.id |  | keyword |
| jamf_protect.telemetry.process.group.name |  | keyword |
| jamf_protect.telemetry.process.name |  | keyword |
| jamf_protect.telemetry.process.pid |  | long |
| jamf_protect.telemetry.process.session.id |  | keyword |
| jamf_protect.telemetry.process.terminal_id.addr |  | keyword |
| jamf_protect.telemetry.process.terminal_id.ip_address |  | ip |
| jamf_protect.telemetry.process.terminal_id.port |  | long |
| jamf_protect.telemetry.process.terminal_id.type |  | keyword |
| jamf_protect.telemetry.process.user.id |  | keyword |
| jamf_protect.telemetry.process.user.name |  | keyword |
| jamf_protect.telemetry.return.description |  | keyword |
| jamf_protect.telemetry.signal_event_info.signal |  | long |
| jamf_protect.telemetry.socket.inet.addr |  | keyword |
| jamf_protect.telemetry.socket.inet.family |  | keyword |
| jamf_protect.telemetry.socket.inet.id |  | keyword |
| jamf_protect.telemetry.socket.unix.family |  | keyword |
| jamf_protect.telemetry.socket.unix.path |  | text |
| jamf_protect.telemetry.subject.audit.id |  | keyword |
| jamf_protect.telemetry.subject.audit.user.name |  | keyword |
| jamf_protect.telemetry.subject.effective.group.id |  | keyword |
| jamf_protect.telemetry.subject.effective.group.name |  | keyword |
| jamf_protect.telemetry.subject.effective.user.id |  | keyword |
| jamf_protect.telemetry.subject.effective.user.name |  | keyword |
| jamf_protect.telemetry.subject.process.name |  | keyword |
| jamf_protect.telemetry.subject.process.pid |  | long |
| jamf_protect.telemetry.subject.responsible.process.id |  | keyword |
| jamf_protect.telemetry.subject.responsible.process.name |  | keyword |
| jamf_protect.telemetry.subject.session.id |  | keyword |
| jamf_protect.telemetry.subject.terminal_id.addr |  | keyword |
| jamf_protect.telemetry.subject.terminal_id.port |  | long |
| jamf_protect.telemetry.subject.terminal_id.type |  | keyword |
| jamf_protect.telemetry.texts |  | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.real_group.id | Unique identifier for the group on the system/platform. | keyword |
| process.real_group.name | Name of the group. | keyword |
| process.real_user.id | Unique identifier of the user. | keyword |
| process.real_user.name | Short name or login of the user. | keyword |
| process.real_user.name.text | Multi-field of `process.real_user.name`. | match_only_text |
| process.user.id | Unique identifier of the user. | keyword |
| process.user.name | Short name or login of the user. | keyword |
| process.user.name.text | Multi-field of `process.user.name`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.effective.name.text | Multi-field of `user.effective.name`. | match_only_text |
| user.email | User email address. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.group.name | Name of the group. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


#### threats event stream

This is the `Threats Event Stream` dataset.

##### Example

An example event for `web_threat_events` looks as following:

```json
{
    "@timestamp": "2024-05-17T00:11:29.057Z",
    "agent": {
        "ephemeral_id": "0eddc4c4-e383-459e-925e-3ba00e7abfbf",
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "jamf_protect.web_threat_events",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "ip",
        "domain": "host",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "Detected",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "jamf_protect.web_threat_events",
        "id": "013b15c9-8f62-4bf1-948a-d82367af2a10",
        "ingested": "2024-05-17T00:11:39Z",
        "kind": "alert",
        "provider": "Jamf Protect",
        "reason": "Sideloaded App",
        "severity": 6,
        "start": "2020-01-30T17:47:41.767Z",
        "url": "https://radar.wandera.com/security/events/detail/013b15c9-8f62-4bf1-948a-d82367af2a10.SIDE_LOADED_APP_IN_INVENTORY?createdUtcMs=1580406461767"
    },
    "file": {
        "hash": {
            "sha1": "16336078972773bc6c8cef69d722c8c093ba727ddc5bb31eb2",
            "sha256": "16336078978a306dc23b67dae9df18bc2a0205e3ff0cbf97c46e76fd670f93fd142d7042"
        },
        "name": "Books"
    },
    "host": {
        "geo": {
            "country_iso_code": "gb"
        },
        "hostname": "Apple iPhone 11",
        "id": "09f81436-de17-441e-a631-0461252c629b",
        "os": {
            "full": "IOS 11.2.5"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "observer": {
        "product": "Jamf Protect",
        "vendor": "Jamf"
    },
    "organization": {
        "id": "fb4567b6-4ee2-3c4c-abb9-4c78ec463b25"
    },
    "rule": {
        "description": "Sideloaded App",
        "name": "SIDE_LOADED_APP_IN_INVENTORY"
    },
    "source": {
        "port": 3025
    },
    "tags": [
        "forwarded",
        "jamf_protect-web-threat-events"
    ],
    "user": {
        "email": "user@mail.com",
        "name": "John Doe"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.image.tag | Container image tags. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| file.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| file.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.gid | Primary group ID (GID) of the file. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.mode | Mode of the file in octal representation. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.uid | The user ID (UID) or security identifier (SID) of the file owner. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.geo.country_iso_code | Country ISO code. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| organization.id |  | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.group_leader.pid | Process id. | long |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.pid | Process id. | long |
| process.real_group.id | Unique identifier for the group on the system/platform. | keyword |
| process.real_user.id | Unique identifier of the user. | keyword |
| process.start | The time the process started. | date |
| process.tty.char_device.major | The major number identifies the driver associated with the device. The character device's major and minor numbers can be algorithmically combined to produce the more familiar terminal identifiers such as "ttyS0" and "pts/0". For more details, please refer to the Linux kernel documentation. | long |
| process.tty.char_device.minor | The minor number is used only by the driver specified by the major number; other parts of the kernel don’t use it, and merely pass it along to the driver. It is common for a driver to control several devices; the minor number provides a way for the driver to differentiate among them. | long |
| process.tty.columns | The number of character columns per line. e.g terminal width Terminal sizes can change, so this value reflects the maximum value for a given IO event. i.e. where event.action = 'text_output' | long |
| process.tty.rows | The number of character rows in the terminal. e.g terminal height Terminal sizes can change, so this value reflects the maximum value for a given IO event. i.e. where event.action = 'text_output' | long |
| process.user.id | Unique identifier of the user. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.enrichments | A list of associated indicators objects enriching the event, and the context of that association/enrichment. | nested |
| threat.framework | Name of the threat framework used to further categorize and classify the tactic and technique of the reported threat. Framework classification can be provided by detecting systems, evaluated at ingest time, or retrospectively tagged to events. | keyword |
| threat.software.platforms | The platforms of the software used by this threat to conduct behavior commonly modeled using MITRE ATT&CK®. While not required, you can use MITRE ATT&CK® software platform values. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.tactic.reference | The reference url of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| threat.technique.reference | The reference url of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| volume.bus_type |  | keyword |
| volume.file_system_type |  | keyword |
| volume.nt_name |  | keyword |
| volume.product_id |  | keyword |
| volume.product_name |  | keyword |
| volume.removable |  | boolean |
| volume.serial_number |  | keyword |
| volume.size |  | long |
| volume.vendor_id |  | keyword |
| volume.vendor_name |  | keyword |
| volume.writable |  | boolean |


#### network traffic stream

This is the `Network Traffic Stream` dataset.

##### Example

An example event for `web_traffic_events` looks as following:

```json
{
    "@timestamp": "2024-05-17T00:12:27.062Z",
    "agent": {
        "ephemeral_id": "ffca4568-15a9-4780-bc89-e026120c233e",
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "jamf_protect.web_traffic_events",
        "namespace": "ep",
        "type": "logs"
    },
    "dns": {
        "answers": {
            "ttl": 101,
            "type": "HTTPS"
        },
        "question": {
            "name": "s.youtube.com",
            "registered_domain": "youtube",
            "top_level_domain": "com"
        },
        "response_code": "NOERROR"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c3650180-e3d1-4dad-9094-89c988e721d7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "DNS Lookup",
        "agent_id_status": "verified",
        "category": [
            "host",
            "network"
        ],
        "dataset": "jamf_protect.web_traffic_events",
        "ingested": "2024-05-17T00:12:37Z",
        "kind": "event",
        "outcome": [
            "success"
        ],
        "provider": "Jamf Protect",
        "reason": "CLEAN",
        "start": "2024-02-02T06:26:04.273Z",
        "type": [
            "connection"
        ]
    },
    "host": {
        "id": "3453be41-0f2d-4d43-9ec2-a53f39fff93c",
        "os": {
            "type": [
                "ios"
            ]
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "observer": {
        "product": "Jamf Protect",
        "vendor": "Jamf"
    },
    "organization": {
        "id": "9608556b-0c3a-4a9c-9b4a-d714d8a028a1"
    },
    "rule": {
        "name": "DNS Lookup"
    },
    "tags": [
        "forwarded",
        "jamf_protect-web-traffic-events"
    ],
    "user": {
        "email": "hjilling@icloud.com",
        "name": "07a5a2ae-16de-4767-831e-0ea8b7c3abe4"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.response_code | The DNS response code. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| file.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| file.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.gid | Primary group ID (GID) of the file. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.mode | Mode of the file in octal representation. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.uid | The user ID (UID) or security identifier (SID) of the file owner. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.geo.country_iso_code | Country ISO code. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| organization.id |  | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
