# Windows AppLocker Integration

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Setup

For step-by-step instructions on how to set up an integration,
see the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

Note: Because the Windows integration always applies to the local server, the `hosts` config option is not needed.

## Notes

### Windows Event ID clause limit

If you specify more than 22 query conditions (event IDs or event ID ranges), some
versions of Windows will prevent the integration from reading the event log due to
limits in the query system. If this occurs, a similar warning as shown below:

```
The specified query is invalid.
```

In some cases, the limit may be lower than 22 conditions. For instance, using a
mixture of ranges and single event IDs, along with an additional parameter such
as `ignore older`, results in a limit of 21 conditions.

If you have more than 22 conditions, you can work around this Windows limitation
by using a drop_event processor to do the filtering after filebeat has received
the events from Windows. The filter shown below is equivalent to
`event_id: 903, 1024, 2000-2004, 4624` but can be expanded beyond 22 event IDs.

```yaml
- drop_event.when.not.or:
  - equals.winlog.event_id: "903"
  - equals.winlog.event_id: "1024"
  - equals.winlog.event_id: "4624"
  - range:
      winlog.event_id.gte: 2000
      winlog.event_id.lte: 2004
```

## Logs reference

### AppLocker/EXE and DLL

The Windows `applocker_exe_and_dll` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/EXE and DLL` event log.

An example event for `applocker_exe_and_dll` looks as following:

```json
{
    "@timestamp": "2023-07-20T15:05:03.882Z",
    "agent": {
        "ephemeral_id": "026312ee-e6f4-4086-92cc-0e7c56bdbb5a",
        "id": "49658d66-b405-4c92-8e7c-5c2646556bf2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "data_stream": {
        "dataset": "windows.applocker_exe_and_dll",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "49658d66-b405-4c92-8e7c-5c2646556bf2",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "action": "None",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "code": "8003",
        "created": "2024-06-21T01:53:30.508Z",
        "dataset": "windows.applocker_exe_and_dll",
        "ingested": "2024-06-21T01:53:42Z",
        "kind": "event",
        "original": "\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}' /\u003e\u003cEventID\u003e8003\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e3\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x8000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2023-07-20T15:05:03.8826518Z' /\u003e\u003cEventRecordID\u003e154247\u003c/EventRecordID\u003e\u003cCorrelation /\u003e\u003cExecution ProcessID='33848' ThreadID='12040' /\u003e\u003cChannel\u003eMicrosoft-Windows-AppLocker/EXE and DLL\u003c/Channel\u003e\u003cComputer\u003eTOPSYLL.local\u003c/Computer\u003e\u003cSecurity UserID='S-1-5-21-1133191089-1850170202-1535859923-200319' /\u003e\u003c/System\u003e\u003cUserData\u003e\u003cRuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'\u003e\u003cPolicyNameLength\u003e3\u003c/PolicyNameLength\u003e\u003cPolicyName\u003eEXE\u003c/PolicyName\u003e\u003cRuleId\u003e{00000000-0000-0000-0000-000000000000}\u003c/RuleId\u003e\u003cRuleNameLength\u003e1\u003c/RuleNameLength\u003e\u003cRuleName\u003e-\u003c/RuleName\u003e\u003cRuleSddlLength\u003e1\u003c/RuleSddlLength\u003e\u003cRuleSddl\u003e-\u003c/RuleSddl\u003e\u003cTargetUser\u003eS-1-5-21-1133191089-1850170202-1535859923-200319\u003c/TargetUser\u003e\u003cTargetProcessId\u003e27116\u003c/TargetProcessId\u003e\u003cFilePathLength\u003e101\u003c/FilePathLength\u003e\u003cFilePath\u003e%OSDRIVE%\\USERS\\TOPSY\\APPDATA\\LOCAL\\GITHUBDESKTOP\\APP-3.1.2\\RESOURCES\\APP\\GIT\\MINGW64\\BIN\\GIT.EXE\u003c/FilePath\u003e\u003cFileHashLength\u003e32\u003c/FileHashLength\u003e\u003cFileHash\u003e11D3940DE41D28E044CE45AB76A6D824E617D99B62C5FB44E37BE5CD7B0545F5\u003c/FileHash\u003e\u003cFqbnLength\u003e72\u003c/FqbnLength\u003e\u003cFqbn\u003eO=JOHANNES SCHINDELIN, S=NORDRHEIN-WESTFALEN, C=DE\\GIT\\GIT.EXE\\2.35.5.01\u003c/Fqbn\u003e\u003cTargetLogonId\u003e0x14fcb7\u003c/TargetLogonId\u003e\u003cFullFilePathLength\u003e94\u003c/FullFilePathLength\u003e\u003cFullFilePath\u003eC:\\Users\\TOPSY\\AppData\\Local\\GitHubDesktop\\app-3.1.2\\resources\\app\\git\\mingw64\\bin\\git.exe\u003c/FullFilePath\u003e\u003c/RuleAndFileData\u003e\u003c/UserData\u003e\u003c/Event\u003e",
        "provider": "Microsoft-Windows-AppLocker",
        "type": [
            "start"
        ]
    },
    "file": {
        "hash": {
            "sha256": "11D3940DE41D28E044CE45AB76A6D824E617D99B62C5FB44E37BE5CD7B0545F5"
        },
        "name": "git.exe",
        "pe": {
            "file_version": "2.35.5.01",
            "original_file_name": "GIT.EXE",
            "product": "GIT"
        },
        "x509": {
            "subject": {
                "country": [
                    "DE"
                ],
                "organization": [
                    "JOHANNES SCHINDELIN"
                ],
                "state_or_province": [
                    "NORDRHEIN-WESTFALEN"
                ]
            }
        }
    },
    "host": {
        "name": "TOPSYLL.local"
    },
    "input": {
        "type": "httpjson"
    },
    "log": {
        "level": "warning"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "id": "S-1-5-21-1133191089-1850170202-1535859923-200319"
    },
    "winlog": {
        "channel": "Microsoft-Windows-AppLocker/EXE and DLL",
        "computer_name": "TOPSYLL.local",
        "event_id": "8003",
        "level": "warning",
        "opcode": "Info",
        "process": {
            "pid": 33848,
            "thread": {
                "id": 12040
            }
        },
        "provider_guid": "{cbda4dbf-8d5d-4f69-9578-be14aa540d22}",
        "provider_name": "Microsoft-Windows-AppLocker",
        "record_id": "154247",
        "task": "None",
        "time_created": "2023-07-20T15:05:03.882Z",
        "user": {
            "identifier": "S-1-5-21-1133191089-1850170202-1535859923-200319"
        },
        "user_data": {
            "FileHash": "11D3940DE41D28E044CE45AB76A6D824E617D99B62C5FB44E37BE5CD7B0545F5",
            "FileHashLength": 32,
            "FilePath": "%OSDRIVE%\\USERS\\TOPSY\\APPDATA\\LOCAL\\GITHUBDESKTOP\\APP-3.1.2\\RESOURCES\\APP\\GIT\\MINGW64\\BIN\\GIT.EXE",
            "FilePathLength": 101,
            "Fqbn": "O=JOHANNES SCHINDELIN, S=NORDRHEIN-WESTFALEN, C=DE\\GIT\\GIT.EXE\\2.35.5.01",
            "FqbnLength": 72,
            "FullFilePath": "C:\\Users\\TOPSY\\AppData\\Local\\GitHubDesktop\\app-3.1.2\\resources\\app\\git\\mingw64\\bin\\git.exe",
            "FullFilePathLength": 94,
            "PolicyName": "EXE",
            "PolicyNameLength": 3,
            "RuleId": "{00000000-0000-0000-0000-000000000000}",
            "RuleName": "-",
            "RuleNameLength": 1,
            "RuleSddl": "-",
            "RuleSddlLength": 1,
            "TargetLogonId": "0x14fcb7",
            "TargetProcessId": 27116,
            "TargetUser": "S-1-5-21-1133191089-1850170202-1535859923-200319",
            "xml_name": "RuleAndFileData"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| file.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| file.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| file.x509.subject.country | List of country \(C) code | keyword |
| file.x509.subject.locality | List of locality names (L) | keyword |
| file.x509.subject.organization | List of organizations (O) of subject. | keyword |
| file.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_data | The event-specific data. This field is mutually exclusive with `user_data`. If you are capturing event data on versions prior to Windows Vista, the parameters in `event_data` are named `param1`, `param2`, and so on, because event log parameters are unnamed in earlier versions of Windows. | object |
| winlog.event_data.AuthenticationPackageName |  | keyword |
| winlog.event_data.Binary |  | keyword |
| winlog.event_data.BitlockerUserInputTime |  | keyword |
| winlog.event_data.BootMode |  | keyword |
| winlog.event_data.BootType |  | keyword |
| winlog.event_data.BuildVersion |  | keyword |
| winlog.event_data.Company |  | keyword |
| winlog.event_data.CorruptionActionState |  | keyword |
| winlog.event_data.CreationUtcTime |  | keyword |
| winlog.event_data.Description |  | keyword |
| winlog.event_data.Detail |  | keyword |
| winlog.event_data.DeviceName |  | keyword |
| winlog.event_data.DeviceNameLength |  | keyword |
| winlog.event_data.DeviceTime |  | keyword |
| winlog.event_data.DeviceVersionMajor |  | keyword |
| winlog.event_data.DeviceVersionMinor |  | keyword |
| winlog.event_data.DriveName |  | keyword |
| winlog.event_data.DriverName |  | keyword |
| winlog.event_data.DriverNameLength |  | keyword |
| winlog.event_data.DwordVal |  | keyword |
| winlog.event_data.EntryCount |  | keyword |
| winlog.event_data.ExtraInfo |  | keyword |
| winlog.event_data.FailureName |  | keyword |
| winlog.event_data.FailureNameLength |  | keyword |
| winlog.event_data.FileVersion |  | keyword |
| winlog.event_data.FinalStatus |  | keyword |
| winlog.event_data.Group |  | keyword |
| winlog.event_data.IdleImplementation |  | keyword |
| winlog.event_data.IdleStateCount |  | keyword |
| winlog.event_data.ImpersonationLevel |  | keyword |
| winlog.event_data.IntegrityLevel |  | keyword |
| winlog.event_data.IpAddress |  | keyword |
| winlog.event_data.IpPort |  | keyword |
| winlog.event_data.KeyLength |  | keyword |
| winlog.event_data.LastBootGood |  | keyword |
| winlog.event_data.LastShutdownGood |  | keyword |
| winlog.event_data.LmPackageName |  | keyword |
| winlog.event_data.LogonGuid |  | keyword |
| winlog.event_data.LogonId |  | keyword |
| winlog.event_data.LogonProcessName |  | keyword |
| winlog.event_data.LogonType |  | keyword |
| winlog.event_data.MajorVersion |  | keyword |
| winlog.event_data.MaximumPerformancePercent |  | keyword |
| winlog.event_data.MemberName |  | keyword |
| winlog.event_data.MemberSid |  | keyword |
| winlog.event_data.MinimumPerformancePercent |  | keyword |
| winlog.event_data.MinimumThrottlePercent |  | keyword |
| winlog.event_data.MinorVersion |  | keyword |
| winlog.event_data.NewProcessId |  | keyword |
| winlog.event_data.NewProcessName |  | keyword |
| winlog.event_data.NewSchemeGuid |  | keyword |
| winlog.event_data.NewTime |  | keyword |
| winlog.event_data.NominalFrequency |  | keyword |
| winlog.event_data.Number |  | keyword |
| winlog.event_data.OldSchemeGuid |  | keyword |
| winlog.event_data.OldTime |  | keyword |
| winlog.event_data.OriginalFileName |  | keyword |
| winlog.event_data.Path |  | keyword |
| winlog.event_data.PerformanceImplementation |  | keyword |
| winlog.event_data.PreviousCreationUtcTime |  | keyword |
| winlog.event_data.PreviousTime |  | keyword |
| winlog.event_data.PrivilegeList |  | keyword |
| winlog.event_data.ProcessId |  | keyword |
| winlog.event_data.ProcessName |  | keyword |
| winlog.event_data.ProcessPath |  | keyword |
| winlog.event_data.ProcessPid |  | keyword |
| winlog.event_data.Product |  | keyword |
| winlog.event_data.PuaCount |  | keyword |
| winlog.event_data.PuaPolicyId |  | keyword |
| winlog.event_data.QfeVersion |  | keyword |
| winlog.event_data.Reason |  | keyword |
| winlog.event_data.SchemaVersion |  | keyword |
| winlog.event_data.ScriptBlockText |  | keyword |
| winlog.event_data.ServiceName |  | keyword |
| winlog.event_data.ServiceVersion |  | keyword |
| winlog.event_data.ShutdownActionType |  | keyword |
| winlog.event_data.ShutdownEventCode |  | keyword |
| winlog.event_data.ShutdownReason |  | keyword |
| winlog.event_data.Signature |  | keyword |
| winlog.event_data.SignatureStatus |  | keyword |
| winlog.event_data.Signed |  | keyword |
| winlog.event_data.StartTime |  | keyword |
| winlog.event_data.State |  | keyword |
| winlog.event_data.Status |  | keyword |
| winlog.event_data.StopTime |  | keyword |
| winlog.event_data.SubjectDomainName |  | keyword |
| winlog.event_data.SubjectLogonId |  | keyword |
| winlog.event_data.SubjectUserName |  | keyword |
| winlog.event_data.SubjectUserSid |  | keyword |
| winlog.event_data.TSId |  | keyword |
| winlog.event_data.TargetDomainName |  | keyword |
| winlog.event_data.TargetInfo |  | keyword |
| winlog.event_data.TargetLogonGuid |  | keyword |
| winlog.event_data.TargetLogonId |  | keyword |
| winlog.event_data.TargetServerName |  | keyword |
| winlog.event_data.TargetUserName |  | keyword |
| winlog.event_data.TargetUserSid |  | keyword |
| winlog.event_data.TerminalSessionId |  | keyword |
| winlog.event_data.TokenElevationType |  | keyword |
| winlog.event_data.TransmittedServices |  | keyword |
| winlog.event_data.UserSid |  | keyword |
| winlog.event_data.Version |  | keyword |
| winlog.event_data.Workstation |  | keyword |
| winlog.event_data.param1 |  | keyword |
| winlog.event_data.param2 |  | keyword |
| winlog.event_data.param3 |  | keyword |
| winlog.event_data.param4 |  | keyword |
| winlog.event_data.param5 |  | keyword |
| winlog.event_data.param6 |  | keyword |
| winlog.event_data.param7 |  | keyword |
| winlog.event_data.param8 |  | keyword |
| winlog.event_id | The event identifier. The value is specific to the source of the event. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.level | The level assigned to the event such as Information, Warning, or Critical. | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process ID (PID) of the process that generated/logged the event. This is often the event collector process and not necessarily the process that the event is about. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.time_created | The time the event was created. | date |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.user_data.FileHash |  | keyword |
| winlog.user_data.FileHashLength |  | long |
| winlog.user_data.FilePath |  | keyword |
| winlog.user_data.FilePathLength |  | long |
| winlog.user_data.Fqbn |  | keyword |
| winlog.user_data.FqbnLength |  | long |
| winlog.user_data.FullFilePath |  | keyword |
| winlog.user_data.FullFilePathLength |  | long |
| winlog.user_data.PolicyName |  | keyword |
| winlog.user_data.PolicyNameLength |  | long |
| winlog.user_data.RuleId |  | keyword |
| winlog.user_data.RuleName |  | keyword |
| winlog.user_data.RuleNameLength |  | long |
| winlog.user_data.RuleSddl |  | keyword |
| winlog.user_data.RuleSddlLength |  | long |
| winlog.user_data.TargetLogonId |  | keyword |
| winlog.user_data.TargetProcessId |  | long |
| winlog.user_data.TargetUser |  | keyword |
| winlog.user_data.xml_name |  | keyword |
| winlog.version | The version number of the event's definition. | long |


### AppLocker/MSI and Script

The Windows `applocker_msi_and_script` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/MSI and Script` event log.

An example event for `applocker_msi_and_script` looks as following:

```json
{
    "@timestamp": "2023-08-04T21:26:32.757Z",
    "agent": {
        "ephemeral_id": "17b8f200-259d-4f9f-898e-ccfd2f82705a",
        "id": "15b01abd-cefe-4ddd-8359-617acef7bf30",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "data_stream": {
        "dataset": "windows.applocker_msi_and_script",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "15b01abd-cefe-4ddd-8359-617acef7bf30",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "action": "None",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "code": "8006",
        "created": "2023-08-05T12:31:30.395Z",
        "dataset": "windows.applocker_msi_and_script",
        "ingested": "2023-08-05T12:31:34Z",
        "kind": "event",
        "original": "\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}' /\u003e\u003cEventID\u003e8006\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e3\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x4000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2023-08-04T21:26:32.7572144Z' /\u003e\u003cEventRecordID\u003e239\u003c/EventRecordID\u003e\u003cCorrelation ActivityID='{f64315e2-bea0-0000-6d01-d5f6a0bed901}' /\u003e\u003cExecution ProcessID='25192' ThreadID='7740' /\u003e\u003cChannel\u003eMicrosoft-Windows-AppLocker/MSI and Script\u003c/Channel\u003e\u003cComputer\u003eel33t-b00k-1\u003c/Computer\u003e\u003cSecurity UserID='S-1-5-21-2707992022-4034939591-3454028951-1001' /\u003e\u003c/System\u003e\u003cUserData\u003e\u003cRuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'\u003e\u003cPolicyNameLength\u003e6\u003c/PolicyNameLength\u003e\u003cPolicyName\u003eSCRIPT\u003c/PolicyName\u003e\u003cRuleId\u003e{00000000-0000-0000-0000-000000000000}\u003c/RuleId\u003e\u003cRuleNameLength\u003e1\u003c/RuleNameLength\u003e\u003cRuleName\u003e-\u003c/RuleName\u003e\u003cRuleSddlLength\u003e1\u003c/RuleSddlLength\u003e\u003cRuleSddl\u003e-\u003c/RuleSddl\u003e\u003cTargetUser\u003eS-1-5-21-2707992022-4034939591-3454028951-1001\u003c/TargetUser\u003e\u003cTargetProcessId\u003e25192\u003c/TargetProcessId\u003e\u003cFilePathLength\u003e124\u003c/FilePathLength\u003e\u003cFilePath\u003e%OSDRIVE%\\USERS\\NICPE\\.VSCODE\\EXTENSIONS\\MS-VSCODE.POWERSHELL-2023.6.0\\MODULES\\PSSCRIPTANALYZER\\1.21.0\\PSSCRIPTANALYZER.PSM1\u003c/FilePath\u003e\u003cFileHashLength\u003e32\u003c/FileHashLength\u003e\u003cFileHash\u003eD2A09AC074F8D326B4DCC8B8BE5BC003C41CCB6EB5FC35E13B73F834F2946B01\u003c/FileHash\u003e\u003cFqbnLength\u003e65\u003c/FqbnLength\u003e\u003cFqbn\u003eO=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\\\\\\0.0.0.00\u003c/Fqbn\u003e\u003cTargetLogonId\u003e0x4c18f\u003c/TargetLogonId\u003e\u003cFullFilePathLength\u003e117\u003c/FullFilePathLength\u003e\u003cFullFilePath\u003eC:\\Users\\nicpe\\.vscode\\extensions\\ms-vscode.powershell-2023.6.0\\modules\\PSScriptAnalyzer\\1.21.0\\PSScriptAnalyzer.psm1\u003c/FullFilePath\u003e\u003c/RuleAndFileData\u003e\u003c/UserData\u003e\u003c/Event\u003e",
        "provider": "Microsoft-Windows-AppLocker",
        "type": [
            "start"
        ]
    },
    "file": {
        "hash": {
            "sha256": "D2A09AC074F8D326B4DCC8B8BE5BC003C41CCB6EB5FC35E13B73F834F2946B01"
        },
        "name": "PSScriptAnalyzer.psm1",
        "pe": {
            "file_version": "0.0.0.00",
            "original_file_name": "",
            "product": ""
        },
        "x509": {
            "subject": {
                "country": [
                    "US"
                ],
                "locality": [
                    "REDMOND"
                ],
                "organization": [
                    "MICROSOFT CORPORATION"
                ],
                "state_or_province": [
                    "WASHINGTON"
                ]
            }
        }
    },
    "host": {
        "name": "el33t-b00k-1"
    },
    "input": {
        "type": "httpjson"
    },
    "log": {
        "level": "warning"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "id": "S-1-5-21-2707992022-4034939591-3454028951-1001"
    },
    "winlog": {
        "activity_id": "{f64315e2-bea0-0000-6d01-d5f6a0bed901}",
        "channel": "Microsoft-Windows-AppLocker/MSI and Script",
        "computer_name": "el33t-b00k-1",
        "event_id": "8006",
        "level": "warning",
        "opcode": "Info",
        "process": {
            "pid": 25192,
            "thread": {
                "id": 7740
            }
        },
        "provider_guid": "{cbda4dbf-8d5d-4f69-9578-be14aa540d22}",
        "provider_name": "Microsoft-Windows-AppLocker",
        "record_id": "239",
        "task": "None",
        "time_created": "2023-08-04T21:26:32.757Z",
        "user": {
            "identifier": "S-1-5-21-2707992022-4034939591-3454028951-1001"
        },
        "user_data": {
            "FileHash": "D2A09AC074F8D326B4DCC8B8BE5BC003C41CCB6EB5FC35E13B73F834F2946B01",
            "FileHashLength": 32,
            "FilePath": "%OSDRIVE%\\USERS\\NICPE\\.VSCODE\\EXTENSIONS\\MS-VSCODE.POWERSHELL-2023.6.0\\MODULES\\PSSCRIPTANALYZER\\1.21.0\\PSSCRIPTANALYZER.PSM1",
            "FilePathLength": 124,
            "Fqbn": "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\\\\\\0.0.0.00",
            "FqbnLength": 65,
            "FullFilePath": "C:\\Users\\nicpe\\.vscode\\extensions\\ms-vscode.powershell-2023.6.0\\modules\\PSScriptAnalyzer\\1.21.0\\PSScriptAnalyzer.psm1",
            "FullFilePathLength": 117,
            "PolicyName": "SCRIPT",
            "PolicyNameLength": 6,
            "RuleId": "{00000000-0000-0000-0000-000000000000}",
            "RuleName": "-",
            "RuleNameLength": 1,
            "RuleSddl": "-",
            "RuleSddlLength": 1,
            "TargetLogonId": "0x4c18f",
            "TargetProcessId": 25192,
            "TargetUser": "S-1-5-21-2707992022-4034939591-3454028951-1001",
            "xml_name": "RuleAndFileData"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| file.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| file.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| file.x509.subject.country | List of country \(C) code | keyword |
| file.x509.subject.locality | List of locality names (L) | keyword |
| file.x509.subject.organization | List of organizations (O) of subject. | keyword |
| file.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_data | The event-specific data. This field is mutually exclusive with `user_data`. If you are capturing event data on versions prior to Windows Vista, the parameters in `event_data` are named `param1`, `param2`, and so on, because event log parameters are unnamed in earlier versions of Windows. | object |
| winlog.event_data.AuthenticationPackageName |  | keyword |
| winlog.event_data.Binary |  | keyword |
| winlog.event_data.BitlockerUserInputTime |  | keyword |
| winlog.event_data.BootMode |  | keyword |
| winlog.event_data.BootType |  | keyword |
| winlog.event_data.BuildVersion |  | keyword |
| winlog.event_data.Company |  | keyword |
| winlog.event_data.CorruptionActionState |  | keyword |
| winlog.event_data.CreationUtcTime |  | keyword |
| winlog.event_data.Description |  | keyword |
| winlog.event_data.Detail |  | keyword |
| winlog.event_data.DeviceName |  | keyword |
| winlog.event_data.DeviceNameLength |  | keyword |
| winlog.event_data.DeviceTime |  | keyword |
| winlog.event_data.DeviceVersionMajor |  | keyword |
| winlog.event_data.DeviceVersionMinor |  | keyword |
| winlog.event_data.DriveName |  | keyword |
| winlog.event_data.DriverName |  | keyword |
| winlog.event_data.DriverNameLength |  | keyword |
| winlog.event_data.DwordVal |  | keyword |
| winlog.event_data.EntryCount |  | keyword |
| winlog.event_data.ExtraInfo |  | keyword |
| winlog.event_data.FailureName |  | keyword |
| winlog.event_data.FailureNameLength |  | keyword |
| winlog.event_data.FileVersion |  | keyword |
| winlog.event_data.FinalStatus |  | keyword |
| winlog.event_data.Group |  | keyword |
| winlog.event_data.IdleImplementation |  | keyword |
| winlog.event_data.IdleStateCount |  | keyword |
| winlog.event_data.ImpersonationLevel |  | keyword |
| winlog.event_data.IntegrityLevel |  | keyword |
| winlog.event_data.IpAddress |  | keyword |
| winlog.event_data.IpPort |  | keyword |
| winlog.event_data.KeyLength |  | keyword |
| winlog.event_data.LastBootGood |  | keyword |
| winlog.event_data.LastShutdownGood |  | keyword |
| winlog.event_data.LmPackageName |  | keyword |
| winlog.event_data.LogonGuid |  | keyword |
| winlog.event_data.LogonId |  | keyword |
| winlog.event_data.LogonProcessName |  | keyword |
| winlog.event_data.LogonType |  | keyword |
| winlog.event_data.MajorVersion |  | keyword |
| winlog.event_data.MaximumPerformancePercent |  | keyword |
| winlog.event_data.MemberName |  | keyword |
| winlog.event_data.MemberSid |  | keyword |
| winlog.event_data.MinimumPerformancePercent |  | keyword |
| winlog.event_data.MinimumThrottlePercent |  | keyword |
| winlog.event_data.MinorVersion |  | keyword |
| winlog.event_data.NewProcessId |  | keyword |
| winlog.event_data.NewProcessName |  | keyword |
| winlog.event_data.NewSchemeGuid |  | keyword |
| winlog.event_data.NewTime |  | keyword |
| winlog.event_data.NominalFrequency |  | keyword |
| winlog.event_data.Number |  | keyword |
| winlog.event_data.OldSchemeGuid |  | keyword |
| winlog.event_data.OldTime |  | keyword |
| winlog.event_data.OriginalFileName |  | keyword |
| winlog.event_data.Path |  | keyword |
| winlog.event_data.PerformanceImplementation |  | keyword |
| winlog.event_data.PreviousCreationUtcTime |  | keyword |
| winlog.event_data.PreviousTime |  | keyword |
| winlog.event_data.PrivilegeList |  | keyword |
| winlog.event_data.ProcessId |  | keyword |
| winlog.event_data.ProcessName |  | keyword |
| winlog.event_data.ProcessPath |  | keyword |
| winlog.event_data.ProcessPid |  | keyword |
| winlog.event_data.Product |  | keyword |
| winlog.event_data.PuaCount |  | keyword |
| winlog.event_data.PuaPolicyId |  | keyword |
| winlog.event_data.QfeVersion |  | keyword |
| winlog.event_data.Reason |  | keyword |
| winlog.event_data.SchemaVersion |  | keyword |
| winlog.event_data.ScriptBlockText |  | keyword |
| winlog.event_data.ServiceName |  | keyword |
| winlog.event_data.ServiceVersion |  | keyword |
| winlog.event_data.ShutdownActionType |  | keyword |
| winlog.event_data.ShutdownEventCode |  | keyword |
| winlog.event_data.ShutdownReason |  | keyword |
| winlog.event_data.Signature |  | keyword |
| winlog.event_data.SignatureStatus |  | keyword |
| winlog.event_data.Signed |  | keyword |
| winlog.event_data.StartTime |  | keyword |
| winlog.event_data.State |  | keyword |
| winlog.event_data.Status |  | keyword |
| winlog.event_data.StopTime |  | keyword |
| winlog.event_data.SubjectDomainName |  | keyword |
| winlog.event_data.SubjectLogonId |  | keyword |
| winlog.event_data.SubjectUserName |  | keyword |
| winlog.event_data.SubjectUserSid |  | keyword |
| winlog.event_data.TSId |  | keyword |
| winlog.event_data.TargetDomainName |  | keyword |
| winlog.event_data.TargetInfo |  | keyword |
| winlog.event_data.TargetLogonGuid |  | keyword |
| winlog.event_data.TargetLogonId |  | keyword |
| winlog.event_data.TargetServerName |  | keyword |
| winlog.event_data.TargetUserName |  | keyword |
| winlog.event_data.TargetUserSid |  | keyword |
| winlog.event_data.TerminalSessionId |  | keyword |
| winlog.event_data.TokenElevationType |  | keyword |
| winlog.event_data.TransmittedServices |  | keyword |
| winlog.event_data.UserSid |  | keyword |
| winlog.event_data.Version |  | keyword |
| winlog.event_data.Workstation |  | keyword |
| winlog.event_data.param1 |  | keyword |
| winlog.event_data.param2 |  | keyword |
| winlog.event_data.param3 |  | keyword |
| winlog.event_data.param4 |  | keyword |
| winlog.event_data.param5 |  | keyword |
| winlog.event_data.param6 |  | keyword |
| winlog.event_data.param7 |  | keyword |
| winlog.event_data.param8 |  | keyword |
| winlog.event_id | The event identifier. The value is specific to the source of the event. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.level | The level assigned to the event such as Information, Warning, or Critical. | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process ID (PID) of the process that generated/logged the event. This is often the event collector process and not necessarily the process that the event is about. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.time_created | The time the event was created. | date |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.user_data.FileHash |  | keyword |
| winlog.user_data.FileHashLength |  | long |
| winlog.user_data.FilePath |  | keyword |
| winlog.user_data.FilePathLength |  | long |
| winlog.user_data.Fqbn |  | keyword |
| winlog.user_data.FqbnLength |  | long |
| winlog.user_data.FullFilePath |  | keyword |
| winlog.user_data.FullFilePathLength |  | long |
| winlog.user_data.PolicyName |  | keyword |
| winlog.user_data.PolicyNameLength |  | long |
| winlog.user_data.RuleId |  | keyword |
| winlog.user_data.RuleName |  | keyword |
| winlog.user_data.RuleNameLength |  | long |
| winlog.user_data.RuleSddl |  | keyword |
| winlog.user_data.RuleSddlLength |  | long |
| winlog.user_data.TargetLogonId |  | keyword |
| winlog.user_data.TargetProcessId |  | long |
| winlog.user_data.TargetUser |  | keyword |
| winlog.user_data.xml_name |  | keyword |
| winlog.version | The version number of the event's definition. | long |


### AppLocker/Packaged app-Deployment

The Windows `applocker_packaged_app_deployment` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/Packaged app-Deployment` event log.

An example event for `applocker_packaged_app_deployment` looks as following:

```json
{
    "@timestamp": "2023-08-15T14:12:32.680Z",
    "agent": {
        "ephemeral_id": "03a46cd5-bd39-49b3-b8cf-493dcd361920",
        "id": "4c6333d2-c654-4cac-be07-248d79340ee5",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "data_stream": {
        "dataset": "windows.applocker_packaged_app_deployment",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.9.0"
    },
    "elastic_agent": {
        "id": "4c6333d2-c654-4cac-be07-248d79340ee5",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "action": "None",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "code": "8023",
        "created": "2023-08-15T22:51:13.753Z",
        "dataset": "windows.applocker_packaged_app_deployment",
        "ingested": "2023-08-15T22:51:17Z",
        "kind": "event",
        "original": "\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/\u003e\u003cEventID\u003e8023\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x1000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2023-08-15T14:12:32.6801945Z'/\u003e\u003cEventRecordID\u003e6269\u003c/EventRecordID\u003e\u003cCorrelation ActivityID='{eac4f4ed-cf73-0001-a741-c5ea73cfd901}'/\u003e\u003cExecution ProcessID='4584' ThreadID='26688'/\u003e\u003cChannel\u003eMicrosoft-Windows-AppLocker/Packaged app-Deployment\u003c/Channel\u003e\u003cComputer\u003eWIN1012009LL.local\u003c/Computer\u003e\u003cSecurity UserID='S-1-5-21-1133191089-1850170202-1535859923-200319'/\u003e\u003c/System\u003e\u003cUserData\u003e\u003cRuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'\u003e\u003cPolicyNameLength\u003e4\u003c/PolicyNameLength\u003e\u003cPolicyName\u003eAPPX\u003c/PolicyName\u003e\u003cRuleId\u003e{a9e18c21-ff8f-43cf-b9fc-db40eed693ba}\u003c/RuleId\u003e\u003cRuleNameLength\u003e39\u003c/RuleNameLength\u003e\u003cRuleName\u003e(Default Rule) All signed packaged apps\u003c/RuleName\u003e\u003cRuleSddlLength\u003e81\u003c/RuleSddlLength\u003e\u003cRuleSddl\u003eyams\u003c/RuleSddl\u003e\u003cTargetUser\u003eS-1-5-21-1133191089-1850170202-1535859923-200319\u003c/TargetUser\u003e\u003cTargetProcessId\u003e4584\u003c/TargetProcessId\u003e\u003cPackageLength\u003e18\u003c/PackageLength\u003e\u003cPackage\u003eMicrosoft.BingNews\u003c/Package\u003e\u003cFqbnLength\u003e118\u003c/FqbnLength\u003e\u003cFqbn\u003eCN=MICROSOFT CORPORATION, O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\\MICROSOFT.BINGNEWS\\APPX\\4.55.62231.00\u003c/Fqbn\u003e\u003c/RuleAndFileData\u003e\u003c/UserData\u003e\u003c/Event\u003e",
        "provider": "Microsoft-Windows-AppLocker",
        "type": [
            "start"
        ]
    },
    "file": {
        "pe": {
            "file_version": "4.55.62231.00",
            "original_file_name": "APPX",
            "product": "MICROSOFT.BINGNEWS"
        },
        "x509": {
            "subject": {
                "common_name": [
                    "MICROSOFT CORPORATION"
                ],
                "country": [
                    "US"
                ],
                "locality": [
                    "REDMOND"
                ],
                "organization": [
                    "MICROSOFT CORPORATION"
                ],
                "state_or_province": [
                    "WASHINGTON"
                ]
            }
        }
    },
    "host": {
        "name": "WIN1012009LL.local"
    },
    "input": {
        "type": "httpjson"
    },
    "log": {
        "level": "information"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "id": "S-1-5-21-1133191089-1850170202-1535859923-200319"
    },
    "winlog": {
        "activity_id": "{eac4f4ed-cf73-0001-a741-c5ea73cfd901}",
        "channel": "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "computer_name": "WIN1012009LL.local",
        "event_id": "8023",
        "level": "information",
        "opcode": "Info",
        "process": {
            "pid": 4584,
            "thread": {
                "id": 26688
            }
        },
        "provider_guid": "{cbda4dbf-8d5d-4f69-9578-be14aa540d22}",
        "provider_name": "Microsoft-Windows-AppLocker",
        "record_id": "6269",
        "task": "None",
        "time_created": "2023-08-15T14:12:32.680Z",
        "user": {
            "identifier": "S-1-5-21-1133191089-1850170202-1535859923-200319"
        },
        "user_data": {
            "Fqbn": "CN=MICROSOFT CORPORATION, O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\\MICROSOFT.BINGNEWS\\APPX\\4.55.62231.00",
            "FqbnLength": 118,
            "Package": "Microsoft.BingNews",
            "PackageLength": "18",
            "PolicyName": "APPX",
            "PolicyNameLength": 4,
            "RuleId": "{a9e18c21-ff8f-43cf-b9fc-db40eed693ba}",
            "RuleName": "(Default Rule) All signed packaged apps",
            "RuleNameLength": 39,
            "RuleSddl": "yams",
            "RuleSddlLength": 81,
            "TargetProcessId": 4584,
            "TargetUser": "S-1-5-21-1133191089-1850170202-1535859923-200319",
            "xml_name": "RuleAndFileData"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| file.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| file.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| file.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| file.x509.subject.country | List of country \(C) code | keyword |
| file.x509.subject.locality | List of locality names (L) | keyword |
| file.x509.subject.organization | List of organizations (O) of subject. | keyword |
| file.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_data | The event-specific data. This field is mutually exclusive with `user_data`. If you are capturing event data on versions prior to Windows Vista, the parameters in `event_data` are named `param1`, `param2`, and so on, because event log parameters are unnamed in earlier versions of Windows. | object |
| winlog.event_data.AuthenticationPackageName |  | keyword |
| winlog.event_data.Binary |  | keyword |
| winlog.event_data.BitlockerUserInputTime |  | keyword |
| winlog.event_data.BootMode |  | keyword |
| winlog.event_data.BootType |  | keyword |
| winlog.event_data.BuildVersion |  | keyword |
| winlog.event_data.Company |  | keyword |
| winlog.event_data.CorruptionActionState |  | keyword |
| winlog.event_data.CreationUtcTime |  | keyword |
| winlog.event_data.Description |  | keyword |
| winlog.event_data.Detail |  | keyword |
| winlog.event_data.DeviceName |  | keyword |
| winlog.event_data.DeviceNameLength |  | keyword |
| winlog.event_data.DeviceTime |  | keyword |
| winlog.event_data.DeviceVersionMajor |  | keyword |
| winlog.event_data.DeviceVersionMinor |  | keyword |
| winlog.event_data.DriveName |  | keyword |
| winlog.event_data.DriverName |  | keyword |
| winlog.event_data.DriverNameLength |  | keyword |
| winlog.event_data.DwordVal |  | keyword |
| winlog.event_data.EntryCount |  | keyword |
| winlog.event_data.ExtraInfo |  | keyword |
| winlog.event_data.FailureName |  | keyword |
| winlog.event_data.FailureNameLength |  | keyword |
| winlog.event_data.FileVersion |  | keyword |
| winlog.event_data.FinalStatus |  | keyword |
| winlog.event_data.Group |  | keyword |
| winlog.event_data.IdleImplementation |  | keyword |
| winlog.event_data.IdleStateCount |  | keyword |
| winlog.event_data.ImpersonationLevel |  | keyword |
| winlog.event_data.IntegrityLevel |  | keyword |
| winlog.event_data.IpAddress |  | keyword |
| winlog.event_data.IpPort |  | keyword |
| winlog.event_data.KeyLength |  | keyword |
| winlog.event_data.LastBootGood |  | keyword |
| winlog.event_data.LastShutdownGood |  | keyword |
| winlog.event_data.LmPackageName |  | keyword |
| winlog.event_data.LogonGuid |  | keyword |
| winlog.event_data.LogonId |  | keyword |
| winlog.event_data.LogonProcessName |  | keyword |
| winlog.event_data.LogonType |  | keyword |
| winlog.event_data.MajorVersion |  | keyword |
| winlog.event_data.MaximumPerformancePercent |  | keyword |
| winlog.event_data.MemberName |  | keyword |
| winlog.event_data.MemberSid |  | keyword |
| winlog.event_data.MinimumPerformancePercent |  | keyword |
| winlog.event_data.MinimumThrottlePercent |  | keyword |
| winlog.event_data.MinorVersion |  | keyword |
| winlog.event_data.NewProcessId |  | keyword |
| winlog.event_data.NewProcessName |  | keyword |
| winlog.event_data.NewSchemeGuid |  | keyword |
| winlog.event_data.NewTime |  | keyword |
| winlog.event_data.NominalFrequency |  | keyword |
| winlog.event_data.Number |  | keyword |
| winlog.event_data.OldSchemeGuid |  | keyword |
| winlog.event_data.OldTime |  | keyword |
| winlog.event_data.OriginalFileName |  | keyword |
| winlog.event_data.Path |  | keyword |
| winlog.event_data.PerformanceImplementation |  | keyword |
| winlog.event_data.PreviousCreationUtcTime |  | keyword |
| winlog.event_data.PreviousTime |  | keyword |
| winlog.event_data.PrivilegeList |  | keyword |
| winlog.event_data.ProcessId |  | keyword |
| winlog.event_data.ProcessName |  | keyword |
| winlog.event_data.ProcessPath |  | keyword |
| winlog.event_data.ProcessPid |  | keyword |
| winlog.event_data.Product |  | keyword |
| winlog.event_data.PuaCount |  | keyword |
| winlog.event_data.PuaPolicyId |  | keyword |
| winlog.event_data.QfeVersion |  | keyword |
| winlog.event_data.Reason |  | keyword |
| winlog.event_data.SchemaVersion |  | keyword |
| winlog.event_data.ScriptBlockText |  | keyword |
| winlog.event_data.ServiceName |  | keyword |
| winlog.event_data.ServiceVersion |  | keyword |
| winlog.event_data.ShutdownActionType |  | keyword |
| winlog.event_data.ShutdownEventCode |  | keyword |
| winlog.event_data.ShutdownReason |  | keyword |
| winlog.event_data.Signature |  | keyword |
| winlog.event_data.SignatureStatus |  | keyword |
| winlog.event_data.Signed |  | keyword |
| winlog.event_data.StartTime |  | keyword |
| winlog.event_data.State |  | keyword |
| winlog.event_data.Status |  | keyword |
| winlog.event_data.StopTime |  | keyword |
| winlog.event_data.SubjectDomainName |  | keyword |
| winlog.event_data.SubjectLogonId |  | keyword |
| winlog.event_data.SubjectUserName |  | keyword |
| winlog.event_data.SubjectUserSid |  | keyword |
| winlog.event_data.TSId |  | keyword |
| winlog.event_data.TargetDomainName |  | keyword |
| winlog.event_data.TargetInfo |  | keyword |
| winlog.event_data.TargetLogonGuid |  | keyword |
| winlog.event_data.TargetLogonId |  | keyword |
| winlog.event_data.TargetServerName |  | keyword |
| winlog.event_data.TargetUserName |  | keyword |
| winlog.event_data.TargetUserSid |  | keyword |
| winlog.event_data.TerminalSessionId |  | keyword |
| winlog.event_data.TokenElevationType |  | keyword |
| winlog.event_data.TransmittedServices |  | keyword |
| winlog.event_data.UserSid |  | keyword |
| winlog.event_data.Version |  | keyword |
| winlog.event_data.Workstation |  | keyword |
| winlog.event_data.param1 |  | keyword |
| winlog.event_data.param2 |  | keyword |
| winlog.event_data.param3 |  | keyword |
| winlog.event_data.param4 |  | keyword |
| winlog.event_data.param5 |  | keyword |
| winlog.event_data.param6 |  | keyword |
| winlog.event_data.param7 |  | keyword |
| winlog.event_data.param8 |  | keyword |
| winlog.event_id | The event identifier. The value is specific to the source of the event. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.level | The level assigned to the event such as Information, Warning, or Critical. | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process ID (PID) of the process that generated/logged the event. This is often the event collector process and not necessarily the process that the event is about. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.time_created | The time the event was created. | date |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.user_data.FileHash |  | keyword |
| winlog.user_data.FileHashLength |  | long |
| winlog.user_data.FilePath |  | keyword |
| winlog.user_data.FilePathLength |  | long |
| winlog.user_data.Fqbn |  | keyword |
| winlog.user_data.FqbnLength |  | long |
| winlog.user_data.FullFilePath |  | keyword |
| winlog.user_data.FullFilePathLength |  | long |
| winlog.user_data.Package |  | keyword |
| winlog.user_data.PackageLength |  | keyword |
| winlog.user_data.PolicyName |  | keyword |
| winlog.user_data.PolicyNameLength |  | long |
| winlog.user_data.RuleId |  | keyword |
| winlog.user_data.RuleName |  | keyword |
| winlog.user_data.RuleNameLength |  | long |
| winlog.user_data.RuleSddl |  | keyword |
| winlog.user_data.RuleSddlLength |  | long |
| winlog.user_data.TargetLogonId |  | keyword |
| winlog.user_data.TargetProcessId |  | long |
| winlog.user_data.TargetUser |  | keyword |
| winlog.user_data.xml_name |  | keyword |
| winlog.version | The version number of the event's definition. | long |


### AppLocker/Packaged app-Execution

The Windows `applocker_packaged_app_execution` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/Packaged app-Execution` event log.

An example event for `applocker_packaged_app_execution` looks as following:

```json
{
    "@timestamp": "2023-08-13T13:53:33.706Z",
    "agent": {
        "ephemeral_id": "b26295a5-6dd5-4ff4-9102-98ebdf4f097c",
        "id": "a2f04e82-dbc6-4eae-b003-e7cd21a975ef",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "data_stream": {
        "dataset": "windows.applocker_packaged_app_execution",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.9.0"
    },
    "elastic_agent": {
        "id": "a2f04e82-dbc6-4eae-b003-e7cd21a975ef",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "action": "None",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "code": "8020",
        "created": "2023-08-17T14:13:22.965Z",
        "dataset": "windows.applocker_packaged_app_execution",
        "ingested": "2023-08-17T14:13:26Z",
        "kind": "event",
        "original": "\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/\u003e\u003cEventID\u003e8020\u003c/EventID\u003e\u003cVersion\u003e0\u003c/Version\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e0\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x2000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2023-08-13T13:53:33.7067781Z'/\u003e\u003cEventRecordID\u003e2986\u003c/EventRecordID\u003e\u003cCorrelation/\u003e\u003cExecution ProcessID='1672' ThreadID='8384'/\u003e\u003cChannel\u003eMicrosoft-Windows-AppLocker/Packaged app-Execution\u003c/Channel\u003e\u003cComputer\u003eel33t-b00k-1\u003c/Computer\u003e\u003cSecurity UserID='S-1-5-21-2707992022-4034939591-3454028951-1001'/\u003e\u003c/System\u003e\u003cUserData\u003e\u003cRuleAndFileData xmlns='http://schemas.microsoft.com/schemas/event/Microsoft.Windows/1.0.0.0'\u003e\u003cPolicyNameLength\u003e4\u003c/PolicyNameLength\u003e\u003cPolicyName\u003eAPPX\u003c/PolicyName\u003e\u003cRuleId\u003e{a9e18c21-ff8f-43cf-b9fc-db40eed693ba}\u003c/RuleId\u003e\u003cRuleNameLength\u003e39\u003c/RuleNameLength\u003e\u003cRuleName\u003e(Default Rule) All signed packaged apps\u003c/RuleName\u003e\u003cRuleSddlLength\u003e81\u003c/RuleSddlLength\u003e\u003cRuleSddl\u003eD:(XA;;FX;;;S-1-1-0;((Exists APPID://FQBN) \u0026amp;\u0026amp; ((APPID://FQBN) \u0026gt;= ({\"*\\*\\*\",0}))))\u003c/RuleSddl\u003e\u003cTargetUser\u003eS-1-5-21-2707992022-4034939591-3454028951-1001\u003c/TargetUser\u003e\u003cTargetProcessId\u003e41864\u003c/TargetProcessId\u003e\u003cPackageLength\u003e15\u003c/PackageLength\u003e\u003cPackage\u003eMICROSOFT.TODOS\u003c/Package\u003e\u003cFqbnLength\u003e116\u003c/FqbnLength\u003e\u003cFqbn\u003eCN=MICROSOFT CORPORATION, O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\\MICROSOFT.TODOS\\APPX\\2.100.61791.00\u003c/Fqbn\u003e\u003c/RuleAndFileData\u003e\u003c/UserData\u003e\u003c/Event\u003e",
        "provider": "Microsoft-Windows-AppLocker",
        "type": [
            "start"
        ]
    },
    "file": {
        "pe": {
            "file_version": "2.100.61791.00",
            "original_file_name": "APPX",
            "product": "MICROSOFT.TODOS"
        },
        "x509": {
            "subject": {
                "common_name": [
                    "MICROSOFT CORPORATION"
                ],
                "country": [
                    "US"
                ],
                "locality": [
                    "REDMOND"
                ],
                "organization": [
                    "MICROSOFT CORPORATION"
                ],
                "state_or_province": [
                    "WASHINGTON"
                ]
            }
        }
    },
    "host": {
        "name": "el33t-b00k-1"
    },
    "input": {
        "type": "httpjson"
    },
    "log": {
        "level": "information"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "id": "S-1-5-21-2707992022-4034939591-3454028951-1001"
    },
    "winlog": {
        "channel": "Microsoft-Windows-AppLocker/Packaged app-Execution",
        "computer_name": "el33t-b00k-1",
        "event_id": "8020",
        "level": "information",
        "opcode": "Info",
        "process": {
            "pid": 1672,
            "thread": {
                "id": 8384
            }
        },
        "provider_guid": "{cbda4dbf-8d5d-4f69-9578-be14aa540d22}",
        "provider_name": "Microsoft-Windows-AppLocker",
        "record_id": "2986",
        "task": "None",
        "time_created": "2023-08-13T13:53:33.706Z",
        "user": {
            "identifier": "S-1-5-21-2707992022-4034939591-3454028951-1001"
        },
        "user_data": {
            "Fqbn": "CN=MICROSOFT CORPORATION, O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\\MICROSOFT.TODOS\\APPX\\2.100.61791.00",
            "FqbnLength": 116,
            "Package": "MICROSOFT.TODOS",
            "PackageLength": "15",
            "PolicyName": "APPX",
            "PolicyNameLength": 4,
            "RuleId": "{a9e18c21-ff8f-43cf-b9fc-db40eed693ba}",
            "RuleName": "(Default Rule) All signed packaged apps",
            "RuleNameLength": 39,
            "RuleSddl": "D:(XA;;FX;;;S-1-1-0;((Exists APPID://FQBN) \u0026\u0026 ((APPID://FQBN) \u003e= ({\"*\\*\\*\",0}))))",
            "RuleSddlLength": 81,
            "TargetProcessId": 41864,
            "TargetUser": "S-1-5-21-2707992022-4034939591-3454028951-1001",
            "xml_name": "RuleAndFileData"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| file.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| file.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| file.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| file.x509.subject.country | List of country \(C) code | keyword |
| file.x509.subject.locality | List of locality names (L) | keyword |
| file.x509.subject.organization | List of organizations (O) of subject. | keyword |
| file.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_data | The event-specific data. This field is mutually exclusive with `user_data`. If you are capturing event data on versions prior to Windows Vista, the parameters in `event_data` are named `param1`, `param2`, and so on, because event log parameters are unnamed in earlier versions of Windows. | object |
| winlog.event_data.AuthenticationPackageName |  | keyword |
| winlog.event_data.Binary |  | keyword |
| winlog.event_data.BitlockerUserInputTime |  | keyword |
| winlog.event_data.BootMode |  | keyword |
| winlog.event_data.BootType |  | keyword |
| winlog.event_data.BuildVersion |  | keyword |
| winlog.event_data.Company |  | keyword |
| winlog.event_data.CorruptionActionState |  | keyword |
| winlog.event_data.CreationUtcTime |  | keyword |
| winlog.event_data.Description |  | keyword |
| winlog.event_data.Detail |  | keyword |
| winlog.event_data.DeviceName |  | keyword |
| winlog.event_data.DeviceNameLength |  | keyword |
| winlog.event_data.DeviceTime |  | keyword |
| winlog.event_data.DeviceVersionMajor |  | keyword |
| winlog.event_data.DeviceVersionMinor |  | keyword |
| winlog.event_data.DriveName |  | keyword |
| winlog.event_data.DriverName |  | keyword |
| winlog.event_data.DriverNameLength |  | keyword |
| winlog.event_data.DwordVal |  | keyword |
| winlog.event_data.EntryCount |  | keyword |
| winlog.event_data.ExtraInfo |  | keyword |
| winlog.event_data.FailureName |  | keyword |
| winlog.event_data.FailureNameLength |  | keyword |
| winlog.event_data.FileVersion |  | keyword |
| winlog.event_data.FinalStatus |  | keyword |
| winlog.event_data.Group |  | keyword |
| winlog.event_data.IdleImplementation |  | keyword |
| winlog.event_data.IdleStateCount |  | keyword |
| winlog.event_data.ImpersonationLevel |  | keyword |
| winlog.event_data.IntegrityLevel |  | keyword |
| winlog.event_data.IpAddress |  | keyword |
| winlog.event_data.IpPort |  | keyword |
| winlog.event_data.KeyLength |  | keyword |
| winlog.event_data.LastBootGood |  | keyword |
| winlog.event_data.LastShutdownGood |  | keyword |
| winlog.event_data.LmPackageName |  | keyword |
| winlog.event_data.LogonGuid |  | keyword |
| winlog.event_data.LogonId |  | keyword |
| winlog.event_data.LogonProcessName |  | keyword |
| winlog.event_data.LogonType |  | keyword |
| winlog.event_data.MajorVersion |  | keyword |
| winlog.event_data.MaximumPerformancePercent |  | keyword |
| winlog.event_data.MemberName |  | keyword |
| winlog.event_data.MemberSid |  | keyword |
| winlog.event_data.MinimumPerformancePercent |  | keyword |
| winlog.event_data.MinimumThrottlePercent |  | keyword |
| winlog.event_data.MinorVersion |  | keyword |
| winlog.event_data.NewProcessId |  | keyword |
| winlog.event_data.NewProcessName |  | keyword |
| winlog.event_data.NewSchemeGuid |  | keyword |
| winlog.event_data.NewTime |  | keyword |
| winlog.event_data.NominalFrequency |  | keyword |
| winlog.event_data.Number |  | keyword |
| winlog.event_data.OldSchemeGuid |  | keyword |
| winlog.event_data.OldTime |  | keyword |
| winlog.event_data.OriginalFileName |  | keyword |
| winlog.event_data.Path |  | keyword |
| winlog.event_data.PerformanceImplementation |  | keyword |
| winlog.event_data.PreviousCreationUtcTime |  | keyword |
| winlog.event_data.PreviousTime |  | keyword |
| winlog.event_data.PrivilegeList |  | keyword |
| winlog.event_data.ProcessId |  | keyword |
| winlog.event_data.ProcessName |  | keyword |
| winlog.event_data.ProcessPath |  | keyword |
| winlog.event_data.ProcessPid |  | keyword |
| winlog.event_data.Product |  | keyword |
| winlog.event_data.PuaCount |  | keyword |
| winlog.event_data.PuaPolicyId |  | keyword |
| winlog.event_data.QfeVersion |  | keyword |
| winlog.event_data.Reason |  | keyword |
| winlog.event_data.SchemaVersion |  | keyword |
| winlog.event_data.ScriptBlockText |  | keyword |
| winlog.event_data.ServiceName |  | keyword |
| winlog.event_data.ServiceVersion |  | keyword |
| winlog.event_data.ShutdownActionType |  | keyword |
| winlog.event_data.ShutdownEventCode |  | keyword |
| winlog.event_data.ShutdownReason |  | keyword |
| winlog.event_data.Signature |  | keyword |
| winlog.event_data.SignatureStatus |  | keyword |
| winlog.event_data.Signed |  | keyword |
| winlog.event_data.StartTime |  | keyword |
| winlog.event_data.State |  | keyword |
| winlog.event_data.Status |  | keyword |
| winlog.event_data.StopTime |  | keyword |
| winlog.event_data.SubjectDomainName |  | keyword |
| winlog.event_data.SubjectLogonId |  | keyword |
| winlog.event_data.SubjectUserName |  | keyword |
| winlog.event_data.SubjectUserSid |  | keyword |
| winlog.event_data.TSId |  | keyword |
| winlog.event_data.TargetDomainName |  | keyword |
| winlog.event_data.TargetInfo |  | keyword |
| winlog.event_data.TargetLogonGuid |  | keyword |
| winlog.event_data.TargetLogonId |  | keyword |
| winlog.event_data.TargetServerName |  | keyword |
| winlog.event_data.TargetUserName |  | keyword |
| winlog.event_data.TargetUserSid |  | keyword |
| winlog.event_data.TerminalSessionId |  | keyword |
| winlog.event_data.TokenElevationType |  | keyword |
| winlog.event_data.TransmittedServices |  | keyword |
| winlog.event_data.UserSid |  | keyword |
| winlog.event_data.Version |  | keyword |
| winlog.event_data.Workstation |  | keyword |
| winlog.event_data.param1 |  | keyword |
| winlog.event_data.param2 |  | keyword |
| winlog.event_data.param3 |  | keyword |
| winlog.event_data.param4 |  | keyword |
| winlog.event_data.param5 |  | keyword |
| winlog.event_data.param6 |  | keyword |
| winlog.event_data.param7 |  | keyword |
| winlog.event_data.param8 |  | keyword |
| winlog.event_id | The event identifier. The value is specific to the source of the event. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.level | The level assigned to the event such as Information, Warning, or Critical. | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process ID (PID) of the process that generated/logged the event. This is often the event collector process and not necessarily the process that the event is about. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.time_created | The time the event was created. | date |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.user_data.FileHash |  | keyword |
| winlog.user_data.FileHashLength |  | long |
| winlog.user_data.FilePath |  | keyword |
| winlog.user_data.FilePathLength |  | long |
| winlog.user_data.Fqbn |  | keyword |
| winlog.user_data.FqbnLength |  | long |
| winlog.user_data.FullFilePath |  | keyword |
| winlog.user_data.FullFilePathLength |  | long |
| winlog.user_data.Package |  | keyword |
| winlog.user_data.PackageLength |  | keyword |
| winlog.user_data.PolicyName |  | keyword |
| winlog.user_data.PolicyNameLength |  | long |
| winlog.user_data.RuleId |  | keyword |
| winlog.user_data.RuleName |  | keyword |
| winlog.user_data.RuleNameLength |  | long |
| winlog.user_data.RuleSddl |  | keyword |
| winlog.user_data.RuleSddlLength |  | long |
| winlog.user_data.TargetLogonId |  | keyword |
| winlog.user_data.TargetProcessId |  | long |
| winlog.user_data.TargetUser |  | keyword |
| winlog.user_data.xml_name |  | keyword |
| winlog.version | The version number of the event's definition. | long |
