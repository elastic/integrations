# CrowdStrike Falcon SIEM Connector Integration

This integration is for [CrowdStrike Falcon SIEM Connector](
https://www.crowdstrike.com/blog/tech-center/integrate-with-your-siem/) logs.
The SIEM connector writes Falcon data to a log file that this integration reads.

## Compatibility

This integration supports CrowdStrike Falcon SIEM-Connector-v2.0.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
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
| crowdstrike.event.AuditKeyValues | Fields that were changed in this event. | nested |
| crowdstrike.event.CommandLine | Executable path with command line arguments. | keyword |
| crowdstrike.event.Commands | Commands run in a remote session. | keyword |
| crowdstrike.event.ComputerName | Name of the computer where the detection occurred. | keyword |
| crowdstrike.event.ConnectionDirection | Direction for network connection. | keyword |
| crowdstrike.event.CustomerId | Customer identifier. | keyword |
| crowdstrike.event.DetectDescription | Description of the detection. | keyword |
| crowdstrike.event.DetectId | Unique ID associated with the detection. | keyword |
| crowdstrike.event.DetectName | Name of the detection. | keyword |
| crowdstrike.event.DeviceId | Device on which the event occurred. | keyword |
| crowdstrike.event.EndTimestamp | End time for the remote session in UTC UNIX format. | date |
| crowdstrike.event.EventType | CrowdStrike provided event type. | keyword |
| crowdstrike.event.ExecutablesWritten | Detected executables written to disk by a process. | nested |
| crowdstrike.event.FalconHostLink | URL to view the detection in Falcon. | keyword |
| crowdstrike.event.FileName | File name of the associated process for the detection. | keyword |
| crowdstrike.event.FilePath | Path of the executable associated with the detection. | keyword |
| crowdstrike.event.FineScore | Score for incident. | float |
| crowdstrike.event.Flags.Audit | CrowdStrike audit flag. | boolean |
| crowdstrike.event.Flags.Log | CrowdStrike log flag. | boolean |
| crowdstrike.event.Flags.Monitor | CrowdStrike monitor flag. | boolean |
| crowdstrike.event.GrandparentCommandLine | Grandparent process command line arguments. | keyword |
| crowdstrike.event.GrandparentImageFileName | Path to the grandparent process. | keyword |
| crowdstrike.event.HostName | Host name of the local machine. | keyword |
| crowdstrike.event.HostnameField | Host name of the machine for the remote session. | keyword |
| crowdstrike.event.ICMPCode | RFC2780 ICMP Code field. | keyword |
| crowdstrike.event.ICMPType | RFC2780 ICMP Type field. | keyword |
| crowdstrike.event.IOCType | CrowdStrike type for indicator of compromise. | keyword |
| crowdstrike.event.IOCValue | CrowdStrike value for indicator of compromise. | keyword |
| crowdstrike.event.ImageFileName | File name of the associated process for the detection. | keyword |
| crowdstrike.event.IncidentEndTime | End time for the incident in UTC UNIX format. | date |
| crowdstrike.event.IncidentStartTime | Start time for the incident in UTC UNIX format. | date |
| crowdstrike.event.Ipv | Protocol for network request. | keyword |
| crowdstrike.event.LateralMovement | Lateral movement field for incident. | long |
| crowdstrike.event.LocalAddress | IP address of local machine. | ip |
| crowdstrike.event.LocalIP | IP address of the host associated with the detection. | keyword |
| crowdstrike.event.LocalPort | Port of local machine. | long |
| crowdstrike.event.MACAddress | MAC address of the host associated with the detection. | keyword |
| crowdstrike.event.MD5String | MD5 sum of the executable associated with the detection. | keyword |
| crowdstrike.event.MachineDomain | Domain for the machine associated with the detection. | keyword |
| crowdstrike.event.MatchCount | Number of firewall rule matches. | long |
| crowdstrike.event.MatchCountSinceLastReport | Number of firewall rule matches since the last report. | long |
| crowdstrike.event.NetworkProfile | CrowdStrike network profile. | keyword |
| crowdstrike.event.Objective | Method of detection. | keyword |
| crowdstrike.event.OperationName | Event subtype. | keyword |
| crowdstrike.event.PID | Associated process id for the detection. | long |
| crowdstrike.event.ParentCommandLine | Parent process command line arguments. | keyword |
| crowdstrike.event.ParentImageFileName | Path to the parent process. | keyword |
| crowdstrike.event.ParentProcessId | Parent process ID related to the detection. | integer |
| crowdstrike.event.PatternDispositionDescription | Action taken by Falcon. | keyword |
| crowdstrike.event.PatternDispositionFlags.BootupSafeguardEnabled |  | boolean |
| crowdstrike.event.PatternDispositionFlags.CriticalProcessDisabled |  | boolean |
| crowdstrike.event.PatternDispositionFlags.Detect |  | boolean |
| crowdstrike.event.PatternDispositionFlags.FsOperationBlocked |  | boolean |
| crowdstrike.event.PatternDispositionFlags.InddetMask |  | boolean |
| crowdstrike.event.PatternDispositionFlags.Indicator |  | boolean |
| crowdstrike.event.PatternDispositionFlags.KillParent |  | boolean |
| crowdstrike.event.PatternDispositionFlags.KillProcess |  | boolean |
| crowdstrike.event.PatternDispositionFlags.KillSubProcess |  | boolean |
| crowdstrike.event.PatternDispositionFlags.OperationBlocked |  | boolean |
| crowdstrike.event.PatternDispositionFlags.PolicyDisabled |  | boolean |
| crowdstrike.event.PatternDispositionFlags.ProcessBlocked |  | boolean |
| crowdstrike.event.PatternDispositionFlags.QuarantineFile |  | boolean |
| crowdstrike.event.PatternDispositionFlags.QuarantineMachine |  | boolean |
| crowdstrike.event.PatternDispositionFlags.RegistryOperationBlocked |  | boolean |
| crowdstrike.event.PatternDispositionFlags.Rooting |  | boolean |
| crowdstrike.event.PatternDispositionFlags.SensorOnly |  | boolean |
| crowdstrike.event.PatternDispositionValue | Unique ID associated with action taken. | integer |
| crowdstrike.event.PolicyID | CrowdStrike policy id. | keyword |
| crowdstrike.event.PolicyName | CrowdStrike policy name. | keyword |
| crowdstrike.event.ProcessEndTime | The process termination time in UTC UNIX_MS format. | date |
| crowdstrike.event.ProcessId | Process ID related to the detection. | integer |
| crowdstrike.event.ProcessStartTime | The process start time in UTC UNIX_MS format. | date |
| crowdstrike.event.Protocol | CrowdStrike provided protocol. | keyword |
| crowdstrike.event.RemoteAddress | IP address of remote machine. | ip |
| crowdstrike.event.RemotePort | Port of remote machine. | long |
| crowdstrike.event.RuleAction | Firewall rule action. | keyword |
| crowdstrike.event.RuleDescription | Firewall rule description. | keyword |
| crowdstrike.event.RuleFamilyID | Firewall rule family id. | keyword |
| crowdstrike.event.RuleGroupName | Firewall rule group name. | keyword |
| crowdstrike.event.RuleId | Firewall rule id. | keyword |
| crowdstrike.event.RuleName | Firewall rule name. | keyword |
| crowdstrike.event.SHA1String | SHA1 sum of the executable associated with the detection. | keyword |
| crowdstrike.event.SHA256String | SHA256 sum of the executable associated with the detection. | keyword |
| crowdstrike.event.SensorId | Unique ID associated with the Falcon sensor. | keyword |
| crowdstrike.event.ServiceName | Service associated with this event. | keyword |
| crowdstrike.event.SessionId | Session ID of the remote response session. | keyword |
| crowdstrike.event.Severity | Severity score of the detection. | integer |
| crowdstrike.event.SeverityName | Severity score text. | keyword |
| crowdstrike.event.StartTimestamp | Start time for the remote session in UTC UNIX format. | date |
| crowdstrike.event.State | Whether the incident summary is open and ongoing or closed. | keyword |
| crowdstrike.event.Status | CrowdStrike status. | keyword |
| crowdstrike.event.Success | Indicator of whether or not this event was successful. | boolean |
| crowdstrike.event.Tactic | MITRE tactic category of the detection. | keyword |
| crowdstrike.event.Technique | MITRE technique category of the detection. | keyword |
| crowdstrike.event.Timestamp | Firewall rule triggered timestamp. | date |
| crowdstrike.event.TreeID | CrowdStrike tree id. | keyword |
| crowdstrike.event.UTCTimestamp | Timestamp associated with this event in UTC UNIX format. | date |
| crowdstrike.event.UserId | Email address or user ID associated with the event. | keyword |
| crowdstrike.event.UserIp | IP address associated with the user. | keyword |
| crowdstrike.event.UserName | User name associated with the detection. | keyword |
| crowdstrike.metadata.customerIDString | Customer identifier | keyword |
| crowdstrike.metadata.eventCreationTime | The time this event occurred on the endpoint in UTC UNIX_MS format. | date |
| crowdstrike.metadata.eventType | DetectionSummaryEvent, FirewallMatchEvent, IncidentSummaryEvent, RemoteResponseSessionStartEvent, RemoteResponseSessionEndEvent, AuthActivityAuditEvent, or UserActivityAuditEvent | keyword |
| crowdstrike.metadata.offset | Offset number that tracks the location of the event in stream. This is used to identify unique detection events. | integer |
| crowdstrike.metadata.version | Schema version | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
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
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


An example event for `falcon` looks as following:

```json
{
    "@timestamp": "2020-02-12T21:29:10.710Z",
    "agent": {
        "ephemeral_id": "cc9fb403-5b26-4fe7-aefc-41666b9f4575",
        "id": "ca0beb8d-9522-4450-8af7-3cb7f3d8c478",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "crowdstrike": {
        "event": {
            "AuditKeyValues": [
                {
                    "Key": "APIClientID",
                    "ValueString": "1234567890abcdefghijklmnopqr"
                },
                {
                    "Key": "partition",
                    "ValueString": "0"
                },
                {
                    "Key": "offset",
                    "ValueString": "-1"
                },
                {
                    "Key": "appId",
                    "ValueString": "siem-connector-v2.0.0"
                },
                {
                    "Key": "eventType",
                    "ValueString": "[UserActivityAuditEvent HashSpreadingEvent RemoteResponseSessionStartEvent RemoteResponseSessionEndEvent DetectionSummaryEvent AuthActivityAuditEvent]"
                }
            ],
            "OperationName": "streamStarted",
            "ServiceName": "Crowdstrike Streaming API",
            "Success": true,
            "UTCTimestamp": "2020-02-12T21:29:10.000Z",
            "UserId": "api-client-id:1234567890abcdefghijklmnopqrstuvwxyz",
            "UserIp": "10.10.0.8"
        },
        "metadata": {
            "customerIDString": "8f69fe9e-b995-4204-95ad-44f9bcf75b6b",
            "eventCreationTime": "2020-02-12T21:29:10.710Z",
            "eventType": "AuthActivityAuditEvent",
            "offset": 0,
            "version": "1.0"
        }
    },
    "data_stream": {
        "dataset": "crowdstrike.falcon",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "ca0beb8d-9522-4450-8af7-3cb7f3d8c478",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "crowdstrike.falcon",
        "ingested": "2022-05-09T16:35:19Z",
        "kind": "event",
        "original": "{\n    \"metadata\": {\n        \"customerIDString\": \"8f69fe9e-b995-4204-95ad-44f9bcf75b6b\",\n        \"offset\": 0,\n        \"eventType\": \"AuthActivityAuditEvent\",\n        \"eventCreationTime\": 1581542950710,\n        \"version\": \"1.0\"\n    },\n    \"event\": {\n        \"UserId\": \"api-client-id:1234567890abcdefghijklmnopqrstuvwxyz\",\n        \"UserIp\": \"10.10.0.8\",\n        \"OperationName\": \"streamStarted\",\n        \"ServiceName\": \"Crowdstrike Streaming API\",\n        \"Success\": true,\n        \"UTCTimestamp\": 1581542950,\n        \"AuditKeyValues\": [\n            {\n                \"Key\": \"APIClientID\",\n                \"ValueString\": \"1234567890abcdefghijklmnopqr\"\n            },\n            {\n                \"Key\": \"partition\",\n                \"ValueString\": \"0\"\n            },\n            {\n                \"Key\": \"offset\",\n                \"ValueString\": \"-1\"\n            },\n            {\n                \"Key\": \"appId\",\n                \"ValueString\": \"siem-connector-v2.0.0\"\n            },\n            {\n                \"Key\": \"eventType\",\n                \"ValueString\": \"[UserActivityAuditEvent HashSpreadingEvent RemoteResponseSessionStartEvent RemoteResponseSessionEndEvent DetectionSummaryEvent AuthActivityAuditEvent]\"\n            }\n        ]\n    }\n}",
        "outcome": "success",
        "type": [
            "change"
        ]
    },
    "event.action": "stream_started",
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/falcon-audit-events.log"
        },
        "flags": [
            "multiline"
        ],
        "offset": 910
    },
    "message": "Crowdstrike Streaming API",
    "related": {
        "ip": [
            "10.10.0.8"
        ],
        "user": [
            "api-client-id:1234567890abcdefghijklmnopqrstuvwxyz"
        ]
    },
    "source": {
        "ip": "10.10.0.8"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "crowdstrike-falcon"
    ],
    "user": {
        "name": "api-client-id:1234567890abcdefghijklmnopqrstuvwxyz"
    }
}
```
