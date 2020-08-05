# CrowdStrike Integration

This integration is for CrowdStrike products. It includes the
following datasets for receiving logs:

- `falcon` dataset: consists of endpoint data and Falcon platform audit data forwarded from Falcon SIEM Connector.

## Compatibility

This integration supports CrowdStrike Falcon SIEM-Connector-v2.0.

## Logs

### Falcon

Contains endpoint data and CrowdStrike Falcon platform audit data forwarded from Falcon SIEM Connector.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.id | Unique identifier of this agent. | keyword |
| agent.name | Custom name of the agent. | keyword |
| agent.type | Type of the agent. | keyword |
| container.id | Unique container id. | keyword |
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
| crowdstrike.event.PatternDispositionFlags | Flags indicating actions taken. | object |
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
| destination.ip | IP address of the destination. | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category (e.g. database) | keyword |
| event.code | Identification code for this event. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | Event kind (e.g. event) | keyword |
| event.outcome |  | keyword |
| event.severity | Numeric severity of the event. | long |
| event.type | Event type (e.g. info, error) | keyword |
| event.url | Event investigation URL | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| host.name | Name of the host. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| network.direction | Direction of the network traffic. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc | keyword |
| process.args | Array of process arguments. | keyword |
| process.command_line | Full command line that started the process. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.name | Process name. | keyword |
| process.parent.command_line | Full command line that started the process. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.pid | Process id. | long |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| rule.category | Rule category | keyword |
| rule.description | Rule description | keyword |
| rule.id | Rule ID | keyword |
| rule.name | Rule name | keyword |
| rule.ruleset | Rule ruleset | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.tactic.name | Threat tactic. | keyword |
| threat.technique.name | Threat technique name. | keyword |
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |

