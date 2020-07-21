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
| @timestamp | Date/time when the event originated. | date |
| agent.id | Unique identifier of this agent. | keyword |
| agent.name | Custom name of the agent. | keyword |
| agent.type | Type of the agent. | keyword |
| crowdstrike.event.AuditKeyValues | Fields that were changed in this event. | nested |
| crowdstrike.event.CommandLine | Executable path with command line arguments. | keyword |
| crowdstrike.event.ComputerName | Name of the computer where the detection occurred. | keyword |
| crowdstrike.event.DetectDescription | Description of the detection. | keyword |
| crowdstrike.event.DetectId | Unique ID associated with the detection. | keyword |
| crowdstrike.event.DetectName | Name of the detection. | keyword |
| crowdstrike.event.EndTimestamp | End time for the remote session in UTC UNIX format. | date |
| crowdstrike.event.FalconHostLink | URL to view the detection in Falcon. | keyword |
| crowdstrike.event.FileName | File name of the associated process for the detection. | keyword |
| crowdstrike.event.FilePath | Path of the executable associated with the detection. | keyword |
| crowdstrike.event.FineScore | Score for incident. | float |
| crowdstrike.event.HostnameField | Host name of the machine for the remote session. | keyword |
| crowdstrike.event.IncidentEndTime | End time for the incident in UTC UNIX format. | date |
| crowdstrike.event.IncidentStartTime | Start time for the incident in UTC UNIX format. | date |
| crowdstrike.event.LocalIP | IP address of the host associated with the detection. | keyword |
| crowdstrike.event.MACAddress | MAC address of the host associated with the detection. | keyword |
| crowdstrike.event.MD5String | MD5 sum of the executable associated with the detection. | keyword |
| crowdstrike.event.MachineDomain | Domain for the machine associated with the detection. | keyword |
| crowdstrike.event.Objective | Method of detection. | keyword |
| crowdstrike.event.OperationName | Event subtype. | keyword |
| crowdstrike.event.ParentProcessId | Parent process ID related to the detection. | integer |
| crowdstrike.event.PatternDispositionDescription | Action taken by Falcon. | keyword |
| crowdstrike.event.PatternDispositionFlags | Flags indicating actions taken. | object |
| crowdstrike.event.PatternDispositionValue | Unique ID associated with action taken. | integer |
| crowdstrike.event.ProcessEndTime | The process termination time in UTC UNIX_MS format. | date |
| crowdstrike.event.ProcessId | Process ID related to the detection. | integer |
| crowdstrike.event.ProcessStartTime | The process start time in UTC UNIX_MS format. | date |
| crowdstrike.event.SHA256String | SHA256 sum of the executable associated with the detection. | keyword |
| crowdstrike.event.SensorId | Unique ID associated with the Falcon sensor. | keyword |
| crowdstrike.event.ServiceName | Service associated with this event. | keyword |
| crowdstrike.event.SessionId | Session ID of the remote response session. | keyword |
| crowdstrike.event.Severity | Severity score of the detection. | integer |
| crowdstrike.event.SeverityName | Severity score text. | keyword |
| crowdstrike.event.StartTimestamp | Start time for the remote session in UTC UNIX format. | date |
| crowdstrike.event.State | Whether the incident summary is open and ongoing or closed. | keyword |
| crowdstrike.event.Success | Indicator of whether or not this event was successful. | boolean |
| crowdstrike.event.Tactic | MITRE tactic category of the detection. | keyword |
| crowdstrike.event.Technique | MITRE technique category of the detection. | keyword |
| crowdstrike.event.UTCTimestamp | Timestamp associated with this event in UTC UNIX format. | date |
| crowdstrike.event.UserId | Email address or user ID associated with the event. | keyword |
| crowdstrike.event.UserIp | IP address associated with the user. | keyword |
| crowdstrike.event.UserName | User name associated with the detection. | keyword |
| crowdstrike.metadata.customerIDString | Customer identifier | keyword |
| crowdstrike.metadata.eventCreationTime | The time this event occurred on the endpoint in UTC UNIX_MS format. | date |
| crowdstrike.metadata.eventType | DetectionSummaryEvent, IncidentSummaryEvent, RemoteResponseSessionStartEvent, RemoteResponseSessionEndEvent, AuthActivityAuditEvent, or UserActivityAuditEvent | keyword |
| crowdstrike.metadata.offset | Offset number that tracks the location of the event in stream. This is used to identify unique detection events. | integer |
| crowdstrike.metadata.version | Schema version | keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | Event category (e.g. database) | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.kind | Event kind (e.g. event) | keyword |
| event.outcome |  | keyword |
| event.severity | Numeric severity of the event. | long |
| event.type | Event type (e.g. info, error) | keyword |
| event.url | Event investigation URL | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| host.name | Name of the host. | keyword |
| message | Log message optimized for viewing in a log viewer. | text |
| process.args | Array of process arguments. | keyword |
| process.command_line | Full command line that started the process. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.name | Process name. | keyword |
| process.pid | Process id. | long |
| rule.name | Rule name | keyword |
| source.ip | IP address of the source. | ip |
| threat.tactic.name | Threat tactic. | keyword |
| threat.technique.name | Threat technique name. | keyword |
| user.domain | Name of the directory the user is a member of. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |

