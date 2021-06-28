# Windows Integration

The Windows package allows you to monitor the Windows os, services, applications etc. Because the Windows integration
always applies to the local server, the `hosts` config option is not needed. Note that for 7.11, `security`, `application` and `system` logs have been moved to the system package.

## Compatibility

The Windows datasets collect different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Configuration

### Splunk Enterprise

To configure Splunk Enterprise to be able to pull events from it, please visit
[Splunk docs](https://docs.splunk.com/Documentation/SplunkCloud/latest/Data/MonitorWindowseventlogdata) for details. **The integration requires events in XML format, for this `renderXml` option needs to be set to `1` in your `inputs.conf`.**

## Metrics

### Service

The Windows `service` dataset provides service details.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| windows.service.display_name | The display name of the service. | keyword |
| windows.service.exit_code | For `Stopped` services this is the error code that service reports when starting to stopping. This will be the generic Windows service error code unless the service provides a service-specific error code. | keyword |
| windows.service.id | A unique ID for the service. It is a hash of the machine's GUID and the service name. | keyword |
| windows.service.name | The service name. | keyword |
| windows.service.path_name | Fully qualified path to the file that implements the service, including arguments. | keyword |
| windows.service.pid | For `Running` services this is the associated process PID. | long |
| windows.service.start_name | Account name under which a service runs. | keyword |
| windows.service.start_type | The startup type of the service. The possible values are `Automatic`, `Boot`, `Disabled`, `Manual`, and `System`. | keyword |
| windows.service.state | The actual state of the service. The possible values are `Continuing`, `Pausing`, `Paused`, `Running`, `Starting`, `Stopping`, and `Stopped`. | keyword |
| windows.service.uptime.ms | The service's uptime specified in milliseconds. | long |



### Perfmon

The Windows `perfmon` dataset provides performance counter values.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| windows.perfmon.instance | Instance value. | keyword |
| windows.perfmon.metrics.*.* | Metric values returned. | object |
| windows.perfmon.object | Object value. | keyword |



Both datasets are available on Windows only.

## Logs

### Forwarded

The Windows `forwarded` dataset provides events from the Windows
`ForwardedEvents` event log. The fields will be the same as the 
channel specific datasets.

### Powershell

The Windows `powershell` dataset provides events from the Windows
`Windows PowerShell` event log.

An example event for `powershell` looks as following:

```json
{
    "@timestamp": "2020-05-13T13:21:43.183Z",
    "agent": {
        "ephemeral_id": "0db86869-9076-44ed-acbc-32415bdaa793",
        "hostname": "docker-fleet-agent",
        "id": "8a695e28-aed6-4bbf-90be-5a9b7f99eab9",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "windows.powershell",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "24ec544f-3818-44a4-ac26-223be6af154a",
        "snapshot": true,
        "version": "7.14.0"
    },
    "event": {
        "agent_id_status": "agent_id_mismatch",
        "category": "process",
        "code": "600",
        "created": "2021-06-14T13:43:24.815Z",
        "dataset": "windows.powershell",
        "ingested": "2021-06-14T13:43:25.859030600Z",
        "kind": "event",
        "original": "\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='PowerShell'/\u003e\u003cEventID Qualifiers='0'\u003e600\u003c/EventID\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e6\u003c/Task\u003e\u003cKeywords\u003e0x80000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2020-05-13T13:21:43.183180900Z'/\u003e\u003cEventRecordID\u003e1089\u003c/EventRecordID\u003e\u003cChannel\u003eWindows PowerShell\u003c/Channel\u003e\u003cComputer\u003evagrant\u003c/Computer\u003e\u003cSecurity/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData\u003eCertificate\u003c/Data\u003e\u003cData\u003eStarted\u003c/Data\u003e\u003cData\u003e\tProviderName=Certificate\n\tNewProviderState=Started\n\n\tSequenceNumber=35\n\n\tHostName=Windows PowerShell ISE Host\n\tHostVersion=5.1.17763.1007\n\tHostId=86edc16f-6943-469e-8bd8-ef1857080206\n\tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe C:\\Users\\vagrant\\Desktop\\lateral.ps1\n\tEngineVersion=5.1.17763.1007\n\tRunspaceId=9d21da0b-e402-40e1-92ff-98c5ab1137a9\n\tPipelineId=15\n\tCommandName=\n\tCommandType=\n\tScriptName=\n\tCommandPath=\n\tCommandLine=\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e\n\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='PowerShell'/\u003e\u003cEventID Qualifiers='0'\u003e600\u003c/EventID\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e6\u003c/Task\u003e\u003cKeywords\u003e0x80000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2020-05-13T13:25:04.656426900Z'/\u003e\u003cEventRecordID\u003e1266\u003c/EventRecordID\u003e\u003cChannel\u003eWindows PowerShell\u003c/Channel\u003e\u003cComputer\u003evagrant\u003c/Computer\u003e\u003cSecurity/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData\u003eRegistry\u003c/Data\u003e\u003cData\u003eStarted\u003c/Data\u003e\u003cData\u003e\tProviderName=Registry\n\tNewProviderState=Started\n\n\tSequenceNumber=1\n\n\tHostName=ConsoleHost\n\tHostVersion=5.1.17763.1007\n\tHostId=44b8d66c-f5a2-4abb-ac7d-6db73990a6d3\n\tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -command 'C:\\Gopath\\src\\github.com\\elastic\\beats'\n\tEngineVersion=\n\tRunspaceId=\n\tPipelineId=\n\tCommandName=\n\tCommandType=\n\tScriptName=\n\tCommandPath=\n\tCommandLine=\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e\n\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='PowerShell'/\u003e\u003cEventID Qualifiers='0'\u003e600\u003c/EventID\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e6\u003c/Task\u003e\u003cKeywords\u003e0x80000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2020-06-04T07:25:04.857430200Z'/\u003e\u003cEventRecordID\u003e18640\u003c/EventRecordID\u003e\u003cChannel\u003eWindows PowerShell\u003c/Channel\u003e\u003cComputer\u003evagrant\u003c/Computer\u003e\u003cSecurity/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData\u003eCertificate\u003c/Data\u003e\u003cData\u003eStarted\u003c/Data\u003e\u003cData\u003e\tProviderName=Certificate\n\tNewProviderState=Started\n\n\tSequenceNumber=8\n\n\tHostName=ConsoleHost\n\tHostVersion=2.0\n\tHostId=99a16837-7392-463d-afe5-5f3ed24bd358\n\tEngineVersion=\n\tRunspaceId=\n\tPipelineId=\n\tCommandName=\n\tCommandType=\n\tScriptName=\n\tCommandPath=\n\tCommandLine=\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e",
        "provider": "PowerShell",
        "sequence": 35,
        "type": "info"
    },
    "host": {
        "name": "vagrant"
    },
    "input": {
        "type": "httpjson"
    },
    "log": {
        "level": "information"
    },
    "powershell": {
        "engine": {
            "version": "5.1.17763.1007"
        },
        "pipeline_id": "15",
        "process": {
            "executable_version": "5.1.17763.1007"
        },
        "provider": {
            "name": "Certificate",
            "new_state": "Started"
        },
        "runspace_id": "9d21da0b-e402-40e1-92ff-98c5ab1137a9"
    },
    "process": {
        "args": [
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe",
            "C:\\Users\\vagrant\\Desktop\\lateral.ps1"
        ],
        "args_count": 2,
        "command_line": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe C:\\Users\\vagrant\\Desktop\\lateral.ps1",
        "entity_id": "86edc16f-6943-469e-8bd8-ef1857080206",
        "title": "Windows PowerShell ISE Host"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "winlog": {
        "channel": "Windows PowerShell",
        "computer_name": "vagrant",
        "event_id": "600",
        "keywords": [
            "Classic"
        ],
        "provider_name": "PowerShell",
        "record_id": "1089"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.user.domain | Name of the directory the user is a member of. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| ecs.version | ECS version | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.code | Identification code for this event, if one exists. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. | date |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. | keyword |
| event.module | Name of the module this data is coming from. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.sequence | Sequence number of the event. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. | keyword |
| powershell.command.invocation_details | An array of objects containing detailed information of the executed command. | array |
| powershell.command.invocation_details.name | Only used for ParameterBinding detail type. Indicates the parameter name. | keyword |
| powershell.command.invocation_details.related_command | The command to which the detail is related to. | keyword |
| powershell.command.invocation_details.type | The type of detail. | keyword |
| powershell.command.invocation_details.value | The value of the detail. The meaning of it will depend on the detail type. | text |
| powershell.command.name | Name of the executed command. | keyword |
| powershell.command.path | Path of the executed command. | keyword |
| powershell.command.type | Type of the executed command. | keyword |
| powershell.command.value | The invoked command. | text |
| powershell.connected_user.domain | User domain. | keyword |
| powershell.connected_user.name | User name. | keyword |
| powershell.engine.new_state | New state of the PowerShell engine. | keyword |
| powershell.engine.previous_state | Previous state of the PowerShell engine. | keyword |
| powershell.engine.version | Version of the PowerShell engine version used to execute the command. | keyword |
| powershell.file.script_block_id | Id of the executed script block. | keyword |
| powershell.file.script_block_text | Text of the executed script block. | text |
| powershell.id | Shell Id. | keyword |
| powershell.pipeline_id | Pipeline id. | keyword |
| powershell.process.executable_version | Version of the engine hosting process executable. | keyword |
| powershell.provider.name | Provider name. | keyword |
| powershell.provider.new_state | New state of the PowerShell provider. | keyword |
| powershell.runspace_id | Runspace id. | keyword |
| powershell.sequence | Sequence number of the powershell execution. | long |
| powershell.total | Total number of messages in the sequence. | long |
| process.args | Array of process arguments, starting with the absolute path to the executable. | keyword |
| process.args_count | Length of the process.args array. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. | wildcard |
| process.entity_id | Unique identifier for the process. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.name | Process name. | keyword |
| process.pid | Process PID. | long |
| process.title | Process title. | keyword |
| related.hash |  | keyword |
| related.hosts |  | keyword |
| related.ip |  | ip |
| related.user |  | keyword |
| source.user.domain | Name of the directory the user is a member of. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
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
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process_id of the Client Server Runtime Process. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.version | The version number of the event's definition. | long |


### Powershell/Operational

The Windows `powershell_operational` dataset provides events from the Windows
`Microsoft-Windows-PowerShell/Operational` event log.

An example event for `powershell_operational` looks as following:

```json
{
    "@timestamp": "2020-05-13T09:04:04.755Z",
    "agent": {
        "ephemeral_id": "0db86869-9076-44ed-acbc-32415bdaa793",
        "hostname": "docker-fleet-agent",
        "id": "8a695e28-aed6-4bbf-90be-5a9b7f99eab9",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "windows.powershell_operational",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "24ec544f-3818-44a4-ac26-223be6af154a",
        "snapshot": true,
        "version": "7.14.0"
    },
    "event": {
        "agent_id_status": "agent_id_mismatch",
        "category": "process",
        "code": "4105",
        "created": "2021-06-14T13:44:07.370Z",
        "dataset": "windows.powershell_operational",
        "ingested": "2021-06-14T13:44:08.399097100Z",
        "kind": "event",
        "original": "\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='Microsoft-Windows-PowerShell' Guid='{a0c1853b-5c40-4b15-8766-3cf1c58f985a}'/\u003e\u003cEventID\u003e4105\u003c/EventID\u003e\u003cVersion\u003e1\u003c/Version\u003e\u003cLevel\u003e5\u003c/Level\u003e\u003cTask\u003e102\u003c/Task\u003e\u003cOpcode\u003e15\u003c/Opcode\u003e\u003cKeywords\u003e0x0\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2020-05-13T09:04:04.755232500Z'/\u003e\u003cEventRecordID\u003e790\u003c/EventRecordID\u003e\u003cCorrelation ActivityID='{dd68516a-2930-0000-5962-68dd3029d601}'/\u003e\u003cExecution ProcessID='4204' ThreadID='1476'/\u003e\u003cChannel\u003eMicrosoft-Windows-PowerShell/Operational\u003c/Channel\u003e\u003cComputer\u003evagrant\u003c/Computer\u003e\u003cSecurity UserID='S-1-5-21-1350058589-2282154016-2764056528-1000'/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData Name='ScriptBlockId'\u003ef4a378ab-b74f-41a7-a5ef-6dd55562fdb9\u003c/Data\u003e\u003cData Name='RunspaceId'\u003e9c031e5c-8d5a-4b91-a12e-b3624970b623\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e",
        "provider": "Microsoft-Windows-PowerShell",
        "type": "start"
    },
    "host": {
        "name": "vagrant"
    },
    "input": {
        "type": "httpjson"
    },
    "log": {
        "level": "verbose"
    },
    "powershell": {
        "file": {
            "script_block_id": "f4a378ab-b74f-41a7-a5ef-6dd55562fdb9"
        },
        "runspace_id": "9c031e5c-8d5a-4b91-a12e-b3624970b623"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "id": "S-1-5-21-1350058589-2282154016-2764056528-1000"
    },
    "winlog": {
        "activity_id": "{dd68516a-2930-0000-5962-68dd3029d601}",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "computer_name": "vagrant",
        "event_id": "4105",
        "process": {
            "pid": 4204,
            "thread": {
                "id": 1476
            }
        },
        "provider_guid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
        "provider_name": "Microsoft-Windows-PowerShell",
        "record_id": "790",
        "user": {
            "identifier": "S-1-5-21-1350058589-2282154016-2764056528-1000"
        },
        "version": 1
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.user.domain | Name of the directory the user is a member of. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| ecs.version | ECS version | keyword |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.code | Identification code for this event, if one exists. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. | date |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. | keyword |
| event.module | Name of the module this data is coming from. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.sequence | Sequence number of the event. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. | keyword |
| powershell.command.invocation_details | An array of objects containing detailed information of the executed command. | array |
| powershell.command.invocation_details.name | Only used for ParameterBinding detail type. Indicates the parameter name. | keyword |
| powershell.command.invocation_details.related_command | The command to which the detail is related to. | keyword |
| powershell.command.invocation_details.type | The type of detail. | keyword |
| powershell.command.invocation_details.value | The value of the detail. The meaning of it will depend on the detail type. | text |
| powershell.command.name | Name of the executed command. | keyword |
| powershell.command.path | Path of the executed command. | keyword |
| powershell.command.type | Type of the executed command. | keyword |
| powershell.command.value | The invoked command. | text |
| powershell.connected_user.domain | User domain. | keyword |
| powershell.connected_user.name | User name. | keyword |
| powershell.engine.new_state | New state of the PowerShell engine. | keyword |
| powershell.engine.previous_state | Previous state of the PowerShell engine. | keyword |
| powershell.engine.version | Version of the PowerShell engine version used to execute the command. | keyword |
| powershell.file.script_block_id | Id of the executed script block. | keyword |
| powershell.file.script_block_text | Text of the executed script block. | text |
| powershell.id | Shell Id. | keyword |
| powershell.pipeline_id | Pipeline id. | keyword |
| powershell.process.executable_version | Version of the engine hosting process executable. | keyword |
| powershell.provider.name | Provider name. | keyword |
| powershell.provider.new_state | New state of the PowerShell provider. | keyword |
| powershell.runspace_id | Runspace id. | keyword |
| powershell.sequence | Sequence number of the powershell execution. | long |
| powershell.total | Total number of messages in the sequence. | long |
| process.args | Array of process arguments, starting with the absolute path to the executable. | keyword |
| process.args_count | Length of the process.args array. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. | wildcard |
| process.entity_id | Unique identifier for the process. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.name | Process name. | keyword |
| process.pid | Process PID. | long |
| process.title | Process title. | keyword |
| related.hash |  | keyword |
| related.hosts |  | keyword |
| related.ip |  | ip |
| related.user |  | keyword |
| source.user.domain | Name of the directory the user is a member of. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
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
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process_id of the Client Server Runtime Process. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.version | The version number of the event's definition. | long |


### Sysmon/Operational

The Windows `sysmon_operational` dataset provides events from the Windows
`Microsoft-Windows-Sysmon/Operational` event log.

An example event for `sysmon_operational` looks as following:

```json
{
    "@timestamp": "2019-07-18T03:34:01.261Z",
    "agent": {
        "ephemeral_id": "0db86869-9076-44ed-acbc-32415bdaa793",
        "hostname": "docker-fleet-agent",
        "id": "8a695e28-aed6-4bbf-90be-5a9b7f99eab9",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.14.0"
    },
    "data_stream": {
        "dataset": "windows.sysmon_operational",
        "namespace": "ep",
        "type": "logs"
    },
    "dns": {
        "answers": [
            {
                "data": "www-msn-com.a-0003.a-msedge.net",
                "type": "CNAME"
            },
            {
                "data": "a-0003.a-msedge.net",
                "type": "CNAME"
            },
            {
                "data": "204.79.197.203",
                "type": "A"
            }
        ],
        "question": {
            "name": "www.msn.com",
            "registered_domain": "msn.com",
            "subdomain": "www",
            "top_level_domain": "com"
        },
        "resolved_ip": [
            "204.79.197.203"
        ]
    },
    "ecs": {
        "version": "1.10.0"
    },
    "elastic_agent": {
        "id": "24ec544f-3818-44a4-ac26-223be6af154a",
        "snapshot": true,
        "version": "7.14.0"
    },
    "event": {
        "agent_id_status": "agent_id_mismatch",
        "category": [
            "network"
        ],
        "code": "22",
        "created": "2019-07-18T03:34:02.025Z",
        "dataset": "windows.sysmon_operational",
        "ingested": "2021-06-14T13:44:51.825787300Z",
        "kind": "event",
        "original": "\u003cEvent xmlns='http://schemas.microsoft.com/win/2004/08/events/event'\u003e\u003cSystem\u003e\u003cProvider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/\u003e\u003cEventID\u003e22\u003c/EventID\u003e\u003cVersion\u003e5\u003c/Version\u003e\u003cLevel\u003e4\u003c/Level\u003e\u003cTask\u003e22\u003c/Task\u003e\u003cOpcode\u003e0\u003c/Opcode\u003e\u003cKeywords\u003e0x8000000000000000\u003c/Keywords\u003e\u003cTimeCreated SystemTime='2019-07-18T03:34:02.025237700Z'/\u003e\u003cEventRecordID\u003e67\u003c/EventRecordID\u003e\u003cCorrelation/\u003e\u003cExecution ProcessID='2828' ThreadID='1684'/\u003e\u003cChannel\u003eMicrosoft-Windows-Sysmon/Operational\u003c/Channel\u003e\u003cComputer\u003evagrant-2016\u003c/Computer\u003e\u003cSecurity UserID='S-1-5-18'/\u003e\u003c/System\u003e\u003cEventData\u003e\u003cData Name='RuleName'\u003e\u003c/Data\u003e\u003cData Name='UtcTime'\u003e2019-07-18 03:34:01.261\u003c/Data\u003e\u003cData Name='ProcessGuid'\u003e{fa4a0de6-e8a9-5d2f-0000-001053699900}\u003c/Data\u003e\u003cData Name='ProcessId'\u003e2736\u003c/Data\u003e\u003cData Name='QueryName'\u003ewww.msn.com\u003c/Data\u003e\u003cData Name='QueryStatus'\u003e0\u003c/Data\u003e\u003cData Name='QueryResults'\u003etype:  5 www-msn-com.a-0003.a-msedge.net;type:  5 a-0003.a-msedge.net;::ffff:204.79.197.203;\u003c/Data\u003e\u003cData Name='Image'\u003eC:\\Program Files (x86)\\Internet Explorer\\iexplore.exe\u003c/Data\u003e\u003c/EventData\u003e\u003c/Event\u003e",
        "provider": "Microsoft-Windows-Sysmon",
        "type": [
            "connection",
            "protocol",
            "info"
        ]
    },
    "host": {
        "name": "vagrant-2016"
    },
    "input": {
        "type": "httpjson"
    },
    "log": {
        "level": "information"
    },
    "network": {
        "protocol": "dns"
    },
    "process": {
        "entity_id": "{fa4a0de6-e8a9-5d2f-0000-001053699900}",
        "executable": "C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe",
        "name": "iexplore.exe",
        "pid": 2736
    },
    "related": {
        "hosts": [
            "www-msn-com.a-0003.a-msedge.net",
            "a-0003.a-msedge.net",
            "www.msn.com"
        ],
        "ip": [
            "204.79.197.203"
        ]
    },
    "sysmon": {
        "dns": {
            "status": "SUCCESS"
        }
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "id": "S-1-5-18"
    },
    "winlog": {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer_name": "vagrant-2016",
        "event_id": "22",
        "opcode": "Info",
        "process": {
            "pid": 2828,
            "thread": {
                "id": 1684
            }
        },
        "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        "provider_name": "Microsoft-Windows-Sysmon",
        "record_id": "67",
        "user": {
            "identifier": "S-1-5-18"
        },
        "version": 5
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.domain | Destination domain. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dns.answers | An array containing an object for each answer section returned by the server. | object |
| dns.answers.class | The class of DNS data contained in this resource record. | keyword |
| dns.answers.data | The data describing the resource. | keyword |
| dns.answers.name | The domain name to which this resource record pertains. | keyword |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.header_flags | Array of 2 letter DNS header flags. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.op_code | The DNS operation code that specifies the kind of query in the message. This value is set by the originator of a query and copied into the response. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. | ip |
| dns.response_code | The DNS response code. | keyword |
| dns.type | The type of DNS event captured, query or answer. | keyword |
| ecs.version | ECS version | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. | keyword |
| event.code | Identification code for this event, if one exists. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. | date |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. | keyword |
| event.module | Name of the module this data is coming from. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.provider | Source of the event. | keyword |
| event.sequence | Sequence number of the event. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. | keyword |
| file.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| file.code_signature.status | Additional information about the certificate status. | keyword |
| file.code_signature.subject_name | Subject name of the code signer | keyword |
| file.code_signature.trusted | Stores the trust status of the certificate chain. | boolean |
| file.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. | boolean |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.pe.architecture | CPU architecture target for the file. | keyword |
| file.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| file.pe.description | Internal description of the file, provided at compile-time. | keyword |
| file.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| file.pe.imphash | A hash of the imports in a PE file. | keyword |
| file.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| file.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| group.domain | Name of the directory the group is a member of. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.level | Original log level of the log event. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. | text |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. | keyword |
| network.direction | Direction of the network traffic. | keyword |
| network.protocol | L7 Network protocol name. ex. http, lumberjack, transport protocol. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. | keyword |
| process.args_count | Length of the process.args array. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. | wildcard |
| process.entity_id | Unique identifier for the process. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.hash.sha512 | SHA512 hash. | keyword |
| process.name | Process name. | keyword |
| process.parent.args | Array of process arguments, starting with the absolute path to the executable. | keyword |
| process.parent.args_count | Length of the process.args array. | long |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. | wildcard |
| process.parent.entity_id | Unique identifier for the process. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.name | Process name. | keyword |
| process.parent.pid | Process id. | long |
| process.pe.architecture | CPU architecture target for the file. | keyword |
| process.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.pe.imphash | A hash of the imports in a PE file. | keyword |
| process.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.working_directory | The working directory of the process. | keyword |
| registry.data.strings | Content when writing string types. | wildcard |
| registry.data.type | Standard registry type for encoding contents | keyword |
| registry.hive | Abbreviated name for the hive. | keyword |
| registry.key | Hive-relative path of keys. | keyword |
| registry.path | Full path, including hive, key and value Options\winword.exe\Debugger | keyword |
| registry.value | Name of the value written. | keyword |
| related.hash |  | keyword |
| related.hosts |  | keyword |
| related.ip |  | ip |
| related.user |  | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| service.name | Name of the service data is collected from. | keyword |
| service.type | The type of the service data is collected from. | keyword |
| source.domain | Source domain. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| sysmon.dns.status | Windows status code returned for the DNS query. | keyword |
| sysmon.file.archived | Indicates if the deleted file was archived. | boolean |
| sysmon.file.is_executable | Indicates if the deleted file was an executable. | boolean |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.group.domain | Name of the directory the group is a member of. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.name | Short name or login of the user. | keyword |
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
| winlog.event_data.ClientInfo |  | keyword |
| winlog.event_data.Company |  | keyword |
| winlog.event_data.Configuration |  | keyword |
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
| winlog.event_data.EventType |  | keyword |
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
| winlog.event_data.Session |  | keyword |
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
| winlog.event_data.Type |  | keyword |
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
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process_id of the Client Server Runtime Process. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.version | The version number of the event's definition. | long |
