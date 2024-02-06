# Custom Windows event log package

The custom Windows event log package allows you to ingest events from any [Windows event log](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log) channel.
You can get a list of available event log channels by running [`Get-WinEvent -ListLog * | Format-List -Property LogName`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) in PowerShell on Windows Vista or newer.
If `Get-WinEvent` is not available, [`Get-EventLog *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog) may be used.
Custom ingest pipelines may be added by setting one up in [Ingest Node Pipelines](/app/management/ingest/ingest_pipelines/).

## Configuration

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

## Fields Mapping

In addition to the fields specified below, this integration includes the ECS Dynamic Template. Any field that follow the ECS Schema will get assigned the correct index field mapping and does not need to be added manually.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computerObject.domain |  | keyword |
| winlog.computerObject.id |  | keyword |
| winlog.computerObject.name |  | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_data | The event-specific data. This field is mutually exclusive with `user_data`. If you are capturing event data on versions prior to Windows Vista, the parameters in `event_data` are named `param1`, `param2`, and so on, because event log parameters are unnamed in earlier versions of Windows. | object |
| winlog.event_data.AccessGranted |  | keyword |
| winlog.event_data.AccessRemoved |  | keyword |
| winlog.event_data.AccountDomain |  | keyword |
| winlog.event_data.AccountExpires |  | keyword |
| winlog.event_data.AccountName |  | keyword |
| winlog.event_data.AllowedToDelegateTo |  | keyword |
| winlog.event_data.AuditPolicyChanges |  | keyword |
| winlog.event_data.AuditPolicyChangesDescription |  | keyword |
| winlog.event_data.AuditSourceName |  | keyword |
| winlog.event_data.AuthenticationPackageName |  | keyword |
| winlog.event_data.Binary |  | keyword |
| winlog.event_data.BitlockerUserInputTime |  | keyword |
| winlog.event_data.BootMode |  | keyword |
| winlog.event_data.BootType |  | keyword |
| winlog.event_data.BuildVersion |  | keyword |
| winlog.event_data.CallerProcessId |  | keyword |
| winlog.event_data.CallerProcessName |  | keyword |
| winlog.event_data.Category |  | keyword |
| winlog.event_data.CategoryId |  | keyword |
| winlog.event_data.ClientAddress |  | keyword |
| winlog.event_data.ClientName |  | keyword |
| winlog.event_data.CommandLine |  | keyword |
| winlog.event_data.Company |  | keyword |
| winlog.event_data.CorruptionActionState |  | keyword |
| winlog.event_data.CrashOnAuditFailValue |  | keyword |
| winlog.event_data.CreationUtcTime |  | keyword |
| winlog.event_data.Description |  | keyword |
| winlog.event_data.Detail |  | keyword |
| winlog.event_data.DeviceName |  | keyword |
| winlog.event_data.DeviceNameLength |  | keyword |
| winlog.event_data.DeviceTime |  | keyword |
| winlog.event_data.DeviceVersionMajor |  | keyword |
| winlog.event_data.DeviceVersionMinor |  | keyword |
| winlog.event_data.DisplayName |  | keyword |
| winlog.event_data.DomainBehaviorVersion |  | keyword |
| winlog.event_data.DomainName |  | keyword |
| winlog.event_data.DomainPolicyChanged |  | keyword |
| winlog.event_data.DomainSid |  | keyword |
| winlog.event_data.DriveName |  | keyword |
| winlog.event_data.DriverName |  | keyword |
| winlog.event_data.DriverNameLength |  | keyword |
| winlog.event_data.Dummy |  | keyword |
| winlog.event_data.DwordVal |  | keyword |
| winlog.event_data.EntryCount |  | keyword |
| winlog.event_data.EventSourceId |  | keyword |
| winlog.event_data.ExtraInfo |  | keyword |
| winlog.event_data.FailureName |  | keyword |
| winlog.event_data.FailureNameLength |  | keyword |
| winlog.event_data.FailureReason |  | keyword |
| winlog.event_data.FileVersion |  | keyword |
| winlog.event_data.FinalStatus |  | keyword |
| winlog.event_data.Group |  | keyword |
| winlog.event_data.GroupTypeChange |  | keyword |
| winlog.event_data.HandleId |  | keyword |
| winlog.event_data.HomeDirectory |  | keyword |
| winlog.event_data.HomePath |  | keyword |
| winlog.event_data.IdleImplementation |  | keyword |
| winlog.event_data.IdleStateCount |  | keyword |
| winlog.event_data.ImpersonationLevel |  | keyword |
| winlog.event_data.IntegrityLevel |  | keyword |
| winlog.event_data.IpAddress |  | keyword |
| winlog.event_data.IpPort |  | keyword |
| winlog.event_data.KerberosPolicyChange |  | keyword |
| winlog.event_data.KeyLength |  | keyword |
| winlog.event_data.LastBootGood |  | keyword |
| winlog.event_data.LastShutdownGood |  | keyword |
| winlog.event_data.LmPackageName |  | keyword |
| winlog.event_data.LogonGuid |  | keyword |
| winlog.event_data.LogonHours |  | keyword |
| winlog.event_data.LogonID |  | keyword |
| winlog.event_data.LogonId |  | keyword |
| winlog.event_data.LogonProcessName |  | keyword |
| winlog.event_data.LogonType |  | keyword |
| winlog.event_data.MachineAccountQuota |  | keyword |
| winlog.event_data.MajorVersion |  | keyword |
| winlog.event_data.MandatoryLabel |  | keyword |
| winlog.event_data.MaximumPerformancePercent |  | keyword |
| winlog.event_data.MemberName |  | keyword |
| winlog.event_data.MemberSid |  | keyword |
| winlog.event_data.MinimumPerformancePercent |  | keyword |
| winlog.event_data.MinimumThrottlePercent |  | keyword |
| winlog.event_data.MinorVersion |  | keyword |
| winlog.event_data.MixedDomainMode |  | keyword |
| winlog.event_data.NewProcessId |  | keyword |
| winlog.event_data.NewProcessName |  | keyword |
| winlog.event_data.NewSchemeGuid |  | keyword |
| winlog.event_data.NewSd |  | keyword |
| winlog.event_data.NewSdDacl0 |  | keyword |
| winlog.event_data.NewSdDacl1 |  | keyword |
| winlog.event_data.NewSdDacl2 |  | keyword |
| winlog.event_data.NewSdSacl0 |  | keyword |
| winlog.event_data.NewSdSacl1 |  | keyword |
| winlog.event_data.NewSdSacl2 |  | keyword |
| winlog.event_data.NewTargetUserName |  | keyword |
| winlog.event_data.NewTime |  | keyword |
| winlog.event_data.NewUACList |  | keyword |
| winlog.event_data.NewUacValue |  | keyword |
| winlog.event_data.NominalFrequency |  | keyword |
| winlog.event_data.Number |  | keyword |
| winlog.event_data.ObjectName |  | keyword |
| winlog.event_data.ObjectServer |  | keyword |
| winlog.event_data.ObjectType |  | keyword |
| winlog.event_data.OemInformation |  | keyword |
| winlog.event_data.OldSchemeGuid |  | keyword |
| winlog.event_data.OldSd |  | keyword |
| winlog.event_data.OldSdDacl0 |  | keyword |
| winlog.event_data.OldSdDacl1 |  | keyword |
| winlog.event_data.OldSdDacl2 |  | keyword |
| winlog.event_data.OldSdSacl0 |  | keyword |
| winlog.event_data.OldSdSacl1 |  | keyword |
| winlog.event_data.OldSdSacl2 |  | keyword |
| winlog.event_data.OldTargetUserName |  | keyword |
| winlog.event_data.OldTime |  | keyword |
| winlog.event_data.OldUacValue |  | keyword |
| winlog.event_data.OriginalFileName |  | keyword |
| winlog.event_data.PackageName |  | keyword |
| winlog.event_data.ParentProcessName |  | keyword |
| winlog.event_data.PasswordHistoryLength |  | keyword |
| winlog.event_data.PasswordLastSet |  | keyword |
| winlog.event_data.Path |  | keyword |
| winlog.event_data.PerformanceImplementation |  | keyword |
| winlog.event_data.PreAuthType |  | keyword |
| winlog.event_data.PreviousCreationUtcTime |  | keyword |
| winlog.event_data.PreviousTime |  | keyword |
| winlog.event_data.PrimaryGroupId |  | keyword |
| winlog.event_data.PrivilegeList |  | keyword |
| winlog.event_data.ProcessId |  | keyword |
| winlog.event_data.ProcessName |  | keyword |
| winlog.event_data.ProcessPath |  | keyword |
| winlog.event_data.ProcessPid |  | keyword |
| winlog.event_data.Product |  | keyword |
| winlog.event_data.ProfilePath |  | keyword |
| winlog.event_data.PuaCount |  | keyword |
| winlog.event_data.PuaPolicyId |  | keyword |
| winlog.event_data.QfeVersion |  | keyword |
| winlog.event_data.Reason |  | keyword |
| winlog.event_data.SamAccountName |  | keyword |
| winlog.event_data.SchemaVersion |  | keyword |
| winlog.event_data.ScriptBlockText |  | keyword |
| winlog.event_data.ScriptPath |  | keyword |
| winlog.event_data.Service |  | keyword |
| winlog.event_data.ServiceAccount |  | keyword |
| winlog.event_data.ServiceFileName |  | keyword |
| winlog.event_data.ServiceName |  | keyword |
| winlog.event_data.ServiceSid |  | keyword |
| winlog.event_data.ServiceStartType |  | keyword |
| winlog.event_data.ServiceType |  | keyword |
| winlog.event_data.ServiceVersion |  | keyword |
| winlog.event_data.SessionName |  | keyword |
| winlog.event_data.ShutdownActionType |  | keyword |
| winlog.event_data.ShutdownEventCode |  | keyword |
| winlog.event_data.ShutdownReason |  | keyword |
| winlog.event_data.SidFilteringEnabled |  | keyword |
| winlog.event_data.SidHistory |  | keyword |
| winlog.event_data.Signature |  | keyword |
| winlog.event_data.SignatureStatus |  | keyword |
| winlog.event_data.Signed |  | keyword |
| winlog.event_data.StartTime |  | keyword |
| winlog.event_data.State |  | keyword |
| winlog.event_data.Status |  | keyword |
| winlog.event_data.StatusDescription |  | keyword |
| winlog.event_data.StopTime |  | keyword |
| winlog.event_data.SubCategory |  | keyword |
| winlog.event_data.SubCategoryGuid |  | keyword |
| winlog.event_data.SubCategoryId |  | keyword |
| winlog.event_data.SubStatus |  | keyword |
| winlog.event_data.SubcategoryGuid |  | keyword |
| winlog.event_data.SubcategoryId |  | keyword |
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
| winlog.event_data.TargetSid |  | keyword |
| winlog.event_data.TargetUserName |  | keyword |
| winlog.event_data.TargetUserSid |  | keyword |
| winlog.event_data.TdoAttributes |  | keyword |
| winlog.event_data.TdoDirection |  | keyword |
| winlog.event_data.TdoType |  | keyword |
| winlog.event_data.TerminalSessionId |  | keyword |
| winlog.event_data.TicketEncryptionType |  | keyword |
| winlog.event_data.TicketEncryptionTypeDescription |  | keyword |
| winlog.event_data.TicketOptions |  | keyword |
| winlog.event_data.TicketOptionsDescription |  | keyword |
| winlog.event_data.TokenElevationType |  | keyword |
| winlog.event_data.TransmittedServices |  | keyword |
| winlog.event_data.UserAccountControl |  | keyword |
| winlog.event_data.UserParameters |  | keyword |
| winlog.event_data.UserPrincipalName |  | keyword |
| winlog.event_data.UserSid |  | keyword |
| winlog.event_data.UserWorkstations |  | keyword |
| winlog.event_data.Version |  | keyword |
| winlog.event_data.Workstation |  | keyword |
| winlog.event_data.WorkstationName |  | keyword |
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
| winlog.level | The event severity.  Levels are Critical, Error, Warning and Information, Verbose | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.outcome | Success or Failure of the event. | keyword |
| winlog.process.pid | The process_id of the Client Server Runtime Process. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.time_created | Time event was created | date |
| winlog.trustAttribute |  | keyword |
| winlog.trustDirection |  | keyword |
| winlog.trustType |  | keyword |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.user_data.BackupPath |  | keyword |
| winlog.user_data.Channel |  | keyword |
| winlog.user_data.SubjectDomainName |  | keyword |
| winlog.user_data.SubjectLogonId |  | keyword |
| winlog.user_data.SubjectUserName |  | keyword |
| winlog.user_data.SubjectUserSid |  | keyword |
| winlog.user_data.xml_name |  | keyword |
| winlog.version | The version number of the event's definition. | long |
