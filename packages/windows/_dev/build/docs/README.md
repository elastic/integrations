# Windows Integration

The Windows package allows you to monitor the Windows os, services, applications etc. Because the Windows integration
always applies to the local server, the `hosts` config option is not needed.

## Compatibility

The Windows datasets collect different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Metrics

### Service

The Windows `service` dataset provides service details.

{{fields "service"}}


### Perfmon

The Windows `perfmon` dataset provides performance counter values.

{{fields "perfmon"}}


Both datasets are available on Windows only.

## Logs

### Forwarded

The Windows `forwarded` dataset provides events from the Windows
`ForwardedEvents` event log.

{{fields "forwarded"}}

### Powershell

The Windows `powershell` dataset provides events from the Windows
`Windows PowerShell` event log.

{{fields "powershell"}}

### Powershell/Operational

The Windows `powershell_operational` dataset provides events from the Windows
`Microsoft-Windows-PowerShell/Operational` event log.

{{fields "powershell_operational"}}


### Security

The Windows `security` dataset provides events from the Windows
`Security` event log.

{{fields "security"}}

### Sysmon/Operational

The Windows `sysmon_operational` dataset provides events from the Windows
`Microsoft-Windows-Sysmon/Operational` event log.

{{fields "sysmon_operational"}}
