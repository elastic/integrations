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

### Sysmon/Operational

The Windows `sysmon_operational` dataset provides events from the Windows
`Microsoft-Windows-Sysmon/Operational` event log.

{{fields "sysmon_operational"}}