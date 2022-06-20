# Windows Integration

The Windows package allows you to monitor the [Windows](https://docs.microsoft.com) os, services, applications etc. Because the Windows integration
always applies to the local server, the `hosts` config option is not needed. Note that for 7.11, `security`, `application` and `system` logs have been moved to the system package.

## Compatibility

The Windows datasets collect different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Configuration

### Ingesting Windows Events via Splunk

This integration offers the ability to seamlessly ingest data from a Splunk Enterprise instance.
These integrations work by using the [httpjson input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-httpjson.html) in Elastic Agent to run a Splunk search via the Splunk REST API and then extract the raw event from the results.
The raw event is then processed via the Elastic Agent.
The Splunk search is customizable and the interval between searches is customizable.
See the [Splunk API integration documentation](https://www.elastic.co/guide/en/observability/current/ingest-splunk.html) for more information.

This integration requires Windows Events from Splunk to be in XML format.
To achieve this, `renderXml` needs to be set to `1` in your [inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf) file.

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
`ForwardedEvents` event log. The fields will be the same as the 
channel specific datasets.

### Powershell

The Windows `powershell` dataset provides events from the Windows
`Windows PowerShell` event log.

{{event "powershell"}}

{{fields "powershell"}}

### Powershell/Operational

The Windows `powershell_operational` dataset provides events from the Windows
`Microsoft-Windows-PowerShell/Operational` event log.

{{event "powershell_operational"}}

{{fields "powershell_operational"}}

### Sysmon/Operational

The Windows `sysmon_operational` dataset provides events from the Windows
`Microsoft-Windows-Sysmon/Operational` event log.

{{event "sysmon_operational"}}

{{fields "sysmon_operational"}}
