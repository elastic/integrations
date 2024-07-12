# Windows Integration

The Windows integration allows you to monitor the [Windows](https://docs.microsoft.com) OS, services, applications, and more.

Use the Windows integration to collect metrics and logs from your machine.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

For example, if you wanted to know if a Windows service unexpectedly stops running, you could install the Windows integration to send service metrics to Elastic.
Then, you could view real-time changes to service status in Kibana's _[Metrics Windows] Services_ dashboard.

## Data streams

The Windows integration collects two types of data: logs and metrics.

**Logs** help you keep a record of events that happen on your machine.
Log data streams collected by the Windows integration include forwarded events, PowerShell events, and Sysmon events.
Log collection for the Security, Application, and System event logs is handled by the System integration.
See more details in the [Logs reference](#logs-reference).

**Metrics** give you insight into the state of the machine.
Metric data streams collected by the Windows integration include service details and performance counter values.
See more details in the [Metrics reference](#metrics-reference).

Note: For 7.11, `security`, `application` and `system` logs have been moved to the system package.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Setup

For step-by-step instructions on how to set up an integration,
see the {{ url "getting-started-observability" "Getting started" }} guide.

Note: Because the Windows integration always applies to the local server, the `hosts` config option is not needed.

### Ingesting Windows Events via Splunk

This integration allows you to seamlessly ingest data from a Splunk Enterprise instance.
The integration uses the {{ url "filebeat-input-httpjson" "`httpjson` input" }} in Elastic Agent to run a Splunk search via the Splunk REST API and then extract the raw event from the results.
The raw event is then processed via the Elastic Agent.
You can customize both the Splunk search query and the interval between searches.
For more information see {{ url "observability-ingest-splunk" "Ingest data from Splunk" }}.

Note: This integration requires Windows Events from Splunk to be in XML format.
To achieve this, `renderXml` needs to be set to `1` in your [`inputs.conf`](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf) file.

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

{{event "applocker_exe_and_dll"}}

{{fields "applocker_exe_and_dll"}}

### AppLocker/MSI and Script

The Windows `applocker_msi_and_script` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/MSI and Script` event log.

{{event "applocker_msi_and_script"}}

{{fields "applocker_msi_and_script"}}

### AppLocker/Packaged app-Deployment

The Windows `applocker_packaged_app_deployment` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/Packaged app-Deployment` event log.

{{event "applocker_packaged_app_deployment"}}

{{fields "applocker_packaged_app_deployment"}}

### AppLocker/Packaged app-Execution

The Windows `applocker_packaged_app_execution` data stream provides events from the Windows
`Microsoft-Windows-AppLocker/Packaged app-Execution` event log.

{{event "applocker_packaged_app_execution"}}

{{fields "applocker_packaged_app_execution"}}

### Forwarded

The Windows `forwarded` data stream provides events from the Windows
`ForwardedEvents` event log. The fields will be the same as the 
channel specific data streams.

### Powershell

The Windows `powershell` data stream provides events from the Windows
`Windows PowerShell` event log.

{{event "powershell"}}

{{fields "powershell"}}

### Powershell/Operational

The Windows `powershell_operational` data stream provides events from the Windows
`Microsoft-Windows-PowerShell/Operational` event log.

{{event "powershell_operational"}}

{{fields "powershell_operational"}}

### Sysmon/Operational

The Windows `sysmon_operational` data stream provides events from the Windows
`Microsoft-Windows-Sysmon/Operational` event log.

{{event "sysmon_operational"}}

{{fields "sysmon_operational"}}

### Windows Defender/Operational

The Windows `windows_defender` data stream provides events from the Windows
`Microsoft-Windows-Windows Defender/Operational` event log.

{{event "windows_defender"}}

{{fields "windows_defender"}}

## Metrics reference

Both data streams are available on Windows only.

### Service

The Windows `service` data stream provides service details.

{{fields "service"}}

### Perfmon

The Windows `perfmon` data stream provides performance counter values.

{{fields "perfmon"}}
