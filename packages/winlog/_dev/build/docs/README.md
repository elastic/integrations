# Custom Windows event log package

The custom Windows event log package allows you to ingest events from any [Windows event log](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log) channel.
You can get a list of available event log channels by running [`Get-WinEvent -ListLog * | Format-List -Property LogName`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) in PowerShell on Windows Vista or newer.
If `Get-WinEvent` is not available, [`Get-EventLog *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog) may be used.
Custom ingest pipelines may be added by setting one up in [Ingest Node Pipelines](/app/management/ingest/ingest_pipelines/).

## Configuration

### Ingesting Windows Events via Splunk

This integration offers the ability to seamlessly ingest data from a Splunk Enterprise instance.
These integrations work by using the {{ url "filebeat-input-httpjson" "httpjson input" }} in Elastic Agent to run a Splunk search via the Splunk REST API and then extract the raw event from the results.
The raw event is then processed via the Elastic Agent.
The Splunk search is customizable and the interval between searches is customizable.
See the {{ url "observability-ingest-splunk" "Splunk API integration documentation" }} for more information.

This integration requires Windows Events from Splunk to be in XML format.
To achieve this, `renderXml` needs to be set to `1` in your [inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf) file.

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

## Logs

{{fields "winlog"}}
