# Custom Windows event log package

The custom Windows event log package allows you to ingest events from
any Windows event log channel.  You can get a list of available event
log channels by running Get-EventLog * in PowerShell.  Custom ingest
pipelines may be added by setting one up in
[Ingest Node Pipelines](/app/management/ingest/ingest_pipelines/).

## Configuration

### Splunk Enterprise

To configure Splunk Enterprise to be able to pull events from it, please visit
[Splunk docs](https://docs.splunk.com/Documentation/SplunkCloud/latest/Data/MonitorWindowseventlogdata) for details. **The integration requires events in XML format, for this `renderXml` option needs to be set to `1` in your `inputs.conf`.**

{{fields "winlog"}}
