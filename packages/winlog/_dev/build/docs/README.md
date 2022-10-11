# Custom Windows event log package

The custom Windows event log package allows you to ingest events from
any [Windows event log](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log) channel.  You can get a list of available event
log channels by running `Get-EventLog *` in PowerShell.  Custom ingest
pipelines may be added by setting one up in
[Ingest Node Pipelines](/app/management/ingest/ingest_pipelines/).

## Configuration

### Ingesting Windows Events via Splunk

This integration offers the ability to seamlessly ingest data from a Splunk Enterprise instance.
These integrations work by using the {{ url "filebeat-input-httpjson" "httpjson input" }} in Elastic Agent to run a Splunk search via the Splunk REST API and then extract the raw event from the results.
The raw event is then processed via the Elastic Agent.
The Splunk search is customizable and the interval between searches is customizable.
See the {{ url "observability-ingest-splunk" "Splunk API integration documentation" }} for more information.

This integration requires Windows Events from Splunk to be in XML format.
To achieve this, `renderXml` needs to be set to `1` in your [inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf) file.

## Logs

{{fields "winlog"}}
