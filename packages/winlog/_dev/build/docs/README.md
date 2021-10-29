# Custom Windows event log package

The custom Windows event log package allows you to ingest events from
any Windows event log channel.  You can get a list of available event
log channels by running Get-EventLog * in PowerShell.  Custom ingest
pipelines may be added by setting one up in
[Ingest Node Pipelines](/app/management/ingest/ingest_pipelines/).

## Configuration

### Ingesting Windows Events via Splunk

This integration offers the ability to seamlessly ingest data from a Splunk Enterprise instance.
These integrations work by using the [httpjson input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-httpjson.html) in Elastic Agent to run a Splunk search via the Splunk REST API and then extract the raw event from the results.
The raw event is then processed via the Elastic Agent.
The Splunk search is customizable and the interval between searches is customizable.
For more information on the Splunk API integration please see [here](https://www.elastic.co/guide/en/observability/current/ingest-splunk.html).

This integration requires Windows Events from Splunk to be in XML format.
To achieve this, `renderXml` needs to be set to `1` in your [inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf) file.

## Logs

{{fields "winlog"}}
