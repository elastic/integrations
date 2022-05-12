# Windows Integration

The Windows integration allows you to monitor the Windows OS, services, applications, and more.

Use the Windows integration to collect metrics and logs from your machine.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

For example, if you wanted to know if a Windows service unexpectedly stops running, you could install the Windows integration to send service metrics to Elastic.
Then, you could view real-time changes to to service status in Kibana's _[Metrics Windows] Services_ dashboard.

## Data types

The Windows integration collects two types of data: logs and metrics.

**Logs** help you keep a record of events that happen on your machine.
Log datasets collected by the Windows integration include forwarded events, PowerShell events, and Sysmon events. 
See more details in the [Logs reference](#logs-reference).

**Metrics** give you insight into the state of the machine.
Metric datasets collected by the Windows integration include service details and performance counter values.
See more details in the [Metrics reference](#metrics-reference).

Note: for 7.11, `security`, `application` and `system` logs have been moved to the system package.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

The Windows datasets collect different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.
Details on the permissions needed for each dataset are available in the [Metrics](#metrics-reference) and [Logs](#logs-reference) reference.

## Setup

For step-by-step instructions on how to set up an integration,
see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

Note: Because the Windows integration always applies to the local server, the `hosts` config option is not needed.

### Ingesting Windows Events via Splunk

This integration allows you to seamlessly ingest data from a Splunk Enterprise instance.
The integration uses the [`httpjson` input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-httpjson.html) in Elastic Agent to run a Splunk search via the Splunk REST API and extract the raw event from the results.
The raw event is then processed via the Elastic Agent.
You can customized both the Splunk search query and the interval between searches.
For more information see [Ingest data from Splunk](https://www.elastic.co/guide/en/observability/current/ingest-splunk.html).

Note: This integration requires Windows Events from Splunk to be in XML format.
To achieve this, `renderXml` needs to be set to `1` in your [`inputs.conf`](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf) file.

## Logs reference

### Forwarded

The Windows `forwarded` dataset provides events from the Windows
`ForwardedEvents` event log. The fields will be the same as the 
channel specific datasets.

#### Permissions

This data should be available without elevated permissions.

### Powershell

The Windows `powershell` dataset provides events from the Windows
`Windows PowerShell` event log.

#### Permissions

This data should be available without elevated permissions.

{{event "powershell"}}

{{fields "powershell"}}

### Powershell/Operational

The Windows `powershell_operational` dataset provides events from the Windows
`Microsoft-Windows-PowerShell/Operational` event log.

#### Permissions

This data should be available without elevated permissions.

{{event "powershell_operational"}}

{{fields "powershell_operational"}}

### Sysmon/Operational

The Windows `sysmon_operational` dataset provides events from the Windows
`Microsoft-Windows-Sysmon/Operational` event log.

#### Permissions

This data should be available without elevated permissions.

{{event "sysmon_operational"}}

{{fields "sysmon_operational"}}

## Metrics reference

Both datasets are available on Windows only.

### Service

The Windows `service` dataset provides service details.

#### Permissions

This data should be available without elevated permissions.

{{fields "service"}}

### Perfmon

The Windows `perfmon` dataset provides performance counter values.

#### Permissions

This data should be available without elevated permissions.

{{fields "perfmon"}}
