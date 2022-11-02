# Sysmon Integration

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

### Sysmon/Operational

The Sysmon `log` data stream provides events from the Sysmon
`Linux Syslog` log.

{{event "log"}}

{{fields "log"}}
