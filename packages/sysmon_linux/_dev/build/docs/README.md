# Sysmon for Linux Integration

The Sysmon for Linux integration allows you to monitor the [Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux), which is an open-source system monitor tool developed to collect security events from Linux environments.

Use the Sysmon for Linux integration to collect logs from linux machine which has sysmon tool running.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

NOTE: To collect Sysmon events from Windows event log, use [Windows `sysmon_operational` data stream](https://docs.elastic.co/en/integrations/windows#sysmonoperational) instead.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration,
see the {{ url "getting-started-observability" "Getting started" }} guide.

## Data streams

The Sysmon for Linux `log` data stream provides events from logs produced by Sysmon tool running on Linux machine.

{{event "log"}}

{{fields "log"}}
