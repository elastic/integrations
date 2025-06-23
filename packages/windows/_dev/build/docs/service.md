# Windows Service Integration

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Setup

For step-by-step instructions on how to set up an integration,
see the {{ url "getting-started-observability" "Getting started" }} guide.

Note: Because the Windows integration always applies to the local server, the `hosts` config option is not needed.

## Metrics reference

Available on Windows only.

### Service

The Windows `service` data stream provides service details.

{{fields "service"}}

