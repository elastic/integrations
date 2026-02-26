# Windows Event Log OpenTelemetry Input Package

## Overview
The Windows Event Log OpenTelemetry Input Package for Elastic enables collection of Windows event log data through OpenTelemetry protocols using the [windowseventlogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/windowseventlogreceiver).


### How it works
This package receives Windows event log data by configuring the event log channel in the Input Package, which then gets applied to the windowseventlogreceiver present in the OpenTelemetry Collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, it can be used with the [Windows Event Log (winlog) package](https://github.com/elastic/integrations/tree/main/packages/winlog) assets for dashboards and visualizations.


## Configuration reference
For a complete list of all available configuration options and their descriptions, refer to the [Windows Event Log Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/windowseventlogreceiver) in the upstream OpenTelemetry Collector repository.
