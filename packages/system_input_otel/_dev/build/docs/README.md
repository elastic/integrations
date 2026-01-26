# System OpenTelemetry Input Package

## Overview
The System OpenTelemetry Input Package for Elastic enables collection of telemetry data about the host system through OpenTelemetry protocols using the [hostmetricsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver#host-metrics-receiver).


### How it works
This package receives telemetry data from host system by configuring the Input Package, which uses the hostmetrics receiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [System OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/system_otel) gets auto installed and the dashboards light up.



## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [Hostmetrics Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver/README.md) in the upstream OpenTelemetry Collector repository.