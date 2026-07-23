# Host Metrics OpenTelemetry Input Package

## Overview
The Host Metrics OpenTelemetry Input Package for Elastic enables collection of telemetry data about the host system through OpenTelemetry protocols using the [hostmetricsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver#host-metrics-receiver).


### How it works
This package receives telemetry data from host system by configuring the Input Package, which uses the hostmetrics receiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [System OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/system_otel) gets auto installed and the dashboards light up.

## Configuration options

### Scrapers

It is possible to disable individual scrapers of the Hostmetrics Receiver using toggles. For the list of the available scrapers and their further descriptions, refer to the [Hostmetrics Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver/README.md) in the upstream OpenTelemetry Collector repository.

### Processors

The Resource Detection Processor is enabled and it's System submodule is configurable via the "Resource Detection Processor / System configuration" parameter. For each resource attribute description, refer to the [Resource Detection Processor / System documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/resourcedetectionprocessor/internal/system/documentation.md) in the upstream OpenTelemetry Collector repository.

## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [Hostmetrics Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver/README.md) in the upstream OpenTelemetry Collector repository.