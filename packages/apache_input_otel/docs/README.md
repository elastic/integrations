# Apache HTTP Server OpenTelemetry Input Package 

## Overview
The Apache HTTP Server OpenTelemetry Input Package for Elastic enables collection of telemetry data from Apache web servers through OpenTelemetry protocols using the [apachereceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/apachereceiver).


### How it works
This package receives telemetry data from Apache HTTP servers by configuring the Apache status endpoint in the Input Package, which then gets applied to the apachereceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [Apache OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/apache_otel) gets auto installed and the dashboards light up.


## Requirements

- Apache HTTP Server 2.4.13+
- The `mod_status` module must be enabled and accessible


## Configuration

For the full list of settings exposed for the receiver and examples, refer to the [configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/apachereceiver#configuration) section.


## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [Apache Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/apachereceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
