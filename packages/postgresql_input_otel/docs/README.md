# PostgreSQL OpenTelemetry Input Package

## Overview
The PostgreSQL OpenTelemetry Input Package for Elastic enables collection of telemetry data from PostgreSQL web servers through OpenTelemetry protocols using the [postgresqlreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/postgresqlreceiver).


### How it works
This package receives telemetry data from PostgreSQL servers by configuring the PostgreSQL endpoint in the Input Package, which then gets applied to the postgresqlreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.



## Metrics reference
For a complete list of all available metrics and their detailed descriptions, refer to the [PostgreSQL Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/postgresqlreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.