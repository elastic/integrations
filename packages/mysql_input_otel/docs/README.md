# MySQL OpenTelemetry Input Package

## Overview

The MySQL OpenTelemetry Input Package for Elastic enables collection of telemetry data from MySQL database servers through OpenTelemetry protocols using the [mysqlreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/mysqlreceiver).

### How it works

This package receives telemetry data from MySQL servers by configuring the MySQL endpoint and credentials in the Input Package, which then gets applied to the mysqlreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis. Once the data arrives into Elasticsearch, its corresponding [MySQL OpenTelemetry Assets Package](https://www.elastic.co/docs/reference/integrations/mysql_otel) gets auto installed and the dashboards light up.

## Requirements

- MySQL 8.0+ or MariaDB 10.11+
- A MySQL user with permissions to run `SHOW GLOBAL STATUS`
- For query sample collection, the `performance_schema` must be enabled

## Configuration

For the full list of settings exposed for the receiver and examples, refer to the [configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/mysqlreceiver#configuration) section.

## Metrics reference

For a complete list of all available metrics and their detailed descriptions, refer to the [MySQL Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/mysqlreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
