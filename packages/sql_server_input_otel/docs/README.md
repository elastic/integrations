# SQL Server OpenTelemetry Input Package

## Overview

The SQL Server OpenTelemetry Input Package for Elastic enables collection of telemetry data from Microsoft SQL Server instances through OpenTelemetry protocols using the [sqlserverreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/sqlserverreceiver).

### How it works

This package receives telemetry data from SQL Server instances by configuring the SQL Server receiver in the Input Package, which then gets applied to the sqlserverreceiver present in the EDOT collector, which then forwards the data to Elastic Agent. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

## Requirements

### Windows Performance Counters

Make sure to run the collector as administrator to collect all performance counters for metrics.

### Direct Connection

When configured to directly connect to the SQL Server instance, the user must have the following permissions:

1. At least one of the following permissions:
   - `CREATE DATABASE`
   - `ALTER ANY DATABASE`
   - `VIEW ANY DATABASE`

2. Permission to view server state:
   - SQL Server pre-2022: `VIEW SERVER STATE`
   - SQL Server 2022 and later: `VIEW SERVER PERFORMANCE STATE`

## Configuration

For the full list of settings exposed for the receiver and examples, refer to the [configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/sqlserverreceiver#configuration) section.

## Metrics reference

For a complete list of all available metrics and their detailed descriptions, refer to the [SQL Server Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/sqlserverreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.
