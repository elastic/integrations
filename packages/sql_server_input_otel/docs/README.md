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

## Logs reference

The SQL Server receiver can collect log events when a direct database connection is configured. Two event types are available, both disabled by default:

- **Query Sample Events** (`db.server.query_sample`): Captures currently executing queries at scrape time, including session details, wait information, and resource consumption. Enable by setting **Enable Query Sample Events** to `true`.

- **Top Query Events** (`db.server.top_query`): Captures the most expensive queries by execution time within a configurable lookback window, including execution counts, CPU time, and logical reads. Enable by setting **Enable Top Query Events** to `true`.

Both event types require a direct database connection (server, port, username, and password must be configured). The `query_sample_collection` and `top_query_collection` settings control the behavior of each event type.

For a complete list of log attributes, refer to the [SQL Server Receiver logs documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/sqlserverreceiver/logs-documentation.md) in the upstream OpenTelemetry Collector repository.

## Known limitations

### Feature gate: `receiver.sqlserver.RemoveServerResourceAttribute`

Starting with EDOT Collector versions based on OpenTelemetry Collector Contrib v0.129.0+, the upstream receiver includes a feature gate `receiver.sqlserver.RemoveServerResourceAttribute` that removes `server.address` and `server.port` from resource attributes, as they are not identified as resource attributes in the semantic conventions. This feature gate is currently opt-in. Refer to the [upstream documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/sqlserverreceiver#feature-gate) for details.
