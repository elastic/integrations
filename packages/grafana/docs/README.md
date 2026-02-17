# Grafana Integration

The Grafana integration collects metrics and logs from [Grafana](https://grafana.com/) instances using Elastic Agent.

## Compatibility

This integration has been tested with Grafana versions 10.x, 11.x, and 12.x.

## Data Streams

### Metrics

The `metrics` data stream scrapes Prometheus metrics from Grafana's `/metrics` endpoint. It collects application-level metrics (HTTP performance, alerting, datasource requests, database connections, instance stats) and Go runtime metrics (CPU, memory, goroutines, file descriptors).

Grafana must have metrics enabled (`GF_METRICS_ENABLED=true` or `[metrics] enabled = true` in `grafana.ini`).

**Exported fields**

| Field | Type | Description |
|---|---|---|
| `grafana.stat.dashboards.total` | long | Total dashboards |
| `grafana.stat.users.total` | long | Total users |
| `grafana.stat.users.active` | long | Active users |
| `grafana.stat.datasources.total` | long | Total datasources |
| `grafana.stat.alert_rules.total` | long | Total alert rules |
| `grafana.alerting.active_alerts` | long | Active alerts |
| `grafana.database.connections.open` | long | Open DB connections |
| `grafana.database.connections.in_use` | long | In-use DB connections |
| `grafana.process.cpu.seconds.total` | double | Total CPU seconds |
| `grafana.process.memory.resident_bytes` | long | Resident memory bytes |
| `grafana.go.goroutines` | long | Number of goroutines |

### Logs

The `logs` data stream collects Grafana server logs from file. Both JSON and logfmt (the default) formats are supported. To use JSON logging, set `format = json` under `[log.file]` in `grafana.ini` or set `GF_LOG_FILE_FORMAT=json`.

**Exported fields**

| Field | Type | Description |
|---|---|---|
| `grafana.log.logger` | keyword | Internal logger/component name |
| `grafana.log.method` | keyword | HTTP method |
| `grafana.log.path` | keyword | HTTP request path |
| `grafana.log.status` | long | HTTP status code |
| `grafana.log.remote_addr` | ip | Remote IP address |
| `grafana.log.duration` | keyword | Request duration |
| `grafana.log.uname` | keyword | Username in context |
| `grafana.log.orgId` | long | Organization ID |
| `log.level` | keyword | Log level (info, warn, error, debug) |

## Setup

1. Add the Grafana integration in Fleet.
2. Configure the **Grafana Hosts** to point at your Grafana instance(s), e.g. `http://grafana:3000`.
3. For logs, set the **Log Paths** to the location of your Grafana log file(s), e.g. `/var/log/grafana/grafana.log`.
4. If your `/metrics` endpoint requires authentication, provide the **Username** and **Password**.

## Dashboards

The integration includes two dashboards:

- **[Grafana] Overview** — Instance stats, CPU, memory, goroutines, file descriptors, database connections, and alerting status.
- **[Grafana] Logs** — Log volume by level, top error messages, component breakdown, HTTP status codes, and request paths.
