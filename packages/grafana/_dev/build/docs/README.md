# Grafana Integration

The Grafana integration collects metrics and logs from [Grafana](https://grafana.com/) instances using Elastic Agent.

## Compatibility

This integration has been tested with Grafana versions 10.x, 11.x, and 12.x.

## Data Streams

### Metrics

The `metrics` data stream scrapes Prometheus metrics from Grafana's `/metrics` endpoint. It collects application-level metrics (HTTP performance, alerting, datasource requests, database connections, instance stats) and Go runtime metrics (CPU, memory, goroutines, file descriptors).

Grafana must have metrics enabled (`GF_METRICS_ENABLED=true` or `[metrics] enabled = true` in `grafana.ini`). Metrics are enabled by default.

{{event "metrics"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "metrics"}}

### Logs

The `logs` data stream collects Grafana server logs from file. Both JSON and logfmt (the default) formats are supported. To use JSON logging, set `format = json` under `[log.file]` in `grafana.ini` or set the `GF_LOG_FILE_FORMAT=json` environment variable.

{{event "logs"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "logs"}}

## Setup

1. Add the Grafana integration in Fleet.
2. Configure the **Grafana Hosts** to point at your Grafana instance(s), for example `http://grafana:3000`.
3. For logs, set the **Log Paths** to the location of your Grafana log file(s), for example `/var/log/grafana/grafana.log`.
4. If your `/metrics` endpoint requires authentication, provide the **Username** and **Password**.

## Dashboards

The integration includes two dashboards:

- **[Grafana] Overview** — Instance stats, CPU, memory, goroutines, file descriptors, database connections, and alerting status.
- **[Grafana] Logs** — Log volume by level, top error messages, component breakdown, HTTP status codes, and request paths.
