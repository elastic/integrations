# Nginx OpenTelemetry Integration

[Nginx](https://nginx.org/) is a high-performance web server, reverse proxy, and load balancer.

## Overview

This integration collects Nginx telemetry through OpenTelemetry Collector receivers managed by Elastic Agent:

- **Metrics** (`nginxreceiver.otel`) — stub_status request count, accepted and handled connections, and current connections by state (active, reading, writing, waiting), scraped by the [nginxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver)
- **Access logs** (`nginx.access.otel`) — HTTP access log lines tailed by the [filelogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver) and parsed by a transform processor into fields such as `http.request.method`, `http.response.status_code`, `url.original`, `url.path`, `client.address`, `network.protocol.version`, and `user_agent.name`
- **Error logs** (`nginx.error.otel`) — error log lines tailed by the filelogreceiver, with multiline support, parsed into `log.level`, `severity_text`, `process.pid`, `process.thread.id`, and request details from the message (`client.address`, `http.request.method`)

Metrics and logs are stored with the native OTel schema — no field renaming or custom mapping is applied.

Once data starts flowing, the **[NGINX OpenTelemetry Assets](https://www.elastic.co/docs/reference/integrations/nginx_otel)** package provides dashboards, alerting rule templates, and SLO templates.

## Compatibility

This integration requires Nginx with the `stub_status` module enabled. It has been tested with Nginx 1.27 and Elastic Stack 9.4.0+.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

The Elastic Agent (or EDOT Collector) must be able to reach the Nginx `stub_status` endpoint and read the access and error log files.

## Prerequisites

| Requirement | Details |
|---|---|
| **Nginx** | `stub_status` module enabled and a reachable status URL |
| **Log files** | Agent must have read access to the access and error log paths |
| **Elastic Stack** | 9.4.0+ |
| **Input packages** | `nginx_otel_input` and `filelog_otel` (installed automatically as dependencies) |
| **Content package** | `nginx_otel` (installed automatically as a dependency) |

## Setup

1. Enable `stub_status` in Nginx and confirm the endpoint is reachable from the agent host. For example:

    ```
    server {
        listen 80;
        server_name localhost;
        location /nginx_status {
            stub_status on;
            allow 127.0.0.1;
            deny all;
        }
    }
    ```

2. Confirm the agent can read the access and error log files (typically `/var/log/nginx/access.log` and `/var/log/nginx/error.log`).

3. Add the integration in Kibana:
   - Go to **Management** → **Integrations** → search for "Nginx (OpenTelemetry)"
   - Click **Add Nginx (OpenTelemetry)**
   - Set **Nginx Status Endpoint** to your `stub_status` URL
   - Confirm the access and error log paths match your host

### Verify data

In **Discover**:

- Metrics: `data_stream.dataset: "nginxreceiver.otel"`
- Access logs: `data_stream.dataset: "nginx.access.otel"`
- Error logs: `data_stream.dataset: "nginx.error.otel"`

## Reference

### Metrics

| Signal | Data stream | Fields |
|--------|-------------|--------|
| Metrics | `metrics-nginxreceiver.otel-*` | [NGINX receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md) |

| Metric | Description | Type |
|---|---|---|
| `nginx.requests` | Total number of client requests | Counter |
| `nginx.connections_accepted` | Total number of accepted client connections | Counter |
| `nginx.connections_handled` | Total number of handled connections | Counter |
| `nginx.connections_current` | Current client connections by `state` (`active`, `reading`, `writing`, `waiting`) | Gauge |

### Logs

| Signal | Data stream | Notes |
|--------|-------------|--------|
| Access logs | `logs-nginx.access.otel-*` | Combined access log format, parsed by `transform/parse_nginx_access` |
| Error logs | `logs-nginx.error.otel-*` | Multiline entries start with `YYYY/MM/DD HH:MM:SS`, parsed by `transform/parse_nginx_error` |
