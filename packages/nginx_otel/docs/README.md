# NGINX metrics and logs from OpenTelemetry Collector

The NGINX OTEL integration allows you to monitor [Nginx](https://nginx.org/), a high-performance web server, reverse proxy, and load balancer. NGINX is widely used for serving web content, proxying traffic, and load balancing across multiple servers.

Use the NGINX OTEL integration to collect and analyze performance metrics and logs from your NGINX instances. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics and logs when troubleshooting performance issues.

For example, if you want to monitor the request rate or connection status of your NGINX server, you can use the [NGINX Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver#nginx-receiver) to collect metrics such as `nginx.requests` or `nginx.connections_current`, and the [Filelog Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver) to collect access and error logs. The NGINX OTEL integration lets you visualize these in Kibana dashboards, set up alerts for high error rates, or troubleshoot by analyzing metric and log trends.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. Compatibility and supported versions: This integration is compatible with systems running either [EDOT Collector](https://www.elastic.co/docs/reference/opentelemetry/quickstart/) or vanilla upstream Collector and NGINX with the `stub_status` module enabled. This integration has been tested with OTEL collector version [v0.129.0](https://github.com/open-telemetry/opentelemetry-collector/tree/v0.129.0), EDOT collector version [9.0](https://www.elastic.co/docs/reference/opentelemetry/compatibility/collectors), and NGINX version 1.27.5. 

2. Permissions required: The collector requires access to the NGINX `stub_status` endpoint (for example, http://localhost:80/nginx_status) and read access to the NGINX log files (typically `/var/log/nginx/access.log` and `/var/log/nginx/error.log`). When running the collector, make sure you have the appropriate permissions.

3. NGINX configuration: The NGINX `stub_status` module must be enabled, and the status endpoint must be accessible. For example:
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


## Setup

1. Make sure the NGINX `stub_status` module is enabled and the status endpoint is accessible.

2. Make sure the NGINX access and error log files are readable by the collector.

3. Install and configure the EDOT Collector or upstream Collector to export metrics and logs to Elasticsearch.

### Receivers

The collector configuration uses three receivers:

- **`nginx`** — Scrapes performance metrics from the NGINX `stub_status` endpoint.
- **`filelog/nginx_access`** — Tails the NGINX access log file.
- **`filelog/nginx_error`** — Tails the NGINX error log file, with multiline support for entries that span multiple lines.

```
extensions:
  file_storage:
    directory: /var/otelcol/storage

receivers:
  nginx:
    endpoint: "http://localhost:80/nginx_status"
    collection_interval: 10s

  filelog/nginx_access:
    include: [/var/log/nginx/access.log]
    include_file_path: true
    start_at: beginning
    storage: file_storage

  filelog/nginx_error:
    include: [/var/log/nginx/error.log]
    include_file_path: true
    start_at: beginning
    multiline:
      line_start_pattern: '^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}'
    storage: file_storage
```

The `file_storage` extension persists the filelog receiver checkpoints so log collection resumes from the correct position after a restart.

### Processors

The `transform` processors parse raw log lines into structured fields using grok patterns:

- **`transform/parse_nginx_access/log`** — Parses the NGINX combined access log format and extracts fields such as `http.request.method`, `http.response.status_code`, `url.original`, `source.address`, `http.response.body.size`, `http.version`, and `user_agent.original`. It also runs user-agent parsing to populate `user_agent.name`.
- **`transform/parse_nginx_error/log`** — Parses NGINX error log entries and extracts `log.level`, `process.pid`, `process.thread.id`, `nginx.error.connection_id`, and `message`.
- **`resourcedetection/system`** — Detects and attaches host-level resource attributes such as `host.name` and `host.arch`.

```
processors:
  transform/parse_nginx_access/log:
    error_mode: ignore
    log_statements:
      - context: log
        conditions:
          - IsMatch(body, "^[\\d.]+ - .+ \\[.+\\] \".+\" \\d+ \\d+ \".+\" \".+\"")
        statements:
          - set(body, ExtractGrokPatterns(body, "%{IPORHOST:source.address} - (-|%{DATA:user.name}) \\[%{HTTPDATE:nginx.access.time}\\] \"%{WORD:http.request.method} %{DATA:url.original} HTTP/%{NUMBER:http.version}\" %{NUMBER:http.response.status_code:long} %{NUMBER:http.response.body.size:long} \"(-|%{DATA:http.request.referrer})\" \"(-|%{DATA:user_agent.original})\"", true))
          - set(attributes["data_stream.dataset"], "nginx.access")
          - set(attributes["event.name"], "nginx.access")
          - set(time, Time(body["nginx.access.time"], "%d/%b/%Y:%H:%M:%S %z"))
          - delete_key(body, "nginx.access.time")
          - set(attributes["http.response.status_code"], body["http.response.status_code"])
          - set(attributes["http.request.method"], body["http.request.method"])
          - set(attributes["url.original"], body["url.original"])
          - set(attributes["source.address"], body["source.address"])
          - set(attributes["http.response.body.size"], body["http.response.body.size"])
          - set(attributes["http.version"], body["http.version"])
          - set(attributes["user_agent.original"], body["user_agent.original"])
      - context: log
        conditions:
          - body["user_agent.original"] != nil
        statements:
          - merge_maps(body, UserAgent(body["user_agent.original"]), "upsert")
          - set(attributes["user_agent.name"], body["user_agent.name"])

  transform/parse_nginx_error/log:
    error_mode: ignore
    log_statements:
      - context: log
        conditions:
          - IsMatch(body, "^\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2} \\[.+\\]")
        statements:
          - 'set(body, ExtractGrokPatterns(body, "%{DATA:nginx.error.time} \\[%{LOGLEVEL:log.level}\\] %{NUMBER:process.pid:long}#%{NUMBER:process.thread.id:long}: (\\*%{NUMBER:nginx.error.connection_id:long} )?%{GREEDYMULTILINE:message}", true, ["GREEDYMULTILINE=(.|\\n)*", "LOGLEVEL=[a-zA-Z]+"]))'
          - set(attributes["data_stream.dataset"], "nginx.error")
          - set(attributes["event.name"], "nginx.error")
          - set(severity_text, body["log.level"])
          - set(attributes["log.level"], body["log.level"])
          - set(attributes["message"], body["message"])
          - set(attributes["process.pid"], body["process.pid"])

  resourcedetection/system:
    detectors: ["system"]
    system:
      hostname_sources: ["os"]
      resource_attributes:
        host.name:
          enabled: true
        host.id:
          enabled: false
        host.arch:
          enabled: true
```

### Exporters and pipelines

Configure the exporter and wire the pipelines together:

```
exporters:
  elasticsearch:
    endpoint: https://localhost:9200
    user: <userid>
    password: <password>
    tls:
      insecure_skip_verify: true
    mapping:
      mode: otel

service:
  extensions: [file_storage]
  pipelines:
    logs/nginx_access:
      receivers: [filelog/nginx_access]
      processors: [transform/parse_nginx_access/log, resourcedetection/system]
      exporters: [elasticsearch]
    logs/nginx_error:
      receivers: [filelog/nginx_error]
      processors: [transform/parse_nginx_error/log, resourcedetection/system]
      exporters: [elasticsearch]
    metrics:
      receivers: [nginx]
      processors: [resourcedetection/system]
      exporters: [elasticsearch]
```

The `resourcedetection/system` processor is required across all pipelines to populate host information used by the dashboard.

## Metrics reference

### NGINX metrics
The [NGINX receiver]((https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md)) collects performance metrics from the NGINX `stub_status` module. Key metrics include:


| Metric Name | Description | Type | Attributes |
|-------------|-------------|------|------------|
| `nginx.requests` | Total number of client requests | Counter | - |
| `nginx.connections_accepted` | Total number of accepted client connections | Counter | - |
| `nginx.connections_handled` | Total number of handled connections | Counter | - |
| `nginx.connections_current` | Current number of client connections by state | Gauge | `state`: `active`, `reading`, `writing`, `waiting` |

#### Connection States

- `active`: Currently active client connections
- `reading`: Connections currently reading request headers
- `writing`: Connections currently writing response to client  
- `waiting`: Idle client connections waiting for a request

These metrics provide insights into:
- **Request volume and patterns** through request counts
- **Connection health** via accepted, and handled connection statistics  
- **Server performance** using active, reading, writing, and waiting connection states

For a complete list of all available metrics and their detailed descriptions, refer to the [NGINX Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md) in the upstream OpenTelemetry Collector repository.








