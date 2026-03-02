# Haproxy metrics from OpenTelemetry Collector 

The HAProxy OpenTelemetry integration collects performance and availability metrics from [HAProxy](https://www.haproxy.org/) load balancers.

HAProxy exposes operational statistics through its stats socket or HTTP stats endpoint. The OpenTelemetry Collector retrieves these metrics and forwards them to Elastic, where you can visualize them in Kibana, create dashboards, and configure alerts.

With this integration, you can monitor frontend and backend sessions, traffic distribution, connection rates, errors, and overall service health within the Elastic Observability platform.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

1. Compatibility and supported versions: This integration is compatible with systems running the upstream OpenTelemetry Collector and HAProxy. This integration has been tested with OTEL Collector version v0.144.0 and HAProxy version 3.3.

2. Permissions required: The collector requires access to HAProxy metrics, which are exposed via either the stats socket or the HTTP stats endpoint. Ensure that the OTEL Collector can read from the socket or query the HTTP endpoint. For example, if using the stats socket, the user running the collector must have read permissions on the socket file.

3. HAProxy configuration: HTTP stats endpoint: If using the HTTP stats page, configure HAProxy to allow access from the collector host. For example:

listen stats
    bind *:8404
    mode http
    stats enable
    stats uri /metrics
    stats refresh 10s
    stats auth admin:password

4. Finding the HAProxy config: On most Linux systems, HAProxy’s configuration file is typically located at /etc/haproxy/haproxy.cfg. Check that the stats section or stats socket is enabled and accessible.

## Setup

1. Install OpenTelemetry Collector: You need an OTel Collector to scrape HAProxy metrics and send them to Elasticsearch. Download the collector and verify the installation.

2. Configure OpenTelemetry Collector: You need a collector config YAML to:

- Scrape HAProxy metrics

- Convert to OTLP format

- Export to Elasticsearch

Example: otel-collector-config.yaml:

```
receivers:
  haproxy:
    endpoint: http://localhost:8404/stats
    collection_interval: 10s
    metrics:
      haproxy.sessions.total:
        enabled: true
      haproxy.connections.total:
        enabled: true
      haproxy.downtime:
        enabled: true
      haproxy.connections.average_time:
        enabled: true
      haproxy.active:
        enabled: true
      haproxy.backup:
        enabled: true
      haproxy.clients.canceled:
        enabled: true
      haproxy.compression.bypass:
        enabled: true
      haproxy.compression.count:
        enabled: true
      haproxy.compression.input:
        enabled: true
      haproxy.compression.output:
        enabled: true
      haproxy.failed_checks:
        enabled: true
      haproxy.requests.average_time:
        enabled: true
      haproxy.responses.average_time:
        enabled: true
      haproxy.sessions.limit:
        enabled: true
      haproxy.weight:
        enabled: true

exporters:
  debug:
    verbosity: normal
  elasticsearch/otel:
    endpoint: https://localhost:9200
    user: <userid>
    password: <password>
    mapping:
      mode: otel
    metrics_dynamic_index:
      enabled: true



service:
  pipelines:
    metrics:
      receivers: [haproxy]
      processors: [batch]

```



3. Run OpenTelemetry Collector: Use this above example configuration to run the collector.

4. Enable [Optional Haproxy metrics](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/haproxyreceiver/documentation.md#optional-metrics) in config file: HAProxy exposes a set of default metrics automatically. The OpenTelemetry HAProxy receiver has a list of optional metrics that are not enabled by default. If you want these optional metrics to appear in Elasticsearch, you must explicitly enable them in the OTel Collector HAProxy receiver configuration like in the example above.


## Metrics reference

### Haproxy metrics

Refer to [the documentation of the OpenTelemetry's Haproxy receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/haproxyreceiver/documentation.md).