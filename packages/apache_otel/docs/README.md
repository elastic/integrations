# Apache HTTP Server OpenTelemetry Assets

Apache HTTP Server is a widely used open-source web server that delivers web content over HTTP. It supports modular functionality through dynamically loadable modules, including `mod_status` for runtime server performance monitoring.

This package provides dashboards, alert rules, and SLO templates for monitoring Apache HTTP Server using data collected by the OpenTelemetry Collector's Apache receiver, covering request traffic, worker pool utilization, connection management, and system resource consumption.

## Compatibility

The Apache HTTP Server OpenTelemetry assets have been tested with OpenTelemetry Apache receiver v0.146.1.

Apache versions tested against:

- Apache 2.4

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage
the Elastic Stack on your own hardware.

## Setup

### Prerequisites

The Apache receiver collects metrics from Apache's `mod_status` module. You must enable `mod_status` and make the `server-status` endpoint accessible.

1. Ensure `mod_status` is loaded in your Apache configuration:

```
LoadModule status_module modules/mod_status.so
```

2. Enable `ExtendedStatus` and configure access to the status endpoint:

```apache
ExtendedStatus On

<Location /server-status>
    SetHandler server-status
    Require local
    Require ip <COLLECTOR_IP>
</Location>
```

3. Verify the endpoint is accessible:

```bash
curl http://localhost/server-status?auto
```

### Configuration

Configure the OpenTelemetry Collector (EDOT Collector or upstream Collector) to scrape Apache metrics and export them to Elasticsearch.

- `<APACHE_STATUS_ENDPOINT>`: Full URL to the Apache server-status endpoint (for example, `http://localhost:80/server-status?auto`)
- `<ES_ENDPOINT>`: Elasticsearch endpoint (for example, `https://localhost:9200`)
- `${env:ES_USER}`: Elasticsearch username (set using an environment variable)
- `${env:ES_PASSWORD}`: Elasticsearch password (set using an environment variable)

```yaml
receivers:
  apache:
    endpoint: <APACHE_STATUS_ENDPOINT>
    collection_interval: 10s

processors:
  resourcedetection/system:
    detectors: ["system"]
    system:
      hostname_sources: ["os"]
      resource_attributes:
        host.name:
          enabled: true
        host.id:
          enabled: false

exporters:
  elasticsearch/otel:
    endpoint: <ES_ENDPOINT>
    user: ${env:ES_USER}
    password: ${env:ES_PASSWORD}
    mapping:
      mode: otel

service:
  pipelines:
    metrics:
      receivers: [apache]
      processors: [resourcedetection/system]
      exporters: [elasticsearch/otel]
```

## Reference

### Metrics

Refer to the [metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/apachereceiver/metadata.yaml)
of the OpenTelemetry Apache receiver for details on available metrics.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[Apache OTel] Overview** | Overview of Apache HTTP Server health and performance including request rate, traffic throughput, worker pool utilization, connection counts, server load, and CPU usage. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[Apache OTel] Worker pool exhaustion** | Busy workers exceed 80% of total workers for a server over a 5-minute window | High |
| **[Apache OTel] High server load** | 1-minute server load average exceeds 5.0 over a 5-minute window | High |
| **[Apache OTel] No requests received** | Zero new requests received by a server over a 5-minute window | Critical |

## SLO templates

> **Note**: SLO templates require Elastic Stack version 9.4.0 or later.

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[Apache OTel] Average request latency** | 99% | 30-day rolling | Ensures 99% of 1-minute timeslices show average per-request latency below 200 ms. |
