# Prometheus OpenTelemetry Input Package

## Overview

This package allows you to scrape Prometheus-compatible metrics endpoints using the OpenTelemetry Collector's [Prometheus receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver).

### How it works

This package configures the Prometheus receiver in the EDOT collector to scrape metrics from Prometheus-compatible endpoints. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

## Configuration Modes

This package offers two configuration modes to accommodate different user preferences:

### Guided Mode (Prometheus Metrics - Guided)

Use this mode if you want a simplified setup experience. Configure individual fields like targets, scrape interval, and TLS settings through the Fleet UI. This mode is recommended for new setups.

### Raw Config Mode (Prometheus Metrics - Raw Config)

Use this mode if you have an existing Prometheus `scrape_configs` YAML that you want to use directly. Simply paste your existing Prometheus scrape configuration and the package will use it as-is.

**Example - paste your existing scrape config:**

```yaml
- job_name: 'my-app'
  scrape_interval: 15s
  scrape_timeout: 10s
  metrics_path: /metrics
  scheme: http
  static_configs:
    - targets:
        - 'localhost:9090'
        - 'localhost:9100'
  honor_labels: true
  honor_timestamps: true
```

This becomes the literal receiver config:

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: 'my-app'
          scrape_interval: 15s
          scrape_timeout: 10s
          metrics_path: /metrics
          scheme: http
          static_configs:
            - targets:
                - 'localhost:9090'
                - 'localhost:9100'
          honor_labels: true
          honor_timestamps: true
```

## Configuration Reference

For detailed configuration options and their descriptions, refer to the [Prometheus Receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/prometheusreceiver/README.md) in the upstream OpenTelemetry Collector repository.

## Use Cases

- Monitor applications exposing Prometheus metrics
- Scrape Node Exporter, cAdvisor, or other Prometheus exporters
- Collect custom application metrics in Prometheus format
- Migrate from Prometheus to Elastic Observability

## Compatibility

This package requires:

- Kibana 9.2.0 or later
- Elastic Agent with OpenTelemetry Collector support
