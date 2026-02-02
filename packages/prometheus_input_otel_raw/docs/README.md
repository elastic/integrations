# Prometheus OpenTelemetry Raw Input

## Overview

This package allows you to scrape Prometheus-compatible metrics endpoints using the OpenTelemetry Collector's [Prometheus receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver) by pasting your existing Prometheus scrape configuration directly.

### How it works

This package configures the Prometheus receiver in the EDOT collector to scrape metrics from Prometheus-compatible endpoints. Simply paste your existing Prometheus `scrape_configs` YAML and the package will use it as-is. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

**Looking for guided configuration?** If you prefer configuring individual settings through the Fleet UI, consider using the [Prometheus OpenTelemetry Input](https://github.com/elastic/integrations/tree/main/packages/prometheus_input_otel) package instead.

## Configuration

Paste your existing Prometheus `scrape_configs` YAML directly from your `prometheus.yml` file:

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

- Quickly migrate existing Prometheus scrape configurations
- Use advanced Prometheus scraping features not exposed in the guided package
- Monitor applications exposing Prometheus metrics
- Scrape Node Exporter, cAdvisor, or other Prometheus exporters

## Compatibility

This package requires:

- Kibana 9.2.0 or later
- Elastic Agent with OpenTelemetry Collector support
