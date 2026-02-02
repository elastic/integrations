# Prometheus OpenTelemetry Input

## Overview

This package allows you to scrape Prometheus-compatible metrics endpoints using the OpenTelemetry Collector's [Prometheus receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver).

### How it works

This package configures the Prometheus receiver in the EDOT collector to scrape metrics from Prometheus-compatible endpoints. The Elastic Agent processes and enriches the data before sending it to Elasticsearch for indexing and analysis.

## Configuration

Configure individual fields like targets, scrape interval, and TLS settings through the Fleet UI.

**Looking for raw config mode?** If you have an existing Prometheus `scrape_configs` YAML that you want to use directly, consider using the [Prometheus OpenTelemetry Raw Input](https://github.com/elastic/integrations/tree/main/packages/prometheus_input_otel_raw) package instead.

### Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Scrape Targets | List of targets in `host:port` format | `localhost:9090` |
| Scrape Interval | How frequently to scrape targets | `60s` |
| Scrape Timeout | Timeout for scraping | `10s` |
| Metrics Path | HTTP path to fetch metrics | `/metrics` |
| Scheme | Protocol scheme (HTTP/HTTPS) | `http` |
| Honor Labels | Honor labels from scraped metrics | `false` |
| Honor Timestamps | Honor timestamps from scraped metrics | `true` |

### TLS Configuration

For HTTPS endpoints, you can configure:
- Skip TLS verification for self-signed certificates
- CA certificate path for custom certificate authorities
- Client certificate and key for mutual TLS authentication

### Basic Authentication

Username and password can be configured for endpoints requiring basic authentication.

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
