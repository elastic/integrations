# Prometheus OpenTelemetry Input Package

This package allows you to scrape Prometheus-compatible metrics endpoints using the OpenTelemetry Collector's [Prometheus receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver).

## Overview

The Prometheus receiver is built to be a drop-in replacement for Prometheus, fully supporting the Prometheus exposition format. It can scrape metrics from any endpoint that exposes metrics in the Prometheus format.

## Configuration

### Scrape Targets

Specify one or more targets to scrape. Each target should be in the format `host:port`. The metrics path is configured separately using the `metrics_path` option (default: `/metrics`). For example:

- `localhost:9090` - Prometheus server
- `localhost:9100` - Node Exporter
- `localhost:8080` - Spring Boot application (with metrics_path set to `/actuator/prometheus`) 

### Scrape Interval

How frequently to scrape targets. Default is `60s`. Common values:

- `15s` - High frequency monitoring
- `30s` - Standard monitoring
- `60s` - Low overhead monitoring

### Scheme

The protocol to use when scraping. Options:

- `http` (default) - Use HTTP
- `https` - Use HTTPS for secure endpoints

### TLS Configuration

When using HTTPS endpoints, you can configure TLS settings:

| Option | Description |
|--------|-------------|
| **Enable TLS Configuration** | Must be enabled to use any TLS options |
| **Skip TLS Verification** | Disable certificate verification (useful for self-signed certificates) |
| **CA Certificate Path** | Path to a custom CA certificate file for verifying the server |
| **Client Certificate Path** | Path to client certificate for mutual TLS (mTLS) authentication |
| **Client Key Path** | Path to client private key for mTLS authentication |

> **Note:** For mutual TLS authentication, both the client certificate and client key must be provided together.

#### Example: Self-signed certificate

1. Set **Scheme** to `https`
2. Enable **TLS Configuration**
3. Enable **Skip TLS Verification**

#### Example: Custom CA

1. Set **Scheme** to `https`
2. Enable **TLS Configuration**
3. Set **CA Certificate Path** to `/path/to/ca.crt`

### Basic Authentication

For endpoints that require HTTP basic authentication, provide the username and password:

| Option | Description |
|--------|-------------|
| **Username** | Username for basic authentication |
| **Password** | Password for basic authentication (stored securely) |

> **Note:** Both username and password must be provided together for basic authentication to work.

## Use Cases

- Monitor applications exposing Prometheus metrics
- Scrape Node Exporter, cAdvisor, or other Prometheus exporters
- Collect custom application metrics in Prometheus format
- Migrate from Prometheus to Elastic Observability

## Compatibility

This package requires:

- Kibana 9.2.0 or later
- Elastic Agent with OpenTelemetry Collector support

## Metrics

The metrics collected depend on the target being scraped. Common metrics include:

- `process_*` - Process-level metrics
- `go_*` - Go runtime metrics (for Go applications)
- Custom application metrics

All metrics are stored in the `metrics-*` data stream with the namespace configured in Fleet.
