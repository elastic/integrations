# AWS ELB Metrics OpenTelemetry Assets

This package contains Kibana assets for monitoring ELB load balancers with CloudWatch metrics with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Configure the OpenTelemetry Collector CloudWatch receiver to collect the required AWS service metrics and export them to Elasticsearch.

## What's included

| Dashboard | What it covers |
|-----------|----------------|
| **AWS ELB** | Monitors load-balancer health, request volume, processed bytes, backend 5xx errors, latency, healthy hosts, active connections, and rejected connections. |

The dashboard reads metric-stream style OpenTelemetry documents from `metrics-awscloudwatchreceiver.otel-default` and isolates CloudWatch statistics with `stat` before aggregating values.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-awscloudwatchreceiver.otel-default` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.4.0`.
