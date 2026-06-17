# AWS RDS OpenTelemetry Assets

This package contains Kibana assets for monitoring RDS database instances with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Configure the OpenTelemetry Collector CloudWatch receiver to collect the required AWS service metrics and export them to Elasticsearch.

## What's included

| Dashboard | What it covers |
|-----------|----------------|
| **AWS RDS** | Monitors database health, CPU utilization, free storage, memory, connections, IOPS, latency, and network throughput. |

The dashboard reads metric-stream style OpenTelemetry documents from `metrics-aws.rds.otel-*` and isolates CloudWatch statistics with `stat` before aggregating values.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.rds.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.4.0`.
