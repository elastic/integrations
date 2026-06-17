# AWS EC2 OpenTelemetry Assets

This package contains Kibana assets for monitoring EC2 instances with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Configure the OpenTelemetry Collector CloudWatch receiver to collect the required AWS service metrics and export them to Elasticsearch.

## What's included

| Dashboard | What it covers |
|-----------|----------------|
| **AWS EC2** | Monitors instance health, status checks, CPU utilization, network throughput, disk read/write activity, and EBS write activity. |

The dashboard reads metric-stream style OpenTelemetry documents from `metrics-aws.ec2.otel-*` and isolates CloudWatch statistics with `stat` before aggregating values.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.ec2.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.4.0`.
