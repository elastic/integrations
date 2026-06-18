# AWS ECS OpenTelemetry Assets

This package contains Kibana assets for monitoring ECS services with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Configure the OpenTelemetry Collector CloudWatch receiver to collect the required AWS service metrics and export them to Elasticsearch.

## What's included

| Dashboard | What it covers |
|-----------|----------------|
| **AWS ECS** | Monitors service health, CPU and memory utilization, Service Connect connection metrics, processed bytes, and running service state. |

The dashboard reads metric-stream style OpenTelemetry documents from `metrics-aws.ecs.otel-*` and isolates CloudWatch statistics with `stat` before aggregating values.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.ecs.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.5.0`.

## Alerting Rule Template
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [AWS ECS OTel] CPU utilization high | Alerts when average CPU utilization of reserved task CPU exceeds a threshold. Sustained high CPU throttles workloads and raises application latency. |
| [AWS ECS OTel] Memory utilization high | Alerts when average memory utilization of reserved task memory exceeds a threshold. Sustained high memory risks OOM kills and task churn. |

</details>


