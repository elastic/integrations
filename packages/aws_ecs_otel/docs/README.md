# AWS ECS Metrics OpenTelemetry Assets

This package contains Kibana assets for monitoring ECS services with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Use the **AWS CloudWatch OpenTelemetry Input Package** (`aws_cloudwatch_input_otel`) to configure the OpenTelemetry Collector CloudWatch receiver and collect the required AWS service metrics into Elasticsearch.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.ecs.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.5.0`.

## Dashboards

This package includes one pre-built Kibana dashboard:

| Name | Description |
|---|---|
| [AWS ECS OTel] Metrics | AWS ECS dashboard for CloudWatch metrics collected by the OpenTelemetry Collector. |

## Alerting Rule Templates
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


