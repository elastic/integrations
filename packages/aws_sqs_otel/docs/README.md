# AWS SQS Metrics OpenTelemetry Assets

This package contains Kibana assets for monitoring SQS queues with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Use the **AWS CloudWatch OpenTelemetry Input Package** (`aws_cloudwatch_input_otel`) to configure the OpenTelemetry Collector CloudWatch receiver and collect the required AWS service metrics into Elasticsearch.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.sqs.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.5.0`.

## Dashboards

This package includes one pre-built Kibana dashboard:

| Name | Description |
|---|---|
| [AWS SQS OTel] Metrics | AWS SQS dashboard for CloudWatch metrics collected by the OpenTelemetry Collector. |

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [AWS SQS OTel] DLQ has messages | Alerts when any dead-letter queue has one or more visible messages. Any message in a DLQ represents a processing failure and warrants immediate investigation. |
| [AWS SQS OTel] High backlog | Alerts when a queue's visible message backlog stays above the configured depth across the evaluation window, indicating consumers are not keeping up with producers. Pair with the oldest-message-age alert/SLO, which captures processing lag directly. |
| [AWS SQS OTel] In-flight saturation | Alerts when in-flight messages approach the standard-queue limit (~120,000), indicating stuck consumers or processing bottlenecks. |
| [AWS SQS OTel] Oldest message age high | Alerts when the oldest unprocessed message on a queue exceeds a configurable age threshold. This is the headline SQS processing-lag signal. |
| [AWS SQS OTel] Producer send rate drop | Alerts when a queue's message send rate drops below the configured minimum, indicating producer slowdown or failure. Requires threshold tuning to match your expected baseline send rate. |

</details>



## SLO Templates
SLO templates provide pre-defined configurations for creating SLOs in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/solutions/observability/incident-management/service-level-objectives-slos).

SLO templates require Elastic Stack version 9.4.0 or later.

**The following SLO templates are available:**

<details>
<summary>View the SLO templates</summary>

| Name | Description |
|---|---|
| [AWS SQS OTel] DLQ empty 99.5% rolling 30 days | Tracks dead-letter queue correctness: 99.5% of 1-minute intervals must show zero visible messages on DLQ queues (QueueName matching \*dlq\*). Any message in a DLQ represents a processing failure and dropped work — the primary SQS error signal. Adjust the QueueName pattern if your DLQ naming convention differs. |
| [AWS SQS OTel] Oldest message age 99.5% rolling 30 days | Tracks processing freshness per queue: 99.5% of 1-minute intervals must show maximum oldest-message age below 300 seconds on non-DLQ queues. ApproximateAgeOfOldestMessage is the headline SQS timeliness signal — sustained elevation means consumers are falling behind. Threshold is workload-dependent and should be tuned per queue SLA. |

</details>


