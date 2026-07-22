# AWS Lambda Metrics OpenTelemetry Assets

This package contains Kibana assets for monitoring Lambda functions with AWS CloudWatch metrics collected by the OpenTelemetry Collector.

The package is **content only**. It provides a curated metrics dashboard, but it does not configure data collection. Use the **AWS CloudWatch OpenTelemetry Input Package** (`aws_cloudwatch_input_otel`) to configure the OpenTelemetry Collector CloudWatch receiver and collect the required AWS service metrics into Elasticsearch.

## Data requirements

- CloudWatch metrics collected by the OpenTelemetry Collector AWS CloudWatch receiver.
- Documents indexed into the `metrics-aws.lambda.otel-*` data stream.
- The relevant AWS dimensions for this service, such as resource name, region, and service-specific identifiers.

## Compatibility

Requires Kibana `^9.5.0`.

## Dashboards

This package includes one pre-built Kibana dashboard:

| Name | Description |
|---|---|
| [AWS Lambda OTel] Metrics | AWS Lambda dashboard for CloudWatch metrics collected by the OpenTelemetry Collector. |

## Alerting Rule Templates
Alert rule templates provide pre-defined configurations for creating alert rules in Kibana.

For more information, refer to the [Elastic documentation](https://www.elastic.co/docs/reference/fleet/alerting-rule-templates).

Alert rule templates require Elastic Stack version 9.2.0 or later.

**The following alert rule templates are available:**

<details>
<summary>View the alert rule templates</summary>

| Name | Description |
|---|---|
| [AWS Lambda OTel] Dead letter errors | Alerts when Lambda fails to write events to the configured dead-letter queue, meaning failed events may be lost. |
| [AWS Lambda OTel] Destination delivery failures | Alerts when Lambda fails to deliver events to configured on-success or on-failure destinations. |
| [AWS Lambda OTel] High async event age | Alerts when async-invoked Lambda functions show high AsyncEventAge, indicating events are aging in the internal queue. |
| [AWS Lambda OTel] High concurrent executions | Alerts when peak concurrent executions approach capacity limits, predicting imminent throttling. |
| [AWS Lambda OTel] High average duration | Alerts when average Lambda invocation duration exceeds a configurable threshold over a 15-minute window. |
| [AWS Lambda OTel] High tail duration | Alerts when peak (Maximum) Lambda invocation duration exceeds a configurable threshold, indicating slow handler execution or downstream latency. |
| [AWS Lambda OTel] High error rate | Alerts when a Lambda function exceeds a configurable error rate (Errors / Invocations) over a 15-minute window. Evaluates the top 10 functions by error rate. |
| [AWS Lambda OTel] High iterator age | Alerts when stream-based Lambda consumers show high IteratorAge, indicating the function is falling behind the record arrival rate. |
| [AWS Lambda OTel] High throttle rate | Alerts when a Lambda function exceeds a configurable throttle rate (Throttles / (Invocations + Throttles)) over a 15-minute window. |

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
| [AWS Lambda OTel] Average duration 99.5% rolling 30 days | Tracks per-function execution latency from CloudWatch Duration (Average statistic). Each 1-minute window is good when average duration stays below 3000 ms; 99.5% of windows must be good over a rolling 30-day period. Sustained duration regressions degrade user-facing response times and increase Lambda billing. |
| [AWS Lambda OTel] Invocation success rate 99.5% rolling 30 days | Tracks per-function invocation reliability from CloudWatch Errors and Invocations (Sum statistics). Each 1-minute window is good when the error rate is below 0.5%; 99.5% of windows must be good over a rolling 30-day period. Rising error rates indicate function code failures that directly break synchronous and asynchronous workloads. |

</details>


