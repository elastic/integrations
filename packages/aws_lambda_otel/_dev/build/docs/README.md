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
{{alertRuleTemplates}}

## SLO Templates
{{sloTemplates}}
