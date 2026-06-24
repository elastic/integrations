# AWS CloudWatch OpenTelemetry Input Package

## Overview
The AWS CloudWatch OpenTelemetry Input Package for Elastic enables collection of CloudWatch metrics for selected AWS services through OpenTelemetry protocols using the [awscloudwatchmetricsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awscloudwatchmetricsreceiver#aws-cloudwatch-metrics-receiver).

### How it works
This package configures the AWS region, credentials, and a CloudWatch namespace once per supported AWS service (EC2, RDS, SQS, ELB, Lambda, Fargate). The configuration is applied to the `awscloudwatchmetrics` receiver in the EDOT collector, which polls CloudWatch via the AWS API and forwards metrics to the Elastic Agent. The Elastic Agent enriches the data and ships it to Elasticsearch for indexing and analysis. The receiver runs in autodiscover mode so newly published metrics from AWS are picked up automatically without package changes.

## Supported services
Each service is exposed as a separate policy template. Add the integration once per service you want to monitor.

| Policy template | CloudWatch namespace |
|---|---|
| AWS EC2 | `AWS/EC2` |
| AWS Lambda | `AWS/Lambda` |
| AWS RDS | `AWS/RDS` |
| AWS SQS | `AWS/SQS` |
| AWS Application ELB | `AWS/ApplicationELB` |
| AWS ECS / Fargate | `AWS/ECS` |

## Metrics reference
For a complete list of available metrics in each namespace, refer to the [Amazon CloudWatch metrics and dimensions reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CW_Support_For_AWS.html). For receiver configuration options, refer to the [`awscloudwatchmetricsreceiver` documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/awscloudwatchmetricsreceiver/README.md) in the upstream OpenTelemetry Collector repository.
