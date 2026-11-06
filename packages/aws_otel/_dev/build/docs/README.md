{{- generatedHeader }}
# AWS (OpenTelemetry)

## Overview

The AWS OpenTelemetry integration collects CloudWatch metrics for AWS services. Each service is its own data stream. Collection uses the [AWS CloudWatch receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awscloudwatchreceiver) from the `aws_cloudwatch_input_otel` input package, which supplies the receiver and the credentials extension.

This integration adds metric discovery and poll settings on each data stream. The input package flattens CloudWatch dimensions. Each data stream adds host resource detection. EC2 also adds only the EC2 detector, and ECS adds only the ECS detector.

Installing this integration also installs the AWS OpenTelemetry content packages for EC2, Lambda, RDS, SQS, load balancers, and ECS. Classic Load Balancer has no content package yet. Fleet installs all of them together, not only the data streams enabled on a policy.

## Deployment modes

- **Elastic Managed** (default): Elastic manages the collector. There is no agent infrastructure to run.
- **Elastic Agent**: Run the collector on your own Elastic Agent.

## Services

| Data stream | CloudWatch namespace | Period | Resource detector |
|---|---|---|---|
| EC2 | `AWS/EC2` | 5m | EC2 |
| Lambda | `AWS/Lambda` | 1m | none |
| RDS | `AWS/RDS` | 1m | none |
| SQS | `AWS/SQS` | 1m | none |
| Application Load Balancer | `AWS/ApplicationELB` | 1m | none |
| Classic Load Balancer | `AWS/ELB` | 1m | none |
| Network Load Balancer | `AWS/NetworkELB` | 1m | none |
| Gateway Load Balancer | `AWS/GatewayELB` | 1m | none |
| ECS | `AWS/ECS` | 1m | ECS |

Every data stream collects on a 5-minute interval, waits 5 minutes for late CloudWatch data, and caps discovery at 10,000 metrics. Statistics differ by service and are an advanced setting on that data stream.

## Requirements

| Requirement | Details |
|---|---|
| **AWS account** | Permission to read CloudWatch metrics (`cloudwatch:ListMetrics`, `cloudwatch:GetMetricData`) |
| **AWS region** | The region your resources run in |
| **Elastic Stack** | 9.5.0+ |
| **Input package** | `aws_cloudwatch_input_otel` (installed automatically as a dependency) |
| **Content packages** | `aws_ec2_otel`, `aws_lambda_otel`, `aws_rds_otel`, `aws_sqs_otel`, `aws_elb_metrics_otel`, `aws_ecs_otel` (installed automatically as dependencies) |

## Configuration

| Setting | Description |
|---|---|
| Period | CloudWatch aggregation window for that service. Advanced setting on each data stream. |
| AWS Region | AWS region to query, for example `us-east-1`. Defined on the CloudWatch input and shown on the main form. Required. |
| AWS Access Key ID | Access key from the CloudWatch input. Shown on the main form. |
| AWS Secret Access Key | Secret key from the CloudWatch input. Shown on the main form. |
| AWS Session Token | Session token from the CloudWatch input. Shown on the main form. Required for temporary credentials. |

## Authentication

- **Access keys**: Provide an access key ID and secret access key.
- **Temporary credentials**: Provide an access key ID, secret access key, and session token.
- **IAM role assumption**: Provide a Role ARN (and optionally an External ID) under the advanced settings to assume a role.

Use credentials scoped to read-only CloudWatch access wherever possible.
