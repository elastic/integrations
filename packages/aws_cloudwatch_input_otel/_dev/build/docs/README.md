{{- generatedHeader }}
# AWS CloudWatch (OpenTelemetry)

## Overview

The AWS CloudWatch OpenTelemetry Input collects Amazon CloudWatch metrics using the [AWS CloudWatch receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awscloudwatchreceiver) from the OpenTelemetry Collector.

This is a generic input package. It configures the `awscloudwatch` receiver, the `awscredentialsprovider` extension, and the dimension-flattening transform used by every service. It does not select a CloudWatch namespace. An integration data stream supplies metric discovery, poll settings, and any other processors.

## How it works

This input configures the AWS CloudWatch receiver in the EDOT (Elastic Distribution of OpenTelemetry) Collector, which:

1. Authenticates to AWS with the credentials you provide, through the `awscredentialsprovider` extension.
2. Queries CloudWatch in the AWS region you set.
3. Flattens each metric's CloudWatch `Dimensions` map into top-level attributes.
4. Forwards the metrics to Elastic Agent, which ships them to Elasticsearch for indexing and visualization.

## Deployment modes

This input can be deployed in two ways:

- **Elastic Managed** (default): Elastic manages the collector for you, with no infrastructure to run.
- **Elastic Agent**: Run the collector on your own Elastic Agent.

## Requirements

- An AWS account with the services you want to monitor.
- AWS credentials with permission to read CloudWatch metrics. At minimum, the credentials must allow:
  - `cloudwatch:ListMetrics`
  - `cloudwatch:GetMetricData`
- The AWS region your resources run in.

## Configuration

### Core settings

| Setting | Description |
|---|---|
| AWS Region | The AWS region to query CloudWatch metrics from (for example, `us-east-1`). |
| AWS Access Key ID | The access key used to authenticate to AWS. Mapped to `AWS_ACCESS_KEY_ID`. |
| AWS Secret Access Key | The secret key paired with the access key. Mapped to `AWS_SECRET_ACCESS_KEY`. |
| AWS Session Token | Required only when using temporary (STS) credentials. Mapped to `AWS_SESSION_TOKEN`. |

### Advanced settings

| Setting | Description |
|---|---|
| AWS Role ARN | Role to assume. Mapped to `AWS_ROLE_ARN`. |
| AWS External ID | External ID for the assumed role. Mapped to `AWS_ROLE_EXTERNAL_ID`. |

## Authentication

The input supports the following ways to authenticate to AWS:

- **Access keys**: Provide an access key ID and secret access key.
- **Temporary credentials**: Provide an access key ID, secret access key, and session token.
- **IAM role assumption**: Provide a Role ARN (and optionally an External ID) under the advanced settings to assume a role.

Use credentials scoped to read-only CloudWatch access wherever possible.

## Metrics reference

For the complete list of metrics available in each namespace, see the [Amazon CloudWatch metrics and dimensions reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CW_Support_For_AWS.html).

## Troubleshooting

### No metrics appear

1. Confirm the AWS Region matches where your resources are running.
2. Verify the credentials are valid and not expired (temporary credentials require a session token).
3. Ensure the credentials have `cloudwatch:ListMetrics` and `cloudwatch:GetMetricData` permissions.
4. Confirm the integration data stream sets a CloudWatch namespace. This input does not discover metrics on its own.
5. Allow time for the first collection cycle to complete. CloudWatch publishes metrics with a short delay.

### Authentication errors

1. Double-check the access key ID and secret access key.
2. If using temporary credentials, make sure the session token is set and current.
3. If assuming a role, verify the Role ARN and, if required, the External ID.

## Further reading

- [Amazon CloudWatch documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html)
- [AWS CloudWatch receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awscloudwatchreceiver)
- [OpenTelemetry Collector documentation](https://opentelemetry.io/docs/collector/)
