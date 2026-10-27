{{- generatedHeader }}
# AWS CloudWatch (OpenTelemetry)

## Overview

The AWS CloudWatch OpenTelemetry Input collects Amazon CloudWatch metrics for selected AWS services using the [AWS CloudWatch receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awscloudwatchreceiver) from the OpenTelemetry Collector.

Instead of listing individual metrics, the integration automatically discovers the metrics published in each service's CloudWatch namespace, so newly available metrics are picked up without any configuration changes. This makes it a low-maintenance way to bring AWS infrastructure metrics into Elastic for dashboards, alerting, and analysis.

## How it works

This integration configures the AWS CloudWatch receiver in the EDOT (Elastic Distribution of OpenTelemetry) Collector, which:

1. Authenticates to AWS using the credentials you provide.
2. Discovers the metrics available in the selected service's CloudWatch namespace.
3. Polls CloudWatch on a regular interval and retrieves the configured statistics (such as Average, Sum, and Maximum) for each metric.
4. Forwards the metrics to Elastic Agent, which ships them to Elasticsearch for indexing and visualization.

You add the integration once for each AWS service you want to monitor.

## Deployment modes

This integration can be deployed in two ways:

- **Elastic Managed** (default): Elastic manages the collector for you, with no infrastructure to run. This is the recommended option for most users. Elastic Managed deployments can authenticate with [Identity Federation](#authentication), so no AWS credentials are stored in Elastic.
- **Elastic Agent**: Run the collector on your own Elastic Agent.

## Supported services

Each AWS service is available as a separate option when you add the integration.

| Service | CloudWatch namespace |
|---|---|
| AWS EC2 | `AWS/EC2` |
| AWS Lambda | `AWS/Lambda` |
| AWS RDS | `AWS/RDS` |
| AWS SQS | `AWS/SQS` |
| AWS Application ELB | `AWS/ApplicationELB` |
| AWS Classic ELB | `AWS/ELB` |
| AWS Network ELB | `AWS/NetworkELB` |
| AWS Gateway ELB | `AWS/GatewayELB` |
| AWS ECS / Fargate | `AWS/ECS` |

Each service collects a set of statistics chosen to suit that service's metrics (for example, averages for utilization metrics and sums for counters). These defaults work well out of the box and require no configuration.

## Requirements

- An AWS account with the services you want to monitor.
- An AWS identity with permission to read CloudWatch metrics. At minimum, it must allow:
  - `cloudwatch:ListMetrics`
  - `cloudwatch:GetMetricData`

  With Identity Federation, the CloudFormation template grants these permissions to the IAM role it creates.
- The AWS region your resources run in.

## Configuration

### Core settings

| Setting | Description |
|---|---|
| AWS Region | The AWS region to collect metrics from (for example, `us-east-1`). |
| Setup Access | How the collector authenticates to AWS: Identity Federation (Elastic Managed only), direct or temporary access keys, or an assumed role. See [Authentication](#authentication). |
| AWS Access Key ID | The access key used to authenticate to AWS. |
| AWS Secret Access Key | The secret key paired with the access key. |
| AWS Session Token | Required only when using temporary (STS) credentials. |
| AWS Role ARN | The IAM role to assume. With Identity Federation, Kibana fills it in from the CloudFormation stack output. |

### Collection settings

Each service template exposes two settings that control how metrics are polled from CloudWatch:

| Setting | Description |
|---|---|
| **Collection Interval** | How often the integration polls CloudWatch (one `GetMetricData` cycle). Shorter intervals give fresher data but increase the number of API calls. |
| **Period** | The CloudWatch aggregation window for each data point. It must match the resolution at which the AWS service publishes the metric, otherwise you may see gaps or repeated values. |

Guidance:

- Set **Period** to the metric's native publishing resolution — typically **5 minutes** for services on 5-minute resolution (for example, EC2 basic monitoring) and **1 minute** for services that publish at 1-minute resolution (for example, RDS and Application ELB).
- Set **Collection Interval** to **Period**, or to a multiple of it. Each poll returns every data point in the elapsed window, so polling less often reduces cost proportionally without losing data — it only delays how soon the data arrives. Polling more often than Period re-reads the same data point and multiplies cost for no benefit.
- The defaults below are pre-tuned per service, so you typically don't need to change them.

| Service             | Collection Interval | Period |
|---------------------|---------------------|--------|
| AWS EC2             | 5m                  | 5m     |
| AWS Lambda          | 5m                  | 1m     |
| AWS RDS             | 5m                  | 1m     |
| AWS SQS             | 5m                  | 1m     |
| AWS Application ELB | 5m                  | 1m     |
| AWS Classic ELB     | 5m                  | 1m     |
| AWS Network ELB     | 5m                  | 1m     |
| AWS Gateway ELB     | 5m                  | 1m     |
| AWS ECS             | 5m                  | 1m     |

### Autodiscover Limit and impact on cost

This integration automatically discovers and collects CloudWatch metrics published for the configured namespaces. The CloudWatch API bills per metric requested, so the more resources that exist in your account, the more metrics are discovered and the higher the collection cost.

To avoid unexpectedly large bills, the number of metrics collected is capped by the **Autodiscover Limit**, which defaults to 10,000, high enough to capture all metrics in a typical deployment. The limit applies to each namespace separately. It is a ceiling, not a fixed value - you are billed only for the metrics that actually exist, so smaller accounts cost proportionally less. With the 10,000 limit, the maximum cost per namespace is ~$2,600 per month at the default 5-minute collection interval.

If you need to reduce cost, you can lower the **Autodiscover Limit** in the integration's advanced settings. Reducing the limit below the number of metrics in your account means some metrics will not be collected, and which ones are dropped is not predictable. We recommend changing this value only if you understand the metric volume in your AWS account, and lowering it gradually while verifying that the metrics you rely on are still present.

## Authentication

Select how the collector authenticates to AWS under **Setup Access** when you add the integration:

- **Identity Federation** (Elastic Managed only): No AWS credentials are stored in Elastic. Kibana opens a pre-filled CloudFormation template that creates an IAM role in your AWS account. The role trusts the workload identity issuer of your Elastic Cloud organization and can only be assumed by the deployment or project it was created for, and it is granted the CloudWatch read permissions listed under [Requirements](#requirements). Paste the Role ARN from the stack outputs into the integration; the Elastic Managed collector then obtains short-lived credentials for the role on every collection cycle.
- **Direct Access Keys**: Provide an access key ID and secret access key.
- **Temporary Access Keys**: Provide an access key ID, secret access key, and session token.
- **Assume Role**: Provide a Role ARN (and optionally an External ID under the advanced settings) that the collector assumes with the credentials available on its host.

Use an identity scoped to read-only CloudWatch access wherever possible.

## Metrics reference

For the complete list of metrics available in each namespace, see the [Amazon CloudWatch metrics and dimensions reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CW_Support_For_AWS.html).

## Troubleshooting

### No metrics appear

1. Confirm the AWS Region matches where your resources are running.
2. Verify the credentials are valid and not expired (temporary credentials require a session token).
3. Ensure the credentials have `cloudwatch:ListMetrics` and `cloudwatch:GetMetricData` permissions.
4. Allow time for the first collection cycle to complete, and remember that CloudWatch publishes metrics with a short delay.

### Authentication errors

1. Double-check the access key ID and secret access key.
2. If using temporary credentials, make sure the session token is set and current.
3. If assuming a role, verify the Role ARN and, if required, the External ID.
4. If using Identity Federation, confirm the CloudFormation stack was created from the link in this deployment or project. A role created for another deployment or project cannot be assumed, because its trust policy is bound to the Elastic resource that created it.

## Further reading

- [Amazon CloudWatch documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html)
- [AWS CloudWatch receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/awscloudwatchreceiver)
- [OpenTelemetry Collector documentation](https://opentelemetry.io/docs/collector/)
