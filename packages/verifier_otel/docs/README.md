# Permission Verifier Integration

## Overview

The Permission Verifier integration uses the OpenTelemetry Collector's Verifier receiver to verify cloud connector based integration permissions and report results to Elasticsearch.

This integration is designed for Cloud Connectors to proactively check that all necessary permissions are available for attached integrations.

## Supported Providers

| Provider | Status | Description |
|----------|--------|-------------|
| AWS | Active | CloudTrail, GuardDuty, Security Hub, S3, EC2, VPC Flow Logs, WAF, Route53, ELB, CloudFront |
| Azure | Planned | Activity Logs, Audit Logs, Blob Storage |
| GCP | Planned | Audit Logs, Cloud Storage, Pub/Sub |
| Okta | Planned | System Logs, User Events |

## Configuration

### Cloud Connector Identification

| Field | Required | Description |
|-------|----------|-------------|
| Cloud Connector ID | Yes | Unique identifier for the Cloud Connector being verified |
| Cloud Connector Name | No | Human-readable name of the Cloud Connector |
| Verification ID | Yes | Unique identifier for this verification session |
| Verification Type | No | Type of verification: `on_demand` (default) or `scheduled` |

### AWS Provider Authentication

| Field | Required | Description |
|-------|----------|-------------|
| `providers.aws.credentials.role_arn` | Yes (for AWS) | ARN of the IAM role to assume in the customer's AWS account |
| `providers.aws.credentials.external_id` | Yes (for AWS) | External ID to prevent confused deputy attacks |
| `providers.aws.credentials.default_region` | No | Default AWS region for API calls (default: `us-east-1`) |

### Policy Configuration

| Field | Required | Description |
|-------|----------|-------------|
| Policy ID | Yes | The agent policy ID for this set of integrations |
| Policy Name | No | Human-readable name of the policy |

### Integration Configuration

| Field | Required | Description |
|-------|----------|-------------|
| Integration Type | Yes | Package type (for example, `aws_cloudtrail`, `azure_activitylogs`, `gcp_audit`, `okta_system`) |
| Integration ID | No | Unique identifier for the integration instance |
| Integration Name | No | Human-readable name of the integration |
| Integration Version | No | Semantic version of the integration package (for example, `2.17.0`). Different versions can require different permissions. When empty, the latest permission set is used. |

## Supported Integration Types

### AWS Integrations

| Integration Type | Permissions Verified |
|-----------------|---------------------|
| `aws_cloudtrail` | cloudtrail:LookupEvents, DescribeTrails, s3:GetObject, ListBucket, sqs:ReceiveMessage |
| `aws_guardduty` | guardduty:ListDetectors, GetFindings, ListFindings |
| `aws_securityhub` | securityhub:GetFindings, DescribeHub |
| `aws_s3` | s3:ListBucket, GetObject, GetBucketLocation |
| `aws_ec2` | ec2:DescribeInstances, DescribeRegions, cloudwatch:GetMetricData |
| `aws_vpcflow` | logs:FilterLogEvents, DescribeLogGroups, ec2:DescribeFlowLogs |
| `aws_waf` | wafv2:GetWebACL, ListWebACLs, s3:GetObject |
| `aws_route53` | logs:FilterLogEvents, DescribeLogGroups, route53:ListHostedZones |
| `aws_elb` | s3:GetObject, ListBucket, elasticloadbalancing:DescribeLoadBalancers |
| `aws_cloudfront` | s3:GetObject, ListBucket, cloudfront:ListDistributions |

### Azure Integrations (Planned)

| Integration Type | Permissions Verified |
|-----------------|---------------------|
| `azure_activitylogs` | Microsoft.Insights/eventtypes/values/Read |
| `azure_auditlogs` | Microsoft.Insights/eventtypes/values/Read |
| `azure_blob_storage` | Microsoft.Storage/storageAccounts/blobServices/containers/read |

### GCP Integrations (Planned)

| Integration Type | Permissions Verified |
|-----------------|---------------------|
| `gcp_audit` | logging.logEntries.list |
| `gcp_storage` | storage.objects.get, storage.objects.list |
| `gcp_pubsub` | pubsub.subscriptions.consume |

### Okta Integrations (Planned)

| Integration Type | Permissions Verified |
|-----------------|---------------------|
| `okta_system` | okta.logs.read |
| `okta_users` | okta.users.read |

## Output

The integration emits OTEL logs with the following structure:

### Resource Attributes

| Attribute | Description |
|-----------|-------------|
| `cloud_connector.id` | Cloud Connector identifier |
| `cloud_connector.name` | Cloud Connector name |
| `verification.id` | Verification session ID |
| `verification.timestamp` | When verification started |
| `verification.type` | `on_demand` or `scheduled` |
| `service.name` | Always `permission-verifier` |

### Log Record Attributes

| Attribute | Description |
|-----------|-------------|
| `policy.id` | Policy identifier |
| `policy.name` | Policy name |
| `integration.id` | Integration instance identifier |
| `integration.name` | Integration name |
| `integration.type` | Integration type (for example, `aws_cloudtrail`) |
| `integration.version` | Integration package version (for example, `2.17.0`) or `unspecified` |
| `provider.type` | Provider type (`aws`, `azure`, `gcp`, `okta`) |
| `provider.account` | Provider account identifier |
| `provider.region` | Provider region |
| `permission.action` | Permission being checked (for example, `cloudtrail:LookupEvents`) |
| `permission.category` | Permission category (for example, `data_access`) |
| `permission.status` | Result: `granted`, `denied`, `error`, or `skipped` |
| `permission.required` | Whether this permission is required |
| `permission.error_code` | Error code from provider (if denied/error) |
| `permission.error_message` | Error message from provider (if denied/error) |
| `verification.method` | Method used: `api_call` or `dry_run` |
| `verification.endpoint` | The API endpoint used for verification |
| `verification.duration_ms` | Time taken for verification in milliseconds |

## Example Configuration

```yaml
cloud_connector_id: "cc-12345"
cloud_connector_name: "Production Connector"
verification_id: "verify-abc123"
verification_type: "on_demand"

# AWS Provider Authentication
providers.aws.credentials.role_arn: "arn:aws:iam::123456789012:role/ElasticAgentRole"
providers.aws.credentials.external_id: "elastic-external-id-from-setup"
providers.aws.credentials.default_region: "us-east-1"

# Policy
policy_id: "policy-aws-security"
policy_name: "AWS Security Monitoring"

# Integration
integration_type: "aws_cloudtrail"
integration_name: "AWS CloudTrail"
integration_version: "2.17.0"
```

## Related

- [Verifier Receiver Documentation](https://github.com/elastic/opentelemetry-collector-components/tree/main/receiver/verifierreceiver)
