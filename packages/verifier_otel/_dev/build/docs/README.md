# Permission Verifier Integration

## Overview

The Permission Verifier integration uses the OpenTelemetry Collector's Verifier receiver to verify cloud connector based integration permissions and report results to Elasticsearch.

This integration is designed for Cloud Connectors to proactively check that all necessary permissions are available for attached integrations.

## Supported Providers

| Provider | Status | Description |
|----------|--------|-------------|
| AWS | Active | CloudTrail, GuardDuty, Security Hub, S3, EC2, VPC Flow Logs, WAF, Route53, ELB, CloudFront, CSPM, Asset Inventory |
| Azure | Active | Activity Logs, Audit Logs, Blob Storage, CSPM, Asset Inventory |
| GCP | Active | Audit Logs, Cloud Storage, Pub/Sub, CSPM, Asset Inventory |
| Okta | Planned | System Logs, User Events |

## Configuration

### Cloud Connector Identification

| Field | Required | Description |
|-------|----------|-------------|
| Cloud Connector ID | Yes | Unique identifier for the Cloud Connector being verified |
| Cloud Connector Name | No | Human-readable name of the Cloud Connector |
| Verification ID | Yes | Unique identifier for this verification session |
| Verification Type | No | Type of verification: `on_demand` (default) or `scheduled` |

### Provider and Account Configuration

| Field | Required | Description |
|-------|----------|-------------|
| `provider` | Yes | Cloud provider type (`aws`, `azure`, `gcp`, `okta`) |
| `account_type` | No | Whether the target is a `single_account` (default) or `organization` (management account). Affects which permissions are verified since assuming a role behaves differently for single accounts vs organization management accounts. |

### Credentials

Credential fields use a flat, normalized naming convention to stay consistent with Fleet and avoid translation layers across packages. Only set the fields relevant to your `provider`.

#### AWS Credentials

| Field | Required | Description |
|-------|----------|-------------|
| `credentials_role_arn` | Yes | ARN of the IAM role to assume in the customer's AWS account |
| `credentials_external_id` | Yes | External ID to prevent confused deputy attacks |
| `default_region` | No | Default AWS region for API calls (default: `us-east-1`) |

#### Azure Credentials

| Field | Required | Description |
|-------|----------|-------------|
| `credentials_tenant_id` | Yes | Azure AD tenant ID |
| `credentials_client_id` | Yes | Azure application (client) ID |

#### GCP Credentials

| Field | Required | Description |
|-------|----------|-------------|
| `credentials_project_id` | Yes | GCP project ID to scope verification to |
| `credentials_workload_identity_provider` | No | Full Workload Identity Federation resource name |
| `credentials_service_account_email` | No | GCP service account email for impersonation |

### Policy Configuration

| Field | Required | Description |
|-------|----------|-------------|
| Policy ID | Yes | The agent policy ID for this set of integrations |
| Policy Name | No | Human-readable name of the policy |

### Integration Configuration (Package Metadata)

Integration identification uses `policy_template` + `package_name` as the composite unique key, aligning with Fleet's package policy API vocabulary. This keeps the Agentless API request self-describing with no lookups needed.

| Field | Required | Description |
|-------|----------|-------------|
| `policy_template` | Yes | Policy template name from the integration package (for example, `cloudtrail`, `guardduty`, `activitylogs`). Not globally unique on its own; must be combined with `package_name`. |
| `package_name` | Yes | Integration package name (for example, `aws`, `azure`, `gcp`, `okta`) |
| `package_title` | No | Human-readable title of the integration package (for example, `AWS`, `Azure`) |
| `package_version` | No | Semantic version of the integration package (for example, `2.17.0`). Different versions can require different permissions. When empty, the latest permission set is used. |
| `package_policy_id` | No | Unique identifier for the package policy instance |
| `namespace` | No | Namespace for the integration (default: `default`) |

## Supported Policy Templates

Each `policy_template` is scoped per integration following the least-privilege principle. Only the permissions required by that specific policy template are verified, rather than checking global permissions shared across the entire integration package. This ensures that each Cloud Connector only needs the exact IAM permissions its attached integrations require.

### AWS Integrations (`package_name: aws`)

| Policy Template | Permissions Verified |
|-----------------|---------------------|
| `cloudtrail` | cloudtrail:LookupEvents, DescribeTrails, s3:GetObject, ListBucket, sqs:ReceiveMessage |
| `guardduty` | guardduty:ListDetectors, GetFindings, ListFindings |
| `securityhub` | securityhub:GetFindings, DescribeHub |
| `s3` | s3:ListBucket, GetObject, GetBucketLocation |
| `ec2` | ec2:DescribeInstances, DescribeRegions, cloudwatch:GetMetricData |
| `vpcflow` | logs:FilterLogEvents, DescribeLogGroups, ec2:DescribeFlowLogs |
| `waf` | wafv2:GetWebACL, ListWebACLs, s3:GetObject |
| `route53` | logs:FilterLogEvents, DescribeLogGroups, route53:ListHostedZones |
| `elb` | s3:GetObject, ListBucket, elasticloadbalancing:DescribeLoadBalancers |
| `cloudfront` | s3:GetObject, ListBucket, cloudfront:ListDistributions |
| `cspm` | SecurityAudit managed policy attachment (policy_attachment_check) |
| `asset_inventory` | SecurityAudit managed policy attachment (policy_attachment_check) |

### Azure Integrations (`package_name: azure`)

| Policy Template | Permissions Verified |
|-----------------|---------------------|
| `activitylogs` | Microsoft.Insights/eventtypes/values/Read |
| `auditlogs` | Microsoft.Insights/eventtypes/values/Read |
| `blob_storage` | Microsoft.Storage/storageAccounts/blobServices/containers/read |
| `cspm` | Reader built-in role assignment (policy_attachment_check) |
| `asset_inventory` | Reader built-in role assignment (policy_attachment_check) |

### GCP Integrations (`package_name: gcp`)

| Policy Template | Permissions Verified |
|-----------------|---------------------|
| `audit` | logging.logEntries.list |
| `storage` | storage.objects.get, storage.objects.list |
| `pubsub` | pubsub.subscriptions.consume |
| `cspm` | roles/cloudasset.viewer, roles/browser IAM bindings (policy_attachment_check) |
| `asset_inventory` | roles/cloudasset.viewer, roles/browser IAM bindings (policy_attachment_check) |

### Okta Integrations (`package_name: okta`) — Planned

| Policy Template | Permissions Verified |
|-----------------|---------------------|
| `system` | okta.logs.read |
| `users` | okta.users.read |

## Output

The integration emits OTEL logs with the following structure:

### Resource Attributes

| Attribute | Description |
|-----------|-------------|
| `cloud_connector.id` | Cloud Connector identifier |
| `cloud_connector.name` | Cloud Connector name |
| `cloud_connector.namespace` | Kibana Space the Cloud Connector belongs to (default: `default`) |
| `data_stream.type` | Always `logs` |
| `data_stream.dataset` | Always `verifier_otel.verification` |
| `data_stream.namespace` | Data stream namespace, matches `cloud_connector.namespace` |
| `verification.id` | Verification session ID |
| `verification.timestamp` | When verification started |
| `verification.type` | `on_demand` or `scheduled` |
| `service.name` | Always `permission-verifier` |
| `service.version` | Service version (for example, `1.0.0`) |

### Log Record Attributes

| Attribute | Description |
|-----------|-------------|
| `policy.id` | Policy identifier |
| `policy.name` | Policy name |
| `policy_template` | Policy template name (for example, `cloudtrail`) |
| `package.name` | Integration package name (for example, `aws`) |
| `package.title` | Integration package title (for example, `AWS`) |
| `package.version` | Integration package version (for example, `2.17.0`) or `unspecified` |
| `package_policy.id` | Package policy instance identifier |
| `provider.type` | Provider type (`aws`, `azure`, `gcp`, `okta`) |
| `provider.account` | Provider account identifier |
| `provider.region` | Provider region |
| `provider.project_id` | GCP project ID (when applicable) |
| `account_type` | `single_account` or `organization` |
| `permission.action` | Permission being checked (for example, `cloudtrail:LookupEvents`) |
| `permission.category` | Permission category (for example, `data_access`) |
| `permission.status` | Result: `granted`, `denied`, `error`, or `skipped` |
| `permission.required` | Whether this permission is required |
| `permission.error_code` | Error code from provider (if denied/error) |
| `permission.error_message` | Error message from provider (if denied/error) |
| `verification.method` | Method used: `api_call`, `dry_run`, or `policy_attachment_check` |
| `verification.endpoint` | The API endpoint used for verification |
| `verification.duration_ms` | Time taken for verification in milliseconds |
| `verification.verified_at` | ISO 8601 timestamp of when this individual permission check was performed |

## Example Configurations

### AWS Example

```yaml
cloud_connector_id: "cc-12345"
cloud_connector_name: "Production Connector"
verification_id: "verify-abc123"
verification_type: "on_demand"

provider: "aws"
account_type: "single_account"

credentials_role_arn: "arn:aws:iam::123456789012:role/ElasticAgentRole"
credentials_external_id: "elastic-external-id-from-setup"
default_region: "us-east-1"

policy_id: "policy-aws-security"
policy_name: "AWS Security Monitoring"

policy_template: "cloudtrail"
package_name: "aws"
package_title: "AWS"
package_version: "2.17.0"
namespace: "default"
```

### Azure Example

```yaml
cloud_connector_id: "cc-67890"
cloud_connector_name: "Azure Connector"
verification_id: "verify-def456"
verification_type: "on_demand"

provider: "azure"
account_type: "single_account"

credentials_tenant_id: "00000000-0000-0000-0000-000000000000"
credentials_client_id: "11111111-1111-1111-1111-111111111111"

policy_id: "policy-azure-monitoring"
policy_name: "Azure Activity Monitoring"

policy_template: "activitylogs"
package_name: "azure"
package_title: "Azure"
package_version: "1.5.0"
namespace: "default"
```

### GCP Example

```yaml
cloud_connector_id: "cc-gcp-01"
cloud_connector_name: "GCP Connector"
verification_id: "verify-ghi789"
verification_type: "on_demand"

provider: "gcp"
account_type: "single_account"

credentials_project_id: "my-gcp-project-123"
credentials_workload_identity_provider: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"
credentials_service_account_email: "verifier@my-gcp-project-123.iam.gserviceaccount.com"

policy_id: "policy-gcp-audit"
policy_name: "GCP Audit Monitoring"

policy_template: "audit"
package_name: "gcp"
package_title: "GCP"
package_version: "1.2.0"
namespace: "default"
```

## Related

- [Verifier Receiver Documentation](https://github.com/elastic/opentelemetry-collector-components/tree/main/receiver/verifierreceiver)
