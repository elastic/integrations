# Permission Verifier Integration

## Overview

The Permission Verifier integration uses the OpenTelemetry Collector's Verifier receiver to verify identity federation based integration permissions and report results to Elasticsearch.

This integration is designed for Identity Federations to proactively check that all necessary permissions are available for attached integrations.

## Supported Providers

| Provider | Status | Description |
|----------|--------|-------------|
| AWS | Active | CloudTrail, GuardDuty, Security Hub, S3, EC2, VPC Flow Logs, WAF, Route53, ELB, CloudFront, CSPM, Asset Inventory |
| Azure | Active | Activity Logs, Audit Logs, Blob Storage, CSPM, Asset Inventory |
| GCP | Active | Audit Logs, Cloud Storage, Pub/Sub, CSPM, Asset Inventory |
| Okta | Planned | System Logs, User Events |

## Configuration

### Identity Federation Identification

| Field | Required | Description |
|-------|----------|-------------|
| Identity Federation ID | Yes | Unique identifier for the Identity Federation being verified |
| Identity Federation Name | No | Human-readable name of the Identity Federation |
| Verification ID | Yes | Unique identifier for this verification session |
| Verification Type | No | Type of verification: `on_demand` (default) or `scheduled` |

### Provider and Account Configuration

| Field | Required | Description |
|-------|----------|-------------|
| `provider` | Yes | Cloud provider type (`aws`, `azure`, `gcp`, `okta`) |
| `account_type` | No | Whether the target is a `single-account` (default) or `organization-account` (management account). Affects which permissions are verified since assuming a role behaves differently for single accounts vs organization management accounts. |

### Credentials

Credential fields use a flat, normalized naming convention to stay consistent with Fleet and avoid translation layers across packages. Only set the fields relevant to your `provider`.

#### AWS Credentials

| Field | Required | Description |
|-------|----------|-------------|
| `credentials_role_arn` | Yes | ARN of the IAM role to assume in the customer's AWS account |
| `credentials_external_id` | Yes | External ID to prevent confused deputy attacks |

#### Azure Credentials

| Field | Required | Description |
|-------|----------|-------------|
| `credentials_tenant_id` | Yes | Azure AD tenant ID |
| `credentials_client_id` | Yes | Azure application (client) ID |

#### GCP Credentials

| Field | Required | Description |
|-------|----------|-------------|
| `credentials_audience` | Yes | Full WIF resource name used as the STS audience (project number is derived from this when `credentials_service_account_email` is not set) |
| `credentials_service_account_email` | Yes | GCP service account email for impersonation (project ID is derived from this when set) |

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

## Supported Policy Templates

Each `policy_template` is scoped per integration following the least-privilege principle. Only the permissions required by that specific policy template are verified, rather than checking global permissions shared across the entire integration package. This ensures that each Identity Federation only needs the exact IAM permissions its attached integrations require.

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

Set by the receiver:

| Attribute | Description |
|-----------|-------------|
| `identity_federation.id` | Identity Federation identifier |
| `identity_federation.name` | Identity Federation name |
| `verification.id` | Verification session ID |
| `verification.timestamp` | When verification started |
| `verification.type` | `on_demand` or `scheduled` |
| `service.name` | Always `permission-verifier` |
| `service.version` | Service version (for example, `1.0.0`) |

Set by Fleet (via auto-injected `transform` processor):

| Attribute | Description |
|-----------|-------------|
| `data_stream.type` | Always `logs` |
| `data_stream.dataset` | Derived from the policy template name |
| `data_stream.namespace` | Kibana Space the Identity Federation belongs to |

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
| `account_type` | `single-account` or `organization-account` |
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

The examples below show complete OTel pipeline configurations. When managed by Fleet, the `resource/verifier` processor block is injected automatically and `${var:namespace}` is resolved to the Kibana Space. For standalone testing, define the processor explicitly with a literal namespace value.

### AWS Example

```yaml
receivers:
  verifier:
    identity_federation_id: "cc-12345"
    identity_federation_name: "Production Connector"
    verification_id: "verify-abc123"
    verification_type: "on_demand"
    account_type: "single-account"
    providers:
      aws:
        credentials:
          role_arn: "arn:aws:iam::123456789012:role/ElasticAgentRole"
          external_id: "elastic-external-id-from-setup"
    policies:
      - policy_id: "policy-aws-security"
        policy_name: "AWS Security Monitoring"
        integrations:
          - policy_template: "cloudtrail"
            package_name: "aws"
            package_title: "AWS"
            package_version: "2.17.0"

processors:
  resource/verifier:
    attributes:
      - action: insert
        key: data_stream.type
        value: logs
      - action: insert
        key: data_stream.dataset
        value: verifier_otel.verification
      - action: insert
        key: data_stream.namespace
        value: ${var:namespace}
      - action: insert
        key: identity_federation.namespace
        value: ${var:namespace}

service:
  pipelines:
    logs:
      receivers: [verifier]
      processors: [resource/verifier]
      exporters: [elasticsearch/otel]
```

### Azure Example

```yaml
receivers:
  verifier:
    identity_federation_id: "cc-67890"
    identity_federation_name: "Azure Connector"
    verification_id: "verify-def456"
    verification_type: "on_demand"
    account_type: "single-account"
    providers:
      azure:
        credentials:
          tenant_id: "00000000-0000-0000-0000-000000000000"
          client_id: "11111111-1111-1111-1111-111111111111"
    policies:
      - policy_id: "policy-azure-monitoring"
        policy_name: "Azure Activity Monitoring"
        integrations:
          - policy_template: "activitylogs"
            package_name: "azure"
            package_title: "Azure"
            package_version: "1.5.0"

processors:
  resource/verifier:
    attributes:
      - action: insert
        key: data_stream.type
        value: logs
      - action: insert
        key: data_stream.dataset
        value: verifier_otel.verification
      - action: insert
        key: data_stream.namespace
        value: ${var:namespace}
      - action: insert
        key: identity_federation.namespace
        value: ${var:namespace}

service:
  pipelines:
    logs:
      receivers: [verifier]
      processors: [resource/verifier]
      exporters: [elasticsearch/otel]
```

### GCP Example

```yaml
receivers:
  verifier:
    identity_federation_id: "cc-gcp-01"
    identity_federation_name: "GCP Connector"
    verification_id: "verify-ghi789"
    verification_type: "on_demand"
    account_type: "single-account"
    providers:
      gcp:
        credentials:
          audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"
          service_account_email: "verifier@my-gcp-project-123.iam.gserviceaccount.com"
    policies:
      - policy_id: "policy-gcp-audit"
        policy_name: "GCP Audit Monitoring"
        integrations:
          - policy_template: "audit"
            package_name: "gcp"
            package_title: "GCP"
            package_version: "1.2.0"

processors:
  resource/verifier:
    attributes:
      - action: insert
        key: data_stream.type
        value: logs
      - action: insert
        key: data_stream.dataset
        value: verifier_otel.verification
      - action: insert
        key: data_stream.namespace
        value: ${var:namespace}
      - action: insert
        key: identity_federation.namespace
        value: ${var:namespace}

service:
  pipelines:
    logs:
      receivers: [verifier]
      processors: [resource/verifier]
      exporters: [elasticsearch/otel]
```

## Related

- [Verifier Receiver Documentation](https://github.com/elastic/opentelemetry-collector-components/tree/main/receiver/verifierreceiver)
