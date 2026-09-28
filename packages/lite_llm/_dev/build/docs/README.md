# LiteLLM Integration

## Overview

[LiteLLM](https://www.litellm.ai/) is a **unified LLM gateway and proxy** that provides a unified interface for accessing multiple large language models (LLMs) from different providers. It offers comprehensive audit logging, rate limiting, and cost tracking across hybrid LLM deployments — combining authentication, authorization, and detailed audit trails into a unified platform for **critical LLM infrastructure monitoring and compliance**.

The LiteLLM integration for Elastic collects logs using the **LiteLLM API** or through **AWS S3/SQS** cloud storage, and visualizes them in Kibana.

### Compatibility

The LiteLLM integration is compatible with **LiteLLM version 1.91.0 and above**.

### How it works

This integration supports two collection methods:

- **Direct API polling** via the CEL input, which periodically queries the LiteLLM API using API key authentication with cursor-based pagination.
- **Cloud storage** via AWS S3/SQS, for organizations that export logs from LiteLLM to an AWS S3 bucket.

## What data does this integration collect?

The LiteLLM integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `spend_tracking` | Spend and usage tracking records retrieved from the LiteLLM `/spend/logs/v2` API or S3 buckets, including token usage, costs, errors, and authentication events for each LLM request. | `/spend/logs/v2` API or AWS S3 |
| `audit` | Audit log records retrieved from the LiteLLM `/audit` API or S3 buckets, including API usage, authentication events, configuration changes, and user actions across LiteLLM_VerificationToken, LiteLLM_UserTable, and LiteLLM_TeamTable entities. | `/audit` API or AWS S3 |

### Supported use cases

Integrating LiteLLM with Elastic provides centralized visibility into LLM API usage, cost tracking, and error events across your LiteLLM deployment, enabling efficient cost monitoring, investigation, and compliance reporting within Kibana dashboards.

## What do I need to use this integration?

### From LiteLLM (API collection)

To collect data via the API, you need an **API key** with permission to access the `/spend/logs/v2` and `/audit` endpoints.

1. Sign in to your LiteLLM deployment admin panel.
2. Navigate to **API Keys** or **Credentials**.
3. Create or select an API key with permission to read from the `/spend/logs/v2` and `/audit` endpoints.

For more information on configuring API keys in LiteLLM, refer to the [LiteLLM API documentation](https://docs.litellm.ai/docs/proxy/virtual_keys).

### From LiteLLM (AWS S3 collection)

To collect data using AWS S3, configure LiteLLM to export logs to an S3 bucket, then point Elastic at that bucket.

#### Step 1: Set up AWS infrastructure:

1. Create an **S3 bucket** and note the bucket name and region.
2. Create an **IAM access policy** with these permissions:
   - Read: `GetObject`, `ListBucket`
   - SQS (optional): `ReceiveMessage`, `DeleteMessage`
3. Create an **IAM user** with programmatic access, attach the policy, and save the **Access Key ID** and **Secret Access Key**.

#### Step 2: Configure S3 export in LiteLLM:

1. Sign in to your LiteLLM deployment admin panel.
2. Navigate to **Configuration** > **S3 Export** or **Cloud Storage Settings**.
3. Select **Enable S3 Export** and choose your bucket.
4. Enter the **Access Key ID**, **Secret Access Key**, **Bucket** name, and **Region**.
5. Set the data format to **ECS - Elastic Common Schema**.
6. Click **Validate Settings**, then **Save Settings**.

> **Note:** Spend tracking and audit logs are exported to S3 in JSON format at regular intervals.

For more information on configuring S3 export in LiteLLM, refer to the [LiteLLM S3 export documentation](https://docs.litellm.ai/docs/proxy/multiple_admins).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **LiteLLM**.
3. Select the **LiteLLM** integration from the search results.
4. Select **Add LiteLLM** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs using LiteLLM API (CEL)**:

        - Set the **URL** to the base URL of your LiteLLM instance (e.g., `https://litellm.example.com`).
        - Set the **API Key** obtained from your LiteLLM admin panel.
        - Optionally adjust **Initial Interval**, **Interval**, **Batch Size**, and **HTTP Client Timeout**.

    * To **Collect logs using AWS S3**:

        - Set the **Bucket ARN** of the S3 bucket configured in LiteLLM S3 Export Settings.
        - Set **AWS Access Key ID** and **Secret Access Key** for an IAM user with read access to the bucket.
        - Optionally configure **Queue URL** (SQS) if using event-driven notifications instead of bucket polling.

6. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected (CEL)**: Verify that the LiteLLM API is enabled and reachable from the Elastic Agent host. Confirm that the configured URL and API key are correct.
* **No data collected (S3)**: Verify that the S3 bucket exists and is accessible from the Elastic Agent host. Confirm that AWS credentials have S3:GetObject and S3:ListBucket permissions.
* **Authentication failures (CEL)**: Ensure the API key has permission to read logs from the endpoint. Verify the key has not been revoked or expired.
* **Authentication failures (S3)**: Verify AWS credentials are correct and have appropriate S3 permissions. Check that cross-account role assumption is configured correctly if using a role in a different account.
* **SSL certificate errors**: If LiteLLM or AWS endpoints use self-signed certificates, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Pagination or rate limiting (CEL)**: If data collection is incomplete, verify batch size and interval settings. LiteLLM may enforce rate limits on the endpoint.
* **S3 access denied**: Verify IAM permissions include S3:GetObject, S3:ListBucket, and optionally SQS:ReceiveMessage, SQS:DeleteMessage (for SQS-based collection).
* **SQS visibility timeout**: If messages are being reprocessed, increase the visibility timeout to allow sufficient processing time.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **LiteLLM**, and verify the dashboard information is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links

- [LiteLLM Proxy Server Documentation](https://docs.litellm.ai/docs/proxy/quick_start)
- [LiteLLM API Authentication](https://docs.litellm.ai/docs/proxy/virtual_keys)
- [LiteLLM API Reference (OpenAPI)](https://litellm-api.up.railway.app)
- [LiteLLM Model Hub](https://docs.litellm.ai/docs/proxy/model_management)

### Spend Tracking

The `spend_tracking` data stream provides LLM request usage and cost records collected from LiteLLM via API or S3.

#### Spend Tracking fields

{{fields "spend_tracking"}}

#### Spend Tracking example event

{{event "spend_tracking"}}

### Audit

The `audit` data stream provides audit log records collected from LiteLLM via API or S3.

#### Audit fields

{{fields "audit"}}

#### Audit example event

{{event "audit"}}

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
- [AWS S3](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3)

### API usage

This integration uses the following APIs:

- `Spend Tracking`: Collects spend tracking records via the **LiteLLM Spend Tracking API** (endpoint: `/spend/logs/v2`) or via **AWS S3/SQS** for organizations that export spend tracking data from LiteLLM to an S3 bucket.

- `Audit`: Collects audit logs via the **LiteLLM Audit API** (endpoint: `/audit`) or via **AWS S3/SQS** for organizations that export logs from LiteLLM to an S3 bucket.
