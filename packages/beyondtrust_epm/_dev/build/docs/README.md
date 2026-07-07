# BeyondTrust EPM Integration for Elastic

## Overview

[BeyondTrust Endpoint Privilege Management (EPM)](https://www.beyondtrust.com/products/endpoint-privilege-management) is a security solution that enforces least-privilege policies across endpoints, controls application usage, audits privileged activity, and tracks event activity. It helps organizations reduce their attack surface by managing and monitoring privilege escalation, application control, event activity, and configuration changes across users and devices.

The BeyondTrust EPM integration for Elastic collects audit and event logs using the **BeyondTrust EPM Management API** or through **AWS S3/SQS** cloud storage, and visualizes them in Kibana.

### Compatibility

The BeyondTrust EPM integration is compatible with BeyondTrust EPM version **26.1** and Management API version **v3**.

### How it works

This integration supports two collection methods:

- **Direct API polling** via CEL input, which periodically queries the BeyondTrust EPM Management API using OAuth 2.0 (Client Credentials) authentication.
- **Cloud storage** via AWS S3/SQS, for organizations that export audit and event logs from BeyondTrust EPM to an AWS S3 bucket using the built-in SIEM integration.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Audit`: Collects audit logs via the **BeyondTrust EPM Management API** (endpoint: `/management-api/v3/ActivityAudits/Details`) or via **AWS S3/SQS** for organizations that export logs from BeyondTrust EPM to an S3 bucket.
- `Event`: Collects event logs via the **BeyondTrust EPM Management API** (endpoint: `/management-api/v3/Events/search`) or via **AWS S3/SQS** for organizations that export logs from BeyondTrust EPM to an S3 bucket.

### Supported use cases

Integrating BeyondTrust EPM with Elastic provides centralized visibility into privileged activity and configuration changes across your endpoints, enabling efficient monitoring, investigation, and compliance reporting within Kibana dashboards.

## What do I need to use this integration?

### From BeyondTrust EPM (API collection)

To collect data via the Management API, you need a **Client ID** and **Client Secret** with OAuth 2.0 Client Credentials authentication.

1. Sign in to `app.beyondtrust.io`.
2. Navigate to **Configuration** > **API Registration**.
3. Create or select an API client and copy the **Client ID** and **Client Secret**.

For more information on configuring API registration in BeyondTrust EPM, refer to the [API Settings guide](https://docs.beyondtrust.com/epm-wm/docs/pathfinder-epm-api-settings) in the BeyondTrust documentation.

### From BeyondTrust EPM (AWS S3 collection)

To collect data using AWS S3, configure BeyondTrust EPM to export logs to an S3 bucket, then point Elastic at that bucket.

#### Step 1: Set up AWS infrastructure:

1. Create an **S3 bucket** and note the bucket name and region.
2. Create an **IAM access policy** with these permissions:
   - List: `ListAllMyBuckets`
   - Write: `PutObject`
   - Read: `GetBucketAcl`, `GetBucketLocation`, `GetUser`, `SimulatePrincipalPolicy`
3. Create an **IAM user** with programmatic access, attach the policy, and save the **Access Key ID** and **Secret Access Key**.

#### Step 2:  Configure SIEM export in BeyondTrust EPM:

1. Sign in to **app.beyondtrust.io**.
2. Navigate to **Endpoint Privilege Management for Windows and Mac** > **Configuration** > **SIEM Settings**.
3. Select **Enable SIEM Integration**, then choose **S3** as the Integration Type.
4. Enter the **Access Key ID**, **Secret Access Key**, **Bucket** name, and **Region**.
5. Set the data format to **ECS - Elastic Common Schema**.
6. Click **Validate Settings**, then **Save Settings**.

> **Note:** Only one SIEM integration can be configured at a time. Events are batched and exported to S3 in one-minute intervals in JSON format.

For more information on configuring SIEM settings in BeyondTrust EPM, refer to the [SIEM Settings guide](https://docs.beyondtrust.com/epm-wm/docs/pathfinder-epm-siem-settings) in the BeyondTrust documentation.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **BeyondTrust EPM**.
3. Select the **BeyondTrust EPM** integration from the search results.
4. Select **Add BeyondTrust EPM** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs using BeyondTrust EPM API (CEL)**:

        - Set the **URL** to the base URL of your BeyondTrust EPM instance (e.g., `https://app.beyondtrust.io`).
        - Set the **Client ID** and **Client Secret** obtained from API Registration.
        - Optionally adjust **Initial Interval**, **Interval**, **Page Size**, and **HTTP Client Timeout**.

    * To **Collect logs using AWS S3**:

        - Set the **Bucket ARN** of the S3 bucket configured in BeyondTrust EPM SIEM Settings.
        - Set **AWS Access Key ID** and **Secret Access Key** for an IAM user with read access to the bucket.
        - Optionally configure **Queue URL** (SQS) if using event-driven notifications instead of bucket polling.

6. Select **Save and continue** to save the integration.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **BeyondTrust EPM**, and verify the dashboard information is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Audit

#### Audit fields

{{fields "audit"}}

### Example event

#### Audit

{{event "audit"}}

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
- [AWS S3](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3)

### API usage

This integration dataset uses the following API:

* List Activity Audit Details (endpoint: `/management-api/v3/ActivityAudits/Details`)
* List Event Details (endpoint: `/management-api/v3/Events/search`)
