# BeyondTrust EPM Integration for Elastic

## Overview

[BeyondTrust Endpoint Privilege Management (EPM)](https://www.beyondtrust.com/products/endpoint-privilege-management) is a security solution that enforces least-privilege policies across endpoints, controls application usage, and audits privileged activity. It helps organizations reduce their attack surface by managing and monitoring privilege escalation, application control, and configuration changes across users and devices.

The BeyondTrust EPM integration for Elastic collects event logs via the **BeyondTrust EPM Management API** or through **AWS S3/SQS** cloud storage, and visualizes them in Kibana.

### Compatibility

The BeyondTrust EPM integration is compatible with BeyondTrust EPM version **26.1** and Management API version **v3**.

### How it works

This integration supports two collection methods:

- **Direct API polling** via CEL input, which periodically queries the BeyondTrust EPM Management API using OAuth 2.0 (Client Credentials) authentication.
- **Cloud storage** via AWS S3/SQS, for organizations that export event logs from BeyondTrust EPM to an AWS S3 bucket using the built-in SIEM integration.

## What data does this integration collect?

This integration collects log messages of the following type:

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

To collect data via AWS S3, configure BeyondTrust EPM to export logs to an S3 bucket, then point Elastic at that bucket.

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

    * To **Collect logs via BeyondTrust EPM API (CEL)**:

        - Set the **URL** to the base URL of your BeyondTrust EPM instance (e.g., `https://app.beyondtrust.io`).
        - Set the **Client ID** and **Client Secret** obtained from API Registration.
        - Optionally adjust **Initial Interval**, **Interval**, **Page Size**, and **HTTP Client Timeout**.

    * To **Collect logs via AWS S3**:

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

### Event

#### Event fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| aws.s3.bucket.arn |  | keyword |
| aws.s3.bucket.name |  | keyword |
| aws.s3.object.key |  | keyword |
| beyondtrust_epm.event.agent.build.original |  | keyword |
| beyondtrust_epm.event.agent.ephemeral_id |  | keyword |
| beyondtrust_epm.event.agent.id |  | keyword |
| beyondtrust_epm.event.agent.name |  | keyword |
| beyondtrust_epm.event.agent.type |  | keyword |
| beyondtrust_epm.event.agent.version |  | keyword |
| beyondtrust_epm.event.client.address |  | keyword |
| beyondtrust_epm.event.client.as.number |  | long |
| beyondtrust_epm.event.client.as.organization.name |  | keyword |
| beyondtrust_epm.event.client.bytes |  | long |
| beyondtrust_epm.event.client.domain |  | keyword |
| beyondtrust_epm.event.client.geo.city_name |  | keyword |
| beyondtrust_epm.event.client.geo.continent_code |  | keyword |
| beyondtrust_epm.event.client.geo.continent_name |  | keyword |
| beyondtrust_epm.event.client.geo.country_iso_code |  | keyword |
| beyondtrust_epm.event.client.geo.country_name |  | keyword |
| beyondtrust_epm.event.client.geo.location.lat |  | long |
| beyondtrust_epm.event.client.geo.location.lon |  | long |
| beyondtrust_epm.event.client.geo.name |  | keyword |
| beyondtrust_epm.event.client.geo.postal_code |  | keyword |
| beyondtrust_epm.event.client.geo.region_iso_code |  | keyword |
| beyondtrust_epm.event.client.geo.region_name |  | keyword |
| beyondtrust_epm.event.client.geo.timezone |  | keyword |
| beyondtrust_epm.event.client.geo.timezone_offset |  | long |
| beyondtrust_epm.event.client.ip |  | ip |
| beyondtrust_epm.event.client.mac |  | keyword |
| beyondtrust_epm.event.client.name |  | keyword |
| beyondtrust_epm.event.client.nat.ip |  | ip |
| beyondtrust_epm.event.client.nat.port |  | long |
| beyondtrust_epm.event.client.packets |  | long |
| beyondtrust_epm.event.client.port |  | long |
| beyondtrust_epm.event.client.registered_domain |  | keyword |
| beyondtrust_epm.event.client.subdomain |  | keyword |
| beyondtrust_epm.event.client.top_level_domain |  | keyword |
| beyondtrust_epm.event.client.user.changes.default_timezone_offset |  | long |
| beyondtrust_epm.event.client.user.changes.domain |  | keyword |
| beyondtrust_epm.event.client.user.changes.domain_identifier |  | keyword |
| beyondtrust_epm.event.client.user.changes.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.client.user.changes.email |  | keyword |
| beyondtrust_epm.event.client.user.changes.full_name |  | keyword |
| beyondtrust_epm.event.client.user.changes.group.domain |  | keyword |
| beyondtrust_epm.event.client.user.changes.group.id |  | keyword |
| beyondtrust_epm.event.client.user.changes.group.name |  | keyword |
| beyondtrust_epm.event.client.user.changes.hash |  | keyword |
| beyondtrust_epm.event.client.user.changes.id |  | keyword |
| beyondtrust_epm.event.client.user.changes.local_identifier |  | long |
| beyondtrust_epm.event.client.user.changes.name |  | keyword |
| beyondtrust_epm.event.client.user.changes.roles |  | keyword |
| beyondtrust_epm.event.client.user.default_timezone_offset |  | long |
| beyondtrust_epm.event.client.user.domain |  | keyword |
| beyondtrust_epm.event.client.user.domain_identifier |  | keyword |
| beyondtrust_epm.event.client.user.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.client.user.effective.default_timezone_offset |  | long |
| beyondtrust_epm.event.client.user.effective.domain |  | keyword |
| beyondtrust_epm.event.client.user.effective.domain_identifier |  | keyword |
| beyondtrust_epm.event.client.user.effective.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.client.user.effective.email |  | keyword |
| beyondtrust_epm.event.client.user.effective.full_name |  | keyword |
| beyondtrust_epm.event.client.user.effective.group.domain |  | keyword |
| beyondtrust_epm.event.client.user.effective.group.id |  | keyword |
| beyondtrust_epm.event.client.user.effective.group.name |  | keyword |
| beyondtrust_epm.event.client.user.effective.hash |  | keyword |
| beyondtrust_epm.event.client.user.effective.id |  | keyword |
| beyondtrust_epm.event.client.user.effective.local_identifier |  | long |
| beyondtrust_epm.event.client.user.effective.name |  | keyword |
| beyondtrust_epm.event.client.user.effective.roles |  | keyword |
| beyondtrust_epm.event.client.user.email |  | keyword |
| beyondtrust_epm.event.client.user.full_name |  | keyword |
| beyondtrust_epm.event.client.user.group.domain |  | keyword |
| beyondtrust_epm.event.client.user.group.id |  | keyword |
| beyondtrust_epm.event.client.user.group.name |  | keyword |
| beyondtrust_epm.event.client.user.hash |  | keyword |
| beyondtrust_epm.event.client.user.id |  | keyword |
| beyondtrust_epm.event.client.user.local_identifier |  | long |
| beyondtrust_epm.event.client.user.name |  | keyword |
| beyondtrust_epm.event.client.user.roles |  | keyword |
| beyondtrust_epm.event.client.user.target.default_timezone_offset |  | long |
| beyondtrust_epm.event.client.user.target.domain |  | keyword |
| beyondtrust_epm.event.client.user.target.domain_identifier |  | keyword |
| beyondtrust_epm.event.client.user.target.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.client.user.target.email |  | keyword |
| beyondtrust_epm.event.client.user.target.full_name |  | keyword |
| beyondtrust_epm.event.client.user.target.group.domain |  | keyword |
| beyondtrust_epm.event.client.user.target.group.id |  | keyword |
| beyondtrust_epm.event.client.user.target.group.name |  | keyword |
| beyondtrust_epm.event.client.user.target.hash |  | keyword |
| beyondtrust_epm.event.client.user.target.id |  | keyword |
| beyondtrust_epm.event.client.user.target.local_identifier |  | long |
| beyondtrust_epm.event.client.user.target.name |  | keyword |
| beyondtrust_epm.event.client.user.target.roles |  | keyword |
| beyondtrust_epm.event.cloud.account.id |  | keyword |
| beyondtrust_epm.event.cloud.account.name |  | keyword |
| beyondtrust_epm.event.cloud.availability_zone |  | keyword |
| beyondtrust_epm.event.cloud.instance.id |  | keyword |
| beyondtrust_epm.event.cloud.instance.name |  | keyword |
| beyondtrust_epm.event.cloud.machine.type |  | keyword |
| beyondtrust_epm.event.cloud.origin.account.id |  | keyword |
| beyondtrust_epm.event.cloud.origin.account.name |  | keyword |
| beyondtrust_epm.event.cloud.origin.availability_zone |  | keyword |
| beyondtrust_epm.event.cloud.origin.instance.id |  | keyword |
| beyondtrust_epm.event.cloud.origin.instance.name |  | keyword |
| beyondtrust_epm.event.cloud.origin.machine.type |  | keyword |
| beyondtrust_epm.event.cloud.origin.project.id |  | keyword |
| beyondtrust_epm.event.cloud.origin.project.name |  | keyword |
| beyondtrust_epm.event.cloud.origin.provider |  | keyword |
| beyondtrust_epm.event.cloud.origin.region |  | keyword |
| beyondtrust_epm.event.cloud.origin.service.name |  | keyword |
| beyondtrust_epm.event.cloud.project.id |  | keyword |
| beyondtrust_epm.event.cloud.project.name |  | keyword |
| beyondtrust_epm.event.cloud.provider |  | keyword |
| beyondtrust_epm.event.cloud.region |  | keyword |
| beyondtrust_epm.event.cloud.service.name |  | keyword |
| beyondtrust_epm.event.cloud.target.account.id |  | keyword |
| beyondtrust_epm.event.cloud.target.account.name |  | keyword |
| beyondtrust_epm.event.cloud.target.availability_zone |  | keyword |
| beyondtrust_epm.event.cloud.target.instance.id |  | keyword |
| beyondtrust_epm.event.cloud.target.instance.name |  | keyword |
| beyondtrust_epm.event.cloud.target.machine.type |  | keyword |
| beyondtrust_epm.event.cloud.target.project.id |  | keyword |
| beyondtrust_epm.event.cloud.target.project.name |  | keyword |
| beyondtrust_epm.event.cloud.target.provider |  | keyword |
| beyondtrust_epm.event.cloud.target.region |  | keyword |
| beyondtrust_epm.event.cloud.target.service.name |  | keyword |
| beyondtrust_epm.event.container.cpu.usage |  | scaled_float |
| beyondtrust_epm.event.container.disk.read.bytes |  | long |
| beyondtrust_epm.event.container.disk.write.bytes |  | long |
| beyondtrust_epm.event.container.id |  | keyword |
| beyondtrust_epm.event.container.image.hash.all |  | keyword |
| beyondtrust_epm.event.container.image.name |  | keyword |
| beyondtrust_epm.event.container.image.tag |  | keyword |
| beyondtrust_epm.event.container.labels |  | keyword |
| beyondtrust_epm.event.container.memory.usage |  | scaled_float |
| beyondtrust_epm.event.container.name |  | keyword |
| beyondtrust_epm.event.container.network.egress.bytes |  | long |
| beyondtrust_epm.event.container.network.ingress.bytes |  | long |
| beyondtrust_epm.event.container.runtime |  | keyword |
| beyondtrust_epm.event.data_stream.dataset |  | constant_keyword |
| beyondtrust_epm.event.data_stream.namespace |  | constant_keyword |
| beyondtrust_epm.event.data_stream.type |  | constant_keyword |
| beyondtrust_epm.event.destination.address |  | keyword |
| beyondtrust_epm.event.destination.as.number |  | long |
| beyondtrust_epm.event.destination.as.organization.name |  | keyword |
| beyondtrust_epm.event.destination.bytes |  | long |
| beyondtrust_epm.event.destination.domain |  | keyword |
| beyondtrust_epm.event.destination.geo.city_name |  | keyword |
| beyondtrust_epm.event.destination.geo.continent_code |  | keyword |
| beyondtrust_epm.event.destination.geo.continent_name |  | keyword |
| beyondtrust_epm.event.destination.geo.country_iso_code |  | keyword |
| beyondtrust_epm.event.destination.geo.country_name |  | keyword |
| beyondtrust_epm.event.destination.geo.location.lat |  | long |
| beyondtrust_epm.event.destination.geo.location.lon |  | long |
| beyondtrust_epm.event.destination.geo.name |  | keyword |
| beyondtrust_epm.event.destination.geo.postal_code |  | keyword |
| beyondtrust_epm.event.destination.geo.region_iso_code |  | keyword |
| beyondtrust_epm.event.destination.geo.region_name |  | keyword |
| beyondtrust_epm.event.destination.geo.timezone |  | keyword |
| beyondtrust_epm.event.destination.geo.timezone_offset |  | long |
| beyondtrust_epm.event.destination.ip |  | ip |
| beyondtrust_epm.event.destination.mac |  | keyword |
| beyondtrust_epm.event.destination.nat.ip |  | ip |
| beyondtrust_epm.event.destination.nat.port |  | long |
| beyondtrust_epm.event.destination.packets |  | long |
| beyondtrust_epm.event.destination.port |  | long |
| beyondtrust_epm.event.destination.registered_domain |  | keyword |
| beyondtrust_epm.event.destination.subdomain |  | keyword |
| beyondtrust_epm.event.destination.top_level_domain |  | keyword |
| beyondtrust_epm.event.destination.user.changes.default_timezone_offset |  | long |
| beyondtrust_epm.event.destination.user.changes.domain |  | keyword |
| beyondtrust_epm.event.destination.user.changes.domain_identifier |  | keyword |
| beyondtrust_epm.event.destination.user.changes.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.destination.user.changes.email |  | keyword |
| beyondtrust_epm.event.destination.user.changes.full_name |  | keyword |
| beyondtrust_epm.event.destination.user.changes.group.domain |  | keyword |
| beyondtrust_epm.event.destination.user.changes.group.id |  | keyword |
| beyondtrust_epm.event.destination.user.changes.group.name |  | keyword |
| beyondtrust_epm.event.destination.user.changes.hash |  | keyword |
| beyondtrust_epm.event.destination.user.changes.id |  | keyword |
| beyondtrust_epm.event.destination.user.changes.local_identifier |  | long |
| beyondtrust_epm.event.destination.user.changes.name |  | keyword |
| beyondtrust_epm.event.destination.user.changes.roles |  | keyword |
| beyondtrust_epm.event.destination.user.default_timezone_offset |  | long |
| beyondtrust_epm.event.destination.user.domain |  | keyword |
| beyondtrust_epm.event.destination.user.domain_identifier |  | keyword |
| beyondtrust_epm.event.destination.user.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.destination.user.effective.default_timezone_offset |  | long |
| beyondtrust_epm.event.destination.user.effective.domain |  | keyword |
| beyondtrust_epm.event.destination.user.effective.domain_identifier |  | keyword |
| beyondtrust_epm.event.destination.user.effective.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.destination.user.effective.email |  | keyword |
| beyondtrust_epm.event.destination.user.effective.full_name |  | keyword |
| beyondtrust_epm.event.destination.user.effective.group.domain |  | keyword |
| beyondtrust_epm.event.destination.user.effective.group.id |  | keyword |
| beyondtrust_epm.event.destination.user.effective.group.name |  | keyword |
| beyondtrust_epm.event.destination.user.effective.hash |  | keyword |
| beyondtrust_epm.event.destination.user.effective.id |  | keyword |
| beyondtrust_epm.event.destination.user.effective.local_identifier |  | long |
| beyondtrust_epm.event.destination.user.effective.name |  | keyword |
| beyondtrust_epm.event.destination.user.effective.roles |  | keyword |
| beyondtrust_epm.event.destination.user.email |  | keyword |
| beyondtrust_epm.event.destination.user.full_name |  | keyword |
| beyondtrust_epm.event.destination.user.group.domain |  | keyword |
| beyondtrust_epm.event.destination.user.group.id |  | keyword |
| beyondtrust_epm.event.destination.user.group.name |  | keyword |
| beyondtrust_epm.event.destination.user.hash |  | keyword |
| beyondtrust_epm.event.destination.user.id |  | keyword |
| beyondtrust_epm.event.destination.user.local_identifier |  | long |
| beyondtrust_epm.event.destination.user.name |  | keyword |
| beyondtrust_epm.event.destination.user.roles |  | keyword |
| beyondtrust_epm.event.destination.user.target.default_timezone_offset |  | long |
| beyondtrust_epm.event.destination.user.target.domain |  | keyword |
| beyondtrust_epm.event.destination.user.target.domain_identifier |  | keyword |
| beyondtrust_epm.event.destination.user.target.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.destination.user.target.email |  | keyword |
| beyondtrust_epm.event.destination.user.target.full_name |  | keyword |
| beyondtrust_epm.event.destination.user.target.group.domain |  | keyword |
| beyondtrust_epm.event.destination.user.target.group.id |  | keyword |
| beyondtrust_epm.event.destination.user.target.group.name |  | keyword |
| beyondtrust_epm.event.destination.user.target.hash |  | keyword |
| beyondtrust_epm.event.destination.user.target.id |  | keyword |
| beyondtrust_epm.event.destination.user.target.local_identifier |  | long |
| beyondtrust_epm.event.destination.user.target.name |  | keyword |
| beyondtrust_epm.event.destination.user.target.roles |  | keyword |
| beyondtrust_epm.event.dll.code_signature.digest_algorithm |  | keyword |
| beyondtrust_epm.event.dll.code_signature.exists |  | boolean |
| beyondtrust_epm.event.dll.code_signature.signing_id |  | keyword |
| beyondtrust_epm.event.dll.code_signature.status |  | keyword |
| beyondtrust_epm.event.dll.code_signature.subject_name |  | keyword |
| beyondtrust_epm.event.dll.code_signature.team_id |  | keyword |
| beyondtrust_epm.event.dll.code_signature.timestamp |  | date |
| beyondtrust_epm.event.dll.code_signature.trusted |  | boolean |
| beyondtrust_epm.event.dll.code_signature.valid |  | boolean |
| beyondtrust_epm.event.dll.hash.md5 |  | keyword |
| beyondtrust_epm.event.dll.hash.sha1 |  | keyword |
| beyondtrust_epm.event.dll.hash.sha256 |  | keyword |
| beyondtrust_epm.event.dll.hash.sha384 |  | keyword |
| beyondtrust_epm.event.dll.hash.sha512 |  | keyword |
| beyondtrust_epm.event.dll.hash.ssdeep |  | keyword |
| beyondtrust_epm.event.dll.hash.tlsh |  | keyword |
| beyondtrust_epm.event.dll.name |  | keyword |
| beyondtrust_epm.event.dll.path |  | keyword |
| beyondtrust_epm.event.dll.pe.architecture |  | keyword |
| beyondtrust_epm.event.dll.pe.company |  | keyword |
| beyondtrust_epm.event.dll.pe.description |  | keyword |
| beyondtrust_epm.event.dll.pe.file_version |  | keyword |
| beyondtrust_epm.event.dll.pe.imphash |  | keyword |
| beyondtrust_epm.event.dll.pe.original_file_name |  | keyword |
| beyondtrust_epm.event.dll.pe.pehash |  | keyword |
| beyondtrust_epm.event.dll.pe.product |  | keyword |
| beyondtrust_epm.event.dns.answers |  | keyword |
| beyondtrust_epm.event.dns.header_flags |  | keyword |
| beyondtrust_epm.event.dns.id |  | keyword |
| beyondtrust_epm.event.dns.op_code |  | keyword |
| beyondtrust_epm.event.dns.question.class |  | keyword |
| beyondtrust_epm.event.dns.question.name |  | keyword |
| beyondtrust_epm.event.dns.question.registered_domain |  | keyword |
| beyondtrust_epm.event.dns.question.subdomain |  | keyword |
| beyondtrust_epm.event.dns.question.top_level_domain |  | keyword |
| beyondtrust_epm.event.dns.question.type |  | keyword |
| beyondtrust_epm.event.dns.resolved_ip |  | ip |
| beyondtrust_epm.event.dns.response_code |  | keyword |
| beyondtrust_epm.event.dns.type |  | keyword |
| beyondtrust_epm.event.ecs.version |  | keyword |
| beyondtrust_epm.event.email.attachments.file.extension |  | keyword |
| beyondtrust_epm.event.email.attachments.file.hash.md5 |  | keyword |
| beyondtrust_epm.event.email.attachments.file.hash.sha1 |  | keyword |
| beyondtrust_epm.event.email.attachments.file.hash.sha256 |  | keyword |
| beyondtrust_epm.event.email.attachments.file.hash.sha384 |  | keyword |
| beyondtrust_epm.event.email.attachments.file.hash.sha512 |  | keyword |
| beyondtrust_epm.event.email.attachments.file.hash.ssdeep |  | keyword |
| beyondtrust_epm.event.email.attachments.file.hash.tlsh |  | keyword |
| beyondtrust_epm.event.email.attachments.file.mime_type |  | keyword |
| beyondtrust_epm.event.email.attachments.file.name |  | keyword |
| beyondtrust_epm.event.email.attachments.file.size |  | long |
| beyondtrust_epm.event.email.bcc.address |  | keyword |
| beyondtrust_epm.event.email.cc.address |  | keyword |
| beyondtrust_epm.event.email.content_type |  | keyword |
| beyondtrust_epm.event.email.delivery_timestamp |  | date |
| beyondtrust_epm.event.email.direction |  | keyword |
| beyondtrust_epm.event.email.from.address |  | keyword |
| beyondtrust_epm.event.email.local_id |  | keyword |
| beyondtrust_epm.event.email.message_id |  | keyword |
| beyondtrust_epm.event.email.origination_timestamp |  | date |
| beyondtrust_epm.event.email.reply_to.address |  | keyword |
| beyondtrust_epm.event.email.sender.address |  | keyword |
| beyondtrust_epm.event.email.subject |  | keyword |
| beyondtrust_epm.event.email.to.address |  | keyword |
| beyondtrust_epm.event.email.x_mailer |  | keyword |
| beyondtrust_epm.event.epm_win_mac.active_x.clsid |  | keyword |
| beyondtrust_epm.event.epm_win_mac.active_x.codebase |  | keyword |
| beyondtrust_epm.event.epm_win_mac.active_x.version |  | keyword |
| beyondtrust_epm.event.epm_win_mac.adapter_version |  | keyword |
| beyondtrust_epm.event.epm_win_mac.authorization_request.auth_request_uri |  | keyword |
| beyondtrust_epm.event.epm_win_mac.authorization_request.control_authorization |  | boolean |
| beyondtrust_epm.event.epm_win_mac.authorizing_user.credential_source |  | keyword |
| beyondtrust_epm.event.epm_win_mac.authorizing_user.domain_identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.authorizing_user.domain_name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.authorizing_user.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.epm_win_mac.authorizing_user.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.authorizing_user.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.com.app_id |  | keyword |
| beyondtrust_epm.event.epm_win_mac.com.clsid |  | keyword |
| beyondtrust_epm.event.epm_win_mac.com.display_name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.application.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.application.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.application.type |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.application_group.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.application_group.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.application_group.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.content.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.content.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.content.type |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.content_group.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.content_group.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.content_group.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.gpo.active_directory_path |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.gpo.display_name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.gpo.link_information |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.gpo.version |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.load_audit_mode |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.auth_methods |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.authentication.user |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.authorization.challenge_code |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.authorization.response_status |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.type |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.user_reason |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.message.user_request_management_id |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.path |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.revision_number |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.rule.action |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.rule.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.rule.matched_child |  | boolean |
| beyondtrust_epm.event.epm_win_mac.configuration.rule.on_demand |  | boolean |
| beyondtrust_epm.event.epm_win_mac.configuration.rule_script.file_name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.rule_script.outcome.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.rule_script.outcome.output |  | match_only_text |
| beyondtrust_epm.event.epm_win_mac.configuration.rule_script.outcome.result |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.rule_script.outcome.rule_affected |  | boolean |
| beyondtrust_epm.event.epm_win_mac.configuration.rule_script.outcome.version |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.rule_script.publisher |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.signing_enforcement |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.source |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.token.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.token.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.token.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.workstyle.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.workstyle.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.configuration.workstyle.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.event.action |  | keyword |
| beyondtrust_epm.event.epm_win_mac.event.type |  | keyword |
| beyondtrust_epm.event.epm_win_mac.group_id |  | keyword |
| beyondtrust_epm.event.epm_win_mac.installer.action |  | keyword |
| beyondtrust_epm.event.epm_win_mac.installer.product_code |  | keyword |
| beyondtrust_epm.event.epm_win_mac.installer.upgrade_code |  | keyword |
| beyondtrust_epm.event.epm_win_mac.license.invalid_reason |  | keyword |
| beyondtrust_epm.event.epm_win_mac.privileged_group.access |  | keyword |
| beyondtrust_epm.event.epm_win_mac.privileged_group.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.privileged_group.rid |  | keyword |
| beyondtrust_epm.event.epm_win_mac.remote_power_shell.command |  | wildcard |
| beyondtrust_epm.event.epm_win_mac.schema_version |  | keyword |
| beyondtrust_epm.event.epm_win_mac.service_control.service.action |  | keyword |
| beyondtrust_epm.event.epm_win_mac.service_control.service.display_name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.service_control.service.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.administrator |  | boolean |
| beyondtrust_epm.event.epm_win_mac.session.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.application.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.application.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.application.type |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.application_group.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.application_group.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.application_group.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.content.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.content.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.content.type |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.content_group.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.content_group.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.content_group.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.gpo.active_directory_path |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.gpo.display_name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.gpo.link_information |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.gpo.version |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.load_audit_mode |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.auth_methods |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.authentication.user |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.authorization.challenge_code |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.authorization.response_status |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.type |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.user_reason |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.message.user_request_management_id |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.path |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.revision_number |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule.action |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule.matched_child |  | boolean |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule.on_demand |  | boolean |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule_script.file_name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule_script.outcome.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule_script.outcome.output |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule_script.outcome.result |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule_script.outcome.rule_affected |  | boolean |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule_script.outcome.version |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.rule_script.publisher |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.signing_enforcement |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.source |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.token.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.token.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.token.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.workstyle.description |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.workstyle.identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.configuration.workstyle.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.request_identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.jit_admin.ticket_identifier |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.locale |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.power_user |  | boolean |
| beyondtrust_epm.event.epm_win_mac.session.ui_language |  | keyword |
| beyondtrust_epm.event.epm_win_mac.session.windows_session_id |  | keyword |
| beyondtrust_epm.event.epm_win_mac.store_app.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.store_app.publisher |  | keyword |
| beyondtrust_epm.event.epm_win_mac.store_app.version |  | keyword |
| beyondtrust_epm.event.epm_win_mac.tenant_id |  | keyword |
| beyondtrust_epm.event.epm_win_mac.trusted_application.name |  | keyword |
| beyondtrust_epm.event.epm_win_mac.trusted_application.version |  | keyword |
| beyondtrust_epm.event.error.code |  | keyword |
| beyondtrust_epm.event.error.id |  | keyword |
| beyondtrust_epm.event.error.message |  | match_only_text |
| beyondtrust_epm.event.error.stack_trace |  | wildcard |
| beyondtrust_epm.event.error.type |  | keyword |
| beyondtrust_epm.event.event.action |  | keyword |
| beyondtrust_epm.event.event.agent_id_status |  | keyword |
| beyondtrust_epm.event.event.category |  | keyword |
| beyondtrust_epm.event.event.code |  | keyword |
| beyondtrust_epm.event.event.created |  | date |
| beyondtrust_epm.event.event.dataset |  | keyword |
| beyondtrust_epm.event.event.duration |  | long |
| beyondtrust_epm.event.event.end |  | date |
| beyondtrust_epm.event.event.hash |  | keyword |
| beyondtrust_epm.event.event.id |  | keyword |
| beyondtrust_epm.event.event.ingested |  | date |
| beyondtrust_epm.event.event.kind |  | keyword |
| beyondtrust_epm.event.event.module |  | keyword |
| beyondtrust_epm.event.event.original |  | keyword |
| beyondtrust_epm.event.event.outcome |  | keyword |
| beyondtrust_epm.event.event.provider |  | keyword |
| beyondtrust_epm.event.event.reason |  | keyword |
| beyondtrust_epm.event.event.received_at |  | date |
| beyondtrust_epm.event.event.reference |  | keyword |
| beyondtrust_epm.event.event.risk_score |  | float |
| beyondtrust_epm.event.event.risk_score_norm |  | float |
| beyondtrust_epm.event.event.sequence |  | long |
| beyondtrust_epm.event.event.severity |  | long |
| beyondtrust_epm.event.event.start |  | date |
| beyondtrust_epm.event.event.timezone |  | keyword |
| beyondtrust_epm.event.event.type |  | keyword |
| beyondtrust_epm.event.event.url |  | keyword |
| beyondtrust_epm.event.faas.coldstart |  | boolean |
| beyondtrust_epm.event.faas.execution |  | keyword |
| beyondtrust_epm.event.faas.id |  | keyword |
| beyondtrust_epm.event.faas.name |  | keyword |
| beyondtrust_epm.event.faas.trigger.request_id |  | keyword |
| beyondtrust_epm.event.faas.trigger.type |  | keyword |
| beyondtrust_epm.event.faas.version |  | keyword |
| beyondtrust_epm.event.file.accessed |  | date |
| beyondtrust_epm.event.file.attributes |  | keyword |
| beyondtrust_epm.event.file.bundle.creator |  | keyword |
| beyondtrust_epm.event.file.bundle.download_source |  | keyword |
| beyondtrust_epm.event.file.bundle.info_description |  | keyword |
| beyondtrust_epm.event.file.bundle.name |  | keyword |
| beyondtrust_epm.event.file.bundle.type |  | keyword |
| beyondtrust_epm.event.file.bundle.uri |  | keyword |
| beyondtrust_epm.event.file.bundle.version |  | keyword |
| beyondtrust_epm.event.file.code_signature.digest_algorithm |  | keyword |
| beyondtrust_epm.event.file.code_signature.exists |  | boolean |
| beyondtrust_epm.event.file.code_signature.signing_id |  | keyword |
| beyondtrust_epm.event.file.code_signature.status |  | keyword |
| beyondtrust_epm.event.file.code_signature.subject_name |  | keyword |
| beyondtrust_epm.event.file.code_signature.team_id |  | keyword |
| beyondtrust_epm.event.file.code_signature.timestamp |  | date |
| beyondtrust_epm.event.file.code_signature.trusted |  | boolean |
| beyondtrust_epm.event.file.code_signature.valid |  | boolean |
| beyondtrust_epm.event.file.created |  | date |
| beyondtrust_epm.event.file.ctime |  | date |
| beyondtrust_epm.event.file.description |  | keyword |
| beyondtrust_epm.event.file.device |  | keyword |
| beyondtrust_epm.event.file.directory |  | keyword |
| beyondtrust_epm.event.file.drive_letter |  | keyword |
| beyondtrust_epm.event.file.drive_type |  | keyword |
| beyondtrust_epm.event.file.elf.architecture |  | keyword |
| beyondtrust_epm.event.file.elf.byte_order |  | keyword |
| beyondtrust_epm.event.file.elf.cpu_type |  | keyword |
| beyondtrust_epm.event.file.elf.creation_date |  | date |
| beyondtrust_epm.event.file.elf.exports.additional_prop |  | keyword |
| beyondtrust_epm.event.file.elf.header.abi_version |  | keyword |
| beyondtrust_epm.event.file.elf.header.class |  | keyword |
| beyondtrust_epm.event.file.elf.header.data |  | keyword |
| beyondtrust_epm.event.file.elf.header.entrypoint |  | long |
| beyondtrust_epm.event.file.elf.header.object_version |  | keyword |
| beyondtrust_epm.event.file.elf.header.os_abi |  | keyword |
| beyondtrust_epm.event.file.elf.header.type |  | keyword |
| beyondtrust_epm.event.file.elf.header.version |  | keyword |
| beyondtrust_epm.event.file.elf.imports.additional_prop |  | keyword |
| beyondtrust_epm.event.file.elf.sections.chi2 |  | long |
| beyondtrust_epm.event.file.elf.sections.entropy |  | long |
| beyondtrust_epm.event.file.elf.sections.flags |  | keyword |
| beyondtrust_epm.event.file.elf.sections.name |  | keyword |
| beyondtrust_epm.event.file.elf.sections.physical_offset |  | keyword |
| beyondtrust_epm.event.file.elf.sections.physical_size |  | long |
| beyondtrust_epm.event.file.elf.sections.type |  | keyword |
| beyondtrust_epm.event.file.elf.sections.virtual_address |  | long |
| beyondtrust_epm.event.file.elf.sections.virtual_size |  | long |
| beyondtrust_epm.event.file.elf.segments.sections |  | keyword |
| beyondtrust_epm.event.file.elf.segments.type |  | keyword |
| beyondtrust_epm.event.file.elf.shared_libraries |  | keyword |
| beyondtrust_epm.event.file.elf.telfhash |  | keyword |
| beyondtrust_epm.event.file.extension |  | keyword |
| beyondtrust_epm.event.file.fork_name |  | keyword |
| beyondtrust_epm.event.file.gid |  | keyword |
| beyondtrust_epm.event.file.group |  | keyword |
| beyondtrust_epm.event.file.hash.md5 |  | keyword |
| beyondtrust_epm.event.file.hash.sha1 |  | keyword |
| beyondtrust_epm.event.file.hash.sha256 |  | keyword |
| beyondtrust_epm.event.file.hash.sha384 |  | keyword |
| beyondtrust_epm.event.file.hash.sha512 |  | keyword |
| beyondtrust_epm.event.file.hash.ssdeep |  | keyword |
| beyondtrust_epm.event.file.hash.tlsh |  | keyword |
| beyondtrust_epm.event.file.inode |  | keyword |
| beyondtrust_epm.event.file.mime_type |  | keyword |
| beyondtrust_epm.event.file.mode |  | keyword |
| beyondtrust_epm.event.file.mtime |  | date |
| beyondtrust_epm.event.file.name |  | keyword |
| beyondtrust_epm.event.file.owner.domain_identifier |  | keyword |
| beyondtrust_epm.event.file.owner.domain_name |  | keyword |
| beyondtrust_epm.event.file.owner.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.file.owner.identifier |  | keyword |
| beyondtrust_epm.event.file.owner.name |  | keyword |
| beyondtrust_epm.event.file.owner_keyword |  | keyword |
| beyondtrust_epm.event.file.path |  | keyword |
| beyondtrust_epm.event.file.pe.architecture |  | keyword |
| beyondtrust_epm.event.file.pe.company |  | keyword |
| beyondtrust_epm.event.file.pe.description |  | keyword |
| beyondtrust_epm.event.file.pe.file_version |  | keyword |
| beyondtrust_epm.event.file.pe.imphash |  | keyword |
| beyondtrust_epm.event.file.pe.original_file_name |  | keyword |
| beyondtrust_epm.event.file.pe.pehash |  | keyword |
| beyondtrust_epm.event.file.pe.product |  | keyword |
| beyondtrust_epm.event.file.product_version |  | keyword |
| beyondtrust_epm.event.file.size |  | long |
| beyondtrust_epm.event.file.source_url |  | keyword |
| beyondtrust_epm.event.file.target_path |  | keyword |
| beyondtrust_epm.event.file.type |  | keyword |
| beyondtrust_epm.event.file.uid |  | keyword |
| beyondtrust_epm.event.file.version |  | keyword |
| beyondtrust_epm.event.file.x509.alternative_names |  | keyword |
| beyondtrust_epm.event.file.x509.issuer.common_name |  | keyword |
| beyondtrust_epm.event.file.x509.issuer.country |  | keyword |
| beyondtrust_epm.event.file.x509.issuer.distinguished_name |  | keyword |
| beyondtrust_epm.event.file.x509.issuer.locality |  | keyword |
| beyondtrust_epm.event.file.x509.issuer.organization |  | keyword |
| beyondtrust_epm.event.file.x509.issuer.organizational_unit |  | keyword |
| beyondtrust_epm.event.file.x509.issuer.state_or_province |  | keyword |
| beyondtrust_epm.event.file.x509.not_after |  | date |
| beyondtrust_epm.event.file.x509.not_before |  | date |
| beyondtrust_epm.event.file.x509.public_key_algorithm |  | keyword |
| beyondtrust_epm.event.file.x509.public_key_curve |  | keyword |
| beyondtrust_epm.event.file.x509.public_key_exponent |  | long |
| beyondtrust_epm.event.file.x509.public_key_size |  | long |
| beyondtrust_epm.event.file.x509.serial_number |  | keyword |
| beyondtrust_epm.event.file.x509.signature_algorithm |  | keyword |
| beyondtrust_epm.event.file.x509.subject.common_name |  | keyword |
| beyondtrust_epm.event.file.x509.subject.country |  | keyword |
| beyondtrust_epm.event.file.x509.subject.distinguished_name |  | keyword |
| beyondtrust_epm.event.file.x509.subject.locality |  | keyword |
| beyondtrust_epm.event.file.x509.subject.organization |  | keyword |
| beyondtrust_epm.event.file.x509.subject.organizational_unit |  | keyword |
| beyondtrust_epm.event.file.x509.subject.state_or_province |  | keyword |
| beyondtrust_epm.event.file.x509.version_number |  | keyword |
| beyondtrust_epm.event.file.zone_tag |  | keyword |
| beyondtrust_epm.event.group.domain |  | keyword |
| beyondtrust_epm.event.group.id |  | keyword |
| beyondtrust_epm.event.group.name |  | keyword |
| beyondtrust_epm.event.group_leader |  | flattened |
| beyondtrust_epm.event.host.architecture |  | keyword |
| beyondtrust_epm.event.host.boot.id |  | keyword |
| beyondtrust_epm.event.host.chassis_type |  | keyword |
| beyondtrust_epm.event.host.cpu.usage |  | scaled_float |
| beyondtrust_epm.event.host.default_locale |  | keyword |
| beyondtrust_epm.event.host.default_ui_language |  | keyword |
| beyondtrust_epm.event.host.disk.read.bytes |  | long |
| beyondtrust_epm.event.host.disk.write.bytes |  | long |
| beyondtrust_epm.event.host.domain |  | keyword |
| beyondtrust_epm.event.host.domain_identifier |  | keyword |
| beyondtrust_epm.event.host.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.host.geo.city_name |  | keyword |
| beyondtrust_epm.event.host.geo.continent_code |  | keyword |
| beyondtrust_epm.event.host.geo.continent_name |  | keyword |
| beyondtrust_epm.event.host.geo.country_iso_code |  | keyword |
| beyondtrust_epm.event.host.geo.country_name |  | keyword |
| beyondtrust_epm.event.host.geo.location.lat |  | long |
| beyondtrust_epm.event.host.geo.location.lon |  | long |
| beyondtrust_epm.event.host.geo.name |  | keyword |
| beyondtrust_epm.event.host.geo.postal_code |  | keyword |
| beyondtrust_epm.event.host.geo.region_iso_code |  | keyword |
| beyondtrust_epm.event.host.geo.region_name |  | keyword |
| beyondtrust_epm.event.host.geo.timezone |  | keyword |
| beyondtrust_epm.event.host.geo.timezone_offset |  | long |
| beyondtrust_epm.event.host.hostname |  | keyword |
| beyondtrust_epm.event.host.id |  | keyword |
| beyondtrust_epm.event.host.ip |  | ip |
| beyondtrust_epm.event.host.mac |  | keyword |
| beyondtrust_epm.event.host.name |  | keyword |
| beyondtrust_epm.event.host.net_bios_name |  | keyword |
| beyondtrust_epm.event.host.net_biosname |  | keyword |
| beyondtrust_epm.event.host.network.egress.bytes |  | long |
| beyondtrust_epm.event.host.network.egress.packets |  | long |
| beyondtrust_epm.event.host.network.ingress.bytes |  | long |
| beyondtrust_epm.event.host.network.ingress.packets |  | long |
| beyondtrust_epm.event.host.os.family |  | keyword |
| beyondtrust_epm.event.host.os.full |  | keyword |
| beyondtrust_epm.event.host.os.kernel |  | keyword |
| beyondtrust_epm.event.host.os.name |  | keyword |
| beyondtrust_epm.event.host.os.platform |  | keyword |
| beyondtrust_epm.event.host.os.product_type |  | keyword |
| beyondtrust_epm.event.host.os.type |  | keyword |
| beyondtrust_epm.event.host.os.version |  | keyword |
| beyondtrust_epm.event.host.pid_ns_ino |  | keyword |
| beyondtrust_epm.event.host.type |  | keyword |
| beyondtrust_epm.event.host.uptime |  | long |
| beyondtrust_epm.event.http.request.body.bytes |  | long |
| beyondtrust_epm.event.http.request.body.content |  | wildcard |
| beyondtrust_epm.event.http.request.bytes |  | long |
| beyondtrust_epm.event.http.request.id |  | keyword |
| beyondtrust_epm.event.http.request.method |  | keyword |
| beyondtrust_epm.event.http.request.mime_type |  | keyword |
| beyondtrust_epm.event.http.request.referrer |  | keyword |
| beyondtrust_epm.event.http.response.body.bytes |  | long |
| beyondtrust_epm.event.http.response.body.content |  | wildcard |
| beyondtrust_epm.event.http.response.bytes |  | long |
| beyondtrust_epm.event.http.response.mime_type |  | keyword |
| beyondtrust_epm.event.http.response.status_code |  | long |
| beyondtrust_epm.event.http.version |  | keyword |
| beyondtrust_epm.event.labels |  | keyword |
| beyondtrust_epm.event.log.file.path |  | keyword |
| beyondtrust_epm.event.log.level |  | keyword |
| beyondtrust_epm.event.log.logger |  | keyword |
| beyondtrust_epm.event.log.origin.file.line |  | long |
| beyondtrust_epm.event.log.origin.file.name |  | keyword |
| beyondtrust_epm.event.log.origin.function |  | keyword |
| beyondtrust_epm.event.log.syslog |  | keyword |
| beyondtrust_epm.event.message |  | match_only_text |
| beyondtrust_epm.event.network.application |  | keyword |
| beyondtrust_epm.event.network.bytes |  | long |
| beyondtrust_epm.event.network.community_id |  | keyword |
| beyondtrust_epm.event.network.direction |  | keyword |
| beyondtrust_epm.event.network.forwarded_ip |  | ip |
| beyondtrust_epm.event.network.iana_number |  | keyword |
| beyondtrust_epm.event.network.inner |  | keyword |
| beyondtrust_epm.event.network.name |  | keyword |
| beyondtrust_epm.event.network.packets |  | long |
| beyondtrust_epm.event.network.protocol |  | keyword |
| beyondtrust_epm.event.network.transport |  | keyword |
| beyondtrust_epm.event.network.type |  | keyword |
| beyondtrust_epm.event.network.vlan.id |  | keyword |
| beyondtrust_epm.event.network.vlan.name |  | keyword |
| beyondtrust_epm.event.observer.egress |  | keyword |
| beyondtrust_epm.event.observer.geo.city_name |  | keyword |
| beyondtrust_epm.event.observer.geo.continent_code |  | keyword |
| beyondtrust_epm.event.observer.geo.continent_name |  | keyword |
| beyondtrust_epm.event.observer.geo.country_iso_code |  | keyword |
| beyondtrust_epm.event.observer.geo.country_name |  | keyword |
| beyondtrust_epm.event.observer.geo.location.lat |  | long |
| beyondtrust_epm.event.observer.geo.location.lon |  | long |
| beyondtrust_epm.event.observer.geo.name |  | keyword |
| beyondtrust_epm.event.observer.geo.postal_code |  | keyword |
| beyondtrust_epm.event.observer.geo.region_iso_code |  | keyword |
| beyondtrust_epm.event.observer.geo.region_name |  | keyword |
| beyondtrust_epm.event.observer.geo.timezone |  | keyword |
| beyondtrust_epm.event.observer.geo.timezone_offset |  | long |
| beyondtrust_epm.event.observer.hostname |  | keyword |
| beyondtrust_epm.event.observer.ingress |  | keyword |
| beyondtrust_epm.event.observer.ip |  | ip |
| beyondtrust_epm.event.observer.mac |  | keyword |
| beyondtrust_epm.event.observer.name |  | keyword |
| beyondtrust_epm.event.observer.os.family |  | keyword |
| beyondtrust_epm.event.observer.os.full |  | keyword |
| beyondtrust_epm.event.observer.os.kernel |  | keyword |
| beyondtrust_epm.event.observer.os.name |  | keyword |
| beyondtrust_epm.event.observer.os.platform |  | keyword |
| beyondtrust_epm.event.observer.os.product_type |  | keyword |
| beyondtrust_epm.event.observer.os.type |  | keyword |
| beyondtrust_epm.event.observer.os.version |  | keyword |
| beyondtrust_epm.event.observer.product |  | keyword |
| beyondtrust_epm.event.observer.serial_number |  | keyword |
| beyondtrust_epm.event.observer.type |  | keyword |
| beyondtrust_epm.event.observer.vendor |  | keyword |
| beyondtrust_epm.event.observer.version |  | keyword |
| beyondtrust_epm.event.orchestrator.api_version |  | keyword |
| beyondtrust_epm.event.orchestrator.cluster.id |  | keyword |
| beyondtrust_epm.event.orchestrator.cluster.name |  | keyword |
| beyondtrust_epm.event.orchestrator.cluster.url |  | keyword |
| beyondtrust_epm.event.orchestrator.cluster.version |  | keyword |
| beyondtrust_epm.event.orchestrator.namespace |  | keyword |
| beyondtrust_epm.event.orchestrator.organization |  | keyword |
| beyondtrust_epm.event.orchestrator.resource.id |  | keyword |
| beyondtrust_epm.event.orchestrator.resource.ip |  | ip |
| beyondtrust_epm.event.orchestrator.resource.name |  | keyword |
| beyondtrust_epm.event.orchestrator.resource.parent.type |  | keyword |
| beyondtrust_epm.event.orchestrator.resource.type |  | keyword |
| beyondtrust_epm.event.orchestrator.type |  | keyword |
| beyondtrust_epm.event.organization.id |  | keyword |
| beyondtrust_epm.event.organization.name |  | keyword |
| beyondtrust_epm.event.package.architecture |  | keyword |
| beyondtrust_epm.event.package.build_version |  | keyword |
| beyondtrust_epm.event.package.checksum |  | keyword |
| beyondtrust_epm.event.package.description |  | keyword |
| beyondtrust_epm.event.package.install_scope |  | keyword |
| beyondtrust_epm.event.package.installed |  | date |
| beyondtrust_epm.event.package.license |  | keyword |
| beyondtrust_epm.event.package.name |  | keyword |
| beyondtrust_epm.event.package.path |  | keyword |
| beyondtrust_epm.event.package.reference |  | keyword |
| beyondtrust_epm.event.package.size |  | long |
| beyondtrust_epm.event.package.type |  | keyword |
| beyondtrust_epm.event.package.version |  | keyword |
| beyondtrust_epm.event.process.args |  | keyword |
| beyondtrust_epm.event.process.args_count |  | long |
| beyondtrust_epm.event.process.code_signature.digest_algorithm |  | keyword |
| beyondtrust_epm.event.process.code_signature.exists |  | boolean |
| beyondtrust_epm.event.process.code_signature.signing_id |  | keyword |
| beyondtrust_epm.event.process.code_signature.status |  | keyword |
| beyondtrust_epm.event.process.code_signature.subject_name |  | keyword |
| beyondtrust_epm.event.process.code_signature.team_id |  | keyword |
| beyondtrust_epm.event.process.code_signature.timestamp |  | date |
| beyondtrust_epm.event.process.code_signature.trusted |  | boolean |
| beyondtrust_epm.event.process.code_signature.valid |  | boolean |
| beyondtrust_epm.event.process.command_line |  | wildcard |
| beyondtrust_epm.event.process.elevation_required |  | boolean |
| beyondtrust_epm.event.process.elf.architecture |  | keyword |
| beyondtrust_epm.event.process.elf.byte_order |  | keyword |
| beyondtrust_epm.event.process.elf.cpu_type |  | keyword |
| beyondtrust_epm.event.process.elf.creation_date |  | date |
| beyondtrust_epm.event.process.elf.exports.additional_prop |  | keyword |
| beyondtrust_epm.event.process.elf.header.abi_version |  | keyword |
| beyondtrust_epm.event.process.elf.header.class |  | keyword |
| beyondtrust_epm.event.process.elf.header.data |  | keyword |
| beyondtrust_epm.event.process.elf.header.entrypoint |  | long |
| beyondtrust_epm.event.process.elf.header.object_version |  | keyword |
| beyondtrust_epm.event.process.elf.header.os_abi |  | keyword |
| beyondtrust_epm.event.process.elf.header.type |  | keyword |
| beyondtrust_epm.event.process.elf.header.version |  | keyword |
| beyondtrust_epm.event.process.elf.imports.additional_prop |  | keyword |
| beyondtrust_epm.event.process.elf.sections.chi2 |  | long |
| beyondtrust_epm.event.process.elf.sections.entropy |  | long |
| beyondtrust_epm.event.process.elf.sections.flags |  | keyword |
| beyondtrust_epm.event.process.elf.sections.name |  | keyword |
| beyondtrust_epm.event.process.elf.sections.physical_offset |  | keyword |
| beyondtrust_epm.event.process.elf.sections.physical_size |  | long |
| beyondtrust_epm.event.process.elf.sections.type |  | keyword |
| beyondtrust_epm.event.process.elf.sections.virtual_address |  | long |
| beyondtrust_epm.event.process.elf.sections.virtual_size |  | long |
| beyondtrust_epm.event.process.elf.segments.sections |  | keyword |
| beyondtrust_epm.event.process.elf.segments.type |  | keyword |
| beyondtrust_epm.event.process.elf.shared_libraries |  | keyword |
| beyondtrust_epm.event.process.elf.telfhash |  | keyword |
| beyondtrust_epm.event.process.end |  | date |
| beyondtrust_epm.event.process.entity_id |  | keyword |
| beyondtrust_epm.event.process.entry_leader |  | flattened |
| beyondtrust_epm.event.process.entry_meta.source.address |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.as.number |  | long |
| beyondtrust_epm.event.process.entry_meta.source.as.organization.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.bytes |  | long |
| beyondtrust_epm.event.process.entry_meta.source.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.city_name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.continent_code |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.continent_name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.country_iso_code |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.country_name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.location.lat |  | long |
| beyondtrust_epm.event.process.entry_meta.source.geo.location.lon |  | long |
| beyondtrust_epm.event.process.entry_meta.source.geo.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.postal_code |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.region_iso_code |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.region_name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.timezone |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.geo.timezone_offset |  | long |
| beyondtrust_epm.event.process.entry_meta.source.ip |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.mac |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.nat.ip |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.nat.port |  | long |
| beyondtrust_epm.event.process.entry_meta.source.packets |  | long |
| beyondtrust_epm.event.process.entry_meta.source.port |  | long |
| beyondtrust_epm.event.process.entry_meta.source.registered_domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.subdomain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.top_level_domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.default_timezone_offset |  | long |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.email |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.full_name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.group.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.group.id |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.group.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.hash |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.id |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.local_identifier |  | long |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.changes.roles |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.default_timezone_offset |  | long |
| beyondtrust_epm.event.process.entry_meta.source.user.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.default_timezone_offset |  | long |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.email |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.full_name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.group.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.group.id |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.group.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.hash |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.id |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.local_identifier |  | long |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.effective.roles |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.email |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.full_name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.group.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.group.id |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.group.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.hash |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.id |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.local_identifier |  | long |
| beyondtrust_epm.event.process.entry_meta.source.user.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.roles |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.default_timezone_offset |  | long |
| beyondtrust_epm.event.process.entry_meta.source.user.target.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.email |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.full_name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.group.domain |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.group.id |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.group.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.hash |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.id |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.local_identifier |  | long |
| beyondtrust_epm.event.process.entry_meta.source.user.target.name |  | keyword |
| beyondtrust_epm.event.process.entry_meta.source.user.target.roles |  | keyword |
| beyondtrust_epm.event.process.entry_meta.type |  | keyword |
| beyondtrust_epm.event.process.env_vars |  | keyword |
| beyondtrust_epm.event.process.executable |  | keyword |
| beyondtrust_epm.event.process.exit_code |  | long |
| beyondtrust_epm.event.process.group.domain |  | keyword |
| beyondtrust_epm.event.process.group.id |  | keyword |
| beyondtrust_epm.event.process.group.name |  | keyword |
| beyondtrust_epm.event.process.hash.md5 |  | keyword |
| beyondtrust_epm.event.process.hash.sha1 |  | keyword |
| beyondtrust_epm.event.process.hash.sha256 |  | keyword |
| beyondtrust_epm.event.process.hash.sha384 |  | keyword |
| beyondtrust_epm.event.process.hash.sha512 |  | keyword |
| beyondtrust_epm.event.process.hash.ssdeep |  | keyword |
| beyondtrust_epm.event.process.hash.tlsh |  | keyword |
| beyondtrust_epm.event.process.hosted_file.accessed |  | date |
| beyondtrust_epm.event.process.hosted_file.attributes |  | keyword |
| beyondtrust_epm.event.process.hosted_file.bundle.creator |  | keyword |
| beyondtrust_epm.event.process.hosted_file.bundle.download_source |  | keyword |
| beyondtrust_epm.event.process.hosted_file.bundle.info_description |  | keyword |
| beyondtrust_epm.event.process.hosted_file.bundle.name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.bundle.type |  | keyword |
| beyondtrust_epm.event.process.hosted_file.bundle.uri |  | keyword |
| beyondtrust_epm.event.process.hosted_file.bundle.version |  | keyword |
| beyondtrust_epm.event.process.hosted_file.code_signature.digest_algorithm |  | keyword |
| beyondtrust_epm.event.process.hosted_file.code_signature.exists |  | boolean |
| beyondtrust_epm.event.process.hosted_file.code_signature.signing_id |  | keyword |
| beyondtrust_epm.event.process.hosted_file.code_signature.status |  | keyword |
| beyondtrust_epm.event.process.hosted_file.code_signature.subject_name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.code_signature.team_id |  | keyword |
| beyondtrust_epm.event.process.hosted_file.code_signature.timestamp |  | date |
| beyondtrust_epm.event.process.hosted_file.code_signature.trusted |  | boolean |
| beyondtrust_epm.event.process.hosted_file.code_signature.valid |  | boolean |
| beyondtrust_epm.event.process.hosted_file.created |  | date |
| beyondtrust_epm.event.process.hosted_file.ctime |  | date |
| beyondtrust_epm.event.process.hosted_file.description |  | keyword |
| beyondtrust_epm.event.process.hosted_file.device |  | keyword |
| beyondtrust_epm.event.process.hosted_file.directory |  | keyword |
| beyondtrust_epm.event.process.hosted_file.drive_letter |  | keyword |
| beyondtrust_epm.event.process.hosted_file.drive_type |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.architecture |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.byte_order |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.cpu_type |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.creation_date |  | date |
| beyondtrust_epm.event.process.hosted_file.elf.exports.additional_prop |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.header.abi_version |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.header.class |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.header.data |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.header.entrypoint |  | long |
| beyondtrust_epm.event.process.hosted_file.elf.header.object_version |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.header.os_abi |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.header.type |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.header.version |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.imports.additional_prop |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.sections.chi2 |  | long |
| beyondtrust_epm.event.process.hosted_file.elf.sections.entropy |  | long |
| beyondtrust_epm.event.process.hosted_file.elf.sections.flags |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.sections.name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.sections.physical_offset |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.sections.physical_size |  | long |
| beyondtrust_epm.event.process.hosted_file.elf.sections.type |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.sections.virtual_address |  | long |
| beyondtrust_epm.event.process.hosted_file.elf.sections.virtual_size |  | long |
| beyondtrust_epm.event.process.hosted_file.elf.segments.sections |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.segments.type |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.shared_libraries |  | keyword |
| beyondtrust_epm.event.process.hosted_file.elf.telfhash |  | keyword |
| beyondtrust_epm.event.process.hosted_file.extension |  | keyword |
| beyondtrust_epm.event.process.hosted_file.fork_name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.gid |  | keyword |
| beyondtrust_epm.event.process.hosted_file.group |  | keyword |
| beyondtrust_epm.event.process.hosted_file.hash.md5 |  | keyword |
| beyondtrust_epm.event.process.hosted_file.hash.sha1 |  | keyword |
| beyondtrust_epm.event.process.hosted_file.hash.sha256 |  | keyword |
| beyondtrust_epm.event.process.hosted_file.hash.sha384 |  | keyword |
| beyondtrust_epm.event.process.hosted_file.hash.sha512 |  | keyword |
| beyondtrust_epm.event.process.hosted_file.hash.ssdeep |  | keyword |
| beyondtrust_epm.event.process.hosted_file.hash.tlsh |  | keyword |
| beyondtrust_epm.event.process.hosted_file.inode |  | keyword |
| beyondtrust_epm.event.process.hosted_file.mime_type |  | keyword |
| beyondtrust_epm.event.process.hosted_file.mode |  | keyword |
| beyondtrust_epm.event.process.hosted_file.mtime |  | date |
| beyondtrust_epm.event.process.hosted_file.name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.owner.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.hosted_file.owner.domain_name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.owner.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.hosted_file.owner.identifier |  | keyword |
| beyondtrust_epm.event.process.hosted_file.owner.name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.owner_keyword |  | keyword |
| beyondtrust_epm.event.process.hosted_file.path |  | keyword |
| beyondtrust_epm.event.process.hosted_file.pe.architecture |  | keyword |
| beyondtrust_epm.event.process.hosted_file.pe.company |  | keyword |
| beyondtrust_epm.event.process.hosted_file.pe.description |  | keyword |
| beyondtrust_epm.event.process.hosted_file.pe.file_version |  | keyword |
| beyondtrust_epm.event.process.hosted_file.pe.imphash |  | keyword |
| beyondtrust_epm.event.process.hosted_file.pe.original_file_name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.pe.pehash |  | keyword |
| beyondtrust_epm.event.process.hosted_file.pe.product |  | keyword |
| beyondtrust_epm.event.process.hosted_file.product_version |  | keyword |
| beyondtrust_epm.event.process.hosted_file.size |  | long |
| beyondtrust_epm.event.process.hosted_file.source_url |  | keyword |
| beyondtrust_epm.event.process.hosted_file.target_path |  | keyword |
| beyondtrust_epm.event.process.hosted_file.type |  | keyword |
| beyondtrust_epm.event.process.hosted_file.uid |  | keyword |
| beyondtrust_epm.event.process.hosted_file.version |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.alternative_names |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.issuer.common_name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.issuer.country |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.issuer.distinguished_name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.issuer.locality |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.issuer.organization |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.issuer.organizational_unit |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.issuer.state_or_province |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.not_after |  | date |
| beyondtrust_epm.event.process.hosted_file.x509.not_before |  | date |
| beyondtrust_epm.event.process.hosted_file.x509.public_key_algorithm |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.public_key_curve |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.public_key_exponent |  | long |
| beyondtrust_epm.event.process.hosted_file.x509.public_key_size |  | long |
| beyondtrust_epm.event.process.hosted_file.x509.serial_number |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.signature_algorithm |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.subject.common_name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.subject.country |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.subject.distinguished_name |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.subject.locality |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.subject.organization |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.subject.organizational_unit |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.subject.state_or_province |  | keyword |
| beyondtrust_epm.event.process.hosted_file.x509.version_number |  | keyword |
| beyondtrust_epm.event.process.hosted_file.zone_tag |  | keyword |
| beyondtrust_epm.event.process.interactive |  | boolean |
| beyondtrust_epm.event.process.name |  | keyword |
| beyondtrust_epm.event.process.parent |  | flattened |
| beyondtrust_epm.event.process.pe.architecture |  | keyword |
| beyondtrust_epm.event.process.pe.company |  | keyword |
| beyondtrust_epm.event.process.pe.description |  | keyword |
| beyondtrust_epm.event.process.pe.file_version |  | keyword |
| beyondtrust_epm.event.process.pe.imphash |  | keyword |
| beyondtrust_epm.event.process.pe.original_file_name |  | keyword |
| beyondtrust_epm.event.process.pe.pehash |  | keyword |
| beyondtrust_epm.event.process.pe.product |  | keyword |
| beyondtrust_epm.event.process.pgid |  | long |
| beyondtrust_epm.event.process.pid |  | long |
| beyondtrust_epm.event.process.previous |  | flattened |
| beyondtrust_epm.event.process.real_group |  | flattened |
| beyondtrust_epm.event.process.real_user |  | flattened |
| beyondtrust_epm.event.process.same_as_process |  | boolean |
| beyondtrust_epm.event.process.saved_group |  | flattened |
| beyondtrust_epm.event.process.saved_user |  | flattened |
| beyondtrust_epm.event.process.session_leader |  | flattened |
| beyondtrust_epm.event.process.start |  | date |
| beyondtrust_epm.event.process.supplemental_groups |  | flattened |
| beyondtrust_epm.event.process.thread.id |  | long |
| beyondtrust_epm.event.process.thread.name |  | keyword |
| beyondtrust_epm.event.process.title |  | keyword |
| beyondtrust_epm.event.process.tty |  | keyword |
| beyondtrust_epm.event.process.uptime |  | long |
| beyondtrust_epm.event.process.user.changes.default_timezone_offset |  | long |
| beyondtrust_epm.event.process.user.changes.domain |  | keyword |
| beyondtrust_epm.event.process.user.changes.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.user.changes.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.user.changes.email |  | keyword |
| beyondtrust_epm.event.process.user.changes.full_name |  | keyword |
| beyondtrust_epm.event.process.user.changes.group.domain |  | keyword |
| beyondtrust_epm.event.process.user.changes.group.id |  | keyword |
| beyondtrust_epm.event.process.user.changes.group.name |  | keyword |
| beyondtrust_epm.event.process.user.changes.hash |  | keyword |
| beyondtrust_epm.event.process.user.changes.id |  | keyword |
| beyondtrust_epm.event.process.user.changes.local_identifier |  | long |
| beyondtrust_epm.event.process.user.changes.name |  | keyword |
| beyondtrust_epm.event.process.user.changes.roles |  | keyword |
| beyondtrust_epm.event.process.user.default_timezone_offset |  | long |
| beyondtrust_epm.event.process.user.domain |  | keyword |
| beyondtrust_epm.event.process.user.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.user.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.user.effective.default_timezone_offset |  | long |
| beyondtrust_epm.event.process.user.effective.domain |  | keyword |
| beyondtrust_epm.event.process.user.effective.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.user.effective.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.user.effective.email |  | keyword |
| beyondtrust_epm.event.process.user.effective.full_name |  | keyword |
| beyondtrust_epm.event.process.user.effective.group.domain |  | keyword |
| beyondtrust_epm.event.process.user.effective.group.id |  | keyword |
| beyondtrust_epm.event.process.user.effective.group.name |  | keyword |
| beyondtrust_epm.event.process.user.effective.hash |  | keyword |
| beyondtrust_epm.event.process.user.effective.id |  | keyword |
| beyondtrust_epm.event.process.user.effective.local_identifier |  | long |
| beyondtrust_epm.event.process.user.effective.name |  | keyword |
| beyondtrust_epm.event.process.user.effective.roles |  | keyword |
| beyondtrust_epm.event.process.user.email |  | keyword |
| beyondtrust_epm.event.process.user.full_name |  | keyword |
| beyondtrust_epm.event.process.user.group.domain |  | keyword |
| beyondtrust_epm.event.process.user.group.id |  | keyword |
| beyondtrust_epm.event.process.user.group.name |  | keyword |
| beyondtrust_epm.event.process.user.hash |  | keyword |
| beyondtrust_epm.event.process.user.id |  | keyword |
| beyondtrust_epm.event.process.user.local_identifier |  | long |
| beyondtrust_epm.event.process.user.name |  | keyword |
| beyondtrust_epm.event.process.user.roles |  | keyword |
| beyondtrust_epm.event.process.user.target.default_timezone_offset |  | long |
| beyondtrust_epm.event.process.user.target.domain |  | keyword |
| beyondtrust_epm.event.process.user.target.domain_identifier |  | keyword |
| beyondtrust_epm.event.process.user.target.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.process.user.target.email |  | keyword |
| beyondtrust_epm.event.process.user.target.full_name |  | keyword |
| beyondtrust_epm.event.process.user.target.group.domain |  | keyword |
| beyondtrust_epm.event.process.user.target.group.id |  | keyword |
| beyondtrust_epm.event.process.user.target.group.name |  | keyword |
| beyondtrust_epm.event.process.user.target.hash |  | keyword |
| beyondtrust_epm.event.process.user.target.id |  | keyword |
| beyondtrust_epm.event.process.user.target.local_identifier |  | long |
| beyondtrust_epm.event.process.user.target.name |  | keyword |
| beyondtrust_epm.event.process.user.target.roles |  | keyword |
| beyondtrust_epm.event.process.working_directory |  | keyword |
| beyondtrust_epm.event.registry.data.bytes |  | keyword |
| beyondtrust_epm.event.registry.data.strings |  | wildcard |
| beyondtrust_epm.event.registry.data.type |  | keyword |
| beyondtrust_epm.event.registry.hive |  | keyword |
| beyondtrust_epm.event.registry.key |  | keyword |
| beyondtrust_epm.event.registry.path |  | keyword |
| beyondtrust_epm.event.registry.value |  | keyword |
| beyondtrust_epm.event.related.hash |  | keyword |
| beyondtrust_epm.event.related.hosts |  | keyword |
| beyondtrust_epm.event.related.ip |  | ip |
| beyondtrust_epm.event.related.user |  | keyword |
| beyondtrust_epm.event.rule.author |  | keyword |
| beyondtrust_epm.event.rule.category |  | keyword |
| beyondtrust_epm.event.rule.description |  | keyword |
| beyondtrust_epm.event.rule.id |  | keyword |
| beyondtrust_epm.event.rule.license |  | keyword |
| beyondtrust_epm.event.rule.name |  | keyword |
| beyondtrust_epm.event.rule.reference |  | keyword |
| beyondtrust_epm.event.rule.ruleset |  | keyword |
| beyondtrust_epm.event.rule.uuid |  | keyword |
| beyondtrust_epm.event.rule.version |  | keyword |
| beyondtrust_epm.event.server.address |  | keyword |
| beyondtrust_epm.event.server.as.number |  | long |
| beyondtrust_epm.event.server.as.organization.name |  | keyword |
| beyondtrust_epm.event.server.bytes |  | long |
| beyondtrust_epm.event.server.domain |  | keyword |
| beyondtrust_epm.event.server.geo.city_name |  | keyword |
| beyondtrust_epm.event.server.geo.continent_code |  | keyword |
| beyondtrust_epm.event.server.geo.continent_name |  | keyword |
| beyondtrust_epm.event.server.geo.country_iso_code |  | keyword |
| beyondtrust_epm.event.server.geo.country_name |  | keyword |
| beyondtrust_epm.event.server.geo.location.lat |  | long |
| beyondtrust_epm.event.server.geo.location.lon |  | long |
| beyondtrust_epm.event.server.geo.name |  | keyword |
| beyondtrust_epm.event.server.geo.postal_code |  | keyword |
| beyondtrust_epm.event.server.geo.region_iso_code |  | keyword |
| beyondtrust_epm.event.server.geo.region_name |  | keyword |
| beyondtrust_epm.event.server.geo.timezone |  | keyword |
| beyondtrust_epm.event.server.geo.timezone_offset |  | long |
| beyondtrust_epm.event.server.ip |  | ip |
| beyondtrust_epm.event.server.mac |  | keyword |
| beyondtrust_epm.event.server.nat.ip |  | ip |
| beyondtrust_epm.event.server.nat.port |  | long |
| beyondtrust_epm.event.server.packets |  | long |
| beyondtrust_epm.event.server.port |  | long |
| beyondtrust_epm.event.server.registered_domain |  | keyword |
| beyondtrust_epm.event.server.subdomain |  | keyword |
| beyondtrust_epm.event.server.top_level_domain |  | keyword |
| beyondtrust_epm.event.server.user.changes.default_timezone_offset |  | long |
| beyondtrust_epm.event.server.user.changes.domain |  | keyword |
| beyondtrust_epm.event.server.user.changes.domain_identifier |  | keyword |
| beyondtrust_epm.event.server.user.changes.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.server.user.changes.email |  | keyword |
| beyondtrust_epm.event.server.user.changes.full_name |  | keyword |
| beyondtrust_epm.event.server.user.changes.group.domain |  | keyword |
| beyondtrust_epm.event.server.user.changes.group.id |  | keyword |
| beyondtrust_epm.event.server.user.changes.group.name |  | keyword |
| beyondtrust_epm.event.server.user.changes.hash |  | keyword |
| beyondtrust_epm.event.server.user.changes.id |  | keyword |
| beyondtrust_epm.event.server.user.changes.local_identifier |  | long |
| beyondtrust_epm.event.server.user.changes.name |  | keyword |
| beyondtrust_epm.event.server.user.changes.roles |  | keyword |
| beyondtrust_epm.event.server.user.default_timezone_offset |  | long |
| beyondtrust_epm.event.server.user.domain |  | keyword |
| beyondtrust_epm.event.server.user.domain_identifier |  | keyword |
| beyondtrust_epm.event.server.user.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.server.user.effective.default_timezone_offset |  | long |
| beyondtrust_epm.event.server.user.effective.domain |  | keyword |
| beyondtrust_epm.event.server.user.effective.domain_identifier |  | keyword |
| beyondtrust_epm.event.server.user.effective.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.server.user.effective.email |  | keyword |
| beyondtrust_epm.event.server.user.effective.full_name |  | keyword |
| beyondtrust_epm.event.server.user.effective.group.domain |  | keyword |
| beyondtrust_epm.event.server.user.effective.group.id |  | keyword |
| beyondtrust_epm.event.server.user.effective.group.name |  | keyword |
| beyondtrust_epm.event.server.user.effective.hash |  | keyword |
| beyondtrust_epm.event.server.user.effective.id |  | keyword |
| beyondtrust_epm.event.server.user.effective.local_identifier |  | long |
| beyondtrust_epm.event.server.user.effective.name |  | keyword |
| beyondtrust_epm.event.server.user.effective.roles |  | keyword |
| beyondtrust_epm.event.server.user.email |  | keyword |
| beyondtrust_epm.event.server.user.full_name |  | keyword |
| beyondtrust_epm.event.server.user.group.domain |  | keyword |
| beyondtrust_epm.event.server.user.group.id |  | keyword |
| beyondtrust_epm.event.server.user.group.name |  | keyword |
| beyondtrust_epm.event.server.user.hash |  | keyword |
| beyondtrust_epm.event.server.user.id |  | keyword |
| beyondtrust_epm.event.server.user.local_identifier |  | long |
| beyondtrust_epm.event.server.user.name |  | keyword |
| beyondtrust_epm.event.server.user.roles |  | keyword |
| beyondtrust_epm.event.server.user.target.default_timezone_offset |  | long |
| beyondtrust_epm.event.server.user.target.domain |  | keyword |
| beyondtrust_epm.event.server.user.target.domain_identifier |  | keyword |
| beyondtrust_epm.event.server.user.target.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.server.user.target.email |  | keyword |
| beyondtrust_epm.event.server.user.target.full_name |  | keyword |
| beyondtrust_epm.event.server.user.target.group.domain |  | keyword |
| beyondtrust_epm.event.server.user.target.group.id |  | keyword |
| beyondtrust_epm.event.server.user.target.group.name |  | keyword |
| beyondtrust_epm.event.server.user.target.hash |  | keyword |
| beyondtrust_epm.event.server.user.target.id |  | keyword |
| beyondtrust_epm.event.server.user.target.local_identifier |  | long |
| beyondtrust_epm.event.server.user.target.name |  | keyword |
| beyondtrust_epm.event.server.user.target.roles |  | keyword |
| beyondtrust_epm.event.service.address |  | keyword |
| beyondtrust_epm.event.service.environment |  | keyword |
| beyondtrust_epm.event.service.ephemeral_id |  | keyword |
| beyondtrust_epm.event.service.id |  | keyword |
| beyondtrust_epm.event.service.name |  | keyword |
| beyondtrust_epm.event.service.node.name |  | keyword |
| beyondtrust_epm.event.service.node.role |  | keyword |
| beyondtrust_epm.event.service.origin.address |  | keyword |
| beyondtrust_epm.event.service.origin.environment |  | keyword |
| beyondtrust_epm.event.service.origin.ephemeral_id |  | keyword |
| beyondtrust_epm.event.service.origin.id |  | keyword |
| beyondtrust_epm.event.service.origin.name |  | keyword |
| beyondtrust_epm.event.service.origin.node.name |  | keyword |
| beyondtrust_epm.event.service.origin.node.role |  | keyword |
| beyondtrust_epm.event.service.origin.state |  | keyword |
| beyondtrust_epm.event.service.origin.type |  | keyword |
| beyondtrust_epm.event.service.origin.version |  | keyword |
| beyondtrust_epm.event.service.state |  | keyword |
| beyondtrust_epm.event.service.target.address |  | keyword |
| beyondtrust_epm.event.service.target.environment |  | keyword |
| beyondtrust_epm.event.service.target.ephemeral_id |  | keyword |
| beyondtrust_epm.event.service.target.id |  | keyword |
| beyondtrust_epm.event.service.target.name |  | keyword |
| beyondtrust_epm.event.service.target.node.name |  | keyword |
| beyondtrust_epm.event.service.target.node.role |  | keyword |
| beyondtrust_epm.event.service.target.state |  | keyword |
| beyondtrust_epm.event.service.target.type |  | keyword |
| beyondtrust_epm.event.service.target.version |  | keyword |
| beyondtrust_epm.event.service.type |  | keyword |
| beyondtrust_epm.event.service.version |  | keyword |
| beyondtrust_epm.event.source.address |  | keyword |
| beyondtrust_epm.event.source.as.number |  | long |
| beyondtrust_epm.event.source.as.organization.name |  | keyword |
| beyondtrust_epm.event.source.bytes |  | long |
| beyondtrust_epm.event.source.domain |  | keyword |
| beyondtrust_epm.event.source.geo.city_name |  | keyword |
| beyondtrust_epm.event.source.geo.continent_code |  | keyword |
| beyondtrust_epm.event.source.geo.continent_name |  | keyword |
| beyondtrust_epm.event.source.geo.country_iso_code |  | keyword |
| beyondtrust_epm.event.source.geo.country_name |  | keyword |
| beyondtrust_epm.event.source.geo.location.lat |  | long |
| beyondtrust_epm.event.source.geo.location.lon |  | long |
| beyondtrust_epm.event.source.geo.name |  | keyword |
| beyondtrust_epm.event.source.geo.postal_code |  | keyword |
| beyondtrust_epm.event.source.geo.region_iso_code |  | keyword |
| beyondtrust_epm.event.source.geo.region_name |  | keyword |
| beyondtrust_epm.event.source.geo.timezone |  | keyword |
| beyondtrust_epm.event.source.geo.timezone_offset |  | long |
| beyondtrust_epm.event.source.ip |  | ip |
| beyondtrust_epm.event.source.mac |  | keyword |
| beyondtrust_epm.event.source.nat.ip |  | ip |
| beyondtrust_epm.event.source.nat.port |  | long |
| beyondtrust_epm.event.source.packets |  | long |
| beyondtrust_epm.event.source.port |  | long |
| beyondtrust_epm.event.source.registered_domain |  | keyword |
| beyondtrust_epm.event.source.subdomain |  | keyword |
| beyondtrust_epm.event.source.top_level_domain |  | keyword |
| beyondtrust_epm.event.source.user.changes.default_timezone_offset |  | long |
| beyondtrust_epm.event.source.user.changes.domain |  | keyword |
| beyondtrust_epm.event.source.user.changes.domain_identifier |  | keyword |
| beyondtrust_epm.event.source.user.changes.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.source.user.changes.email |  | keyword |
| beyondtrust_epm.event.source.user.changes.full_name |  | keyword |
| beyondtrust_epm.event.source.user.changes.group.domain |  | keyword |
| beyondtrust_epm.event.source.user.changes.group.id |  | keyword |
| beyondtrust_epm.event.source.user.changes.group.name |  | keyword |
| beyondtrust_epm.event.source.user.changes.hash |  | keyword |
| beyondtrust_epm.event.source.user.changes.id |  | keyword |
| beyondtrust_epm.event.source.user.changes.local_identifier |  | long |
| beyondtrust_epm.event.source.user.changes.name |  | keyword |
| beyondtrust_epm.event.source.user.changes.roles |  | keyword |
| beyondtrust_epm.event.source.user.default_timezone_offset |  | long |
| beyondtrust_epm.event.source.user.domain |  | keyword |
| beyondtrust_epm.event.source.user.domain_identifier |  | keyword |
| beyondtrust_epm.event.source.user.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.source.user.effective.default_timezone_offset |  | long |
| beyondtrust_epm.event.source.user.effective.domain |  | keyword |
| beyondtrust_epm.event.source.user.effective.domain_identifier |  | keyword |
| beyondtrust_epm.event.source.user.effective.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.source.user.effective.email |  | keyword |
| beyondtrust_epm.event.source.user.effective.full_name |  | keyword |
| beyondtrust_epm.event.source.user.effective.group.domain |  | keyword |
| beyondtrust_epm.event.source.user.effective.group.id |  | keyword |
| beyondtrust_epm.event.source.user.effective.group.name |  | keyword |
| beyondtrust_epm.event.source.user.effective.hash |  | keyword |
| beyondtrust_epm.event.source.user.effective.id |  | keyword |
| beyondtrust_epm.event.source.user.effective.local_identifier |  | long |
| beyondtrust_epm.event.source.user.effective.name |  | keyword |
| beyondtrust_epm.event.source.user.effective.roles |  | keyword |
| beyondtrust_epm.event.source.user.email |  | keyword |
| beyondtrust_epm.event.source.user.full_name |  | keyword |
| beyondtrust_epm.event.source.user.group.domain |  | keyword |
| beyondtrust_epm.event.source.user.group.id |  | keyword |
| beyondtrust_epm.event.source.user.group.name |  | keyword |
| beyondtrust_epm.event.source.user.hash |  | keyword |
| beyondtrust_epm.event.source.user.id |  | keyword |
| beyondtrust_epm.event.source.user.local_identifier |  | long |
| beyondtrust_epm.event.source.user.name |  | keyword |
| beyondtrust_epm.event.source.user.roles |  | keyword |
| beyondtrust_epm.event.source.user.target.default_timezone_offset |  | long |
| beyondtrust_epm.event.source.user.target.domain |  | keyword |
| beyondtrust_epm.event.source.user.target.domain_identifier |  | keyword |
| beyondtrust_epm.event.source.user.target.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.source.user.target.email |  | keyword |
| beyondtrust_epm.event.source.user.target.full_name |  | keyword |
| beyondtrust_epm.event.source.user.target.group.domain |  | keyword |
| beyondtrust_epm.event.source.user.target.group.id |  | keyword |
| beyondtrust_epm.event.source.user.target.group.name |  | keyword |
| beyondtrust_epm.event.source.user.target.hash |  | keyword |
| beyondtrust_epm.event.source.user.target.id |  | keyword |
| beyondtrust_epm.event.source.user.target.local_identifier |  | long |
| beyondtrust_epm.event.source.user.target.name |  | keyword |
| beyondtrust_epm.event.source.user.target.roles |  | keyword |
| beyondtrust_epm.event.span.id |  | keyword |
| beyondtrust_epm.event.tags |  | keyword |
| beyondtrust_epm.event.threat.enrichments.indicator |  | keyword |
| beyondtrust_epm.event.threat.enrichments.matched.atomic |  | keyword |
| beyondtrust_epm.event.threat.enrichments.matched.field |  | keyword |
| beyondtrust_epm.event.threat.enrichments.matched.id |  | keyword |
| beyondtrust_epm.event.threat.enrichments.matched.index |  | keyword |
| beyondtrust_epm.event.threat.enrichments.matched.occurred |  | date |
| beyondtrust_epm.event.threat.enrichments.matched.type |  | keyword |
| beyondtrust_epm.event.threat.feed.dashboard_id |  | keyword |
| beyondtrust_epm.event.threat.feed.description |  | keyword |
| beyondtrust_epm.event.threat.feed.name |  | keyword |
| beyondtrust_epm.event.threat.feed.reference |  | keyword |
| beyondtrust_epm.event.threat.framework |  | keyword |
| beyondtrust_epm.event.threat.group.alias |  | keyword |
| beyondtrust_epm.event.threat.group.id |  | keyword |
| beyondtrust_epm.event.threat.group.name |  | keyword |
| beyondtrust_epm.event.threat.group.reference |  | keyword |
| beyondtrust_epm.event.threat.indicator.as.number |  | long |
| beyondtrust_epm.event.threat.indicator.as.organization.name |  | keyword |
| beyondtrust_epm.event.threat.indicator.confidence |  | keyword |
| beyondtrust_epm.event.threat.indicator.description |  | keyword |
| beyondtrust_epm.event.threat.indicator.email.address |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.accessed |  | date |
| beyondtrust_epm.event.threat.indicator.file.attributes |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.bundle.creator |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.bundle.download_source |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.bundle.info_description |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.bundle.name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.bundle.type |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.bundle.uri |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.bundle.version |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.code_signature.digest_algorithm |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.code_signature.exists |  | boolean |
| beyondtrust_epm.event.threat.indicator.file.code_signature.signing_id |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.code_signature.status |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.code_signature.subject_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.code_signature.team_id |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.code_signature.timestamp |  | date |
| beyondtrust_epm.event.threat.indicator.file.code_signature.trusted |  | boolean |
| beyondtrust_epm.event.threat.indicator.file.code_signature.valid |  | boolean |
| beyondtrust_epm.event.threat.indicator.file.created |  | date |
| beyondtrust_epm.event.threat.indicator.file.ctime |  | date |
| beyondtrust_epm.event.threat.indicator.file.description |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.device |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.directory |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.drive_letter |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.drive_type |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.architecture |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.byte_order |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.cpu_type |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.creation_date |  | date |
| beyondtrust_epm.event.threat.indicator.file.elf.exports.additional_prop |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.header.abi_version |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.header.class |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.header.data |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.header.entrypoint |  | long |
| beyondtrust_epm.event.threat.indicator.file.elf.header.object_version |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.header.os_abi |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.header.type |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.header.version |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.imports.additional_prop |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.chi2 |  | long |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.entropy |  | long |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.flags |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.physical_offset |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.physical_size |  | long |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.type |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.virtual_address |  | long |
| beyondtrust_epm.event.threat.indicator.file.elf.sections.virtual_size |  | long |
| beyondtrust_epm.event.threat.indicator.file.elf.segments.sections |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.segments.type |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.shared_libraries |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.elf.telfhash |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.extension |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.fork_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.gid |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.group |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.hash.md5 |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.hash.sha1 |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.hash.sha256 |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.hash.sha384 |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.hash.sha512 |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.hash.ssdeep |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.hash.tlsh |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.inode |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.mime_type |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.mode |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.mtime |  | date |
| beyondtrust_epm.event.threat.indicator.file.name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.owner.domain_identifier |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.owner.domain_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.owner.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.owner.identifier |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.owner.name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.owner_keyword |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.path |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.pe.architecture |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.pe.company |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.pe.description |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.pe.file_version |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.pe.imphash |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.pe.original_file_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.pe.pehash |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.pe.product |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.product_version |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.size |  | long |
| beyondtrust_epm.event.threat.indicator.file.source_url |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.target_path |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.type |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.uid |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.version |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.alternative_names |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.issuer.common_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.issuer.country |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.issuer.distinguished_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.issuer.locality |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.issuer.organization |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.issuer.organizational_unit |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.issuer.state_or_province |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.not_after |  | date |
| beyondtrust_epm.event.threat.indicator.file.x509.not_before |  | date |
| beyondtrust_epm.event.threat.indicator.file.x509.public_key_algorithm |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.public_key_curve |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.public_key_exponent |  | long |
| beyondtrust_epm.event.threat.indicator.file.x509.public_key_size |  | long |
| beyondtrust_epm.event.threat.indicator.file.x509.serial_number |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.signature_algorithm |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.subject.common_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.subject.country |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.subject.distinguished_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.subject.locality |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.subject.organization |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.subject.organizational_unit |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.subject.state_or_province |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.x509.version_number |  | keyword |
| beyondtrust_epm.event.threat.indicator.file.zone_tag |  | keyword |
| beyondtrust_epm.event.threat.indicator.first_seen |  | date |
| beyondtrust_epm.event.threat.indicator.geo.city_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.continent_code |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.continent_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.country_iso_code |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.country_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.location.lat |  | long |
| beyondtrust_epm.event.threat.indicator.geo.location.lon |  | long |
| beyondtrust_epm.event.threat.indicator.geo.name |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.postal_code |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.region_iso_code |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.region_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.timezone |  | keyword |
| beyondtrust_epm.event.threat.indicator.geo.timezone_offset |  | long |
| beyondtrust_epm.event.threat.indicator.ip |  | ip |
| beyondtrust_epm.event.threat.indicator.last_seen |  | date |
| beyondtrust_epm.event.threat.indicator.marking.tlp |  | keyword |
| beyondtrust_epm.event.threat.indicator.modified_at |  | date |
| beyondtrust_epm.event.threat.indicator.port |  | long |
| beyondtrust_epm.event.threat.indicator.provider |  | keyword |
| beyondtrust_epm.event.threat.indicator.reference |  | keyword |
| beyondtrust_epm.event.threat.indicator.registry.data.bytes |  | keyword |
| beyondtrust_epm.event.threat.indicator.registry.data.strings |  | wildcard |
| beyondtrust_epm.event.threat.indicator.registry.data.type |  | keyword |
| beyondtrust_epm.event.threat.indicator.registry.hive |  | keyword |
| beyondtrust_epm.event.threat.indicator.registry.key |  | keyword |
| beyondtrust_epm.event.threat.indicator.registry.path |  | keyword |
| beyondtrust_epm.event.threat.indicator.registry.value |  | keyword |
| beyondtrust_epm.event.threat.indicator.scanner_stats |  | long |
| beyondtrust_epm.event.threat.indicator.sightings |  | long |
| beyondtrust_epm.event.threat.indicator.type |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.domain |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.extension |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.fragment |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.full |  | wildcard |
| beyondtrust_epm.event.threat.indicator.url.original |  | wildcard |
| beyondtrust_epm.event.threat.indicator.url.password |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.path |  | wildcard |
| beyondtrust_epm.event.threat.indicator.url.port |  | long |
| beyondtrust_epm.event.threat.indicator.url.query |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.registered_domain |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.scheme |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.subdomain |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.top_level_domain |  | keyword |
| beyondtrust_epm.event.threat.indicator.url.username |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.alternative_names |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.issuer.common_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.issuer.country |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.issuer.distinguished_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.issuer.locality |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.issuer.organization |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.issuer.organizational_unit |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.issuer.state_or_province |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.not_after |  | date |
| beyondtrust_epm.event.threat.indicator.x509.not_before |  | date |
| beyondtrust_epm.event.threat.indicator.x509.public_key_algorithm |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.public_key_curve |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.public_key_exponent |  | long |
| beyondtrust_epm.event.threat.indicator.x509.public_key_size |  | long |
| beyondtrust_epm.event.threat.indicator.x509.serial_number |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.signature_algorithm |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.subject.common_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.subject.country |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.subject.distinguished_name |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.subject.locality |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.subject.organization |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.subject.organizational_unit |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.subject.state_or_province |  | keyword |
| beyondtrust_epm.event.threat.indicator.x509.version_number |  | keyword |
| beyondtrust_epm.event.threat.software.alias |  | keyword |
| beyondtrust_epm.event.threat.software.id |  | keyword |
| beyondtrust_epm.event.threat.software.name |  | keyword |
| beyondtrust_epm.event.threat.software.platforms |  | keyword |
| beyondtrust_epm.event.threat.software.reference |  | keyword |
| beyondtrust_epm.event.threat.software.type |  | keyword |
| beyondtrust_epm.event.threat.tactic.id |  | keyword |
| beyondtrust_epm.event.threat.tactic.name |  | keyword |
| beyondtrust_epm.event.threat.tactic.reference |  | keyword |
| beyondtrust_epm.event.threat.technique.id |  | keyword |
| beyondtrust_epm.event.threat.technique.name |  | keyword |
| beyondtrust_epm.event.threat.technique.reference |  | keyword |
| beyondtrust_epm.event.threat.technique.subtechnique.id |  | keyword |
| beyondtrust_epm.event.threat.technique.subtechnique.name |  | keyword |
| beyondtrust_epm.event.threat.technique.subtechnique.reference |  | keyword |
| beyondtrust_epm.event.timestamp |  | date |
| beyondtrust_epm.event.tls.cipher |  | keyword |
| beyondtrust_epm.event.tls.client.certificate |  | keyword |
| beyondtrust_epm.event.tls.client.certificate_chain |  | keyword |
| beyondtrust_epm.event.tls.client.hash.md5 |  | keyword |
| beyondtrust_epm.event.tls.client.hash.sha1 |  | keyword |
| beyondtrust_epm.event.tls.client.hash.sha256 |  | keyword |
| beyondtrust_epm.event.tls.client.issuer |  | keyword |
| beyondtrust_epm.event.tls.client.ja3 |  | keyword |
| beyondtrust_epm.event.tls.client.not_after |  | date |
| beyondtrust_epm.event.tls.client.not_before |  | date |
| beyondtrust_epm.event.tls.client.server_name |  | keyword |
| beyondtrust_epm.event.tls.client.subject |  | keyword |
| beyondtrust_epm.event.tls.client.supported_ciphers |  | keyword |
| beyondtrust_epm.event.tls.client.x509.alternative_names |  | keyword |
| beyondtrust_epm.event.tls.client.x509.issuer.common_name |  | keyword |
| beyondtrust_epm.event.tls.client.x509.issuer.country |  | keyword |
| beyondtrust_epm.event.tls.client.x509.issuer.distinguished_name |  | keyword |
| beyondtrust_epm.event.tls.client.x509.issuer.locality |  | keyword |
| beyondtrust_epm.event.tls.client.x509.issuer.organization |  | keyword |
| beyondtrust_epm.event.tls.client.x509.issuer.organizational_unit |  | keyword |
| beyondtrust_epm.event.tls.client.x509.issuer.state_or_province |  | keyword |
| beyondtrust_epm.event.tls.client.x509.not_after |  | date |
| beyondtrust_epm.event.tls.client.x509.not_before |  | date |
| beyondtrust_epm.event.tls.client.x509.public_key_algorithm |  | keyword |
| beyondtrust_epm.event.tls.client.x509.public_key_curve |  | keyword |
| beyondtrust_epm.event.tls.client.x509.public_key_exponent |  | long |
| beyondtrust_epm.event.tls.client.x509.public_key_size |  | long |
| beyondtrust_epm.event.tls.client.x509.serial_number |  | keyword |
| beyondtrust_epm.event.tls.client.x509.signature_algorithm |  | keyword |
| beyondtrust_epm.event.tls.client.x509.subject.common_name |  | keyword |
| beyondtrust_epm.event.tls.client.x509.subject.country |  | keyword |
| beyondtrust_epm.event.tls.client.x509.subject.distinguished_name |  | keyword |
| beyondtrust_epm.event.tls.client.x509.subject.locality |  | keyword |
| beyondtrust_epm.event.tls.client.x509.subject.organization |  | keyword |
| beyondtrust_epm.event.tls.client.x509.subject.organizational_unit |  | keyword |
| beyondtrust_epm.event.tls.client.x509.subject.state_or_province |  | keyword |
| beyondtrust_epm.event.tls.client.x509.version_number |  | keyword |
| beyondtrust_epm.event.tls.curve |  | keyword |
| beyondtrust_epm.event.tls.established |  | boolean |
| beyondtrust_epm.event.tls.next_protocol |  | keyword |
| beyondtrust_epm.event.tls.resumed |  | boolean |
| beyondtrust_epm.event.tls.server.certificate |  | keyword |
| beyondtrust_epm.event.tls.server.certificate_chain |  | keyword |
| beyondtrust_epm.event.tls.server.hash.md5 |  | keyword |
| beyondtrust_epm.event.tls.server.hash.sha1 |  | keyword |
| beyondtrust_epm.event.tls.server.hash.sha256 |  | keyword |
| beyondtrust_epm.event.tls.server.issuer |  | keyword |
| beyondtrust_epm.event.tls.server.ja3s |  | keyword |
| beyondtrust_epm.event.tls.server.not_after |  | date |
| beyondtrust_epm.event.tls.server.not_before |  | date |
| beyondtrust_epm.event.tls.server.subject |  | keyword |
| beyondtrust_epm.event.tls.server.x509.alternative_names |  | keyword |
| beyondtrust_epm.event.tls.server.x509.issuer.common_name |  | keyword |
| beyondtrust_epm.event.tls.server.x509.issuer.country |  | keyword |
| beyondtrust_epm.event.tls.server.x509.issuer.distinguished_name |  | keyword |
| beyondtrust_epm.event.tls.server.x509.issuer.locality |  | keyword |
| beyondtrust_epm.event.tls.server.x509.issuer.organization |  | keyword |
| beyondtrust_epm.event.tls.server.x509.issuer.organizational_unit |  | keyword |
| beyondtrust_epm.event.tls.server.x509.issuer.state_or_province |  | keyword |
| beyondtrust_epm.event.tls.server.x509.not_after |  | date |
| beyondtrust_epm.event.tls.server.x509.not_before |  | date |
| beyondtrust_epm.event.tls.server.x509.public_key_algorithm |  | keyword |
| beyondtrust_epm.event.tls.server.x509.public_key_curve |  | keyword |
| beyondtrust_epm.event.tls.server.x509.public_key_exponent |  | long |
| beyondtrust_epm.event.tls.server.x509.public_key_size |  | long |
| beyondtrust_epm.event.tls.server.x509.serial_number |  | keyword |
| beyondtrust_epm.event.tls.server.x509.signature_algorithm |  | keyword |
| beyondtrust_epm.event.tls.server.x509.subject.common_name |  | keyword |
| beyondtrust_epm.event.tls.server.x509.subject.country |  | keyword |
| beyondtrust_epm.event.tls.server.x509.subject.distinguished_name |  | keyword |
| beyondtrust_epm.event.tls.server.x509.subject.locality |  | keyword |
| beyondtrust_epm.event.tls.server.x509.subject.organization |  | keyword |
| beyondtrust_epm.event.tls.server.x509.subject.organizational_unit |  | keyword |
| beyondtrust_epm.event.tls.server.x509.subject.state_or_province |  | keyword |
| beyondtrust_epm.event.tls.server.x509.version_number |  | keyword |
| beyondtrust_epm.event.tls.version |  | keyword |
| beyondtrust_epm.event.tls.version_protocol |  | keyword |
| beyondtrust_epm.event.trace.id |  | keyword |
| beyondtrust_epm.event.transaction.id |  | keyword |
| beyondtrust_epm.event.url.domain |  | keyword |
| beyondtrust_epm.event.url.extension |  | keyword |
| beyondtrust_epm.event.url.fragment |  | keyword |
| beyondtrust_epm.event.url.full |  | wildcard |
| beyondtrust_epm.event.url.original |  | wildcard |
| beyondtrust_epm.event.url.password |  | keyword |
| beyondtrust_epm.event.url.path |  | wildcard |
| beyondtrust_epm.event.url.port |  | long |
| beyondtrust_epm.event.url.query |  | keyword |
| beyondtrust_epm.event.url.registered_domain |  | keyword |
| beyondtrust_epm.event.url.scheme |  | keyword |
| beyondtrust_epm.event.url.subdomain |  | keyword |
| beyondtrust_epm.event.url.top_level_domain |  | keyword |
| beyondtrust_epm.event.url.username |  | keyword |
| beyondtrust_epm.event.user.changes.default_timezone_offset |  | long |
| beyondtrust_epm.event.user.changes.domain |  | keyword |
| beyondtrust_epm.event.user.changes.domain_identifier |  | keyword |
| beyondtrust_epm.event.user.changes.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.user.changes.email |  | keyword |
| beyondtrust_epm.event.user.changes.full_name |  | keyword |
| beyondtrust_epm.event.user.changes.group.domain |  | keyword |
| beyondtrust_epm.event.user.changes.group.id |  | keyword |
| beyondtrust_epm.event.user.changes.group.name |  | keyword |
| beyondtrust_epm.event.user.changes.hash |  | keyword |
| beyondtrust_epm.event.user.changes.id |  | keyword |
| beyondtrust_epm.event.user.changes.local_identifier |  | long |
| beyondtrust_epm.event.user.changes.name |  | keyword |
| beyondtrust_epm.event.user.changes.roles |  | keyword |
| beyondtrust_epm.event.user.default_timezone_offset |  | long |
| beyondtrust_epm.event.user.domain |  | keyword |
| beyondtrust_epm.event.user.domain_identifier |  | keyword |
| beyondtrust_epm.event.user.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.user.effective.default_timezone_offset |  | long |
| beyondtrust_epm.event.user.effective.domain |  | keyword |
| beyondtrust_epm.event.user.effective.domain_identifier |  | keyword |
| beyondtrust_epm.event.user.effective.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.user.effective.email |  | keyword |
| beyondtrust_epm.event.user.effective.full_name |  | keyword |
| beyondtrust_epm.event.user.effective.group.domain |  | keyword |
| beyondtrust_epm.event.user.effective.group.id |  | keyword |
| beyondtrust_epm.event.user.effective.group.name |  | keyword |
| beyondtrust_epm.event.user.effective.hash |  | keyword |
| beyondtrust_epm.event.user.effective.id |  | keyword |
| beyondtrust_epm.event.user.effective.local_identifier |  | long |
| beyondtrust_epm.event.user.effective.name |  | keyword |
| beyondtrust_epm.event.user.effective.roles |  | keyword |
| beyondtrust_epm.event.user.email |  | keyword |
| beyondtrust_epm.event.user.full_name |  | keyword |
| beyondtrust_epm.event.user.group.domain |  | keyword |
| beyondtrust_epm.event.user.group.id |  | keyword |
| beyondtrust_epm.event.user.group.name |  | keyword |
| beyondtrust_epm.event.user.hash |  | keyword |
| beyondtrust_epm.event.user.id |  | keyword |
| beyondtrust_epm.event.user.local_identifier |  | long |
| beyondtrust_epm.event.user.name |  | keyword |
| beyondtrust_epm.event.user.roles |  | keyword |
| beyondtrust_epm.event.user.target.default_timezone_offset |  | long |
| beyondtrust_epm.event.user.target.domain |  | keyword |
| beyondtrust_epm.event.user.target.domain_identifier |  | keyword |
| beyondtrust_epm.event.user.target.domain_net_biosname |  | keyword |
| beyondtrust_epm.event.user.target.email |  | keyword |
| beyondtrust_epm.event.user.target.full_name |  | keyword |
| beyondtrust_epm.event.user.target.group.domain |  | keyword |
| beyondtrust_epm.event.user.target.group.id |  | keyword |
| beyondtrust_epm.event.user.target.group.name |  | keyword |
| beyondtrust_epm.event.user.target.hash |  | keyword |
| beyondtrust_epm.event.user.target.id |  | keyword |
| beyondtrust_epm.event.user.target.local_identifier |  | long |
| beyondtrust_epm.event.user.target.name |  | keyword |
| beyondtrust_epm.event.user.target.roles |  | keyword |
| beyondtrust_epm.event.user_agent.device.name |  | keyword |
| beyondtrust_epm.event.user_agent.name |  | keyword |
| beyondtrust_epm.event.user_agent.original |  | keyword |
| beyondtrust_epm.event.user_agent.os.family |  | keyword |
| beyondtrust_epm.event.user_agent.os.full |  | keyword |
| beyondtrust_epm.event.user_agent.os.kernel |  | keyword |
| beyondtrust_epm.event.user_agent.os.name |  | keyword |
| beyondtrust_epm.event.user_agent.os.platform |  | keyword |
| beyondtrust_epm.event.user_agent.os.product_type |  | keyword |
| beyondtrust_epm.event.user_agent.os.type |  | keyword |
| beyondtrust_epm.event.user_agent.os.version |  | keyword |
| beyondtrust_epm.event.user_agent.version |  | keyword |
| beyondtrust_epm.event.vulnerability.category |  | keyword |
| beyondtrust_epm.event.vulnerability.classification |  | keyword |
| beyondtrust_epm.event.vulnerability.description |  | keyword |
| beyondtrust_epm.event.vulnerability.enumeration |  | keyword |
| beyondtrust_epm.event.vulnerability.id |  | keyword |
| beyondtrust_epm.event.vulnerability.reference |  | keyword |
| beyondtrust_epm.event.vulnerability.report_id |  | keyword |
| beyondtrust_epm.event.vulnerability.scanner.vendor |  | keyword |
| beyondtrust_epm.event.vulnerability.score.base |  | float |
| beyondtrust_epm.event.vulnerability.score.environmental |  | float |
| beyondtrust_epm.event.vulnerability.score.temporal |  | float |
| beyondtrust_epm.event.vulnerability.score.version |  | keyword |
| beyondtrust_epm.event.vulnerability.severity |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |


### Example event

#### Event

An example event for `event` looks as following:

```json
{
    "@timestamp": "2026-04-15T06:49:55.541Z",
    "agent": {
        "ephemeral_id": "c20ae157-244b-49a0-acf0-32be2ef878a4",
        "id": "4ab492ae-2a84-49b3-a9d5-ae019712a17c",
        "name": "elastic-agent-73458",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-beyondtrust-epm-bucket-72886",
                "name": "elastic-package-beyondtrust-epm-bucket-72886"
            },
            "object": {
                "key": "event.log"
            }
        }
    },
    "beyondtrust_epm": {
        "event": {
            "agent": {
                "build": {
                    "original": "metricbeat version 7.6.0 (amd64), libbeat 7.6.0 [6a23e8f8f30f5001ba344e4e54d8d9cb82cb107c built 2020-02-05 23:10:10 +0000 UTC]"
                },
                "ephemeral_id": "8a4f500f",
                "id": "8a4f500d",
                "name": "foo",
                "type": "filebeat",
                "version": "6.0.0-rc2"
            },
            "client": {
                "address": "198.51.100.100",
                "as": {
                    "number": 15169,
                    "organization": {
                        "name": "Google LLC"
                    }
                },
                "bytes": 184,
                "domain": "foo.example.com",
                "geo": {
                    "city_name": "Montreal",
                    "continent_code": "NA",
                    "continent_name": "North America",
                    "country_iso_code": "CA",
                    "country_name": "Canada",
                    "location": {
                        "lat": 37,
                        "lon": -122
                    },
                    "name": "boston-dc",
                    "postal_code": "94040",
                    "region_iso_code": "CA-QC",
                    "region_name": "Quebec",
                    "timezone": "America/Argentina/Buenos_Aires",
                    "timezone_offset": -480
                },
                "ip": "81.2.69.144",
                "mac": "00-00-5E-00-53-23",
                "name": "DESKTOP-ACME-01",
                "nat": {
                    "ip": "81.2.69.144",
                    "port": 443
                },
                "packets": 12,
                "port": 443,
                "registered_domain": "example.com",
                "subdomain": "east",
                "top_level_domain": "co.uk",
                "user": {
                    "changes": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "DESKTOP-ACME-01"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-1013",
                        "local_identifier": 10001,
                        "name": "DESKTOP-ACME-01",
                        "roles": [
                            "admin"
                        ]
                    },
                    "default_timezone_offset": -480,
                    "domain": "alice",
                    "domain_identifier": "alice",
                    "domain_net_biosname": "alice",
                    "effective": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "DESKTOP-ACME-01"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-1013",
                        "local_identifier": 10001,
                        "name": "DESKTOP-ACME-01",
                        "roles": [
                            "admin"
                        ]
                    },
                    "email": "alice",
                    "full_name": "Albert Einstein",
                    "group": {
                        "domain": "corp.example.com",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "name": "DESKTOP-ACME-01"
                    },
                    "hash": "alice",
                    "id": "S-1-5-21-202424912787-2692429404-2351956786-1000",
                    "local_identifier": 10001,
                    "name": "a.einstein",
                    "roles": [
                        "kibana_admin",
                        "reporting_user"
                    ],
                    "target": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "DESKTOP-ACME-01"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-1013",
                        "local_identifier": 10001,
                        "name": "DESKTOP-ACME-01",
                        "roles": [
                            "admin"
                        ]
                    }
                }
            },
            "cloud": {
                "account": {
                    "id": "666777888999",
                    "name": "elastic-dev"
                },
                "availability_zone": "us-east-1c",
                "instance": {
                    "id": "i-1234567890abcdef0",
                    "name": "sample-resource"
                },
                "machine": {
                    "type": "t2.medium"
                },
                "origin": {
                    "account": {
                        "id": "666777888999",
                        "name": "elastic-dev"
                    },
                    "availability_zone": "us-east-1c",
                    "instance": {
                        "id": "i-1234567890abcdef0",
                        "name": "sample-resource"
                    },
                    "machine": {
                        "type": "t2.medium"
                    },
                    "project": {
                        "id": "my-project",
                        "name": "my project"
                    },
                    "provider": "aws",
                    "region": "us-east-1",
                    "service": {
                        "name": "lambda"
                    }
                },
                "project": {
                    "id": "my-project",
                    "name": "my project"
                },
                "provider": "aws",
                "region": "us-east-1",
                "service": {
                    "name": "lambda"
                },
                "target": {
                    "account": {
                        "id": "666777888999",
                        "name": "elastic-dev"
                    },
                    "availability_zone": "us-east-1c",
                    "instance": {
                        "id": "i-1234567890abcdef0",
                        "name": "sample-resource"
                    },
                    "machine": {
                        "type": "t2.medium"
                    },
                    "project": {
                        "id": "my-project",
                        "name": "my project"
                    },
                    "provider": "aws",
                    "region": "us-east-1",
                    "service": {
                        "name": "lambda"
                    }
                }
            },
            "container": {
                "cpu": {
                    "usage": 1
                },
                "disk": {
                    "read": {
                        "bytes": 42
                    },
                    "write": {
                        "bytes": 42
                    }
                },
                "id": "sample-id",
                "image": {
                    "hash": {
                        "all": [
                            "[sha256:f8fefc80e3273dc756f288a63945820d6476ad64883892c771b5e2ece6bf1b26]"
                        ]
                    },
                    "name": "sample-resource",
                    "tag": [
                        "item-0"
                    ]
                },
                "labels": "sample-environment",
                "memory": {
                    "usage": 1
                },
                "name": "sample-resource",
                "network": {
                    "egress": {
                        "bytes": 42
                    },
                    "ingress": {
                        "bytes": 42
                    }
                },
                "runtime": "docker"
            },
            "data_stream": {
                "dataset": "beyondtrust_epm.event",
                "namespace": "production",
                "type": "logs"
            },
            "destination": {
                "address": "198.51.100.100",
                "as": {
                    "number": 15169,
                    "organization": {
                        "name": "Google LLC"
                    }
                },
                "bytes": 184,
                "domain": "foo.example.com",
                "geo": {
                    "city_name": "Montreal",
                    "continent_code": "NA",
                    "continent_name": "North America",
                    "country_iso_code": "CA",
                    "country_name": "Canada",
                    "location": {
                        "lat": 37,
                        "lon": -122
                    },
                    "name": "boston-dc",
                    "postal_code": "94040",
                    "region_iso_code": "CA-QC",
                    "region_name": "Quebec",
                    "timezone": "America/Argentina/Buenos_Aires",
                    "timezone_offset": -480
                },
                "ip": "81.2.69.144",
                "mac": "00-00-5E-00-53-23",
                "nat": {
                    "ip": "81.2.69.144",
                    "port": 443
                },
                "packets": 12,
                "port": 443,
                "registered_domain": "example.com",
                "subdomain": "east",
                "top_level_domain": "co.uk",
                "user": {
                    "changes": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "DESKTOP-ACME-01"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-1013",
                        "local_identifier": 10001,
                        "name": "DESKTOP-ACME-01",
                        "roles": [
                            "admin"
                        ]
                    },
                    "default_timezone_offset": -480,
                    "domain": "alice",
                    "domain_identifier": "alice",
                    "domain_net_biosname": "alice",
                    "effective": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "DESKTOP-ACME-01"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-1013",
                        "local_identifier": 10001,
                        "name": "DESKTOP-ACME-01",
                        "roles": [
                            "admin"
                        ]
                    },
                    "email": "alice",
                    "full_name": "Albert Einstein",
                    "group": {
                        "domain": "corp.example.com",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "name": "DESKTOP-ACME-01"
                    },
                    "hash": "alice",
                    "id": "S-1-5-21-202424912787-2692429404-2351956786-1000",
                    "local_identifier": 10001,
                    "name": "a.einstein",
                    "roles": [
                        "kibana_admin",
                        "reporting_user"
                    ],
                    "target": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "DESKTOP-ACME-01"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-1013",
                        "local_identifier": 10001,
                        "name": "DESKTOP-ACME-01",
                        "roles": [
                            "admin"
                        ]
                    }
                }
            },
            "dll": {
                "code_signature": {
                    "digest_algorithm": "sha256",
                    "exists": true,
                    "signing_id": "com.apple.xpc.proxy",
                    "status": "ERROR_UNTRUSTED_ROOT",
                    "subject_name": "Microsoft Corporation",
                    "team_id": "EQHXZ8M8AV",
                    "timestamp": "2026-04-15T06:49:55.541Z",
                    "trusted": true,
                    "valid": true
                },
                "hash": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha256": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha384": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha512": "d41d8cd98f00b204e9800998ecf8427e",
                    "ssdeep": "d41d8cd98f00b204e9800998ecf8427e",
                    "tlsh": "d41d8cd98f00b204e9800998ecf8427e"
                },
                "name": "kernel32.dll",
                "path": "C:\\Windows\\System32\\kernel32.dll",
                "pe": {
                    "architecture": "x64",
                    "company": "Microsoft Corporation",
                    "description": "Paint",
                    "file_version": "6.3.9600.17415",
                    "imphash": "0c6803c4e922103c4dca5963aad36ddf",
                    "original_file_name": "MSPAINT.EXE",
                    "pehash": "73ff189b63cd6be375a7ff25179a38d347651975",
                    "product": "Microsoft® Windows® Operating System"
                }
            },
            "dns": {
                "answers": "sample-answers",
                "header_flags": [
                    "RD",
                    "RA"
                ],
                "id": "62111",
                "op_code": "QUERY",
                "question": {
                    "class": "IN",
                    "name": "www.example.com",
                    "registered_domain": "example.com",
                    "subdomain": "www",
                    "top_level_domain": "co.uk",
                    "type": "AAAA"
                },
                "resolved_ip": [
                    "10.10.10.10",
                    "10.10.10.11"
                ],
                "response_code": "NOERROR",
                "type": "answer"
            },
            "ecs": {
                "version": "1.0.0"
            },
            "email": {
                "attachments": [
                    {
                        "file": {
                            "extension": "sample-extension",
                            "hash": {
                                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha1": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha256": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha384": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha512": "d41d8cd98f00b204e9800998ecf8427e",
                                "ssdeep": "d41d8cd98f00b204e9800998ecf8427e",
                                "tlsh": "d41d8cd98f00b204e9800998ecf8427e"
                            },
                            "mime_type": "sample-mime-type",
                            "name": "sample.bin"
                        }
                    }
                ],
                "bcc": {
                    "address": [
                        "bcc.user1@example.com"
                    ]
                },
                "cc": {
                    "address": [
                        "cc.user1@example.com"
                    ]
                },
                "content_type": "text/plain",
                "delivery_timestamp": "2026-04-15T06:49:55.541Z",
                "direction": "inbound",
                "from": {
                    "address": [
                        "sender@example.com"
                    ]
                },
                "local_id": "c26dbea0-80d5-463b-b93c-4e8b708219ce",
                "message_id": "81ce15$8r2j59@mail01.example.com",
                "origination_timestamp": "2026-04-15T06:49:55.541Z",
                "reply_to": {
                    "address": [
                        "reply.here@example.com"
                    ]
                },
                "sender": {
                    "address": "198.51.100.100"
                },
                "subject": "Please see this important message.",
                "to": {
                    "address": [
                        "user1@example.com"
                    ]
                },
                "x_mailer": "Spambot v2.5"
            },
            "error": {
                "code": "sample-code",
                "id": "sample-id",
                "stack_trace": "sample-stack-trace",
                "type": "java.lang.NullPointerException"
            },
            "event": {
                "action": "user-password-change",
                "agent_id_status": "verified",
                "category": [
                    "authentication"
                ],
                "code": "4648",
                "created": "2026-04-15T06:49:55.541Z",
                "dataset": "beyondtrust_epm.event",
                "duration": 42,
                "end": "2026-04-15T06:49:55.541Z",
                "hash": "123456789012345678901234567890ABCD",
                "id": "8a4f500d",
                "ingested": "2026-04-15T06:49:55.541Z",
                "kind": "alert",
                "module": "beyondtrust_epm",
                "original": "Sep 19 08:26:10 host CEF:0&#124;Security&#124; threatmanager&#124;1.0&#124;100&#124; worm successfully stopped&#124;10&#124;src=10.0.0.1 dst=2.1.2.2spt=1232",
                "outcome": "success",
                "provider": "kernel",
                "reason": "Terminated an unexpected process",
                "received_at": "2026-04-15T06:49:55.541Z",
                "reference": "https://system.example.com/event/#0001234",
                "risk_score": 1,
                "risk_score_norm": 1,
                "sequence": 42,
                "severity": 7,
                "start": "2026-04-15T06:49:55.541Z",
                "timezone": "America/Los_Angeles",
                "type": [
                    "item-0"
                ],
                "url": "https://mysystem.example.com/alert/5271dedb-f5b0-4218-87f0-4ac4870a38fe"
            },
            "faas": {
                "coldstart": true,
                "execution": "af9d5aa4-a685-4c5f-a22b-444f80b3cc28",
                "id": "arn:aws:lambda:us-west-2:123456789012:function:my-function",
                "name": "my-function",
                "trigger": {
                    "request_id": "123456789",
                    "type": "http"
                },
                "version": "123"
            },
            "file": {
                "accessed": "2026-04-15T06:49:55.541Z",
                "attributes": [
                    "readonly",
                    "system"
                ],
                "bundle": {
                    "creator": "sample-reator",
                    "download_source": "sample-ownload-ource",
                    "info_description": "sample-info-escription",
                    "name": "sample.bin",
                    "type": "EXEC",
                    "uri": "sample-ri",
                    "version": "sample-version"
                },
                "code_signature": {
                    "digest_algorithm": "sha256",
                    "exists": true,
                    "signing_id": "com.apple.xpc.proxy",
                    "status": "ERROR_UNTRUSTED_ROOT",
                    "subject_name": "Microsoft Corporation",
                    "team_id": "EQHXZ8M8AV",
                    "timestamp": "2026-04-15T06:49:55.541Z",
                    "trusted": true,
                    "valid": true
                },
                "created": "2026-04-15T06:49:55.541Z",
                "ctime": "2026-04-15T06:49:55.541Z",
                "description": "sample-escription",
                "device": "sda",
                "directory": "/home/alice",
                "drive_letter": "C",
                "drive_type": "sample-rive-ype",
                "elf": {
                    "architecture": "x86-64",
                    "byte_order": "Little Endian",
                    "cpu_type": "Intel",
                    "creation_date": "2026-04-15T06:49:55.541Z",
                    "exports": {
                        "additional_prop": "sample-additional-rop"
                    },
                    "header": {
                        "abi_version": "sample-abi-version",
                        "class": "sample-class",
                        "data": "sample-data",
                        "entrypoint": 42,
                        "object_version": "sample-object-version",
                        "os_abi": "sample-os-abi",
                        "type": "EXEC",
                        "version": "sample-version"
                    },
                    "imports": {
                        "additional_prop": "sample-additional-rop"
                    },
                    "segments": [
                        {
                            "sections": "sample-sections",
                            "type": "EXEC"
                        }
                    ],
                    "shared_libraries": [
                        "item-0"
                    ],
                    "telfhash": "b1946ac92492d2347c6235b4d2611184"
                },
                "extension": "png",
                "fork_name": "Zone.Identifier",
                "gid": "1001",
                "group": "alice",
                "hash": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha256": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha384": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha512": "d41d8cd98f00b204e9800998ecf8427e",
                    "ssdeep": "d41d8cd98f00b204e9800998ecf8427e",
                    "tlsh": "d41d8cd98f00b204e9800998ecf8427e"
                },
                "inode": "256383",
                "mime_type": "sample-mime-type",
                "mode": "0640",
                "mtime": "2026-04-15T06:49:55.541Z",
                "name": "example.png",
                "owner": {
                    "domain_identifier": "corp.example.com",
                    "domain_name": "corp.example.com",
                    "domain_net_biosname": "corp.example.com",
                    "identifier": "801e9de5-5a58-4f93-a1dc-5c2c3e7c9e01",
                    "name": "alice"
                },
                "owner_keyword": "alice",
                "path": "/home/alice/example.png",
                "pe": {
                    "architecture": "x64",
                    "company": "Microsoft Corporation",
                    "description": "Paint",
                    "file_version": "6.3.9600.17415",
                    "imphash": "0c6803c4e922103c4dca5963aad36ddf",
                    "original_file_name": "MSPAINT.EXE",
                    "pehash": "73ff189b63cd6be375a7ff25179a38d347651975",
                    "product": "Microsoft® Windows® Operating System"
                },
                "product_version": "sample-roduct-ersion",
                "size": 16384,
                "source_url": "sample-ource-rl",
                "target_path": "sample-target-path",
                "type": "file",
                "uid": "1001",
                "version": "sample-version",
                "x509": {
                    "alternative_names": [
                        "*.elastic.co"
                    ],
                    "issuer": {
                        "common_name": [
                            "Example SHA2 High Assurance Server CA"
                        ],
                        "country": [
                            "US"
                        ],
                        "distinguished_name": "C=US, O=Example Inc, OU=www.example.com, CN=Example SHA2 High Assurance Server CA",
                        "locality": [
                            "Mountain View"
                        ],
                        "organization": [
                            "Example Inc"
                        ],
                        "organizational_unit": [
                            "www.example.com"
                        ],
                        "state_or_province": [
                            "California"
                        ]
                    },
                    "not_after": "2026-04-15T06:49:55.541Z",
                    "not_before": "2026-04-15T06:49:55.541Z",
                    "public_key_algorithm": "RSA",
                    "public_key_curve": "nistp521",
                    "public_key_exponent": 65537,
                    "public_key_size": 2048,
                    "serial_number": "55FBB9C7DEBF09809D12CCAA",
                    "signature_algorithm": "SHA256-RSA",
                    "subject": {
                        "common_name": [
                            "shared.global.example.net"
                        ],
                        "country": [
                            "US"
                        ],
                        "distinguished_name": "C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net",
                        "locality": [
                            "San Francisco"
                        ],
                        "organization": [
                            "Example, Inc."
                        ],
                        "organizational_unit": [
                            "item-0"
                        ],
                        "state_or_province": [
                            "California"
                        ]
                    },
                    "version_number": "3"
                },
                "zone_tag": "sample-one-ag"
            },
            "group": {
                "domain": "corp.example.com",
                "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                "name": "sample-resource"
            },
            "group_leader": {
                "args": [
                    "item-0"
                ],
                "args_count": 3,
                "code_signature": {
                    "digest_algorithm": "sha256",
                    "exists": true,
                    "signing_id": "com.apple.xpc.proxy",
                    "status": "ERROR_UNTRUSTED_ROOT",
                    "subject_name": "Microsoft Corporation",
                    "team_id": "EQHXZ8M8AV",
                    "timestamp": "2026-04-15T06:49:55.541Z",
                    "trusted": true,
                    "valid": true
                },
                "command_line": "sample-command-line",
                "elevation_required": true,
                "elf": {
                    "architecture": "x86-64",
                    "byte_order": "Little Endian",
                    "cpu_type": "Intel",
                    "creation_date": "2026-04-15T06:49:55.541Z",
                    "exports": {
                        "additional_prop": "sample-additional-rop"
                    },
                    "header": {
                        "abi_version": "sample-abi-version",
                        "class": "sample-class",
                        "data": "sample-data",
                        "entrypoint": 42,
                        "object_version": "sample-object-version",
                        "os_abi": "sample-os-abi",
                        "type": "EXEC",
                        "version": "sample-version"
                    },
                    "imports": {
                        "additional_prop": "sample-additional-rop"
                    },
                    "sections": [
                        {
                            "chi2": 1000,
                            "entropy": 4,
                            "flags": "sample-flags",
                            "name": "sample-resource",
                            "physical_offset": "sample-physical-offset",
                            "physical_size": 8192,
                            "type": "EXEC",
                            "virtual_address": 4096,
                            "virtual_size": 8192
                        }
                    ],
                    "segments": [
                        {
                            "sections": "sample-sections",
                            "type": "EXEC"
                        }
                    ],
                    "shared_libraries": [
                        "item-0"
                    ],
                    "telfhash": "b1946ac92492d2347c6235b4d2611184"
                },
                "end": "2026-04-15T06:49:55.541Z",
                "entity_id": "sample-entity-id",
                "entry_meta": {
                    "source": {
                        "address": "198.51.100.100",
                        "as": {
                            "number": 15169,
                            "organization": {
                                "name": "DESKTOP-ACME-01"
                            }
                        },
                        "bytes": 1024,
                        "domain": "corp.example.com",
                        "geo": {
                            "city_name": "San Francisco",
                            "continent_code": "US",
                            "continent_name": "North America",
                            "country_iso_code": "US",
                            "country_name": "United States",
                            "location": {
                                "lat": 37,
                                "lon": -122
                            },
                            "name": "us-west-2",
                            "postal_code": "US",
                            "region_iso_code": "US",
                            "region_name": "California",
                            "timezone": "America/Los_Angeles",
                            "timezone_offset": -480
                        },
                        "ip": "81.2.69.144",
                        "mac": "00:1a:2b:3c:4d:5e",
                        "nat": {
                            "ip": "81.2.69.144",
                            "port": 443
                        },
                        "packets": 1024,
                        "port": 443,
                        "registered_domain": "example.com",
                        "subdomain": "corp.example.com",
                        "top_level_domain": "corp.example.com",
                        "user": {
                            "changes": {
                                "default_timezone_offset": -480,
                                "domain": "corp.example.com",
                                "domain_identifier": "corp.example.com",
                                "domain_net_biosname": "corp.example.com",
                                "email": "alice.williams@example.com",
                                "full_name": "Alice Williams",
                                "group": {
                                    "domain": "corp.example.com",
                                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                                    "name": "DESKTOP-ACME-01"
                                },
                                "hash": "b1946ac92492d2347c6235b4d2611184",
                                "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                                "local_identifier": 10001,
                                "name": "DESKTOP-ACME-01",
                                "roles": [
                                    "admin"
                                ]
                            },
                            "default_timezone_offset": -480,
                            "domain": "alice",
                            "domain_identifier": "alice",
                            "domain_net_biosname": "alice",
                            "effective": {
                                "default_timezone_offset": -480,
                                "domain": "corp.example.com",
                                "domain_identifier": "corp.example.com",
                                "domain_net_biosname": "corp.example.com",
                                "email": "alice.williams@example.com",
                                "full_name": "Alice Williams",
                                "group": {
                                    "domain": "corp.example.com",
                                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                                    "name": "DESKTOP-ACME-01"
                                },
                                "hash": "b1946ac92492d2347c6235b4d2611184",
                                "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                                "local_identifier": 10001,
                                "name": "DESKTOP-ACME-01",
                                "roles": [
                                    "admin"
                                ]
                            },
                            "email": "alice",
                            "full_name": "alice",
                            "group": {
                                "domain": "corp.example.com",
                                "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                                "name": "DESKTOP-ACME-01"
                            },
                            "hash": "alice",
                            "id": "alice",
                            "local_identifier": 10001,
                            "name": "alice",
                            "roles": [
                                "admin"
                            ],
                            "target": {
                                "default_timezone_offset": -480,
                                "domain": "corp.example.com",
                                "domain_identifier": "corp.example.com",
                                "domain_net_biosname": "corp.example.com",
                                "email": "alice.williams@example.com",
                                "full_name": "Alice Williams",
                                "group": {
                                    "domain": "corp.example.com",
                                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                                    "name": "DESKTOP-ACME-01"
                                },
                                "hash": "b1946ac92492d2347c6235b4d2611184",
                                "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                                "local_identifier": 10001,
                                "name": "DESKTOP-ACME-01",
                                "roles": [
                                    "admin"
                                ]
                            }
                        }
                    },
                    "type": "terminal"
                },
                "env_vars": "sample-env-vars",
                "executable": "sample-executable",
                "exit_code": 137,
                "group": {
                    "domain": "corp.example.com",
                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                    "name": "sample-resource"
                },
                "hash": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha256": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha384": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha512": "d41d8cd98f00b204e9800998ecf8427e",
                    "ssdeep": "d41d8cd98f00b204e9800998ecf8427e",
                    "tlsh": "d41d8cd98f00b204e9800998ecf8427e"
                },
                "hosted_file": {
                    "accessed": "2026-04-15T06:49:55.541Z",
                    "attributes": [
                        "item-0"
                    ],
                    "bundle": {
                        "creator": "sample-reator",
                        "download_source": "sample-ownload-ource",
                        "info_description": "sample-nfo-escription",
                        "name": "sample.bin",
                        "type": "EXEC",
                        "uri": "sample-ri",
                        "version": "sample-version"
                    },
                    "code_signature": {
                        "digest_algorithm": "sample-digest-algorithm",
                        "exists": true,
                        "signing_id": "sample-signing-id",
                        "status": "sample-status",
                        "subject_name": "sample-subject-name",
                        "team_id": "sample-team-id",
                        "timestamp": "2026-04-15T06:49:55.541Z",
                        "trusted": true,
                        "valid": true
                    },
                    "created": "2026-04-15T06:49:55.541Z",
                    "ctime": "2026-04-15T06:49:55.541Z",
                    "description": "sample-escription",
                    "device": "sample-device",
                    "directory": "sample-directory",
                    "drive_letter": "sample-drive-letter",
                    "drive_type": "sample-rive-ype",
                    "elf": {
                        "architecture": "sample-architecture",
                        "byte_order": "sample-byte-order",
                        "cpu_type": "sample-cpu-type",
                        "creation_date": "2026-04-15T06:49:55.541Z",
                        "exports": {
                            "additional_prop": "sample-additional-rop"
                        },
                        "header": {
                            "abi_version": "sample-abi-version",
                            "class": "sample-class",
                            "data": "sample-data",
                            "entrypoint": 42,
                            "object_version": "sample-object-version",
                            "os_abi": "sample-os-abi",
                            "type": "EXEC",
                            "version": "sample-version"
                        },
                        "imports": {
                            "additional_prop": "sample-additional-rop"
                        },
                        "sections": [
                            {
                                "chi2": 1000,
                                "entropy": 4,
                                "flags": "sample-flags",
                                "name": "sample.bin",
                                "physical_offset": "sample-physical-offset",
                                "physical_size": 8192,
                                "type": "EXEC",
                                "virtual_address": 4096,
                                "virtual_size": 8192
                            }
                        ],
                        "segments": [
                            {
                                "sections": "sample-sections",
                                "type": "EXEC"
                            }
                        ],
                        "shared_libraries": [
                            "item-0"
                        ],
                        "telfhash": "b1946ac92492d2347c6235b4d2611184"
                    },
                    "extension": "sample-extension",
                    "fork_name": "sample-fork-name",
                    "gid": "sample-gid",
                    "group": "sample-group",
                    "hash": {
                        "md5": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha1": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha256": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha384": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha512": "d41d8cd98f00b204e9800998ecf8427e",
                        "ssdeep": "d41d8cd98f00b204e9800998ecf8427e",
                        "tlsh": "d41d8cd98f00b204e9800998ecf8427e"
                    },
                    "inode": "sample-inode",
                    "mime_type": "sample-mime-type",
                    "mode": "sample-mode",
                    "mtime": "2026-04-15T06:49:55.541Z",
                    "name": "sample.bin",
                    "owner": "sample-owner",
                    "path": "sample-path",
                    "pe": {
                        "architecture": "sample-architecture",
                        "company": "sample-company",
                        "description": "sample-description",
                        "file_version": "sample-file-version",
                        "imphash": "sample-imphash",
                        "original_file_name": "sample-original-file-name",
                        "pehash": "b1946ac92492d2347c6235b4d2611184",
                        "product": "sample-product"
                    },
                    "product_version": "sample-roduct-ersion",
                    "size": 1024,
                    "source_url": "sample-ource-rl",
                    "target_path": "sample-target-path",
                    "type": "EXEC",
                    "uid": "sample-uid",
                    "version": "sample-version",
                    "x509": {
                        "alternative_names": [
                            "item-0"
                        ],
                        "issuer": {
                            "common_name": [
                                "item-0"
                            ],
                            "country": [
                                "item-0"
                            ],
                            "distinguished_name": "sample-distinguished-name",
                            "locality": [
                                "item-0"
                            ],
                            "organization": [
                                "item-0"
                            ],
                            "organizational_unit": [
                                "item-0"
                            ],
                            "state_or_province": [
                                "item-0"
                            ]
                        },
                        "not_after": "2026-04-15T06:49:55.541Z",
                        "not_before": "2026-04-15T06:49:55.541Z",
                        "public_key_algorithm": "sample-public-key-algorithm",
                        "public_key_curve": "sample-public-key-curve",
                        "public_key_exponent": 42,
                        "public_key_size": 42,
                        "serial_number": "sample-serial-number",
                        "signature_algorithm": "sample-signature-algorithm",
                        "subject": {
                            "common_name": [
                                "item-0"
                            ],
                            "country": [
                                "item-0"
                            ],
                            "distinguished_name": "sample-distinguished-name",
                            "locality": [
                                "item-0"
                            ],
                            "organization": [
                                "item-0"
                            ],
                            "organizational_unit": [
                                "item-0"
                            ],
                            "state_or_province": [
                                "item-0"
                            ]
                        },
                        "version_number": "sample-version-number"
                    },
                    "zone_tag": "sample-one-ag"
                },
                "interactive": true,
                "name": "sample-resource",
                "pe": {
                    "architecture": "x64",
                    "company": "Microsoft Corporation",
                    "description": "Paint",
                    "file_version": "6.3.9600.17415",
                    "imphash": "0c6803c4e922103c4dca5963aad36ddf",
                    "original_file_name": "MSPAINT.EXE",
                    "pehash": "73ff189b63cd6be375a7ff25179a38d347651975",
                    "product": "Microsoft® Windows® Operating System"
                },
                "pgid": 4242,
                "pid": 4242,
                "real_group": {
                    "domain": "corp.example.com",
                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                    "name": "sample-resource"
                },
                "real_user": {
                    "changes": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "local_identifier": 10001,
                        "name": "alice",
                        "roles": [
                            "admin"
                        ]
                    },
                    "default_timezone_offset": -480,
                    "domain": "corp.example.com",
                    "domain_identifier": "corp.example.com",
                    "domain_net_biosname": "corp.example.com",
                    "effective": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "local_identifier": 10001,
                        "name": "alice",
                        "roles": [
                            "admin"
                        ]
                    },
                    "email": "alice.williams@example.com",
                    "full_name": "Alice Williams",
                    "group": {
                        "domain": "corp.example.com",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "name": "alice"
                    },
                    "hash": "b1946ac92492d2347c6235b4d2611184",
                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                    "local_identifier": 10001,
                    "name": "alice",
                    "roles": [
                        "admin"
                    ],
                    "target": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "local_identifier": 10001,
                        "name": "alice",
                        "roles": [
                            "admin"
                        ]
                    }
                },
                "same_as_process": true,
                "saved_group": {
                    "domain": "corp.example.com",
                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                    "name": "sample-resource"
                },
                "saved_user": {
                    "changes": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "local_identifier": 10001,
                        "name": "alice",
                        "roles": [
                            "admin"
                        ]
                    },
                    "default_timezone_offset": -480,
                    "domain": "corp.example.com",
                    "domain_identifier": "corp.example.com",
                    "domain_net_biosname": "corp.example.com",
                    "effective": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "local_identifier": 10001,
                        "name": "alice",
                        "roles": [
                            "admin"
                        ]
                    },
                    "email": "alice.williams@example.com",
                    "full_name": "Alice Williams",
                    "group": {
                        "domain": "corp.example.com",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "name": "alice"
                    },
                    "hash": "b1946ac92492d2347c6235b4d2611184",
                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                    "local_identifier": 10001,
                    "name": "alice",
                    "roles": [
                        "admin"
                    ],
                    "target": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Alice Williams",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "local_identifier": 10001,
                        "name": "alice",
                        "roles": [
                            "admin"
                        ]
                    }
                },
                "start": "2026-04-15T06:49:55.541Z",
                "supplemental_groups": {
                    "domain": "corp.example.com",
                    "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                    "name": "sample-resource"
                },
                "thread": {
                    "id": "4242",
                    "name": "sample-resource"
                },
                "title": "sample-title",
                "tty": "sample-tty",
                "uptime": 3600,
                "user": {
                    "changes": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Albert Einstein",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-202424912787-2692429404-2351956786-1000",
                        "local_identifier": 10001,
                        "name": "a.einstein",
                        "roles": [
                            "kibana_admin",
                            "reporting_user"
                        ]
                    },
                    "default_timezone_offset": -480,
                    "domain": "alice",
                    "domain_identifier": "alice",
                    "domain_net_biosname": "alice",
                    "effective": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Albert Einstein",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-202424912787-2692429404-2351956786-1000",
                        "local_identifier": 10001,
                        "name": "a.einstein",
                        "roles": [
                            "kibana_admin",
                            "reporting_user"
                        ]
                    },
                    "email": "alice",
                    "full_name": "Albert Einstein",
                    "group": {
                        "domain": "corp.example.com",
                        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                        "name": "alice"
                    },
                    "hash": "alice",
                    "id": "S-1-5-21-202424912787-2692429404-2351956786-1000",
                    "local_identifier": 10001,
                    "name": "a.einstein",
                    "roles": [
                        "kibana_admin",
                        "reporting_user"
                    ],
                    "target": {
                        "default_timezone_offset": -480,
                        "domain": "corp.example.com",
                        "domain_identifier": "corp.example.com",
                        "domain_net_biosname": "corp.example.com",
                        "email": "alice.williams@example.com",
                        "full_name": "Albert Einstein",
                        "group": {
                            "domain": "corp.example.com",
                            "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                            "name": "alice"
                        },
                        "hash": "b1946ac92492d2347c6235b4d2611184",
                        "id": "S-1-5-21-202424912787-2692429404-2351956786-1000",
                        "local_identifier": 10001,
                        "name": "a.einstein",
                        "roles": [
                            "kibana_admin",
                            "reporting_user"
                        ]
                    }
                },
                "working_directory": "sample-working-directory"
            },
            "host": {
                "architecture": "x86_64",
                "boot": {
                    "id": "88a1f0ed-5ae5-41ee-af6b-41921c311872"
                },
                "chassis_type": "sample-hassis-ype",
                "cpu": {
                    "usage": 1
                },
                "default_locale": "sample-efault-ocale",
                "default_ui_language": "example-default-ui-language",
                "disk": {
                    "read": {
                        "bytes": 42
                    },
                    "write": {
                        "bytes": 42
                    }
                },
                "domain": "CONTOSO",
                "domain_identifier": "corp.example.com",
                "domain_net_biosname": "corp.example.com",
                "geo": {
                    "city_name": "Montreal",
                    "continent_code": "NA",
                    "continent_name": "North America",
                    "country_iso_code": "CA",
                    "country_name": "Canada",
                    "location": {
                        "lat": 37,
                        "lon": -122
                    },
                    "name": "boston-dc",
                    "postal_code": "94040",
                    "region_iso_code": "CA-QC",
                    "region_name": "Quebec",
                    "timezone": "America/Argentina/Buenos_Aires",
                    "timezone_offset": -480
                },
                "hostname": "sample-hostname",
                "id": "sample-id",
                "ip": [
                    "81.2.69.144"
                ],
                "mac": [
                    "00-00-5E-00-53-23",
                    "00-00-5E-00-53-24"
                ],
                "name": "sample-resource",
                "net_biosname": "sample-net-bios",
                "network": {
                    "egress": {
                        "bytes": 42,
                        "packets": 42
                    },
                    "ingress": {
                        "bytes": 42,
                        "packets": 42
                    }
                },
                "os": {
                    "family": "debian",
                    "full": "Mac OS Mojave",
                    "kernel": "4.4.0-112-generic",
                    "name": "Mac OS X",
                    "platform": "darwin",
                    "product_type": "sample-roduct-ype",
                    "type": "macos",
                    "version": "10.14.1"
                },
                "pid_ns_ino": "256383",
                "type": "EXEC",
                "uptime": 1325
            },
            "http": {
                "request": {
                    "body": {
                        "bytes": 887,
                        "content": "Hello world"
                    },
                    "bytes": 1437,
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "method": "POST",
                    "mime_type": "image/gif",
                    "referrer": "https://blog.example.com/"
                },
                "response": {
                    "body": {
                        "bytes": 887,
                        "content": "Hello world"
                    },
                    "bytes": 1437,
                    "mime_type": "image/gif",
                    "status_code": 404
                },
                "version": "1.1"
            },
            "labels": "application",
            "log": {
                "file": {
                    "path": "/var/log/fun-times.log"
                },
                "level": "error",
                "logger": "org.elasticsearch.bootstrap.Bootstrap",
                "origin": {
                    "file": {
                        "line": 42,
                        "name": "Bootstrap.java"
                    },
                    "function": "init"
                },
                "syslog": "sample-syslog"
            },
            "message": "Hello World",
            "network": {
                "application": "aim",
                "bytes": 368,
                "community_id": "1:hO+sN4H+MG5MY/8hIrXPqc4ZQz0=",
                "direction": "inbound",
                "forwarded_ip": "67.43.156.1",
                "iana_number": "6",
                "inner": "sample-inner",
                "name": "Guest Wifi",
                "packets": 24,
                "protocol": "http",
                "transport": "tcp",
                "type": "ipv4",
                "vlan": {
                    "id": "10",
                    "name": "outside"
                }
            },
            "observer": {
                "egress": "sample-egress",
                "geo": {
                    "city_name": "Montreal",
                    "continent_code": "NA",
                    "continent_name": "North America",
                    "country_iso_code": "CA",
                    "country_name": "Canada",
                    "location": {
                        "lat": 37,
                        "lon": -122
                    },
                    "name": "boston-dc",
                    "postal_code": "94040",
                    "region_iso_code": "CA-QC",
                    "region_name": "Quebec",
                    "timezone": "America/Argentina/Buenos_Aires",
                    "timezone_offset": -480
                },
                "hostname": "sample-hostname",
                "ingress": "sample-ingress",
                "ip": [
                    "81.2.69.144"
                ],
                "mac": [
                    "00-00-5E-00-53-23",
                    "00-00-5E-00-53-24"
                ],
                "name": "1_proxySG",
                "os": {
                    "family": "debian",
                    "full": "Mac OS Mojave",
                    "kernel": "4.4.0-112-generic",
                    "name": "Mac OS X",
                    "platform": "darwin",
                    "product_type": "sample-roduct-ype",
                    "type": "macos",
                    "version": "10.14.1"
                },
                "product": "s200",
                "serial_number": "sample-serial-number",
                "type": "firewall",
                "vendor": "Symantec",
                "version": "sample-version"
            },
            "orchestrator": {
                "api_version": "v1beta1",
                "cluster": {
                    "id": "sample-id",
                    "name": "sample-resource",
                    "url": "sample-url",
                    "version": "sample-version"
                },
                "namespace": "kube-system",
                "organization": "elastic",
                "resource": {
                    "id": "sample-id",
                    "ip": [
                        "81.2.69.144"
                    ],
                    "name": "test-pod-cdcws",
                    "parent": {
                        "type": "DaemonSet"
                    },
                    "type": "service"
                },
                "type": "kubernetes"
            },
            "organization": {
                "id": "sample-id",
                "name": "sample-resource"
            },
            "package": {
                "architecture": "x86_64",
                "build_version": "36f4f7e89dd61b0988b12ee000b98966867710cd",
                "checksum": "68b329da9893e34099c7d8ad5cb9c940",
                "description": "Open source programming language to build simple/reliable/efficient software.",
                "install_scope": "global",
                "installed": "2026-04-15T06:49:55.541Z",
                "license": "Apache License 2.0",
                "name": "go",
                "path": "/usr/local/Cellar/go/1.12.9/",
                "reference": "https://golang.org",
                "size": 62231,
                "type": "rpm",
                "version": "1.12.9"
            },
            "tags": [
                "production",
                "env2"
            ],
            "timestamp": "2026-04-15T06:49:55.541Z"
        }
    },
    "client": {
        "address": "198.51.100.100",
        "as": {
            "number": 15169,
            "organization": {
                "name": "Google LLC"
            }
        },
        "bytes": 184,
        "domain": "foo.example.com",
        "geo": {
            "city_name": "Montreal",
            "continent_code": "NA",
            "continent_name": "North America",
            "country_iso_code": "CA",
            "country_name": "Canada",
            "name": "boston-dc",
            "postal_code": "94040",
            "region_iso_code": "CA-QC",
            "region_name": "Quebec",
            "timezone": "America/Argentina/Buenos_Aires"
        },
        "ip": "81.2.69.144",
        "mac": "00-00-5E-00-53-23",
        "nat": {
            "ip": "81.2.69.144",
            "port": 443
        },
        "packets": 12,
        "port": 443,
        "registered_domain": "example.com",
        "subdomain": "east",
        "top_level_domain": "co.uk",
        "user": {
            "domain": "alice",
            "email": "alice",
            "full_name": "Albert Einstein",
            "group": {
                "domain": "corp.example.com",
                "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                "name": "DESKTOP-ACME-01"
            },
            "hash": "alice",
            "id": "S-1-5-21-202424912787-2692429404-2351956786-1000",
            "name": "a.einstein",
            "roles": [
                "kibana_admin",
                "reporting_user"
            ]
        }
    },
    "cloud": {
        "account": {
            "id": [
                "666777888999"
            ],
            "name": "elastic-dev"
        },
        "availability_zone": "us-east-1c",
        "instance": {
            "id": "i-1234567890abcdef0",
            "name": "sample-resource"
        },
        "machine": {
            "type": "t2.medium"
        },
        "origin": {
            "account": {
                "id": "666777888999",
                "name": "elastic-dev"
            },
            "availability_zone": "us-east-1c",
            "instance": {
                "id": "i-1234567890abcdef0",
                "name": "sample-resource"
            },
            "machine": {
                "type": "t2.medium"
            },
            "project": {
                "id": "my-project",
                "name": "my project"
            },
            "provider": "aws",
            "region": "us-east-1",
            "service": {
                "name": "lambda"
            }
        },
        "project": {
            "id": "my-project",
            "name": "my project"
        },
        "provider": "aws",
        "region": "us-east-1",
        "service": {
            "name": "lambda"
        },
        "target": {
            "account": {
                "id": "666777888999",
                "name": "elastic-dev"
            },
            "availability_zone": "us-east-1c",
            "instance": {
                "id": "i-1234567890abcdef0",
                "name": "sample-resource"
            },
            "machine": {
                "type": "t2.medium"
            },
            "project": {
                "id": "my-project",
                "name": "my project"
            },
            "provider": "aws",
            "region": "us-east-1",
            "service": {
                "name": "lambda"
            }
        }
    },
    "container": {
        "cpu": {
            "usage": 1
        },
        "disk": {
            "read": {
                "bytes": 42
            },
            "write": {
                "bytes": 42
            }
        },
        "id": "sample-id",
        "image": {
            "hash": {
                "all": [
                    "[sha256:f8fefc80e3273dc756f288a63945820d6476ad64883892c771b5e2ece6bf1b26]"
                ]
            },
            "name": "sample-resource",
            "tag": [
                "item-0"
            ]
        },
        "memory": {
            "usage": 1
        },
        "name": "sample-resource",
        "network": {
            "egress": {
                "bytes": 42
            },
            "ingress": {
                "bytes": 42
            }
        },
        "runtime": "docker"
    },
    "data_stream": {
        "dataset": "beyondtrust_epm.event",
        "namespace": "14305",
        "type": "logs"
    },
    "destination": {
        "address": "198.51.100.100",
        "as": {
            "number": 15169,
            "organization": {
                "name": "Google LLC"
            }
        },
        "bytes": 184,
        "domain": "foo.example.com",
        "geo": {
            "city_name": "Montreal",
            "continent_code": "NA",
            "continent_name": "North America",
            "country_iso_code": "CA",
            "country_name": "Canada",
            "name": "boston-dc",
            "postal_code": "94040",
            "region_iso_code": "CA-QC",
            "region_name": "Quebec",
            "timezone": "America/Argentina/Buenos_Aires"
        },
        "ip": "81.2.69.144",
        "mac": "00-00-5E-00-53-23",
        "nat": {
            "ip": "81.2.69.144",
            "port": 443
        },
        "packets": 12,
        "port": 443,
        "registered_domain": "example.com",
        "subdomain": "east",
        "top_level_domain": "co.uk",
        "user": {
            "domain": "alice",
            "email": "alice",
            "full_name": "Albert Einstein",
            "group": {
                "domain": "corp.example.com",
                "id": "S-1-5-21-3623811015-3361044348-30300820-513",
                "name": "DESKTOP-ACME-01"
            },
            "hash": "alice",
            "id": "S-1-5-21-202424912787-2692429404-2351956786-1000",
            "name": "a.einstein",
            "roles": [
                "kibana_admin",
                "reporting_user"
            ]
        }
    },
    "dll": {
        "code_signature": {
            "digest_algorithm": "sha256",
            "exists": true,
            "signing_id": "com.apple.xpc.proxy",
            "status": "ERROR_UNTRUSTED_ROOT",
            "subject_name": "Microsoft Corporation",
            "team_id": "EQHXZ8M8AV",
            "timestamp": "2026-04-15T06:49:55.541Z",
            "trusted": true,
            "valid": true
        },
        "hash": {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "d41d8cd98f00b204e9800998ecf8427e",
            "sha384": "d41d8cd98f00b204e9800998ecf8427e",
            "sha512": "d41d8cd98f00b204e9800998ecf8427e",
            "ssdeep": "d41d8cd98f00b204e9800998ecf8427e",
            "tlsh": "d41d8cd98f00b204e9800998ecf8427e"
        },
        "name": "kernel32.dll",
        "path": "C:\\Windows\\System32\\kernel32.dll",
        "pe": {
            "architecture": "x64",
            "company": "Microsoft Corporation",
            "description": "Paint",
            "file_version": "6.3.9600.17415",
            "imphash": "0c6803c4e922103c4dca5963aad36ddf",
            "original_file_name": "MSPAINT.EXE",
            "pehash": "73ff189b63cd6be375a7ff25179a38d347651975",
            "product": "Microsoft® Windows® Operating System"
        }
    },
    "dns": {
        "header_flags": [
            "RD",
            "RA"
        ],
        "id": "62111",
        "op_code": "QUERY",
        "question": {
            "class": "IN",
            "name": "www.example.com",
            "registered_domain": "example.com",
            "subdomain": "www",
            "top_level_domain": "co.uk",
            "type": "AAAA"
        },
        "resolved_ip": [
            "10.10.10.10",
            "10.10.10.11"
        ],
        "response_code": "NOERROR",
        "type": "answer"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "4ab492ae-2a84-49b3-a9d5-ae019712a17c",
        "snapshot": false,
        "version": "8.18.0"
    },
    "email": {
        "attachments": {
            "file": {
                "extension": [
                    "sample-extension"
                ],
                "hash": {
                    "md5": [
                        "d41d8cd98f00b204e9800998ecf8427e"
                    ],
                    "sha1": [
                        "d41d8cd98f00b204e9800998ecf8427e"
                    ],
                    "sha256": [
                        "d41d8cd98f00b204e9800998ecf8427e"
                    ],
                    "sha384": [
                        "d41d8cd98f00b204e9800998ecf8427e"
                    ],
                    "sha512": [
                        "d41d8cd98f00b204e9800998ecf8427e"
                    ],
                    "ssdeep": [
                        "d41d8cd98f00b204e9800998ecf8427e"
                    ],
                    "tlsh": [
                        "d41d8cd98f00b204e9800998ecf8427e"
                    ]
                },
                "mime_type": [
                    "sample-mime-type"
                ],
                "name": [
                    "sample.bin"
                ]
            }
        },
        "bcc": {
            "address": [
                "bcc.user1@example.com"
            ]
        },
        "cc": {
            "address": [
                "cc.user1@example.com"
            ]
        },
        "content_type": "text/plain",
        "delivery_timestamp": "2026-04-15T06:49:55.541Z",
        "direction": "inbound",
        "from": {
            "address": [
                "sender@example.com"
            ]
        },
        "local_id": "c26dbea0-80d5-463b-b93c-4e8b708219ce",
        "message_id": "81ce15$8r2j59@mail01.example.com",
        "origination_timestamp": "2026-04-15T06:49:55.541Z",
        "reply_to": {
            "address": [
                "reply.here@example.com"
            ]
        },
        "sender": {
            "address": "198.51.100.100"
        },
        "subject": "Please see this important message.",
        "to": {
            "address": [
                "user1@example.com"
            ]
        },
        "x_mailer": "Spambot v2.5"
    },
    "error": {
        "code": "sample-code",
        "id": "sample-id",
        "stack_trace": "sample-stack-trace",
        "type": "java.lang.NullPointerException"
    },
    "event": {
        "action": [
            "user-password-change"
        ],
        "agent_id_status": "verified",
        "category": [
            "email",
            "file",
            "host",
            "process",
            "threat",
            "vulnerability"
        ],
        "code": [
            "4648"
        ],
        "created": "2026-04-15T06:49:55.541Z",
        "dataset": "beyondtrust_epm.event",
        "duration": 42,
        "end": "2026-04-15T06:49:55.541Z",
        "hash": "123456789012345678901234567890ABCD",
        "id": [
            "8a4f500d"
        ],
        "ingested": "2026-04-29T12:31:45Z",
        "kind": "event",
        "original": "{\"agent\":{\"version\":\"6.0.0-rc2\",\"build\":{\"original\":\"metricbeat version 7.6.0 (amd64), libbeat 7.6.0 [6a23e8f8f30f5001ba344e4e54d8d9cb82cb107c built 2020-02-05 23:10:10 +0000 UTC]\"},\"name\":\"foo\",\"type\":\"filebeat\",\"id\":\"8a4f500d\",\"ephemeral_id\":\"8a4f500f\"},\"@timestamp\":\"2026-04-15T06:49:55.541Z\",\"tags\":[\"production\",\"env2\"],\"labels\":\"application\",\"message\":\"Hello World\",\"client\":{\"address\":\"198.51.100.100\",\"ip\":\"81.2.69.144\",\"port\":443,\"mac\":\"00:00:5E:00:53:23\",\"domain\":\"foo.example.com\",\"registered_domain\":\"example.com\",\"top_level_domain\":\"co.uk\",\"subdomain\":\"east\",\"bytes\":184,\"packets\":12,\"nat\":{\"ip\":\"81.2.69.144\",\"port\":443},\"Name\":\"DESKTOP-ACME-01\",\"as\":{\"number\":15169,\"organization\":{\"name\":\"Google LLC\"}},\"geo\":{\"location\":{\"lon\":-122,\"lat\":37},\"continent_code\":\"NA\",\"continent_name\":\"North America\",\"country_name\":\"Canada\",\"region_name\":\"Quebec\",\"city_name\":\"Montreal\",\"country_iso_code\":\"CA\",\"postal_code\":\"94040\",\"region_iso_code\":\"CA-QC\",\"timezone\":\"America/Argentina/Buenos_Aires\",\"name\":\"boston-dc\",\"TimezoneOffset\":-480},\"user\":{\"id\":\"S-1-5-21-202424912787-2692429404-2351956786-1000\",\"name\":\"a.einstein\",\"full_name\":\"Albert Einstein\",\"email\":\"alice\",\"hash\":\"alice\",\"domain\":\"alice\",\"roles\":[\"kibana_admin\",\"reporting_user\"],\"DomainIdentifier\":\"alice\",\"DomainNetBIOSName\":\"alice\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"},\"target\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-1013\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}},\"effective\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-1013\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}},\"changes\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-1013\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}}}},\"cloud\":{\"provider\":\"aws\",\"availability_zone\":\"us-east-1c\",\"region\":\"us-east-1\",\"instance\":{\"id\":\"i-1234567890abcdef0\",\"name\":\"sample-resource\"},\"machine\":{\"type\":\"t2.medium\"},\"account\":{\"id\":\"666777888999\",\"name\":\"elastic-dev\"},\"service\":{\"name\":\"lambda\"},\"project\":{\"id\":\"my-project\",\"name\":\"my project\"},\"origin\":{\"provider\":\"aws\",\"availability_zone\":\"us-east-1c\",\"region\":\"us-east-1\",\"instance\":{\"id\":\"i-1234567890abcdef0\",\"name\":\"sample-resource\"},\"machine\":{\"type\":\"t2.medium\"},\"account\":{\"id\":\"666777888999\",\"name\":\"elastic-dev\"},\"service\":{\"name\":\"lambda\"},\"project\":{\"id\":\"my-project\",\"name\":\"my project\"}},\"target\":{\"provider\":\"aws\",\"availability_zone\":\"us-east-1c\",\"region\":\"us-east-1\",\"instance\":{\"id\":\"i-1234567890abcdef0\",\"name\":\"sample-resource\"},\"machine\":{\"type\":\"t2.medium\"},\"account\":{\"id\":\"666777888999\",\"name\":\"elastic-dev\"},\"service\":{\"name\":\"lambda\"},\"project\":{\"id\":\"my-project\",\"name\":\"my project\"}}},\"container\":{\"cpu\":{\"usage\":1},\"disk\":{\"read\":{\"bytes\":42},\"write\":{\"bytes\":42}},\"id\":\"sample-id\",\"image\":{\"name\":\"sample-resource\",\"tag\":[\"item-0\"],\"hash\":{\"all\":[\"[sha256:f8fefc80e3273dc756f288a63945820d6476ad64883892c771b5e2ece6bf1b26]\"]}},\"labels\":\"sample-environment\",\"memory\":{\"usage\":1},\"name\":\"sample-resource\",\"network\":{\"ingress\":{\"bytes\":42},\"egress\":{\"bytes\":42}},\"runtime\":\"docker\"},\"data_stream\":{\"type\":\"logs\",\"dataset\":\"beyondtrust_epm.event\",\"namespace\":\"production\"},\"destination\":{\"address\":\"198.51.100.100\",\"ip\":\"81.2.69.144\",\"port\":443,\"mac\":\"00-00-5E-00-53-23\",\"domain\":\"foo.example.com\",\"registered_domain\":\"example.com\",\"top_level_domain\":\"co.uk\",\"subdomain\":\"east\",\"bytes\":184,\"packets\":12,\"nat\":{\"ip\":\"81.2.69.144\",\"port\":443},\"as\":{\"number\":15169,\"organization\":{\"name\":\"Google LLC\"}},\"geo\":{\"location\":{\"lon\":-122,\"lat\":37},\"continent_code\":\"NA\",\"continent_name\":\"North America\",\"country_name\":\"Canada\",\"region_name\":\"Quebec\",\"city_name\":\"Montreal\",\"country_iso_code\":\"CA\",\"postal_code\":\"94040\",\"region_iso_code\":\"CA-QC\",\"timezone\":\"America/Argentina/Buenos_Aires\",\"name\":\"boston-dc\",\"TimezoneOffset\":-480},\"user\":{\"id\":\"S-1-5-21-202424912787-2692429404-2351956786-1000\",\"name\":\"a.einstein\",\"full_name\":\"Albert Einstein\",\"email\":\"alice\",\"hash\":\"alice\",\"domain\":\"alice\",\"roles\":[\"kibana_admin\",\"reporting_user\"],\"DomainIdentifier\":\"alice\",\"DomainNetBIOSName\":\"alice\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"},\"target\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-1013\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}},\"effective\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-1013\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}},\"changes\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-1013\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}}}},\"dll\":{\"name\":\"kernel32.dll\",\"path\":\"C:\\\\Windows\\\\System32\\\\kernel32.dll\",\"hash\":{\"md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha1\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha256\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha384\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha512\":\"d41d8cd98f00b204e9800998ecf8427e\",\"ssdeep\":\"d41d8cd98f00b204e9800998ecf8427e\",\"tlsh\":\"d41d8cd98f00b204e9800998ecf8427e\"},\"pe\":{\"original_file_name\":\"MSPAINT.EXE\",\"file_version\":\"6.3.9600.17415\",\"description\":\"Paint\",\"product\":\"Microsoft® Windows® Operating System\",\"company\":\"Microsoft Corporation\",\"imphash\":\"0c6803c4e922103c4dca5963aad36ddf\",\"architecture\":\"x64\",\"pehash\":\"73ff189b63cd6be375a7ff25179a38d347651975\"},\"code_signature\":{\"exists\":true,\"subject_name\":\"Microsoft Corporation\",\"valid\":true,\"trusted\":true,\"status\":\"ERROR_UNTRUSTED_ROOT\",\"team_id\":\"EQHXZ8M8AV\",\"signing_id\":\"com.apple.xpc.proxy\",\"digest_algorithm\":\"sha256\",\"timestamp\":\"2026-04-15T06:49:55.541Z\"}},\"dns\":{\"type\":\"answer\",\"id\":\"62111\",\"op_code\":\"QUERY\",\"header_flags\":[\"RD\",\"RA\"],\"response_code\":\"NOERROR\",\"question\":{\"name\":\"www.example.com\",\"type\":\"AAAA\",\"class\":\"IN\",\"registered_domain\":\"example.com\",\"top_level_domain\":\"co.uk\",\"subdomain\":\"www\"},\"answers\":\"sample-answers\",\"resolved_ip\":[\"10.10.10.10\",\"10.10.10.11\"]},\"ecs\":{\"version\":\"1.0.0\"},\"email\":{\"attachments\":[{\"file\":{\"extension\":\"sample-extension\",\"mime_type\":\"sample-mime-type\",\"name\":\"sample.bin\",\"hash\":{\"md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha1\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha256\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha384\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha512\":\"d41d8cd98f00b204e9800998ecf8427e\",\"ssdeep\":\"d41d8cd98f00b204e9800998ecf8427e\",\"tlsh\":\"d41d8cd98f00b204e9800998ecf8427e\"}}}],\"bcc\":{\"address\":[\"bcc.user1@example.com\"]},\"cc\":{\"address\":[\"cc.user1@example.com\"]},\"content_type\":\"text/plain\",\"delivery_timestamp\":\"2026-04-15T06:49:55.541Z\",\"direction\":\"inbound\",\"from\":{\"address\":[\"sender@example.com\"]},\"local_id\":\"c26dbea0-80d5-463b-b93c-4e8b708219ce\",\"message_id\":\"81ce15$8r2j59@mail01.example.com\",\"origination_timestamp\":\"2026-04-15T06:49:55.541Z\",\"reply_to\":{\"address\":[\"reply.here@example.com\"]},\"sender\":{\"address\":\"198.51.100.100\"},\"subject\":\"Please see this important message.\",\"to\":{\"address\":[\"user1@example.com\"]},\"x_mailer\":\"Spambot v2.5\"},\"error\":{\"id\":\"sample-id\",\"code\":\"sample-code\",\"type\":\"java.lang.NullPointerException\",\"stack_trace\":\"sample-stack-trace\"},\"event\":{\"id\":\"8a4f500d\",\"code\":\"4648\",\"kind\":\"alert\",\"category\":[\"authentication\"],\"action\":\"user-password-change\",\"outcome\":\"success\",\"type\":[\"item-0\"],\"module\":\"beyondtrust_epm\",\"dataset\":\"beyondtrust_epm.event\",\"provider\":\"kernel\",\"severity\":7,\"original\":\"Sep 19 08:26:10 host CEF:0&#124;Security&#124; threatmanager&#124;1.0&#124;100&#124; worm successfully stopped&#124;10&#124;src=10.0.0.1 dst=2.1.2.2spt=1232\",\"hash\":\"123456789012345678901234567890ABCD\",\"duration\":42,\"sequence\":42,\"timezone\":\"America/Los_Angeles\",\"created\":\"2026-04-15T06:49:55.541Z\",\"start\":\"2026-04-15T06:49:55.541Z\",\"end\":\"2026-04-15T06:49:55.541Z\",\"risk_score\":1,\"risk_score_norm\":1,\"ingested\":\"2026-04-15T06:49:55.541Z\",\"reference\":\"https://system.example.com/event/#0001234\",\"url\":\"https://mysystem.example.com/alert/5271dedb-f5b0-4218-87f0-4ac4870a38fe\",\"reason\":\"Terminated an unexpected process\",\"agent_id_status\":\"verified\",\"ReceivedAt\":\"2026-04-15T06:49:55.541Z\"},\"faas\":{\"name\":\"my-function\",\"id\":\"arn:aws:lambda:us-west-2:123456789012:function:my-function\",\"version\":\"123\",\"coldstart\":true,\"execution\":\"af9d5aa4-a685-4c5f-a22b-444f80b3cc28\",\"trigger\":{\"type\":\"http\",\"request_id\":\"123456789\"}},\"file\":{\"name\":\"example.png\",\"attributes\":[\"readonly\",\"system\"],\"directory\":\"/home/alice\",\"drive_letter\":\"C\",\"path\":\"/home/alice/example.png\",\"target_path\":\"sample-target-path\",\"extension\":\"png\",\"type\":\"file\",\"device\":\"sda\",\"inode\":\"256383\",\"uid\":\"1001\",\"gid\":\"1001\",\"group\":\"alice\",\"owner\":\"alice\",\"mode\":\"0640\",\"size\":16384,\"mtime\":\"2026-04-15T06:49:55.541Z\",\"ctime\":\"2026-04-15T06:49:55.541Z\",\"created\":\"2026-04-15T06:49:55.541Z\",\"accessed\":\"2026-04-15T06:49:55.541Z\",\"mime_type\":\"sample-mime-type\",\"fork_name\":\"Zone.Identifier\",\"DriveType\":\"sample-rive-ype\",\"SourceUrl\":\"sample-ource-rl\",\"ZoneTag\":\"sample-one-ag\",\"ProductVersion\":\"sample-roduct-ersion\",\"Description\":\"sample-escription\",\"Version\":\"sample-version\",\"hash\":{\"md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha1\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha256\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha384\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha512\":\"d41d8cd98f00b204e9800998ecf8427e\",\"ssdeep\":\"d41d8cd98f00b204e9800998ecf8427e\",\"tlsh\":\"d41d8cd98f00b204e9800998ecf8427e\"},\"pe\":{\"original_file_name\":\"MSPAINT.EXE\",\"file_version\":\"6.3.9600.17415\",\"description\":\"Paint\",\"product\":\"Microsoft® Windows® Operating System\",\"company\":\"Microsoft Corporation\",\"imphash\":\"0c6803c4e922103c4dca5963aad36ddf\",\"architecture\":\"x64\",\"pehash\":\"73ff189b63cd6be375a7ff25179a38d347651975\"},\"x509\":{\"version_number\":\"3\",\"serial_number\":\"55FBB9C7DEBF09809D12CCAA\",\"issuer\":{\"distinguished_name\":\"C=US, O=Example Inc, OU=www.example.com, CN=Example SHA2 High Assurance Server CA\",\"common_name\":[\"Example SHA2 High Assurance Server CA\"],\"organizational_unit\":[\"www.example.com\"],\"organization\":[\"Example Inc\"],\"locality\":[\"Mountain View\"],\"state_or_province\":[\"California\"],\"country\":[\"US\"]},\"signature_algorithm\":\"SHA256-RSA\",\"not_before\":\"2026-04-15T06:49:55.541Z\",\"not_after\":\"2026-04-15T06:49:55.541Z\",\"subject\":{\"distinguished_name\":\"C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net\",\"common_name\":[\"shared.global.example.net\"],\"organizational_unit\":[\"item-0\"],\"organization\":[\"Example, Inc.\"],\"locality\":[\"San Francisco\"],\"state_or_province\":[\"California\"],\"country\":[\"US\"]},\"public_key_algorithm\":\"RSA\",\"public_key_size\":2048,\"public_key_exponent\":65537,\"public_key_curve\":\"nistp521\",\"alternative_names\":[\"*.elastic.co\"]},\"Bundle\":{\"Name\":\"sample.bin\",\"Type\":\"EXEC\",\"Creator\":\"sample-reator\",\"InfoDescription\":\"sample-info-escription\",\"Version\":\"sample-version\",\"DownloadSource\":\"sample-ownload-ource\",\"Uri\":\"sample-ri\"},\"Owner\":{\"Identifier\":\"801e9de5-5a58-4f93-a1dc-5c2c3e7c9e01\",\"Name\":\"alice\",\"DomainIdentifier\":\"corp.example.com\",\"DomainName\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\"},\"code_signature\":{\"exists\":true,\"subject_name\":\"Microsoft Corporation\",\"valid\":true,\"trusted\":true,\"status\":\"ERROR_UNTRUSTED_ROOT\",\"team_id\":\"EQHXZ8M8AV\",\"signing_id\":\"com.apple.xpc.proxy\",\"digest_algorithm\":\"sha256\",\"timestamp\":\"2026-04-15T06:49:55.541Z\"},\"elf\":{\"creation_date\":\"2026-04-15T06:49:55.541Z\",\"architecture\":\"x86-64\",\"byte_order\":\"Little Endian\",\"cpu_type\":\"Intel\",\"header\":{\"class\":\"sample-class\",\"data\":\"sample-data\",\"os_abi\":\"sample-os-abi\",\"type\":\"EXEC\",\"version\":\"sample-version\",\"abi_version\":\"sample-abi-version\",\"entrypoint\":42,\"object_version\":\"sample-object-version\"},\"exports\":{\"additionalProp\":\"sample-additional-rop\"},\"imports\":{\"additionalProp\":\"sample-additional-rop\"},\"shared_libraries\":[\"item-0\"],\"telfhash\":\"b1946ac92492d2347c6235b4d2611184\",\"segments\":[{\"type\":\"EXEC\",\"sections\":\"sample-sections\"}]}},\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"sample-resource\",\"domain\":\"corp.example.com\"},\"host\":{\"DefaultUILanguage\":\"example-default-ui-language\",\"NetBIOSName\":\"sample-net-bios\",\"hostname\":\"sample-hostname\",\"name\":\"sample-resource\",\"id\":\"sample-id\",\"ip\":[\"81.2.69.144\"],\"mac\":[\"00-00-5E-00-53-23\",\"00-00-5E-00-53-24\"],\"type\":\"EXEC\",\"uptime\":1325,\"architecture\":\"x86_64\",\"domain\":\"CONTOSO\",\"cpu\":{\"usage\":1},\"disk\":{\"read\":{\"bytes\":42},\"write\":{\"bytes\":42}},\"network\":{\"ingress\":{\"bytes\":42,\"packets\":42},\"egress\":{\"bytes\":42,\"packets\":42}},\"boot\":{\"id\":\"88a1f0ed-5ae5-41ee-af6b-41921c311872\"},\"pid_ns_ino\":\"256383\",\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"ChassisType\":\"sample-hassis-ype\",\"DefaultLocale\":\"sample-efault-ocale\",\"geo\":{\"location\":{\"lon\":-122,\"lat\":37},\"continent_code\":\"NA\",\"continent_name\":\"North America\",\"country_name\":\"Canada\",\"region_name\":\"Quebec\",\"city_name\":\"Montreal\",\"country_iso_code\":\"CA\",\"postal_code\":\"94040\",\"region_iso_code\":\"CA-QC\",\"timezone\":\"America/Argentina/Buenos_Aires\",\"name\":\"boston-dc\",\"TimezoneOffset\":-480},\"os\":{\"type\":\"macos\",\"platform\":\"darwin\",\"name\":\"Mac OS X\",\"full\":\"Mac OS Mojave\",\"family\":\"debian\",\"version\":\"10.14.1\",\"kernel\":\"4.4.0-112-generic\",\"ProductType\":\"sample-roduct-ype\"}},\"http\":{\"request\":{\"id\":\"123e4567-e89b-12d3-a456-426614174000\",\"method\":\"POST\",\"mime_type\":\"image/gif\",\"body\":{\"content\":\"Hello world\",\"bytes\":887},\"referrer\":\"https://blog.example.com/\",\"bytes\":1437},\"response\":{\"status_code\":404,\"mime_type\":\"image/gif\",\"body\":{\"content\":\"Hello world\",\"bytes\":887},\"bytes\":1437},\"version\":\"1.1\"},\"log\":{\"level\":\"error\",\"file\":{\"path\":\"/var/log/fun-times.log\"},\"logger\":\"org.elasticsearch.bootstrap.Bootstrap\",\"origin\":{\"file\":{\"name\":\"Bootstrap.java\",\"line\":42},\"function\":\"init\"},\"syslog\":\"sample-syslog\"},\"network\":{\"name\":\"Guest Wifi\",\"type\":\"ipv4\",\"iana_number\":\"6\",\"transport\":\"tcp\",\"application\":\"aim\",\"protocol\":\"http\",\"direction\":\"inbound\",\"forwarded_ip\":\"67.43.156.1\",\"community_id\":\"1:hO+sN4H+MG5MY/8hIrXPqc4ZQz0=\",\"bytes\":368,\"packets\":24,\"inner\":\"sample-inner\",\"vlan\":{\"id\":\"10\",\"name\":\"outside\"}},\"observer\":{\"mac\":[\"00-00-5E-00-53-23\",\"00-00-5E-00-53-24\"],\"ip\":[\"81.2.69.144\"],\"hostname\":\"sample-hostname\",\"name\":\"1_proxySG\",\"product\":\"s200\",\"vendor\":\"Symantec\",\"version\":\"sample-version\",\"serial_number\":\"sample-serial-number\",\"type\":\"firewall\",\"ingress\":\"sample-ingress\",\"egress\":\"sample-egress\",\"geo\":{\"location\":{\"lon\":-122,\"lat\":37},\"continent_code\":\"NA\",\"continent_name\":\"North America\",\"country_name\":\"Canada\",\"region_name\":\"Quebec\",\"city_name\":\"Montreal\",\"country_iso_code\":\"CA\",\"postal_code\":\"94040\",\"region_iso_code\":\"CA-QC\",\"timezone\":\"America/Argentina/Buenos_Aires\",\"name\":\"boston-dc\",\"TimezoneOffset\":-480},\"os\":{\"type\":\"macos\",\"platform\":\"darwin\",\"name\":\"Mac OS X\",\"full\":\"Mac OS Mojave\",\"family\":\"debian\",\"version\":\"10.14.1\",\"kernel\":\"4.4.0-112-generic\",\"ProductType\":\"sample-roduct-ype\"}},\"orchestrator\":{\"cluster\":{\"name\":\"sample-resource\",\"id\":\"sample-id\",\"url\":\"sample-url\",\"version\":\"sample-version\"},\"type\":\"kubernetes\",\"organization\":\"elastic\",\"namespace\":\"kube-system\",\"resource\":{\"name\":\"test-pod-cdcws\",\"type\":\"service\",\"parent\":{\"type\":\"DaemonSet\"},\"ip\":[\"81.2.69.144\"],\"id\":\"sample-id\"},\"api_version\":\"v1beta1\"},\"organization\":{\"name\":\"sample-resource\",\"id\":\"sample-id\"},\"package\":{\"name\":\"go\",\"version\":\"1.12.9\",\"build_version\":\"36f4f7e89dd61b0988b12ee000b98966867710cd\",\"description\":\"Open source programming language to build simple/reliable/efficient software.\",\"size\":62231,\"installed\":\"2026-04-15T06:49:55.541Z\",\"path\":\"/usr/local/Cellar/go/1.12.9/\",\"architecture\":\"x86_64\",\"checksum\":\"68b329da9893e34099c7d8ad5cb9c940\",\"install_scope\":\"global\",\"license\":\"Apache License 2.0\",\"reference\":\"https://golang.org\",\"type\":\"rpm\"},\"group_leader\":{\"pid\":4242,\"entity_id\":\"sample-entity-id\",\"name\":\"sample-resource\",\"pgid\":4242,\"command_line\":\"sample-command-line\",\"args\":[\"item-0\"],\"args_count\":3,\"executable\":\"sample-executable\",\"title\":\"sample-title\",\"thread\":{\"id\":\"4242\",\"name\":\"sample-resource\"},\"start\":\"2026-04-15T06:49:55.541Z\",\"uptime\":3600,\"working_directory\":\"sample-working-directory\",\"exit_code\":137,\"end\":\"2026-04-15T06:49:55.541Z\",\"interactive\":true,\"same_as_process\":true,\"env_vars\":\"sample-env-vars\",\"entry_meta\":{\"type\":\"terminal\",\"source\":{\"address\":\"198.51.100.100\",\"ip\":\"81.2.69.144\",\"port\":443,\"mac\":\"00:1a:2b:3c:4d:5e\",\"domain\":\"corp.example.com\",\"registered_domain\":\"example.com\",\"top_level_domain\":\"corp.example.com\",\"subdomain\":\"corp.example.com\",\"bytes\":1024,\"packets\":1024,\"nat\":{\"ip\":\"81.2.69.144\",\"port\":443},\"as\":{\"number\":15169,\"organization\":{\"name\":\"DESKTOP-ACME-01\"}},\"geo\":{\"location\":{\"lon\":-122,\"lat\":37},\"continent_code\":\"US\",\"continent_name\":\"North America\",\"country_name\":\"United States\",\"region_name\":\"California\",\"city_name\":\"San Francisco\",\"country_iso_code\":\"US\",\"postal_code\":\"US\",\"region_iso_code\":\"US\",\"timezone\":\"America/Los_Angeles\",\"name\":\"us-west-2\",\"TimezoneOffset\":-480},\"user\":{\"id\":\"alice\",\"name\":\"alice\",\"full_name\":\"alice\",\"email\":\"alice\",\"hash\":\"alice\",\"domain\":\"alice\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"alice\",\"DomainNetBIOSName\":\"alice\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"},\"target\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}},\"effective\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}},\"changes\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"DESKTOP-ACME-01\",\"domain\":\"corp.example.com\"}}}}},\"tty\":\"sample-tty\",\"ElevationRequired\":true,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"sample-resource\",\"domain\":\"corp.example.com\"},\"real_group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"sample-resource\",\"domain\":\"corp.example.com\"},\"saved_group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"sample-resource\",\"domain\":\"corp.example.com\"},\"supplemental_groups\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"sample-resource\",\"domain\":\"corp.example.com\"},\"hash\":{\"md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha1\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha256\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha384\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha512\":\"d41d8cd98f00b204e9800998ecf8427e\",\"ssdeep\":\"d41d8cd98f00b204e9800998ecf8427e\",\"tlsh\":\"d41d8cd98f00b204e9800998ecf8427e\"},\"pe\":{\"original_file_name\":\"MSPAINT.EXE\",\"file_version\":\"6.3.9600.17415\",\"description\":\"Paint\",\"product\":\"Microsoft® Windows® Operating System\",\"company\":\"Microsoft Corporation\",\"imphash\":\"0c6803c4e922103c4dca5963aad36ddf\",\"architecture\":\"x64\",\"pehash\":\"73ff189b63cd6be375a7ff25179a38d347651975\"},\"code_signature\":{\"exists\":true,\"subject_name\":\"Microsoft Corporation\",\"valid\":true,\"trusted\":true,\"status\":\"ERROR_UNTRUSTED_ROOT\",\"team_id\":\"EQHXZ8M8AV\",\"signing_id\":\"com.apple.xpc.proxy\",\"digest_algorithm\":\"sha256\",\"timestamp\":\"2026-04-15T06:49:55.541Z\"},\"elf\":{\"creation_date\":\"2026-04-15T06:49:55.541Z\",\"architecture\":\"x86-64\",\"byte_order\":\"Little Endian\",\"cpu_type\":\"Intel\",\"header\":{\"class\":\"sample-class\",\"data\":\"sample-data\",\"os_abi\":\"sample-os-abi\",\"type\":\"EXEC\",\"version\":\"sample-version\",\"abi_version\":\"sample-abi-version\",\"entrypoint\":42,\"object_version\":\"sample-object-version\"},\"sections\":[{\"flags\":\"sample-flags\",\"name\":\"sample-resource\",\"physical_offset\":\"sample-physical-offset\",\"type\":\"EXEC\",\"physical_size\":8192,\"virtual_address\":4096,\"virtual_size\":8192,\"entropy\":4,\"chi2\":1000}],\"exports\":{\"additionalProp\":\"sample-additional-rop\"},\"imports\":{\"additionalProp\":\"sample-additional-rop\"},\"shared_libraries\":[\"item-0\"],\"telfhash\":\"b1946ac92492d2347c6235b4d2611184\",\"segments\":[{\"type\":\"EXEC\",\"sections\":\"sample-sections\"}]},\"HostedFile\":{\"name\":\"sample.bin\",\"attributes\":[\"item-0\"],\"directory\":\"sample-directory\",\"drive_letter\":\"sample-drive-letter\",\"path\":\"sample-path\",\"target_path\":\"sample-target-path\",\"extension\":\"sample-extension\",\"type\":\"EXEC\",\"device\":\"sample-device\",\"inode\":\"sample-inode\",\"uid\":\"sample-uid\",\"owner\":\"sample-owner\",\"gid\":\"sample-gid\",\"group\":\"sample-group\",\"mode\":\"sample-mode\",\"size\":1024,\"mtime\":\"2026-04-15T06:49:55.541Z\",\"ctime\":\"2026-04-15T06:49:55.541Z\",\"created\":\"2026-04-15T06:49:55.541Z\",\"accessed\":\"2026-04-15T06:49:55.541Z\",\"mime_type\":\"sample-mime-type\",\"fork_name\":\"sample-fork-name\",\"DriveType\":\"sample-rive-ype\",\"SourceUrl\":\"sample-ource-rl\",\"ZoneTag\":\"sample-one-ag\",\"ProductVersion\":\"sample-roduct-ersion\",\"Description\":\"sample-escription\",\"Version\":\"sample-version\",\"hash\":{\"md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha1\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha256\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha384\":\"d41d8cd98f00b204e9800998ecf8427e\",\"sha512\":\"d41d8cd98f00b204e9800998ecf8427e\",\"ssdeep\":\"d41d8cd98f00b204e9800998ecf8427e\",\"tlsh\":\"d41d8cd98f00b204e9800998ecf8427e\"},\"pe\":{\"original_file_name\":\"sample-original-file-name\",\"file_version\":\"sample-file-version\",\"description\":\"sample-description\",\"product\":\"sample-product\",\"company\":\"sample-company\",\"imphash\":\"sample-imphash\",\"architecture\":\"sample-architecture\",\"pehash\":\"b1946ac92492d2347c6235b4d2611184\"},\"x509\":{\"version_number\":\"sample-version-number\",\"serial_number\":\"sample-serial-number\",\"issuer\":{\"distinguished_name\":\"sample-distinguished-name\",\"common_name\":[\"item-0\"],\"organizational_unit\":[\"item-0\"],\"organization\":[\"item-0\"],\"locality\":[\"item-0\"],\"state_or_province\":[\"item-0\"],\"country\":[\"item-0\"]},\"signature_algorithm\":\"sample-signature-algorithm\",\"not_before\":\"2026-04-15T06:49:55.541Z\",\"not_after\":\"2026-04-15T06:49:55.541Z\",\"subject\":{\"distinguished_name\":\"sample-distinguished-name\",\"common_name\":[\"item-0\"],\"organizational_unit\":[\"item-0\"],\"organization\":[\"item-0\"],\"locality\":[\"item-0\"],\"state_or_province\":[\"item-0\"],\"country\":[\"item-0\"]},\"public_key_algorithm\":\"sample-public-key-algorithm\",\"public_key_size\":42,\"public_key_exponent\":42,\"public_key_curve\":\"sample-public-key-curve\",\"alternative_names\":[\"item-0\"]},\"Bundle\":{\"Name\":\"sample.bin\",\"Type\":\"EXEC\",\"Creator\":\"sample-reator\",\"InfoDescription\":\"sample-nfo-escription\",\"Version\":\"sample-version\",\"DownloadSource\":\"sample-ownload-ource\",\"Uri\":\"sample-ri\"},\"Owner\":{\"Identifier\":\"801e9de5-5a58-4f93-a1dc-5c2c3e7c9e01\",\"Name\":\"alice\",\"DomainIdentifier\":\"corp.example.com\",\"DomainName\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\"},\"code_signature\":{\"exists\":true,\"subject_name\":\"sample-subject-name\",\"valid\":true,\"trusted\":true,\"status\":\"sample-status\",\"team_id\":\"sample-team-id\",\"signing_id\":\"sample-signing-id\",\"digest_algorithm\":\"sample-digest-algorithm\",\"timestamp\":\"2026-04-15T06:49:55.541Z\"},\"elf\":{\"creation_date\":\"2026-04-15T06:49:55.541Z\",\"architecture\":\"sample-architecture\",\"byte_order\":\"sample-byte-order\",\"cpu_type\":\"sample-cpu-type\",\"header\":{\"class\":\"sample-class\",\"data\":\"sample-data\",\"os_abi\":\"sample-os-abi\",\"type\":\"EXEC\",\"version\":\"sample-version\",\"abi_version\":\"sample-abi-version\",\"entrypoint\":42,\"object_version\":\"sample-object-version\"},\"sections\":[{\"flags\":\"sample-flags\",\"name\":\"sample.bin\",\"physical_offset\":\"sample-physical-offset\",\"type\":\"EXEC\",\"physical_size\":8192,\"virtual_address\":4096,\"virtual_size\":8192,\"entropy\":4,\"chi2\":1000}],\"exports\":{\"additionalProp\":\"sample-additional-rop\"},\"imports\":{\"additionalProp\":\"sample-additional-rop\"},\"shared_libraries\":[\"item-0\"],\"telfhash\":\"b1946ac92492d2347c6235b4d2611184\",\"segments\":[{\"type\":\"EXEC\",\"sections\":\"sample-sections\"}]}},\"user\":{\"id\":\"S-1-5-21-202424912787-2692429404-2351956786-1000\",\"name\":\"a.einstein\",\"full_name\":\"Albert Einstein\",\"email\":\"alice\",\"hash\":\"alice\",\"domain\":\"alice\",\"roles\":[\"kibana_admin\",\"reporting_user\"],\"DomainIdentifier\":\"alice\",\"DomainNetBIOSName\":\"alice\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"},\"target\":{\"id\":\"S-1-5-21-202424912787-2692429404-2351956786-1000\",\"name\":\"a.einstein\",\"full_name\":\"Albert Einstein\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"kibana_admin\",\"reporting_user\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}},\"effective\":{\"id\":\"S-1-5-21-202424912787-2692429404-2351956786-1000\",\"name\":\"a.einstein\",\"full_name\":\"Albert Einstein\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"kibana_admin\",\"reporting_user\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}},\"changes\":{\"id\":\"S-1-5-21-202424912787-2692429404-2351956786-1000\",\"name\":\"a.einstein\",\"full_name\":\"Albert Einstein\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"kibana_admin\",\"reporting_user\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}}},\"saved_user\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"},\"target\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}},\"effective\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}},\"changes\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}}},\"real_user\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"},\"target\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}},\"effective\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}},\"changes\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"full_name\":\"Alice Williams\",\"email\":\"alice.williams@example.com\",\"hash\":\"b1946ac92492d2347c6235b4d2611184\",\"domain\":\"corp.example.com\",\"roles\":[\"admin\"],\"DomainIdentifier\":\"corp.example.com\",\"DomainNetBIOSName\":\"corp.example.com\",\"DefaultTimezoneOffset\":-480,\"LocalIdentifier\":10001,\"group\":{\"id\":\"S-1-5-21-3623811015-3361044348-30300820-513\",\"name\":\"alice\",\"domain\":\"corp.example.com\"}}}}}",
        "outcome": "success",
        "provider": "kernel",
        "reason": [
            "Terminated an unexpected process"
        ],
        "reference": "https://system.example.com/event/#0001234",
        "risk_score": 1,
        "risk_score_norm": 1,
        "sequence": 42,
        "severity": 7,
        "start": "2026-04-15T06:49:55.541Z",
        "timezone": "America/Los_Angeles",
        "url": "https://mysystem.example.com/alert/5271dedb-f5b0-4218-87f0-4ac4870a38fe"
    },
    "faas": {
        "coldstart": true,
        "execution": "af9d5aa4-a685-4c5f-a22b-444f80b3cc28",
        "id": "arn:aws:lambda:us-west-2:123456789012:function:my-function",
        "name": "my-function",
        "trigger": {
            "request_id": "123456789",
            "type": "http"
        },
        "version": "123"
    },
    "file": {
        "accessed": "2026-04-15T06:49:55.541Z",
        "attributes": [
            "readonly",
            "system"
        ],
        "code_signature": {
            "digest_algorithm": "sha256",
            "exists": true,
            "signing_id": "com.apple.xpc.proxy",
            "status": "ERROR_UNTRUSTED_ROOT",
            "subject_name": "Microsoft Corporation",
            "team_id": "EQHXZ8M8AV",
            "timestamp": "2026-04-15T06:49:55.541Z",
            "trusted": true,
            "valid": true
        },
        "created": "2026-04-15T06:49:55.541Z",
        "ctime": "2026-04-15T06:49:55.541Z",
        "device": "sda",
        "directory": "/home/alice",
        "drive_letter": "C",
        "elf": {
            "architecture": "x86-64",
            "byte_order": "Little Endian",
            "cpu_type": "Intel",
            "creation_date": "2026-04-15T06:49:55.541Z",
            "header": {
                "abi_version": "sample-abi-version",
                "class": "sample-class",
                "data": "sample-data",
                "entrypoint": 42,
                "object_version": "sample-object-version",
                "os_abi": "sample-os-abi",
                "type": "EXEC",
                "version": "sample-version"
            },
            "segments": {
                "sections": [
                    "sample-sections"
                ],
                "type": [
                    "EXEC"
                ]
            },
            "shared_libraries": [
                "item-0"
            ],
            "telfhash": "b1946ac92492d2347c6235b4d2611184"
        },
        "extension": "png",
        "fork_name": "Zone.Identifier",
        "gid": "1001",
        "group": "alice",
        "hash": {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "d41d8cd98f00b204e9800998ecf8427e",
            "sha384": "d41d8cd98f00b204e9800998ecf8427e",
            "sha512": "d41d8cd98f00b204e9800998ecf8427e",
            "ssdeep": "d41d8cd98f00b204e9800998ecf8427e",
            "tlsh": "d41d8cd98f00b204e9800998ecf8427e"
        },
        "inode": "256383",
        "mime_type": "sample-mime-type",
        "mode": "0640",
        "mtime": "2026-04-15T06:49:55.541Z",
        "name": "example.png",
        "origin_url": "sample-ource-rl",
        "owner": "alice",
        "path": "/home/alice/example.png",
        "pe": {
            "architecture": "x64",
            "company": "Microsoft Corporation",
            "description": "Paint",
            "file_version": "6.3.9600.17415",
            "imphash": "0c6803c4e922103c4dca5963aad36ddf",
            "original_file_name": "MSPAINT.EXE",
            "pehash": "73ff189b63cd6be375a7ff25179a38d347651975",
            "product": "Microsoft® Windows® Operating System"
        },
        "size": 16384,
        "target_path": "sample-target-path",
        "type": "file",
        "uid": "1001",
        "x509": {
            "alternative_names": [
                "*.elastic.co"
            ],
            "issuer": {
                "common_name": [
                    "Example SHA2 High Assurance Server CA"
                ],
                "country": [
                    "US"
                ],
                "distinguished_name": "C=US, O=Example Inc, OU=www.example.com, CN=Example SHA2 High Assurance Server CA",
                "locality": [
                    "Mountain View"
                ],
                "organization": [
                    "Example Inc"
                ],
                "organizational_unit": [
                    "www.example.com"
                ],
                "state_or_province": [
                    "California"
                ]
            },
            "not_after": "2026-04-15T06:49:55.541Z",
            "not_before": "2026-04-15T06:49:55.541Z",
            "public_key_algorithm": "RSA",
            "public_key_curve": "nistp521",
            "public_key_exponent": 65537,
            "public_key_size": 2048,
            "serial_number": "55FBB9C7DEBF09809D12CCAA",
            "signature_algorithm": "SHA256-RSA",
            "subject": {
                "common_name": [
                    "shared.global.example.net"
                ],
                "country": [
                    "US"
                ],
                "distinguished_name": "C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net",
                "locality": [
                    "San Francisco"
                ],
                "organization": [
                    "Example, Inc."
                ],
                "organizational_unit": [
                    "item-0"
                ],
                "state_or_province": [
                    "California"
                ]
            },
            "version_number": "3"
        }
    },
    "group": {
        "domain": "corp.example.com",
        "id": "S-1-5-21-3623811015-3361044348-30300820-513",
        "name": [
            "sample-resource"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "boot": {
            "id": "88a1f0ed-5ae5-41ee-af6b-41921c311872"
        },
        "cpu": {
            "usage": 1
        },
        "disk": {
            "read": {
                "bytes": 42
            },
            "write": {
                "bytes": 42
            }
        },
        "domain": "CONTOSO",
        "geo": {
            "city_name": "Montreal",
            "continent_code": "NA",
            "continent_name": "North America",
            "country_iso_code": "CA",
            "country_name": "Canada",
            "name": "boston-dc",
            "postal_code": "94040",
            "region_iso_code": "CA-QC",
            "region_name": "Quebec",
            "timezone": "America/Argentina/Buenos_Aires"
        },
        "hostname": "sample-hostname",
        "id": "sample-id",
        "ip": [
            "81.2.69.144"
        ],
        "mac": [
            "00-00-5E-00-53-23",
            "00-00-5E-00-53-24"
        ],
        "name": "sample-resource",
        "network": {
            "egress": {
                "bytes": 42,
                "packets": 42
            },
            "ingress": {
                "bytes": 42,
                "packets": 42
            }
        },
        "os": {
            "family": "debian",
            "full": "Mac OS Mojave",
            "kernel": "4.4.0-112-generic",
            "name": "Mac OS X",
            "platform": "darwin",
            "type": "macos",
            "version": "10.14.1"
        },
        "pid_ns_ino": "256383",
        "type": "EXEC",
        "uptime": 1325
    },
    "http": {
        "request": {
            "body": {
                "bytes": 887,
                "content": "Hello world"
            },
            "bytes": 1437,
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "method": "POST",
            "mime_type": "image/gif",
            "referrer": "https://blog.example.com/"
        },
        "response": {
            "body": {
                "bytes": 887,
                "content": "Hello world"
            },
            "bytes": 1437,
            "mime_type": "image/gif",
            "status_code": 404
        },
        "version": "1.1"
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "/var/log/fun-times.log"
        },
        "level": "error",
        "logger": "org.elasticsearch.bootstrap.Bootstrap",
        "offset": 0,
        "origin": {
            "file": {
                "line": 42,
                "name": "Bootstrap.java"
            },
            "function": "init"
        }
    },
    "message": [
        "Hello World"
    ],
    "network": {
        "application": "aim",
        "bytes": 368,
        "community_id": "1:hO+sN4H+MG5MY/8hIrXPqc4ZQz0=",
        "direction": "inbound",
        "forwarded_ip": "67.43.156.1",
        "iana_number": "6",
        "name": "Guest Wifi",
        "packets": 24,
        "protocol": "http",
        "transport": "tcp",
        "type": "ipv4",
        "vlan": {
            "id": "10",
            "name": "outside"
        }
    },
    "observer": {
        "geo": {
            "city_name": "Montreal",
            "continent_code": "NA",
            "continent_name": "North America",
            "country_iso_code": "CA",
            "country_name": "Canada",
            "name": "boston-dc",
            "postal_code": "94040",
            "region_iso_code": "CA-QC",
            "region_name": "Quebec",
            "timezone": "America/Argentina/Buenos_Aires"
        },
        "hostname": "sample-hostname",
        "ip": [
            "81.2.69.144"
        ],
        "mac": [
            "00-00-5E-00-53-23",
            "00-00-5E-00-53-24"
        ],
        "name": "1_proxySG",
        "os": {
            "family": "debian",
            "full": "Mac OS Mojave",
            "kernel": "4.4.0-112-generic",
            "name": "Mac OS X",
            "platform": "darwin",
            "type": "macos",
            "version": "10.14.1"
        },
        "product": [
            "Endpoint Privilege Management",
            "s200"
        ],
        "serial_number": "sample-serial-number",
        "type": "firewall",
        "vendor": [
            "BeyondTrust",
            "Symantec"
        ],
        "version": "sample-version"
    },
    "orchestrator": {
        "api_version": "v1beta1",
        "cluster": {
            "id": "sample-id",
            "name": "sample-resource",
            "url": "sample-url",
            "version": "sample-version"
        },
        "namespace": "kube-system",
        "organization": "elastic",
        "resource": {
            "id": "sample-id",
            "ip": [
                "81.2.69.144"
            ],
            "name": "test-pod-cdcws",
            "parent": {
                "type": "DaemonSet"
            },
            "type": "service"
        },
        "type": "kubernetes"
    },
    "organization": {
        "id": [
            "sample-id"
        ],
        "name": "sample-resource"
    },
    "package": {
        "architecture": "x86_64",
        "build_version": "36f4f7e89dd61b0988b12ee000b98966867710cd",
        "checksum": "68b329da9893e34099c7d8ad5cb9c940",
        "description": "Open source programming language to build simple/reliable/efficient software.",
        "install_scope": "global",
        "installed": "2026-04-15T06:49:55.541Z",
        "license": "Apache License 2.0",
        "name": "go",
        "path": "/usr/local/Cellar/go/1.12.9/",
        "reference": "https://golang.org",
        "size": 62231,
        "type": "rpm",
        "version": "1.12.9"
    },
    "related": {
        "hash": [
            "b1946ac92492d2347c6235b4d2611184",
            "alice",
            "[sha256:f8fefc80e3273dc756f288a63945820d6476ad64883892c771b5e2ece6bf1b26]",
            "d41d8cd98f00b204e9800998ecf8427e",
            "0c6803c4e922103c4dca5963aad36ddf",
            "73ff189b63cd6be375a7ff25179a38d347651975",
            "123456789012345678901234567890ABCD"
        ],
        "hosts": [
            "DESKTOP-ACME-01"
        ],
        "ip": [
            "81.2.69.144",
            "10.10.10.10",
            "10.10.10.11",
            "67.43.156.1"
        ],
        "user": [
            "alice.williams@example.com",
            "Alice Williams",
            "DESKTOP-ACME-01",
            "S-1-5-21-3623811015-3361044348-30300820-1013",
            "alice",
            "Albert Einstein",
            "S-1-5-21-202424912787-2692429404-2351956786-1000",
            "a.einstein"
        ]
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "beyondtrust_epm-event",
        "production",
        "env2"
    ],
    "user": {
        "domain": "alice",
        "id": "alice"
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
- [AWS S3](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3)

### API usage

This integration dataset uses the following API:

* List Event Details (endpoint: `/management-api/v3/Events/search`)
