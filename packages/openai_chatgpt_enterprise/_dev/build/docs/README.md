# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/chatgpt/enterprise/) is the enterprise offering of ChatGPT, providing workspace administration, security controls, and compliance capabilities for organizations. The [Compliance Logs Platform](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers) exposes the compliance events generated across a workspace or organization, including administrative activity, authentication, application access, and Codex activity.

This integration for Elastic allows you to collect ChatGPT Enterprise compliance logs using the OpenAI Compliance Logs Platform API, then visualize the data in Kibana.

### Compatibility

This integration is compatible with the OpenAI Compliance Logs Platform API for ChatGPT Enterprise customers.

### How it works

This integration periodically queries the OpenAI Compliance Logs Platform API to retrieve compliance logs. Collection is a two-step (chained) process: the integration first lists the available log files for the configured event type, then downloads each log file and emits every JSON Lines record it contains as an individual event.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Audit Logs`: Collect administrative and workspace audit activity (event type: `AUDIT_LOG`) from the OpenAI Compliance Logs Platform. Each audit event captures the action performed, the acting principal, the outcome, and request metadata such as client IP and user agent.

### Supported use cases

Bringing OpenAI ChatGPT Enterprise Audit Logs into Elastic gives security and compliance teams a searchable, correlatable record of administrative and workspace activity. Audit events describe who performed which action, on which resource, from where, and whether the action succeeded, was blocked, or failed.

Use the `audit_log` data stream to monitor privileged administrative actions (role changes, application access grants, feature toggles, invitations, and workspace policy updates), investigate suspicious activity by user, IP, or geography, and track outcome trends over time. Bundled dashboards summarize activity volume, top actions, top users, action outcomes, and source geography for day-to-day monitoring and investigation.

## What do I need to use this integration?

### From OpenAI

To collect data through the OpenAI Compliance Logs Platform API, you need a **Compliance API key** authorized for enterprise logs and the **Workspace ID** or **Organization ID** whose compliance logs you want to collect.

1. Ensure your account has access to the [Compliance API for enterprise customers](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers).
2. Generate a **Compliance API key** authorized for enterprise logs.
3. Obtain the **Workspace ID** (when Scope is `workspace`) or the **Organization ID** (when Scope is `organization`) whose logs will be collected.
4. Store these values securely for use in the integration configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the OpenAI Compliance Logs Platform API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html)

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **OpenAI ChatGPT Enterprise**.
3. Select the **OpenAI ChatGPT Enterprise** integration from the search results.
4. Select **Add OpenAI ChatGPT Enterprise** to add the integration.
5. Enable and configure the collection method:

    * To **Collect ChatGPT Enterprise compliance logs**, you'll need to:

        - Configure the **URL** and **Compliance API key**.
        - Set the **Scope** (`workspace` or `organization`) and the corresponding **Workspace / Organization ID**.
        - Adjust the integration configuration parameters if required, including the Interval, Initial Interval, and HTTP Client Timeout to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **OpenAI ChatGPT Enterprise**, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Audit Logs

The `audit_log` data stream provides administrative and workspace audit events from the OpenAI ChatGPT Enterprise Compliance Logs Platform.

#### Audit Log fields

{{ fields "audit_log" }}

### Example event

{{ event "audit_log" }}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage

These APIs are used with this integration:

* List compliance log files (endpoint: `GET /v1/compliance/workspaces/{workspace_id}/logs` or `GET /v1/compliance/organizations/{organization_id}/logs`)
* Download a compliance log file (endpoint: `GET /v1/compliance/workspaces/{workspace_id}/logs/{log_file_id}` or `GET /v1/compliance/organizations/{organization_id}/logs/{log_file_id}`)
