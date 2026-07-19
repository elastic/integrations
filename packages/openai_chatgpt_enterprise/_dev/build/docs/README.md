# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/enterprise) provides enterprise-grade access to ChatGPT along with a Compliance Logs Platform that exports a tamper-evident record of workspace and organization activity. Codex Security Logs (`CODEX_SECURITY_LOG`) capture security findings and scan-configuration activity produced by Codex — including scan configurations being created and updated, security findings being triaged (status, criticality, resolution), and proposed patch pull requests being opened for findings.

This integration for Elastic allows you to collect Codex Security Logs using the OpenAI Compliance Logs Platform API, then visualize and investigate the data in Kibana.

### Compatibility

This integration collects data from the [OpenAI Compliance Logs Platform API](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers), available to ChatGPT Enterprise customers with the Compliance Logs Platform enabled.

### How it works

This integration periodically queries the Compliance Logs Platform API for `CODEX_SECURITY_LOG` events. Collection uses a two-step chain call: it first lists available log files for the configured workspace or organization, then downloads each file's JSON Lines content and emits one event per line. Pagination advances using the `last_end_time` cursor returned by the listing call, so subsequent runs resume without gaps or duplication.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Codex Security Log`: Collects ChatGPT Enterprise `CODEX_SECURITY_LOG` events — Codex security findings and scan-configuration changes, including scan configuration create/update details (repository, environment, lookback window, notification rules), finding updates (status, criticality, resolution reason, assignee), and proposed patch pull requests, along with the acting user, Codex client, and workspace context (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CODEX_SECURITY_LOG`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).

### Supported use cases

Bringing OpenAI ChatGPT Enterprise Codex Security Logs into Elastic lets security teams monitor Codex-driven security scanning and finding management. Use it to track scan configurations being created and changed, follow the lifecycle of security findings (triage, criticality, resolution, and remediation via proposed patch PRs), attribute activity to specific users and Codex clients, and correlate findings with the rest of your security data in Elastic. Bundled dashboards summarize findings and scan activity for day-to-day monitoring and auditing.

## What do I need to use this integration?

### From Elastic

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

### From OpenAI ChatGPT Enterprise

To collect data through the OpenAI Compliance Logs Platform API, you need:

- A ChatGPT Enterprise plan with the Compliance Logs Platform enabled.
- A **Compliance API key** authorized for enterprise logs (scope `chatgpt.enterprise.compliance_export.read`). Request the key from OpenAI and, if required, contact OpenAI support to grant the scope. See [Compliance API for enterprise customers](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers) for details.
- The **workspace ID** or **organization ID** whose compliance logs you want to collect.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the OpenAI Compliance Logs Platform API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **OpenAI ChatGPT Enterprise**.
3. Select the **OpenAI ChatGPT Enterprise** integration from the search results.
4. Select **Add OpenAI ChatGPT Enterprise** to add the integration.
5. Configure the data collection method by providing:

    - **URL** — the base URL of the Compliance Logs Platform API (default `https://api.chatgpt.com`).
    - **Compliance API key** — the enterprise-authorized compliance API key.
    - **Scope** — collect at the `workspace` or `organization` level.
    - **Workspace / Organization ID** — the resource ID whose compliance logs are collected.
    - Adjust the integration configuration parameters if required, including the Initial Interval and Interval, to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **OpenAI ChatGPT Enterprise**, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

> Note: OpenAI retains compliance logs for a limited window (up to 30 days). Configure the initial interval accordingly when first enabling the integration; values beyond the retention window will not return older data.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Codex Security Logs

The `codex_security_log` data stream captures ChatGPT Enterprise `CODEX_SECURITY_LOG` events (Codex security findings and scan-configuration changes).

#### Codex Security Log fields

{{fields "codex_security_log"}}

### Example event

{{event "codex_security_log"}}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage

These APIs are used with this integration:

- List Codex Security Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CODEX_SECURITY_LOG`).
- Download a Codex Security Log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
