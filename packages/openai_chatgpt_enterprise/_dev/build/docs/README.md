# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/enterprise) provides enterprise-grade access to ChatGPT along with a Compliance Logs Platform that exports a tamper-evident record of workspace and organization activity. Application Logs (`APP_LOG`) capture in-app connector activity — the requests ChatGPT sends to connected apps and connectors (for example Google Drive, Slack, or MCP servers) and the responses returned — together with the acting user, the app involved, and the conversation in which the app was invoked.

This integration for Elastic allows you to collect Application Logs using the OpenAI Compliance Logs Platform API, then visualize and investigate the data in Kibana.

### Compatibility

This integration collects data from the [OpenAI Compliance Logs Platform API](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers), available to ChatGPT Enterprise customers with the Compliance Logs Platform enabled.

### How it works

This integration periodically queries the Compliance Logs Platform API for `APP_LOG` events. Collection uses a two-step chain call: it first lists available log files for the configured workspace or organization, then downloads each file's JSON Lines content and emits one event per line. Pagination advances using the `last_end_time` cursor returned by the listing call, so subsequent runs resume without gaps or duplication.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Application Log`: Collects ChatGPT Enterprise `APP_LOG` events — in-app connector requests and responses, including the app/connector identity and type, the acting user, the conversation, the request input, any returned result items, and client context such as user agent and source geolocation (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=APP_LOG`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).

### Supported use cases

Bringing OpenAI ChatGPT Enterprise Application Logs into Elastic lets security and governance teams see how connected apps and connectors are used inside ChatGPT Enterprise. Use it to monitor which apps users invoke and how often, review the requests sent to connectors and the responses returned, attribute connector activity to specific users and conversations, and add source geolocation and user-agent context to investigations. Bundled dashboards summarize connector usage and top apps, users, and actions for day-to-day monitoring and auditing.

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

### App Log

The `app_log` data stream captures ChatGPT Enterprise `APP_LOG` events (in-app connector requests and responses).

#### App Log fields

{{fields "app_log"}}

### Example event

#### App Log

{{event "app_log"}}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage

These APIs are used with this integration:

- List Application Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=APP_LOG`).
- Download an Application Log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
