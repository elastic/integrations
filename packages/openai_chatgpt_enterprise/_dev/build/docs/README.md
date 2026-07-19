# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/enterprise/) provides a Compliance Logs Platform (Compliance API) that lets enterprise administrators export activity from their ChatGPT Enterprise workspace or organization for security, compliance, and auditing purposes. The platform exposes conversation content, application activity, authentication events, audit events, and Codex activity as structured log files that can be retrieved programmatically.

This integration for Elastic allows you to collect ChatGPT Enterprise compliance logs using the OpenAI Compliance Logs Platform API, then visualize and investigate the data in Kibana.

### Compatibility

This integration collects data from the OpenAI Compliance Logs Platform API for ChatGPT Enterprise. It requires a Compliance API key authorized for enterprise logs.

### How it works

This integration periodically queries the OpenAI Compliance Logs Platform API to retrieve logs. Collection uses a chain of two requests: the integration first lists the available log files for the selected event type (paging forward with a time cursor), and then downloads each listed file, which serves its content as JSON Lines. Each line is emitted as a separate event and processed by the integration's ingest pipeline.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Custom Agents Logs`: Workspace Agents (Custom Agents) activity such as agent lifecycle changes, agent runs and messages, memory access, connector calls, skill usage, and trigger management, including the acting user or agent, agent metadata, and per-event details (endpoint: `/v1/compliance/{workspaces|organizations}/{id}/logs` with `event_type=CUSTOM_AGENTS_LOG`, then `/v1/compliance/{workspaces|organizations}/{id}/logs/{log_file_id}`).

### Supported use cases

This integration brings ChatGPT Enterprise Custom Agents activity into Elastic so security, compliance, and governance teams can search, correlate, and investigate usage in one place.

The **Custom Agents Logs** data stream supports monitoring how Workspace Agents are built, published, and operated: which users create, update, publish, or delete agents; how agents run and which models they use; which connectors, skills, and tools they invoke; how they read and write memory; and how triggers are configured. Actor, agent, and event details help track adoption, spot risky or failing activity, and add agent context to broader security investigations in Elastic Security and Kibana.

## What do I need to use this integration?

### From Elastic

Elastic Agent must be installed for the agent-based deployment. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### From OpenAI

To collect data through the OpenAI Compliance Logs Platform API, you need a **Compliance API key** authorized for enterprise logs, and the **workspace ID** or **organization ID** whose logs you want to collect.

1. Confirm your organization has the ChatGPT Enterprise Compliance API enabled. See [Compliance API for enterprise customers](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers).
2. Generate a Compliance API key with access to enterprise compliance logs and store it securely.
3. Identify the **Scope** (`workspace` or `organization`) and the corresponding **Workspace / Organization ID** for the logs you want to collect.

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
5. Enable and configure only the collection methods which you will use.

    * To **Collect ChatGPT Enterprise compliance logs**, you'll need to:

        - Configure the **URL** and **Compliance API key**.
        - Set the **Scope** and **Workspace / Organization ID**.
        - Adjust the integration configuration parameters if required, including the Initial Interval, Interval, HTTP Client Timeout etc. to enable data collection.

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

### Custom Agents Log

The `custom_agents_log` data stream provides Workspace Agents (Custom Agents) activity events from the OpenAI ChatGPT Enterprise Compliance Logs Platform.

#### Custom Agents Log fields

{{ fields "custom_agents_log" }}

### Example event

#### Custom Agents Log

{{ event "custom_agents_log" }}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage

These APIs are used with this integration:

* List compliance log files (endpoint: `/v1/compliance/{workspaces|organizations}/{id}/logs`)
* Download a compliance log file (endpoint: `/v1/compliance/{workspaces|organizations}/{id}/logs/{log_file_id}`)
