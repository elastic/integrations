# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/enterprise) is the enterprise offering of ChatGPT, giving organizations administrative controls, security, and compliance capabilities for their use of ChatGPT and Codex. The OpenAI Compliance Logs Platform exposes an API that lets enterprises export compliance logs of activity across their workspace or organization, including authentication activity such as user logins, token issuance, and logouts; application authentication activity such as connecting (linking) and disconnecting (unlinking) apps and connectors; application (connector) activity such as in-app requests and responses to connected apps; Codex agent activity such as tool calls, prompts and responses, plugins, environments, and access tokens; administrative audit activity such as role changes, invitations, and workspace policy updates; Custom Agents (Workspace Agents) activity such as agent lifecycle changes, runs, memory access, connector calls, and trigger management; and conversation messages exchanged between users and the assistant.

This integration for Elastic allows you to collect ChatGPT Enterprise compliance logs using the OpenAI Compliance Logs Platform API, then visualize the data in Kibana.

### Compatibility

This integration collects data from the [OpenAI Compliance Logs Platform API](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers) and requires a ChatGPT Enterprise plan with the Compliance Logs Platform enabled.

### How it works

This integration periodically queries the OpenAI Compliance Logs Platform API to retrieve authentication, application authentication, application (connector), Codex, audit, Custom Agents, and conversation message logs. Collection can be scoped to a single **workspace** or an entire **organization**, and follows a two-step (chained) flow:

1. The integration calls the list endpoint (`GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs`) with the `event_type`, and paginates forward using the `last_end_time` cursor and `has_more` flag returned by the API. This returns metadata for each available log file.
2. For each listed file, the integration downloads its contents (`GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`). This endpoint redirects to a signed download URL that serves the log file as JSON Lines, and each line is ingested as a separate event.

On the first run, logs are pulled back as far as the configured initial interval. From the second collection onward, each run resumes from the `last_end_time` cursor returned by the previous request, so events are collected without gaps or duplication.

> Note: OpenAI retains compliance logs for a limited window (up to 30 days). Configure the initial interval accordingly when first enabling the integration.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Authentication Log`: Collect ChatGPT Enterprise `AUTH_LOG` events, covering user authentication activity such as logins, token issuance, and logouts, along with the client and request context (IP, geo, user agent, and TLS fingerprints) associated with each action (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=AUTH_LOG`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Application Authentication Log`: Collect ChatGPT Enterprise `APP_AUTH_LOG` events, covering application authentication activity such as linking and unlinking apps and connectors (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=APP_AUTH_LOG`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Application Log`: Collects ChatGPT Enterprise `APP_LOG` events — in-app connector requests and responses, including the app/connector identity and type, the acting user, the conversation, the request input, any returned result items, and client context such as user agent and source geolocation (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=APP_LOG`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Codex Log`: Collect ChatGPT Enterprise `CODEX_LOG` events, covering Codex activity such as tool calls, prompts and responses, plugins, environments, and access tokens (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CODEX_LOG`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Audit Log`: Collect ChatGPT Enterprise `AUDIT_LOG` events, covering administrative and workspace audit activity such as role changes, application access grants, feature toggles, invitations, and workspace policy updates, along with request metadata such as client IP and user agent (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=AUDIT_LOG`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Custom Agents Log`: Collect ChatGPT Enterprise `CUSTOM_AGENTS_LOG` events, covering Workspace Agents (Custom Agents) activity such as agent lifecycle changes, agent runs and messages, memory access, connector calls, skill usage, and trigger management, including the acting user or agent, agent metadata, and per-event details (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CUSTOM_AGENTS_LOG`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Conversation Messages`: Collect ChatGPT Enterprise `CONVERSATION_MESSAGE` events — individual user and assistant messages exchanged in ChatGPT Enterprise conversations, including author, client surface, model, tools and skills used, message content, and conversation metadata (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CONVERSATION_MESSAGE`, followed by `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).

### Supported use cases

Bringing ChatGPT Enterprise authentication, application authentication, application (connector), Codex, audit, Custom Agents, and conversation activity into Elastic lets security, compliance, and platform teams search, correlate, and investigate sign-in, app-connection, in-app connector, AI-assisted development, administrative, agent, and conversation activity in one place instead of moving between separate tools.

The **Authentication Log** data stream provides visibility into who signed in, when, from where, and with what client, including the action outcome and source geolocation. Use it to monitor login, token issuance, and logout activity, detect sign-ins from unexpected locations, and surface anomalous or high-risk authentication behavior to support security oversight and auditing.

The **Application Authentication Log** data stream provides visibility into which apps and connectors are linked or unlinked, who performed the action, and the client and request context associated with it. Use it to audit connector lifecycle changes, monitor app-authorization activity, and surface anomalous or high-risk link/unlink actions to support security oversight and auditing.

The **Application Log** data stream provides visibility into how connected apps and connectors are used inside ChatGPT Enterprise. Use it to monitor which apps users invoke and how often, review the requests sent to connectors and the responses returned, attribute connector activity to specific users and conversations, and add source geolocation and user-agent context to investigations.


The **Codex Log** data stream provides visibility into who is using Codex and how, including tool calls and their outcomes, prompts and responses, plugin and environment lifecycle changes, model and token usage, and access token creation and revocation. Use it to audit Codex usage, monitor prompt and response activity, track model and token consumption, and surface anomalous or high-risk actions to support security oversight, auditing, and usage analysis.

The **Audit Log** data stream provides a searchable, correlatable record of administrative and workspace activity. Audit events describe who performed which action, on which resource, from where, and whether the action succeeded, was blocked, or failed. Use it to monitor privileged administrative actions, investigate suspicious activity by user, IP, or geography, and track outcome trends over time.

The **Custom Agents Log** data stream supports monitoring how Workspace Agents are built, published, and operated: which users create, update, publish, or delete agents; how agents run and which models they use; which connectors, skills, and tools they invoke; how they read and write memory; and how triggers are configured. Actor, agent, and event details help track adoption, spot risky or failing activity, and add agent context to broader security investigations in Elastic Security and Kibana.

The **Conversation Messages** data stream supports monitoring how users interact with ChatGPT Enterprise: which users and workspaces are most active, which models and client surfaces are used, how conversations flow between users and the assistant, and which tools, skills, and citations the assistant applies. Message and conversation metadata help track engagement, spot unusual activity, and add conversation context to broader security investigations in Elastic Security and Kibana.


## What do I need to use this integration?

### From Elastic

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

### From OpenAI

To collect data through the OpenAI Compliance Logs Platform API, you need to provide the **Compliance API key** and the **workspace or organization ID** whose logs you want to collect. Authentication is handled using the Compliance API key, which serves as the required credential.

#### Retrieve the Compliance API key and resource ID:

1. Ensure your organization has a **ChatGPT Enterprise** plan with the **Compliance Logs Platform** enabled.
2. Request a **Compliance API key** from OpenAI and ensure it is authorized for enterprise logs (contact OpenAI support to grant the key the `chatgpt.enterprise.compliance_export.read` scope).
3. Identify the **workspace ID** or **organization ID** whose compliance logs you want to collect.
4. Copy both the **Compliance API key** and the **resource ID** and store them securely for use in the integration configuration.

See [Compliance API for enterprise customers](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers) for more details.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **OpenAI ChatGPT Enterprise**.
3. Select the **OpenAI ChatGPT Enterprise** integration from the search results.
4. Select **Add OpenAI ChatGPT Enterprise** to add the integration.
5. Configure the integration:

    * To **Collect ChatGPT Enterprise compliance logs**, you'll need to:

        - Configure the **URL** (default `https://api.chatgpt.com`) and **Compliance API key**.
        - Set the **Scope** to `workspace` or `organization`.
        - Set the **Workspace / Organization ID** to the resource whose compliance logs are collected.
        - Adjust the integration configuration parameters if required, including the Initial Interval, Interval, HTTP Client Timeout and so on to enable data collection.

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

### Auth Log

The `auth_log` data stream captures ChatGPT Enterprise `AUTH_LOG` events (user authentication activity such as logins, token issuance, and logouts, including client and request context).

#### Auth Log fields

{{ fields "auth_log" }}

### Example event

#### Auth Log

{{ event "auth_log" }}

### App Auth Log

The `app_auth_log` data stream captures ChatGPT Enterprise `APP_AUTH_LOG` events (application authentication activity such as linking and unlinking apps and connectors).

#### App Auth Log fields

{{ fields "app_auth_log" }}

### Example event

#### App Auth Log

{{ event "app_auth_log" }}

### App Log

The `app_log` data stream captures ChatGPT Enterprise `APP_LOG` events (in-app connector requests and responses).

#### App Log fields

{{ fields "app_log" }}

### Example event

#### App Log

{{ event "app_log" }}

### Codex Log

The `codex_log` data stream captures ChatGPT Enterprise `CODEX_LOG` events.

#### Codex Log fields

{{ fields "codex_log" }}

### Example event

#### Codex Log

{{ event "codex_log" }}

### Audit Log

The `audit_log` data stream provides administrative and workspace audit events from the OpenAI ChatGPT Enterprise Compliance Logs Platform.

#### Audit Log fields

{{ fields "audit_log" }}

### Example event

#### Audit Log

{{ event "audit_log" }}

### Custom Agents Log

The `custom_agents_log` data stream provides Workspace Agents (Custom Agents) activity events from the OpenAI ChatGPT Enterprise Compliance Logs Platform.

#### Custom Agents Log fields

{{ fields "custom_agents_log" }}

### Example event

#### Custom Agents Log

{{ event "custom_agents_log" }}

### Conversation Messages

The `conversation_message` data stream provides conversation message events from the OpenAI ChatGPT Enterprise Compliance Logs Platform.

#### Conversation Messages fields

{{ fields "conversation_message" }}

### Example event

#### Conversation Messages

{{ event "conversation_message" }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:

* List Authentication Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=AUTH_LOG`).
* List Application Authentication Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=APP_AUTH_LOG`).
* List Application Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=APP_LOG`).
* List Codex Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CODEX_LOG`).
* List Audit Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=AUDIT_LOG`).
* List Custom Agents Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CUSTOM_AGENTS_LOG`).
* List Conversation Message files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CONVERSATION_MESSAGE`).
* Download a compliance log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
