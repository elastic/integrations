# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/enterprise) is the enterprise offering of ChatGPT, giving organizations administrative controls, security, and compliance capabilities for their use of ChatGPT and Codex. The OpenAI Compliance Logs Platform exposes an API that lets enterprises export compliance logs of activity across their workspace or organization, including Codex agent activity such as tool calls, prompts and responses, plugins, environments, and access tokens.

This integration for Elastic allows you to collect ChatGPT Enterprise compliance logs using the OpenAI Compliance Logs Platform API, then visualize the data in Kibana.

### Compatibility

The Axonius integration is compatible with ChatGPT API version **v1**.

### How it works

This integration periodically queries the OpenAI Compliance Logs Platform API to retrieve Codex logs. Collection can be scoped to a single **workspace** or an entire **organization**, and follows a two-step (chained) flow:

1. The integration calls the list endpoint (`GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs`) with the `event_type`, and paginates forward using the `last_end_time` cursor and `has_more` flag returned by the API. This returns metadata for each available log file.
2. For each listed file, the integration downloads its contents (`GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`). This endpoint redirects to a signed download URL that serves the log file as JSON Lines, and each line is ingested as a separate event.

On the first run, logs are pulled back as far as the configured initial interval. From the second collection onward, each run resumes from the `last_end_time` cursor returned by the previous request, so events are collected without gaps or duplication.

> Note: OpenAI retains compliance logs for a limited window (up to 30 days). Configure the initial interval accordingly when first enabling the integration.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Codex Log`: Collect ChatGPT Enterprise `CODEX_LOG` events, covering Codex activity such as tool calls, prompts and responses, plugins, environments, and access tokens (endpoints: `/v1/compliance/{workspaces|organizations}/{resource_id}/logs` and `/v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).

### Supported use cases

Bringing ChatGPT Enterprise Codex activity into Elastic lets security, compliance, and platform teams search, correlate, and investigate AI-assisted development activity in one place instead of moving between separate tools.

The **Codex Log** data stream provides visibility into who is using Codex and how, including tool calls and their outcomes, prompts and responses, plugin and environment lifecycle changes, model and token usage, and access token creation and revocation. Use it to audit Codex usage, monitor prompt and response activity, track model and token consumption, and surface anomalous or high-risk actions to support security oversight, auditing, and usage analysis. Bundled dashboards summarize this activity for day-to-day monitoring and investigation.

## What do I need to use this integration?

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

### Codex Log

The `codex_log` data stream captures ChatGPT Enterprise `CODEX_LOG` events.

#### Codex Log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| gen_ai.usage.input_tokens | The number of tokens used in the GenAI input (prompt). | integer |
| gen_ai.usage.output_tokens | The number of tokens used in the GenAI response (completion). | integer |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| openai_chatgpt_enterprise.codex_log.actor.redacted_id | Redacted identifier of the API key (present when actor.type = API_KEY). | keyword |
| openai_chatgpt_enterprise.codex_log.actor.type | Type of actor that performed the action (e.g. ACCOUNT_USER, API_KEY). | keyword |
| openai_chatgpt_enterprise.codex_log.app_id | Identifier of the connected app / connector. | keyword |
| openai_chatgpt_enterprise.codex_log.client_id | Codex client identifier associated with the event. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.access_token_id | Codex access token identifier. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.access_token_name | User-provided access token name. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.arguments.jql | Arguments passed to an app/MCP call (shape varies; example is a Jira JQL query). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.call_id | Identifier of the MCP/tool call. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.created_by_user_id | Auth user ID that created the resource. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.current_settings.default_model | Default model after the change. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.current_settings.network_access | Network-access policy after the change. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.decision | Approval decision for a suggested tool call (e.g. approved, denied). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.detail_type | Discriminator identifying the specific Codex event-details schema. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.elicitation_type | Type of MCP elicitation (e.g. oauth_consent). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.environment_fields.agent_settings.model | Model configured for the environment's agent. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.environment_fields.cache_settings.enabled | Whether environment caching is enabled. | boolean |
| openai_chatgpt_enterprise.codex_log.event_details.environment_fields.description | Environment description. | text |
| openai_chatgpt_enterprise.codex_log.event_details.environment_fields.env_var_keys | Names (keys only) of configured environment variables. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.environment_fields.label | Environment label / name. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.environment_fields.permissions.network_access | Environment network-access permission. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.environment_fields.repos | Repositories attached to the environment. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.environment_id | Codex environment identifier. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.expires_at | Expiration time, e.g. for access tokens. Format assumed RFC3339 (verify). | date |
| openai_chatgpt_enterprise.codex_log.event_details.marketplace_name | Marketplace source for a plugin. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.phase | Turn phase (e.g. prompt). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.plugin_creator_account_user_id | Account user ID that created the plugin. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.plugin_display_name | Plugin display name. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.plugin_id | Plugin identifier. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.plugin_name | Plugin (technical) name. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.plugin_release_id | Plugin release identifier. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.plugin_scope | Plugin scope (e.g. WORKSPACE). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.plugin_version | Plugin version. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.previous_settings.default_model | Default model before the change. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.previous_settings.network_access | Network-access policy before the change. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.prompt_text | Prompt text submitted by the user (sensitive content). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.reasoning_effort | Reasoning effort setting (e.g. low/medium/high). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.response_text | Model response text (sensitive content). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.result_preview | Preview of a tool/call result. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.service_tier | Service tier used for the request. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.session_id | Codex session identifier. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.status | Outcome status (e.g. success, error). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.token_usage.cached_input_tokens | Cached input tokens used. | long |
| openai_chatgpt_enterprise.codex_log.event_details.token_usage.reasoning_output_tokens | Reasoning output tokens generated. | long |
| openai_chatgpt_enterprise.codex_log.event_details.tool_input | Input passed to the tool (shape varies). | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.tool_meta.connector_id | Connector identifier associated with the tool. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.tool_meta.resource_id | Resource identifier associated with the tool. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.turn_id | Identifier of the conversation turn. | keyword |
| openai_chatgpt_enterprise.codex_log.principal.type | Principal that owns the event (e.g. CHATGPT_WORKSPACE). | keyword |
| openai_chatgpt_enterprise.codex_log.type | Top-level event category (e.g. CODEX_LOG). | keyword |
| openai_chatgpt_enterprise.codex_log.workspace_id | Workspace identifier associated with the event. | keyword |


### Example event

#### Codex Log

An example event for `codex_log` looks as following:

```json
{
    "@timestamp": "2026-07-09T10:08:44.000Z",
    "agent": {
        "ephemeral_id": "a5d40f9d-2f79-4cbc-a509-3e959597a92f",
        "id": "220ecd1e-f1fb-4130-9216-6a4ac52af7f1",
        "name": "elastic-agent-81011",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.codex_log",
        "namespace": "90729",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "220ecd1e-f1fb-4130-9216-6a4ac52af7f1",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "prompt_response_received",
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "openai_chatgpt_enterprise.codex_log",
        "id": "cd000000-0000-0000-0000-000000000006",
        "ingested": "2026-07-18T19:32:42Z",
        "kind": "event",
        "original": "{\"event_id\":\"cd000000-0000-0000-0000-000000000006\",\"type\":\"CODEX_LOG\",\"timestamp\":\"2026-07-09T10:08:44.000000Z\",\"principal\":{\"id\":\"be545252-ad04-4cfa-9ca5-deca58416151\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-TUvqhBX7HbQPRgHyEBt5WRcI\",\"user_email\":\"user@example.org\"},\"event_type\":\"PROMPT_RESPONSE_RECEIVED\",\"client_id\":\"CODEX_CLI\",\"workspace_id\":\"be545252-ad04-4cfa-9ca5-deca58416151\",\"event_details\":{\"detail_type\":\"PROMPT_RESPONSE_RECEIVED\",\"session_id\":\"session-123\",\"response_text\":\"Refactored timeline.tsx and split the remediation view.\",\"status\":\"success\",\"turn_id\":\"turn-1\",\"call_id\":\"call-1\",\"model\":\"gpt-5.1-codex-max\",\"service_tier\":\"default\",\"reasoning_effort\":\"medium\",\"token_usage\":{\"input_tokens\":4200,\"output_tokens\":1800,\"cached_input_tokens\":900,\"reasoning_output_tokens\":600},\"environment_id\":\"env-123\"}}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "gen_ai": {
        "request": {
            "model": "gpt-5.1-codex-max"
        },
        "system": "openai",
        "tool": {
            "call": {
                "id": "call-1"
            }
        },
        "usage": {
            "input_tokens": 4200,
            "output_tokens": 1800
        }
    },
    "input": {
        "type": "cel"
    },
    "openai_chatgpt_enterprise": {
        "codex_log": {
            "actor": {
                "type": "ACCOUNT_USER"
            },
            "client_id": "CODEX_CLI",
            "event_details": {
                "call_id": "call-1",
                "detail_type": "PROMPT_RESPONSE_RECEIVED",
                "environment_id": "env-123",
                "reasoning_effort": "medium",
                "response_text": "Refactored timeline.tsx and split the remediation view.",
                "service_tier": "default",
                "session_id": "session-123",
                "status": "success",
                "token_usage": {
                    "cached_input_tokens": 900,
                    "reasoning_output_tokens": 600
                },
                "turn_id": "turn-1"
            },
            "principal": {
                "type": "CHATGPT_WORKSPACE"
            },
            "type": "CODEX_LOG",
            "workspace_id": "be545252-ad04-4cfa-9ca5-deca58416151"
        }
    },
    "organization": {
        "id": "be545252-ad04-4cfa-9ca5-deca58416151"
    },
    "related": {
        "user": [
            "user@example.org",
            "user-TUvqhBX7HbQPRgHyEBt5WRcI"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "openai_chatgpt_enterprise-codex_log"
    ],
    "user": {
        "domain": "example.org",
        "email": "user@example.org",
        "id": "user-TUvqhBX7HbQPRgHyEBt5WRcI"
    }
}
```

### Inputs used

These inputs can be used with this integration:
<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:
- Network connectivity to the target API endpoint
- Valid authentication credentials (API keys, tokens, or certificates as required)
- Appropriate permissions to read from the target data source

### Collecting logs from CEL

To configure the CEL input, you must specify the `request.url` value pointing to the API endpoint. The interval parameter controls how frequently requests are made and is the primary way to balance data freshness with API rate limits and costs. Authentication is often configured through the `request.headers` section using the appropriate method for the service.

NOTE: To access the API service, make sure you have the necessary API credentials and that the Filebeat instance can reach the endpoint URL. Some services may require IP whitelisting or VPN access.

To collect logs via API endpoint, configure the following parameters:

- API Endpoint URL
- API credentials (tokens, keys, or username/password)
- Request interval (how often to fetch data)
</details>


### API usage

These APIs are used with this integration:

* Codex Log:
    * List log files (endpoint: `/v1/compliance/{workspaces|organizations}/{resource_id}/logs`)
    * Download log file (endpoint: `/v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`)
