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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.agent_runtime.delegator.type | Type of the principal that delegated the agent run. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.agent_runtime.id | Agent runtime identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.agent_task.id | Agent task identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.id | Agent harness identifier for an AGENT actor. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.name | Display name of an AGENT actor. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.product_id | Product (agent) identifier for an AGENT actor. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.product_type | Product type of an AGENT actor. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.redacted_id | Redacted identifier of the API key (present when actor.type = API_KEY). | keyword |
| openai_chatgpt_enterprise.custom_agents_log.actor.type | Type of actor that performed the action (for example ACCOUNT_USER or AGENT). | keyword |
| openai_chatgpt_enterprise.custom_agents_log.client_id | Normalized Workspace Agents client identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.access_method | Memory access mode. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.action_name | Connector action name. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.category | Agent category. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.file_tree_id | Snapshot file tree identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.model_spec.reasoning_effort | Reasoning effort configured for the agent model. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.prompt | Agent system prompt snapshot. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.skills.id | Attached skill identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.skills.name | Attached skill name. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.skills.type | Attached skill type. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.starter_prompts | Configured starter prompts. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.store_visible | Whether the agent is visible in the store. | boolean |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tagline | Agent tagline. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.connectors.allowed_tools | Tools allowed for the connector. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.connectors.auth_variant_type | Connector auth variant type. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.connectors.connector_id | Connector identifier configured on the agent. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.connectors.link_id | Connector link identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.connectors.user_approvals | User approval policy for the connector. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.image_generation | Image generation tool configuration. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.image_generation_enabled | Whether image generation is enabled. | boolean |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.web_search | Web search tool configuration. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.tools.widget_tools | Configured widget tools. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.agent_fields.workspace_capability | Workspace capability of the agent. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.changes_count | Count of included changes in a publish. | long |
| openai_chatgpt_enterprise.custom_agents_log.event_details.connector_id | Connector identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.conversation_id | Conversation identifier for ChatGPT custom-agent invocations. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.detail_type | Discriminator identifying the specific Custom Agents event-details schema. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.elicitation_type | Elicitation mode. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.failure_message | Terminal failure string for incident triage. | text |
| openai_chatgpt_enterprise.custom_agents_log.event_details.had_published_version | Whether the agent had a published version at deletion time. | boolean |
| openai_chatgpt_enterprise.custom_agents_log.event_details.interaction_id | Interaction identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.case_name | Optional case name on the invoker. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.connector_id | Connector identifier for webhook trigger invocations. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.initiator.auth_user_id | Auth user identifier of the initiator when available. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.initiator.display_name | Initiator display name. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.initiator.id | Initiator identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.initiator.kind | Initiator kind. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.is_shared_invocation | Whether this is a shared-agent invocation. | boolean |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.schedule_id | Schedule identifier for scheduled trigger invocations. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.type | Invoker type. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.user_message_text | End-user message text that started a ChatGPT custom-agent run. | text |
| openai_chatgpt_enterprise.custom_agents_log.event_details.invoker.webhook_name | Webhook name for webhook trigger invocations. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.link_id | Connector link identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.memory_path | Memory file or directory path relative to the agent Memory root. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.message_id | Runtime message identifier. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.phase | Agent message phase. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.publish_type | Publication mode. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.release_description | Release description. | text |
| openai_chatgpt_enterprise.custom_agents_log.event_details.release_name | Release title. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.requires_elicitation | Whether the agent determined the tool call needs elicitation before execution. | boolean |
| openai_chatgpt_enterprise.custom_agents_log.event_details.run_id | Stable runtime identifier used to correlate later activity for the same run. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.save_source | Save source label. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.skill_id | Identifier for the attached skill on the agent version. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.skill_name | Display name of the attached skill. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.skill_type | Skill source type. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.text | Extracted displayable agent-authored message text. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_count | Count of triggers linked to the agent at delete time. | long |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_fields.connector_id | Connector identifier for a connector trigger. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_fields.enabled | Whether the trigger is enabled. | boolean |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_fields.instructions | Trigger instructions. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_fields.link_id | Connector link identifier for a trigger. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_fields.param_keys | Parameter keys (keys only) for a trigger. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_fields.required_actions | Required actions for a connector trigger. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_fields.webhook_name | Webhook name for a trigger. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_id | Identifier for the trigger. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.trigger_type | Trigger type string. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.event_details.version_id | Identifier for the saved, runtime, or published version. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.principal.type | Principal that owns the event (for example CHATGPT_WORKSPACE). | keyword |
| openai_chatgpt_enterprise.custom_agents_log.type | Top-level event category. Always CUSTOM_AGENTS_LOG for this data stream. | keyword |
| openai_chatgpt_enterprise.custom_agents_log.workspace_id | Workspace identifier associated with the event. | keyword |


### Example event

#### Custom Agents Log

An example event for `custom_agents_log` looks as following:

```json
{
    "@timestamp": "2026-02-28T20:43:58.762Z",
    "agent": {
        "ephemeral_id": "6a831393-4cfc-48f3-b1e8-2a3887afe2e8",
        "id": "903a05dc-d792-49e6-bb67-d573b87a24b8",
        "name": "elastic-agent-93002",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.custom_agents_log",
        "namespace": "55261",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "903a05dc-d792-49e6-bb67-d573b87a24b8",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "agent_published",
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "openai_chatgpt_enterprise.custom_agents_log",
        "id": "ca000000-0000-0000-0000-000000000003",
        "ingested": "2026-07-19T17:37:41Z",
        "kind": "event",
        "original": "{\"event_id\":\"ca000000-0000-0000-0000-000000000003\",\"type\":\"CUSTOM_AGENTS_LOG\",\"timestamp\":\"2026-02-28T20:43:58.762392Z\",\"principal\":{\"id\":\"9f1c2e3a-0b1d-4c2e-8a3f-1122334455aa\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-Aa11QwErTyUiOp\",\"user_email\":\"alice.martin@example.com\"},\"event_type\":\"AGENT_PUBLISHED\",\"client_id\":\"AGENT_BUILDER_WEB\",\"workspace_id\":\"9f1c2e3a-0b1d-4c2e-8a3f-1122334455aa\",\"event_details\":{\"detail_type\":\"AGENT_PUBLISHED\",\"agent_id\":\"agent-123\",\"version_id\":\"version-7\",\"publish_type\":\"changes\",\"changes_count\":4,\"release_name\":\"v2\",\"release_description\":\"Workflow and connector updates\",\"agent_fields\":{\"model_spec\":{\"name\":\"gpt-5\",\"reasoning_effort\":\"medium\"},\"name\":\"Sales Ops Agent\",\"description\":\"Workspace sales assistant\",\"category\":\"operations\",\"workspace_capability\":\"discover\",\"store_visible\":true,\"skills\":[{\"id\":\"skill-1\",\"type\":\"uploaded_skill\",\"name\":\"crm-guide\"}],\"file_tree_id\":\"snapshot-99\",\"tools\":{\"image_generation_enabled\":false,\"widget_tools\":[],\"connectors\":[{\"connector_id\":\"salesforce\",\"auth_variant_type\":\"LINK\",\"link_id\":\"link-1\",\"allowed_tools\":[\"read\"],\"user_approvals\":\"never\"}]}}}}",
        "type": [
            "info"
        ]
    },
    "gen_ai": {
        "agent": {
            "description": "Workspace sales assistant",
            "id": "agent-123",
            "name": "Sales Ops Agent"
        },
        "request": {
            "model": "gpt-5"
        },
        "system": "openai"
    },
    "input": {
        "type": "cel"
    },
    "openai_chatgpt_enterprise": {
        "custom_agents_log": {
            "actor": {
                "type": "ACCOUNT_USER"
            },
            "client_id": "AGENT_BUILDER_WEB",
            "event_details": {
                "agent_fields": {
                    "category": "operations",
                    "file_tree_id": "snapshot-99",
                    "model_spec": {
                        "reasoning_effort": "medium"
                    },
                    "skills": [
                        {
                            "id": "skill-1",
                            "name": "crm-guide",
                            "type": "uploaded_skill"
                        }
                    ],
                    "store_visible": true,
                    "tools": {
                        "connectors": [
                            {
                                "allowed_tools": [
                                    "read"
                                ],
                                "auth_variant_type": "LINK",
                                "connector_id": "salesforce",
                                "link_id": "link-1",
                                "user_approvals": "never"
                            }
                        ],
                        "image_generation_enabled": false
                    },
                    "workspace_capability": "discover"
                },
                "changes_count": 4,
                "detail_type": "AGENT_PUBLISHED",
                "publish_type": "changes",
                "release_description": "Workflow and connector updates",
                "release_name": "v2",
                "version_id": "version-7"
            },
            "principal": {
                "type": "CHATGPT_WORKSPACE"
            },
            "type": "CUSTOM_AGENTS_LOG",
            "workspace_id": "9f1c2e3a-0b1d-4c2e-8a3f-1122334455aa"
        }
    },
    "organization": {
        "id": "9f1c2e3a-0b1d-4c2e-8a3f-1122334455aa"
    },
    "related": {
        "user": [
            "alice.martin@example.com",
            "user-Aa11QwErTyUiOp"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "openai_chatgpt_enterprise-custom_agents_log"
    ],
    "user": {
        "domain": "example.com",
        "email": "alice.martin@example.com",
        "id": "user-Aa11QwErTyUiOp"
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

* List compliance log files (endpoint: `/v1/compliance/{workspaces|organizations}/{id}/logs`)
* Download a compliance log file (endpoint: `/v1/compliance/{workspaces|organizations}/{id}/logs/{log_file_id}`)
