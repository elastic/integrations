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

- `Conversation Messages`: Individual user and assistant messages exchanged in ChatGPT Enterprise conversations, including author, client surface, model, tools and skills used, message content, and conversation metadata (endpoint: `/v1/compliance/{workspaces|organizations}/{id}/logs` with `event_type=CONVERSATION_MESSAGE`, then `/v1/compliance/{workspaces|organizations}/{id}/logs/{log_file_id}`).

### Supported use cases

This integration brings ChatGPT Enterprise conversation activity into Elastic so security, compliance, and governance teams can search, correlate, and investigate usage in one place.

The **Conversation Messages** data stream supports monitoring how users interact with ChatGPT Enterprise: which users and workspaces are most active, which models and client surfaces are used, how conversations flow between users and the assistant, and which tools, skills, and citations the assistant applies. Message and conversation metadata help track engagement, spot unusual activity, and add conversation context to broader security investigations in Elastic Security and Kibana.

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

### Conversation Messages

The `conversation_message` data stream provides conversation message events from the OpenAI ChatGPT Enterprise Compliance Logs Platform.

#### Conversation Messages fields

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
| openai_chatgpt_enterprise.conversation_message.actor.type | Type of actor that performed the action (for example ACCOUNT_USER or API_KEY). | keyword |
| openai_chatgpt_enterprise.conversation_message.conversation.created_at | ISO 8601 timestamp for conversation creation. | date |
| openai_chatgpt_enterprise.conversation_message.conversation.id | Conversation identifier. | keyword |
| openai_chatgpt_enterprise.conversation_message.conversation.is_pinned | Whether the conversation was pinned at the time of the event. | boolean |
| openai_chatgpt_enterprise.conversation_message.conversation.is_temporary_chat | Whether the conversation was a temporary chat at the time of the event. | boolean |
| openai_chatgpt_enterprise.conversation_message.conversation.title | Conversation title. | keyword |
| openai_chatgpt_enterprise.conversation_message.message.author.client_type | Client surface associated with a user message. | keyword |
| openai_chatgpt_enterprise.conversation_message.message.author.skills_used | Skill IDs associated with the message. | keyword |
| openai_chatgpt_enterprise.conversation_message.message.author.tools_used | Assistant tools invoked for the response. | keyword |
| openai_chatgpt_enterprise.conversation_message.message.author.type | Author variant discriminator (for example user or assistant). | keyword |
| openai_chatgpt_enterprise.conversation_message.message.content.annotations.type | Annotation type on text content (for example url_citation). | keyword |
| openai_chatgpt_enterprise.conversation_message.message.content.annotations.urls | URLs cited in the text. | keyword |
| openai_chatgpt_enterprise.conversation_message.message.content.type | Content payload discriminator (for example text). | keyword |
| openai_chatgpt_enterprise.conversation_message.message.content.value | Message text/value; may be null when no displayable text exists. | keyword |
| openai_chatgpt_enterprise.conversation_message.message.created_at | ISO 8601 timestamp for when the message was created, when available. | date |
| openai_chatgpt_enterprise.conversation_message.message.id | Stable message identifier. | keyword |
| openai_chatgpt_enterprise.conversation_message.previous_message_id | The message.id of the previous message in the conversation. Omitted for the first message. | keyword |
| openai_chatgpt_enterprise.conversation_message.principal.type | Principal that owns the event (for example CHATGPT_WORKSPACE). | keyword |
| openai_chatgpt_enterprise.conversation_message.type | Top-level event category. Always CONVERSATION_MESSAGE for this data stream. | keyword |


### Example event

An example event for `conversation_message` looks as following:

```json
{
    "@timestamp": "2026-07-15T15:29:00.243Z",
    "agent": {
        "ephemeral_id": "5573e26f-3d19-493e-94aa-fe99080b6d86",
        "id": "5a7ebd3c-e513-4d17-b74e-ccd589f3e2d5",
        "name": "elastic-agent-76339",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.conversation_message",
        "namespace": "14464",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "5a7ebd3c-e513-4d17-b74e-ccd589f3e2d5",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "openai_chatgpt_enterprise.conversation_message",
        "id": "9d6bb4e9-3882-4dbe-9d4c-2668b692f9a1",
        "ingested": "2026-07-19T16:40:00Z",
        "kind": "event",
        "original": "{\"event_id\":\"9d6bb4e9-3882-4dbe-9d4c-2668b692f9a1\",\"type\":\"CONVERSATION_MESSAGE\",\"principal\":{\"id\":\"9f1c2e3a-0b1d-4c2e-8a3f-1122334455aa\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-Aa11QwErTyUiOp\",\"user_email\":\"alice.martin@example.com\"},\"timestamp\":\"2026-07-15T15:29:00.243000Z\",\"message\":{\"id\":\"39adf8b1-e281-42c0-920b-9d8f63426fc8\",\"created_at\":\"2026-07-15T15:29:00.243000Z\",\"author\":{\"type\":\"user\",\"client_type\":\"desktop_web\"},\"content\":{\"type\":\"text\",\"value\":\"Draft a concise release note for v2.3.\"}},\"conversation\":{\"id\":\"6a57a2e4-ba84-832d-9604-9567f8223bc6\",\"title\":\"Release notes\",\"created_at\":\"2026-07-15T15:10:34.219710Z\",\"is_pinned\":false,\"is_temporary_chat\":false}}"
    },
    "gen_ai": {
        "system": "openai"
    },
    "input": {
        "type": "cel"
    },
    "openai_chatgpt_enterprise": {
        "conversation_message": {
            "actor": {
                "type": "ACCOUNT_USER"
            },
            "conversation": {
                "created_at": "2026-07-15T15:10:34.219Z",
                "id": "6a57a2e4-ba84-832d-9604-9567f8223bc6",
                "is_pinned": false,
                "is_temporary_chat": false,
                "title": "Release notes"
            },
            "message": {
                "author": {
                    "client_type": "desktop_web",
                    "type": "user"
                },
                "content": {
                    "type": "text",
                    "value": "Draft a concise release note for v2.3."
                },
                "created_at": "2026-07-15T15:29:00.243Z",
                "id": "39adf8b1-e281-42c0-920b-9d8f63426fc8"
            },
            "principal": {
                "type": "CHATGPT_WORKSPACE"
            },
            "type": "CONVERSATION_MESSAGE"
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
        "openai_chatgpt_enterprise-conversation_message"
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
