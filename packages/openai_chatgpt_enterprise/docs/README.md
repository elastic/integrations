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
| openai_chatgpt_enterprise.app_log.actor.type | Type of actor that performed the action (e.g. ACCOUNT_USER, API_KEY). | keyword |
| openai_chatgpt_enterprise.app_log.app_id | Identifier of the connected app / connector. | keyword |
| openai_chatgpt_enterprise.app_log.app_name | Friendly name of the app / connector. | keyword |
| openai_chatgpt_enterprise.app_log.app_type | App backend type (e.g. SERVICE, MCP, FIRST_PARTY_ECOSYSTEM, OPEN_API). | keyword |
| openai_chatgpt_enterprise.app_log.conversation_id | Conversation in which the app was invoked. | keyword |
| openai_chatgpt_enterprise.app_log.input | Raw, free-form request input arguments sent to the app. | flattened |
| openai_chatgpt_enterprise.app_log.log_type | APP_LOG sub-type (request or response). | keyword |
| openai_chatgpt_enterprise.app_log.meta.locale | Locale of the client that issued the request. | keyword |
| openai_chatgpt_enterprise.app_log.meta.organization | Opaque organization identifier of the client that issued the request. | keyword |
| openai_chatgpt_enterprise.app_log.meta.session | Opaque session identifier of the client that issued the request. | keyword |
| openai_chatgpt_enterprise.app_log.meta.subject | Opaque subject identifier of the client that issued the request. | keyword |
| openai_chatgpt_enterprise.app_log.meta.timezone | Timezone reported by the client that issued the request. | keyword |
| openai_chatgpt_enterprise.app_log.output | Raw, free-form response output returned by the app. | flattened |
| openai_chatgpt_enterprise.app_log.principal.type | Principal that owns the event (e.g. CHATGPT_WORKSPACE). | keyword |
| openai_chatgpt_enterprise.app_log.query | Query/input sent to the app on a request log. | keyword |
| openai_chatgpt_enterprise.app_log.type | Top-level event category (e.g. APP_LOG). | keyword |


### Example event

#### App Log

An example event for `app_log` looks as following:

```json
{
    "@timestamp": "2026-07-15T15:39:18.154Z",
    "agent": {
        "ephemeral_id": "87be6f7f-80bc-49d8-ad30-f68b72b3f36d",
        "id": "254ac796-0d7c-4238-815c-490e9920f496",
        "name": "elastic-agent-86157",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.app_log",
        "namespace": "95204",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "254ac796-0d7c-4238-815c-490e9920f496",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "dataset": "openai_chatgpt_enterprise.app_log",
        "id": "3f1a9c02-1111-4a11-8b11-000000000001",
        "ingested": "2026-07-19T14:31:18Z",
        "kind": "event",
        "original": "{\"event_id\":\"3f1a9c02-1111-4a11-8b11-000000000001\",\"type\":\"APP_LOG\",\"principal\":{\"id\":\"11111111-2222-3333-4444-555555555555\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-Aaaaaaaaaaaaaaaaaaaaaaa1\",\"user_email\":\"alice.martin@example.org\"},\"timestamp\":\"2026-07-15T15:39:18.154524Z\",\"app_id\":\"asdk_app_1111111111111111aaaa\",\"app_name\":\"Slack\",\"app_type\":\"MCP\",\"conversation_id\":\"c-1111-aaaa-2222-bbbb\",\"log_type\":\"request\",\"input\":{\"query\":\"in:general after:2026-07-14\",\"limit\":20,\"include_bots\":true,\"sort\":\"timestamp\",\"sort_dir\":\"desc\",\"response_format\":\"concise\",\"_meta\":{\"openai/userAgent\":\"ChatGPT/1.2026.183 (Mac OS X 26.5.2; arm64; build 1783607847)\",\"openai/locale\":\"en-GB\",\"openai/userLocation\":{\"city\":\"London\",\"region\":\"England\",\"country\":\"GB\",\"timezone\":\"Europe/London\",\"latitude\":\"51.50853\",\"longitude\":\"-0.12574\"},\"timezone\":\"Europe/London\",\"openai/subject\":\"v1/mock-subject-aaaaaaaaaaaaaaaa\",\"openai/session\":\"v1/mock-session-aaaaaaaaaaaaaaaa\",\"openai/organization\":\"v1/mock-org-aaaaaaaaaaaaaaaa\"}}}",
        "type": [
            "access"
        ]
    },
    "gen_ai": {
        "system": "openai"
    },
    "input": {
        "type": "cel"
    },
    "openai_chatgpt_enterprise": {
        "app_log": {
            "actor": {
                "type": "ACCOUNT_USER"
            },
            "app_id": "asdk_app_1111111111111111aaaa",
            "app_name": "Slack",
            "app_type": "MCP",
            "conversation_id": "c-1111-aaaa-2222-bbbb",
            "input": {
                "include_bots": true,
                "limit": 20,
                "query": "in:general after:2026-07-14",
                "response_format": "concise",
                "sort": "timestamp",
                "sort_dir": "desc"
            },
            "log_type": "request",
            "meta": {
                "locale": "en-GB",
                "organization": "v1/mock-org-aaaaaaaaaaaaaaaa",
                "session": "v1/mock-session-aaaaaaaaaaaaaaaa",
                "subject": "v1/mock-subject-aaaaaaaaaaaaaaaa",
                "timezone": "Europe/London"
            },
            "principal": {
                "type": "CHATGPT_WORKSPACE"
            },
            "query": "in:general after:2026-07-14",
            "type": "APP_LOG"
        }
    },
    "organization": {
        "id": "11111111-2222-3333-4444-555555555555"
    },
    "related": {
        "user": [
            "alice.martin@example.org",
            "user-Aaaaaaaaaaaaaaaaaaaaaaa1"
        ]
    },
    "source": {
        "geo": {
            "city_name": "London",
            "country_iso_code": "GB",
            "location": "51.50853,-0.12574",
            "region_name": "England"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "openai_chatgpt_enterprise-app_log"
    ],
    "user": {
        "domain": "example.org",
        "email": "alice.martin@example.org",
        "id": "user-Aaaaaaaaaaaaaaaaaaaaaaa1"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Other",
        "original": "ChatGPT/1.2026.183 (Mac OS X 26.5.2; arm64; build 1783607847)",
        "os": {
            "full": "Mac OS X 26.5.2",
            "name": "Mac OS X",
            "version": "26.5.2"
        }
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

- List Application Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=APP_LOG`).
- Download an Application Log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
