# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/enterprise) is the enterprise offering of ChatGPT, giving organizations administrative controls, security, and compliance capabilities for their use of ChatGPT and Codex. The OpenAI Compliance Logs Platform exposes an API that lets enterprises export compliance logs of activity across their workspace or organization, including authentication activity such as user logins, token issuance, and logouts; application authentication activity such as connecting (linking) and disconnecting (unlinking) apps and connectors; application (connector) activity such as in-app requests and responses to connected apps; Codex agent activity such as tool calls, prompts and responses, plugins, environments, and access tokens; and Codex security findings and scan-configuration activity.

This integration for Elastic allows you to collect ChatGPT Enterprise compliance logs using the OpenAI Compliance Logs Platform API, then visualize the data in Kibana.

### Compatibility

This integration collects data from the [OpenAI Compliance Logs Platform API](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers) and requires a ChatGPT Enterprise plan with the Compliance Logs Platform enabled.

### How it works

This integration periodically queries the OpenAI Compliance Logs Platform API to retrieve authentication, application authentication, application (connector), Codex, and Codex security logs. Collection can be scoped to a single **workspace** or an entire **organization**, and follows a two-step (chained) flow:

1. The integration calls the list endpoint (`GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs`) with the `event_type`, and paginates forward using the `last_end_time` cursor and `has_more` flag returned by the API. This returns metadata for each available log file.
2. For each listed file, the integration downloads its contents (`GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`). This endpoint redirects to a signed download URL that serves the log file as JSON Lines, and each line is ingested as a separate event.

On the first run, logs are pulled back as far as the configured initial interval. From the second collection onward, each run resumes from the `last_end_time` cursor returned by the previous request, so events are collected without gaps or duplication.

> Note: OpenAI retains compliance logs for a limited window (up to 30 days). Configure the initial interval accordingly when first enabling the integration.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Authentication Log`: Collect ChatGPT Enterprise `AUTH_LOG` events, covering user authentication activity such as logins, token issuance, and logouts, along with the client and request context (IP, geo, user agent, and TLS fingerprints) associated with each action (endpoints: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=AUTH_LOG` and `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Application Authentication Log`: Collect ChatGPT Enterprise `APP_AUTH_LOG` events, covering application authentication activity such as linking and unlinking apps and connectors (endpoints: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=APP_AUTH_LOG` and `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Application Log`: Collects ChatGPT Enterprise `APP_LOG` events — in-app connector requests and responses, including the app/connector identity and type, the acting user, the conversation, the request input, any returned result items, and client context such as user agent and source geolocation (endpoints: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=APP_LOG` and `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Codex Log`: Collect ChatGPT Enterprise `CODEX_LOG` events, covering Codex activity such as tool calls, prompts and responses, plugins, environments, and access tokens (endpoints: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=CODEX_LOG` and `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
- `Codex Security Log`: Collects ChatGPT Enterprise `CODEX_SECURITY_LOG` events — Codex security findings and scan-configuration changes, including scan configuration create/update details (repository, environment, lookback window, notification rules), finding updates (status, criticality, resolution reason, assignee), and proposed patch pull requests, along with the acting user, Codex client, and workspace context (endpoints: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=CODEX_SECURITY_LOG` and `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).

### Supported use cases

Bringing ChatGPT Enterprise authentication, application authentication, application (connector), Codex, and Codex security activity into Elastic lets security, compliance, and platform teams search, correlate, and investigate sign-in, app-connection, in-app connector, AI-assisted development, and Codex security-scanning activity in one place instead of moving between separate tools.

The **Authentication Log** data stream provides visibility into who signed in, when, from where, and with what client, including the action outcome and source geolocation. Use it to monitor login, token issuance, and logout activity, detect sign-ins from unexpected locations, and surface anomalous or high-risk authentication behavior to support security oversight and auditing.

The **Application Authentication Log** data stream provides visibility into which apps and connectors are linked or unlinked, who performed the action, and the client and request context associated with it. Use it to audit connector lifecycle changes, monitor app-authorization activity, and surface anomalous or high-risk link/unlink actions to support security oversight and auditing.

The **Application Log** data stream provides visibility into how connected apps and connectors are used inside ChatGPT Enterprise. Use it to monitor which apps users invoke and how often, review the requests sent to connectors and the responses returned, attribute connector activity to specific users and conversations, and add source geolocation and user-agent context to investigations.

The **Codex Log** data stream provides visibility into who is using Codex and how, including tool calls and their outcomes, prompts and responses, plugin and environment lifecycle changes, model and token usage, and access token creation and revocation. Use it to audit Codex usage, monitor prompt and response activity, track model and token consumption, and surface anomalous or high-risk actions to support security oversight, auditing, and usage analysis.

The **Codex Security Log** data stream provides visibility into Codex-driven security scanning and finding management. Use it to track scan configurations being created and changed, follow the lifecycle of security findings (triage, criticality, resolution, and remediation via proposed patch PRs), attribute activity to specific users and Codex clients, and correlate findings with the rest of your security data in Elastic.

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
| openai_chatgpt_enterprise.auth_log.action_data.role | Role of the acting user at the time of the authentication event (for example, standard-user). | keyword |
| openai_chatgpt_enterprise.auth_log.actor.type | Type of actor that performed the action (for example, ACCOUNT_USER, API_KEY). | keyword |
| openai_chatgpt_enterprise.auth_log.principal.type | Principal that owns the event (for example, CHATGPT_WORKSPACE). | keyword |
| openai_chatgpt_enterprise.auth_log.request_metadata.client_ja4 | JA4 TLS client fingerprint captured at request time. | keyword |
| openai_chatgpt_enterprise.auth_log.type | Top-level event category (for example, AUTH_LOG). | keyword |


### Example event

#### Auth Log

An example event for `auth_log` looks as following:

```json
{
    "@timestamp": "2026-07-15T10:53:18.000Z",
    "agent": {
        "ephemeral_id": "94c9b8af-07f2-4f86-9080-3f2b91504a2b",
        "id": "ab1e5dd6-d45f-40f1-9f24-efb5f02221cc",
        "name": "elastic-agent-87818",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.auth_log",
        "namespace": "69711",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "ab1e5dd6-d45f-40f1-9f24-efb5f02221cc",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "login_success",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "openai_chatgpt_enterprise.auth_log",
        "id": "9532e1b4-e44a-42c7-a52a-083c345e0001",
        "ingested": "2026-08-27T10:24:43Z",
        "kind": "event",
        "original": "{\"event_id\":\"9532e1b4-e44a-42c7-a52a-083c345e0001\",\"type\":\"AUTH_LOG\",\"principal\":{\"id\":\"11111111-2222-3333-4444-555555555555\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-Aaaaaaaaaaaaaaaaaaaaaaa1\",\"user_email\":\"alice.martin@example.org\"},\"timestamp\":\"2026-07-15T10:53:18Z\",\"request_metadata\":{\"client_ip\":\"81.2.69.142\",\"client_ip_details\":{\"country\":\"GB\",\"city\":\"London\",\"region\":\"England\",\"region_code\":\"ENG\",\"latitude\":\"51.50853\",\"longitude\":\"-0.12574\"},\"client_ja3\":\"f90ffded875933863a95a1a84285c922\",\"client_ja4\":\"q13d0311h3_55b375c5d22e_653d80c3fe9d\"},\"action_data\":{\"action\":\"login_success\",\"role\":\"standard-user\"}}",
        "outcome": "success",
        "type": [
            "start"
        ]
    },
    "gen_ai": {
        "provider": {
            "name": "openai"
        }
    },
    "input": {
        "type": "cel"
    },
    "openai_chatgpt_enterprise": {
        "auth_log": {
            "action_data": {
                "role": "standard-user"
            },
            "actor": {
                "type": "ACCOUNT_USER"
            },
            "principal": {
                "type": "CHATGPT_WORKSPACE"
            },
            "request_metadata": {
                "client_ja4": "q13d0311h3_55b375c5d22e_653d80c3fe9d"
            },
            "type": "AUTH_LOG"
        }
    },
    "organization": {
        "id": "11111111-2222-3333-4444-555555555555"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ],
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
            "region_iso_code": "ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "openai_chatgpt_enterprise-auth_log"
    ],
    "tls": {
        "client": {
            "ja3": "f90ffded875933863a95a1a84285c922"
        }
    },
    "user": {
        "domain": "example.org",
        "email": "alice.martin@example.org",
        "id": "user-Aaaaaaaaaaaaaaaaaaaaaaa1"
    }
}
```

### App Auth Log

The `app_auth_log` data stream captures ChatGPT Enterprise `APP_AUTH_LOG` events (application authentication activity such as linking and unlinking apps and connectors).

#### App Auth Log fields

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
| openai_chatgpt_enterprise.app_auth_log.actor.type | Type of actor that performed the action (e.g. ACCOUNT_USER, API_KEY). | keyword |
| openai_chatgpt_enterprise.app_auth_log.app_id | Identifier of the connected app / connector. | keyword |
| openai_chatgpt_enterprise.app_auth_log.link_id | Identifier of the app connection (link) that was linked/unlinked. | keyword |
| openai_chatgpt_enterprise.app_auth_log.principal.type | Principal that owns the event (e.g. CHATGPT_WORKSPACE). | keyword |
| openai_chatgpt_enterprise.app_auth_log.type | Top-level event category (e.g. APP_AUTH_LOG). | keyword |


### Example event

#### App Auth Log

An example event for `app_auth_log` looks as following:

```json
{
    "@timestamp": "2026-07-09T10:10:00.000Z",
    "agent": {
        "ephemeral_id": "2bce5b29-5be0-4a07-a104-19ee02e172de",
        "id": "765890be-1de5-458b-b2e6-f8c0ea163b13",
        "name": "elastic-agent-85768",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.app_auth_log",
        "namespace": "43559",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "765890be-1de5-458b-b2e6-f8c0ea163b13",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "link",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "openai_chatgpt_enterprise.app_auth_log",
        "id": "7b3e4de1-2219-4d6c-9d6e-8f4d40c7c001",
        "ingested": "2026-08-27T10:23:05Z",
        "kind": "event",
        "original": "{\"event_id\":\"7b3e4de1-2219-4d6c-9d6e-8f4d40c7c001\",\"type\":\"APP_AUTH_LOG\",\"timestamp\":\"2026-07-09T10:10:00.000000Z\",\"principal\":{\"id\":\"be545252-ad04-4cfa-9ca5-deca58416151\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-AbCdEf1234567890\",\"user_email\":\"user@example.org\"},\"app_id\":\"asdk_app_0123456789abcdef0123456789abcdef\",\"link_id\":\"link_00112233445566778899aabbccddeeff\",\"action\":\"link\"}",
        "type": [
            "change"
        ]
    },
    "gen_ai": {
        "provider": {
            "name": "openai"
        }
    },
    "input": {
        "type": "cel"
    },
    "openai_chatgpt_enterprise": {
        "app_auth_log": {
            "actor": {
                "type": "ACCOUNT_USER"
            },
            "app_id": "asdk_app_0123456789abcdef0123456789abcdef",
            "link_id": "link_00112233445566778899aabbccddeeff",
            "principal": {
                "type": "CHATGPT_WORKSPACE"
            },
            "type": "APP_AUTH_LOG"
        }
    },
    "organization": {
        "id": "be545252-ad04-4cfa-9ca5-deca58416151"
    },
    "related": {
        "user": [
            "user@example.org",
            "user-AbCdEf1234567890"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "openai_chatgpt_enterprise-app_auth_log"
    ],
    "user": {
        "domain": "example.org",
        "email": "user@example.org",
        "id": "user-AbCdEf1234567890"
    }
}
```

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
        "ephemeral_id": "7e6eae22-73d9-4583-9118-52bd111c571c",
        "id": "a55b9626-c44b-4de5-9bf6-0d9935deeaef",
        "name": "elastic-agent-16522",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.app_log",
        "namespace": "99788",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "a55b9626-c44b-4de5-9bf6-0d9935deeaef",
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
        "ingested": "2026-08-26T06:44:59Z",
        "kind": "event",
        "original": "{\"event_id\":\"3f1a9c02-1111-4a11-8b11-000000000001\",\"type\":\"APP_LOG\",\"principal\":{\"id\":\"11111111-2222-3333-4444-555555555555\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-Aaaaaaaaaaaaaaaaaaaaaaa1\",\"user_email\":\"alice.martin@example.org\"},\"timestamp\":\"2026-07-15T15:39:18.154524Z\",\"app_id\":\"asdk_app_1111111111111111aaaa\",\"app_name\":\"Slack\",\"app_type\":\"MCP\",\"conversation_id\":\"c-1111-aaaa-2222-bbbb\",\"log_type\":\"request\",\"input\":{\"query\":\"in:general after:2026-07-14\",\"limit\":20,\"include_bots\":true,\"sort\":\"timestamp\",\"sort_dir\":\"desc\",\"response_format\":\"concise\",\"_meta\":{\"openai/userAgent\":\"ChatGPT/1.2026.183 (Mac OS X 26.5.2; arm64; build 1783607847)\",\"openai/locale\":\"en-GB\",\"openai/userLocation\":{\"city\":\"London\",\"region\":\"England\",\"country\":\"GB\",\"timezone\":\"Europe/London\",\"latitude\":\"51.50853\",\"longitude\":\"-0.12574\"},\"timezone\":\"Europe/London\",\"openai/subject\":\"v1/mock-subject-aaaaaaaaaaaaaaaa\",\"openai/session\":\"v1/mock-session-aaaaaaaaaaaaaaaa\",\"openai/organization\":\"v1/mock-org-aaaaaaaaaaaaaaaa\"}}}",
        "type": [
            "access"
        ]
    },
    "gen_ai": {
        "provider": {
            "name": "openai"
        }
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
| gen_ai.output.messages | Messages returned by the model where each message represents a specific model response. | flattened |
| gen_ai.tool.call.arguments | Arguments passed to the tool call. | flattened |
| input.type | Type of filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| openai_chatgpt_enterprise.codex_log.actor.redacted_id | Redacted identifier of the API key (present when actor.type = API_KEY). | keyword |
| openai_chatgpt_enterprise.codex_log.actor.type | Type of actor that performed the action (e.g. ACCOUNT_USER, API_KEY). | keyword |
| openai_chatgpt_enterprise.codex_log.app_id | Identifier of the connected app / connector. | keyword |
| openai_chatgpt_enterprise.codex_log.client_id | Codex client identifier associated with the event. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.access_token_id | Codex access token identifier. | keyword |
| openai_chatgpt_enterprise.codex_log.event_details.access_token_name | User-provided access token name. | keyword |
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
        "ephemeral_id": "096cbe4b-c3d2-4e2b-8ccf-1b622b77f266",
        "id": "9477887c-4be9-4d36-b79c-b8f7ff49b7bd",
        "name": "elastic-agent-91546",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.codex_log",
        "namespace": "56933",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "9477887c-4be9-4d36-b79c-b8f7ff49b7bd",
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
        "ingested": "2026-08-27T10:45:45Z",
        "kind": "event",
        "original": "{\"event_id\":\"cd000000-0000-0000-0000-000000000006\",\"type\":\"CODEX_LOG\",\"timestamp\":\"2026-07-09T10:08:44.000000Z\",\"principal\":{\"id\":\"be545252-ad04-4cfa-9ca5-deca58416151\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-TUvqhBX7HbQPRgHyEBt5WRcI\",\"user_email\":\"user@example.org\"},\"event_type\":\"PROMPT_RESPONSE_RECEIVED\",\"client_id\":\"CODEX_CLI\",\"workspace_id\":\"be545252-ad04-4cfa-9ca5-deca58416151\",\"event_details\":{\"detail_type\":\"PROMPT_RESPONSE_RECEIVED\",\"session_id\":\"session-123\",\"response_text\":\"Refactored timeline.tsx and split the remediation view.\",\"status\":\"success\",\"turn_id\":\"turn-1\",\"call_id\":\"call-1\",\"model\":\"gpt-5.1-codex-max\",\"service_tier\":\"default\",\"reasoning_effort\":\"medium\",\"token_usage\":{\"input_tokens\":4200,\"output_tokens\":1800,\"cached_input_tokens\":900,\"reasoning_output_tokens\":600},\"environment_id\":\"env-123\"}}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "gen_ai": {
        "operation": {
            "name": "chat"
        },
        "output": {
            "messages": [
                {
                    "parts": [
                        {
                            "content": "Refactored timeline.tsx and split the remediation view.",
                            "type": "text"
                        }
                    ],
                    "role": "assistant"
                }
            ],
            "type": "text"
        },
        "provider": {
            "name": "openai"
        },
        "request": {
            "model": "gpt-5.1-codex-max"
        },
        "response": {
            "model": "gpt-5.1-codex-max"
        },
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

### Codex Security Logs

The `codex_security_log` data stream captures ChatGPT Enterprise `CODEX_SECURITY_LOG` events (Codex security findings and scan-configuration changes).

#### Codex Security Log fields

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
| openai_chatgpt_enterprise.codex_security_log.actor.type | Type of actor that performed the action (e.g. ACCOUNT_USER, API_KEY). | keyword |
| openai_chatgpt_enterprise.codex_security_log.client_id | Codex client identifier associated with the event (e.g. CODEX_CLI, CODEX_WEB, CODEX_IDE_VSCODE). | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.detail_type | Discriminator identifying the specific Codex security event-details schema. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.environment_id | Environment the scan configuration targets. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.lookback_days | Scan lookback window in days. | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.notification_rules_created_count | Count of notification rules created. | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.notification_rules_deleted_count | Count of notification rules deleted. | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.notification_rules_updated_count | Count of notification rules updated. | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.owner_id | Owner (auth user ID) of the scan configuration. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.repo_id | Repository identifier scanned. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.repo_url | Repository URL scanned. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.scan_type | Type of scan (e.g. secrets). | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.state | Scan configuration state (e.g. active). | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_fields.workspace_id | Workspace of the scan configuration. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.scan_configuration_id | Scan configuration identifier. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.assignee_user_email | Email of the finding assignee after update. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.criticality_reason | Reason for the criticality. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.criticality_reason_updated | Whether criticality_reason changed in this update. | boolean |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.environment_id | Environment identifier (updated field). | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.lookback_days | Lookback days (updated field). | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.notification_rules_created_count | Notification rules created count (updated field). | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.notification_rules_deleted_count | Notification rules deleted count (updated field). | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.notification_rules_updated_count | Notification rules updated count (updated field). | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.owner_id | Owner id (updated field). | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.project_overview_length | Length of the project overview text (updated). | long |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.project_overview_updated | Whether the project overview changed. | boolean |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.resolution_reason | Reason recorded when resolving the finding. | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.resolution_reason_updated | Whether resolution_reason changed. | boolean |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.state | State (updated field). | keyword |
| openai_chatgpt_enterprise.codex_security_log.event_details.updated_fields.status | Finding status after update (e.g. wontfix). | keyword |
| openai_chatgpt_enterprise.codex_security_log.principal.type | Principal that owns the event (e.g. CHATGPT_WORKSPACE). | keyword |
| openai_chatgpt_enterprise.codex_security_log.type | Top-level event category (CODEX_SECURITY_LOG). | keyword |
| openai_chatgpt_enterprise.codex_security_log.workspace_id | Workspace identifier associated with the event. | keyword |


### Example event

#### Codex Security Log

An example event for `codex_security_log` looks as following:

```json
{
    "@timestamp": "2026-07-09T12:00:00.000Z",
    "agent": {
        "ephemeral_id": "a6dfe8ba-7f29-4e70-a709-baec1cf95e45",
        "id": "e19bfbce-9441-45e8-abef-bdcace007442",
        "name": "elastic-agent-99793",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.codex_security_log",
        "namespace": "80099",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "e19bfbce-9441-45e8-abef-bdcace007442",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "scan_configuration_created",
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "openai_chatgpt_enterprise.codex_security_log",
        "id": "cs000000-1111-4a11-8b11-000000000002",
        "ingested": "2026-08-18T06:40:14Z",
        "kind": "event",
        "original": "{\"event_id\":\"cs000000-1111-4a11-8b11-000000000002\",\"type\":\"CODEX_SECURITY_LOG\",\"timestamp\":\"2026-07-09T12:00:00.000000Z\",\"principal\":{\"id\":\"11111111-2222-3333-4444-555555555555\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-Aaaaaaaaaaaaaaaaaaaaaaa1\",\"user_email\":\"alice.martin@example.org\"},\"event_type\":\"SCAN_CONFIGURATION_CREATED\",\"client_id\":\"CODEX_WEB\",\"workspace_id\":\"11111111-2222-3333-4444-555555555555\",\"event_details\":{\"detail_type\":\"SCAN_CONFIGURATION_CREATED\",\"scan_configuration_id\":\"scfg-mock-1\",\"scan_configuration_fields\":{\"scan_type\":\"secrets\",\"owner_id\":\"user-Aaaaaaaaaaaaaaaaaaaaaaa1\",\"workspace_id\":\"11111111-2222-3333-4444-555555555555\",\"repo_id\":\"repo-mock-9\",\"repo_url\":\"https://github.com/example-org/example-repo\",\"environment_id\":\"env-mock-123\",\"state\":\"active\",\"lookback_days\":30,\"notification_rules_created_count\":2,\"notification_rules_updated_count\":0,\"notification_rules_deleted_count\":0}}}",
        "type": [
            "info"
        ]
    },
    "gen_ai": {
        "provider": {
            "name": "openai"
        }
    },
    "input": {
        "type": "cel"
    },
    "openai_chatgpt_enterprise": {
        "codex_security_log": {
            "actor": {
                "type": "ACCOUNT_USER"
            },
            "client_id": "CODEX_WEB",
            "event_details": {
                "detail_type": "SCAN_CONFIGURATION_CREATED",
                "scan_configuration_fields": {
                    "environment_id": "env-mock-123",
                    "lookback_days": 30,
                    "notification_rules_created_count": 2,
                    "notification_rules_deleted_count": 0,
                    "notification_rules_updated_count": 0,
                    "owner_id": "user-Aaaaaaaaaaaaaaaaaaaaaaa1",
                    "repo_id": "repo-mock-9",
                    "repo_url": "https://github.com/example-org/example-repo",
                    "scan_type": "secrets",
                    "state": "active",
                    "workspace_id": "11111111-2222-3333-4444-555555555555"
                },
                "scan_configuration_id": "scfg-mock-1"
            },
            "principal": {
                "type": "CHATGPT_WORKSPACE"
            },
            "type": "CODEX_SECURITY_LOG",
            "workspace_id": "11111111-2222-3333-4444-555555555555"
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
    "tags": [
        "preserve_original_event",
        "forwarded",
        "openai_chatgpt_enterprise-codex_security_log"
    ],
    "user": {
        "domain": "example.org",
        "email": "alice.martin@example.org",
        "id": "user-Aaaaaaaaaaaaaaaaaaaaaaa1"
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

* Authentication Log:
    * List log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=AUTH_LOG`)
    * Download log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`)
* Application Authentication Log:
    * List log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=APP_AUTH_LOG`)
    * Download log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`)
* Application Log:
    * List log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=APP_LOG`)
    * Download log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`)
* Codex Log:
    * List log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=CODEX_LOG`)
    * Download log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`)
* Codex Security Log:
    * List log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs?event_type=CODEX_SECURITY_LOG`)
    * Download log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`)
