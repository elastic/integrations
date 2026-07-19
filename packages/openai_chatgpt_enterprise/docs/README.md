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

An example event for `codex_security_log` looks as following:

```json
{
    "@timestamp": "2026-07-09T12:00:00.000Z",
    "agent": {
        "ephemeral_id": "ec5dc270-4e76-4225-a53e-3964288bc1fe",
        "id": "3195a644-075f-4bff-bbd0-8a4ec62b29b4",
        "name": "elastic-agent-74712",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.codex_security_log",
        "namespace": "43150",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "3195a644-075f-4bff-bbd0-8a4ec62b29b4",
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
        "ingested": "2026-07-19T15:27:31Z",
        "kind": "event",
        "original": "{\"event_id\":\"cs000000-1111-4a11-8b11-000000000002\",\"type\":\"CODEX_SECURITY_LOG\",\"timestamp\":\"2026-07-09T12:00:00.000000Z\",\"principal\":{\"id\":\"11111111-2222-3333-4444-555555555555\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-Aaaaaaaaaaaaaaaaaaaaaaa1\",\"user_email\":\"alice.martin@example.org\"},\"event_type\":\"SCAN_CONFIGURATION_CREATED\",\"client_id\":\"CODEX_WEB\",\"workspace_id\":\"11111111-2222-3333-4444-555555555555\",\"event_details\":{\"detail_type\":\"SCAN_CONFIGURATION_CREATED\",\"scan_configuration_id\":\"scfg-mock-1\",\"scan_configuration_fields\":{\"scan_type\":\"secrets\",\"owner_id\":\"user-Aaaaaaaaaaaaaaaaaaaaaaa1\",\"workspace_id\":\"11111111-2222-3333-4444-555555555555\",\"repo_id\":\"repo-mock-9\",\"repo_url\":\"https://github.com/example-org/example-repo\",\"environment_id\":\"env-mock-123\",\"state\":\"active\",\"lookback_days\":30,\"notification_rules_created_count\":2,\"notification_rules_updated_count\":0,\"notification_rules_deleted_count\":0}}}",
        "type": [
            "info"
        ]
    },
    "gen_ai": {
        "system": "openai"
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

- List Codex Security Log files (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs` with `event_type=CODEX_SECURITY_LOG`).
- Download a Codex Security Log file (endpoint: `GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).
