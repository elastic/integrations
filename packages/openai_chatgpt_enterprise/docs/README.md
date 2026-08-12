# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/enterprise) is the enterprise offering of ChatGPT, giving organizations administrative controls, security, and compliance capabilities for their use of ChatGPT and Codex. The OpenAI Compliance Logs Platform exposes an API that lets enterprises export compliance logs of activity across their workspace or organization, including authentication activity such as user logins, token issuance, and logouts.

This integration for Elastic allows you to collect ChatGPT Enterprise compliance logs using the OpenAI Compliance Logs Platform API, then visualize the data in Kibana.

### Compatibility

This integration collects data from the [OpenAI Compliance Logs Platform API](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers) and requires a ChatGPT Enterprise plan with the Compliance Logs Platform enabled.

### How it works

This integration periodically queries the OpenAI Compliance Logs Platform API to retrieve authentication logs. Collection can be scoped to a single **workspace** or an entire **organization**, and follows a two-step (chained) flow:

1. The integration calls the list endpoint (`GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs`) with the `event_type`, and paginates forward using the `last_end_time` cursor and `has_more` flag returned by the API. This returns metadata for each available log file.
2. For each listed file, the integration downloads its contents (`GET /v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`). This endpoint redirects to a signed download URL that serves the log file as JSON Lines, and each line is ingested as a separate event.

On the first run, logs are pulled back as far as the configured initial interval. From the second collection onward, each run resumes from the `last_end_time` cursor returned by the previous request, so events are collected without gaps or duplication.

> Note: OpenAI retains compliance logs for a limited window (up to 30 days). Configure the initial interval accordingly when first enabling the integration.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Authentication Log`: Collect ChatGPT Enterprise `AUTH_LOG` events, covering user authentication activity such as logins, token issuance, and logouts, along with the client and request context (IP, geo, user agent, and TLS fingerprints) associated with each action (endpoints: `/v1/compliance/{workspaces|organizations}/{resource_id}/logs` and `/v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`).

### Supported use cases

Bringing ChatGPT Enterprise authentication activity into Elastic lets security, compliance, and platform teams search, correlate, and investigate sign-in activity in one place instead of moving between separate tools.

The **Authentication Log** data stream provides visibility into who signed in, when, from where, and with what client, including the action outcome and source geolocation. Use it to monitor login, token issuance, and logout activity, detect sign-ins from unexpected locations, and surface anomalous or high-risk authentication behavior to support security oversight and auditing.

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
        "ephemeral_id": "4474e3c9-7a41-4b3d-bc3c-14f903733703",
        "id": "5ec78776-e8cd-446a-93af-32bd65607825",
        "name": "elastic-agent-10602",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.auth_log",
        "namespace": "39461",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "5ec78776-e8cd-446a-93af-32bd65607825",
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
        "ingested": "2026-08-11T11:15:49Z",
        "kind": "event",
        "original": "{\"event_id\":\"9532e1b4-e44a-42c7-a52a-083c345e0001\",\"type\":\"AUTH_LOG\",\"principal\":{\"id\":\"11111111-2222-3333-4444-555555555555\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"ACCOUNT_USER\",\"user_id\":\"user-Aaaaaaaaaaaaaaaaaaaaaaa1\",\"user_email\":\"alice.martin@example.org\"},\"timestamp\":\"2026-07-15T10:53:18Z\",\"request_metadata\":{\"client_ip\":\"81.2.69.142\",\"client_ip_details\":{\"country\":\"GB\",\"city\":\"London\",\"region\":\"England\",\"region_code\":\"ENG\",\"latitude\":\"51.50853\",\"longitude\":\"-0.12574\"},\"client_ja3\":\"f90ffded875933863a95a1a84285c922\",\"client_ja4\":\"q13d0311h3_55b375c5d22e_653d80c3fe9d\"},\"action_data\":{\"action\":\"login_success\",\"role\":\"standard-user\"}}",
        "outcome": "success",
        "type": [
            "start"
        ]
    },
    "gen_ai": {
        "system": "openai"
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
    * List log files (endpoint: `/v1/compliance/{workspaces|organizations}/{resource_id}/logs`)
    * Download log file (endpoint: `/v1/compliance/{workspaces|organizations}/{resource_id}/logs/{log_file_id}`)
