# Axonius Integration for Elastic

## Overview

[Axonius](https://www.axonius.com/) is a cybersecurity asset management platform that automatically collects data from hundreds of IT and security tools through adapters, merges that information, and builds a unified inventory of all assets—devices, users, SaaS apps, cloud instances, and more. By correlating data from multiple systems, Axonius helps organizations identify visibility gaps, missing security controls, risky configurations, and compliance issues. It lets you create powerful queries to answer any security or IT question and automate actions such as sending alerts, creating tickets, or enforcing policies.

This integration for Elastic allows you to collect assets and security events data using the Axonius API, then visualize the data in Kibana.

### Compatibility
The Axonius integration is compatible with product version **7.0**.

### How it works
This integration periodically queries the Axonius API to retrieve logs.

## What data does this integration collect?
This integration collects log messages of the following type:

- `Gateway`: Collect details of all Gateway (endpoint: `/api/v2/gateway`).

### Supported use cases

Integrating the Axonius Gateway Datastream with Elastic SIEM provides centralized visibility into gateway configurations and the network context they operate in. Kibana dashboards surface key insights into gateway status, routing behavior, and essential connection attributes, helping analysts quickly understand overall network posture.

The dashboards offer clear views of status distribution, highlight important gateway metrics, and provide searchable details that support deeper investigation. Additional tables and saved searches reveal underlying network dependencies and proxy-related information, enabling teams to track configuration changes and identify irregularities.

These insights help security teams monitor gateway health, detect misconfigurations, and streamline network-focused investigations across the environment.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Axonius

To collect data through the Axonius APIs, you need to provide the **URL**, **API Key** and **API Secret**. Authentication is handled using the **API Key** and **API Secret**, which serves as the required credential.

#### Retrieve URL, API Token and API Secret:

1. Log in to the **Axonius** instance.
2. Your instance URL is your Base **URL**.
3. Navigate to **User Settings > API Key**.
4. Generate an **API Key**.
5. Copy both values including **API Key and Secret Key** and store them securely for use in the Integration configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html)

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Axonius**.
3. Select the **Axonius** integration from the search results.
4. Select **Add Axonius** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Axonius API**, you'll need to:

        - Configure **URL**, **API Key** and **API Secret**.
        - Adjust the integration configuration parameters if required, including the Interval, HTTP Client Timeout etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Axonius**, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **axonius**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Gateway

The `gateway` data stream provides gateway events from axonius.

#### gateway fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.gateway.backup_ids | A list of backup gateway IDs. | keyword |
| axonius.gateway.default | Indicates if this gateway is the default gateway connection. | boolean |
| axonius.gateway.dns_server | The IP of the DNS server. | ip |
| axonius.gateway.email_recipients | A list of recipient email addresses. | keyword |
| axonius.gateway.email_when_connected | Notify by email when gateway is connected. | boolean |
| axonius.gateway.email_when_disconnected | Notify by email when gateway is disconnected. | boolean |
| axonius.gateway.id | Gateway ID. | keyword |
| axonius.gateway.name | Gateway name. | keyword |
| axonius.gateway.status | The gateway's connection status. | keyword |
| axonius.gateway.tunnel_proxy_settings.enabled |  | boolean |
| axonius.gateway.tunnel_proxy_settings.tunnel_proxy_addr |  | keyword |
| axonius.gateway.tunnel_proxy_settings.tunnel_proxy_port |  | keyword |
| axonius.gateway.tunnel_proxy_settings.tunnel_proxy_user |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Indicates whether a gateway is in the raw source data stream, or in the latest destination index. | constant_keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `gateway` looks as following:

```json
{
    "@timestamp": "2025-11-26T07:13:10.629Z",
    "agent": {
        "ephemeral_id": "594a7f0e-4997-4f55-9396-b711f61561db",
        "id": "bf9a635e-aa7c-4820-8563-bc0a1a5a6139",
        "name": "elastic-agent-13247",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "axonius": {
        "gateway": {
            "backup_ids": [
                "backup1",
                "backup2"
            ],
            "default": false,
            "dns_server": "1.128.0.0",
            "email_recipients": [
                "john.doe@example.com"
            ],
            "email_when_connected": false,
            "email_when_disconnected": false,
            "id": "tunnel3",
            "name": "Gateway_1",
            "status": "pending",
            "tunnel_proxy_settings": {
                "enabled": false,
                "tunnel_proxy_addr": "addr",
                "tunnel_proxy_port": "8080",
                "tunnel_proxy_user": "tunnel-proxy-01"
            }
        }
    },
    "data_stream": {
        "dataset": "axonius.gateway",
        "namespace": "83710",
        "type": "logs"
    },
    "dns": {
        "resolved_ip": [
            "1.128.0.0"
        ]
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "bf9a635e-aa7c-4820-8563-bc0a1a5a6139",
        "snapshot": false,
        "version": "8.18.0"
    },
    "email": {
        "to": {
            "address": [
                "john.doe@example.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "axonius.gateway",
        "id": "tunnel3",
        "ingested": "2025-11-26T07:13:13Z",
        "kind": "event",
        "original": "{\"backup_ids\":[\"backup1\",\"backup2\"],\"default\":false,\"dns_server\":\"1.128.0.0\",\"email_recipients\":[\"john.doe@example.com\"],\"email_when_connected\":false,\"email_when_disconnected\":false,\"id\":\"tunnel3\",\"name\":\"Gateway_1\",\"status\":\"pending\",\"tunnel_proxy_settings\":{\"enabled\":false,\"tunnel_proxy_addr\":\"addr\",\"tunnel_proxy_port\":8080,\"tunnel_proxy_user\":\"tunnel-proxy-01\"}}"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "ip": [
            "1.128.0.0"
        ],
        "user": [
            "tunnel-proxy-01"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-gateway"
    ]
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

* Gateway (endpoint: `/api/v2/gateway`)

#### ILM Policy

To facilitate gateway data, source data stream-backed indices `.ds-logs-axonius.gateway-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.gateway-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
