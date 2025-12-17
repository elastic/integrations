# Axonius Integration for Elastic

## Overview

[Axonius](https://www.axonius.com/) is a cybersecurity asset management platform that automatically collects data from hundreds of IT and security tools through adapters, merges that information, and builds a unified inventory of all assets including devices, users, SaaS apps, cloud instances, and more. By correlating data from multiple systems, Axonius helps organizations identify visibility gaps, missing security controls, risky configurations, and compliance issues. It lets you create powerful queries to answer any security or IT question and automate actions such as sending alerts, creating tickets, or enforcing policies.

This integration for Elastic allows you to collect assets and security events data using the Axonius API, then visualize the data in Kibana.

### Compatibility
The Axonius integration is compatible with product version **7.0**.

### How it works
This integration periodically queries the Axonius API to retrieve logs.

## What data does this integration collect?
This integration collects log messages of the following type:

- `Adapter`: Collect details of all adapters (endpoint: `/api/v2/adapters`).

- `User`: Collect details of all users (endpoint: `/api/v2/users`).

### Supported use cases

Integrating the Axonius Adapters and User Datastreams with Elastic SIEM provides centralized visibility into both data-collection health and user identity context across the environment. Together, these datastreams help analysts understand how data is being ingested through adapters and how that data maps to user identities and access posture.

The dashboards highlight overall adapter status and connection behavior, making it easy to identify healthy integrations, failing plugins, and error-prone connections that may impact asset visibility. At the same time, user-focused views surface role distribution and essential identity attributes, helping analysts quickly assess access patterns and identify high-privileged or unusual user activity. Consolidated user details and source information provide clarity on where identity data originates and whether coverage gaps exist.

By combining adapter health insights with user identity visibility, security teams can ensure reliable data ingestion, detect identity-related anomalies, reduce blind spots, and streamline investigations that depend on accurate, end-to-end context from both integrations and users.

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
3. In the search bar, type **Axonius**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Adapter

The `adapter` data stream provides adapter logs from axonius.

#### adapter fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.adapter.adapter_configs | All the adapter level configuration. | flattened |
| axonius.adapter.connections.active | Indicates whether the connection is active or not. | boolean |
| axonius.adapter.connections.adapter_name | Name of the adapter. | keyword |
| axonius.adapter.connections.connection_adapter_config | Adapter configuration. Connection level configuration. | flattened |
| axonius.adapter.connections.connection_advanced_config | Advanced configuration of the adapter. | flattened |
| axonius.adapter.connections.connection_config | Basic adapter configuration of the connection. | flattened |
| axonius.adapter.connections.connection_discovery | Discovery configuration of the adapter. | flattened |
| axonius.adapter.connections.connection_id | Unique ID of the connection. | keyword |
| axonius.adapter.connections.curl | Curl command to test. Available only if curl command is known for the received error. | keyword |
| axonius.adapter.connections.did_notify_error | Indicates whether the connection notified an error or not. | boolean |
| axonius.adapter.connections.error | Error of the connection. | keyword |
| axonius.adapter.connections.failed_connections_limit_exceeded | Indicating if the connection attempts limit has been exceeded. | boolean |
| axonius.adapter.connections.id | Unique ID of the connection. | keyword |
| axonius.adapter.connections.last_fetch_time | Last time the connection fetched data from the adapter. | date |
| axonius.adapter.connections.last_successful_fetch | Last date and time the connection successfully fetched data. | date |
| axonius.adapter.connections.node_id | Unique ID of the node. | keyword |
| axonius.adapter.connections.note | Notes of the connection. | keyword |
| axonius.adapter.connections.status | Status of the connection. | keyword |
| axonius.adapter.connections.tunnel_id | Unique ID of the tunnel used for the connection. | keyword |
| axonius.adapter.connections.uuid | Unique ID of the connection. | keyword |
| axonius.adapter.connections_count.error_count |  | long |
| axonius.adapter.connections_count.inactive_count |  | long |
| axonius.adapter.connections_count.success_count |  | long |
| axonius.adapter.connections_count.total_count |  | long |
| axonius.adapter.connections_count.warning_count |  | long |
| axonius.adapter.id | The ID of the adapter. | keyword |
| axonius.adapter.is_master | Whether the adapter is running on the primary Axonius server. | boolean |
| axonius.adapter.node_id | The Axonius server node ID. | keyword |
| axonius.adapter.node_name | The Axonius server node name. | keyword |
| axonius.adapter.plugin_name | The name of the adapter. | keyword |
| axonius.adapter.status | The current status of the adapter. | keyword |
| axonius.adapter.unique_plugin_name | The unique name of the adapter. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `adapter` looks as following:

```json
{
    "@timestamp": "2025-12-26T06:22:25.352Z",
    "agent": {
        "ephemeral_id": "2c60b432-a97d-497a-8759-f3fb63d6e6e3",
        "id": "ee74aaf6-f601-404f-828d-b76ecd29af71",
        "name": "elastic-agent-55098",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "axonius": {
        "adapter": {
            "connections": [
                {
                    "active": true,
                    "adapter_name": "a_cloud_guru_adapter",
                    "connection_id": "conn_12345",
                    "did_notify_error": false,
                    "failed_connections_limit_exceeded": false,
                    "id": "conn_12345",
                    "last_fetch_time": "2025-03-08T18:53:09.000Z",
                    "last_successful_fetch": "2025-03-08T18:53:09.000Z",
                    "node_id": "c69070d9e5e145e4861f2843d1951ab2",
                    "status": "success",
                    "tunnel_id": "khnsjhgvcskdbvnksdjahubnkvdhb",
                    "uuid": "c69070fgredffedfgrfedcfd9e5e145e4861f2843d1951ab2"
                }
            ],
            "connections_count": {
                "error_count": 0,
                "inactive_count": 0,
                "success_count": 1,
                "total_count": 1,
                "warning_count": 0
            },
            "id": "a_cloud_guru_adapter",
            "is_master": true,
            "node_id": "c69070d9e5e145e4861f2843d1951ab2",
            "node_name": "Primary",
            "plugin_name": "a_cloud_guru_adapter",
            "status": "success",
            "unique_plugin_name": "a_cloud_guru_adapter_0"
        }
    },
    "data_stream": {
        "dataset": "axonius.adapter",
        "namespace": "90810",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "ee74aaf6-f601-404f-828d-b76ecd29af71",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "axonius.adapter",
        "id": "a_cloud_guru_adapter",
        "ingested": "2025-12-26T06:22:28Z",
        "kind": "event",
        "original": "{\"adapter_configs\":{},\"connections\":[{\"active\":true,\"adapter_name\":\"a_cloud_guru_adapter\",\"connection_adapter_config\":{},\"connection_advanced_config\":{},\"connection_config\":{},\"connection_discovery\":{},\"connection_id\":\"conn_12345\",\"curl\":null,\"did_notify_error\":false,\"error\":null,\"failed_connections_limit_exceeded\":false,\"id\":\"conn_12345\",\"last_fetch_time\":\"Sat, 08 Mar 2025 18:53:09 GMT\",\"last_successful_fetch\":\"Sat, 08 Mar 2025 18:53:09 GMT\",\"node_id\":\"c69070d9e5e145e4861f2843d1951ab2\",\"note\":\"\",\"status\":\"success\",\"tunnel_id\":\"khnsjhgvcskdbvnksdjahubnkvdhb\",\"uuid\":\"c69070fgredffedfgrfedcfd9e5e145e4861f2843d1951ab2\"}],\"connections_count\":{\"error_count\":0,\"inactive_count\":0,\"success_count\":1,\"total_count\":1,\"warning_count\":0},\"id\":\"a_cloud_guru_adapter\",\"is_master\":true,\"node_id\":\"c69070d9e5e145e4861f2843d1951ab2\",\"node_name\":\"Primary\",\"plugin_name\":\"a_cloud_guru_adapter\",\"status\":\"success\",\"unique_plugin_name\":\"a_cloud_guru_adapter_0\"}",
        "outcome": "success"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-adapter"
    ]
}
```

### User

The `user` data stream provides user events from axonius.

#### user fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.user.allowed_scopes_impersonation |  | keyword |
| axonius.user.data_scope_id |  | keyword |
| axonius.user.data_scope_name |  | keyword |
| axonius.user.department |  | keyword |
| axonius.user.email |  | keyword |
| axonius.user.first_name |  | keyword |
| axonius.user.last_login |  | date |
| axonius.user.last_name |  | keyword |
| axonius.user.last_updated |  | date |
| axonius.user.role_id |  | keyword |
| axonius.user.role_name |  | keyword |
| axonius.user.source |  | keyword |
| axonius.user.title |  | keyword |
| axonius.user.user_name |  | keyword |
| axonius.user.uuid |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Indicates whether a user is in the raw source data stream, or in the latest destination index. | constant_keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `user` looks as following:

```json
{
    "@timestamp": "2025-12-17T10:19:23.994Z",
    "agent": {
        "ephemeral_id": "bad72206-b376-4b34-b9c0-20bd34b8b555",
        "id": "f5417901-9871-48b3-b93e-006e1c37ec1a",
        "name": "elastic-agent-68009",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "axonius": {
        "user": {
            "allowed_scopes_impersonation": [
                "63622d93d27cvdsfa4d9489db6a1cf",
                "63622d93d2dvfwe74d9489db6a1cc"
            ],
            "data_scope_id": "fgreg63622d93d274d9489db6a1cf",
            "data_scope_name": "test data scope",
            "department": "test",
            "email": "alias.doe@example.com",
            "first_name": "alias",
            "last_login": "2025-03-09T18:53:09.000Z",
            "last_name": "doe",
            "last_updated": "2025-03-11T18:53:09.000Z",
            "role_id": "63622vfed93d274d9489dbbgresdcv6a1cf",
            "role_name": "test role",
            "source": "test source",
            "title": "Security Analyst",
            "user_name": "alias.doe",
            "uuid": "63622d93d274ihvbngvbhd9489db6a1cf"
        }
    },
    "data_stream": {
        "dataset": "axonius.user",
        "namespace": "18228",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "f5417901-9871-48b3-b93e-006e1c37ec1a",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "axonius.user",
        "ingested": "2025-12-17T10:19:26Z",
        "kind": "event",
        "original": "{\"allowed_scopes_impersonation\":[\"63622d93d27cvdsfa4d9489db6a1cf\",\"63622d93d2dvfwe74d9489db6a1cc\"],\"data_scope_id\":\"fgreg63622d93d274d9489db6a1cf\",\"data_scope_name\":\"test data scope\",\"department\":\"test\",\"email\":\"alias.doe@example.com\",\"first_name\":\"alias\",\"last_login\":\"Sun, 09 Mar 2025 18:53:09 GMT\",\"last_name\":\"doe\",\"last_updated\":\"Sun, 11 Mar 2025 18:53:09 GMT\",\"role_id\":\"63622vfed93d274d9489dbbgresdcv6a1cf\",\"role_name\":\"test role\",\"source\":\"test source\",\"title\":\"Security Analyst\",\"user_name\":\"alias.doe\",\"uuid\":\"63622d93d274ihvbngvbhd9489db6a1cf\"}"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "alias",
            "doe",
            "alias.doe@example.com",
            "alias.doe",
            "63622d93d274ihvbngvbhd9489db6a1cf"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-user"
    ],
    "user": {
        "domain": "example.com",
        "email": "alias.doe@example.com",
        "full_name": "alias doe",
        "id": "63622d93d274ihvbngvbhd9489db6a1cf",
        "name": "alias.doe",
        "roles": [
            "test role"
        ]
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

* Adapter (endpoint: `/api/v2/adapters`)
* User (endpoint: `/api/v2/users`)

#### ILM Policy

To facilitate adapter and user data, source data stream-backed indices `.ds-logs-axonius.adapter-*` and `.ds-logs-axonius.user-*` respectively are allowed to contain duplicates from each polling interval. ILM policies `logs-axonius.adapter-default_policy` and `logs-axonius.user-default_policy` are added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
