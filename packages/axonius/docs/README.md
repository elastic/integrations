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

- `Gateway`: Collect details of all Gateway (endpoint: `/api/v2/gateway`).

- `Exposure`: Collect details of all exposure assets including:
    - vulnerability_instances (endpoint: `/api/v2/vulnerability_instances`)
    - vulnerabilities (endpoint: `/api/v2/vulnerabilities`)
    - vulnerabilities_repository (endpoint: `/api/v2/vulnerabilities_repository`)

- `Alert and Incidents`: Collect details of all alert findings and incident assets including:
    - alert_findings (endpoint: `/api/v2/alert_findings`)
    - incidents (endpoint: `/api/v2/incidents`)

### Supported use cases

Integrating the Axonius Adapter, User, Gateway, Exposure, and Alert/Incident data streams with Elastic SIEM provides centralized, end-to-end visibility across data ingestion, identity posture, network configuration, vulnerability exposure, and active security events. Together, these data streams help analysts understand how data enters the platform, how it maps to users and access, how gateways operate within the network, where risks exist, and how alerts evolve into incidents.

The dashboards surface insights into integration health, connection behavior, user roles, routing context, vulnerability severity, and alert and incident trends, making it easier to detect misconfigurations, high-risk exposures, and suspicious activity. By correlating operational, identity, exposure, and incident data in one place, security teams can reduce blind spots, prioritize remediation, and streamline investigations with complete, actionable context across the environment.

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
5. If you do not see the API Key tab in your user settings, follow these steps:
    1.  Go to **System Settings** > **User and Role Management** > **Service Accounts**.
    2. Create a Service Account, and then generate an **API Key**.
6. Copy both values including **API Key and Secret Key** and store them securely for use in the Integration configuration.

**Note:**
To generate or reset an API key, your role must be **Admin**, and you must have **API Access** permissions, which include **API Access Enabled** and **Reset API Key**.

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
    "@timestamp": "2026-01-05T09:31:18.314Z",
    "agent": {
        "ephemeral_id": "6be29bb7-8260-424e-932e-b14aa7f1fdda",
        "id": "718d4ca7-c29e-4508-be01-a3b7ef816c4b",
        "name": "elastic-agent-14268",
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
        "namespace": "36432",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "718d4ca7-c29e-4508-be01-a3b7ef816c4b",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "axonius.user",
        "ingested": "2026-01-05T09:31:21Z",
        "kind": "event",
        "original": "{\"allowed_scopes_impersonation\":[\"63622d93d27cvdsfa4d9489db6a1cf\",\"63622d93d2dvfwe74d9489db6a1cc\"],\"data_scope_id\":\"fgreg63622d93d274d9489db6a1cf\",\"data_scope_name\":\"test data scope\",\"department\":\"test\",\"email\":\"alias.doe@example.com\",\"first_name\":\"alias\",\"last_login\":\"Sun, 09 Mar 2025 18:53:09 GMT\",\"last_name\":\"doe\",\"last_updated\":\"Sun, 11 Mar 2025 18:53:09 GMT\",\"role_id\":\"63622vfed93d274d9489dbbgresdcv6a1cf\",\"role_name\":\"test role\",\"source\":\"test source\",\"title\":\"Security Analyst\",\"user_name\":\"alias.doe\",\"uuid\":\"63622d93d274ihvbngvbhd9489db6a1cf\"}"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "alias doe",
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
    "@timestamp": "2026-01-08T06:38:18.036Z",
    "agent": {
        "ephemeral_id": "e272fa8a-259e-402a-a60b-a70cd1e2daef",
        "id": "08ff75a2-4f86-4772-9dae-093f237744d1",
        "name": "elastic-agent-30491",
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
        "namespace": "28244",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "08ff75a2-4f86-4772-9dae-093f237744d1",
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
        "ingested": "2026-01-08T06:38:20Z",
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

### Exposure

The `exposure` data stream provides exposure logs from axonius.

#### exposure fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.exposure.adapter_list_length |  | long |
| axonius.exposure.adapters |  | keyword |
| axonius.exposure.asset_type |  | keyword |
| axonius.exposure.event.accurate_for_datetime |  | date |
| axonius.exposure.event.associated_adapter_plugin_name |  | keyword |
| axonius.exposure.event.association_type |  | keyword |
| axonius.exposure.event.client_used |  | keyword |
| axonius.exposure.event.data.accurate_for_datetime |  | date |
| axonius.exposure.event.data.action |  | keyword |
| axonius.exposure.event.data.added |  | date |
| axonius.exposure.event.data.associated_asset_type |  | keyword |
| axonius.exposure.event.data.associated_asset_type_name |  | keyword |
| axonius.exposure.event.data.axonius_remediation_date |  | date |
| axonius.exposure.event.data.axonius_risk_score |  | double |
| axonius.exposure.event.data.axonius_status |  | keyword |
| axonius.exposure.event.data.axonius_status_last_update |  | date |
| axonius.exposure.event.data.cisa.action |  | keyword |
| axonius.exposure.event.data.cisa.added |  | date |
| axonius.exposure.event.data.cisa.cve_id |  | keyword |
| axonius.exposure.event.data.cisa.desc |  | keyword |
| axonius.exposure.event.data.cisa.due_date |  | date |
| axonius.exposure.event.data.cisa.notes |  | keyword |
| axonius.exposure.event.data.cisa.product |  | keyword |
| axonius.exposure.event.data.cisa.used_in_ransomware |  | boolean |
| axonius.exposure.event.data.cisa.vendor |  | keyword |
| axonius.exposure.event.data.cisa.vulnerability_name |  | keyword |
| axonius.exposure.event.data.cisa_date_added |  | date |
| axonius.exposure.event.data.creation_date |  | date |
| axonius.exposure.event.data.custom_business_unit |  | keyword |
| axonius.exposure.event.data.cve_description |  | keyword |
| axonius.exposure.event.data.cve_from_sw_analysis |  | keyword |
| axonius.exposure.event.data.cve_id |  | keyword |
| axonius.exposure.event.data.cve_list |  | keyword |
| axonius.exposure.event.data.cve_references.tags |  | keyword |
| axonius.exposure.event.data.cve_references.url |  | keyword |
| axonius.exposure.event.data.cve_severity |  | keyword |
| axonius.exposure.event.data.cve_synopsis |  | keyword |
| axonius.exposure.event.data.cvss |  | float |
| axonius.exposure.event.data.cvss2_score |  | float |
| axonius.exposure.event.data.cvss2_score_num |  | float |
| axonius.exposure.event.data.cvss3_score |  | float |
| axonius.exposure.event.data.cvss3_score_num |  | float |
| axonius.exposure.event.data.cvss_str |  | keyword |
| axonius.exposure.event.data.cvss_vector |  | keyword |
| axonius.exposure.event.data.cvss_version |  | keyword |
| axonius.exposure.event.data.cwe_id |  | keyword |
| axonius.exposure.event.data.desc |  | keyword |
| axonius.exposure.event.data.device_internal_axon_id |  | keyword |
| axonius.exposure.event.data.due_date |  | date |
| axonius.exposure.event.data.epss.creation_date |  | date |
| axonius.exposure.event.data.epss.cve_id |  | keyword |
| axonius.exposure.event.data.epss.percentile |  | double |
| axonius.exposure.event.data.epss.score |  | double |
| axonius.exposure.event.data.exploitability_score |  | double |
| axonius.exposure.event.data.fields_to_unset |  | keyword |
| axonius.exposure.event.data.first_fetch_time |  | date |
| axonius.exposure.event.data.first_seen |  | date |
| axonius.exposure.event.data.hash_id |  | keyword |
| axonius.exposure.event.data.id |  | keyword |
| axonius.exposure.event.data.impact_score |  | float |
| axonius.exposure.event.data.is_cve |  | boolean |
| axonius.exposure.event.data.last_fetch |  | date |
| axonius.exposure.event.data.last_fetch_time |  | date |
| axonius.exposure.event.data.last_modified_date |  | date |
| axonius.exposure.event.data.mitigated |  | boolean |
| axonius.exposure.event.data.msrc.creation_date |  | date |
| axonius.exposure.event.data.msrc.cve_id |  | keyword |
| axonius.exposure.event.data.msrc.title |  | keyword |
| axonius.exposure.event.data.msrc_remediations.affected_files |  | keyword |
| axonius.exposure.event.data.msrc_remediations.description |  | keyword |
| axonius.exposure.event.data.msrc_remediations.fixed_build |  | keyword |
| axonius.exposure.event.data.msrc_remediations.supercedence |  | keyword |
| axonius.exposure.event.data.msrc_remediations.url |  | keyword |
| axonius.exposure.event.data.name |  | keyword |
| axonius.exposure.event.data.notes |  | keyword |
| axonius.exposure.event.data.nvd_publish_age |  | long |
| axonius.exposure.event.data.nvd_status |  | keyword |
| axonius.exposure.event.data.percentile |  | double |
| axonius.exposure.event.data.plugin |  | keyword |
| axonius.exposure.event.data.potential_applications_names.software_name |  | keyword |
| axonius.exposure.event.data.potential_applications_names.vendor_name |  | keyword |
| axonius.exposure.event.data.product |  | keyword |
| axonius.exposure.event.data.publish_date |  | date |
| axonius.exposure.event.data.qualys_agent_vuln.first_found |  | date |
| axonius.exposure.event.data.qualys_agent_vuln.last_found |  | date |
| axonius.exposure.event.data.qualys_agent_vuln.qid |  | keyword |
| axonius.exposure.event.data.qualys_agent_vuln.qualys_cve_id |  | keyword |
| axonius.exposure.event.data.qualys_agent_vuln.qualys_solution |  | keyword |
| axonius.exposure.event.data.qualys_agent_vuln.severity |  | long |
| axonius.exposure.event.data.qualys_agent_vuln.vuln_id |  | keyword |
| axonius.exposure.event.data.score |  | double |
| axonius.exposure.event.data.short_description |  | keyword |
| axonius.exposure.event.data.software_name |  | keyword |
| axonius.exposure.event.data.software_type |  | keyword |
| axonius.exposure.event.data.software_vendor |  | keyword |
| axonius.exposure.event.data.software_version |  | keyword |
| axonius.exposure.event.data.solution_hash_id |  | keyword |
| axonius.exposure.event.data.status |  | keyword |
| axonius.exposure.event.data.suggested_remediations.description |  | keyword |
| axonius.exposure.event.data.tags_from_associated_asset |  | keyword |
| axonius.exposure.event.data.tenable_vuln.cve |  | keyword |
| axonius.exposure.event.data.tenable_vuln.has_been_mitigated |  | boolean |
| axonius.exposure.event.data.tenable_vuln.mitigated |  | boolean |
| axonius.exposure.event.data.tenable_vuln.plugin |  | keyword |
| axonius.exposure.event.data.tenable_vuln.solution |  | keyword |
| axonius.exposure.event.data.title |  | keyword |
| axonius.exposure.event.data.used_in_ransomware |  | boolean |
| axonius.exposure.event.data.vector.access_complexity |  | keyword |
| axonius.exposure.event.data.vector.access_vector |  | keyword |
| axonius.exposure.event.data.vector.attack_complexity |  | keyword |
| axonius.exposure.event.data.vector.attack_vector |  | keyword |
| axonius.exposure.event.data.vector.authentication |  | keyword |
| axonius.exposure.event.data.vector.availability |  | keyword |
| axonius.exposure.event.data.vector.confidentiality |  | keyword |
| axonius.exposure.event.data.vector.integrity |  | keyword |
| axonius.exposure.event.data.vector.privileges_required |  | keyword |
| axonius.exposure.event.data.vector.scope |  | keyword |
| axonius.exposure.event.data.vector.user_interaction |  | keyword |
| axonius.exposure.event.data.vector.version |  | keyword |
| axonius.exposure.event.data.vendor |  | keyword |
| axonius.exposure.event.data.vendor_project |  | keyword |
| axonius.exposure.event.data.version_raw |  | keyword |
| axonius.exposure.event.data.vulnerability_name |  | keyword |
| axonius.exposure.event.data.vulnerability_status |  | keyword |
| axonius.exposure.event.initial_plugin_unique_name |  | keyword |
| axonius.exposure.event.name |  | keyword |
| axonius.exposure.event.plugin_name |  | keyword |
| axonius.exposure.event.plugin_type |  | keyword |
| axonius.exposure.event.plugin_unique_name |  | keyword |
| axonius.exposure.event.quick_id |  | keyword |
| axonius.exposure.event.type |  | keyword |
| axonius.exposure.internal_axon_id |  | keyword |
| axonius.exposure.transform_unique_id |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Indicates whether a compute event is in the raw source data stream, or in the latest destination index. | constant_keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `exposure` looks as following:

```json
{
    "@timestamp": "2025-12-03T00:02:28.000Z",
    "agent": {
        "ephemeral_id": "080f273f-25b7-4287-9fc7-4bb2e1ef838b",
        "id": "7e61decf-17ca-4266-8dd7-801a45522a0a",
        "name": "elastic-agent-65541",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "axonius": {
        "exposure": {
            "adapters": [
                "aws_adapter",
                "adapter_01"
            ],
            "asset_type": "vulnerabilities",
            "event": {
                "accurate_for_datetime": "2025-12-03T00:02:28.000Z",
                "client_used": "67fd09ab731ccb57309230fc",
                "data": {
                    "accurate_for_datetime": "2025-12-03T00:02:28.000Z",
                    "cve_id": "CVE-2024-32021",
                    "cve_severity": "LOW",
                    "cvss": 5,
                    "cvss3_score": 5,
                    "fields_to_unset": [
                        "other"
                    ],
                    "first_seen": "2025-04-29T12:00:39.000Z",
                    "id": "CVE-2024-32021",
                    "is_cve": true,
                    "last_fetch": "2025-12-03T00:02:17.000Z",
                    "software_name": [
                        "Git"
                    ],
                    "software_vendor": [
                        "The Git Project"
                    ],
                    "software_version": [
                        "2.39.2"
                    ]
                },
                "initial_plugin_unique_name": "aws_adapter_0",
                "plugin_name": "aws_adapter",
                "plugin_type": "Adapter",
                "plugin_unique_name": "aws_adapter_0",
                "quick_id": "aws_adapter_0!CVE-2024-32021",
                "type": "entitydata"
            },
            "internal_axon_id": "e018a2831e3ab36e86dd7a4a0782c892",
            "transform_unique_id": "7oVTQrrn+0WjVHu/4YZCgjIyM60="
        }
    },
    "data_stream": {
        "dataset": "axonius.exposure",
        "namespace": "23091",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "7e61decf-17ca-4266-8dd7-801a45522a0a",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "axonius.exposure",
        "ingested": "2025-12-26T09:15:58Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-exposure"
    ],
    "vulnerability": {
        "id": [
            "CVE-2024-32021"
        ],
        "score": {
            "base": 5
        },
        "severity": "LOW"
    }
}
```

### Alert and Incident

The `alert_and_incident` data stream provides alert findings and incident asset logs from axonius.

#### alert_and_incident fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.alert_and_incident.adapter_list_length |  | long |
| axonius.alert_and_incident.adapters |  | keyword |
| axonius.alert_and_incident.asset_type |  | keyword |
| axonius.alert_and_incident.event.accurate_for_datetime |  | date |
| axonius.alert_and_incident.event.adapter_categories |  | keyword |
| axonius.alert_and_incident.event.client_used |  | keyword |
| axonius.alert_and_incident.event.data.accurate_for_datetime |  | date |
| axonius.alert_and_incident.event.data.alert_config_id |  | keyword |
| axonius.alert_and_incident.event.data.alert_id |  | keyword |
| axonius.alert_and_incident.event.data.alert_labels |  | keyword |
| axonius.alert_and_incident.event.data.alert_source |  | keyword |
| axonius.alert_and_incident.event.data.alert_state.alert_created_at |  | date |
| axonius.alert_and_incident.event.data.alert_state.alert_high_since |  | date |
| axonius.alert_and_incident.event.data.alert_state.alert_last_seen |  | date |
| axonius.alert_and_incident.event.data.alert_state.alert_orca_score_number |  | double |
| axonius.alert_and_incident.event.data.alert_state.alert_risk_level |  | keyword |
| axonius.alert_and_incident.event.data.alert_state.alert_score |  | long |
| axonius.alert_and_incident.event.data.alert_state.alert_severity |  | keyword |
| axonius.alert_and_incident.event.data.alert_state.alert_status |  | keyword |
| axonius.alert_and_incident.event.data.alert_state.alert_status_time |  | date |
| axonius.alert_and_incident.event.data.alert_type |  | keyword |
| axonius.alert_and_incident.event.data.application_and_account_name |  | keyword |
| axonius.alert_and_incident.event.data.asset_distribution_major_version |  | keyword |
| axonius.alert_and_incident.event.data.asset_distribution_name |  | keyword |
| axonius.alert_and_incident.event.data.asset_distribution_version |  | keyword |
| axonius.alert_and_incident.event.data.description |  | keyword |
| axonius.alert_and_incident.event.data.details |  | keyword |
| axonius.alert_and_incident.event.data.fetch_time |  | date |
| axonius.alert_and_incident.event.data.finding_asset_type |  | keyword |
| axonius.alert_and_incident.event.data.finding_check_and_notify |  | keyword |
| axonius.alert_and_incident.event.data.finding_message |  | keyword |
| axonius.alert_and_incident.event.data.finding_name |  | keyword |
| axonius.alert_and_incident.event.data.finding_severity |  | keyword |
| axonius.alert_and_incident.event.data.first_fetch_time |  | date |
| axonius.alert_and_incident.event.data.from_last_fetch |  | boolean |
| axonius.alert_and_incident.event.data.id |  | keyword |
| axonius.alert_and_incident.event.data.id_raw |  | keyword |
| axonius.alert_and_incident.event.data.is_fetched_from_adapter |  | boolean |
| axonius.alert_and_incident.event.data.last_fetch_connection_id |  | keyword |
| axonius.alert_and_incident.event.data.last_fetch_connection_label |  | keyword |
| axonius.alert_and_incident.event.data.not_fetched_count |  | long |
| axonius.alert_and_incident.event.data.plugin_unique_name |  | keyword |
| axonius.alert_and_incident.event.data.pretty_id |  | keyword |
| axonius.alert_and_incident.event.data.recommendation |  | keyword |
| axonius.alert_and_incident.event.data.source |  | keyword |
| axonius.alert_and_incident.event.data.source_application |  | keyword |
| axonius.alert_and_incident.event.data.status |  | keyword |
| axonius.alert_and_incident.event.data.tenant_number |  | keyword |
| axonius.alert_and_incident.event.data.trigger_date |  | date |
| axonius.alert_and_incident.event.data.type |  | keyword |
| axonius.alert_and_incident.event.initial_plugin_unique_name |  | keyword |
| axonius.alert_and_incident.event.plugin_name |  | keyword |
| axonius.alert_and_incident.event.plugin_type |  | keyword |
| axonius.alert_and_incident.event.plugin_unique_name |  | keyword |
| axonius.alert_and_incident.event.quick_id |  | keyword |
| axonius.alert_and_incident.event.type |  | keyword |
| axonius.alert_and_incident.internal_axon_id |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `alert_and_incident` looks as following:

```json
{
    "@timestamp": "2025-04-14T13:38:49.000Z",
    "agent": {
        "ephemeral_id": "547b93f3-e3de-4a33-9857-969a5229a943",
        "id": "0572ed83-3264-4082-9096-37eaf63541a2",
        "name": "elastic-agent-77501",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "axonius": {
        "alert_and_incident": {
            "adapter_list_length": 1,
            "adapters": [
                "axonius_findings_adapter"
            ],
            "asset_type": "alert_findings",
            "event": {
                "data": {
                    "alert_config_id": "66447fe5e6c4840f32a5b94f",
                    "alert_id": "984",
                    "finding_asset_type": "adapters_fetch_history",
                    "finding_check_and_notify": "Every global discovery cycle",
                    "finding_name": "Failed Adapters",
                    "finding_severity": "high",
                    "id": "d919d74b380c16c8ea9d",
                    "id_raw": "67fd0fe9c0cc9f012ad936ad",
                    "plugin_unique_name": "axonius_findings_adapter",
                    "source": "alert_rule",
                    "status": "open",
                    "trigger_date": "2025-04-14T13:38:49.000Z"
                },
                "plugin_name": "axonius_findings_adapter",
                "plugin_unique_name": "axonius_findings_adapter",
                "quick_id": "axonius_findings_adapter!d919d74b380c16c8ea9d"
            },
            "internal_axon_id": "f8b16b93ecf0c0c4d7d10b797b9f839a"
        }
    },
    "data_stream": {
        "dataset": "axonius.alert_and_incident",
        "namespace": "90668",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "0572ed83-3264-4082-9096-37eaf63541a2",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "axonius.alert_and_incident",
        "id": "66447fe5e6c4840f32a5b94f",
        "ingested": "2025-12-17T12:41:18Z",
        "kind": "alert",
        "original": "{\"adapter_list_length\":1,\"adapters\":[\"axonius_findings_adapter\"],\"asset_type\":\"alert_findings\",\"event\":{\"adapters.$.data.id_raw\":\"67fd0fe9c0cc9f012ad936ad\",\"adapters.$.quick_id\":\"axonius_findings_adapter!d919d74b380c16c8ea9d\",\"data\":{\"alert_config_id\":\"66447fe5e6c4840f32a5b94f\",\"alert_id\":\"984\",\"finding_asset_type\":\"adapters_fetch_history\",\"finding_check_and_notify\":\"Every global discovery cycle\",\"finding_message\":\"\",\"finding_name\":\"Failed Adapters\",\"finding_severity\":\"high\",\"id\":\"d919d74b380c16c8ea9d\",\"id_raw\":\"67fd0fe9c0cc9f012ad936ad\",\"plugin_unique_name\":\"axonius_findings_adapter\",\"source\":\"alert_rule\",\"status\":\"open\",\"trigger_date\":\"Mon, 14 Apr 2025 13:38:49 GMT\"},\"plugin_name\":\"axonius_findings_adapter\",\"plugin_unique_name\":\"axonius_findings_adapter\",\"quick_id\":\"axonius_findings_adapter!d919d74b380c16c8ea9d\"},\"internal_axon_id\":\"f8b16b93ecf0c0c4d7d10b797b9f839a\"}"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-alert_and_incident"
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

* Adapter (endpoint: `/api/v2/adapters`)
* User (endpoint: `/api/v2/users`)
* Gateway (endpoint: `/api/v2/gateway`)
* Exposure:
    * vulnerability_instances (endpoint: `/api/v2/vulnerability_instances`)
    * vulnerabilities (endpoint: `/api/v2/vulnerabilities`)
    * vulnerabilities_repository (endpoint: `/api/v2/vulnerabilities_repository`)
* Alert Findings and Incidents:
    * alert_findings (endpoint: `/api/v2/alert_findings`)
    * incidents (endpoint: `/api/v2/incidents`)

### ILM Policy

To facilitate adapter, user, gateway and assets data including exposures, alert findings and incidents, source data stream-backed indices `.ds-logs-axonius.adapter-*`, `.ds-logs-axonius.user-*`, `.ds-logs-axonius.gateway-*`, `.ds-logs-axonius.exposure-*` and `.ds-logs-axonius.alert_and_incident-*` respectively are allowed to contain duplicates from each polling interval. ILM policies `logs-axonius.adapter-default_policy`, `logs-axonius.user-default_policy`, `logs-axonius.gateway-default_policy`, `logs-axonius.exposure-default_policy` and `logs-axonius.alert_and_incident-default_policy` are added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
