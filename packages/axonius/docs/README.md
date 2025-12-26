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

- `Storage`: Collect details of all storage assets including:
    - object_storages (endpoint: `/api/v2/object_storages`)
    - file_systems (endpoint: `/api/v2/file_systems`)
    - disks (endpoint: `/api/v2/disks`)

### Supported use cases

Integrating the Axonius Storage Datastream with Elastic SIEM provides clear visibility into storage-related assets across the environment, including object storages, file systems, and disks. This datastream helps analysts understand how storage resources are distributed, utilized, and associated with the broader asset ecosystem.

It offers consolidated details for each storage type, enabling teams to quickly validate configurations, identify capacity or availability concerns, and trace relationships between storage assets and the devices that rely on them. By centralizing storage data, analysts can detect anomalies, uncover misconfigurations, and better understand the role of storage components in security or operational events.

These insights enable organizations to maintain accurate storage inventories, strengthen monitoring of critical storage assets, and support investigations where storage-related context is essential.

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

### Storage

The `storage` data stream provides storage asset logs from axonius.

#### storage fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.storage.adapter_list_length |  | long |
| axonius.storage.adapters |  | keyword |
| axonius.storage.asset_type |  | keyword |
| axonius.storage.event.accurate_for_datetime |  | date |
| axonius.storage.event.adapter_categories |  | keyword |
| axonius.storage.event.client_used |  | keyword |
| axonius.storage.event.data.accurate_for_datetime |  | date |
| axonius.storage.event.data.application_and_account_name |  | keyword |
| axonius.storage.event.data.asset_type |  | keyword |
| axonius.storage.event.data.create_time |  | date |
| axonius.storage.event.data.creation_date |  | date |
| axonius.storage.event.data.fetch_time |  | date |
| axonius.storage.event.data.first_fetch_time |  | date |
| axonius.storage.event.data.from_last_fetch |  | boolean |
| axonius.storage.event.data.id |  | keyword |
| axonius.storage.event.data.id_raw |  | keyword |
| axonius.storage.event.data.is_fetched_from_adapter |  | boolean |
| axonius.storage.event.data.last_fetch_connection_id |  | keyword |
| axonius.storage.event.data.last_fetch_connection_label |  | keyword |
| axonius.storage.event.data.name |  | keyword |
| axonius.storage.event.data.not_fetched_count |  | long |
| axonius.storage.event.data.size |  | double |
| axonius.storage.event.data.source_application |  | keyword |
| axonius.storage.event.data.tenant_number |  | keyword |
| axonius.storage.event.data.type |  | keyword |
| axonius.storage.event.data.urls |  | keyword |
| axonius.storage.event.initial_plugin_unique_name |  | keyword |
| axonius.storage.event.plugin_name |  | keyword |
| axonius.storage.event.plugin_type |  | keyword |
| axonius.storage.event.plugin_unique_name |  | keyword |
| axonius.storage.event.quick_id |  | keyword |
| axonius.storage.event.type |  | keyword |
| axonius.storage.internal_axon_id |  | keyword |
| axonius.storage.transform_unique_id |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Indicates whether a storage is in the raw source data stream, or in the latest destination index. | constant_keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `storage` looks as following:

```json
{
    "@timestamp": "2025-12-09T00:02:06.000Z",
    "agent": {
        "ephemeral_id": "38d860f6-9122-4541-a71c-cf60942f0c9c",
        "id": "8572bf92-b04c-4939-90c3-2403c7c97497",
        "name": "elastic-agent-67200",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "axonius": {
        "storage": {
            "adapter_list_length": 1,
            "adapters": [
                "aws_adapter"
            ],
            "asset_type": "disks",
            "event": {
                "accurate_for_datetime": "2025-12-09T00:02:06.000Z",
                "adapter_categories": [
                    "Cloud Infra"
                ],
                "client_used": "67fd09ab731ccb57309230fc",
                "data": {
                    "accurate_for_datetime": "2025-12-09T00:02:06.000Z",
                    "application_and_account_name": "aws/aws-demo",
                    "asset_type": "EBS Volume",
                    "create_time": "2024-12-13T02:59:39.000Z",
                    "fetch_time": "2025-12-09T00:02:06.000Z",
                    "first_fetch_time": "2025-04-14T13:27:02.000Z",
                    "from_last_fetch": true,
                    "id": "140649f1bb9614f2254f",
                    "id_raw": "47c9b542-36de-4415-ad96-5840a082f9dd",
                    "is_fetched_from_adapter": true,
                    "last_fetch_connection_id": "67fd09ab731ccb57309230fc",
                    "last_fetch_connection_label": "aws-demo",
                    "not_fetched_count": 0,
                    "size": 40,
                    "source_application": "AWS",
                    "tenant_number": [
                        "1"
                    ],
                    "type": "Disk"
                },
                "initial_plugin_unique_name": "aws_adapter_0",
                "plugin_name": "aws_adapter",
                "plugin_type": "Adapter",
                "plugin_unique_name": "aws_adapter_0",
                "quick_id": "aws_adapter_0!140649f1bb9614f2254f",
                "type": "entitydata"
            },
            "internal_axon_id": "7e8e5d4db0c7aa12d3b15c556b4513eb",
            "transform_unique_id": "Y55e0DbHhziiAfhMWXWz91rs+40="
        }
    },
    "data_stream": {
        "dataset": "axonius.storage",
        "namespace": "46787",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "8572bf92-b04c-4939-90c3-2403c7c97497",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2024-12-13T02:59:39.000Z",
        "dataset": "axonius.storage",
        "ingested": "2025-12-26T06:40:20Z",
        "kind": "event",
        "original": "{\"adapter_list_length\":1,\"adapters\":[\"aws_adapter\"],\"asset_type\":\"disks\",\"event\":{\"accurate_for_datetime\":\"Tue, 09 Dec 2025 00:02:06 GMT\",\"adapter_categories\":[\"Cloud Infra\"],\"client_used\":\"67fd09ab731ccb57309230fc\",\"data\":{\"accurate_for_datetime\":\"Tue, 09 Dec 2025 00:02:06 GMT\",\"application_and_account_name\":\"aws/aws-demo\",\"asset_type\":\"EBS Volume\",\"create_time\":\"Fri, 13 Dec 2024 02:59:39 GMT\",\"fetch_time\":\"Tue, 09 Dec 2025 00:02:06 GMT\",\"first_fetch_time\":\"Mon, 14 Apr 2025 13:27:02 GMT\",\"from_last_fetch\":true,\"id\":\"140649f1bb9614f2254f\",\"id_raw\":\"47c9b542-36de-4415-ad96-5840a082f9dd\",\"is_fetched_from_adapter\":true,\"last_fetch_connection_id\":\"67fd09ab731ccb57309230fc\",\"last_fetch_connection_label\":\"aws-demo\",\"not_fetched_count\":0,\"size\":40,\"source_application\":\"AWS\",\"tenant_number\":[\"1\"],\"type\":\"Disk\"},\"initial_plugin_unique_name\":\"aws_adapter_0\",\"plugin_name\":\"aws_adapter\",\"plugin_type\":\"Adapter\",\"plugin_unique_name\":\"aws_adapter_0\",\"quick_id\":\"aws_adapter_0!140649f1bb9614f2254f\",\"type\":\"entitydata\"},\"internal_axon_id\":\"7e8e5d4db0c7aa12d3b15c556b4513eb\"}"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-storage"
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

* Storage:
    * object_storages (endpoint: `/api/v2/object_storages`)
    * file_systems (endpoint: `/api/v2/file_systems`)
    * disks (endpoint: `/api/v2/disks`)


#### ILM Policy

To facilitate storage data, source data stream-backed indices `.ds-logs-axonius.storage-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.storage-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
