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

- `Alert and Incidents`: Collect details of all alert findings and incident assets including:
    - alert_findings (endpoint: `/api/v2/alert_findings`)
    - incidents (endpoint: `/api/v2/incidents`)

### Supported use cases

Integrating the Axonius Alert finding, and Incident Datastream with Elastic SIEM provides comprehensive visibility into security alerts and their progression into incidents. Severity and status breakdowns help analysts quickly gauge the proportion of high-risk, medium-risk, and lower-impact alerts, enabling rapid assessment of overall threat activity across the environment.

Views into alert sources, time-based trends, and incident classifications offer deeper context into where alerts originate, how they evolve, and which systems are most frequently involved. Incident-focused insights—such as distributions by risk level, severity, and alert status—help teams understand the impact and urgency of each case. Consolidated details for both alerts and incidents provide quick access to the information needed for triage and investigation.

These insights enable organizations to monitor alert patterns, identify recurring trouble areas, prioritize high-risk incidents, and streamline end-to-end investigation and response workflows.

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
5. If you don’t see the API Key tab in your user settings, follow these steps:
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
| axonius.alert_and_incident.transform_unique_id |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Indicates whether an alert and incident are in the raw source data stream, or in the latest destination index. | constant_keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `alert_and_incident` looks as following:

```json
{
    "@timestamp": "2025-04-14T13:38:49.000Z",
    "agent": {
        "ephemeral_id": "75b1cfdf-ae0c-40a8-9d99-62cefac0f26c",
        "id": "df2f55f5-9ed0-46f7-81aa-76e2347d5e98",
        "name": "elastic-agent-29558",
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
            "internal_axon_id": "f8b16b93ecf0c0c4d7d10b797b9f839a",
            "transform_unique_id": "WVspmVr9FseKluRKa6N3CIRZsb0="
        }
    },
    "data_stream": {
        "dataset": "axonius.alert_and_incident",
        "namespace": "47334",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "df2f55f5-9ed0-46f7-81aa-76e2347d5e98",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "axonius.alert_and_incident",
        "id": "66447fe5e6c4840f32a5b94f",
        "ingested": "2025-12-29T06:05:21Z",
        "kind": "alert"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
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

* Alert Findings and Incidents:
    * alert_findings (endpoint: `/api/v2/alert_findings`)
    * incidents (endpoint: `/api/v2/incidents`)

#### ILM Policy

To facilitate alert findings and incident data, source data stream-backed indices `.ds-logs-axonius.alert_and_incident-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.alert_and_incident-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
