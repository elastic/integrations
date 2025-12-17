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

- `Ticket`: Collect details of all ticket assets including:
    - tickets (endpoint: `/api/v2/tickets`)
    - cases (endpoint: `/api/v2/cases`)

### Supported use cases

Integrating the Axonius Ticket Datastream with Elastic SIEM provides clear visibility into ticket activity and issue trends across the environment. Priority breakdowns help analysts quickly understand the proportion of critical, high, medium, and low-urgency tickets, supporting faster assessment of overall workload and emerging concerns.

Views into ticket status and time-based trends offer additional context, showing how tickets progress through their lifecycle and highlighting spikes or recurring patterns. Tables identifying top reporters help teams trace frequent issue sources, while essential ticket details provide the key information needed for efficient triage and follow-up.

These insights enable organizations to monitor operational issues, identify workload bottlenecks, prioritize high-impact tickets, and streamline ticket management workflows across the environment.

## What do I need to use this integration?

### From Axonius

To collect data through the Axonius APIs, you need to provide the **URL**, **API Key** and **API Secret**. Authentication is handled using the **API Key** and **API Secret**, which serves as the required credential.

#### Retrieve URL, API Token and API Secret:

1. Log in to the **Axonius** instance.
2. Your instance URL is your Base **URL**.
3. Navigate to **User Settings > API Key**.
4. Generate an **API Key**.
5. If you donâ€™t see the API Key tab in your user settings, follow these steps:
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

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Ticket

The `ticket` data stream provides ticket asset logs from axonius.

#### ticket fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.ticket.adapter_list_length |  | long |
| axonius.ticket.adapters |  | keyword |
| axonius.ticket.asset_type |  | keyword |
| axonius.ticket.event.accurate_for_datetime |  | date |
| axonius.ticket.event.adapter_categories |  | keyword |
| axonius.ticket.event.client_used |  | keyword |
| axonius.ticket.event.data.accurate_for_datetime |  | date |
| axonius.ticket.event.data.application_and_account_name |  | keyword |
| axonius.ticket.event.data.category |  | keyword |
| axonius.ticket.event.data.closed |  | date |
| axonius.ticket.event.data.created |  | date |
| axonius.ticket.event.data.description |  | keyword |
| axonius.ticket.event.data.display_id |  | keyword |
| axonius.ticket.event.data.fetch_time |  | date |
| axonius.ticket.event.data.first_fetch_time |  | date |
| axonius.ticket.event.data.from_last_fetch |  | boolean |
| axonius.ticket.event.data.id |  | keyword |
| axonius.ticket.event.data.is_fetched_from_adapter |  | boolean |
| axonius.ticket.event.data.last_fetch_connection_id |  | keyword |
| axonius.ticket.event.data.last_fetch_connection_label |  | keyword |
| axonius.ticket.event.data.not_fetched_count |  | long |
| axonius.ticket.event.data.priority |  | keyword |
| axonius.ticket.event.data.reporter |  | keyword |
| axonius.ticket.event.data.source_application |  | keyword |
| axonius.ticket.event.data.status |  | keyword |
| axonius.ticket.event.data.summary |  | keyword |
| axonius.ticket.event.data.sys_class_name |  | keyword |
| axonius.ticket.event.data.tenant_number |  | keyword |
| axonius.ticket.event.data.ticket_id |  | keyword |
| axonius.ticket.event.data.type |  | keyword |
| axonius.ticket.event.data.updated |  | date |
| axonius.ticket.event.initial_plugin_unique_name |  | keyword |
| axonius.ticket.event.plugin_name |  | keyword |
| axonius.ticket.event.plugin_type |  | keyword |
| axonius.ticket.event.plugin_unique_name |  | keyword |
| axonius.ticket.event.quick_id |  | keyword |
| axonius.ticket.event.type |  | keyword |
| axonius.ticket.internal_axon_id |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `ticket` looks as following:

```json
{
    "@timestamp": "2024-08-10T16:21:10.000Z",
    "agent": {
        "ephemeral_id": "f9e376c8-76a8-4e38-a63b-00cb03eed15f",
        "id": "27b87eaa-1d45-4729-938a-c512585a1dc8",
        "name": "elastic-agent-69478",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "axonius": {
        "ticket": {
            "adapter_list_length": 1,
            "adapters": [
                "service_now_adapter"
            ],
            "asset_type": "tickets",
            "event": {
                "accurate_for_datetime": "2025-12-08T00:02:48.000Z",
                "adapter_categories": [
                    "CMDB",
                    "ITAM/ITSM",
                    "Ticketing",
                    "SaaS Management"
                ],
                "client_used": "67fd0999fe1c8e812a176ba2",
                "data": {
                    "accurate_for_datetime": "2025-12-08T00:02:48.000Z",
                    "application_and_account_name": "servicenow/servicenow-dev",
                    "category": "Access Reviewer",
                    "closed": "2024-08-10T16:21:10.000Z",
                    "created": "2024-07-14T23:21:10.000Z",
                    "description": "Access Reviewer - Needs addressing",
                    "display_id": "INC3566938",
                    "fetch_time": "2025-12-08T00:02:42.000Z",
                    "first_fetch_time": "2025-08-30T12:00:42.000Z",
                    "from_last_fetch": true,
                    "id": "b59da9ea-6814-4ee9-b7b1-ad9088b601cd",
                    "is_fetched_from_adapter": true,
                    "last_fetch_connection_id": "67fd0999fe1c8e812a176ba2",
                    "last_fetch_connection_label": "servicenow-dev",
                    "not_fetched_count": 0,
                    "priority": "5 - Planning",
                    "reporter": "Randy Mason",
                    "source_application": "ServiceNow",
                    "status": "Resolved",
                    "summary": "Access Reviewer",
                    "sys_class_name": "incident",
                    "tenant_number": [
                        "1"
                    ],
                    "ticket_id": "b59da9ea-6814-4ee9-b7b1-ad9088b601cd",
                    "type": "Tickets",
                    "updated": "2024-08-10T16:21:10.000Z"
                },
                "initial_plugin_unique_name": "service_now_adapter_0",
                "plugin_name": "service_now_adapter",
                "plugin_type": "Adapter",
                "plugin_unique_name": "service_now_adapter_0",
                "quick_id": "service_now_adapter_0!b59da9ea-6814-4ee9-b7b1-ad9088b601cd",
                "type": "entitydata"
            },
            "internal_axon_id": "3bd6051f3dd4493796aaf0d55dbcbe1f"
        }
    },
    "data_stream": {
        "dataset": "axonius.ticket",
        "namespace": "75649",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "27b87eaa-1d45-4729-938a-c512585a1dc8",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2024-07-14T23:21:10.000Z",
        "dataset": "axonius.ticket",
        "end": "2024-08-10T16:21:10.000Z",
        "ingested": "2025-12-17T13:36:48Z",
        "kind": "event",
        "original": "{\"adapter_list_length\":1,\"adapters\":[\"service_now_adapter\"],\"asset_type\":\"tickets\",\"event\":{\"accurate_for_datetime\":\"Mon, 08 Dec 2025 00:02:48 GMT\",\"adapter_categories\":[\"CMDB\",\"ITAM/ITSM\",\"Ticketing\",\"SaaS Management\"],\"client_used\":\"67fd0999fe1c8e812a176ba2\",\"data\":{\"accurate_for_datetime\":\"Mon, 08 Dec 2025 00:02:48 GMT\",\"application_and_account_name\":\"servicenow/servicenow-dev\",\"category\":\"Access Reviewer\",\"closed\":\"Sat, 10 Aug 2024 16:21:10 GMT\",\"created\":\"Sun, 14 Jul 2024 23:21:10 GMT\",\"description\":\"Access Reviewer - Needs addressing\",\"display_id\":\"INC3566938\",\"fetch_time\":\"Mon, 08 Dec 2025 00:02:42 GMT\",\"first_fetch_time\":\"Sat, 30 Aug 2025 12:00:42 GMT\",\"from_last_fetch\":true,\"id\":\"b59da9ea-6814-4ee9-b7b1-ad9088b601cd\",\"is_fetched_from_adapter\":true,\"last_fetch_connection_id\":\"67fd0999fe1c8e812a176ba2\",\"last_fetch_connection_label\":\"servicenow-dev\",\"not_fetched_count\":0,\"priority\":\"5 - Planning\",\"reporter\":\"Randy Mason\",\"source_application\":\"ServiceNow\",\"status\":\"Resolved\",\"summary\":\"Access Reviewer\",\"sys_class_name\":\"incident\",\"tenant_number\":[\"1\"],\"ticket_id\":\"b59da9ea-6814-4ee9-b7b1-ad9088b601cd\",\"type\":\"Tickets\",\"updated\":\"Sat, 10 Aug 2024 16:21:10 GMT\"},\"initial_plugin_unique_name\":\"service_now_adapter_0\",\"plugin_name\":\"service_now_adapter\",\"plugin_type\":\"Adapter\",\"plugin_unique_name\":\"service_now_adapter_0\",\"quick_id\":\"service_now_adapter_0!b59da9ea-6814-4ee9-b7b1-ad9088b601cd\",\"type\":\"entitydata\"},\"internal_axon_id\":\"3bd6051f3dd4493796aaf0d55dbcbe1f\"}"
    },
    "input": {
        "type": "cel"
    },
    "message": "Access Reviewer - Needs addressing",
    "related": {
        "user": [
            "Randy Mason"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-ticket"
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

* Ticket:
    * tickets (endpoint: `/api/v2/tickets`)
    * cases (endpoint: `/api/v2/cases`)
