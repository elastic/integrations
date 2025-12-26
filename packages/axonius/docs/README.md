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

- `Exposure`: Collect details of all exposure assets including:
    - vulnerability_instances (endpoint: `/api/v2/vulnerability_instances`)
    - vulnerabilities (endpoint: `/api/v2/vulnerabilities`)
    - vulnerabilities_repository (endpoint: `/api/v2/vulnerabilities_repository`)

### Supported use cases

Integrating the Axonius Exposure Datastream with Elastic SIEM provides a focused view of vulnerability-related activity across the environment. Severity breakdowns help analysts quickly gauge the proportion of critical, high, medium, and low-risk exposures, enabling rapid assessment of overall security posture.

Views into Axonius status and event status offer additional context, helping teams understand which vulnerability events were successfully processed, which require attention, and where failures may indicate deeper issues. A consolidated table of top vulnerabilities highlights the most impactful findings, allowing security teams to prioritize remediation efforts and address high-risk areas efficiently.

These insights enable organizations to monitor exposure trends, detect escalating risks, and streamline vulnerability management workflows across their infrastructure.

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

* Exposure:
    * vulnerability_instances (endpoint: `/api/v2/vulnerability_instances`)
    * vulnerabilities (endpoint: `/api/v2/vulnerabilities`)
    * vulnerabilities_repository (endpoint: `/api/v2/vulnerabilities_repository`)

#### ILM Policy

To facilitate exposure data, source data stream-backed indices `.ds-logs-axonius.exposure-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.exposure-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
