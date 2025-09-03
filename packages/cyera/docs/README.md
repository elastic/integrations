# Cyera Integration for Elastic

## Overview

[Cyera](https://www.cyera.com/) is a cloud data security platform (DSPM – Data Security Posture Management). It focuses on discovering, classifying, monitoring, and protecting sensitive data across cloud environments (AWS, Azure, GCP, SaaS, M365, Snowflake, etc.).

The Cyera integration for Elastic allows you to collect logs and visualise the data in Kibana.

### Compatibility

This integration is compatible with different versions of Cyera APIs for respective data streams as below:

| Data streams   | Version |
|----------------|---------|
| Classification | v1      |
| Issue          | v3      |
| Event          | v1      |

### How it works

This integration periodically queries the Cyera API to retrieve classifications, issues and events.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Classification`: Collects classifications that have been identified by the Cyera system.

- `Issue`: Collects issues that have been identified by the Cyera system.

- `Event`: Collects all events from the Cyera system.

### Supported use cases
Integrating Cyera Classification, Issues, and Events data streams with Elastic SIEM provides visibility into sensitive data, the risks tied to that data, and the security events triggered across cloud and SaaS environments. By correlating Cyera’s classification intelligence with issue context and event activity in Elastic analytics, security teams can strengthen data security posture, accelerate incident response, and simplify compliance. Dashboards in Kibana present breakdowns by sensitivity, category, severity, status, risk status, event type, and trends over time — enabling faster investigations, better prioritization, and improved accountability.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Cyera

While collecting data through the Cyera APIs, authentication is handled using a `Client ID` and `Client Secret`, which serve as the required credentials. Any requests made without credentials will be rejected by the Cyera APIs.

#### Obtain `Credentials`:

- Generate a Cyera API client, retrieve the Client ID and Client Secret.
- Confirm your Cyera API URL, a default is loaded in the configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Cyera**.
3. Select the **Cyera** integration from the search results.
4. Select **Add Cyera** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Cyera logs via API**, you'll need to:

        - Configure **URL**, **Client ID**, and **Client Secret**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Initial Interval, Interval, Batch Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In Kibana, navigate to **Dashboards**.
2. In the search bar, type **cyera**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In Kibana, navigate to **Management** > **Stack Management**.
2. Under **Data**, select **Transforms**.
3. In the search bar, type **cyera**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

### Event

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cyera.event.account.name | Name of the account associated with the event. | keyword |
| cyera.event.account.platform | Platform of the account associated with the event. | keyword |
| cyera.event.account.uid | Unique identifier of the account associated with the event. | keyword |
| cyera.event.affected.data_class_appearances.records_count.data_class.classification_name | Name of the affected data class. | keyword |
| cyera.event.affected.data_class_appearances.records_count.data_class.uid | Unique identifier of the affected data class. | keyword |
| cyera.event.affected.data_class_appearances.records_count.value | Count of records in the affected data class. | long |
| cyera.event.affected.objects_count | Count of affected objects. | long |
| cyera.event.affected.objects_diff | Difference in affected objects count. | long |
| cyera.event.affected.records_diff | Difference in affected records count. | long |
| cyera.event.automatic_scanning |  | keyword |
| cyera.event.changed_classification_uid |  | keyword |
| cyera.event.classification_name | Name of the classification associated with the event. | keyword |
| cyera.event.classifications.name | Names of classifications associated with the event. | keyword |
| cyera.event.classifications.uid | Unique identifiers of classifications associated with the event. | keyword |
| cyera.event.cloud_provider | Cloud provider associated with the event. | keyword |
| cyera.event.datastore.data_owner | Data owner of the datastore associated with the event. | keyword |
| cyera.event.datastore.infrastructure | Infrastructure type of the datastore associated with the event. | keyword |
| cyera.event.datastore.name | Name of the datastore associated with the event. | keyword |
| cyera.event.datastore.records_at_high_risk | long of records at high risk in the datastore. | long |
| cyera.event.datastore.tags.user_tags |  | keyword |
| cyera.event.datastore.uid | Unique identifier of the datastore associated with the event. | keyword |
| cyera.event.datastore.user_tags | User tags associated with the datastore. | keyword |
| cyera.event.datastore.vpc_id | VPC ID of the datastore associated with the event. | keyword |
| cyera.event.date | Date when the event occurred. | date |
| cyera.event.deployment_name | Name of the deployment associated with the event. | keyword |
| cyera.event.domain_name |  | keyword |
| cyera.event.expected_m365_sensitivity_label_assignments_count | Expected count of M365 sensitivity label assignments. | long |
| cyera.event.failed_m365_sensitivity_label_assignments_count | Count of failed M365 sensitivity label assignments. | long |
| cyera.event.frequency | Frequency of the report associated with the event. | keyword |
| cyera.event.in_platform_identifier | Inplatform identifier associated with the event. | keyword |
| cyera.event.is_domain_trusted |  | boolean |
| cyera.event.is_report.deleted | Indicates if the report associated with the event is deleted. | boolean |
| cyera.event.is_report.expired | Indicates if the report associated with the event is expired. | boolean |
| cyera.event.issue.name | Name of the issue associated with the event. | keyword |
| cyera.event.issue.policy.name | Name of the policy associated with the issue. | keyword |
| cyera.event.issue.policy.uid | Unique identifier of the policy associated with the issue. | keyword |
| cyera.event.issue.policy.use_cases | Use cases of the policy associated with the issue. | keyword |
| cyera.event.issue.resolution.note | Resolution note of the issue associated with the event. | keyword |
| cyera.event.issue.resolution.value | Resolution of the issue associated with the event. | keyword |
| cyera.event.issue.risk_status | Risk status of the issue associated with the event. | keyword |
| cyera.event.issue.uid | Unique identifier of the issue associated with the event. | keyword |
| cyera.event.issue_name | Name of the issue associated with the event. | keyword |
| cyera.event.issue_uid | Unique identifier of the issue associated with the event. | keyword |
| cyera.event.issues.policy.name | Names of policies associated with the issues. | keyword |
| cyera.event.issues.policy.uid | Unique identifiers of policies associated with the issues. | keyword |
| cyera.event.issues.policy.use_cases | Use cases of policies associated with the issues. | keyword |
| cyera.event.issues.resolution_note | Resolution notes of issues associated with the event. | keyword |
| cyera.event.issues.resolution_value | Resolutions of issues associated with the event. | keyword |
| cyera.event.issues.risk_status | Risk statuses of issues associated with the event. | keyword |
| cyera.event.issues.uid | Unique identifiers of issues associated with the event. | keyword |
| cyera.event.m365_assigned_sensitivity_label_name | Name of the M365 assigned sensitivity label. | keyword |
| cyera.event.original_sensitivity.display_name | Display name of the original sensitivity level. | keyword |
| cyera.event.original_sensitivity.value | Original sensitivity level. | keyword |
| cyera.event.policy.name | Name of the policy associated with the event. | keyword |
| cyera.event.policy.uid | Unique identifier of the policy associated with the event. | keyword |
| cyera.event.policy.use_cases | Use cases of the policy associated with the event. | keyword |
| cyera.event.project.name | Name of the project associated with the event. | keyword |
| cyera.event.project.uid | Unique identifier of the project associated with the event. | keyword |
| cyera.event.recipients | Recipients associated with the event. | keyword |
| cyera.event.report.file_name | File name of the report associated with the event. | keyword |
| cyera.event.report.instance_uid | Unique identifier of the report instance associated with the event. | keyword |
| cyera.event.report.job_uid | Unique identifier of the report job associated with the event. | keyword |
| cyera.event.report.name | Name of the report associated with the event. | keyword |
| cyera.event.report.type | Type of the report associated with the event. | keyword |
| cyera.event.sku | SKU associated with the event. | keyword |
| cyera.event.source_classifications.name | Names of source classifications. | keyword |
| cyera.event.source_classifications.uid | Unique identifiers of source classifications. | keyword |
| cyera.event.subscription_uid | Unique identifier of the subscription associated with the event. | keyword |
| cyera.event.successful_m365_sensitivity_label_assignments_count | Count of successful M365 sensitivity label assignments. | long |
| cyera.event.target_classifications.name | Names of target classifications. | keyword |
| cyera.event.target_classifications.uid | Unique identifiers of target classifications. | keyword |
| cyera.event.target_sensitivity.display_name | Display name of the target sensitivity level. | keyword |
| cyera.event.target_sensitivity.value | Target sensitivity level. | keyword |
| cyera.event.type | Type of the event. | keyword |
| cyera.event.uid | Unique identifier for the event. | keyword |
| cyera.event.user | User associated with the event. | keyword |
| cyera.event.vendor.link | Vendor link associated with the event. | keyword |
| cyera.event.vendor.status | Vendor status associated with the event. | keyword |
| cyera.event.vendor.ticket_id | Vendor ticket ID associated with the event. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


#### Example event

An example event for `event` looks as following:

```json
{
    "@timestamp": "2025-07-29T17:41:51.058Z",
    "agent": {
        "ephemeral_id": "3037cc24-ebf5-4e0c-a44d-ae55894543a8",
        "id": "2f07e144-4589-4750-ab0a-2a81d787999c",
        "name": "elastic-agent-90612",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "cloud": {
        "account": {
            "id": "mock-account-uid-002",
            "name": "MockAccount"
        }
    },
    "cyera": {
        "event": {
            "account": {
                "name": "MockAccount",
                "uid": "mock-account-uid-002"
            },
            "affected": {
                "data_class_appearances": [
                    {
                        "records_count": {
                            "data_class": {
                                "classification_name": "Mock Classification A",
                                "uid": "mock-dc-010"
                            },
                            "value": 81
                        }
                    }
                ]
            },
            "date": "2025-07-29T17:41:51.058Z",
            "expected_m365_sensitivity_label_assignments_count": 1,
            "failed_m365_sensitivity_label_assignments_count": 0,
            "issue": {
                "risk_status": "RemediationInProgress",
                "uid": "mock-issue-uid-002"
            },
            "m365_assigned_sensitivity_label_name": "Mock Sensitivity Label",
            "policy": {
                "name": "Mock Policy - Missing Label"
            },
            "successful_m365_sensitivity_label_assignments_count": 1,
            "type": "M365SensitivityLabelRemediationFinishedEvent",
            "uid": "mock-uid-2001"
        }
    },
    "data_stream": {
        "dataset": "cyera.event",
        "namespace": "60961",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "2f07e144-4589-4750-ab0a-2a81d787999c",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cyera.event",
        "id": "mock-uid-2001",
        "ingested": "2025-08-30T14:51:23Z",
        "kind": "alert",
        "original": "{\"account\":{\"name\":\"MockAccount\",\"uid\":\"mock-account-uid-002\"},\"affectedDataClassAppearances\":[{\"recordsCount\":{\"dataClass\":{\"classificationName\":\"Mock Classification A\",\"uid\":\"mock-dc-010\"},\"recordsCount\":81}}],\"date\":\"2025-07-29T17:41:51.058Z\",\"expectedM365SensitivityLabelAssignmentsCount\":1,\"failedM365SensitivityLabelAssignmentsCount\":0,\"issue\":{\"riskStatus\":\"RemediationInProgress\",\"uid\":\"mock-issue-uid-002\"},\"m365AssignedSensitivityLabelName\":\"Mock Sensitivity Label\",\"policy\":{\"name\":\"Mock Policy - Missing Label\"},\"successfulM365SensitivityLabelAssignmentsCount\":1,\"type\":\"M365SensitivityLabelRemediationFinishedEvent\",\"uid\":\"mock-uid-2001\"}"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cyera-event"
    ]
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
