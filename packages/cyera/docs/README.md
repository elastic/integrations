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

### How it works

This integration periodically queries the Cyera API to retrieve classifications and issues.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Classification`: Collects classifications that have been identified by the Cyera system.

- `Issue`: Collects issues that have been identified by the Cyera system.

### Supported use cases
Integrating Cyera Classification and Issues data streams with Elastic SIEM provides visibility into both sensitive data classification and the risks associated with that data across cloud and SaaS environments. By correlating Cyera’s classification intelligence with issue context in Elastic analytics, security teams can strengthen data security posture, accelerate incident response, and simplify compliance. Dashboards in Kibana present breakdowns by sensitivity, category, severity, status, risk status, and trends over time, enabling faster investigations, better prioritization, and improved accountability.

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

### Issue

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cyera.issue.account.in_platform_identifier | In-platform identifier for the account. | keyword |
| cyera.issue.account.name | Name of the account associated with the issue. | keyword |
| cyera.issue.classification_groups | Classification groups related to the issue. | keyword |
| cyera.issue.cloud_provider_tags.key | Keys of cloud provider tags. | keyword |
| cyera.issue.cloud_provider_tags.value | Values of cloud provider tags. | keyword |
| cyera.issue.created_date | Date when the issue was created. | date |
| cyera.issue.data.affected_records |  | long |
| cyera.issue.data.data_classes_uids | Unique identifiers of data classes at risk. | keyword |
| cyera.issue.data.objects_at_risk | long of records at risk due to this issue. | long |
| cyera.issue.data.records_at_risk |  | long |
| cyera.issue.datastore_cloud_provider_tags.key | Keys of cloud provider tags for the associated datastore. | keyword |
| cyera.issue.datastore_cloud_provider_tags.value | Values of cloud provider tags for the associated datastore. | keyword |
| cyera.issue.datastore_name | Name of the datastore associated with the issue. | keyword |
| cyera.issue.datastore_owners.datastore_owner_uid |  | keyword |
| cyera.issue.datastore_owners.email |  | keyword |
| cyera.issue.datastore_owners.owner_type |  | keyword |
| cyera.issue.datastore_owners.sources |  | keyword |
| cyera.issue.datastore_uid | Unique identifier of the datastore associated with the issue. | keyword |
| cyera.issue.datastore_user_tags.key | Keys of user-defined tags for the associated datastore. | keyword |
| cyera.issue.datastore_user_tags.uid |  | keyword |
| cyera.issue.datastore_user_tags.value | Values of user-defined tags for the associated datastore. | keyword |
| cyera.issue.engine | Engine type associated with the issue. | keyword |
| cyera.issue.infrastructure | Infrastructure type related to the issue. | keyword |
| cyera.issue.itsm_tickets.uid |  | keyword |
| cyera.issue.itsm_tickets.vendor.link |  | keyword |
| cyera.issue.itsm_tickets.vendor.status |  | keyword |
| cyera.issue.itsm_tickets.vendor.ticket_id |  | keyword |
| cyera.issue.name | Name of the issue. | keyword |
| cyera.issue.owner | Owner of the issue. | keyword |
| cyera.issue.policy_uid |  | keyword |
| cyera.issue.provider | Cloud provider associated with the issue. | keyword |
| cyera.issue.regions | Regions affected by the issue. | keyword |
| cyera.issue.remediation_advice |  | keyword |
| cyera.issue.resolution | Resolution details for the issue. | keyword |
| cyera.issue.resolution_note |  | keyword |
| cyera.issue.risk.description |  | keyword |
| cyera.issue.risk.frameworks | Description of the risk associated with the issue. | keyword |
| cyera.issue.risk.policy_uid | Unique identifier of the risk policy associated with the issue. | keyword |
| cyera.issue.risk.use_cases | Risk frameworks associated with the issue. | keyword |
| cyera.issue.risk_status | Risk status of the issue. | keyword |
| cyera.issue.severity | Severity level of the issue. | keyword |
| cyera.issue.status | Current status of the issue. | keyword |
| cyera.issue.uid | Unique identifier for the issue. | keyword |
| cyera.issue.updated_date | Date when the issue was last updated. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


#### Example event

An example event for `issue` looks as following:

```json
{
    "@timestamp": "2025-07-22T11:45:30.987Z",
    "agent": {
        "ephemeral_id": "e7468920-f21c-4fe8-beba-93492fab51b3",
        "id": "53cd199e-8ede-42a1-9a99-f258b326ca1c",
        "name": "elastic-agent-75052",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "cloud": {
        "account": {
            "id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
            "name": "AWS Account - Finance"
        },
        "provider": "AWS",
        "region": [
            "us-east-1"
        ],
        "service": {
            "name": "rds-mysql"
        }
    },
    "cyera": {
        "issue": {
            "account": {
                "in_platform_identifier": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
                "name": "AWS Account - Finance"
            },
            "classification_groups": [
                "Financial",
                "IT & Security"
            ],
            "created_date": "2025-07-10T08:20:45.123Z",
            "data": {
                "affected_records": 2500,
                "data_classes_uids": [
                    "0198c3ba-1234-5678-9abc-def098765432"
                ],
                "objects_at_risk": 3,
                "records_at_risk": 2500
            },
            "datastore_cloud_provider_tags": [
                {
                    "key": "BusinessUnit",
                    "value": "Finance"
                },
                {
                    "key": "CostCenter",
                    "value": "99887"
                },
                {
                    "key": "Department",
                    "value": "CloudOps"
                },
                {
                    "key": "Environment",
                    "value": "Prod"
                },
                {
                    "key": "Project",
                    "value": "Everest"
                }
            ],
            "datastore_name": "mock-database-prod-xyz",
            "datastore_owners": [
                {
                    "datastore_owner_uid": "0198efgh-6789-1234-abcd-ef9876543210",
                    "email": "datastore.owner@mockmail.com",
                    "owner_type": "application-owner",
                    "sources": [
                        "IAM"
                    ]
                }
            ],
            "datastore_uid": "0198dbcd-4321-8765-9def-abcdef987654",
            "datastore_user_tags": [
                {
                    "key": "owner",
                    "value": "TeamX"
                }
            ],
            "engine": "mysql",
            "infrastructure": "rds-mysql",
            "itsm_tickets": [
                {
                    "uid": "abc12345-6789-def0-1234-56789abcdef0",
                    "vendor": {
                        "link": "https://company.service-now.com/nav_to.do?uri=incident.do?sys_id=12345",
                        "status": "Open",
                        "ticket_id": "SNOW-98765"
                    }
                }
            ],
            "name": "Credit card number in plain text",
            "owner": "owner@mockmail.com",
            "policy_uid": "0198c2ec-55ef-77ab-cc12-778899aabbcc",
            "provider": "AWS",
            "regions": [
                "us-east-1"
            ],
            "remediation_advice": "- Evaluate the need for storing credit card data in the current location. If it is not necessary, promptly delete the information to reduce the risk of unauthorized access.\n- Encrypt the data using strong encryption algorithms.\n- Choose either masking or tokenization as a method for securely displaying or storing credit card numbers.",
            "risk": {
                "description": "According to PCI DSS section 3.4 if PAN storage is unavoidable, the data must be rendered unreadable wherever it is stored. The PCI-DSS explicitly enumerates the acceptable methods for rendering this data unreadable. These methods include - strong one-way hash functions of the entire PAN, truncation, index token with securely stored pads, strong cryptography.",
                "frameworks": [
                    "PCI DSS",
                    "SOC 2",
                    "ISO 27001"
                ],
                "policy_uid": "0198c2ec-55ef-77ab-cc12-778899aabbcc",
                "use_cases": [
                    "DataSprawl",
                    "DataRetention"
                ]
            },
            "risk_status": "Unmitigated",
            "severity": "Critical",
            "status": "Open",
            "uid": "0198abcd-1234-5678-9abc-def012345678",
            "updated_date": "2025-07-22T11:45:30.987Z"
        }
    },
    "data_stream": {
        "dataset": "cyera.issue",
        "namespace": "31472",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "53cd199e-8ede-42a1-9a99-f258b326ca1c",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-07-10T08:20:45.123Z",
        "dataset": "cyera.issue",
        "id": "0198abcd-1234-5678-9abc-def012345678",
        "ingested": "2025-08-26T12:04:29Z",
        "kind": "alert",
        "original": "{\"account\":{\"inPlatformIdentifier\":\"a1b2c3d4-5678-90ab-cdef-1234567890ab\",\"name\":\"AWS Account - Finance\"},\"classificationGroups\":[\"Financial\",\"IT \\u0026 Security\"],\"createdDate\":\"2025-07-10T08:20:45.123Z\",\"data\":{\"affectedRecords\":2500,\"dataClassesUids\":[\"0198c3ba-1234-5678-9abc-def098765432\"],\"objectsAtRisk\":3,\"recordsAtRisk\":2500},\"datastoreCloudProviderTags\":[{\"key\":\"BusinessUnit\",\"value\":\"Finance\"},{\"key\":\"CostCenter\",\"value\":\"99887\"},{\"key\":\"Department\",\"value\":\"CloudOps\"},{\"key\":\"Environment\",\"value\":\"Prod\"},{\"key\":\"Project\",\"value\":\"Everest\"}],\"datastoreName\":\"mock-database-prod-xyz\",\"datastoreOwners\":[{\"datastoreOwnerUid\":\"0198efgh-6789-1234-abcd-ef9876543210\",\"email\":\"datastore.owner@mockmail.com\",\"ownerType\":\"application-owner\",\"sources\":[\"IAM\"]}],\"datastoreUid\":\"0198dbcd-4321-8765-9def-abcdef987654\",\"datastoreUserTags\":[{\"key\":\"owner\",\"value\":\"TeamX\"}],\"engine\":\"mysql\",\"infrastructure\":\"rds-mysql\",\"itsmTickets\":[{\"uid\":\"abc12345-6789-def0-1234-56789abcdef0\",\"vendorLink\":\"https://company.service-now.com/nav_to.do?uri=incident.do?sys_id=12345\",\"vendorStatus\":\"Open\",\"vendorTicketId\":\"SNOW-98765\"}],\"name\":\"Credit card number in plain text\",\"owner\":\"owner@mockmail.com\",\"policyUid\":\"0198c2ec-55ef-77ab-cc12-778899aabbcc\",\"provider\":\"AWS\",\"regions\":[\"us-east-1\"],\"remediationAdvice\":\"- Evaluate the need for storing credit card data in the current location. If it is not necessary, promptly delete the information to reduce the risk of unauthorized access.\\n- Encrypt the data using strong encryption algorithms.\\n- Choose either masking or tokenization as a method for securely displaying or storing credit card numbers.\",\"risk\":{\"description\":\"According to PCI DSS section 3.4 if PAN storage is unavoidable, the data must be rendered unreadable wherever it is stored. The PCI-DSS explicitly enumerates the acceptable methods for rendering this data unreadable. These methods include - strong one-way hash functions of the entire PAN, truncation, index token with securely stored pads, strong cryptography.\",\"frameworks\":[\"PCI DSS\",\"SOC 2\",\"ISO 27001\"],\"policyUid\":\"0198c2ec-55ef-77ab-cc12-778899aabbcc\",\"useCases\":[\"DataSprawl\",\"DataRetention\"]},\"riskStatus\":\"Unmitigated\",\"severity\":\"Critical\",\"status\":\"Open\",\"uid\":\"0198abcd-1234-5678-9abc-def012345678\",\"updatedDate\":\"2025-07-22T11:45:30.987Z\"}",
        "severity": 99
    },
    "input": {
        "type": "cel"
    },
    "message": "Credit card number in plain text",
    "related": {
        "user": [
            "0198efgh-6789-1234-abcd-ef9876543210",
            "datastore.owner@mockmail.com",
            "owner@mockmail.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cyera-issue"
    ],
    "user": {
        "domain": "mockmail.com",
        "email": "owner@mockmail.com",
        "name": "owner",
        "roles": [
            "application-owner"
        ]
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
