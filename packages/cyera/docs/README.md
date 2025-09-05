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
| Datastore      | v2      |

### How it works

This integration periodically queries the Cyera API to retrieve classifications, issues, events and datastores.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Classification`: Collects classifications that have been identified by the Cyera system.

- `Issue`: Collects issues that have been identified by the Cyera system.

- `Event`: Collects all events from the Cyera system.

- `Datastore`: Collects all datastore objects from the Cyera system.

### Supported use cases
Integrating Cyera Classification, Issues, Events and Datastore data streams with Elastic SIEM provides end-to-end visibility into where sensitive data resides, the risks tied to that data, and the security events triggered across cloud and SaaS environments. By correlating datastore metadata (such as type, provider, sensitivity, and ownership) with Cyera’s classification intelligence, issue context, and event activity in Elastic analytics, security teams can strengthen data security posture, accelerate incident response, and simplify compliance. Dashboards in Kibana present breakdowns by datastore type, sensitivity, category, severity, status, risk status, event type, and trends over time — enabling faster investigations, better prioritization, and improved accountability.

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

### Datastore

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cyera.datastore.account.in_platform_identifier | Inplatform identifier for the account. | keyword |
| cyera.datastore.account.name | Name of the account associated with the datastore. | keyword |
| cyera.datastore.arn |  | keyword |
| cyera.datastore.auto_scan |  | boolean |
| cyera.datastore.azure_id |  | keyword |
| cyera.datastore.classification.groups | Classification groups associated with the datastore. | keyword |
| cyera.datastore.classification.level | Logging status of the datastore. | keyword |
| cyera.datastore.cloud_provider.tags.key | Keys of cloud provider tags. | keyword |
| cyera.datastore.cloud_provider.tags.value | Values of cloud provider tags. | keyword |
| cyera.datastore.cloud_provider.url | URL of the cloud provider for this datastore. | keyword |
| cyera.datastore.collections | Collections associated with the datastore. | keyword |
| cyera.datastore.created_date | Date when the datastore was created. | date |
| cyera.datastore.custom_collections | Custom collections associated with the datastore. | keyword |
| cyera.datastore.data_type |  | keyword |
| cyera.datastore.datastore.owners.datastore_uid |  | keyword |
| cyera.datastore.datastore.owners.email |  | keyword |
| cyera.datastore.datastore.owners.owner_type |  | keyword |
| cyera.datastore.datastore.owners.source |  | keyword |
| cyera.datastore.datastore.owners.uid |  | keyword |
| cyera.datastore.datastore.size_in_gi_b |  | double |
| cyera.datastore.discovered_date | Date when the datastore was discovered. | date |
| cyera.datastore.drive_id |  | keyword |
| cyera.datastore.encrypted | Public accessibility state of the datastore. | boolean |
| cyera.datastore.engine | Engine used by the datastore. | keyword |
| cyera.datastore.frameworks | Indicates if the datastore is encrypted. | keyword |
| cyera.datastore.ghost | Indicates if the datastore is a ghost datastore. | boolean |
| cyera.datastore.infrastructure | Infrastructure type of the datastore. | keyword |
| cyera.datastore.issues.closed | long of closed issues for the datastore. | long |
| cyera.datastore.issues.in_progress | long of inprogress issues for the datastore. | long |
| cyera.datastore.issues.open | long of open issues for the datastore. | long |
| cyera.datastore.last.data_refresh |  | date |
| cyera.datastore.last.modified_time |  | date |
| cyera.datastore.learned | SSL enforcement status of the datastore. | boolean |
| cyera.datastore.logging |  | keyword |
| cyera.datastore.name | Name of the datastore. | keyword |
| cyera.datastore.owner | Owner of the datastore. | keyword |
| cyera.datastore.project_ids |  | keyword |
| cyera.datastore.provider | Provider of the datastore. | keyword |
| cyera.datastore.public_accessibility_state |  | keyword |
| cyera.datastore.rds_endpoint |  | keyword |
| cyera.datastore.record_count_by_sensitivity.internal | Count of internal records in the datastore. | long |
| cyera.datastore.record_count_by_sensitivity.not_sensitive | Count of nonsensitive records in the datastore. | long |
| cyera.datastore.record_count_by_sensitivity.sensitive | Count of sensitive records in the datastore. | long |
| cyera.datastore.record_count_by_sensitivity.unclassified | Count of unclassified records in the datastore. | long |
| cyera.datastore.record_count_by_sensitivity.very_sensitive | Count of very sensitive records in the datastore. | long |
| cyera.datastore.regions | Regions associated with the datastore. | keyword |
| cyera.datastore.scanning_state | Current scanning state of the datastore. | keyword |
| cyera.datastore.sensitivity.display_name |  | keyword |
| cyera.datastore.sensitivity.value | Sensitivity level of the datastore. | keyword |
| cyera.datastore.site.id |  | keyword |
| cyera.datastore.site.name |  | keyword |
| cyera.datastore.ssl_enforced |  | keyword |
| cyera.datastore.type | Type of the datastore. | keyword |
| cyera.datastore.uid | Unique identifier for the datastore. | keyword |
| cyera.datastore.user.id |  | keyword |
| cyera.datastore.user.tags.key | Keys of userdefined tags. | keyword |
| cyera.datastore.user.tags.uid |  | keyword |
| cyera.datastore.user.tags.value | Values of userdefined tags. | keyword |
| cyera.datastore.vpc | VPC associated with the datastore. | keyword |
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

An example event for `datastore` looks as following:

```json
{
    "@timestamp": "2025-05-12T05:06:50.000Z",
    "agent": {
        "ephemeral_id": "2ad732d6-eb3b-47a6-a78f-75fdb11de2bc",
        "id": "254b95d2-4cda-4c5f-844d-ebca9ccfc2d5",
        "name": "elastic-agent-74689",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "cloud": {
        "account": {
            "id": "abcd1234-5678-90ab-cdef-1234567890ab",
            "name": "MockAccount"
        },
        "provider": "example365",
        "region": [
            "Americas"
        ],
        "service": {
            "name": "OneDrive"
        }
    },
    "cyera": {
        "datastore": {
            "account": {
                "in_platform_identifier": "abcd1234-5678-90ab-cdef-1234567890ab",
                "name": "MockAccount"
            },
            "auto_scan": false,
            "classification": {
                "level": "Element"
            },
            "cloud_provider": {
                "url": "https://mocktenant.mockpoint.com/sites/teamx/Shared%20Documents"
            },
            "created_date": "2025-05-12T05:06:50.000Z",
            "data_type": "Unstructured",
            "datastore": {
                "owners": [
                    {
                        "datastore_uid": "0197abcd-1234-5678-90ab-dc221b36194d",
                        "email": "teamx_owner@mocktenant.onexample.com",
                        "source": "SaaSOwner",
                        "uid": "abcd1234-ef56-7890-abcd-ef1234567890"
                    },
                    {
                        "datastore_uid": "0197abcd-1234-5678-90ab-dc221b36194d",
                        "email": "teamx_owner@mocktenant.onexample.com",
                        "source": "SaaSOwner",
                        "uid": "1234abcd-5678-90ef-abcd-0987654321ef"
                    }
                ],
                "size_in_gi_b": 0
            },
            "discovered_date": "2025-06-30T23:12:53.928Z",
            "drive_id": "b!abcdEFGH1234ijkl5678mnop9qrstuvwxYZ",
            "encrypted": true,
            "engine": "mockpoint-library",
            "ghost": false,
            "infrastructure": "OneDrive",
            "issues": {
                "closed": 0,
                "in_progress": 0,
                "open": 0
            },
            "learned": false,
            "logging": "Enabled",
            "name": "TeamX/Documents",
            "owner": "teamx_owner@mocktenant.onexample.com",
            "provider": "example365",
            "public_accessibility_state": "Not Public",
            "record_count_by_sensitivity": {
                "internal": 0,
                "not_sensitive": 0,
                "sensitive": 0,
                "unclassified": 0,
                "very_sensitive": 0
            },
            "regions": [
                "Americas"
            ],
            "scanning_state": "Unmonitored",
            "sensitivity": {
                "display_name": "Unclassified",
                "value": "Unclassified"
            },
            "site": {
                "id": "mocktenant.mockpoint.com,abcd1234-5678-90ab-cdef-112233445566,99887766-5544-3322-1100-aabbccddeeff",
                "name": "TeamX"
            },
            "ssl_enforced": "Unknown",
            "type": "M365_DRIVE",
            "uid": "0197abcd-1234-5678-90ab-dc221b36194d",
            "user": {
                "id": "12345678-9abc-def0-1234-56789abcdef0"
            }
        }
    },
    "data_stream": {
        "dataset": "cyera.datastore",
        "namespace": "89183",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "254b95d2-4cda-4c5f-844d-ebca9ccfc2d5",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-05-12T05:06:50.000Z",
        "dataset": "cyera.datastore",
        "id": "0197abcd-1234-5678-90ab-dc221b36194d",
        "ingested": "2025-09-04T06:53:53Z",
        "kind": "event",
        "original": "{\"account\":{\"inPlatformIdentifier\":\"abcd1234-5678-90ab-cdef-1234567890ab\",\"name\":\"MockAccount\"},\"autoScan\":false,\"classificationGroups\":[],\"classificationLevel\":\"Element\",\"cloudProviderTags\":[],\"cloudProviderUrl\":\"https://mocktenant.mockpoint.com/sites/teamx/Shared%20Documents\",\"collections\":[],\"createdDate\":\"2025-05-12T05:06:50.000Z\",\"customCollections\":[],\"dataType\":\"Unstructured\",\"datastoreOwners\":[{\"datastoreOwnerUid\":\"abcd1234-ef56-7890-abcd-ef1234567890\",\"datastoreUid\":\"0197abcd-1234-5678-90ab-dc221b36194d\",\"email\":\"teamx_owner@mocktenant.onexample.com\",\"ownerType\":\"\",\"source\":\"SaaSOwner\"},{\"datastoreOwnerUid\":\"1234abcd-5678-90ef-abcd-0987654321ef\",\"datastoreUid\":\"0197abcd-1234-5678-90ab-dc221b36194d\",\"email\":\"teamx_owner@mocktenant.onexample.com\",\"ownerType\":\"\",\"source\":\"SaaSOwner\"}],\"datastoreSizeInGiB\":0,\"discoveredDate\":\"2025-06-30T23:12:53.928Z\",\"driveId\":\"b!abcdEFGH1234ijkl5678mnop9qrstuvwxYZ\",\"encrypted\":true,\"engine\":\"mockpoint-library\",\"frameworks\":[],\"ghost\":false,\"infrastructure\":\"OneDrive\",\"issues\":{\"closed\":0,\"inProgress\":0,\"open\":0},\"learned\":false,\"logging\":\"Enabled\",\"name\":\"TeamX/Documents\",\"owner\":\"teamx_owner@mocktenant.onexample.com\",\"projectIds\":[],\"provider\":\"example365\",\"publicAccessibilityState\":\"Not Public\",\"rdsEndpoint\":null,\"recordCountBySensitivity\":{\"Internal\":0,\"NotSensitive\":0,\"Sensitive\":0,\"Unclassified\":0,\"VerySensitive\":0},\"regions\":[\"Americas\"],\"scanningState\":\"Unmonitored\",\"sensitivity\":\"Unclassified\",\"sensitivityDisplayName\":\"Unclassified\",\"siteId\":\"mocktenant.mockpoint.com,abcd1234-5678-90ab-cdef-112233445566,99887766-5544-3322-1100-aabbccddeeff\",\"siteName\":\"TeamX\",\"sslEnforced\":\"Unknown\",\"type\":\"M365_DRIVE\",\"uid\":\"0197abcd-1234-5678-90ab-dc221b36194d\",\"userId\":\"12345678-9abc-def0-1234-56789abcdef0\",\"userTags\":[],\"vpc\":null}"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "teamx_owner@mocktenant.onexample.com",
            "12345678-9abc-def0-1234-56789abcdef0"
        ]
    },
    "service": {
        "id": "0197abcd-1234-5678-90ab-dc221b36194d",
        "name": "TeamX/Documents",
        "type": "M365_DRIVE"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cyera-datastore"
    ],
    "user": {
        "domain": "mocktenant.onexample.com",
        "email": "teamx_owner@mocktenant.onexample.com",
        "id": "12345678-9abc-def0-1234-56789abcdef0",
        "name": "teamx_owner"
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

#### ILM Policy

To facilitate datastore data, source data stream-backed indices `.ds-logs-cyera.datastore-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-cyera.datastore-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
