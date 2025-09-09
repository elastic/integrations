# Island Browser Integration for Elastic

## Overview

[Island](https://www.island.io/) reimagines what the browser can be. By taking in the needs of the enterprise, Island delivers a dramatic positive impact on every layer of cybersecurity and all other functions of IT, while improving the end-user experience and productivity. Leveraging the open-source Chromium project that all major browsers are based on, Island provides fine-grain policy control over every facet of a user’s interaction with a web application giving the enterprise limitless visibility, control, and compliance with their most critical applications. As a result, Island can serve as the platform for the future of productive and secured work.

The Island Browser integration for Elastic allows you to collect logs using [Island Browser API](https://documentation.island.io/apidocs), then visualise the data in Kibana.

### Compatibility

The Island Browser integration is compatible with `v1` version of Island Browser API.

### How it works

This integration periodically queries the Island Browser API to retrieve users.

## What data does this integration collect?

This integration collects log messages of the following types:

- `User`: Collects all the users from the Island Browser via [User API endpoint](https://documentation.island.io/apidocs/get-all-browser-users-that-match-the-specified-simple-filter).

### Supported use cases
Integrating Island Browser User endpoint data with Elastic SIEM enhances visibility into account activity and user management. Kibana dashboards track total users, active users, and login trends, while breakdowns by source, type, status, and group highlight usage patterns. Tables for email-verified users and essential details provide quick context for investigations. Together, these insights help analysts monitor identity usage, detect anomalies, and strengthen user oversight.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Island Browser

To collect data through the Island Browser APIs, `Admin` role must be required and admin must have permission to generate and manage API keys (i.e. full admin, system admin). Authentication is handled using a `API Key`, which serve as the required credentials.

#### Generate an `API Key`:

1. Log in to Island Browser Management Console.
2. From the **Island Management Console**, navigate to **Modules > Platform Settings > System Settings > Integrations > API**.
3. Click **+ Create**. The **Create API Key** drawer is displayed to assist in the key creation.
4. Enter a **Name**.
5. Select the **Role** that applies to this API key (i.e. Full Admin, or Read Only).
6. Click **Generate API Key**.
7. Copy the **API Key** to your clipboard to be used when using the [API Explorer](https://documentation.island.io/v1-api/apidocs/introduction-to-the-api-explorer).
8. Click **Save**.

For more details, check [Documentation](https://documentation.island.io/apidocs/generate-and-manage-api-keys).

>**Note**: If an API key already exists and you need to create a new one, you must first deactivate and delete the existing key by selecting **Deactivate and Delete API Key**.


## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Island Browser**.
3. Select the **Island Browser** integration from the search results.
4. Select **Add Island Browser** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Island Browser API**, you'll need to:

        - Configure **URL** and **API Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Interval, Batch Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **island_browser**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **island_browser**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### User

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| island_browser.user.allowed_tenants_ids |  | keyword |
| island_browser.user.claims |  | flattened |
| island_browser.user.connection_name |  | keyword |
| island_browser.user.created_date |  | date |
| island_browser.user.email |  | keyword |
| island_browser.user.email_verified |  | boolean |
| island_browser.user.expiration_date |  | date |
| island_browser.user.first_name |  | keyword |
| island_browser.user.groups |  | keyword |
| island_browser.user.id |  | keyword |
| island_browser.user.invitation_date |  | date |
| island_browser.user.last_login |  | date |
| island_browser.user.last_name |  | keyword |
| island_browser.user.last_seen |  | date |
| island_browser.user.scim_id |  | keyword |
| island_browser.user.tenant_id |  | keyword |
| island_browser.user.updated_date |  | date |
| island_browser.user.user_id |  | keyword |
| island_browser.user.user_source |  | keyword |
| island_browser.user.user_status |  | keyword |
| island_browser.user.user_type |  | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


### Example event

#### User

An example event for `user` looks as following:

```json
{
    "@timestamp": "2025-09-04T12:39:57.547Z",
    "agent": {
        "ephemeral_id": "983d7003-c4da-4291-9fed-1668fed07cd2",
        "id": "d4bbdd48-d331-45dd-9c18-342db4df3990",
        "name": "elastic-agent-10884",
        "type": "filebeat",
        "version": "8.18.5"
    },
    "data_stream": {
        "dataset": "island_browser.user",
        "namespace": "64239",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "d4bbdd48-d331-45dd-9c18-342db4df3990",
        "snapshot": false,
        "version": "8.18.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2025-08-15T10:30:00.000Z",
        "dataset": "island_browser.user",
        "id": "f3d9a7c8-42b1-4f19-9b51-8a3c56e6d912",
        "ingested": "2025-09-04T12:40:00Z",
        "kind": "event",
        "original": "{\"allowedTenantsIds\":[\"acme-tenant-001\",\"partner-tenant-002\"],\"claims\":{},\"connectionName\":\"AzureAD\",\"createdDate\":\"2025-08-15T10:30:00Z\",\"email\":\"john.doe@example.com\",\"emailVerified\":true,\"expirationDate\":null,\"firstName\":\"John\",\"groups\":[\"Admins\",\"Security\"],\"id\":\"f3d9a7c8-42b1-4f19-9b51-8a3c56e6d912\",\"invitationDate\":\"2025-08-10T09:00:00Z\",\"lastLogin\":\"2025-08-18T14:40:10Z\",\"lastName\":\"Doe\",\"lastSeen\":\"2025-08-18T14:41:55Z\",\"scimId\":null,\"tenantId\":\"acme-tenant-001\",\"updatedDate\":\"2025-08-18T14:45:00Z\",\"userId\":\"user-12345\",\"userSource\":\"Email\",\"userStatus\":\"Active\",\"userType\":\"Management\"}",
        "type": [
            "user"
        ]
    },
    "input": {
        "type": "cel"
    },
    "island_browser": {
        "user": {
            "allowed_tenants_ids": [
                "acme-tenant-001",
                "partner-tenant-002"
            ],
            "connection_name": "AzureAD",
            "created_date": "2025-08-15T10:30:00.000Z",
            "email": "john.doe@example.com",
            "email_verified": true,
            "first_name": "John",
            "groups": [
                "Admins",
                "Security"
            ],
            "id": "f3d9a7c8-42b1-4f19-9b51-8a3c56e6d912",
            "invitation_date": "2025-08-10T09:00:00.000Z",
            "last_login": "2025-08-18T14:40:10.000Z",
            "last_name": "Doe",
            "last_seen": "2025-08-18T14:41:55.000Z",
            "tenant_id": "acme-tenant-001",
            "updated_date": "2025-08-18T14:45:00.000Z",
            "user_id": "user-12345",
            "user_source": "Email",
            "user_status": "Active",
            "user_type": "Management"
        }
    },
    "organization": {
        "id": "acme-tenant-001"
    },
    "related": {
        "user": [
            "john.doe@example.com",
            "John",
            "user-12345"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "island_browser-user"
    ],
    "user": {
        "domain": "example.com",
        "email": "john.doe@example.com",
        "full_name": "John Doe",
        "group": {
            "name": [
                "Admins",
                "Security"
            ]
        },
        "id": "user-12345",
        "name": "John"
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following API:

- `User`: [Island Browser API](https://documentation.island.io/apidocs/get-all-browser-users-that-match-the-specified-simple-filter).

#### ILM Policy

To facilitate user data, source data stream-backed indices `.ds-logs-island_browser.user-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-island_browser.user-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
