# PingDirectory Integration

## Overview

[PingDirectory](https://www.pingidentity.com/en/product/pingdirectory.html) is an **enterprise-grade LDAP directory server** and identity data store. It provides high-performance, scalable directory services for managing user identities, credentials, and access control across hybrid environments — combining authentication, authorization, and directory data management into a unified platform for **critical identity infrastructure**.

This integration collects user identity data from PingDirectory via the SCIM v2 API using the Elastic Agent CEL input. It provides visibility into user accounts and identity attributes managed within your PingDirectory environment.

### Compatibility

The PingDirectory integration is compatible with **PingDirectory version 11.0.0.2 and above**.

### How it works

The integration uses the Elastic Agent CEL input to collect user data from the PingDirectory SCIM v2 API. Each collection cycle:

1. Authenticates against the PingDirectory REST API (`/directory/v1/authenticate`) using the configured `bind_dn` and `password` to obtain a short-lived access token.
2. Paginates through all users via the SCIM v2 Users endpoint (`/scim/v2/Users`) using the configured batch size.
3. Emits each user record as an individual event for ingestion and enrichment via the built-in ingest pipeline.
4. Caches the access token across collection cycles and re-authenticates automatically when the token expires.

## What data does this integration collect?

The PingDirectory integration collects the following types of data:

| Data stream | Description | Endpoint |
|---|---|---|
| `user` | User identity records retrieved from the PingDirectory SCIM v2 API, including usernames, email addresses, display names, names, titles, user types, and account metadata. | `/scim/v2/Users` |

### Supported use cases

* **User inventory and identity visibility**: Track all user accounts managed in PingDirectory, including their attributes, email addresses, and account types.

* **Identity data enrichment**: Correlate PingDirectory user records with other security and operational data in Elastic for unified identity context.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From PingDirectory

* **PingDirectory deployment**: An active PingDirectory server with the SCIM v2 API enabled and accessible.
* **Service account credentials**: A bind DN (`bind_dn`) and password with sufficient permissions to authenticate via `/directory/v1/authenticate` and read users from `/scim/v2/Users`.
* **Network access**: Elastic Agent must be able to reach the PingDirectory HTTPS endpoint.
* **SSL certificate**: If PingDirectory uses a self-signed certificate, the certificate must be trusted by the Elastic Agent host.
* **Elastic Agent**: Version 8.18+ or 9.0+ with Fleet enrollment.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to poll the PingDirectory SCIM v2 API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html)

### Set up steps in PingDirectory

Before configuring the integration, ensure that a PingDirectory account is available for API authentication and user retrieval.

1. Create or identify a service account in PingDirectory.
2. Grant the account permission to:

   * Authenticate through the `/directory/v1/authenticate` endpoint.
   * Read user records through the `/scim/v2/Users` endpoint.

3. Record the account's bind DN and password. These values are required when configuring the integration in Kibana.
4. Verify that the SCIM v2 API is enabled and accessible from the Elastic Agent host.
5. If HTTPS is configured with a self-signed certificate, export the certificate so it can be trusted by Elastic Agent.

Refer to the PingDirectory documentation for configuring SCIM 2.0 and authentication requirements.

### Configure

1. In Kibana, navigate to **Fleet → Integrations** and search for **PingDirectory**.
2. Click **Add PingDirectory**.
3. Configure the integration settings:

   * **URL**: The base URL of your PingDirectory instance, for example:
 https://pingdirectory.example.com:2443
   * **Bind DN**: The distinguished name used to authenticate, for example:
 cn=admin,dc=example,dc=com
   * **Password**: The password for the bind DN.
   * **Batch Size**: Number of user records to retrieve per API page (default: `500`).
   * **Interval**: How frequently to poll for new data (default: `24h`).
4. If using a self-signed SSL certificate, configure the SSL settings under **Advanced options**.
5. Select **Save and continue** to save the integration.
6. Add the integration to an existing Agent policy or create a new one.
7. Verify that user records are being ingested into Elasticsearch.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **PingDirectory**.
3. Open the **[CEL PingDirectory] User** dashboard.
4. Verify that the visualizations are populated with user identity data, including usernames, email addresses, and account types.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **PingDirectory**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for the `user` data stream to provide a view of the most recent user identity data. Use the destination alias from the table below to access the latest data for dashboards, rules, and other Elastic features.

Destination indices are aliased to `logs-ping_directory_latest.<data_stream_name>`.

| Source Data Stream | Destination Index Pattern | Destination Alias |
|-------------------|---------------------------|-------------------|
| `logs-ping_directory.user-*` | `logs-ping_directory_latest.dest_user-1` | `logs-ping_directory_latest.user` |

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

* No data collected: Verify that the PingDirectory SCIM v2 API is enabled and reachable from the Elastic Agent host. Confirm that the configured URL, bind DN, and password are correct.
* Authentication failures: Ensure the bind DN has permission to authenticate via `/directory/v1/authenticate` and read from `/scim/v2/Users`.
* SSL certificate errors: If PingDirectory uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* Token expiry: The integration automatically re-authenticates when the access token expires. If repeated auth failures occur, verify the bind DN password has not changed.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

#### Vendor documentation links

- [Configuring SCIM 2.0 on your server](https://docs.pingidentity.com/pingdirectory/9.3/pingdirectory_server_administration_guide/pd_ds_config_scim_2_server.html)
- [PingDirectory Directory REST API Getting Started](https://developer.pingidentity.com/pingdirectory/directory/getting-started.html)
- [PingDirectory REST API Authentication](https://developer.pingidentity.com/pingdirectory/directory/authentication.html)
- [SCIM 2.0 Users API](https://developer.pingidentity.com/pingdirectory/directory-proxy-scim/overview.html)
- [SCIM 2.0 Groups API](https://developer.pingidentity.com/pingdirectory/directory-proxy-scim/user-profile-endpoints/get-read-search-group-members-display-name.html)

### User

The `user` data stream provides user identity records collected from PingDirectory.

#### user fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| ping_directory.user.display_name | Display name of the user. Maps to LDAP cn. | keyword |
| ping_directory.user.email.primary | Indicates whether the email marked as primary (from IT API or derived from SCIM). | boolean |
| ping_directory.user.email.type | Type of email address from IT. | keyword |
| ping_directory.user.meta.created | Timestamp when the user entry was created. | date |
| ping_directory.user.meta.last_modified | Timestamp when the user entry was last modified. | date |
| ping_directory.user.meta.location | Self-link URL of the user resource. | keyword |
| ping_directory.user.meta.resource_type | Always User. Identifies the SCIM resource type. | keyword |
| ping_directory.user.name.family_name | Last name. Maps to LDAP sn. | keyword |
| ping_directory.user.name.given_name | First name. Maps to LDAP givenName. | keyword |
| ping_directory.user.schemas | SCIM schema URNs for the user resource. | keyword |
| ping_directory.user.title | Job title. Maps to LDAP title. | keyword |
| ping_directory.user.user_type | Employment type. Maps to LDAP employeeType. | keyword |


An example event for `user` looks as following:

```json
{
    "@timestamp": "2026-06-17T11:10:47.618Z",
    "agent": {
        "ephemeral_id": "c54df385-2d0f-45a9-a0db-7aedc6fc12b4",
        "id": "7bd99e76-3220-4518-bec1-0284ece07762",
        "name": "elastic-agent-62922",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ping_directory.user",
        "namespace": "19448",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "7bd99e76-3220-4518-bec1-0284ece07762",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "ping_directory.user",
        "ingested": "2026-06-17T11:10:50Z",
        "kind": "event",
        "original": "{\"displayName\":\"John Doe\",\"emails\":[\"john.doe@example.com\"],\"id\":\"c9bbce6c-7d77-4d93-b674-42b1e8a00606\",\"meta\":{\"location\":\"https://10.50.15.29:2443/scim/v2/Users/c9bbce6c-7d77-4d93-b674-42b1e8a00606\",\"resourceType\":\"User\"},\"name\":{\"familyName\":\"Doe\",\"formatted\":\"John Doe\",\"givenName\":\"John\"},\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\",\"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\"],\"title\":\"DevOps Engineer\",\"userName\":\"john.doe\",\"userType\":\"Full-Time\"}",
        "type": [
            "user"
        ]
    },
    "input": {
        "type": "cel"
    },
    "ping_directory": {
        "user": {
            "display_name": "John Doe",
            "meta": {
                "location": "https://10.50.15.29:2443/scim/v2/Users/c9bbce6c-7d77-4d93-b674-42b1e8a00606",
                "resource_type": "User"
            },
            "name": {
                "family_name": "Doe",
                "given_name": "John"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
            ],
            "title": "DevOps Engineer",
            "user_type": "Full-Time"
        }
    },
    "related": {
        "user": [
            "John Doe",
            "c9bbce6c-7d77-4d93-b674-42b1e8a00606",
            "Doe",
            "John",
            "john.doe@example.com",
            "example.com",
            "john.doe"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ping_directory-user"
    ],
    "user": {
        "domain": "example.com",
        "email": "john.doe@example.com",
        "full_name": "John Doe",
        "id": "c9bbce6c-7d77-4d93-b674-42b1e8a00606",
        "name": "john.doe"
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

These PingDirectory REST API endpoints are used by this integration:

| Endpoint | Method | Data stream | Description |
|---|---|---|---|
| `/directory/v1/authenticate` | POST | user | Authenticate with bind DN and password to obtain an access token |
| `/scim/v2/Users` | GET | user | Retrieve paginated user identity records |

### ILM Policy

To facilitate user identity data, the source data stream-backed index `.ds-logs-ping_directory.user-*` is allowed to contain duplicates from each polling interval. The ILM policy `logs-ping_directory.user-default_policy` is added to this source index so it doesn't lead to unbounded growth. This means that in this source index data will be deleted after `30 days` from ingested date.
