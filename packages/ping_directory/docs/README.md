# PingDirectory Integration

## Overview

[PingDirectory](https://www.pingidentity.com/en/product/pingdirectory.html) is an **enterprise-grade LDAP directory server** and identity data store. It provides high-performance, scalable directory services for managing user identities, credentials, and access control across hybrid environments — combining authentication, authorization, and directory data management into a unified platform for **critical identity infrastructure**.

This integration collects group membership data from PingDirectory via the SCIM v2 API using the Elastic Agent CEL input. It provides visibility into group accounts and membership attributes managed within your PingDirectory environment.

### Compatibility

The PingDirectory integration is compatible with **PingDirectory version 11.0.0.2 and above**.

### How it works

The integration uses the Elastic Agent CEL input to collect group data from the PingDirectory SCIM v2 API. Each collection cycle:

1. Authenticates against the PingDirectory REST API (`/directory/v1/authenticate`) using the configured `bind_dn` and `password` to obtain a short-lived access token.
2. Paginates through all groups via the SCIM v2 Groups endpoint (`/scim/v2/Groups`) using the configured batch size.
3. Emits each group record as an individual event for ingestion and enrichment via the built-in ingest pipeline.
4. Caches the access token across collection cycles and re-authenticates automatically when the token expires.

## What data does this integration collect?

The PingDirectory integration collects the following types of data:

| Data stream | Description | Endpoint |
|---|---|---|
| `group` | Group membership records retrieved from the PingDirectory SCIM v2 API, including group names, display names, members, and group metadata. | `/scim/v2/Groups` |

### Supported use cases

* **Group inventory and membership visibility**: Track all groups managed in PingDirectory, including their members, display names, and group types.

* **Identity data enrichment**: Correlate PingDirectory group records with other security and operational data in Elastic for unified identity context.

## What do I need to use this integration?

### From PingDirectory

* **PingDirectory deployment**: An active PingDirectory server with the SCIM v2 API enabled and accessible.
* **Service account credentials**: A bind DN (`bind_dn`) and password with sufficient permissions to authenticate via `/directory/v1/authenticate` and read groups from `/scim/v2/Groups`.
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

Before configuring the integration, ensure that a PingDirectory account is available for API authentication and group retrieval.

1. Create or identify a service account in PingDirectory.
2. Grant the account permission to:

   * Authenticate through the `/directory/v1/authenticate` endpoint.
   * Read group records through the `/scim/v2/Groups` endpoint.

3. Record the account's bind DN and password. These values are required when configuring the integration in Kibana.
4. Verify that the SCIM v2 API is enabled and accessible from the Elastic Agent host.
5. If HTTPS is configured with a self-signed certificate, export the certificate so it can be trusted by Elastic Agent.

Refer to the PingDirectory documentation for configuring SCIM 2.0 and authentication requirements.

### Configure

1. In Kibana, navigate to **Fleet → Integrations** and search for **PingDirectory**.
2. Click **Add PingDirectory**.
3. Configure the integration settings:

   * **URL**: The base URL of your PingDirectory instance, for example:
     `https://pingdirectory.example.com:2443`
   * **Bind DN**: The distinguished name used to authenticate, for example:
     `cn=admin,dc=example,dc=com`
   * **Password**: The password for the bind DN.
   * **Batch Size**: Number of group records to retrieve per API page (default: `500`).
   * **Interval**: How frequently to poll for new data (default: `24h`).
4. If using a self-signed SSL certificate, configure the SSL settings under **Advanced options**.
5. Select **Save and continue** to save the integration.
6. Add the integration to an existing Agent policy or create a new one.
7. Verify that group records are being ingested into Elasticsearch.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **PingDirectory**.
3. Open the **[Logs PingDirectory] Group** dashboard.
4. Verify that the visualizations are populated with group membership data, including group names, members, and membership counts.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

* **No data collected**: Verify that the PingDirectory SCIM v2 API is enabled and reachable from the Elastic Agent host. Confirm that the configured URL, bind DN, and password are correct.
* **Authentication failures**: Ensure the bind DN has permission to authenticate via `/directory/v1/authenticate` and read from `/scim/v2/Groups`.
* **SSL certificate errors**: If PingDirectory uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Token expiry**: The integration automatically re-authenticates when the access token expires. If repeated auth failures occur, verify the bind DN password has not changed.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

#### Vendor documentation links

- [Configuring SCIM 2.0 on your server](https://docs.pingidentity.com/pingdirectory/9.3/pingdirectory_server_administration_guide/pd_ds_config_scim_2_server.html)
- [PingDirectory Directory REST API Getting Started](https://developer.pingidentity.com/pingdirectory/directory/getting-started.html)
- [PingDirectory REST API Authentication](https://developer.pingidentity.com/pingdirectory/directory/authentication.html)
- [SCIM 2.0 Users API](https://developer.pingidentity.com/pingdirectory/directory-proxy-scim/overview.html)
- [SCIM 2.0 Groups API](https://developer.pingidentity.com/pingdirectory/directory-proxy-scim/user-profile-endpoints/get-read-search-group-members-display-name.html)

### Group

The `group` data stream provides group membership records collected from PingDirectory.

#### group fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date and time when the event occurred. | date |
| data_stream.dataset | Name of the dataset associated with the event. | constant_keyword |
| data_stream.namespace | Namespace for the data stream. | constant_keyword |
| data_stream.type | Type of data stream. | constant_keyword |
| event.dataset | Dataset name for events collected from PingDirectory group records. | constant_keyword |
| event.module | Module name for PingDirectory events. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | Product name of the observer that generated the event. | constant_keyword |
| observer.vendor | Vendor name of the observer that generated the event. | constant_keyword |
| ping_directory.group.members_metadata | Member DN metadata with uid removed (ou and dc components only). | keyword |
| ping_directory.group.meta.location | Self-link URL of the group resource. | keyword |
| ping_directory.group.meta.resource_type | Always Group. Identifies the SCIM resource type. | keyword |
| ping_directory.group.schemas | SCIM schema URN for the group resource. | keyword |


An example event for `group` looks as following:

```json
{
    "@timestamp": "2026-06-23T05:26:00.102Z",
    "agent": {
        "ephemeral_id": "9deb4381-f13b-460f-a113-d50474f421d6",
        "id": "b8e1b118-3146-4215-8504-c18df1838432",
        "name": "elastic-agent-98118",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ping_directory.group",
        "namespace": "73116",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "elastic_agent": {
        "id": "b8e1b118-3146-4215-8504-c18df1838432",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "ping_directory.group",
        "ingested": "2026-06-23T05:26:03Z",
        "kind": "event",
        "original": "{\"displayName\":\"security\",\"id\":\"a7631f14-c7eb-490f-8b94-724b78241e13\",\"members\":[\"uid=alice.smith,ou=People,dc=example,dc=com\"],\"meta\":{\"location\":\"https://10.50.15.29:2443/scim/v2/Groups/a7631f14-c7eb-490f-8b94-724b78241e13\",\"resourceType\":\"Group\"},\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"]}",
        "type": [
            "group"
        ]
    },
    "group": {
        "id": "a7631f14-c7eb-490f-8b94-724b78241e13",
        "name": "security"
    },
    "input": {
        "type": "cel"
    },
    "ping_directory": {
        "group": {
            "members_metadata": "ou=People,dc=example,dc=com",
            "meta": {
                "location": "https://10.50.15.29:2443/scim/v2/Groups/a7631f14-c7eb-490f-8b94-724b78241e13",
                "resource_type": "Group"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:Group"
            ]
        }
    },
    "related": {
        "user": [
            "alice.smith"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ping_directory-group"
    ],
    "user": {
        "id": "alice.smith"
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
| `/directory/v1/authenticate` | POST | group | Authenticate with bind DN and password to obtain an access token |
| `/scim/v2/Groups` | GET | group | Retrieve paginated group membership records |