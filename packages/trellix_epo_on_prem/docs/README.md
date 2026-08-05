# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. Its System Tree tracks every managed endpoint — agent identity and version, communication and managed state, tenant and tag assignment — providing visibility into **managed-endpoint inventory and agent health**.

The Trellix ePO On-Prem integration for Elastic collects managed system (endpoint) records using the **Web API** via CEL input, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO Web API at configurable intervals. It retrieves managed system records from the `EPOLeafNode` table using a time-based cursor on `LastUpdate`: each poll requests records at or after the last persisted timestamp, orders results ascending by `LastUpdate`, and persists the latest timestamp returned for the next poll. The cursor boundary is intentionally inclusive on both ends, so a record updated exactly at the boundary timestamp can be returned again on the next poll.

Each record is ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `system` | Trellix ePO managed system (endpoint) records, including node name, path, and type; agent GUID and version; managed and communication state; and tenant, tag, and sequence metadata, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO managed system records with Elastic provides visibility into the endpoints under ePO management — agent version and communication health, managed state, and tag-based grouping — enabling asset inventory tracking, agent health monitoring, and reporting on managed-endpoint posture within Kibana dashboards.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with Web API support enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `EPOLeafNode` table.
   - Sufficient role permissions to execute queries through the Web API.
3. **API credentials**: Username and password for HTTP Basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
5. **Network access**: The Elastic Agent must have outbound HTTPS access to the ePO server.

For more information on configuring Web API access in Trellix ePO, refer to the [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Trellix ePO On-Prem**.
3. Select the **Trellix ePO On-Prem** integration from the search results.
4. Select **Add Trellix ePO On-Prem** to add the integration.
5. Enable and configure the **Collect Trellix ePO Logs** input.

   - Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
   - Set **Username** for the ePO user account with `EPOLeafNode` query permissions.
   - Set **Password** for the ePO user account.
   - Set **Initial Interval** to how far back to pull managed system records on the first run, for example `24h`.
   - Set **Interval** to the duration between system-record collection requests. The default is `5m`.
   - Set **Maximum Pages Per Interval** to the maximum number of pages collected at each interval. The default is `1000`.
   - Set **Page Size** to the number of system records fetched per API request. The default is `500`.
   - Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.   

7. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `EPOLeafNode` table, and that the **Trellix ePO System Logs** stream is enabled.
* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the `EPOLeafNode` table.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all `EPOLeafNode` columns queried by the integration.
* **Pagination or duplicate records**: If system records are not advancing, verify that `LastUpdate` values are increasing in the source table and that the persisted timestamp cursor is being correctly updated between polls. A small amount of overlap at the poll boundary is expected, so the same record may occasionally be delivered more than once.
* **SSL certificate errors**: If your Trellix ePO server uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Network connectivity issues**: Verify firewall rules allow outbound HTTPS traffic from the Elastic Agent host to the Trellix ePO server on the configured port.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify that the dashboard is listed.
3. Open the **[Logs Trellix ePO On-Prem] System** dashboard and verify that System data is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links

- [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html)
- [Trellix ePO Web API Query Language](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-cd01321d-b19b-5095-c79b-eabc7c0726bb.html)
- [Trellix ePO 5.10.0 Product Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-3946078c-6e32-df76-6296-216ee05a2176.html)

### System

The `system` data stream provides Trellix ePO On-Prem managed system (endpoint) records collected from the Web API.

#### System fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date and time when the event occurred. | date |
| data_stream.dataset | Dataset name associated with the data stream. | constant_keyword |
| data_stream.namespace | Namespace used to group related data streams. | constant_keyword |
| data_stream.type | Type of data stream, such as logs or metrics. | constant_keyword |
| event.dataset | Event Dataset. | constant_keyword |
| event.module | Module that generated the event. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | Product name of the observer that generated the event. | constant_keyword |
| observer.vendor | Vendor name of the observer that generated the event. | constant_keyword |
| trellix_epo_on_prem.system.epo_leaf_node.agent_version | Version string of the managed Trellix agent installed on the system. | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.excluded_tags | Comma-separated tags excluded from the managed system node.' | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.last_comm_secure | Source code indicating whether the system’s last communication was secure. | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.managed_state | Numeric managed-state code associated with the system node. | long |
| trellix_epo_on_prem.system.epo_leaf_node.node_path | Hierarchical path of the managed system node. | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.parent_id | Numeric identifier of the parent object in the ePO system hierarchy. | long |
| trellix_epo_on_prem.system.epo_leaf_node.sequence_error_count | Number of sequence errors recorded for the managed system node. | long |
| trellix_epo_on_prem.system.epo_leaf_node.sequence_error_count_last_update | Date and time when the sequence-error count was last updated. | date |
| trellix_epo_on_prem.system.epo_leaf_node.server_key_hash | Base64-encoded cryptographic hash associated with the ePO server key. | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.tenant_id | Numeric tenant identifier associated with the system node. | long |
| trellix_epo_on_prem.system.epo_leaf_node.transfer_site_lists_id | Boolean flag associated with transferring site-list identifiers for the system node. | boolean |
| trellix_epo_on_prem.system.epo_leaf_node.type | Numeric type code assigned to the managed system node. | long |


### Example event

#### System

An example event for `system` looks as following:

```json
{
    "@timestamp": "2026-08-03T12:31:28+05:30",
    "agent": {
        "ephemeral_id": "67d65743-fd56-4ec5-bf71-4a7ac7e3f10f",
        "id": "045adaa8-986a-4ee3-bde2-b65205edb1bd",
        "name": "elastic-agent-15521",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.system",
        "namespace": "56381",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "045adaa8-986a-4ee3-bde2-b65205edb1bd",
        "snapshot": false,
        "version": "8.19.0"
    },
    "entity": {
        "id": "65E387D4-DD78-406F-9765-2A3AAC1DF958",
        "name": "DESKTOP-B9TTHQE",
        "type": [
            "host"
        ]
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "trellix_epo_on_prem.system",
        "id": "3",
        "ingested": "2026-08-04T09:10:46Z",
        "kind": "asset",
        "original": "{\"EPOLeafNode.AgentGUID\":\"65E387D4-DD78-406F-9765-2A3AAC1DF958\",\"EPOLeafNode.AgentVersion\":\"5.8.6.185\",\"EPOLeafNode.AutoID\":3,\"EPOLeafNode.ExcludedTags\":\"\",\"EPOLeafNode.LastCommSecure\":\"1\",\"EPOLeafNode.LastUpdate\":\"2026-08-03T12:31:28+05:30\",\"EPOLeafNode.ManagedState\":1,\"EPOLeafNode.NodeName\":\"DESKTOP-B9TTHQE\",\"EPOLeafNode.NodePath\":null,\"EPOLeafNode.ParentID\":2,\"EPOLeafNode.SequenceErrorCount\":0,\"EPOLeafNode.SequenceErrorCountLastUpdate\":null,\"EPOLeafNode.ServerKeyHash\":\"zCpCbtDGJO5y9CB7kjIW+lY9lEPxhJhunES4S5Aayao=\",\"EPOLeafNode.Tags\":\"Escalated, Workstation\",\"EPOLeafNode.TenantId\":1,\"EPOLeafNode.TransferSiteListsID\":false,\"EPOLeafNode.Type\":1}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "DESKTOP-B9TTHQE",
        "id": "65E387D4-DD78-406F-9765-2A3AAC1DF958",
        "name": "DESKTOP-B9TTHQE"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "zCpCbtDGJO5y9CB7kjIW+lY9lEPxhJhunES4S5Aayao="
        ],
        "hosts": [
            "65E387D4-DD78-406F-9765-2A3AAC1DF958",
            "DESKTOP-B9TTHQE"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-system",
        "Escalated, Workstation"
    ],
    "trellix_epo_on_prem": {
        "system": {
            "epo_leaf_node": {
                "agent_version": "5.8.6.185",
                "last_comm_secure": "1",
                "managed_state": 1,
                "parent_id": 2,
                "sequence_error_count": 0,
                "server_key_hash": "zCpCbtDGJO5y9CB7kjIW+lY9lEPxhJhunES4S5Aayao=",
                "tenant_id": 1,
                "transfer_site_lists_id": false,
                "type": 1
            }
        }
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

- **System**: Collects managed system (endpoint) records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried from `EPOLeafNode` using a time-based cursor with `LastUpdate`.
