# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. Its product event log records every product operation carried out on a managed endpoint — installs, uninstalls, updates, AMCore content changes, property collection, and policy enforcement — together with the initiating account, the affected product, and the resulting error code, providing visibility into **endpoint product deployment and policy enforcement activity**.

The Trellix ePO On-Prem integration for Elastic collects product event records using the **Web API** via CEL input, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO Web API at configurable intervals. It retrieves product event records from the `EPOProductEvents` table using a time-based cursor on `ReceivedUTC`: each poll requests records at or after the last persisted timestamp, orders results ascending by `ReceivedUTC`, and persists the latest timestamp returned for the next poll. The cursor boundary is intentionally inclusive, so a record received exactly at the boundary timestamp can be returned again on the next poll. The ingest pipeline derives the document `_id` from `EPOProductEvents.AutoID`, so any record redelivered at that boundary overwrites its earlier copy instead of creating a duplicate.

When a poll returns a full page of records, the integration immediately requests the next page within the same interval, up to the configured **Maximum Pages Per Interval**.

Each record is ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `product_event` | Trellix ePO product event records, including the operation type and initiator, the affected product code, the managed endpoint's agent GUID, hostname and IP address, the acting user account, and the source event code, severity and error code, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO product event records with Elastic provides visibility into product lifecycle activity across managed endpoints — which products were installed, updated, or removed, on which hosts, by which accounts, and whether each operation succeeded. Failed operations are normalized to `event.outcome: failure` with the source code preserved in `error.code`, enabling deployment failure monitoring, rollout tracking, policy enforcement auditing, and correlation of product changes with endpoint inventory and security events within Kibana dashboards.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with Web API support enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `EPOProductEvents` table.
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
   - Set **Username** for the ePO user account with `EPOProductEvents` query permissions.
   - Set **Password** for the ePO user account.
   - Set **Initial Interval** to how far back to pull product event records on the first run, for example `24h`.
   - Set **Interval** to the duration between product event collection requests. The default is `5m`.
   - Set **Maximum Pages Per Interval** to the maximum number of pages collected at each interval. The default is `1000`.
   - Set **Page Size** to the number of product event records fetched per API request. The default is `500`.
   - Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.

6. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `EPOProductEvents` table, and that the **Trellix ePO Product Event Logs** stream is enabled.
* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the `EPOProductEvents` table.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all `EPOProductEvents` columns queried by the integration.
* **Pagination or duplicate records**: If product event records are not advancing, verify that `ReceivedUTC` values are increasing in the source table and that the persisted timestamp cursor is being correctly updated between polls. A small amount of overlap at the poll boundary is expected; records redelivered at the boundary are deduplicated by document `_id`.
* **Events not categorized**: `event.action`, `event.category`, and `event.type` are derived from `EPOProductEvents.Type`. A source value outside the recognized set (`Install`, `Uninstall`, `Update`, `AMCore`, `Property Collection`, `Policy Enforcement`) leaves these fields unset while the rest of the event is still ingested.
* **SSL certificate errors**: If your Trellix ePO server uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Network connectivity issues**: Verify firewall rules allow outbound HTTPS traffic from the Elastic Agent host to the Trellix ePO server on the configured port.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify that the dashboard is listed.
3. Open the **[Logs Trellix ePO On-Prem] Product Event** dashboard and verify that Product Event data is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links

- [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html)
- [Trellix ePO Web API Query Language](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-cd01321d-b19b-5095-c79b-eabc7c0726bb.html)
- [Trellix ePO 5.10.0 Product Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-3946078c-6e32-df76-6296-216ee05a2176.html)

### Product Event

The `product_event` data stream provides Trellix ePO On-Prem product event logs collected from the Web API.

#### Product Event fields

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
| trellix_epo_on_prem.product_event.epo_product_events.extra_dat_names | Additional DAT names associated with the endpoint product event. | keyword |
| trellix_epo_on_prem.product_event.epo_product_events.initiator_id | Source identifier describing what initiated the product operation. | keyword |
| trellix_epo_on_prem.product_event.epo_product_events.initiator_type | Source classification of the product-operation initiator. | keyword |
| trellix_epo_on_prem.product_event.epo_product_events.locale | Numeric locale identifier associated with the product event. | long |
| trellix_epo_on_prem.product_event.epo_product_events.node_id | Numeric ePO node identifier associated with the endpoint. | long |
| trellix_epo_on_prem.product_event.epo_product_events.site_name | ePO site name associated with the product event. | keyword |
| trellix_epo_on_prem.product_event.epo_product_events.sp_hot_fix | Service-pack hotfix value associated with the product event. | keyword |
| trellix_epo_on_prem.product_event.epo_product_events.tenant_id | Numeric tenant identifier associated with the product event. | long |


### Example event

#### Product Event

An example event for `product_event` looks as following:

```json
{
    "@timestamp": "2026-07-21T09:23:20.000Z",
    "agent": {
        "ephemeral_id": "0690fcde-9a15-4bcc-905e-73ed66b4dc1f",
        "id": "94a75512-d576-4f6e-867a-32ca9749ed8d",
        "name": "elastic-agent-34651",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.product_event",
        "namespace": "97914",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "94a75512-d576-4f6e-867a-32ca9749ed8d",
        "snapshot": false,
        "version": "8.19.0"
    },
    "entity": {
        "id": "89A1D5C1-2B3E-4F67-8A9B-0C1D2E3F4A5B",
        "name": "DESKTOP-K3QM7XP",
        "type": [
            "host"
        ]
    },
    "event": {
        "action": "install",
        "agent_id_status": "verified",
        "category": [
            "package"
        ],
        "code": "2411",
        "created": "2026-07-21T09:23:47.000Z",
        "dataset": "trellix_epo_on_prem.product_event",
        "id": "1",
        "ingested": "2026-08-04T13:02:03Z",
        "kind": "event",
        "original": "{\"EPOProductEvents.AgentGUID\":\"89A1D5C1-2B3E-4F67-8A9B-0C1D2E3F4A5B\",\"EPOProductEvents.AutoID\":1,\"EPOProductEvents.DetectedUTC\":\"2026-07-21T14:53:20+05:30\",\"EPOProductEvents.Error\":0,\"EPOProductEvents.ExtraDATNames\":null,\"EPOProductEvents.HostName\":\"DESKTOP-K3QM7XP\",\"EPOProductEvents.IPV6\":\"2001:DB8:85A3:0:8A2E:370:7334:1\",\"EPOProductEvents.InitiatorID\":null,\"EPOProductEvents.InitiatorType\":\"CommandLine\",\"EPOProductEvents.Locale\":1033,\"EPOProductEvents.NodeID\":1,\"EPOProductEvents.ProductCode\":\"EPOAGENT3000\",\"EPOProductEvents.ReceivedUTC\":\"2026-07-21T14:53:47+05:30\",\"EPOProductEvents.SPHotFix\":null,\"EPOProductEvents.SiteName\":null,\"EPOProductEvents.TVDEventID\":2411,\"EPOProductEvents.TVDSeverity\":0,\"EPOProductEvents.TenantId\":1,\"EPOProductEvents.Type\":\"Install\",\"EPOProductEvents.UserName\":\"SYSTEM\"}",
        "outcome": "success",
        "severity": 0,
        "type": [
            "installation"
        ]
    },
    "host": {
        "hostname": "DESKTOP-K3QM7XP",
        "id": "89A1D5C1-2B3E-4F67-8A9B-0C1D2E3F4A5B",
        "ip": [
            "2001:DB8:85A3:0:8A2E:370:7334:1"
        ],
        "name": "DESKTOP-K3QM7XP"
    },
    "input": {
        "type": "cel"
    },
    "package": {
        "name": "EPOAGENT3000"
    },
    "related": {
        "hosts": [
            "89A1D5C1-2B3E-4F67-8A9B-0C1D2E3F4A5B",
            "DESKTOP-K3QM7XP"
        ],
        "ip": [
            "2001:DB8:85A3:0:8A2E:370:7334:1"
        ],
        "user": [
            "SYSTEM"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-product_event"
    ],
    "trellix_epo_on_prem": {
        "product_event": {
            "epo_product_events": {
                "initiator_type": "CommandLine",
                "locale": 1033,
                "node_id": 1,
                "tenant_id": 1
            }
        }
    },
    "user": {
        "name": "SYSTEM"
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

* **Product Event**: Collects product event records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `EPOProductEvents` table using a time-based cursor on the `ReceivedUTC` field, with results ordered ascending so the cursor advances monotonically across polls.
