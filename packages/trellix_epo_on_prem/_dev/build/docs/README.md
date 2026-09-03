# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. It offers comprehensive audit logging for system administration, user activity, policy changes, and security-related actions; its Web Control component logs web browsing activity together with content and reputation ratings applied to each visited URL; its System Tree maintains a record of every managed endpoint — agent identity and version, communication and managed state, node path, and tenant and tag assignment; and its compliance history reporting captures point-in-time snapshots of how many managed computers are compliant with policy and how that posture changes over time — combining authentication, authorization, detailed audit trails, web usage monitoring, endpoint inventory, agent health, and historical compliance measurement into a unified platform for **critical security infrastructure monitoring and compliance**.

The Trellix ePO On-Prem integration for Elastic collects audit logs, web control logs, endpoint compliance history records, and managed system (endpoint) records using the **REST / Web API** via CEL input, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with REST API / Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO REST / Web API at configurable intervals. It retrieves audit log records from the `OrionAuditLog` table using keyset-based pagination with cursor timestamps, and web control event records from the `WP_EventInfo` table using a keyset cursor on the numeric `EventAutoID` field (because `WP_EventInfo` has no timestamp column). Each poll for web control requests events with `EventAutoID` greater than the last persisted value, orders results ascending by `EventAutoID`, and persists the highest `EventAutoID` returned for the next poll.

It retrieves compliance history records from the `EpoComplianceHistory` table using an inclusive, ascending cursor on `TheTimestamp`, and managed system records from the `EPOLeafNode` table using an inclusive, ascending cursor on `LastUpdate`. Because ePO returns `LastUpdate` with the server's UTC offset while interpreting a bare timestamp in a query as UTC, the system cursor is adjusted by the configured **Timezone Offset** so records are not skipped or re-read on every poll. Overlapping records at each cursor boundary are deduplicated by the ingest pipeline.

Each event is mapped to Elastic Common Schema (ECS) for standardized field naming and ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `audit` | Trellix ePO audit log records, including system administration, policy changes, user activity, and security-related actions retrieved from the ePO REST API. | `/remote/core.executeQuery` API |
| `web_control` | Trellix ePO web control event records, including browsed URLs, user names, content/category ratings (phishing, spam, download, exploit, bad-link, pop-up), overall rating, list/reason/action identifiers, and per-event counts, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `compliance_history` | Trellix ePO compliance history records, including the originating chart and reporting task name, evaluated computer counts, compliant and noncompliant counts and percentages, and snapshot timestamp, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `system` | Trellix ePO managed system (endpoint) records, including node name, path, and type; agent GUID and version; managed and communication state; and tenant, tag, and sequence metadata, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO with Elastic provides centralized visibility into system administration, user activity, and policy changes across your ePO deployment, enabling efficient audit trail monitoring, compliance reporting, and security investigation within Kibana dashboards.

Integrating Trellix ePO Web Control with Elastic provides centralized visibility into user web browsing activity and the ratings/categories Web Control applies to that traffic, enabling web usage monitoring, threat and risk investigation (phishing, spam, exploit, malicious downloads), and policy-violation reporting within Kibana dashboards.

Integrating Trellix ePO compliance history with Elastic provides centralized visibility into how endpoint policy compliance changes over time, enabling trend analysis of compliant and noncompliant computer counts, comparison of compliance percentages across reporting tasks, detection of gaps in compliance reporting, and compliance reporting and alerting within Kibana dashboards.

Integrating Trellix ePO managed system records with Elastic provides centralized visibility into the endpoints under ePO management — agent version and communication health, managed state, node placement in the System Tree, and tag-based grouping — enabling asset inventory tracking, agent health and coverage monitoring, and investigation of unmanaged or stale endpoints within Kibana dashboards.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the REST / Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with REST API / Web API enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `OrionAuditLog` table (or `OrionAuditLogMT` for multitenant deployments), the `WP_EventInfo` table, the `EpoComplianceHistory` table, and/or the `EPOLeafNode` table.
   - Sufficient role permissions to execute queries via the Web API.
3. **API credentials**: Username and password for basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server (default port: 8443, for example `https://epo.example.com:8443`).
5. **Network access**: The Elastic Agent must have outbound HTTPS access to the ePO server.
6. **Compliance history data**: To collect the `compliance_history` data stream, the Trellix ePO compliance history reporting task must be configured and producing records.

For more information on configuring REST API access in Trellix ePO, refer to the [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html).

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
5. Enable and configure the collection methods you need:

    * For **audit** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set the **Username** for the ePO user account with audit log query permissions.
        * Set the **Password** for the ePO user account.
        * Set **Initial Interval** to the lookback period for the first API request. The default is `24h`.
        * Set **Page Size** to the number of audit log records to retrieve per API request. The default is `500`.
        * Optionally adjust **Interval**, **HTTP Client Timeout**, proxy, and SSL settings.
    * For **web control** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `WP_EventInfo` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Event Auto Id** to the starting `EventAutoID` from which to begin querying events. Subsequent collections resume from the last persisted `EventAutoID`. Set to `0` to start from the beginning (default: `0`).
        * Set **Interval** to the polling frequency. The default is `24h`.
        * Set **Page Size** to the number of web control log records to retrieve per API request. The default is `500`.
        * Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.
    * For **compliance history** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set the **Username** for the ePO user account with `EpoComplianceHistory` query permissions.
        * Set the **Password** for the ePO user account.
        * Set **Initial Interval** to the historical lookback used on the first request. The default is `24h`.
        * Set **Interval** to the polling frequency. The default is `24h`.
        * Set **Page Size** to the number of compliance history records to retrieve per API request. The default is `500`.
        * Optionally adjust **Maximum Pages Per Interval**, **HTTP Client Timeout**, proxy, and SSL settings.
    * For **system** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `EPOLeafNode` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Interval** to how far back to pull managed system records on the first run. Subsequent collections resume from the last persisted `LastUpdate` timestamp (default: `24h`).
        * Set **Interval** to the polling frequency. The default is `5m`.
        * Set **Timezone Offset** to the UTC offset of the ePO server, for example `+05:30`, so cursor timestamps are interpreted correctly.
        * Set **Page Size** to the number of system records to retrieve per API request. The default is `500`.
        * Optionally adjust **Maximum Pages Per Interval**, **HTTP Client Timeout**, proxy, and SSL settings.

6. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `OrionAuditLog`, `WP_EventInfo`, `EpoComplianceHistory`, and/or `EPOLeafNode` tables, and that the required data stream is enabled. For compliance history, use the local target `EpoComplianceHistory`; do not use the rollup target unless a rollup database is configured.
* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the required tables.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all fields configured in the integration (select clause in the CEL template).
* **Pagination issues (audit)**: If audit logs are not advancing beyond the initial set, verify that the `StartTime` field is present in all returned records and that pagination timestamps are being correctly updated.
* **Pagination issues (web control)**: If web control logs are not advancing beyond the initial set, verify that `EventAutoID` values are strictly increasing in the source table and that the persisted `EventAutoID` cursor is being correctly updated between polls.
* **Pagination issues (compliance history)**: If compliance history records are not advancing beyond the initial set, verify that every returned record includes `TheTimestamp` and that ePO permits filtering and ordering on this field.
* **Pagination issues (system)**: If system records are not advancing beyond the initial set, verify that the `LastUpdate` field is present in all returned records, that `LastUpdate` values are increasing in the source table, and that the persisted timestamp cursor is being correctly updated between polls. Also confirm that **Timezone Offset** matches the ePO server's UTC offset — an incorrect offset can cause the cursor to skip past unread records or re-read the same window on every poll.
* **SSL certificate errors**: If your Trellix ePO server uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Network connectivity issues**: Verify firewall rules allow outbound HTTPS traffic from the Elastic Agent host to the Trellix ePO server on the configured port.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify the dashboard information is populated.
3. Open the **[Logs Trellix ePO On-Prem] Audit** dashboard to verify audit event data is being collected.
4. Open the **[Logs Trellix ePO On-Prem] Web Control** dashboard and verify that Web Control data is populated.
5. Open the **[Logs Trellix ePO On-Prem] System** dashboard and verify that managed system data is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links

- [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html)
- [Trellix ePO Web API Query Language](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-cd01321d-b19b-5095-c79b-eabc7c0726bb.html)
- [Trellix ePO 5.10.0 Product Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-3946078c-6e32-df76-6296-216ee05a2176.html)

### Audit

The `audit` data stream provides Trellix ePO On-Prem audit logs collected from the REST API.

#### Audit fields

{{ fields "audit" }}

### Example event

#### Audit

{{ event "audit" }}

### Web Control

The `web_control` data stream provides Trellix ePO On-Prem web control logs collected from the Web API.

#### Web Control fields

{{ fields "web_control" }}

### Example event

#### Web Control

{{ event "web_control" }}

### Compliance history

The `compliance_history` data stream provides Trellix ePO On-Prem compliance history logs collected from the Web API.

#### Compliance history fields

{{ fields "compliance_history" }}

### Example event

#### Compliance history

{{ event "compliance_history" }}

### System

The `system` data stream provides Trellix ePO On-Prem managed system (endpoint) logs collected from the Web API.

#### System fields

{{ fields "system" }}

### Example event

#### System

{{ event "system" }}

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

* **Audit**: Collects audit log records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `OrionAuditLog` table using keyset-based pagination with the `StartTime` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Web Control**: Collects web control event records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `WP_EventInfo` table using keyset-based pagination with the `EventAutoID` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Compliance history**: Collects compliance history records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `EpoComplianceHistory` table using keyset-based pagination with the `TheTimestamp` field as a cursor to ensure efficient and non-duplicating retrieval.
* **System**: Collects managed system (endpoint) records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `EPOLeafNode` table using keyset-based pagination with the `LastUpdate` field as a cursor to ensure efficient and non-duplicating retrieval.
