# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. It offers comprehensive audit logging for system administration, user activity, policy changes, and security-related actions; its Web Control component logs web browsing activity together with content and reputation ratings applied to each visited URL; its removable-media device control component logs USB and other removable-storage device activity — connections, backup status, protection/initialization state, and the user's response to device policy prompts; its product event log records every product operation carried out on a managed endpoint — installs, uninstalls, updates, AMCore content changes, property collection, and policy enforcement; and it provides visibility into Data Loss Prevention (DLP) incidents and endpoint threat activity across hybrid endpoint deployments. Combined, these capabilities provide visibility into **critical security infrastructure monitoring and compliance**, **web usage and reputation monitoring**, **removable-media usage and data-loss-prevention posture**, **endpoint product deployment and policy enforcement activity**, and **threat detection and response**.

The Trellix ePO On-Prem integration for Elastic collects audit, web control, product event, device event, DLP incident, and threat event logs using the **REST / Web API** via CEL input, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with REST API / Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO REST / Web API at configurable intervals.

It retrieves audit log records from the `OrionAuditLog` table using a keyset cursor on the unique ascending `AutoId` column: each poll requests records with an `AutoId` strictly greater than the last persisted value, orders results ascending by `AutoId`, and persists the greatest `AutoId` returned. Web control event records are retrieved from the `WP_EventInfo` table using a keyset cursor on the numeric `EventAutoID` field (because `WP_EventInfo` has no timestamp column). Each poll for web control requests events with `EventAutoID` greater than the last persisted value, orders results ascending by `EventAutoID`, and persists the highest `EventAutoID` returned for the next poll.

The `product_event` and `device_event` data streams use a keyset cursor on `AutoID`, a unique ascending column: each poll requests records with an `AutoID` strictly greater than the last persisted value, orders results ascending by `AutoID`, and persists the greatest `AutoID` returned. Because the boundary is exclusive on a unique column, no record is collected twice and no record is skipped. For `product_event`, records are retrieved from the `EPOProductEvents` table. For `device_event`, records are retrieved from the `EEFFDeviceAllEventsView` table. When a poll returns a full page of records, the integration immediately requests the next page within the same interval, up to the configured **Maximum Pages Per Interval**.

The `dlp_incident` data stream retrieves DLP incident records from the `UDLP_EPD_Incidents` table and paginates using `LastUpdateTimestamp` as an inclusive time cursor. Because the filter is inclusive, records sharing the boundary timestamp are re-read on the next poll; the ingest pipeline assigns a stable document ID from `IncidentId` so the repeats overwrite rather than duplicate. An incident that is updated later is therefore collected again, keeping its status, resolution, and reviewer fields current.

The `threat_event` data stream queries the `EPExtendedEvent` target and retrieves fields from both `EPOEvents` and `EPExtendedEvent`, so only threat events with matching extended details are collected. It implements keyset-based pagination using the unique ascending `EPOEvents.AutoID` column as the cursor, so no record is re-read at a page boundary.

Each event is mapped to Elastic Common Schema (ECS) for standardized field naming and ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `audit` | Trellix ePO audit log records, including system administration, policy changes, user activity, and security-related actions retrieved from the ePO REST API. | `/remote/core.executeQuery` API |
| `web_control` | Trellix ePO web control event records, including browsed URLs, user names, content/category ratings (phishing, spam, download, exploit, bad-link, pop-up), overall rating, list/reason/action identifiers, and per-event counts, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `product_event` | Trellix ePO product event records, including the operation type and initiator, the affected product code, the managed endpoint's agent GUID, hostname and IP address, the acting user account, and the source event code, severity and error code, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `device_event` | Trellix ePO removable-media device event records, including device backup size/state/time, protection and initialization status, file system details, the associated agent and user, and vendor/product identifiers, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `dlp_incident` | Trellix ePO DLP incidents, including violation times, severity, status, evidence counts, classifications, matched rules, actions, and reviewer information. | `/remote/core.executeQuery` API |
| `threat_event` | Trellix ePO threat events and extended details, including endpoint detections, rules, actions, severity, network activity, files, processes, registry paths, and related entities. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO with Elastic provides centralized visibility into system administration, user activity, and policy changes across your ePO deployment, enabling efficient audit trail monitoring, compliance reporting, and security investigation within Kibana dashboards.

Integrating Trellix ePO Web Control with Elastic provides centralized visibility into user web browsing activity and the ratings/categories Web Control applies to that traffic, enabling web usage monitoring, threat and risk investigation (phishing, spam, exploit, malicious downloads), and policy-violation reporting within Kibana dashboards.

Integrating Trellix ePO product event records with Elastic provides visibility into product lifecycle activity across managed endpoints — which products were installed, updated, or removed, on which hosts, by which accounts, and whether each operation succeeded. Failed operations are normalized to `event.outcome: failure` with the source code preserved in `error.code`, enabling deployment failure monitoring, rollout tracking, policy enforcement auditing, and correlation of product changes with endpoint inventory and security events within Kibana dashboards.

Integrating Trellix ePO device events with Elastic provides visibility into removable-media device activity across endpoints, enabling data-loss-prevention monitoring, investigation of device protection/backup status, and reporting on user responses to device control policies within Kibana dashboards.

Integrating Trellix ePO DLP with Elastic provides centralized visibility into DLP policy violations and sensitive-data activity across managed endpoints. It supports incident investigation, policy effectiveness analysis, compliance reporting, and monitoring of classifications, matched rules, actions, severity, and reviewer activity in Kibana.

Integrating Trellix ePO threat events with Elastic provides centralized visibility into endpoint threat activity across managed systems, supporting threat investigation, detection and response, endpoint activity analysis, intrusion prevention monitoring, firewall traffic analysis, and correlation across hosts, users, IP addresses, files, processes, hashes, and rules in Kibana.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the REST / Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with REST API / Web API enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `OrionAuditLog` table (or `OrionAuditLogMT` for multitenant deployments), the `WP_EventInfo` table, the `EPOProductEvents` table, the `EEFFDeviceAllEventsView` table, the `UDLP_EPD_Incidents` table, and/or the `EPOEvents` and `EPExtendedEvent` tables, depending on the data streams you enable.
   - Sufficient role permissions to run queries via the Web API.
3. **API credentials**: Username and password for basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server (default port: 8443, for example `https://epo.example.com:8443`).
5. **Network access**: The Elastic Agent must have outbound HTTPS access to the ePO server.

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
5. Enable and configure the **Collect Trellix ePO Logs** collection method.

    * For **audit** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set the **Username** for the ePO user account with audit log query permissions.
        * Set the **Password** for the ePO user account.
        * Set **Initial Event Auto Id** to the `OrionAuditLog.AutoId` from which to begin querying. Subsequent collections resume from the last persisted `AutoId`. Set to `0` to start from the beginning (default: `0`).
        * Set **Interval** to the polling frequency. The default is `24h`.
        * Set **Page Size** to the number of audit log records to retrieve per API request. The default is `500`.
        * Optionally adjust **Maximum Pages Per Interval**, **HTTP Client Timeout**, proxy, and SSL settings.
    * For **web control** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `WP_EventInfo` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Event Auto Id** to the starting `EventAutoID` from which to begin querying events. Subsequent collections resume from the last persisted `EventAutoID`. Set to `0` to start from the beginning (default: `0`).
        * Set **Interval** to the polling frequency. The default is `24h`.
        * Set **Page Size** to the number of web control log records to retrieve per API request. The default is `500`.
        * Optionally adjust **Maximum Pages Per Interval**, **HTTP Client Timeout**, proxy, and SSL settings.
    * For **product event** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `EPOProductEvents` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Event Auto ID** to the starting `AutoID` from which to begin querying events. Subsequent collections resume from the last persisted `AutoID`. Set to `0` to start from the beginning (default: `0`).
        * Set **Interval** to the polling frequency. The default is `24h`.
        * Set **Page Size** to the number of product event records to retrieve per API request. The default is `500`.
        * Optionally adjust **Maximum Pages Per Interval**, **HTTP Client Timeout**, proxy, and SSL settings.
    * For **device event** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `EEFFDeviceAllEventsView` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Event Auto ID** to the starting `AutoID` from which to begin querying events. Subsequent collections resume from the last persisted `AutoID`. Set to `0` to start from the beginning (default: `0`).
        * Set **Interval** to the polling frequency. The default is `24h`.
        * Set **Page Size** to the number of device event records to retrieve per API request. The default is `500`.
        * Optionally adjust **Maximum Pages Per Interval**, **HTTP Client Timeout**, proxy, and SSL settings.
    * For **DLP incident** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `UDLP_EPD_Incidents` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Interval** to the lookback period used for the first API request. The default is `24h`.
        * Set **Interval** to the polling frequency. The default is `5m`.
        * Set **Page Size** to the number of DLP incident records to retrieve per API request. The default is `500`.
        * Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.
    * For **threat event** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `EPOEvents` and `EPExtendedEvent` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Event Auto ID** to the `EPOEvents.AutoID` that collection should start after on the first run. The default is `0`, which collects all threat events available on the server.
        * Set **Interval** to the polling frequency. The default is `5m`.
        * Set **Page Size** to the number of threat event records to retrieve per API request. The default is `500`.
        * Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.

6. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `OrionAuditLog`, `WP_EventInfo`, `EPOProductEvents`, `EEFFDeviceAllEventsView`, `UDLP_EPD_Incidents`, `EPOEvents`, and/or `EPExtendedEvent` tables, and that the relevant stream is enabled.
* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the required tables.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all fields configured in the integration (select clause in the CEL template).
* **Missing expected threat events**: The `threat_event` query uses `EPExtendedEvent` as its target and collects only events with matching extended details.
* **Pagination issues (audit)**: If audit logs are not advancing, verify that `AutoId` values are increasing in the source table and that the persisted `AutoId` cursor is being updated between polls.
* **Pagination issues (web control)**: If web control logs are not advancing beyond the initial set, verify that `EventAutoID` values are strictly increasing in the source table and that the persisted `EventAutoID` cursor is being correctly updated between polls.
* **Pagination issues (device event / product event)**: If records are not advancing, verify that `AutoID` values are increasing in the source table and that the persisted `AutoID` cursor is being updated between polls. A first run left at the default **Initial Event Auto ID** of `0` scans the whole table and may take several intervals to catch up.
* **Pagination issues (DLP incident and threat event)**: If collection does not advance, verify that `UDLP_EPD_Incidents.LastUpdateTimestamp` (DLP incidents) or `EPOEvents.AutoID` (threat events) is present in every returned record and that records are ordered by this field.
* **Collection timeouts**: Increase **HTTP Client Timeout** or reduce **Page Size**.
* **SSL certificate errors**: If your Trellix ePO server uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Network connectivity issues**: Verify firewall rules allow outbound HTTPS traffic from the Elastic Agent host to the Trellix ePO server on the configured port.
* **Missing historical incidents**: Increase **Initial Interval** so that the first DLP incident request covers the required lookback period.
* **Missing historical threat events**: Lower **Initial Event Auto ID** so that the first request starts from an earlier `EPOEvents.AutoID`.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify the dashboard information is populated.
3. Open the **[Logs Trellix ePO On-Prem] Audit** dashboard to verify audit event data is being collected.
4. Open the **[Logs Trellix ePO On-Prem] Web Control** dashboard and verify that Web Control data is populated.
5. Open the **[Logs Trellix ePO On-Prem] Product Event** dashboard and verify that Product Event data is populated.
6. Open the **[Logs Trellix ePO On-Prem] Device Event** dashboard and verify that Device Event data is populated.
7. Open the **[Logs Trellix ePO On-Prem] DLP Incident Overview** dashboard and verify that DLP incident data is populated.
8. Open the **[Logs Trellix ePO On-Prem] Threat Event Overview** dashboard and verify that threat event data is populated.

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

### Web Control

The `web_control` data stream provides Trellix ePO On-Prem web control logs collected from the Web API.

#### Web Control fields

{{ fields "web_control" }}

### Product Event

The `product_event` data stream provides Trellix ePO On-Prem product event logs collected from the Web API.

#### Product Event fields

{{ fields "product_event" }}

### Device event

The `device_event` data stream provides Trellix ePO On-Prem removable-media device event records collected from the Web API.

#### Device event fields

{{ fields "device_event" }}

### DLP incident

The `dlp_incident` data stream provides Trellix ePO On-Prem DLP incident records collected from the Web API.

#### DLP incident fields

{{ fields "dlp_incident" }}

### Threat event

The `threat_event` data stream provides Trellix ePO On-Prem threat event records and matching extended event details collected from the Web API.

#### Threat event fields

{{ fields "threat_event" }}

### Example event

#### Audit

{{ event "audit" }}

#### Web Control

{{ event "web_control" }}

#### Product Event

{{ event "product_event" }}

#### Device event

{{ event "device_event" }}

#### DLP incident

{{ event "dlp_incident" }}

#### Threat event

{{ event "threat_event" }}

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

* **Audit**: Collects audit log records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `OrionAuditLog` table using a keyset cursor on `AutoId`, with results ordered ascending so the cursor advances monotonically across polls.
* **Web Control**: Collects web control event records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `WP_EventInfo` table using keyset-based pagination with the `EventAutoID` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Product Event**: Collects product event records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried from `EPOProductEvents` using a keyset cursor on `AutoID`, with results ordered ascending so the cursor advances monotonically across polls.
* **Device event**: Collects removable-media device event records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried from `EEFFDeviceAllEventsView` using a keyset cursor on `AutoID`, with results ordered ascending so the cursor advances monotonically across polls.
* **DLP incident**: Collects DLP incident records through the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from `UDLP_EPD_Incidents` and ordered by `LastUpdateTimestamp`, which is used as an inclusive time cursor.
* **Threat event**: Collects threat event records through the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried using the `EPExtendedEvent` target, fields are selected from `EPOEvents` and `EPExtendedEvent`, and pagination is keyset-based using `EPOEvents.AutoID` as the cursor.
