# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. It offers comprehensive audit logging for system administration, user activity, policy changes, and security-related actions, and its Web Control component logs web browsing activity together with content and reputation ratings applied to each visited URL. Its removable-media device control component logs USB and other removable-storage device activity — connections, backup status, protection/initialization state, and the user's response to device policy prompts. Its product event log records every product operation carried out on a managed endpoint — installs, uninstalls, updates, AMCore content changes, property collection, and policy enforcement — together with the initiating account, the affected product, and the resulting error code. Combined, these capabilities provide visibility into **critical security infrastructure monitoring and compliance**, **removable-media usage and data-loss-prevention posture**, and **endpoint product deployment and policy enforcement activity**.

The Trellix ePO On-Prem integration for Elastic collects audit, web control, device event, and product event logs using the **REST / Web API** via CEL input, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with REST API / Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO REST / Web API at configurable intervals.

It retrieves audit log records from the `OrionAuditLog` table using a keyset cursor on the unique ascending `AutoId` column: each poll requests records with an `AutoId` strictly greater than the last persisted value, orders results ascending by `AutoId`, and persists the greatest `AutoId` returned. Web control event records are retrieved from the `WP_EventInfo` table using a keyset cursor on the numeric `EventAutoID` field (because `WP_EventInfo` has no timestamp column). Each poll for web control requests events with `EventAutoID` greater than the last persisted value, orders results ascending by `EventAutoID`, and persists the highest `EventAutoID` returned for the next poll.

The `product_event` and `device_event` data streams use a keyset cursor on `AutoID`, a unique ascending column: each poll requests records with an `AutoID` strictly greater than the last persisted value, orders results ascending by `AutoID`, and persists the greatest `AutoID` returned. Because the boundary is exclusive on a unique column, no record is collected twice and no record is skipped. For `product_event`, records are retrieved from the `EPOProductEvents` table. For `device_event`, records are retrieved from the `EEFFDeviceAllEventsView` table. When a poll returns a full page of records, the integration immediately requests the next page within the same interval, up to the configured **Maximum Pages Per Interval**.

Each event is mapped to Elastic Common Schema (ECS) for standardized field naming and ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `audit` | Trellix ePO audit log records, including system administration, policy changes, user activity, and security-related actions retrieved from the ePO REST API. | `/remote/core.executeQuery` API |
| `web_control` | Trellix ePO web control event records, including browsed URLs, user names, content/category ratings (phishing, spam, download, exploit, bad-link, pop-up), overall rating, list/reason/action identifiers, and per-event counts, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `product_event` | Trellix ePO product event records, including the operation type and initiator, the affected product code, the managed endpoint's agent GUID, hostname and IP address, the acting user account, and the source event code, severity and error code, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `device_event` | Trellix ePO removable-media device event records, including device backup size/state/time, protection and initialization status, file system details, the associated agent and user, and vendor/product identifiers, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO with Elastic provides centralized visibility into system administration, user activity, and policy changes across your ePO deployment, enabling efficient audit trail monitoring, compliance reporting, and security investigation within Kibana dashboards.

Integrating Trellix ePO Web Control with Elastic provides centralized visibility into user web browsing activity and the ratings/categories Web Control applies to that traffic, enabling web usage monitoring, threat and risk investigation (phishing, spam, exploit, malicious downloads), and policy-violation reporting within Kibana dashboards.

Integrating Trellix ePO product event records with Elastic provides visibility into product lifecycle activity across managed endpoints — which products were installed, updated, or removed, on which hosts, by which accounts, and whether each operation succeeded. Failed operations are normalized to `event.outcome: failure` with the source code preserved in `error.code`, enabling deployment failure monitoring, rollout tracking, policy enforcement auditing, and correlation of product changes with endpoint inventory and security events within Kibana dashboards.

Integrating Trellix ePO device events with Elastic provides visibility into removable-media device activity across endpoints, enabling data-loss-prevention monitoring, investigation of device protection/backup status, and reporting on user responses to device control policies within Kibana dashboards.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the REST / Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with REST API / Web API enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `OrionAuditLog` table (or `OrionAuditLogMT` for multitenant deployments), the `WP_EventInfo` table, the `EEFFDeviceAllEventsView` table, and/or the `EPOProductEvents` table.
   - Sufficient role permissions to execute queries via the Web API.
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

   - Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
   - Set **Username** and **Password** for an ePO user account with query permissions for the tables of the data streams you enable.
   - Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.

6. Enable each data stream you want to collect (`audit`, `web_control`, `product_event`, `device_event`) and, if needed, adjust:

   - **Initial Event Auto ID** — cursor to begin querying from. Subsequent collections resume from the last persisted value. Set to `0` to start from the beginning (default: `0`).
   - **Interval** — polling frequency. The default is `24h`.
   - **Page Size** — records fetched per API request. The default is `500`.
   - **Maximum Pages Per Interval** — applies to `device_event` and `product_event`. The default is `1000`.

7. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `OrionAuditLog`, `WP_EventInfo`, `EEFFDeviceAllEventsView`, and/or `EPOProductEvents` tables, and that the relevant stream is enabled.
* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the required tables.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all fields configured in the integration (select clause in the CEL template).
* **Pagination issues (audit)**: If audit logs are not advancing, verify that `AutoId` values are increasing in the source table and that the persisted `AutoId` cursor is being updated between polls.
* **Pagination issues (web control)**: If web control logs are not advancing beyond the initial set, verify that `EventAutoID` values are strictly increasing in the source table and that the persisted `EventAutoID` cursor is being correctly updated between polls.
* **Pagination issues (device event / product event)**: If records are not advancing, verify that `AutoID` values are increasing in the source table and that the persisted `AutoID` cursor is being updated between polls. A first run left at the default **Initial Event Auto ID** of `0` scans the whole table and may take several intervals to catch up.
* **SSL certificate errors**: If your Trellix ePO server uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Network connectivity issues**: Verify firewall rules allow outbound HTTPS traffic from the Elastic Agent host to the Trellix ePO server on the configured port.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify the dashboard information is populated.
3. Open the **[Logs Trellix ePO On-Prem] Audit** dashboard to verify audit event data is being collected.
4. Open the **[Logs Trellix ePO On-Prem] Web Control** dashboard and verify that Web Control data is populated.
5. Open the **[Logs Trellix ePO On-Prem] Product Event** dashboard and verify that Product Event data is populated.
6. Open the **[Logs Trellix ePO On-Prem] Device Event** dashboard and verify that Device Event data is populated.

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
| trellix_epo_on_prem.audit.orion_audit_log.priority | Priority/level assigned to the audit entry (enum, observed values 1, 2, 3). | long |


### Web Control

The `web_control` data stream provides Trellix ePO On-Prem web control logs collected from the Web API.

#### Web Control fields

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
| trellix_epo_on_prem.web_control.wp_event_info.action_id | Numeric action identifier associated with the web-control event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.bad_link_rating_id | Numeric identifier for the bad-link rating associated with the event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.content_id | Numeric content identifier associated with the web-control event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.count | Count recorded for the web-control event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.download_rating_id | Numeric identifier for the download rating associated with the event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.exploit_rating_id | Numeric identifier for the exploit rating associated with the event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.list_id | Numeric identifier of a list associated with the web-control event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.observer_mode | Boolean indicating whether observer mode was active for the web-control event. | boolean |
| trellix_epo_on_prem.web_control.wp_event_info.phishing_rating_id | Numeric identifier for the phishing rating associated with the event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.popup_rating_id | Numeric identifier for the pop-up rating associated with the event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.rating_id | Numeric identifier for the overall web-control rating associated with the event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.reason_id | Numeric identifier for the reason associated with the web-control event. | long |
| trellix_epo_on_prem.web_control.wp_event_info.spam_rating_id | Numeric identifier for the spam rating associated with the event. | long |


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


### Device event

The `device_event` data stream provides Trellix ePO On-Prem removable-media device event records collected from the Web API.

#### Device event fields

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
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.backup_size | Backup size value recorded for the removable-media event. | double |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.backup_state | Backup state recorded for the removable-media event. | keyword |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.backup_time | Backup time value recorded for the removable-media event. | double |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.credential_type | Numeric credential-type identifier associated with the event. | long |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.device_size | Size value recorded for the removable-media device. | double |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.exempted | Exemption status recorded for the removable-media event. | keyword |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.file_system | File-system name recorded for the removable-media device. | keyword |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.file_system_version | Version of the file system recorded for the removable-media device. | keyword |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.initialization_state | Initialization state recorded for the removable-media device. | keyword |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.initialization_time | Initialization time value recorded for the removable-media device. | double |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.key | Key value associated with the removable-media event. | keyword |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.media_type | Numeric media-type identifier associated with the removable-media device. | long |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.protected | Protection status recorded for the removable-media device. | keyword |
| trellix_epo_on_prem.device_event.eeff_device_all_events_view.protected_size | Protected-size value recorded for the removable-media device. | double |


### Example event

#### Audit

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2026-07-16T13:45:04+05:30",
    "agent": {
        "ephemeral_id": "7899f7ea-3152-4b60-9875-1a4c875e18e2",
        "id": "c14a0367-eefa-476f-9928-f8cf5fdf580e",
        "name": "elastic-agent-11281",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.audit",
        "namespace": "66291",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "c14a0367-eefa-476f-9928-f8cf5fdf580e",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "delete-user",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "trellix_epo_on_prem.audit",
        "end": "2026-07-16T13:45:05+05:30",
        "id": "1943",
        "ingested": "2026-08-27T14:53:56Z",
        "kind": "event",
        "original": "{\"OrionAuditLog.AutoId\":1943,\"OrionAuditLog.CmdName\":\"Delete user\",\"OrionAuditLog.EndTime\":\"2026-07-16T13:45:05+05:30\",\"OrionAuditLog.Message\":\"User \\\"tempuser\\\" deleted from system\",\"OrionAuditLog.Priority\":3,\"OrionAuditLog.StartTime\":\"2026-07-16T13:45:04+05:30\",\"OrionAuditLog.Success\":true,\"OrionAuditLog.UserId\":1,\"OrionAuditLog.UserName\":\"admin\"}",
        "outcome": "success",
        "start": "2026-07-16T13:45:04+05:30",
        "type": [
            "user",
            "deletion"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "User \"tempuser\" deleted from system",
    "related": {
        "user": [
            "1",
            "admin"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-audit"
    ],
    "trellix_epo_on_prem": {
        "audit": {
            "orion_audit_log": {
                "priority": 3
            }
        }
    },
    "user": {
        "id": "1",
        "name": "admin"
    }
}
```

#### Web Control

An example event for `web_control` looks as following:

```json
{
    "@timestamp": "2026-08-27T12:04:24.300Z",
    "agent": {
        "ephemeral_id": "2ed948bc-3492-4327-817e-83b23c898f5d",
        "id": "97440a4e-3cc5-4d38-be68-1645da3ab54d",
        "name": "elastic-agent-41151",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.web_control",
        "namespace": "21957",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "97440a4e-3cc5-4d38-be68-1645da3ab54d",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "trellix_epo_on_prem.web_control",
        "id": "494",
        "ingested": "2026-08-27T12:04:27Z",
        "kind": "event",
        "original": "{\"WP_EventInfo.BadLinkRatingID\":4,\"WP_EventInfo.ContentID\":0,\"WP_EventInfo.Count\":1,\"WP_EventInfo.DomainName\":\"reports.blockedSiteDSSError\",\"WP_EventInfo.DownloadRatingID\":4,\"WP_EventInfo.EventAutoID\":494,\"WP_EventInfo.ExploitRatingID\":4,\"WP_EventInfo.ListID\":1,\"WP_EventInfo.ObserverMode\":true,\"WP_EventInfo.PhishingRatingID\":4,\"WP_EventInfo.PopupRatingID\":4,\"WP_EventInfo.RatingID\":6,\"WP_EventInfo.ReasonID\":7,\"WP_EventInfo.SpamRatingID\":4,\"WP_EventInfo.URL\":\"reports.blockedSiteDSSError\",\"WP_EventInfo.UserName\":null}",
        "type": [
            "access"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-web_control"
    ],
    "trellix_epo_on_prem": {
        "web_control": {
            "wp_event_info": {
                "bad_link_rating_id": 4,
                "content_id": 0,
                "count": 1,
                "download_rating_id": 4,
                "exploit_rating_id": 4,
                "list_id": 1,
                "observer_mode": true,
                "phishing_rating_id": 4,
                "popup_rating_id": 4,
                "rating_id": 6,
                "reason_id": 7,
                "spam_rating_id": 4
            }
        }
    },
    "url": {
        "domain": "reports.blockedSiteDSSError",
        "original": "reports.blockedSiteDSSError"
    }
}
```

#### Product Event

An example event for `product_event` looks as following:

```json
{
    "@timestamp": "2026-07-21T09:23:20.000Z",
    "agent": {
        "ephemeral_id": "e1e54549-783c-40e3-93ca-36e984765625",
        "id": "4c11c108-bcfe-4f2f-89cc-6242af97b0de",
        "name": "elastic-agent-23379",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.product_event",
        "namespace": "78525",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "4c11c108-bcfe-4f2f-89cc-6242af97b0de",
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
        "action": "deployment-successful",
        "agent_id_status": "verified",
        "category": [
            "package",
            "configuration"
        ],
        "code": "2411",
        "created": "2026-07-21T09:23:47.000Z",
        "dataset": "trellix_epo_on_prem.product_event",
        "id": "1",
        "ingested": "2026-08-28T10:27:11Z",
        "kind": "event",
        "original": "{\"EPOProductEvents.AgentGUID\":\"89A1D5C1-2B3E-4F67-8A9B-0C1D2E3F4A5B\",\"EPOProductEvents.AutoID\":1,\"EPOProductEvents.DetectedUTC\":\"2026-07-21T14:53:20+05:30\",\"EPOProductEvents.Error\":0,\"EPOProductEvents.ExtraDATNames\":null,\"EPOProductEvents.HostName\":\"DESKTOP-K3QM7XP\",\"EPOProductEvents.IPV6\":\"2001:DB8:85A3:0:8A2E:370:7334:1\",\"EPOProductEvents.InitiatorID\":null,\"EPOProductEvents.InitiatorType\":\"CommandLine\",\"EPOProductEvents.Locale\":1033,\"EPOProductEvents.NodeID\":1,\"EPOProductEvents.ProductCode\":\"EPOAGENT3000\",\"EPOProductEvents.ReceivedUTC\":\"2026-07-21T14:53:47+05:30\",\"EPOProductEvents.SPHotFix\":null,\"EPOProductEvents.SiteName\":null,\"EPOProductEvents.TVDEventID\":2411,\"EPOProductEvents.TVDSeverity\":0,\"EPOProductEvents.TenantId\":1,\"EPOProductEvents.Type\":\"Install\",\"EPOProductEvents.UserName\":\"SYSTEM\"}",
        "outcome": "success",
        "severity": 0,
        "type": [
            "installation",
            "change"
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

#### Device event

An example event for `device_event` looks as following:

```json
{
    "@timestamp": "2026-07-31T08:15:42.000Z",
    "agent": {
        "ephemeral_id": "57916f43-c0c7-430f-a7cb-67668f46df8f",
        "id": "11111111-2222-4333-8444-555555555555",
        "name": "elastic-agent-72028",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.device_event",
        "namespace": "90284",
        "type": "logs"
    },
    "device": {
        "manufacturer": "Example Vendor",
        "model": {
            "name": "Example Secure USB"
        },
        "serial_number": "EXAMPLE-DEVICE-SN-001"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "f23ae146-5759-43ed-a647-e151e229426b",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "approved",
        "agent_id_status": "mismatch",
        "category": [
            "host"
        ],
        "code": "3001",
        "created": "2026-07-31T08:16:03.000Z",
        "dataset": "trellix_epo_on_prem.device_event",
        "id": "1048576",
        "ingested": "2026-08-28T11:04:31Z",
        "kind": "event",
        "original": "{\"EEFFDeviceAllEventsView.AgentGUID\":\"11111111-2222-4333-8444-555555555555\",\"EEFFDeviceAllEventsView.AutoID\":1048576,\"EEFFDeviceAllEventsView.BackupSize\":1024.5,\"EEFFDeviceAllEventsView.BackupState\":\"Completed\",\"EEFFDeviceAllEventsView.BackupTime\":18.75,\"EEFFDeviceAllEventsView.CredentialType\":1,\"EEFFDeviceAllEventsView.DeviceSN\":\"EXAMPLE-DEVICE-SN-001\",\"EEFFDeviceAllEventsView.DeviceSize\":64000,\"EEFFDeviceAllEventsView.EventGeneratedTime\":\"2026-07-31T08:15:42.000Z\",\"EEFFDeviceAllEventsView.EventID\":3001,\"EEFFDeviceAllEventsView.EventReportedTime\":\"2026-07-31T08:16:03.000Z\",\"EEFFDeviceAllEventsView.Exempted\":\"No\",\"EEFFDeviceAllEventsView.FileSystem\":\"NTFS\",\"EEFFDeviceAllEventsView.FileSystemVersion\":\"3.1\",\"EEFFDeviceAllEventsView.InitializationState\":\"Initialized\",\"EEFFDeviceAllEventsView.InitializationTime\":12.25,\"EEFFDeviceAllEventsView.Key\":\"example-removable-media-key-001\",\"EEFFDeviceAllEventsView.MediaType\":2,\"EEFFDeviceAllEventsView.ProductName\":\"Example Secure USB\",\"EEFFDeviceAllEventsView.Protected\":\"Yes\",\"EEFFDeviceAllEventsView.ProtectedSize\":62000,\"EEFFDeviceAllEventsView.UserName\":\"EXAMPLE\\\\analyst\",\"EEFFDeviceAllEventsView.UserResponse\":\"Approved\",\"EEFFDeviceAllEventsView.VendorName\":\"Example Vendor\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "EXAMPLE\\analyst"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-device_event"
    ],
    "trellix_epo_on_prem": {
        "device_event": {
            "eeff_device_all_events_view": {
                "backup_size": 1024.5,
                "backup_state": "Completed",
                "backup_time": 18.75,
                "credential_type": 1,
                "device_size": 64000,
                "exempted": "No",
                "file_system": "NTFS",
                "file_system_version": "3.1",
                "initialization_state": "Initialized",
                "initialization_time": 12.25,
                "key": "example-removable-media-key-001",
                "media_type": 2,
                "protected": "Yes",
                "protected_size": 62000
            }
        }
    },
    "user": {
        "name": "EXAMPLE\\analyst"
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

* **Audit**: Collects audit log records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `OrionAuditLog` table using a keyset cursor on `AutoId`, with results ordered ascending so the cursor advances monotonically across polls.
* **Web Control**: Collects web control event records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `WP_EventInfo` table using keyset-based pagination with the `EventAutoID` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Product Event**: Collects product event records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried from `EPOProductEvents` using a keyset cursor on `AutoID`, with results ordered ascending so the cursor advances monotonically across polls.
* **Device event**: Collects removable-media device event records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried from `EEFFDeviceAllEventsView` using a keyset cursor on `AutoID`, with results ordered ascending so the cursor advances monotonically across polls.
