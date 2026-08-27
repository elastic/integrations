# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. It offers comprehensive audit logging for system administration, user activity, policy changes, and security-related actions, and its Web Control component logs web browsing activity together with content and reputation ratings applied to each visited URL — combining authentication, authorization, detailed audit trails, and web usage monitoring into a unified platform for **critical security infrastructure monitoring and compliance**.

The Trellix ePO On-Prem integration for Elastic collects audit and web control logs using the **REST / Web API** via CEL input, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with REST API / Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO REST / Web API at configurable intervals. It retrieves audit log records from the `OrionAuditLog` table using keyset-based pagination with cursor timestamps, and web control event records from the `WP_EventInfo` table using a keyset cursor on the numeric `EventAutoID` field (because `WP_EventInfo` has no timestamp column). Each poll for web control requests events with `EventAutoID` greater than the last persisted value, orders results ascending by `EventAutoID`, and persists the highest `EventAutoID` returned for the next poll. Each event is mapped to Elastic Common Schema (ECS) for standardized field naming and ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `audit` | Trellix ePO audit log records, including system administration, policy changes, user activity, and security-related actions retrieved from the ePO REST API. | `/remote/core.executeQuery` API |
| `web_control` | Trellix ePO web control event records, including browsed URLs, user names, content/category ratings (phishing, spam, download, exploit, bad-link, pop-up), overall rating, list/reason/action identifiers, and per-event counts, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO with Elastic provides centralized visibility into system administration, user activity, and policy changes across your ePO deployment, enabling efficient audit trail monitoring, compliance reporting, and security investigation within Kibana dashboards.

Integrating Trellix ePO Web Control with Elastic provides centralized visibility into user web browsing activity and the ratings/categories Web Control applies to that traffic, enabling web usage monitoring, threat and risk investigation (phishing, spam, exploit, malicious downloads), and policy-violation reporting within Kibana dashboards.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the REST / Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with REST API / Web API enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `OrionAuditLog` table (or `OrionAuditLogMT` for multitenant deployments) and/or the `WP_EventInfo` table.
   - Sufficient role permissions to execute queries via the Web API.
3. **API credentials**: Username and password for basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server (default port: 2400, for example `https://epo.example.com:2400`).
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
5. Enable and configure the collection methods you need:

    * For **audit** logs:
        * Set the **URL** to the base URL of your Trellix ePO server (for example `https://epo.example.com:2400`).
        * Set the **Username** for the ePO user account with audit log query permissions.
        * Set the **Password** for the ePO user account.
        * **Initial Interval**: The lookback period for the first API request (default: `24h`).
        * **Page Size**: Number of audit log records to retrieve per API call (default: `500`).
        * Optionally adjust **Interval** and **HTTP Client Timeout** as needed.
    * For **web control** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `WP_EventInfo` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Event Auto Id** to the starting `EventAutoID` from which to begin querying events. Subsequent collections resume from the last persisted `EventAutoID`. Set to `0` to start from the beginning (default: `0`).
        * Set **Interval** to the polling frequency. The default is `24h`.
        * Set **Page Size** to the number of web control log records to retrieve per API request. The default is `500`.
        * Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.

6. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `OrionAuditLog` and/or `WP_EventInfo` tables.
* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the required tables.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all fields configured in the integration (select clause in the CEL template).
* **Pagination issues (audit)**: If audit logs are not advancing beyond the initial set, verify that the `StartTime` field is present in all returned records and that pagination timestamps are being correctly updated.
* **Pagination issues (web control)**: If web control logs are not advancing beyond the initial set, verify that `EventAutoID` values are strictly increasing in the source table and that the persisted `EventAutoID` cursor is being correctly updated between polls.
* **SSL certificate errors**: If your Trellix ePO server uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Network connectivity issues**: Verify firewall rules allow outbound HTTPS traffic from the Elastic Agent host to the Trellix ePO server on the configured port.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify the dashboard information is populated.
3. Open the **[Logs Trellix ePO On-Prem] Audit** dashboard to verify audit event data is being collected.
4. Open the **[Logs Trellix ePO On-Prem] Web Control** dashboard and verify that Web Control data is populated.

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


### Example event

#### Audit

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2026-07-16T13:45:04+05:30",
    "agent": {
        "ephemeral_id": "72fdf282-d4b1-4149-ae89-25d48bcb2a24",
        "id": "525170d9-a573-4e56-9131-d4d51fa5e465",
        "name": "elastic-agent-81415",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.audit",
        "namespace": "80949",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "525170d9-a573-4e56-9131-d4d51fa5e465",
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
        "ingested": "2026-08-19T10:36:44Z",
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


### Example event

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

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

* **Audit**: Collects audit log records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `OrionAuditLog` table using keyset-based pagination with the `StartTime` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Web Control**: Collects web control event records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `WP_EventInfo` table using keyset-based pagination with the `EventAutoID` field as a cursor to ensure efficient and non-duplicating retrieval.
