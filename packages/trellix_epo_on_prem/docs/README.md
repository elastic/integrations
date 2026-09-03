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

### Compliance history

The `compliance_history` data stream provides Trellix ePO On-Prem compliance history logs collected from the Web API.

#### Compliance history fields

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
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.chart_name | Name of the chart that generated the compliance history record. | keyword |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.count_compliant | Number of computers recorded as compliant. | long |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.count_computers | Total number of computers evaluated by the compliance query. | long |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.count_non_compliant | Number of computers recorded as noncompliant. | long |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.percent_compliant | Percentage of evaluated computers recorded as compliant. | double |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.percent_non_compliant | Percentage of evaluated computers recorded as noncompliant. | double |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.task_name | Name of the server task that generated the compliance history record. | keyword |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.tenant_id | Tenant identifier associated with the compliance history record. | keyword |


### Example event

#### Compliance history

An example event for `compliance_history` looks as following:

```json
{
    "@timestamp": "2026-08-01T19:30:20.000Z",
    "agent": {
        "ephemeral_id": "84b7a05d-35f0-48ca-9b35-875e6eac5f2e",
        "id": "92824ee0-912e-4619-ab3f-aaed676cd6ee",
        "name": "elastic-agent-53476",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.compliance_history",
        "namespace": "82849",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "92824ee0-912e-4619-ab3f-aaed676cd6ee",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "trellix_epo_on_prem.compliance_history",
        "id": "4",
        "ingested": "2026-07-31T12:13:36Z",
        "kind": "state",
        "original": "{\"EpoComplianceHistory.AutoId\":4,\"EpoComplianceHistory.ChartName\":\"Trellix Agent Compliance Summary\",\"EpoComplianceHistory.CountCompliant\":4,\"EpoComplianceHistory.CountComputers\":5,\"EpoComplianceHistory.CountNonCompliant\":1,\"EpoComplianceHistory.PercentCompliant\":80,\"EpoComplianceHistory.PercentNonCompliant\":20,\"EpoComplianceHistory.TaskName\":\"Generate Records for Trellix Agent Compliance History Reporting\",\"EpoComplianceHistory.TenantId\":0,\"EpoComplianceHistory.TheTimestamp\":\"2026-08-02T01:00:20+05:30\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-compliance_history"
    ],
    "trellix_epo_on_prem": {
        "compliance_history": {
            "epo_compliance_history": {
                "chart_name": "Trellix Agent Compliance Summary",
                "count_compliant": 4,
                "count_computers": 5,
                "count_non_compliant": 1,
                "percent_compliant": 80,
                "percent_non_compliant": 20,
                "task_name": "Generate Records for Trellix Agent Compliance History Reporting",
                "tenant_id": "0"
            }
        }
    }
}
```

### System

The `system` data stream provides Trellix ePO On-Prem managed system (endpoint) logs collected from the Web API.

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
    "@timestamp": "2026-08-03T07:01:28.000Z",
    "agent": {
        "ephemeral_id": "79a9dd7e-9312-4418-b4f9-d9ca380af37e",
        "id": "a55de640-a6c2-473f-8c11-f90c1fa451ff",
        "name": "elastic-agent-88753",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.system",
        "namespace": "18303",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "a55de640-a6c2-473f-8c11-f90c1fa451ff",
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
        "ingested": "2026-09-02T05:26:09Z",
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

* **Audit**: Collects audit log records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `OrionAuditLog` table using keyset-based pagination with the `StartTime` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Web Control**: Collects web control event records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `WP_EventInfo` table using keyset-based pagination with the `EventAutoID` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Compliance history**: Collects compliance history records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `EpoComplianceHistory` table using keyset-based pagination with the `TheTimestamp` field as a cursor to ensure efficient and non-duplicating retrieval.
* **System**: Collects managed system (endpoint) records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `EPOLeafNode` table using keyset-based pagination with the `LastUpdate` field as a cursor to ensure efficient and non-duplicating retrieval.
