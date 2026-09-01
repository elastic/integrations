# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. It offers comprehensive audit logging for system administration, user activity, policy changes, and security-related actions; its Web Control component logs web browsing activity together with content and reputation ratings applied to each visited URL; and it provides visibility into Data Loss Prevention (DLP) incidents and endpoint threat activity across hybrid endpoint deployments — combining authentication, authorization, detailed audit trails, web usage monitoring, sensitive-data protection, and threat detection into a unified platform for **critical security infrastructure monitoring and compliance**.

The Trellix ePO On-Prem integration for Elastic collects audit, web control, DLP incident, and threat event logs using the **REST / Web API** via CEL input, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with REST API / Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO REST / Web API at configurable intervals. It retrieves audit log records from the `OrionAuditLog` table using keyset-based pagination with cursor timestamps, and web control event records from the `WP_EventInfo` table using a keyset cursor on the numeric `EventAutoID` field (because `WP_EventInfo` has no timestamp column). Each poll for web control requests events with `EventAutoID` greater than the last persisted value, orders results ascending by `EventAutoID`, and persists the highest `EventAutoID` returned for the next poll.

The `dlp_incident` data stream retrieves DLP incident records from the `UDLP_EPD_Incidents` table and paginates using `LastUpdateTimestamp` as an inclusive time cursor. Because the filter is inclusive, records sharing the boundary timestamp are re-read on the next poll; the ingest pipeline assigns a stable document ID from `IncidentId` so the repeats overwrite rather than duplicate. An incident that is updated later is therefore collected again, keeping its status, resolution, and reviewer fields current.

The `threat_event` data stream queries the `EPExtendedEvent` target and retrieves fields from both `EPOEvents` and `EPExtendedEvent`, so only threat events with matching extended details are collected. It implements keyset-based pagination using the unique ascending `EPOEvents.AutoID` column as the cursor, so no record is re-read at a page boundary.

Each event is mapped to Elastic Common Schema (ECS) for standardized field naming and ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `audit` | Trellix ePO audit log records, including system administration, policy changes, user activity, and security-related actions retrieved from the ePO REST API. | `/remote/core.executeQuery` API |
| `web_control` | Trellix ePO web control event records, including browsed URLs, user names, content/category ratings (phishing, spam, download, exploit, bad-link, pop-up), overall rating, list/reason/action identifiers, and per-event counts, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `dlp_incident` | Trellix ePO DLP incidents, including violation times, severity, status, evidence counts, classifications, matched rules, actions, and reviewer information. | `/remote/core.executeQuery` API |
| `threat_event` | Trellix ePO threat events and extended details, including endpoint detections, rules, actions, severity, network activity, files, processes, registry paths, and related entities. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO with Elastic provides centralized visibility into system administration, user activity, and policy changes across your ePO deployment, enabling efficient audit trail monitoring, compliance reporting, and security investigation within Kibana dashboards.

Integrating Trellix ePO Web Control with Elastic provides centralized visibility into user web browsing activity and the ratings/categories Web Control applies to that traffic, enabling web usage monitoring, threat and risk investigation (phishing, spam, exploit, malicious downloads), and policy-violation reporting within Kibana dashboards.

Integrating Trellix ePO DLP with Elastic provides centralized visibility into DLP policy violations and sensitive-data activity across managed endpoints. It supports incident investigation, policy effectiveness analysis, compliance reporting, and monitoring of classifications, matched rules, actions, severity, and reviewer activity in Kibana.

It also provides centralized visibility into endpoint threat activity across managed systems, supporting threat investigation, detection and response, endpoint activity analysis, intrusion prevention monitoring, firewall traffic analysis, and correlation across hosts, users, IP addresses, files, processes, hashes, and rules in Kibana.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the REST / Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with REST API / Web API enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `OrionAuditLog` table (or `OrionAuditLogMT` for multitenant deployments), the `WP_EventInfo` table, the `UDLP_EPD_Incidents` table, and/or the `EPOEvents` and `EPExtendedEvent` tables, depending on the data streams you enable.
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
5. Enable and configure the collection methods you need:

    * For **audit** logs:
        * Set the **URL** to the base URL of your Trellix ePO server (for example `https://epo.example.com:2400`).
        * Set the **Username** for the ePO user account with audit log query permissions.
        * Set the **Password** for the ePO user account.
        * **Initial Interval**: The lookback period for the first API request (default: `24h`).
        * **Timezone Offset**: The UTC offset the ePO server returns in `StartTime`, as an `HH:mm` value such as `+05:30` or `-08:00` (default: `+5:30`).
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
    * For **DLP incident** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `UDLP_EPD_Incidents` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Interval** to the lookback period used for the first API request. The default is `24h`.
        * Set **Timezone Offset** to the UTC offset the ePO server returns in `LastUpdateTimestamp`, as an `HH:mm` value such as `+05:30` or `-08:00`. The cursor is converted to UTC using this offset, so a mismatch causes incidents to be skipped or re-read on every poll.
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

* **No data collected**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `OrionAuditLog`, `WP_EventInfo`, `UDLP_EPD_Incidents`, `EPOEvents`, and/or `EPExtendedEvent` tables.
* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the required tables.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all fields configured in the integration (select clause in the CEL template).
* **Missing expected threat events**: The `threat_event` query uses `EPExtendedEvent` as its target and collects only events with matching extended details.
* **Pagination issues (audit)**: If audit logs are not advancing beyond the initial set, verify that the `StartTime` field is present in all returned records and that pagination timestamps are being correctly updated.
* **Pagination issues (web control)**: If web control logs are not advancing beyond the initial set, verify that `EventAutoID` values are strictly increasing in the source table and that the persisted `EventAutoID` cursor is being correctly updated between polls.
* **Pagination issues (DLP incident and threat event)**: If collection does not advance, verify that `UDLP_EPD_Incidents.LastUpdateTimestamp` (DLP incidents) or `EPOEvents.AutoID` (threat events) is present in every returned record and that records are ordered by this field.
* **Collection timeouts**: Increase **HTTP Client Timeout** or reduce **Page Size**.
* **SSL certificate errors**: If your Trellix ePO server uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Network connectivity issues**: Verify firewall rules allow outbound HTTPS traffic from the Elastic Agent host to the Trellix ePO server on the configured port.
* **Missing historical incidents**: Increase **Initial Interval** so that the first DLP incident request covers the required lookback period.
* **Missing historical threat events**: Lower **Initial Event Auto ID** so that the first request starts from an earlier `EPOEvents.AutoID`.
* **DLP incidents skipped or repeatedly re-read**: Confirm **Timezone Offset** matches the UTC offset the ePO server returns in `LastUpdateTimestamp`.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify the dashboard information is populated.
3. Open the **[Logs Trellix ePO On-Prem] Audit** dashboard to verify audit event data is being collected.
4. Open the **[Logs Trellix ePO On-Prem] Web Control** dashboard and verify that Web Control data is populated.
5. Open the **[Logs Trellix ePO On-Prem] DLP Incident Overview** dashboard and verify that DLP incident data is populated.
6. Open the **[Logs Trellix ePO On-Prem] Threat Event Overview** dashboard and verify that threat event data is populated.

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

### DLP incident

The `dlp_incident` data stream provides Trellix ePO On-Prem DLP incident records collected from the Web API.

#### DLP incident fields

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
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ActualAction | Numeric identifier of the action actually taken for the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ClassificationsToDisplay | Display label for the data classification associated with the DLP incident. | keyword |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ConnectivityState | Numeric connectivity-state code associated with the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.DlpAgentVersion | Version string of the DLP agent associated with the incident. | keyword |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.EvidenceCount | Number of evidence items associated with the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ExpectedAction | Numeric identifier of the action expected for the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.FailureReason | Numeric failure-reason code associated with the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.LastUpdateTimestamp | Date and time when the DLP incident record was last updated. | date |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.McAfeeAgentGuid | GUID identifying a McAfee agent associated with the DLP incident. | keyword |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.OriginalIncidentId | Numeric identifier of an original incident related to the current DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ReportingProduct | Numeric identifier of the product that reported the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ResolutionId | Numeric identifier of the DLP incident resolution. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ShortMatchString | Short content excerpt associated with a DLP rule match. | keyword |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.StatusId | Numeric identifier of the DLP incident status. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.TotalContentSize | Total content size recorded for the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.TotalMatchCount | Total number of matches recorded for the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ViolationCustomTime | Custom date and time representation associated with the DLP violation. | date |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ViolationLocalTime | Local date and time when the DLP violation occurred. | date |


### Example event

#### DLP incident

An example event for `dlp_incident` looks as following:

```json
{
    "@timestamp": "2026-01-15T10:00:05.000Z",
    "agent": {
        "ephemeral_id": "508bea6c-d729-43fa-b186-9f0db89f11c8",
        "id": "43f5e8ad-9018-4ed2-96c5-7246a0386fa5",
        "name": "elastic-agent-83453",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.dlp_incident",
        "namespace": "22272",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "43f5e8ad-9018-4ed2-96c5-7246a0386fa5",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "code": "1",
        "dataset": "trellix_epo_on_prem.dlp_incident",
        "id": "100006",
        "ingested": "2026-09-01T09:47:55Z",
        "kind": "alert",
        "original": "{\"UDLP_EPD_Incidents.ActualAction\":2,\"UDLP_EPD_Incidents.ClassificationsToDisplay\":\"Restricted Data\",\"UDLP_EPD_Incidents.ConnectivityState\":1,\"UDLP_EPD_Incidents.DlpAgentVersion\":\"11.10.0.456\",\"UDLP_EPD_Incidents.EvidenceCount\":1,\"UDLP_EPD_Incidents.ExpectedAction\":2,\"UDLP_EPD_Incidents.FailureReason\":0,\"UDLP_EPD_Incidents.IncidentId\":100006,\"UDLP_EPD_Incidents.IncidentType\":1,\"UDLP_EPD_Incidents.LastUpdateTimestamp\":\"2026-01-15T10:00:05Z\",\"UDLP_EPD_Incidents.McAfeeAgentGuid\":\"89a1d5c1-2b3e-4f67-8a9b-0c1d2e3f4a5b\",\"UDLP_EPD_Incidents.OriginalIncidentId\":100005,\"UDLP_EPD_Incidents.ReportingProduct\":1,\"UDLP_EPD_Incidents.ResolutionId\":0,\"UDLP_EPD_Incidents.Reviewer\":\"reviewer@example.com\",\"UDLP_EPD_Incidents.RuleSetToDisplay\":\"Endpoint DLP Rules\",\"UDLP_EPD_Incidents.RulesToDisplay\":\"Block restricted upload\",\"UDLP_EPD_Incidents.Severity\":2,\"UDLP_EPD_Incidents.ShortMatchString\":\"Sample restricted identifier: ***-**-5678\",\"UDLP_EPD_Incidents.StatusId\":1,\"UDLP_EPD_Incidents.TotalContentSize\":2048,\"UDLP_EPD_Incidents.TotalMatchCount\":1,\"UDLP_EPD_Incidents.ViolationCustomTime\":\"2026-01-15T15:30:05+05:30\",\"UDLP_EPD_Incidents.ViolationLocalTime\":\"2026-01-15T15:30:05+05:30\",\"UDLP_EPD_Incidents.ViolationTimezone\":\"Asia/Kolkata\",\"UDLP_EPD_Incidents.ViolationUTCTime\":\"2026-01-15T10:00:05Z\"}",
        "severity": 2,
        "timezone": "Asia/Kolkata"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "reviewer@example.com"
        ]
    },
    "rule": {
        "name": "Block restricted upload",
        "ruleset": "Endpoint DLP Rules"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-dlp_incident"
    ],
    "trellix_epo_on_prem": {
        "dlp_incident": {
            "UDLP_EPD_Incidents": {
                "ActualAction": 2,
                "ClassificationsToDisplay": "Restricted Data",
                "ConnectivityState": 1,
                "DlpAgentVersion": "11.10.0.456",
                "EvidenceCount": 1,
                "ExpectedAction": 2,
                "FailureReason": 0,
                "LastUpdateTimestamp": "2026-01-15T10:00:05.000Z",
                "McAfeeAgentGuid": "89a1d5c1-2b3e-4f67-8a9b-0c1d2e3f4a5b",
                "OriginalIncidentId": 100005,
                "ReportingProduct": 1,
                "ResolutionId": 0,
                "ShortMatchString": "Sample restricted identifier: ***-**-5678",
                "StatusId": 1,
                "TotalContentSize": 2048,
                "TotalMatchCount": 1,
                "ViolationCustomTime": "2026-01-15T10:00:05.000Z",
                "ViolationLocalTime": "2026-01-15T10:00:05.000Z"
            }
        }
    },
    "user": {
        "domain": "example.com",
        "email": "reviewer@example.com",
        "name": "reviewer"
    }
}
```

### Threat event

The `threat_event` data stream provides Trellix ePO On-Prem threat event records and matching extended event details collected from the Web API.

#### Threat event fields

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
| observer.vendor | Vendor name of the observer that generated the event. | constant_keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AMCoreContentVersion | AM Core Content Version value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.APIName | API Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AccessRequested | Access Requested value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AnalyzerContentCreationDate | Analyzer Content Creation Date value recorded in the extended threat-event details. | date |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AnalyzerGTIQuery | Analyzer GTI Query value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AnalyzerRegInfo | Analyzer Reg Info value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AnalyzerTechnologyVersion | Analyzer Technology Version value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AttackVectorType | Attack Vector Type value recorded in the extended threat-event details. | long |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.BladeName | Blade Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.Cleanable | Cleanable value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.Direction | Direction value recorded in the extended threat-event details. | long |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.DurationBeforeDetection | Duration Before Detection value recorded in the extended threat-event details. | long |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.EventAutoID | Event Auto ID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.FirstActionStatus | First Action Status value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.FirstAttemptedAction | First Attempted Action value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.Location | Location value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SecondActionStatus | Second Action Status value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SecondAttemptedAction | Second Attempted Action value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceDescription | Source Description value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceDevicePID | Source Device PID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceDeviceSerialNumber | Source Device Serial Number value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceDeviceVID | Source Device VID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceHash | Source Hash value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceShareName | Source Share Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceURLRatingCode | Source URL Rating Code value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceURLWebCategory | Source URL Web Category value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetCreateTime | Target Create Time value recorded in the extended threat-event details. | date |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDescription | Target Description value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDeviceDisplayName | Target Device Display Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDevicePID | Target Device PID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDeviceSerialNumber | Target Device Serial Number value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDeviceVID | Target Device VID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetModifyTime | Target Modify Time value recorded in the extended threat-event details. | date |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetParentProcessHash | Target Parent Process Hash value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetParentProcessName | Target Parent Process Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetParentProcessSigned | Target Parent Process Signed value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetParentProcessSigner | Target Parent Process Signer value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetShareName | Target Share Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetURL | Target URL value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TaskName | Task Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.ThreatDetectedOnCreation | Threat Detected On Creation value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.ThreatImpact | Threat Impact value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.Topic | Topic value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.AgentGUID | Agent GUID value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.Analyzer | Analyzer value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.AnalyzerDATVersion | Analyzer DAT Version value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.AnalyzerEngineVersion | Analyzer Engine Version value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.DetectedUTC | Detection time recorded in the ePO threat event. | date |
| trellix_epo_on_prem.threat_event.EPOEvents.EventTimeLocal | Event Time Local value recorded in the ePO threat event. | date |
| trellix_epo_on_prem.threat_event.EPOEvents.ServerID | Server ID value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.SourceHostName | Source Host Name value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.SourceURL | Source URL value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.TargetProcessName | Target Process Name value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.TenantId | Tenant ID value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatActionTaken | Threat Action Taken value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatCategory | Trellix threat-category identifier used to classify the event variant. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatHandled | Threat Handled value recorded in the ePO threat event. | boolean |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatType | Trellix threat-type identifier used as the primary event variant discriminator. | keyword |


### Example event

#### Threat event

An example event for `threat_event` looks as following:

```json
{
    "@timestamp": "2026-01-15T10:00:05.000Z",
    "agent": {
        "ephemeral_id": "44f1b728-6dc8-482b-a007-50f028483fff",
        "id": "a0444196-e944-4e2a-87c3-461b20e6641e",
        "name": "elastic-agent-66528",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.threat_event",
        "namespace": "52577",
        "type": "logs"
    },
    "destination": {
        "ip": [
            "203.0.113.50",
            "0:0:0:0:0:FFFF:CB00:7132"
        ],
        "mac": "00-11-22-33-44-77",
        "port": 80
    },
    "device": {
        "product": {
            "name": "Example Virtual SCSI Disk Device"
        }
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "a0444196-e944-4e2a-87c3-461b20e6641e",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection"
        ],
        "code": "18063",
        "created": "2025-01-01T00:00:00.000Z",
        "dataset": "trellix_epo_on_prem.threat_event",
        "id": "11111111-1111-4111-8111-111111111106",
        "ingested": "2026-09-01T09:48:46Z",
        "kind": "alert",
        "original": "{\"EPExtendedEvent.AMCoreContentVersion\":\"1.0.0\",\"EPExtendedEvent.APIName\":\"SyntheticApiCall\",\"EPExtendedEvent.AccessRequested\":\"IDS_AAC_REQ_READ\",\"EPExtendedEvent.AnalyzerContentCreationDate\":\"2026-01-01T00:00:00+00:00\",\"EPExtendedEvent.AnalyzerContentVersion\":\"10.7.0.14078\",\"EPExtendedEvent.AnalyzerGTIQuery\":true,\"EPExtendedEvent.AnalyzerRegInfo\":\"Synthetic analyzer registry context\",\"EPExtendedEvent.AnalyzerRuleID\":\"complete-rule-001\",\"EPExtendedEvent.AnalyzerRuleName\":\"Synthetic complete coverage rule\",\"EPExtendedEvent.AnalyzerTechnologyVersion\":\"10.7.20.14030\",\"EPExtendedEvent.AttackVectorType\":3,\"EPExtendedEvent.BladeName\":\"IDS_BLADE_NAME_FW\",\"EPExtendedEvent.Cleanable\":true,\"EPExtendedEvent.Direction\":1,\"EPExtendedEvent.DurationBeforeDetection\":1200,\"EPExtendedEvent.EventAutoID\":6,\"EPExtendedEvent.FirstActionStatus\":true,\"EPExtendedEvent.FirstAttemptedAction\":\"blocked\",\"EPExtendedEvent.Location\":\"C:\\\\Example\\\\sample.exe\",\"EPExtendedEvent.NaturalLangDescription\":\"Synthetic complete field coverage system-test event\",\"EPExtendedEvent.SecondActionStatus\":false,\"EPExtendedEvent.SecondAttemptedAction\":\"quarantined\",\"EPExtendedEvent.SourceAccessTime\":\"2026-01-15T09:00:00+00:00\",\"EPExtendedEvent.SourceCreateTime\":\"2025-01-01T00:00:00+00:00\",\"EPExtendedEvent.SourceDescription\":\"EXAMPLE AGENT MODULE\",\"EPExtendedEvent.SourceDeviceDisplayName\":\"Example Virtual SCSI Disk Device\",\"EPExtendedEvent.SourceDevicePID\":\"PCI\\\\VEN_8086\\u0026DEV_1234\\u0026SUBSYS_00000000\\u0026REV_01\\\\4\\u0026abc\\u00260\\u002600A8\",\"EPExtendedEvent.SourceDeviceSerialNumber\":\"EXAMPLE-SOURCE-SERIAL-0001\",\"EPExtendedEvent.SourceDeviceVID\":\"PCI\\\\VEN_8086\\u0026DEV_1234\\u0026SUBSYS_00000000\\u0026REV_01\\\\4\\u0026abc\\u00260\\u002600A8\",\"EPExtendedEvent.SourceFilePath\":\"C:\\\\Program Files\\\\ExampleApp\",\"EPExtendedEvent.SourceFileSize\":524288,\"EPExtendedEvent.SourceHash\":\"DEADBEEF0123456789ABCDEFF0123456\",\"EPExtendedEvent.SourceModifyTime\":\"2025-01-01T00:00:00+00:00\",\"EPExtendedEvent.SourceParentProcessHash\":\"FEEDFACE0123456789ABCDEFF0123456\",\"EPExtendedEvent.SourceParentProcessName\":\"example-parent.exe\",\"EPExtendedEvent.SourceParentProcessSigned\":true,\"EPExtendedEvent.SourceParentProcessSigner\":\"C=US, O=Example Corp, CN=Example Publisher\",\"EPExtendedEvent.SourcePort\":52000,\"EPExtendedEvent.SourceProcessHash\":\"F6789012345678901234ABCDEF012345\",\"EPExtendedEvent.SourceProcessSigned\":true,\"EPExtendedEvent.SourceProcessSigner\":\"C=US, O=Example Corp, CN=Example Windows\",\"EPExtendedEvent.SourceShareName\":\"\\\\\\\\source-host.example.com\\\\share\",\"EPExtendedEvent.SourceSigned\":true,\"EPExtendedEvent.SourceSigner\":\"C=US, O=Example Corp, CN=Example Windows\",\"EPExtendedEvent.SourceURLRatingCode\":\"trusted\",\"EPExtendedEvent.SourceURLWebCategory\":\"business\",\"EPExtendedEvent.TargetAccessTime\":\"2026-01-15T09:57:00+00:00\",\"EPExtendedEvent.TargetCreateTime\":\"2025-04-01T08:00:00+00:00\",\"EPExtendedEvent.TargetDescription\":\"Synthetic target description\",\"EPExtendedEvent.TargetDeviceDisplayName\":\"Example Target Device\",\"EPExtendedEvent.TargetDevicePID\":\"DEV_5678\",\"EPExtendedEvent.TargetDeviceSerialNumber\":\"EXAMPLE-TARGET-SERIAL-0001\",\"EPExtendedEvent.TargetDeviceVID\":\"VEN_1234\",\"EPExtendedEvent.TargetFileSize\":102400,\"EPExtendedEvent.TargetHash\":\"6789012345678901234ABCDEF0123456\",\"EPExtendedEvent.TargetModifyTime\":\"2025-04-01T08:00:00+00:00\",\"EPExtendedEvent.TargetName\":\"example-document.pdf\",\"EPExtendedEvent.TargetParentProcessHash\":\"B2C3D4E5F6789012345678901234ABCD\",\"EPExtendedEvent.TargetParentProcessName\":\"parent-app.exe\",\"EPExtendedEvent.TargetParentProcessSigned\":true,\"EPExtendedEvent.TargetParentProcessSigner\":\"C=US, O=Example Corp, CN=Example Code Signing\",\"EPExtendedEvent.TargetPath\":\"C:\\\\Users\\\\Public\",\"EPExtendedEvent.TargetShareName\":\"\\\\\\\\target-host.example.com\\\\share\",\"EPExtendedEvent.TargetSigned\":false,\"EPExtendedEvent.TargetSigner\":\"C=US, O=Example Corp, CN=Example Windows Publisher\",\"EPExtendedEvent.TargetURL\":\"https://target.example.com/resource\",\"EPExtendedEvent.TaskName\":\"Synthetic Scan Task\",\"EPExtendedEvent.ThreatDetectedOnCreation\":true,\"EPExtendedEvent.ThreatImpact\":\"low\",\"EPExtendedEvent.Topic\":\"Synthetic threat topic\",\"EPOEvents.AgentGUID\":\"77777777-8888-4999-8AAA-BBBBBBBBBB07\",\"EPOEvents.Analyzer\":\"ENDP_TEST_1000\",\"EPOEvents.AnalyzerDATVersion\":\"9999.0\",\"EPOEvents.AnalyzerDetectionMethod\":\"Access Protection\",\"EPOEvents.AnalyzerEngineVersion\":\"1.2.3\",\"EPOEvents.AnalyzerHostName\":\"lab-host-complete.example.com\",\"EPOEvents.AnalyzerIPV4\":1177773066,\"EPOEvents.AnalyzerIPV6\":\"0:0:0:0:0:FFFF:C633:640A\",\"EPOEvents.AnalyzerMAC\":\"00aabbccddee\",\"EPOEvents.AnalyzerName\":\"Trellix Endpoint Security\",\"EPOEvents.AnalyzerVersion\":\"10.7.20.14066\",\"EPOEvents.AutoGUID\":\"11111111-1111-4111-8111-111111111106\",\"EPOEvents.AutoID\":6,\"EPOEvents.DetectedUTC\":\"2026-01-15T10:00:05+00:00\",\"EPOEvents.EventTimeLocal\":\"2026-01-15T10:00:05+00:00\",\"EPOEvents.ReceivedUTC\":\"2026-01-15T10:00:05+00:00\",\"EPOEvents.ServerID\":\"epo-server-01.example.com\",\"EPOEvents.SourceHostName\":\"source-host.example.com\",\"EPOEvents.SourceIPV4\":1177773066,\"EPOEvents.SourceIPV6\":\"0:0:0:0:0:FFFF:C633:640A\",\"EPOEvents.SourceMAC\":\"010203040506\",\"EPOEvents.SourceProcessName\":\"example-source-process.exe\",\"EPOEvents.SourceURL\":\"https://source.example.com/path\",\"EPOEvents.SourceUserName\":\"EXAMPLE\\\\source_user\",\"EPOEvents.TargetFileName\":\"C:\\\\Users\\\\Public\\\\example-document.pdf\",\"EPOEvents.TargetHostName\":\"target-host.example.com\",\"EPOEvents.TargetIPV4\":1258320178,\"EPOEvents.TargetIPV6\":\"0:0:0:0:0:FFFF:CB00:7132\",\"EPOEvents.TargetMAC\":\"001122334477\",\"EPOEvents.TargetPort\":80,\"EPOEvents.TargetProcessName\":\"example-target-process.exe\",\"EPOEvents.TargetProtocol\":\"TCP\",\"EPOEvents.TargetUserName\":\"EXAMPLE\\\\target_user\",\"EPOEvents.TenantId\":1,\"EPOEvents.ThreatActionTaken\":\"blocked\",\"EPOEvents.ThreatCategory\":\"hip.process\",\"EPOEvents.ThreatEventID\":18063,\"EPOEvents.ThreatHandled\":true,\"EPOEvents.ThreatName\":\"Synthetic complete system-test event\",\"EPOEvents.ThreatSeverity\":2,\"EPOEvents.ThreatType\":\"IDS_THREAT_TYPE_VALUE_SP\"}",
        "provider": "Access Protection",
        "reason": "Synthetic complete system-test event",
        "sequence": 6,
        "severity": 2,
        "type": [
            "info"
        ]
    },
    "file": {
        "accessed": "2026-01-15T09:00:00.000Z",
        "code_signature": {
            "exists": true
        },
        "created": "2025-01-01T00:00:00.000Z",
        "directory": "C:\\Users\\Public",
        "hash": {
            "md5": "6789012345678901234ABCDEF0123456"
        },
        "mtime": "2025-01-01T00:00:00.000Z",
        "path": "C:\\Program Files\\ExampleApp",
        "size": 524288
    },
    "host": {
        "hostname": "lab-host-complete.example.com",
        "ip": [
            "198.51.100.10",
            "0:0:0:0:0:FFFF:C633:640A"
        ],
        "mac": [
            "00-AA-BB-CC-DD-EE"
        ],
        "target": {
            "hostname": "target-host.example.com"
        }
    },
    "input": {
        "type": "cel"
    },
    "message": "Synthetic complete field coverage system-test event",
    "network": {
        "transport": "tcp"
    },
    "observer": {
        "hostname": "lab-host-complete.example.com",
        "ip": [
            "198.51.100.10",
            "0:0:0:0:0:FFFF:C633:640A"
        ],
        "mac": [
            "00-AA-BB-CC-DD-EE"
        ],
        "product": "Trellix Endpoint Security",
        "version": "10.7.20.14066"
    },
    "process": {
        "code_signature": {
            "exists": true,
            "subject_name": "C=US, O=Example Corp, CN=Example Windows"
        },
        "hash": {
            "md5": "F6789012345678901234ABCDEF012345"
        },
        "name": "example-source-process.exe",
        "parent": {
            "code_signature": {
                "exists": true,
                "subject_name": "C=US, O=Example Corp, CN=Example Publisher"
            },
            "hash": {
                "md5": "FEEDFACE0123456789ABCDEFF0123456"
            },
            "name": "example-parent.exe"
        }
    },
    "related": {
        "hash": [
            "F6789012345678901234ABCDEF012345",
            "6789012345678901234ABCDEF0123456",
            "B2C3D4E5F6789012345678901234ABCD",
            "DEADBEEF0123456789ABCDEFF0123456",
            "FEEDFACE0123456789ABCDEFF0123456"
        ],
        "hosts": [
            "lab-host-complete.example.com",
            "epo-server-01.example.com"
        ],
        "ip": [
            "198.51.100.10",
            "0:0:0:0:0:FFFF:C633:640A",
            "203.0.113.50",
            "0:0:0:0:0:FFFF:CB00:7132"
        ],
        "user": [
            "EXAMPLE\\source_user",
            "EXAMPLE\\target_user"
        ]
    },
    "rule": {
        "id": "complete-rule-001",
        "name": "Synthetic complete coverage rule",
        "version": "10.7.0.14078"
    },
    "source": {
        "ip": [
            "198.51.100.10",
            "0:0:0:0:0:FFFF:C633:640A"
        ],
        "mac": "01-02-03-04-05-06",
        "port": 52000
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-threat_event"
    ],
    "threat": {
        "indicator": {
            "file": {
                "accessed": "2026-01-15T09:57:00.000Z",
                "code_signature": {
                    "exists": false,
                    "subject_name": "C=US, O=Example Corp, CN=Example Windows Publisher"
                },
                "directory": "C:\\Users\\Public",
                "name": "example-document.pdf",
                "path": "C:\\Users\\Public\\example-document.pdf",
                "size": 102400
            }
        }
    },
    "trellix_epo_on_prem": {
        "threat_event": {
            "EPExtendedEvent": {
                "AMCoreContentVersion": "1.0.0",
                "APIName": "SyntheticApiCall",
                "AccessRequested": "IDS_AAC_REQ_READ",
                "AnalyzerContentCreationDate": "2026-01-01T00:00:00.000Z",
                "AnalyzerGTIQuery": true,
                "AnalyzerRegInfo": "Synthetic analyzer registry context",
                "AnalyzerTechnologyVersion": "10.7.20.14030",
                "AttackVectorType": 3,
                "BladeName": "IDS_BLADE_NAME_FW",
                "Cleanable": true,
                "Direction": 1,
                "DurationBeforeDetection": 1200,
                "EventAutoID": "6",
                "FirstActionStatus": true,
                "FirstAttemptedAction": "blocked",
                "Location": "C:\\Example\\sample.exe",
                "SecondActionStatus": false,
                "SecondAttemptedAction": "quarantined",
                "SourceDescription": "EXAMPLE AGENT MODULE",
                "SourceDevicePID": "PCI\\VEN_8086&DEV_1234&SUBSYS_00000000&REV_01\\4&abc&0&00A8",
                "SourceDeviceSerialNumber": "EXAMPLE-SOURCE-SERIAL-0001",
                "SourceDeviceVID": "PCI\\VEN_8086&DEV_1234&SUBSYS_00000000&REV_01\\4&abc&0&00A8",
                "SourceHash": "DEADBEEF0123456789ABCDEFF0123456",
                "SourceShareName": "\\\\source-host.example.com\\share",
                "SourceURLRatingCode": "trusted",
                "SourceURLWebCategory": "business",
                "TargetCreateTime": "2025-04-01T08:00:00.000Z",
                "TargetDescription": "Synthetic target description",
                "TargetDeviceDisplayName": "Example Target Device",
                "TargetDevicePID": "DEV_5678",
                "TargetDeviceSerialNumber": "EXAMPLE-TARGET-SERIAL-0001",
                "TargetDeviceVID": "VEN_1234",
                "TargetModifyTime": "2025-04-01T08:00:00.000Z",
                "TargetParentProcessHash": "B2C3D4E5F6789012345678901234ABCD",
                "TargetParentProcessName": "parent-app.exe",
                "TargetParentProcessSigned": true,
                "TargetParentProcessSigner": "C=US, O=Example Corp, CN=Example Code Signing",
                "TargetShareName": "\\\\target-host.example.com\\share",
                "TargetURL": "https://target.example.com/resource",
                "TaskName": "Synthetic Scan Task",
                "ThreatDetectedOnCreation": true,
                "ThreatImpact": "low",
                "Topic": "Synthetic threat topic"
            },
            "EPOEvents": {
                "AgentGUID": "77777777-8888-4999-8AAA-BBBBBBBBBB07",
                "Analyzer": "ENDP_TEST_1000",
                "AnalyzerDATVersion": "9999.0",
                "AnalyzerEngineVersion": "1.2.3",
                "DetectedUTC": "2026-01-15T10:00:05.000Z",
                "EventTimeLocal": "2026-01-15T10:00:05.000Z",
                "ServerID": "epo-server-01.example.com",
                "SourceHostName": "source-host.example.com",
                "SourceURL": "https://source.example.com/path",
                "TargetProcessName": "example-target-process.exe",
                "TenantId": "1",
                "ThreatActionTaken": "blocked",
                "ThreatCategory": "hip.process",
                "ThreatHandled": true,
                "ThreatType": "IDS_THREAT_TYPE_VALUE_SP"
            }
        }
    },
    "user": {
        "name": "EXAMPLE\\source_user",
        "target": {
            "name": "EXAMPLE\\target_user"
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
* **DLP incident**: Collects DLP incident records through the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from `UDLP_EPD_Incidents` and ordered by `LastUpdateTimestamp`, which is used as an inclusive time cursor.
* **Threat event**: Collects threat event records through the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried using the `EPExtendedEvent` target, fields are selected from `EPOEvents` and `EPExtendedEvent`, and pagination is keyset-based using `EPOEvents.AutoID` as the cursor.
