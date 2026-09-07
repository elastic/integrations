# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. It offers comprehensive audit logging for system administration, user activity, policy changes, and security-related actions, and its Web Control component logs web browsing activity together with content and reputation ratings applied to each visited URL — combining authentication, authorization, detailed audit trails, and web usage monitoring into a unified platform for **critical security infrastructure monitoring and compliance**.

The Trellix ePO On-Prem integration for Elastic collects audit and web control logs using the **REST / Web API** via CEL input, and endpoint security event records forwarded over **TCP or UDP syslog**, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with REST API / Web API support enabled. Syslog event collection requires a Trellix ePO deployment configured to forward RFC 5424 syslog messages containing XML `EPOEvent` payloads.

### How it works

For the `audit` and `web_control` data streams, this integration uses the Elastic Agent CEL input to poll the Trellix ePO REST / Web API at configurable intervals. It retrieves audit log records from the `OrionAuditLog` table using keyset-based pagination with cursor timestamps, and web control event records from the `WP_EventInfo` table using a keyset cursor on the numeric `EventAutoID` field (because `WP_EventInfo` has no timestamp column). Each poll for web control requests events with `EventAutoID` greater than the last persisted value, orders results ascending by `EventAutoID`, and persists the highest `EventAutoID` returned for the next poll.

For the `event` data stream, the integration uses the Elastic Agent TCP or UDP input to receive events forwarded by Trellix ePO. For each received event, it:

1. Receives an RFC 5424 syslog message on the configured listen address and port.
2. Extracts the embedded XML payload from the syslog message.
3. Decodes the `EPOEvent` XML object and maps endpoint, network, file, user, registry, and threat details to Elastic Common Schema (ECS).
4. Emits each decoded record as an individual event for ingestion and enrichment by the built-in ingest pipeline.

Each event is mapped to Elastic Common Schema (ECS) for standardized field naming and ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `audit` | Trellix ePO audit log records, including system administration, policy changes, user activity, and security-related actions retrieved from the ePO REST API. | `/remote/core.executeQuery` API |
| `web_control` | Trellix ePO web control event records, including browsed URLs, user names, content/category ratings (phishing, spam, download, exploit, bad-link, pop-up), overall rating, list/reason/action identifiers, and per-event counts, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |
| `event` | Trellix ePO event-forwarder records, including endpoint security, threat prevention, web control, data loss prevention, product, authentication, and reputation events received over TCP or UDP syslog. | TCP / UDP syslog |

### Supported use cases

Integrating Trellix ePO with Elastic provides centralized visibility into system administration, user activity, and policy changes across your ePO deployment, enabling efficient audit trail monitoring, compliance reporting, and security investigation within Kibana dashboards.

Integrating Trellix ePO Web Control with Elastic provides centralized visibility into user web browsing activity and the ratings/categories Web Control applies to that traffic, enabling web usage monitoring, threat and risk investigation (phishing, spam, exploit, malicious downloads), and policy-violation reporting within Kibana dashboards.

* **Threat detection and investigation**: Monitor malware detections, prevention actions, threat severity, affected endpoints, files, users, and network activity.

* **Endpoint and administrative monitoring**: Analyze endpoint product events, policy-related activity, user actions, authentication events, and reputation changes reported through Trellix ePO.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the REST / Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with REST API / Web API enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `OrionAuditLog` table (or `OrionAuditLogMT` for multitenant deployments) and/or the `WP_EventInfo` table.
   - Sufficient role permissions to execute queries via the Web API.
3. **API credentials**: Username and password for basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server (default port: 8443, for example `https://epo.example.com:8443`).
5. **Network access**: The Elastic Agent must have outbound HTTPS access to the ePO server.

For more information on configuring REST API access in Trellix ePO, refer to the [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html).

To collect event logs over syslog, you need the following:

* **Trellix ePO deployment**: An active Trellix ePO On-Prem server capable of forwarding events over syslog.
* **Event forwarding enabled**: Configure Trellix ePO to forward RFC 5424 syslog messages containing XML `EPOEvent` payloads to the Elastic Agent host and port.
* **Network access**: The Trellix ePO server must be able to reach the Elastic Agent over the configured TCP or UDP port.
* **Elastic Agent**: An Elastic Agent enrolled in Fleet and installed on a host that can receive the forwarded syslog traffic.

## How do I deploy this integration?

The `audit` and `web_control` data streams support both Elastic Agentless-based and Agent-based installations. The `event` data stream is collected over syslog and therefore supports Agent-based installation only.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

For syslog collection, Elastic Agent is required to receive the syslog events and ship the data to Elastic, where the events are processed by the integration's ingest pipeline.

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
        * Set **Initial Event Auto Id** to the starting `EventAutoID` from which to begin querying events. Subsequent collections resume from the last persisted `EventAutoID`. Set to `0` to start from the beginning (default: `0`).
        * Set **Interval** to the polling frequency. The default is `5m`.
        * Set **Page Size** to the number of audit log records to retrieve per API request. The default is `500`.
        * Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.
    * For **web control** logs:
        * Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
        * Set **Username** for the ePO user account with `WP_EventInfo` query permissions.
        * Set **Password** for the ePO user account.
        * Set **Initial Event Auto Id** to the starting `EventAutoID` from which to begin querying events. Subsequent collections resume from the last persisted `EventAutoID`. Set to `0` to start from the beginning (default: `0`).
        * Set **Interval** to the polling frequency. The default is `5m`.
        * Set **Page Size** to the number of web control log records to retrieve per API request. The default is `500`.
        * Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.
    * For **event** logs over syslog:
        * Enable either the TCP or UDP input.
        * Set the **Listen Address** and **Listen Port** to the address and port that Trellix ePO will use as its syslog destination.
        * For TCP with TLS, configure the certificate and key under **SSL Configuration**.
        * Configure Trellix ePO to forward events to the Elastic Agent host using the same protocol and port.

6. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected (API)**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `OrionAuditLog` and/or `WP_EventInfo` tables.
* **No data collected (syslog)**: Verify that Trellix ePO event forwarding is enabled and points to the correct Elastic Agent host, protocol, and port. Confirm that network and firewall rules allow traffic to the configured listener.
* **XML payload is not decoded**: Confirm that forwarded messages contain an XML `EPOEvent` payload and that the complete event is delivered as a single syslog message.
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
5. Open the **[Logs Trellix ePO On-Prem] Event** dashboard and verify that the visualizations are populated with event data, including event trends, categories, actions, hosts, users, threats, files, and source locations.

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

### Event

The `event` data stream provides Trellix ePO On-Prem event logs received over TCP or UDP syslog.

#### Event fields

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
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| trellix_epo_on_prem.event.EPOEvent.APIName | API name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AccessRequested | Access requested reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ActionID | Action id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AgentGUID | Agent GUID reported in the 'EPOEvent.MachineInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Analyzer | Analyzer reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerDATVersion | Analyzer DAT version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerDetectionMethod | Analyzer detection method reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerEngineVersion | Analyzer engine version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerGTIQuery | Analyzer GTI query reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerName | Analyzer name reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerVersion | Analyzer version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AttackVectorType | Attack vector type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.BadLinkRatingID | Bad link rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.BladeName | Blade name reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Cleanable | Cleanable reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.ContentFuncGroup | Content func group reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ContentName | Content name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ContentRiskGroup | Content risk group reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Count | Count reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.DAT_Version | DAT version reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.DetectedUTC | Detected UTC reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.DetectionMethod | Detection method reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.DownloadRatingID | Download rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.DurationBeforeDetection | Duration before detection reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.EventType | Event type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ExploitRatingID | Exploit rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.FirstActionStatus | First action status reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.FirstAttemptedAction | First attempted action reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Hostname | Hostname reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ListID | List id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ListType | List type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.MachineInfo.AgentGUID | Agent GUID reported in the 'EPOEvent.MachineInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.MachineInfo.TimeZoneBias | Time zone bias reported in the 'EPOEvent.MachineInfo' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.ObserverMode | Observer mode reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.PhishingRatingID | Phishing rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.PopupRatingID | Popup rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Priority | Priority reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.ProductFamily | Product family reported in the 'EPOEvent.SoftwareInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Rating | Rating reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ReasonID | Reason id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ReasonType | Reason type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.RegistryValue | Registry value reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SecondActionStatus | Second action status reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SecondAttemptedAction | Second attempted action reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ServerID | Server id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SignatureName | Signature name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SiteName | Site name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.Analyzer | Analyzer reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerDATVersion | Analyzer DAT version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerDetectionMethod | Analyzer detection method reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerEngineVersion | Analyzer engine version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerName | Analyzer name reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerVersion | Analyzer version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.DetectedUTC | Detected UTC reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.ThreatEventID | Threat event id reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.ThreatHandled | Threat handled reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | boolean |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.ThreatSeverity | Threat severity reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.ThreatType | Threat type reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CustomFields.AnalyzerContentCreationDate | Analyzer content creation date reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CustomFields.BladeName | Blade name reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CustomFields.ThreatDetectedOnCreation | Threat detected on creation reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | boolean |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CustomFields.target | Target reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.GMTTime | GMT time reported in the 'EPOEvent.SoftwareInfo.Event' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.Severity | Severity reported in the 'EPOEvent.SoftwareInfo.Event' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.ProductFamily | Product family reported in the 'EPOEvent.SoftwareInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.ProductName | Product name reported in the 'EPOEvent.SoftwareInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.ProductVersion | Product version reported in the 'EPOEvent.SoftwareInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SourceFileSize | Source file size reported in the 'EPOEvent' source section. | double |
| trellix_epo_on_prem.event.EPOEvent.SourceProcessName | Source process name reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SpamRatingID | Spam rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Success | Success reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.TVDSeverity | TVD severity reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.TargetName | Target name reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.TargetPath | Target path reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.TaskName | Task name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ThreatDetectedOnCreation | Threat detected on creation reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ThreatHandled | Threat handled reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ThreatSeverity | Threat severity reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.ThreatType | Threat type reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.USBSerialNumber | USB serial number reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Vendor | Vendor reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Version | Version reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.agentGuid | Agent GUID reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.detectionTime | Detection time recorded for the file reputation event. | date |
| trellix_epo_on_prem.event.EPOEvent.jtiObjectType | JTI object type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.jtiReputation | JTI reputation reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.localReputation | Local reputation reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.newReputations.trustLevel | Trust level reported in the 'EPOEvent.newReputations' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.oldReputations.trustLevel | Trust level reported in the 'EPOEvent.newReputations' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.remediationAction | Remediation action reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.siem_last_time | Siem last time reported in the 'EPOEvent' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.wpRating | Wp rating reported in the 'EPOEvent' source section. | keyword |


### Example event

#### Event

An example event for `event` looks as following:

```json
{
    "@timestamp": "2021-05-03T06:27:04.753Z",
    "agent": {
        "ephemeral_id": "3cc56a96-7804-4a32-9e01-841198395023",
        "id": "8ee8f26c-cd67-4672-a3ad-aafd550de929",
        "name": "elastic-agent-48957",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.event",
        "namespace": "69500",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": [
            "198.51.100.10",
            "::ffff:198.51.100.10"
        ],
        "mac": "00-00-5E-00-53-24",
        "port": 443
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "8ee8f26c-cd67-4672-a3ad-aafd550de929",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "ids-alert-act-tak-del",
        "agent_id_status": "verified",
        "dataset": "trellix_epo_on_prem.event",
        "id": "01234567-ABCD-ABCD-ABCD-ABCD01234567",
        "ingested": "2026-09-04T06:10:49Z",
        "kind": "event",
        "original": "{\"EPOEvent\":{\"AnalyzerName\":\"Trellix EndpointSecurity\",\"APIName\":\"CreateFile\",\"Files\":\"C:\\\\temp\\\\file.exe\",\"HostName\":\"host-1.example.local\",\"TargetProtocol\":\"TCP\",\"Analyzer\":\"ENDP_AM_1120\",\"TargetFileSize\":\"68\",\"AnalyzerVersion\":\"198.51.100.10\",\"RegistryValue\":\"1\",\"TargetIPv6\":\"::ffff:198.51.100.10\",\"RemotePort\":\"443\",\"AnalyzerDetectionMethod\":\"On-Demand Scan\",\"ServerID\":\"epo-server-1.example.local\",\"DetectedUTC\":\"2021-05-03 06:26:21.0\",\"Direction\":\"inbound\",\"TaskName\":\"Host IPS protection\",\"ThreatCategory\":\"av.detect\",\"siem_last_time\":\"2021-05-03 06:27:04\",\"ReceivedUTC\":\"2021-05-03 06:27:04.753\",\"SourceHostName\":\"host-1.example.local\",\"Hash\":\"44d88612fea8a8f36de82e1278abb02f\",\"SecondAttemptedAction\":\"IDS_ALERT_THACT_ATT_DEL\",\"RegistryKey\":\"HKLM\\\\Software\\\\Test\\\\Key\",\"AnalyzerIPv6\":\"::ffff:198.51.100.10\",\"ThreatSeverity\":\"2\",\"SourceFilePath\":\"C:\\\\Temp\",\"TargetFileName\":\"eicar.com\",\"SignatureName\":\"Buffer Overflow Detected\",\"SourceMAC\":\"00005e005323\",\"TargetMAC\":\"00005e005324\",\"Subject\":\"Malware Detected\",\"SourceIPv4\":\"198.51.100.10\",\"Vendor\":\"Trellix\",\"ThreatDetectedOnCreation\":\"0\",\"SourceIPv6\":\"::ffff:198.51.100.10\",\"Cleanable\":\"0\",\"TargetHostName\":\"host-1.example.local\",\"BladeName\":\"IDS_BLADE_NAME_SPB\",\"AccessRequested\":\"read\",\"TargetIPv4\":\"198.51.100.10\",\"LocalPort\":\"12345\",\"AutoGUID\":\"01234567-ABCD-ABCD-ABCD-ABCD01234567\",\"TargetProcessName\":\"firefox.exe\",\"ThreatActionTaken\":\"IDS_ALERT_ACT_TAK_DEL\",\"SourceUserName\":\"EXAMPLE\\\\alice.johnson\",\"AnalyzerEngineVersion\":\"5800.7501\",\"AutoID\":\"17443183\",\"SourcePort\":\"12345\",\"SourceFileSize\":\"68\",\"TargetName\":\"eicar.com\",\"SourceProcessName\":\"On-Demand Scan\",\"ThreatHandled\":\"1\",\"AgentGUID\":\"01234567-ABCD-ABCD-ABCD-ABCD01234567\",\"AnalyzerIPv4\":\"198.51.100.10\",\"TargetUserName\":\"EXAMPLE\\\\alice.johnson\",\"AnalyzerGTIQuery\":\"0\",\"FirstAttemptedAction\":\"IDS_ALERT_THACT_ATT_CLE\",\"ProductFamily\":\"HOSTIPS\",\"ThreatType\":\"test\"}}",
        "outcome": "success",
        "sequence": 17443183,
        "severity": 2
    },
    "file": {
        "hash": {
            "md5": "44d88612fea8a8f36de82e1278abb02f"
        },
        "name": "eicar.com",
        "path": "C:\\Temp",
        "size": 68
    },
    "host": {
        "name": "host-1.example.local"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.247.3:51498"
        }
    },
    "message": "Malware Detected",
    "network": {
        "direction": "inbound",
        "transport": "tcp"
    },
    "observer": {
        "ip": [
            "198.51.100.10",
            "::ffff:198.51.100.10"
        ]
    },
    "process": {
        "name": "firefox.exe"
    },
    "registry": {
        "key": "HKLM\\Software\\Test\\Key"
    },
    "related": {
        "hash": [
            "44d88612fea8a8f36de82e1278abb02f"
        ],
        "hosts": [
            "host-1.example.local"
        ],
        "ip": [
            "::ffff:198.51.100.10",
            "198.51.100.10"
        ],
        "user": [
            "EXAMPLE\\alice.johnson"
        ]
    },
    "source": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": [
            "198.51.100.10",
            "::ffff:198.51.100.10"
        ],
        "mac": "00-00-5E-00-53-23",
        "port": 12345,
        "user": {
            "domain": "EXAMPLE",
            "name": "alice.johnson"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-event"
    ],
    "trellix_epo_on_prem": {
        "event": {
            "EPOEvent": {
                "APIName": "CreateFile",
                "AccessRequested": "read",
                "AgentGUID": "01234567-ABCD-ABCD-ABCD-ABCD01234567",
                "Analyzer": "ENDP_AM_1120",
                "AnalyzerDetectionMethod": "On-Demand Scan",
                "AnalyzerEngineVersion": "5800.7501",
                "AnalyzerGTIQuery": "0",
                "AnalyzerName": "Trellix EndpointSecurity",
                "AnalyzerVersion": "198.51.100.10",
                "BladeName": "IDS_BLADE_NAME_SPB",
                "Cleanable": 0,
                "DetectedUTC": "2021-05-03T06:26:21.000Z",
                "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE",
                "ProductFamily": "HOSTIPS",
                "RegistryValue": "1",
                "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL",
                "ServerID": "epo-server-1.example.local",
                "SignatureName": "Buffer Overflow Detected",
                "SourceFileSize": 68,
                "SourceProcessName": "On-Demand Scan",
                "TargetName": "eicar.com",
                "TaskName": "Host IPS protection",
                "ThreatDetectedOnCreation": "0",
                "ThreatHandled": "1",
                "ThreatSeverity": 2,
                "ThreatType": "test",
                "Vendor": "Trellix",
                "siem_last_time": "2021-05-03T06:27:04.000Z"
            }
        }
    },
    "user": {
        "target": {
            "domain": "EXAMPLE",
            "name": "alice.johnson"
        }
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
- [TCP](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-tcp)
- [UDP](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-udp)

### API usage

This integration uses the following API:

* **Audit**: Collects audit log records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `OrionAuditLog` table using keyset-based pagination with the `StartTime` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Web Control**: Collects web control event records via the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`). Records are queried from the `WP_EventInfo` table using keyset-based pagination with the `EventAutoID` field as a cursor to ensure efficient and non-duplicating retrieval.
* **Event**: Does not use an API. Event records are pushed by the Trellix ePO event forwarder to the Elastic Agent as RFC 5424 syslog messages over TCP or UDP.
