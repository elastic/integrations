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

### Event

The `event` data stream provides Trellix ePO On-Prem event logs received over TCP or UDP syslog.

#### Event fields

{{ fields "event" }}

### Example event

#### Event

{{ event "event" }}

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
