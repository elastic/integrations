# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epo/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization.

The Trellix ePO On-Prem integration for Elastic collects logs using the Trellix ePO REST / Web API and events forwarded over syslog, and lets you visualize that data in Kibana.

### Compatibility

This integration collects data from the Trellix ePO On-Prem REST / Web API and from events forwarded over syslog. It has been tested against the Trellix ePO On-Prem Web API. To collect the `event` data stream, Trellix ePO must be configured to forward RFC 5424 syslog messages containing XML `EPOEvent` payloads.

### How it works

For the API-based data streams, this integration periodically queries the Trellix ePO REST / Web API to retrieve records for each enabled data stream. For the `event` data stream, Elastic Agent listens for events that Trellix ePO forwards over TCP syslog. Each record is mapped to the Elastic Common Schema (ECS) and enriched by the integration's ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `audit` | Audit log records covering system administration, policy changes, user activity, and other security-related actions. | `/remote/core.executeQuery` API |
| `web_control` | Web control events, including browsed URLs, the acting user, and the content/category ratings and actions Web Control applied. | `/remote/core.executeQuery` API |
| `compliance_history` | Point-in-time compliance snapshots, including evaluated computer counts and compliant/noncompliant counts and percentages per reporting task. | `/remote/core.executeQuery` API |
| `system` | Managed system (endpoint) records from the System Tree, including agent identity and version, managed and communication state, node placement, and tag assignment. | `/remote/core.executeQuery` API |
| `product_event` | Product operation events on managed endpoints, including the operation type and initiator, the affected product, the acting user, and the event outcome. | `/remote/core.executeQuery` API |
| `device_event` | Removable-media device control events, including device backup, protection, and initialization status and the associated agent and user. | `/remote/core.executeQuery` API |
| `dlp_incident` | Data Loss Prevention incidents, including violation time, severity, status, evidence counts, classifications, and matched rules and actions. | `/remote/core.executeQuery` API |
| `threat_event` | Endpoint threat events with matching extended details, including detections, rules, actions, severity, network activity, files, processes, and related entities. | `/remote/core.executeQuery` API |
| `event` | Endpoint security events forwarded by Trellix ePO over syslog, including threat, web control, data loss prevention, product, authentication, and reputation events. | TCP syslog |

### Supported use cases

Integrating Trellix ePO On-Prem with Elastic provides centralized visibility into endpoint security and administrative activity across your ePO deployment. Dashboards give insight into audit trails, web usage, endpoint inventory and compliance, product and device activity, and threat and DLP detections, helping SOC teams monitor policy compliance, investigate incidents, and correlate activity across hosts, users, and files within Kibana.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the REST / Web API, you need the following:

1. A Trellix ePO On-Prem server with the REST API / Web API enabled.
2. A Trellix ePO user account with query permissions to the tables that back the data streams you enable, and sufficient role permissions to run queries through the Web API:

   | Data stream | Table(s) |
   |---|---|
   | `audit` | `OrionAuditLog` (or `OrionAuditLogMT` for multitenant deployments) |
   | `web_control` | `WP_EventInfo` |
   | `compliance_history` | `EpoComplianceHistory` |
   | `system` | `EPOLeafNode` |
   | `product_event` | `EPOProductEvents` |
   | `device_event` | `EEFFDeviceAllEventsView` |
   | `dlp_incident` | `UDLP_EPD_Incidents` |
   | `threat_event` | `EPOEvents` and `EPExtendedEvent` |

3. Username and password for basic authentication.
4. The base URL of the Trellix ePO server (default port: 8443, for example `https://epo.example.com:8443`).
5. Outbound HTTPS access from the Elastic Agent to the ePO server.

> **Note:** To collect the `compliance_history` data stream, the Trellix ePO compliance history reporting task must be configured and producing records.

For more information on configuring REST API access in Trellix ePO, refer to the [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html).

To collect the `event` data stream over syslog, you need the following:

1. A Trellix ePO On-Prem deployment configured to forward events over syslog.
2. A registered syslog server in Trellix ePO that points at the Elastic Agent host and port. To set this up, refer to [Register syslog servers](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-8919f78f-0968-023f-449b-b2899a6d9c7f.html) in the Trellix ePO documentation.
3. Network access from the Trellix ePO server (and any Agent Handlers) to the Elastic Agent over the configured port.
4. An Elastic Agent enrolled in Fleet and installed on a host that can receive the forwarded syslog traffic.

## How do I deploy this integration?

The API-based data streams support both Elastic Managed (Agentless) and Agent-based installations. The `event` data stream is collected over syslog and therefore supports Agent-based installation only.

### Elastic Managed installation

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Trellix ePO On-Prem**.
3. Select the **Trellix ePO On-Prem** integration from the search results.
4. Select **Add Trellix ePO On-Prem** to add the integration.
5. Enable and configure only the collection methods you will use.

    * To collect logs over the REST / Web API, set the **Trellix ePO URL**, **Username**, and **Password**, then enable the data streams you need and adjust their parameters (such as interval, initial cursor, and page size) if required.
    * To collect the `event` data stream over syslog, enable the TCP input, set the **Listen Address** and **Listen Port** that Trellix ePO will forward to, configure the TLS certificate and key, then configure Trellix ePO to forward events to that host and port. Trellix ePO forwards syslog only over TCP with TLS.

6. Select **Save and continue** to save the integration.

## Troubleshooting

* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the required tables.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all fields configured in the integration (the select clause in the CEL template).
* **XML payload is not decoded**: Confirm that forwarded messages contain an XML `EPOEvent` payload and that the complete event is delivered as a single syslog message.
* **Missing expected threat events**: The `threat_event` query uses `EPExtendedEvent` as its target and collects only events that have matching extended details.
* **Pagination issues**: If a data stream stops advancing beyond the initial set of records, verify that its cursor field is present and increasing in the source table and that the persisted cursor is being updated between polls.
* **Missing historical data**: If older records are missing after the first collection, lower the initial cursor or increase the initial lookback (for example, **Initial Event Auto ID**, **Initial Auto ID**, or **Initial Interval**) so the first request starts from an earlier point.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify the dashboard information is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links

- [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html)
- [Trellix ePO Web API Query Language](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-cd01321d-b19b-5095-c79b-eabc7c0726bb.html)
- [Register syslog servers](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-8919f78f-0968-023f-449b-b2899a6d9c7f.html)
- [Trellix ePO 5.10.0 Product Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-3946078c-6e32-df76-6296-216ee05a2176.html)

### audit

This is the `audit` data stream.

{{event "audit"}}

{{fields "audit"}}

### web_control

This is the `web_control` data stream.

{{event "web_control"}}

{{fields "web_control"}}

### compliance_history

This is the `compliance_history` data stream.

{{event "compliance_history"}}

{{fields "compliance_history"}}

### system

This is the `system` data stream.

{{event "system"}}

{{fields "system"}}

### product_event

This is the `product_event` data stream.

{{event "product_event"}}

{{fields "product_event"}}

### device_event

This is the `device_event` data stream.

{{event "device_event"}}

{{fields "device_event"}}

### dlp_incident

This is the `dlp_incident` data stream.

{{event "dlp_incident"}}

{{fields "dlp_incident"}}

### threat_event

This is the `threat_event` data stream.

{{event "threat_event"}}

{{fields "threat_event"}}

### event

This is the `event` data stream.

{{event "event"}}

{{fields "event"}}

### Inputs used

These inputs are used in this integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
- [TCP](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-tcp)

### API usage

This integration uses the **Trellix ePO executeQuery API** (endpoint: `/remote/core.executeQuery`) for the API-based data streams:

| Data stream | Table |
|---|---|
| `audit` | `OrionAuditLog` |
| `web_control` | `WP_EventInfo` |
| `compliance_history` | `EpoComplianceHistory` |
| `system` | `EPOLeafNode` |
| `product_event` | `EPOProductEvents` |
| `device_event` | `EEFFDeviceAllEventsView` |
| `dlp_incident` | `UDLP_EPD_Incidents` |
| `threat_event` | `EPOEvents` and `EPExtendedEvent` |

The `event` data stream does not use an API. Event records are pushed by the Trellix ePO event forwarder to the Elastic Agent as RFC 5424 syslog messages over TCP with TLS.
