# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. Its removable-media device control component logs USB and other removable-storage device activity — connections, backup status, protection/initialization state, and the user's response to device policy prompts — providing visibility into **removable-media usage and data-loss-prevention posture**.

The Trellix ePO On-Prem integration for Elastic collects device event logs using the **Web API** via CEL input, and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO Web API at configurable intervals. It retrieves device event records from the `EEFFDeviceAllEventsView` table using a time-based cursor on `EventGeneratedTime`: each poll requests events at or after the last persisted timestamp, orders results ascending by `EventGeneratedTime`, and persists the latest timestamp returned for the next poll. The cursor boundary is intentionally inclusive on both ends, so the same event can be returned on two consecutive polls; the ingest pipeline deduplicates it by computing a stable document `_id` from the event's `AutoID`.

Each event is mapped to Elastic Common Schema (ECS) for standardized field naming and ingested as an individual event for enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following types of data:

| Data stream | Description | Source |
|---|---|---|
| `device_event` | Trellix ePO removable-media device event records, including device backup size/state/time, protection and initialization status, file system details, the associated agent and user, and vendor/product identifiers, retrieved from the ePO Web API. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO device events with Elastic provides visibility into removable-media device activity across endpoints, enabling data-loss-prevention monitoring, investigation of device protection/backup status, and reporting on user responses to device control policies within Kibana dashboards.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data via the Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with Web API support enabled.
2. **User account**: A Trellix ePO user account with:
   - **Query permissions** to the `EEFFDeviceAllEventsView` table.
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
5. Enable and configure the **Collect Trellix ePO Logs** collection method.

   - Set **Trellix ePO URL** to the base URL of your Trellix ePO server, for example `https://epo.example.com:8443`.
   - Set **Username** for the ePO user account with `EEFFDeviceAllEventsView` query permissions.
   - Set **Password** for the ePO user account.
   - Set **Initial Interval** to how far back to pull device events on the first run, for example `24h`.
   - Set **Interval** to the duration between device event collection requests. The default is `5m`.
   - Set **Maximum Pages Per Interval** to the maximum number of pages collected at each interval. The default is `1000`.
   - Set **Page Size** to the number of device event log records fetched per API request. The default is `500`.
   - Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.

6. Select **Save and continue** to save the integration.

## Troubleshooting

* **No data collected**: Verify that the Trellix ePO API URL is correct, credentials are valid, and the Elastic Agent has network access to the ePO server. Check that the user account has permissions to query the `EEFFDeviceAllEventsView` table.
* **Authentication failures**: Ensure the username and password are correct and the user account has not been locked or disabled in Trellix ePO. Verify the account has sufficient permissions to access the `EEFFDeviceAllEventsView` table.
* **Incomplete or missing fields**: Confirm that the ePO user account has sufficient permissions to access all `EEFFDeviceAllEventsView` columns configured in the integration (select clause in the CEL template).
* **Pagination issues**: If device event logs are not advancing, or the same events keep reappearing, verify that `EventGeneratedTime` values are increasing in the source table and that the persisted timestamp cursor is being correctly updated between polls. A small amount of overlap at the poll boundary is expected and deduplicated by the ingest pipeline's fingerprint-based document ID.
* **SSL certificate errors**: If your Trellix ePO server uses a self-signed certificate, extract the certificate and configure it under the SSL settings of the integration, or add it to the Elastic Agent's trusted certificate store.
* **Network connectivity issues**: Verify firewall rules allow outbound HTTPS traffic from the Elastic Agent host to the Trellix ePO server on the configured port.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify that the dashboard is listed.
3. Open the **[Logs Trellix ePO On-Prem] Device Event** dashboard and verify that Device Event data is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links

- [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html)
- [Trellix ePO Web API Query Language](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-cd01321d-b19b-5095-c79b-eabc7c0726bb.html)
- [Trellix ePO 5.10.0 Product Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-3946078c-6e32-df76-6296-216ee05a2176.html)

### Device event

The `device_event` data stream provides Trellix ePO On-Prem removable-media device event records collected from the Web API.

#### Device event fields

{{ fields "device_event" }}

### Example event

#### Device event

{{ event "device_event" }}

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

- **Device event**: Collects removable-media device event records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried from `EEFFDeviceAllEventsView` using a time-based cursor with `EventGeneratedTime`.
