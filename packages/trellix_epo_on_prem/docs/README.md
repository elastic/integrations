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

#### Device event

An example event for `device_event` looks as following:

```json
{
    "@timestamp": "2026-07-31T08:15:42.000Z",
    "agent": {
        "ephemeral_id": "798e56ae-8cd2-4f8b-a5ff-bab31ebbdce5",
        "id": "11111111-2222-4333-8444-555555555555",
        "name": "elastic-agent-29845",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.device_event",
        "namespace": "71424",
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
        "id": "09dcb27f-1ea3-4563-b32a-df8d2b5efc8b",
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
        "ingested": "2026-08-03T06:12:36Z",
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
        "domain": "EXAMPLE",
        "name": "analyst"
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

- **Device event**: Collects removable-media device event records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried from `EEFFDeviceAllEventsView` using a time-based cursor with `EventGeneratedTime`.
