# ESET PROTECT

## Overview

ESET PROTECT enables you to manage ESET products on workstations and servers in a networked environment with up to 50,000 devices from one central location. Using the ESET PROTECT Web Console, you can deploy ESET solutions, manage tasks, enforce security policies, monitor system status, and quickly respond to problems or threats on remote computers.

### Compatibility

This integration supports ESET PROTECT Cloud services that expose the ESET Connect APIs in the `eu`, `de`, `us`, `ca`, and `jpn` regions. The Event data stream supports JSON payloads from ESET PROTECT Syslog Forwarder.

### How it works

The Detection, Device, Device Task, and Device Vulnerability data streams periodically query the regional ESET Connect APIs. The Event data stream listens for JSON security and audit events that ESET PROTECT sends over TCP with optional TLS.

## What data does this integration collect?

The ESET PROTECT integration collects five data streams:

**[Detection](https://help.eset.com/eset_connect/en-US/incident_management_v1_detections_get.html)** retrieves detections from the ESET Connect Incident Management API.

**[Device](https://help.eset.com/eset_connect/en-US/device_management_v1_devices_get.html)** retrieves managed-device inventory from the ESET Connect Device Management API.

**[Device Task](https://help.eset.com/eset_connect/en-US/automation_v1_device_tasks_get.html)** retrieves task definitions from the ESET Connect Automation API.

**[Device Vulnerability](https://help.eset.com/eset_connect/en-US/vulnerability_management_v1_device-vulnerabilities_get.html)** retrieves current per-device vulnerability findings from the ESET Connect Vulnerability Management API.

**Event** receives JSON security and audit events from the [ESET PROTECT Syslog Forwarder](https://help.eset.com/protect_cloud/en-US/syslog_forwarder.html). ESET notifications are also received, but their message content is administrator-defined plain text.

### Supported use cases

Use this integration to monitor endpoint detections, investigate security events, track managed-device inventory and task definitions, and assess current device vulnerabilities in Elastic.

## What do I need to use this integration?

### From ESET PROTECT

The ESET Connect API data streams require:

- A dedicated API user with **Integrations** access.
- Read permissions for the intended products and static groups.
- Outbound HTTPS access from the collector to the regional ESET authentication and API endpoints.

The Event data stream requires ESET PROTECT Syslog Forwarder and network access from ESET PROTECT to the TCP/TLS listener.

### From Elastic

The four ESET Connect API data streams support Elastic Managed and Agent-based deployments. Elastic Managed integrations are available on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. Elastic runs the collector, so you do not need to manage the collection infrastructure. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

The Event data stream requires an Agent-based deployment on a host that can accept connections from ESET PROTECT.

## How do I deploy this integration?

### Onboard and configure

#### Collect data from ESET Connect

1. [Create a dedicated API user account](https://help.eset.com/eset_connect/en-US/create_api_user_account.html). Enable **Integrations** access and assign the required read permissions.
2. Complete the API user invitation. An ESET PROTECT Hub API user must sign in to the Hub at least once before using the API.
3. Record the API user's username and password.
4. Identify the service region used by the ESET tenant: `eu`, `de`, `us`, `ca`, or `jpn`.

#### Collect data from ESET PROTECT via Syslog

Use an Agent-based deployment for this data stream. In ESET PROTECT, open **Marketplace** → **Integrations**, add [Syslog Forwarder](https://help.eset.com/protect_cloud/en-US/syslog_forwarder.html), and configure the following settings:

1. Set **Payload** to **JSON**. Notifications remain administrator-defined plain text.
2. Set **Envelope** to **Syslog**.
3. Set the minimum log level to **Information** to collect all severities.
4. Select the required Antivirus, HIPS, Firewall, Web protection, Audit Log, Blocked files, ESET Inspect, and Incident event types.
5. Enter the public IPv4 address or FQDN and port that route to the Elastic Agent. The integration's default port is `6514`.
6. Enable TLS and configure certificate validation as required. The server certificate presented by Elastic Agent must match the destination name and include the complete trusted certificate chain.

ESET enables RFC 6587 octet-counted framing by default. When octet counting is enabled in ESET, add the following under **Custom TCP Options**:

```yaml
framing: rfc6587
max_message_size: 50KiB
```

Alternatively, turn off octet-counted framing in ESET and use the integration's default delimiter framing.

ESET truncates exported messages larger than 8 KB, sends a `HEARTBEAT` message every one to three minutes, and does not buffer events while the destination is unavailable. Events generated during an outage are not replayed after connectivity is restored. For more information, refer to [Syslog restrictions and limits](https://help.eset.com/protect_cloud/en-US/syslogexportsettingsconstraints.html) and [Events exported as JSON](https://help.eset.com/protect_cloud/en-US/events-exported-to-json-format.html).

### Agent-based deployment

Install Elastic Agent on a host that can reach the ESET Connect APIs or receive connections from ESET PROTECT Syslog Forwarder. For installation guidance, refer to [Install Elastic Agents](docs-content://reference/fleet/install-elastic-agents.md).

### Configure the integration in Elastic

1. In Kibana navigate to **Management** → **Integrations**.
2. In the search bar, type **ESET PROTECT**.
3. Select the **ESET PROTECT** integration and add it.
4. To collect from ESET Connect, enable the required API data streams and configure the API username, password, and region.
5. To collect events from Syslog Forwarder, enable the Event data stream and configure:
   - **Listen Address** as `0.0.0.0` or a specific interface reachable through the destination configured in ESET.
   - **Listen Port** to match the ESET destination port.
   - **SSL Configuration** with the server certificate and matching private key.
   - **Custom TCP Options** with `framing: rfc6587` when ESET octet-counted framing is enabled.
6. Save the integration.

### Validation

1. Confirm that the integration policy is healthy in Fleet.
2. Wait for the configured collection interval, then search for `data_stream.dataset: eset_protect.<data_stream>` in Discover.
3. For the Event data stream, generate a supported event in ESET PROTECT and verify that it appears in the `eset_protect.event` dataset.

## Troubleshooting

- **Authentication fails:** Verify the API username and password, confirm that the user completed the ESET PROTECT Hub sign-in, and check that **Integrations** access is enabled.
- **API data is missing:** Verify the selected region, product permissions, static-group scope, and outbound HTTPS connectivity to ESET.
- **Syslog events are missing:** Confirm that ESET PROTECT can reach the configured listener, that the certificate identity and trust chain are valid, and that the ESET and Elastic framing settings match.
- **Syslog messages are incomplete:** ESET truncates messages larger than 8 KB. This limit cannot be increased in the Elastic integration.
- **Events are missing after an outage:** ESET does not buffer Syslog Forwarder events while the destination is unavailable.

For help with Elastic Agent and Fleet, refer to [Common problems with Fleet and Elastic Agent](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

Shorter API polling intervals increase request volume. Choose intervals based on tenant size, enabled data streams, and the time required to complete each paginated collection cycle.

For the Event data stream, size the Agent host and network path for the expected Syslog Forwarder event rate. ESET truncates messages larger than 8 KB and does not buffer events during an outage, so maintain listener availability when event continuity is required.

For scaling architecture guidance, refer to [Ingest architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures).

## Reference

### Vendor documentation

- [ESET Connect API documentation](https://help.eset.com/eset_connect/en-US/)
- [ESET PROTECT Syslog Forwarder](https://help.eset.com/protect_cloud/en-US/syslog_forwarder.html)
- [Syslog restrictions and limits](https://help.eset.com/protect_cloud/en-US/syslogexportsettingsconstraints.html)
- [Events exported as JSON](https://help.eset.com/protect_cloud/en-US/events-exported-to-json-format.html)

### Logs reference

#### Detection

This is the `Detection` dataset.

##### Example

{{event "detection"}}

{{fields "detection"}}

#### Device

This is the `Device` dataset.

##### Example

{{event "device"}}

{{fields "device"}}

#### Device Task

This is the `Device Task` dataset.

##### Example

{{event "device_task"}}

{{fields "device_task"}}

#### Device Vulnerability

This is the `Device Vulnerability` dataset.

##### Example

{{event "device_vulnerability"}}

{{fields "device_vulnerability"}}

#### Event

This is the `Event` dataset.

##### Example

{{event "event"}}

{{fields "event"}}
