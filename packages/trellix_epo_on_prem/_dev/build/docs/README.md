# Trellix ePO On-Premises Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Premises](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization.

This integration collects event records forwarded by Trellix ePO over TCP or UDP syslog. It provides visibility into endpoint security detections, threat prevention activity, web control events, data loss prevention events, product events, user activity, and reputation changes across your Trellix ePO environment.

### How it works

The integration uses the Elastic Agent TCP or UDP input to receive events forwarded by Trellix ePO. For each received event, it:

1. Receives an RFC 5424 syslog message on the configured listen address and port.
2. Extracts the embedded XML payload from the syslog message.
3. Decodes the `EPOEvent` XML object and maps endpoint, network, file, user, registry, and threat details to Elastic Common Schema (ECS).
4. Emits each decoded record as an individual event for ingestion and enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Premises integration collects the following type of data:

| Data stream | Description |
|---|---|
| `event` | Trellix ePO event-forwarder records, including endpoint security, threat prevention, web control, data loss prevention, product, authentication, and reputation events received over TCP or UDP syslog. |

### Supported use cases

* **Threat detection and investigation**: Monitor malware detections, prevention actions, threat severity, affected endpoints, files, users, and network activity.

* **Endpoint and administrative monitoring**: Analyze endpoint product events, policy-related activity, user actions, authentication events, and reputation changes reported through Trellix ePO.

## What do I need to use this integration?

### From Trellix ePO On-Premises

* **Trellix ePO deployment**: An active Trellix ePO On-Premises server capable of forwarding events over syslog.
* **Event forwarding enabled**: Configure Trellix ePO to forward RFC 5424 syslog messages containing XML `EPOEvent` payloads to the Elastic Agent host and port.
* **Network access**: The Trellix ePO server must be able to reach the Elastic Agent over the configured TCP or UDP port.
* **Elastic Agent**: An Elastic Agent enrolled in Fleet and installed on a host that can receive the forwarded syslog traffic.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to receive the syslog events and ship the data to Elastic, where the events are processed by the integration's ingest pipeline.

### Configure

1. In Kibana, navigate to **Fleet → Integrations** and search for **Trellix ePO On-Premises**.
2. Click **Add Trellix ePO On-Premises**.
3. Enable either the TCP or UDP input.
4. Set the **Listen Address** and **Listen Port** to the address and port that Trellix ePO will use as its syslog destination. The default port is `9514`.
5. For TCP with TLS, configure the certificate and key under **SSL Configuration**.
6. Configure Trellix ePO to forward events to the Elastic Agent host using the same protocol and port.
7. Select **Save and continue** to save the integration.
8. Add the integration to an existing Agent policy or create a new one.
9. Verify that Trellix ePO events are being ingested into Elasticsearch.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Premises**.
3. Open the **[Logs Trellix ePO On-Premises] Event Overview** dashboard.
4. Verify that the visualizations are populated with event data, including event trends, categories, actions, hosts, users, threats, files, and source locations.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

* **No data collected**: Verify that Trellix ePO event forwarding is enabled and points to the correct Elastic Agent host, protocol, and port. Confirm that network and firewall rules allow traffic to the configured listener.
* **XML payload is not decoded**: Confirm that forwarded messages contain an XML `EPOEvent` payload and that the complete event is delivered as a single syslog message.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

### Event

The `event` data stream provides Trellix ePO On-Premises event logs.

#### Event fields

{{fields "event"}}

### Example event

#### Event

{{event "event"}}

### Inputs used

{{ inputDocs }}
