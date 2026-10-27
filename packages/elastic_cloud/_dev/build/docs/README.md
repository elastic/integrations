{{- generatedHeader }}
# Elastic Cloud Integration

## Overview

The Elastic Cloud integration installs Elasticsearch mappings, an ingest pipeline, and Kibana dashboards for logs that Elastic Cloud pushes into a destination project. The first data stream is **serverless audit logs**. This package does not collect data with Elastic Agent.

Use it to search and visualize audit activity from Elasticsearch and Kibana in your serverless projects, such as authentication, data access, security configuration changes, and saved object changes.

### Compatibility

This integration requires Kibana 9.6.0 or later, or Elastic Cloud Serverless.

### How it works

1. You install this package's Elasticsearch and Kibana assets on the destination project.
2. Elastic Cloud writes serverless audit events in OpenTelemetry format to the `logs-elastic_cloud.serverless_audit.otel-*` data stream.
3. The package ingest pipeline copies the forwarded client IP to `client.ip` and enriches it with GeoIP.
4. The package dashboards visualize the events.

There is no Elastic Agent input, poll interval, or webhook listener.

## What data does this integration collect?

The Elastic Cloud integration processes the following logs:

- **Serverless audit** — Elasticsearch and Kibana audit events from Elastic Cloud Serverless projects, in OpenTelemetry log format.

### Supported use cases

- Monitor authentication successes and failures by user, API key, and realm
- Investigate access to Elasticsearch indices, including system indices
- Review security configuration changes and Kibana saved object changes
- Reconstruct Kibana sessions and cross-space activity for an actor
- Review client IP addresses and geography when GeoIP is available

These events contain restricted data such as user names, email addresses, and IP addresses. Limit Kibana and index access accordingly.

## What do I need to use this integration?

- An Elastic Cloud Serverless project to receive the audit logs
- This package installed on that destination project **before** the first audit document is written

## How do I deploy this integration?

### Agent-based deployment

This integration does not use Elastic Agent. Do not add it to an agent policy for collection. Install assets only.

### Onboard / configure

In Kibana on the **destination** project:

1. Go to **Management → Integrations**.
2. Search for **Elastic Cloud**.
3. Click **Add Elastic Cloud**.
4. Click **Install assets only** (no agent policy needed).
5. Confirm installation.

This installs:

- Index templates for `logs-elastic_cloud.serverless_audit.otel-*`
- Ingest pipeline for the `elastic_cloud.serverless_audit` data stream
- Field mappings for the GeoIP enrichment of `client.ip`
- The **[Audit]** dashboards, saved searches, and visualizations

### Validation

1. Generate audit activity in a serverless project, such as signing in to Kibana or editing a dashboard.
2. In Discover, query `FROM logs-elastic_cloud.serverless_audit.otel-*`.
3. Confirm documents have `@timestamp`, `attributes.event.action`, and `data_stream.dataset: elastic_cloud.serverless_audit.otel`.
4. Open **[Audit] 🎛️ Command Center** and confirm panels populate.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

**No events in the dashboards**

- Confirm the assets were installed on the **destination** project before audit delivery was turned on.
- Confirm documents are written to a `logs-elastic_cloud.serverless_audit.otel-*` data stream.

**Missing GeoIP fields**

Private or documentation-range IPs do not resolve. If the lookup fails, the error is stored in `error.message`.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

Delivery is a control-plane push into your destination project. There is no customer collector to scale.

## Reference

### Serverless audit

The `serverless_audit` data stream stores one OpenTelemetry log record per audit event. Audit fields are kept under `attributes.*` and `resource.attributes.*` and are mapped by the built-in OpenTelemetry templates.

#### Exported fields

{{fields "serverless_audit"}}

### Inputs used

This package has no Elastic Agent inputs.
