{{- generatedHeader }}
# Elastic Cloud Integration

## Overview

The Elastic Cloud integration adds Elasticsearch mappings, an ingest pipeline, and Kibana dashboards for [audit trail log delivery](https://www.elastic.co/docs/deploy-manage/monitor/log-delivery/audit-trail). The first data stream is **Serverless audit logs**. This package does not collect data with Elastic Agent.

Audit trail delivery writes project-level Elasticsearch and Kibana audit events to `logs-elastic_cloud.serverless_audit.otel-*` on an Elastic Security Serverless or Elastic Observability Serverless destination. The destination can be the same project as the source. You can read more about enablement, ignore filters, and example queries in [Audit trail log delivery](https://www.elastic.co/docs/deploy-manage/monitor/log-delivery/audit-trail).

### Compatibility

This integration requires Kibana 9.6.0 or later.

## What data does this integration collect?

- **Serverless audit**: project-level Elasticsearch and Kibana audit events delivered by Elastic Cloud Serverless.

The ingest pipeline copies the forwarded client IP to `client.ip` and adds GeoIP. If the lookup fails, the error is stored in `error.message`.

## What do I need to use this integration?

- An Elastic Security Serverless or Elastic Observability Serverless project as the destination
- Audit trail log delivery enabled on the source project

The package assets are already installed on the destination project. There is no Elastic Agent policy to configure.

## How do I deploy this integration?

This integration does not use Elastic Agent. Do not add it to an agent policy.

In Kibana on the destination project, open **Dashboards** and then **[Audit] Command Center**. Generate audit activity, such as signing in to Kibana or editing a dashboard, and confirm the panels populate.

This integration installs:

- Index templates for `logs-elastic_cloud.serverless_audit.otel-*`
- An ingest pipeline for the `elastic_cloud.serverless_audit` data stream
- Field mappings for the GeoIP enrichment of `client.ip`
- The **[Audit]** dashboards, saved searches, and visualizations

## Troubleshooting

**No events in the dashboards**

- Make sure audit trail log delivery is enabled and sending to this destination project. See [Audit trail log delivery](https://www.elastic.co/docs/deploy-manage/monitor/log-delivery/audit-trail).
- Make sure documents are written to `logs-elastic_cloud.serverless_audit.otel-*`.

**Missing GeoIP fields**

Private and documentation-range addresses do not resolve. If the lookup fails, the error is stored in `error.message`.

## Reference

### Serverless audit

The `serverless_audit` data stream stores one audit event per document. The package adds `client.ip`, `client.geo.*`, and `error.message`. Other audit fields are mapped by the built-in OpenTelemetry templates.

#### Exported fields

{{fields "serverless_audit"}}

### Inputs used

This package has no Elastic Agent inputs.
