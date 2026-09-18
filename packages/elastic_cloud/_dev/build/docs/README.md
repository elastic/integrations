{{- generatedHeader }}
# Elastic Cloud Integration

## Overview

The Elastic Cloud integration installs Elasticsearch mappings, an ingest pipeline, and a Kibana dashboard for logs that Elastic Cloud Hosted pushes into a destination deployment. The first data stream is **Control Plane API audit logs** from the Self-serving Audit Service. This package does not collect data with Elastic Agent.

Use it to search and visualize and Elastic Cloud Console and API activity for deployments, members, API keys, and other organization-scoped API calls.

### Compatibility

This integration is compatible with:

- Elastic Cloud Hosted (ESS) organizations on a Platinum or Enterprise subscription
- Destination Elastic Stack 8.19+ or 9.1+ (see package conditions)

It is not a replacement for Elasticsearch or Kibana `xpack.security.audit` logging, or the ECE Adminconsole `ece` integration.

### How it works

1. You install this package’s Elasticsearch and Kibana assets on the destination deployment.
2. An organization owner enables audit-log delivery with the Elastic Cloud API and an explicit `logs-elastic_cloud.audit-*` data stream name.
3. Elastic Cloud Audit Service writes one JSON document per completed API request.
4. The package ingest pipeline maps the flat landing fields to Elastic Common Schema (ECS), enriches the caller IP with GeoIP/ASN, and attaches the default dashboard.

There is no Elastic Agent input, poll interval, or webhook listener.

## What data does this integration collect?

The Elastic Cloud integration processes the following logs:

- **Audit** — HTTP API request/response audit records for Elastic Cloud API calls (status, method, URL, client IP, organization, user, API key, optional sanitized request payload)

### Supported use cases

- Monitor Elastic Cloud API volume and method mix over time
- Investigate 4xx/5xx failures by endpoint and caller
- Attribute activity to users (`user.email` / `user.id`), claimed header identity (`elastic_cloud.audit.unvalidated_auth_user`), and API keys
- Review caller IP addresses and geography on the dashboard map when GeoIP is available
- Confirm whether a request included a sanitized payload, without placing payload contents on the default dashboard

These events are restricted (emails, IPs, and possible customer content in URLs or payloads). Limit Kibana and index access accordingly.

## What do I need to use this integration?

- An Elastic Cloud Hosted organization on Platinum or Enterprise subscription
- A destination deployment in that organization (the cluster that will store the audit logs)
- Organization-owner (or equivalent) permission to call `POST /api/v1/organizations/<ORG_ID>/audit_logs`
- This package installed on that destination deployment **before** the first audit document is written

## How do I deploy this integration?

### Agent-based deployment

This integration does not use Elastic Agent. Do not add it to an agent policy for collection. Install assets only.

### Onboard / configure

**1. Install integration assets**

In Kibana on the **destination** deployment:

1. Go to **Management > Integrations**.
2. Search for **Elastic Cloud**.
3. Click **Add Elastic Cloud**.
4. Click **Install assets only** (no agent policy needed).
5. Confirm installation.

This installs:

- Index templates for `logs-elastic_cloud.audit-*`
- Ingest pipeline for the `elastic_cloud.audit` data stream
- Field mappings (ECS + `elastic_cloud.audit.api_key.*`)
- The **Elastic Cloud audit logs** data view (`logs-elastic_cloud.audit-*`)
- The **[Elastic Cloud] Audit Logs** dashboard

**2. Enable audit-log delivery (API only)**

There is no Cloud Console UI for this step. As an organization owner, enable delivery against the destination deployment and pass a `logs-elastic_cloud.audit-*` data-stream name.

If you omit `index`, events land on a classic index called `elastic-org<ORG_ID>-audit`.

```http
POST /api/v1/organizations/<ORG_ID>/audit_logs
Authorization: ApiKey <cloud_api_key>
Content-Type: application/json

{
  "deployment_id": "<DESTINATION_DEPLOYMENT_ID>",
  "index": "logs-elastic_cloud.audit-default"
}
```

Use a different data-stream namespace if needed (`logs-elastic_cloud.audit-<namespace>`). The name must match a `logs-elastic_cloud.audit-*` data stream so Fleet index templates apply.

`GET /api/v1/organizations/<ORG_ID>/audit_logs` returns the configured `deployment_id` and `index`. `DELETE` disables delivery and invalidates the writer API key, but does not delete already indexed documents.

**3. GeoIP (recommended)**

Caller IPs are mapped to `client.ip` and enriched with `client.geo` / `client.as` when the GeoIP databases are available. Enable the downloader if it is not already on:

```json
PUT /_cluster/settings
{
  "persistent": {
    "ingest.geoip.downloader.enabled": true
  }
}
```

### Validation

1. Generate Elastic Cloud API traffic (for example list deployments or members).
2. In Discover, select the **Elastic Cloud audit logs** data view (`logs-elastic_cloud.audit-*`).
3. Confirm documents have `@timestamp`, `http.response.status_code`, `url.full`, `event.dataset: elastic_cloud.audit`, and `data_stream.dataset: elastic_cloud.audit`.
4. Open **[Elastic Cloud] Audit Logs** and confirm panels populate.

If documents appear under `elastic-org<ORG_ID>-audit` instead, the enable request omitted a `logs-elastic_cloud.audit-*` `index`. Re-enable with `"index": "logs-elastic_cloud.audit-default"` after this package is installed.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

**No events in the dashboard or `logs-elastic_cloud.audit-*`**

- Confirm assets were installed on the **destination** deployment before enablement.
- `GET /api/v1/organizations/<ORG_ID>/audit_logs` and verify `index` is a `logs-elastic_cloud.audit-*` name, not `elastic-org...-audit`.
- Confirm organization subscription is Platinum or Enterprise (`POST` is rejected otherwise).
- The dashboard filters on `data_stream.dataset: elastic_cloud.audit`. Cloud does not send `data_stream.*` or `event.dataset`. The package mapping fills `data_stream.type`, `data_stream.dataset`, `event.dataset`, and `event.module`; the ingest pipeline sets `data_stream.namespace` to `default` when it is missing. Documents ingested before this package version need a reindex (or wait for new events).

**Events exist but fields are still `status_code` / `request_url`**

The ingest pipeline did not run. The destination name is not using the package data-stream template. Re-enable with a `logs-elastic_cloud.audit-*` index after installing this package.

**Missing GeoIP fields**

Private or documentation-range IPs do not resolve. For public IPs, check `GET /_ingest/geoip/stats` and wait for the databases to download.

**Restricted data**

Audit documents include personal data (`user.email`, `user.id`, `client.ip`) and can include customer content in `url.full` or `http.request.body.content`. Restrict index and dashboard access. Do not put payload contents on shared boards.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

Delivery is a control-plane push into your destination deployment. There is no customer collector to scale. Retention follows the cluster’s logs data-stream lifecycle / ILM for `logs-elastic_cloud.audit-*`. The writer does not manage ILM.

## Reference

### Audit

The `audit` data stream stores one event per completed Elastic Cloud API request. Optional fields (`user.email`, API key name, request payload) may be absent on a given event. Sentinel value `unknown` on `user.id` or `organization.id` is left as-is. Sentinel `unknown` on `api_key_id` and `unvalidated_auth_user` is dropped. `user.id` is the acting user resolved by authorization. `elastic_cloud.audit.unvalidated_auth_user` is the identity claimed in the request headers and is not copied onto `user.id`. Host+path `request_url` values are stored as `https://` URLs in `url.full`.

#### Sample event

{{event "audit"}}

#### Exported fields

{{fields "audit"}}

{{ ilm }}

{{ transform }}

### Inputs used

This package has no Elastic Agent inputs.

{{ inputDocs }}

### API usage

These Elastic Cloud APIs enable, inspect, and disable delivery. They are not used by Elastic Agent, and they are not a search API for audit events.

- `POST /api/v1/organizations/<ORG_ID>/audit_logs` — enable or re-enable delivery (`deployment_id` required; pass `index` as `logs-elastic_cloud.audit-default`)
- `GET /api/v1/organizations/<ORG_ID>/audit_logs` — status (`deployment_id`, `index`)
- `DELETE /api/v1/organizations/<ORG_ID>/audit_logs` — disable delivery
