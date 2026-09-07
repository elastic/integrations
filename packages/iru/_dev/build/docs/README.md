{{- generatedHeader }}
# Iru Integration for Elastic

## Overview

The Iru integration for Elastic collects console audit events and managed-device inventory from [Iru Endpoint Management](https://docs.iru.com/) (formerly Kandji) via the Iru REST API.

### Compatibility

This integration is compatible with Iru Endpoint Management API v1.

### How it works

This integration periodically queries the Iru Endpoint Management REST API using a tenant Bearer token.

## What data does this integration collect?

The Iru integration collects log messages of the following types:
* `Audit`: Tenant Activity events (blueprint and configuration changes, library item edits, API token administration, and other console actions).
* `Device`: Managed device inventory for Entity Analytics (platform, model, OS version, enrollment and agent status, last check-in, assigned user, blueprint, and tags).

### Supported use cases

Use audit events to monitor who changed device-management configuration, who managed API tokens, and how enrollment changed over time. Use device inventory to join Iru hosts with the same devices and users seen in other data sources, and to find stale or non-reporting devices.

## What do I need to use this integration?

### From Iru

You need an Iru Endpoint tenant with API access (Account Owner or Administrator). API access may need to be enabled by an Iru Customer Success Manager.

Create a dedicated API token in **Account Menu → Access → API tokens** and grant only:

* Devices: Device Information: Device list
* Audit Logs: List Audit Events

Copy **Your organization's API URL** from the same page.

## How do I deploy this integration?

### Set up steps in Iru

1. Sign in as Account Owner or Administrator.
2. Open **Account Menu → Access → API tokens**.
3. Note **Your organization's API URL**.
4. Click **Add Token**, enter a name and description, and click **Create**.
5. Copy the token immediately. It is shown only once.
6. Configure permissions: enable **Device list** and **List Audit Events** only. Do not grant lock, erase, or secrets permissions.
7. Click **Save**.

#### Vendor resources
- [Iru API Overview](https://docs.iru.com/en/endpoint/api/iru-api-overview)
- [Iru Endpoint Management API](https://api-docs.iru.com/)
- [Iru brand and API host compatibility](https://docs.iru.com/en/iru/platform-overview/iru-brand-update)

### Set up steps in Kibana

1. In Kibana, go to **Management > Integrations**.
2. Search for **Iru**.
3. Click **Add Iru**.
4. Enter the **API URL** (`https://` plus the hostname from Access).
5. Enter the **API token**.
6. Enable the **Audit** and/or **Device** data streams and set their intervals.
7. Click **Save and continue**.

### Validation

1. In Iru, confirm the token has Device list and List Audit Events permissions and that the tenant has recent Activity and enrolled devices.
2. In Kibana Discover, search `data_stream.dataset: "iru.audit"` and `data_stream.dataset: "iru.device"`.

## Troubleshooting

- 401 Unauthorized: The token is incorrect, was revoked, or all permissions were removed. Create a new token in Access.
- Permission denied (`You do not have permission to perform this action.`): Enable Device list and List Audit Events on the token.
- API rate limit exceeded: The tenant shares a 10,000 requests per hour cap across all tokens. Increase the device interval (default 1h) and keep page sizes at the API maxima.
- No audit events: Confirm Activity exists in the Iru console for the lookback window (`Initial Interval`).
- No devices: Confirm the tenant has enrolled devices and the token includes Device list.

## Performance and scaling

The Iru API allows 10,000 requests per hour per tenant, shared by every token. Prefer the default device page size of 300 and an interval of at least one hour. Do not enable per-device detail calls; the list endpoint is sufficient for inventory.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:
* [List audit events](https://api-docs.iru.com/) — `GET /api/v1/audit/events`
* [List devices](https://api-docs.iru.com/) — `GET /api/v1/devices`

### Vendor documentation links

- [Iru API Overview](https://docs.iru.com/en/endpoint/api/iru-api-overview)
- [Iru Endpoint Management API](https://api-docs.iru.com/)
- [Official OpenAPI](https://docs.iru.com/openapi/iru-endpoint-openapi.json)

### Data streams

#### Audit

The `audit` data stream collects tenant Activity events from `GET /api/v1/audit/events`.

##### Audit fields

{{ fields "audit" }}

##### Audit sample event

{{ event "audit" }}

#### Device

The `device` data stream collects managed device inventory from `GET /api/v1/devices`.

##### Device fields

{{ fields "device" }}

##### Device sample event

{{ event "device" }}

{{ ilm }}

{{ transform }}
