{{- generatedHeader }}
# evcc Integration for Elastic

## Overview

The evcc integration collects site and per-loadpoint metrics from [evcc](https://evcc.io), the open-source solar charging and energy management system. It enables monitoring of solar production, home battery state, grid power flow, and EV charging activity in Elastic.

### Compatibility

This integration collects data from the evcc REST API (`/api/state`). It has been verified against evcc 0.312.x, but the API is expected to work with other recent evcc releases as well. Refer to the [evcc REST API documentation](https://docs.evcc.io/en/integrations/rest-api) for details.

### How it works

This integration uses the [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html) to periodically poll the evcc REST API. Two data streams each poll `/api/state` independently: one extracts site-level metrics (solar, grid, battery, home power, cost statistics) and the other splits the `loadpoints` array into one event per configured charge point (charging state, power, energy, connected vehicle).

## What data does this integration collect?

The evcc integration collects metrics of the following types:
* **Site**: home power, grid power, solar (PV) power and energy, home battery power/state of charge, and cost/CO2/solar-share statistics for several reporting periods.
* **Loadpoint**: per-charge-point mode, charging/connected/enabled state, charge power, charged energy, session duration, effective current/SoC limits, and connected vehicle name/SoC/range.

### Supported use cases

This integration enables dashboards and alerts for home energy management, such as tracking how much of your EV charging is solar-powered, monitoring home battery state of charge, or being notified when a loadpoint stops charging unexpectedly.

## What do I need to use this integration?

* A running evcc instance reachable over HTTP from the Elastic Agent.
* Network access from the Elastic Agent to the evcc REST API (default port `7070`). This integration does not currently support evcc instances that have password protection enabled.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent polls the evcc REST API directly over HTTP(S) and ships the data to Elastic, where the events are processed via the integration's ingest pipelines.

### Onboard / configure

1. In Kibana, go to **Management > Integrations** and add the **evcc** integration.
2. Set the **evcc URL** to the base URL of your evcc instance, e.g. `http://evcc.local:7070`.
3. Optionally adjust the polling **Interval** for the site and loadpoint data streams (default: `30s`).
4. Assign the integration to an Elastic Agent policy and deploy it to an agent with network access to evcc.

### Validation

After the integration is running, confirm data is arriving by checking the `metrics-evcc.site-*` and `metrics-evcc.loadpoint-*` data streams in **Discover**, or by browsing the field values in the installed dashboards.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

If no data appears, verify that the evcc URL is reachable from the host running Elastic Agent (e.g. `curl <evcc URL>/api/state`) and that no reverse proxy authentication is blocking the request.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### site

The `site` data stream provides site-level metrics from evcc of the following types: home power, grid power, solar power/energy, home battery power/SoC/capacity, and cost/CO2/solar-share statistics.

#### site fields

{{ fields "site" }}

#### site sample event

{{ event "site" }}

### loadpoint

The `loadpoint` data stream provides one event per evcc loadpoint (charge point) of the following types: mode, charging/connected/enabled state, charge power/energy/duration, effective current/SoC limits, and connected vehicle details.

#### loadpoint fields

{{ fields "loadpoint" }}

#### loadpoint sample event

{{ event "loadpoint" }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:
* [`GET /api/state`](https://docs.evcc.io/en/integrations/rest-api) &mdash; returns the complete state of the evcc instance, including site, loadpoint, and vehicle data.
