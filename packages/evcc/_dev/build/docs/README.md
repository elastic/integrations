{{- generatedHeader }}
# evcc Integration for Elastic

## Overview

The evcc integration collects site and per-loadpoint metrics, and application logs, from [evcc](https://evcc.io), the open-source solar charging and energy management system. It enables monitoring of solar production, home battery state, grid power flow, EV charging activity, and operational issues (vehicle API errors, device read failures, charger warnings) in Elastic.

### Compatibility

This integration collects data from the evcc REST API (`/api/state`) and, on Linux hosts where evcc runs as a systemd service, from its journald logs. It has been verified against evcc 0.312.x, but is expected to work with other recent evcc releases as well. Refer to the [evcc REST API documentation](https://docs.evcc.io/en/integrations/rest-api) for details. evcc's log line format is not formally documented upstream and may change between releases; unrecognized log lines are still shipped as plain `message` events rather than being dropped.

### How it works

This integration uses two collection methods:
* The [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html) periodically polls the evcc REST API. Two metrics data streams each poll `/api/state` independently: one extracts site-level metrics (solar, grid, battery, home power, cost statistics) and the other splits the `loadpoints` array into one event per configured charge point (charging state, power, energy, connected vehicle).
* The [journald input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-journald.html) reads evcc's application logs directly from the systemd journal and parses them into ECS fields.

## What data does this integration collect?

The evcc integration collects metrics and logs of the following types:
* **Site**: home power, grid power, solar (PV) power and energy, home battery power/state of charge, and cost/CO2/solar-share statistics for several reporting periods.
* **Loadpoint**: per-charge-point mode, charging/connected/enabled state, charge power, charged energy, session duration, effective current/SoC limits, and connected vehicle name/SoC/range.
* **Log**: evcc's own application logs collected via journald. Charging session lifecycle events (car connected/disconnected, charging started/stopped), vehicle API errors (timeouts, HTTP error status codes), device read failures (battery/PV/grid meter connectivity), and charger logic warnings are parsed into dedicated ECS fields (`event.action`, `event.category`, `event.outcome`, `destination.ip`/`port`, `url.*`, `http.response.status_code`, etc.). High-volume DEBUG-level telemetry lines are kept as plain `message` text, since the same readings are already collected in structured form by the site and loadpoint data streams.

### Supported use cases

This integration enables dashboards and alerts for home energy management, such as tracking how much of your EV charging is solar-powered, monitoring home battery state of charge, being notified when a loadpoint stops charging unexpectedly, or alerting on repeated vehicle API or device read failures surfaced in the logs.

## What do I need to use this integration?

* A running evcc instance reachable over HTTP from the Elastic Agent, for the site and loadpoint metrics data streams. This integration does not currently support evcc instances that have password protection enabled.
* For the log data stream, evcc must run as a systemd service (the default on Linux installations) so its output is captured by journald, and Elastic Agent must run on that same Linux host with access to the system journal.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

For the metrics data streams, Elastic Agent polls the evcc REST API directly over HTTP(S). For the log data stream, Elastic Agent must run on the same Linux host as evcc and reads its logs from the local systemd journal. Events are then processed via the integration's ingest pipelines.

### Onboard / configure

1. In Kibana, go to **Management > Integrations** and add the **evcc** integration.
2. Set the **evcc URL** to the base URL of your evcc instance, e.g. `http://evcc.local:7070`.
3. Optionally adjust the polling **Interval** for the site and loadpoint data streams (default: `30s`).
4. To collect logs, deploy the log data stream's input to an Elastic Agent running directly on the host where evcc's systemd service runs. Adjust **Include Matches** if evcc runs under a different systemd unit name than `evcc.service`. Consider enabling **Drop debug-level logs** if you do not need evcc's high-volume DEBUG telemetry.
5. Assign the integration to an Elastic Agent policy and deploy it to an agent with the required network/host access.

### Validation

After the integration is running, confirm data is arriving by checking the `metrics-evcc.site-*`, `metrics-evcc.loadpoint-*`, and `logs-evcc.log-*` data streams in **Discover**, or by browsing the field values in the installed dashboards.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

If no metrics appear, verify that the evcc URL is reachable from the host running Elastic Agent (e.g. `curl <evcc URL>/api/state`) and that no reverse proxy authentication is blocking the request.

If no logs appear, verify that evcc is running as a systemd service on the same host as the Elastic Agent collecting logs (`systemctl status evcc`), and that the **Include Matches** filter matches its actual unit name (check with `systemctl list-units | grep evcc`).

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

### log

The `log` data stream provides evcc's own application logs, collected via journald, of the following types: charging session lifecycle events, vehicle API errors, device read failures, charger logic warnings, and DEBUG-level telemetry (kept as plain text).

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:
* [`GET /api/state`](https://docs.evcc.io/en/integrations/rest-api) &mdash; returns the complete state of the evcc instance, including site, loadpoint, and vehicle data.
