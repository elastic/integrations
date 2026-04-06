{{- generatedHeader }}
# Global Disaster Alert and Coordination System (GDACS) Integration for Elastic

## Overview

The Global Disaster Alert and Coordination System (GDACS) integration collects natural disaster alert events — earthquakes, tropical cyclones, floods, volcanoes, droughts, and wildfires — from the GDACS public API and indexes them into Elasticsearch with full ECS mapping, severity scoring, and geographic enrichment including affected-area polygons.

GDACS is a cooperation framework between the United Nations and the European Commission that provides near real-time alerts about natural disasters around the world, combining multiple hazard-monitoring sources.

### Compatibility

This integration uses the GDACS public REST API. No authentication is required. The API is available at `https://www.gdacs.org/gdacsapi/api`.

### How it works

The integration uses the CEL input to periodically poll the GDACS Search API for recent events. For each event returned, it fetches the detailed geometry polygon from the GDACS Polygons API (when available) and enriches the event with the affected area shape. Events are then processed through an ingest pipeline that normalizes fields to ECS and custom `gdacs.*` fields.

Key processing steps:
- Extracts centroid `geo_point` and affected-area `geo_shape` from GeoJSON geometry
- Maps GDACS alert levels (Red/Orange/Green) to numeric `event.severity` and `event.risk_score`
- Flattens affected country arrays into searchable keyword fields
- Deduplicates events using a fingerprint of `{event_id}-{episode_id}`
- Supports pagination across large result sets

## What data does this integration collect?

The GDACS integration collects alert events of the following disaster types:
- **EQ** — Earthquakes
- **TC** — Tropical Cyclones
- **FL** — Floods
- **VO** — Volcanoes
- **DR** — Droughts
- **WF** — Wildfires

Each event includes alert level, severity data, geographic coordinates, affected-area polygons, affected countries, and links to GDACS report pages.

### Supported use cases

- Real-time situational awareness dashboards for natural disaster monitoring
- Geographic analysis of disaster impact zones using polygon overlays on maps
- Alerting on high-severity (Red/Orange) disaster events in specific regions or countries
- Correlation of disaster events with infrastructure or supply chain data
- Historical analysis of disaster patterns and trends

## What do I need to use this integration?

No special requirements. The GDACS API is publicly accessible and does not require authentication or API keys.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the GDACS API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Onboard / configure

1. In Kibana, navigate to **Management > Integrations** and search for "GDACS".
2. Click **Add GDACS**.
3. Configure the following settings:
   - **Poll Interval**: How often to check for new events (default: `1h`).
   - **Lookback Window**: Hours of history to fetch on first run (default: `168`, i.e. 7 days).
   - **Event Types**: Semicolon-separated disaster type codes to collect (default: `EQ;TC;FL;VO;DR;WF`).
   - **Alert Levels**: Semicolon-separated alert levels to collect (default: `red;orange;green`).
   - **Country Filter**: Optional ISO3 country code to limit events to a specific country.
   - **Page Size**: Number of events per API page (default: `100`, max: `100`).
4. Save the integration policy and deploy it to your Elastic Agent.

### Validation

After deploying, verify data is flowing:

1. In Kibana, go to **Discover** and select the `logs-gdacs.events-*` data stream.
2. You should see documents with `event.kind: alert` and `event.module: gdacs`.
3. Check for `gdacs.event_type`, `gdacs.alert_level`, and `geo.location` fields.
4. To verify polygon enrichment, check for `gdacs.affected_area` on events that have geometry data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

- **No events collected**: The GDACS API may have no events matching your configured alert levels and event types within the lookback window. Try increasing the lookback window or broadening the alert level filter.
- **Missing polygon data**: Not all GDACS events have associated geometry polygons. Events without a geometry URL will be indexed with only the centroid point in `geo.location`.
- **Rate limiting**: The GDACS API is public and does not document rate limits. If you experience errors, increase the poll interval.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

This integration is lightweight — GDACS typically has tens to hundreds of active events at any time, not thousands. The default 1-hour poll interval is sufficient for most use cases.

## Reference

### Events

The `events` data stream provides natural disaster alert events from the GDACS Search API.

{{ fields "events" }}

{{ event "events" }}

{{ ilm }}

{{ transform }}

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:
- [GDACS Search API](https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH) — Retrieves the list of disaster events matching filter criteria (event type, alert level, date range, country).
- [GDACS Polygons API](https://www.gdacs.org/gdacsapi/api/polygons/getgeometry) — Retrieves GeoJSON geometry features (centroid points and affected-area polygons) for a specific event episode.
