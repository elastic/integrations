{{- generatedHeader }}
# Anduril Lattice Integration for Elastic

## Overview

The Anduril Lattice integration for Elastic collects entity lifecycle events from the [Anduril Lattice](https://www.anduril.com/lattice/) command and control (C2) platform. Lattice fuses data from heterogeneous sensor networks — radar, ADS-B, AIS, RF/EW, optical, and Anduril hardware — into a Common Operational Picture (COP). Every tracked or managed item is an **Entity**: aircraft, surface vessels, ground vehicles, UAS, fixed sensors, geospatial zones, and signals of interest.

This integration collects all entity lifecycle events (created, updated, deleted, preexisting snapshot) and ships them to Elasticsearch for real-time situational awareness, threat monitoring, and asset tracking.

### Compatibility

Compatible with the Anduril Lattice REST API v1 (`/api/v1/entities/events`). Tested against Anduril Lattice SDK v4.0.0.

### How it works

The integration polls the Lattice long-poll API endpoint (`POST /api/v1/entities/events`) using a session-token cursor. Each poll returns a batch of entity lifecycle events. The session token is persisted between polls so the integration resumes from where it left off.

On the first poll (empty session token) the Lattice server delivers a snapshot of all currently live entities as `EVENT_TYPE_PREEXISTING` events, then transitions to streaming ongoing changes. Subsequent polls receive `EVENT_TYPE_CREATED`, `EVENT_TYPE_UPDATE`, and `EVENT_TYPE_DELETED` events as the operational picture evolves.

Two authentication modes are supported:
- **Static bearer token** — supply a single token; rotation is manual.
- **OAuth2 client credentials** — supply a client ID and secret; the integration fetches and refreshes access tokens automatically (30-minute lifetime).

For Anduril sandbox/developer environments, an additional sandbox authorization token is required.

## What data does this integration collect?

The Anduril Lattice integration collects entity lifecycle events from the Lattice long-poll API.

### Supported use cases

- **Real-time situational awareness** — track friendly, hostile, and neutral entities across air, surface, land, and sub-surface domains.
- **Asset health monitoring** — monitor connection status and battery/power state for Anduril hardware assets (towers, sensors).
- **Track analysis** — correlate track quality, sensor hit count, and kinematic data (position, velocity, heading) for sensor-detected contacts.
- **Threat detection** — alert on `DISPOSITION_HOSTILE` or `DISPOSITION_SUSPICIOUS` entity classifications.
- **Geospatial analysis** — visualize entity positions on Kibana Maps using the `anduril_lattice.entity.location.geo` geo_point field.

## What do I need to use this integration?

- **Anduril Lattice environment** — a production environment, or a sandbox via the [Anduril developer program](https://developer.anduril.com/guides/getting-started/set-up).
- **Credentials** — either a static bearer token, or an OAuth2 client ID and client secret generated from the Lattice admin console.
- **Network connectivity** — the Elastic Agent host must be able to reach the Lattice API over HTTPS (port 443).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent polls the Lattice long-poll API and ships events to Elastic, where they are processed by the integration's ingest pipeline.

### Set up steps in Anduril Lattice

1. Log in to the Lattice admin console for your environment.
2. Navigate to **Integrations** and create a new integration to generate OAuth2 credentials (`client_id` and `client_secret`), or obtain a static bearer token from your Lattice administrator.
3. Note your Lattice API base URL (for example, `https://lattice.yourdomain.com`).
4. For sandbox environments, also obtain the `Anduril-Sandbox-Authorization` token from the [Lattice sandbox documentation](https://developer.anduril.com/guides/developer-tools/sandboxes).
5. Ensure the Elastic Agent host has HTTPS/443 access to the Lattice server.

#### Vendor resources

- [Anduril Lattice developer portal](https://developer.anduril.com)
- [Long-poll entity events API reference](https://developer.anduril.com/reference/rest/entities/long-poll-entity-events)
- [Getting started / authentication](https://developer.anduril.com/guides/getting-started/quickstart)
- [Lattice sandbox environments](https://developer.anduril.com/guides/developer-tools/sandboxes)

### Set up steps in Kibana

1. In Kibana, navigate to **Fleet** → **Integrations** and search for **Anduril Lattice**.
2. Click **Add Anduril Lattice** and configure the integration:
   - **Lattice API URL** — the base URL of your Lattice environment (for example, `https://lattice.example.com`).
   - **Authentication** — provide either a static **Bearer Token**, or an **OAuth2 Client ID** and **Client Secret** for automatic token management.
   - **Sandbox Token** — leave empty for production; provide the sandbox token for developer environments.
   - **Interval** — how often to poll for new events (default: `5s`).
3. Save and deploy the policy to the Elastic Agent.

### Validation

After deploying the integration, verify data is flowing:

1. Open **Kibana** → **Discover**.
2. Select the `logs-anduril_lattice.entity-*` index pattern.
3. Check that events appear with `event.dataset: anduril_lattice.entity`.
4. Confirm entity fields such as `anduril_lattice.entity.entity_id`, `anduril_lattice.entity.ontology.template`, and `anduril_lattice.entity.mil_view.disposition` are populated.
5. Open **Kibana Maps** and add a layer using the `anduril_lattice.entity.location.geo` field to visualize entity positions.

## Troubleshooting

- No data collected: Verify the Lattice API URL is reachable from the Elastic Agent host and that the bearer token or OAuth2 credentials are valid.
- Authentication failures: For OAuth2, ensure the token URL follows the pattern `{base_url}/api/v1/oauth/token` and that the client credentials have the correct permissions in the Lattice admin console.
- Self-signed certificates: If the Lattice environment uses a private CA, configure the `SSL Configuration` field with the custom `certificate_authorities` path.
- Sandbox environments: Ensure the `Sandbox Authorization Token` field is populated; the `Anduril-Sandbox-Authorization` header is required for developer sandboxes.
- Session token loss on restart: The CEL input persists the session token in agent state. On cold restart the integration re-delivers a full entity snapshot as `EVENT_TYPE_PREEXISTING` events.

## Performance and scaling

The Lattice long-poll API returns all entities in the environment with no server-side filtering. In large environments with many active entities, the initial snapshot might produce thousands of events across multiple polling cycles. Tune `Batch Size` (default 100, max 2000) and `Interval` (default 5s) for your environment's entity density.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used
{{ inputDocs }}

### API usage

These APIs are used with this integration:

- `POST /api/v1/entities/events` — [Long-poll entity events](https://developer.anduril.com/reference/rest/entities/long-poll-entity-events): returns batches of entity lifecycle events with a session-token cursor for incremental collection.
- `POST /api/v1/oauth/token` — OAuth2 token endpoint: used to obtain and refresh bearer tokens when OAuth2 client credentials are configured.

### Vendor documentation links

- [Anduril Lattice developer portal](https://developer.anduril.com)
- [Lattice API overview](https://developer.anduril.com/reference/overview/overview)
- [Go SDK (public)](https://github.com/anduril/lattice-sdk-go)

### Data streams

#### entity

The `entity` data stream collects entity lifecycle events from the Anduril Lattice long-poll API. Each event represents a state change for a tracked entity in the Lattice Common Operational Picture — creation, update, deletion, or preexisting snapshot on session start.

Entity sub-types (distinguished by `anduril_lattice.entity.ontology.template`):
- `TEMPLATE_TRACK` — sensor-tracked transient contacts (aircraft, vessels, UAVs)
- `TEMPLATE_ASSET` — persistent managed assets (sensors, towers, Anduril hardware)
- `TEMPLATE_GEO` — geospatial zones (keep-in, keep-out, engagement zones)
- `TEMPLATE_SENSOR_POINT_OF_INTEREST` — sensor-detected points of interest
- `TEMPLATE_SIGNAL_OF_INTEREST` — RF/EW signal entities

##### entity fields

{{ fields "entity" }}

##### entity sample event

{{ event "entity" }}

{{ ilm }}

{{ transform }}
