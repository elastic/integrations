{{- generatedHeader }}
# Stamus Networks Integration for Elastic

## Overview

The Stamus Networks integration for Elastic enables collection of IDS/IPS alerts and Declaration
of Compromise (DoC) and Declaration of Policy Violation (DoPV) correlation records from
[Stamus Networks Clear NDR](https://www.stamus-networks.com/) (formerly branded "Stamus Security
Platform") — a Network Detection and Response (NDR) / Network Security Monitoring (NSM) platform
built on [Suricata](https://suricata.io/), the open-source IDS/IPS/NSM engine. Data is collected
from the Clear NDR Central Server (CNCS) REST API.

### Compatibility

This integration is tested against a full Stamus Clear NDR server and the CNCS 42.2.0 REST API.
It relies on a static, per-user API token for authentication (no OAuth2 flow is available).
Retrieving Declaration of Compromise/Policy Violation records requires a Stamus Tier 3 license.
The `alerts` data stream otherwise works with the lower Tier 2 license.

### How it works

This integration polls the CNCS REST API on a configurable interval using the `cel` input. The
`alerts` data stream retrieves Suricata IDS/IPS alert events and Stamus DoC/DoPV correlation
records with a persisted time-range cursor (`from_date`/`to_date`).

Geolocation and ASN fields (`source.geo`, `destination.geo`, `source.as`, `destination.as`) on the
`alerts` data stream are derived by this integration's ingest pipeline using Elasticsearch's
built-in GeoLite2 databases against the event's source/destination IP addresses — Stamus Clear
NDR does not supply its own geolocation data for these events.

## What data does this integration collect?

The Stamus Networks integration collects the following data streams:

* **alerts**: Suricata IDS/IPS signature-match alert events (`event_type: alert`), including the
  embedded Stamus Declaration of Compromise/Policy Violation correlation object (`event_type:
  stamus`) when present, plus Sightings (newly discovered asset attributes), Outlier Alert
  (`stamus_novel`), and File Identification classification tags that decorate alert/stamus
  documents.

### Supported use cases

Use this integration to bring Stamus Networks' curated, high-fidelity NDR threat detections
(alerts and Declarations) into Elastic Security for correlation with other telemetry, threat
hunting, and dashboarding.

## What do I need to use this integration?

* A running Stamus Networks Clear NDR deployment (Central Server, CNCS) reachable from the host
  running Elastic Agent.
* A dedicated, read-only ("Active" tier) CNCS user account is recommended for the integration
  rather than reusing an administrative account's token.
* Stamus Tier 2 licensing (REST API access) at minimum. Tier 3 licensing is required for the
  Declaration of Compromise/Policy Violation records on the `alerts` data stream.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent polls the Stamus Clear NDR Central Server REST API on the configured interval and ships the data to Elastic, where the events are then processed via the integration's ingest pipelines.

### Set up steps in stamus_networks

1. Log in to the CNCS web UI.
2. Open account settings from the header menu.
3. Under **User Settings**, select **Edit Token**.
4. Click **Regenerate** to generate the API token used by this integration.

#### Vendor resources

- [REST API documentation](https://docs.stamus-networks.com/42.2.0/developer-corner/rest-api.html)
- [JSON Data Format](https://docs.stamus-networks.com/42.2.0/developer-corner/json-format.html)

### Set up steps in Kibana

Add the **Stamus Networks** integration in Fleet and configure:

* **Central Server URL** — the base URL of your CNCS instance, for example, `https://cncs.example.com`
  (no trailing `/rest/`).
* **API Token** — the token generated above.

The `alerts` data stream uses these two settings. It also exposes its own **Interval** (polling
frequency, default 5m) and **Initial lookback** (default 24h).

### Validation

After enabling the integration, generate or wait for Suricata alert traffic on your monitored
network, then check **Discover** in Kibana for documents in the
`logs-stamus_networks.alerts-*` data stream.

## Troubleshooting

- No data is being collected: Verify the Central Server URL and API token are correct, and that the host running Elastic Agent can reach the CNCS REST API over HTTPS.
- 401 Unauthorized errors: The API token might have been regenerated or revoked in the CNCS UI. Regenerate the token in CNCS and update the integration configuration. The Stamus API has no automated token-rotation mechanism.
- Alert and stamus documents are retrieved from `/rest/rules/es/events_tail/`. This integration is tested against a full Stamus Clear NDR server, where that endpoint returns full alert documents and `event_type: stamus` correlation records. Pagination is a DRF `{count, next, previous, results}` envelope. A full Clear NDR server honors `page`. Community Clear NDR honors `page_number`. The collector sends both parameters set to the same value, and continues while `next` is non-null.
- Declaration of Compromise / Policy Violation records (`event_type: stamus`) require a Stamus Clear NDR **Tier 3** license and are returned on a full Clear NDR server. If stamus events are missing, confirm the license tier. A non-retryable error on the `stamus` phase advances to the next window; only a persistent error on the `alert` phase retries.
- Beaconing detection fields (`stamus_networks.alerts.beaconing_report.*`, `stamus_networks.alerts.beaconing_statistics.*`) are mapped but have not been observed in any sample data used to build this integration. Treat them as unverified end-to-end even though the fields are vendor-documented.

## Performance and scaling

The `alerts` data stream polls `events_tail` for both alert and Stamus declaration phases. Each
completed collection window requires at least two requests, plus one request for every additional
page returned by either phase. The default interval is 5m and the default initial lookback is 24h.
`collection_delay` (default 1m) keeps the cursor behind now so alerts that become searchable
slightly after their own timestamp are not skipped.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:
* `GET /rest/rules/es/events_tail/` — alert and stamus (Declaration of Compromise/Policy Violation) events for the `alerts` data stream.

See the [REST API documentation](https://docs.stamus-networks.com/42.2.0/developer-corner/rest-api.html) for authentication, pagination, and filtering details.

### Vendor documentation links

- [Stamus Networks Clear NDR documentation](https://docs.stamus-networks.com/)
- [REST API](https://docs.stamus-networks.com/42.2.0/developer-corner/rest-api.html)
- [DoC versus DoPV concepts](https://docs.stamus-networks.com/42.2.0/concepts/doc-vs-dopv.html)
- [Outlier Alerts concepts](https://docs.stamus-networks.com/42.2.0/concepts/alert-outliers.html)

### Dashboards

The package ships one dashboard:

- **[Logs Stamus Networks] Alerts** covers Suricata IDS/IPS signature alerts and Stamus rule metadata.

### Data streams

#### alerts

The `alerts` data stream provides events from the Stamus Clear NDR Central Server REST API of the
following types: Suricata IDS/IPS signature-match alerts (`event_type: alert`) and Stamus
Declaration of Compromise/Policy Violation correlation records (`event_type: stamus`), including
Sightings, Outlier Alert, and File Identification classification tags.

##### alerts fields

{{ fields "alerts" }}

##### alerts sample event

{{ event "alerts" }}

{{ ilm }}

{{ transform }}
