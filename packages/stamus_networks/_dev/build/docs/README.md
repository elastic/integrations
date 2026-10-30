{{- generatedHeader }}
# Stamus Networks Integration for Elastic

## Overview

The Stamus Networks integration for Elastic enables collection of IDS/IPS alerts, protocol and
network logs, Declaration of Compromise (DoC) and Declaration of Policy Violation (DoPV)
correlation records, and host inventory data from [Stamus Networks Clear NDR](https://www.stamus-networks.com/) (formerly
branded "Stamus Security Platform") — a Network Detection and Response (NDR) / Network Security
Monitoring (NSM) platform built on [Suricata](https://suricata.io/), the open-source IDS/IPS/NSM
engine. Data is collected from the Clear NDR Central Server (CNCS) REST API.

### Compatibility

This integration was built and tested against Stamus Networks CNCS 42.2.0 and its documented REST
API. It relies on a static, per-user API token for authentication (no OAuth2 flow is available).
Retrieving the embedded `stamus.*` Declaration of Compromise/Policy Violation object requires a
Stamus Tier 3 license; the `alerts` data stream otherwise works with the lower Tier 2 license.

### How it works

This integration polls the CNCS REST API on a configurable interval using the `cel` input. The
`alerts` data stream retrieves Suricata IDS/IPS alert events and Stamus DoC/DoPV correlation
records with a persisted time-range cursor (`from_date`/`to_date`). The `network` data stream
uses the same `events_tail` endpoint and cursor, walking an ordered list of protocol event types
(fileinfo, then DNS, HTTP, TLS, flow, and the remaining Suricata EVE types) inside each window.
The `host_insights` data stream retrieves the full host inventory on every poll cycle, since the
API does not expose an incremental ("updated since") filter for that endpoint.

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
* **network**: Suricata protocol and network logs from the same `events_tail` API, in one data
  stream rather than one stream per event type. DNS and flow are high volume. Shorten
  **Initial lookback** (`initial_interval`, default 24h) on first install so the first poll does
  not pull a full day of those logs. Event types with no sample in the reference cluster are still
  collected and mapped from the Suricata EVE schema.
* **host_insights**: a continuously-updated per-host inventory/profile object (hostnames, users,
  roles, services, TLS/SSH/HTTP client fingerprints). This is an entity/inventory data stream, not
  a timestamped event stream.

### Supported use cases

Use this integration to bring Stamus Networks' curated, high-fidelity NDR threat detections
(alerts and Declarations) into Elastic Security for correlation with other telemetry, threat
hunting, and dashboarding, and to populate Elastic's entity store with network-asset inventory
collected by Stamus Host Insights.

## What do I need to use this integration?

* A running Stamus Networks Clear NDR deployment (Central Server, CNCS) reachable from the host
  running Elastic Agent.
* A dedicated, read-only ("Active" tier) CNCS user account is recommended for the integration
  rather than reusing an administrative account's token.
* Stamus Tier 2 licensing (REST API access) at minimum; Tier 3 licensing is required for the
  `stamus.*` Declaration of Compromise/Policy Violation object on the `alerts` data stream.

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
- [Host Insights concepts](https://docs.stamus-networks.com/42.2.0/concepts/host-insights.html)

### Set up steps in Kibana

Add the **Stamus Networks** integration in Fleet and configure:

* **Central Server URL** — the base URL of your CNCS instance, for example, `https://cncs.example.com`
  (no trailing `/rest/`).
* **API Token** — the token generated above.

The `alerts`, `network`, and `host_insights` data streams share these two settings. Each data
stream also exposes its own **Interval** (polling frequency) and, for `alerts` and `network`, an
**Initial lookback**. DNS and flow logs on the `network` stream are high volume: shorten
**Initial lookback** on first install (the default is 24h). For `host_insights`, keep the interval
conservative relative to the size of your host inventory, since every poll cycle performs a full
re-read of all hosts (see Performance and scaling, below).

### Validation

After enabling the integration, generate or wait for Suricata alert traffic on your monitored
network, then check **Discover** in Kibana for documents in the
`logs-stamus_networks.alerts-*`, `logs-stamus_networks.network-*`, and `logs-stamus_networks.host_insights-*` data streams.

## Troubleshooting

- No data is being collected: Verify the Central Server URL and API token are correct, and that the host running Elastic Agent can reach the CNCS REST API over HTTPS.
- 401 Unauthorized errors: The API token may have been regenerated or revoked in the CNCS UI. Regenerate the token in CNCS and update the integration configuration; the Stamus API has no automated token-rotation mechanism.
- Multiple host_insights documents per host: The host_insights data stream performs a full re-read of the host inventory on every poll cycle, since the API does not expose an incremental filter. Change detection is handled upstream, by the CEL program's persisted per-host baseline (`host.ip` -> a comparable snapshot of that host's inventory content, with `hostname[]` kept in full and `first_seen`/`last_seen` stripped from every other sub-object): a host is only emitted into a given poll's events when it is new to the baseline or its comparable content has genuinely changed since the last time that specific host was observed, so an unchanged re-poll produces no document at all. Documents therefore get a normal, Elasticsearch-auto-generated `_id`, exactly like any other log event -- no custom `_id` scheme is used. This means `host_insights` will contain **a new document per host only when it is first observed, or when its profile genuinely changes** by design -- not on every poll, and not a fixed one-document-per-host total. If you need a single current-state-per-host view, build it downstream (for example an Elasticsearch transform aggregating by `entity.id` with `max(@timestamp)`, or ingestion into the Elastic Entity Store); this package does not maintain that view itself. Separately, hosts are keyed only by IP address, which is not a maximally stable identifier (no MAC address or UUID is exposed by the API), so a host that changes IP address via DHCP may appear as a new entity.
- REST endpoint behavior for the alerts data stream (confirmed against a live, open-source Clear NDR Community/SELKS instance): this integration's CEL program retrieves alert and stamus documents from `/rest/rules/es/events_tail/` filtered with `qfilter=event_type:alert` and `qfilter=event_type:stamus`. Although vendor documentation describes this endpoint's scope as non-alert protocol events only, a live test confirmed it does return full raw alert documents when filtered this way, and that the pagination response envelope is a standard DRF `{count, next, previous, results}` shape with `page_number` as the real server-side cursor parameter — both match what this integration's CEL program already implements, so no changes were needed.
- Host Insights (`/rest/appliances/host_id/`) and the full DoC/DoPV correlation layer (`event_type: stamus`) require a Stamus Clear NDR **Tier 3** license. Both were validated only against the documented API shape and a mock. Confirmed against a live, open-source Clear NDR Community/SELKS (below Tier 3) instance: the REST API itself works fine, `qfilter=event_type:stamus` consistently returns zero results, and `/rest/appliances/host_id/` returns a `404` (ruled out as a routing/path issue — on that server, every unmatched path under `/rest/` returns `404` and every unmatched path under `/api/v1/` returns a generic `500`, and `/rest/appliances/host_id/` cleanly follows the `404` pattern). This matches Stamus's own licensing documentation, which lists Host Insights ("Assets Insights") and Declaration of Compromise as Tier 3-only, with the REST API itself available starting at Tier 2. If you see no data, or a 404, on `host_insights` or no `stamus`-typed events, confirm your license tier before treating it as an integration bug. On some server configurations the `stamus` correlation phase may instead return a persistent 400/401/403/404/422 (rather than a clean zero-result page) when gated by licensing; the CEL program treats a non-retryable error on the `stamus` phase as "this phase is unavailable for this window" and advances to the next window's alert collection instead of retrying the failed phase forever — only a persistent error on the `alert` phase (the primary data) halts and retries.
- Beaconing detection fields (`beaconing_report.*`, `beaconing_statistics.*`) are mapped but have not been observed in any sample data used to build this integration; treat as unverified end-to-end even though the fields are vendor-documented.
- `flow_id` precision: `flow_id` is delivered by the API as a large integer (commonly >= 2^53 in production) and is mapped as `keyword` since it is used only as an opaque correlation key, never as a metric. The CEL program parses the raw API response with `decode_json_string_numbers()`, which decodes every JSON number (not just `flow_id`) using its exact original textual form instead of float64, and re-emits it the same way through `encode_json()`; `flow_id` therefore round-trips through this integration with no precision loss, even above 2^53. (An earlier version of this program instead rewrote `flow_id` to a quoted JSON string before a plain `decode_json()` call, via a CEL `regexp:` stream-config block; that mechanism caused Elastic Agent to silently fail to schedule a component for this input — confirmed on Elastic Agent 9.5.5, with no errors logged anywhere — and was removed. `decode_json_string_numbers()` requires no stream-config changes, so it does not reintroduce that failure mode.)

## Performance and scaling

The `network` data stream reads every protocol phase in each time window. DNS and flow dominate
volume. On first install, shorten **Initial lookback** from the default 24h so the first cursor
does not request a full day of those events. After the cursor has caught up, the polling interval
(default 5m) is the steady-state load.

The `host_insights` data stream performs a full inventory read on every poll cycle, since the
Stamus REST API does not expose an incremental ("updated since") filter for the host insights
endpoint. For large host inventories, tune the **Interval** setting conservatively to balance
freshness against API and ingest load. Change detection happens before ingestion, in the CEL
program: it keeps a persisted per-host baseline (keyed on `host.ip`) and only emits a host into a
given poll's events when it is new to the baseline or its comparable content has genuinely
changed since that host was last observed (hostname entries are compared in full, since the
pipeline's `resolve_latest_hostname` script can change `host.name` purely from their relative
timestamp ordering; every other sub-object is compared with its own `first_seen`/`last_seen`
stripped, since those observation-window timestamps advance on nearly every poll regardless of
whether the host's actual profile changed). A re-poll of a host whose state hasn't actually
changed produces no document at all, so there is nothing for the ingest pipeline to deduplicate —
each document that does arrive gets a normal, auto-generated `_id`. Expect roughly one new
document per host each time it is first observed or its profile changes, not a new document on
every single poll or a fixed one-document-per-host total — size retention accordingly.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### API usage

These APIs are used with this integration:
* `GET /rest/rules/es/events_tail/` — alert and stamus (Declaration of Compromise/Policy Violation) events for the `alerts` data stream, and protocol/network logs for the `network` data stream.
* `GET /rest/appliances/host_id/` — host inventory profiles for the `host_insights` data stream.

See the [REST API documentation](https://docs.stamus-networks.com/42.2.0/developer-corner/rest-api.html) for authentication, pagination, and filtering details.

### Vendor documentation links

- [Stamus Networks Clear NDR documentation](https://docs.stamus-networks.com/)
- [REST API](https://docs.stamus-networks.com/42.2.0/developer-corner/rest-api.html)
- [DoC versus DoPV concepts](https://docs.stamus-networks.com/42.2.0/concepts/doc-vs-dopv.html)
- [Host Insights concepts](https://docs.stamus-networks.com/42.2.0/concepts/host-insights.html)
- [Outlier Alerts concepts](https://docs.stamus-networks.com/42.2.0/concepts/alert-outliers.html)

### Dashboards

The package ships four dashboards, linked to each other:

- **[Logs Stamus Networks] IDS and Declarations** covers signature alerts and Declaration of Compromise or Policy Violation records: categories, severity, affected products, attack targets, malware families, Stamus classification, kill chain, threat families, assets, and sightings.
- **[Logs Stamus Networks] Protocol Insights** covers TLS versions, server names, JA4 and JA3S, transferred files, DNS questions, HTTP hostnames, and protocol anomalies.
- **[Logs Stamus Networks] Host Insights** covers the host inventory: roles, hostnames, usernames, services, HTTP servers, TLS issuers, and SSH or HTTP client software.
- **[Logs Stamus Networks] SMB Insights** covers SMB commands, status, dialects, named pipes, shares, and SMB insight summaries.

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

#### network

The `network` data stream collects Suricata protocol and network logs from
`GET /rest/rules/es/events_tail/`. One CEL input walks a fixed phase list. Live event types are
collected first (fileinfo, dns, http, tls, flow, snmp, krb5, anomaly, smb, smb_insights, quic,
dhcp, dcerpc, ssh, rdp, mqtt, sip, tftp), then event types that had no sample in the reference
cluster but are still requested (smtp, pop3, ftp, ftp_data, http2, nfs, ike, ikev2, dnp3, rfb,
bittorrent_dht, pgsql, modbus, arp, netflow, stats). An empty first page ends that phase. After
the last phase, the time window advances.

DNS and flow are high volume. Shorten `initial_interval` on first install.

A transport error or HTTP error keeps the cursor on the current phase and page. The next poll
retries that request. The stream does not skip a protocol phase after an error.

##### network fields

{{ fields "network" }}

##### network sample event

{{ event "network" }}

#### host_insights

The `host_insights` data stream provides a continuously-updated per-host inventory/profile from
the Stamus Clear NDR Central Server REST API (hostnames, usernames, roles, services, and
TLS/SSH/HTTP client fingerprints observed for the host). This is an entity/inventory data stream.

##### host_insights fields

{{ fields "host_insights" }}

##### host_insights sample event

{{ event "host_insights" }}

{{ ilm }}

{{ transform }}
