# Speculus Threat Intelligence

## Overview

The Speculus Threat Intelligence integration connects to the Speculus TAXII 2.1 server and collects threat intelligence indicators in [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) format. The indicators are mapped to the Elastic Common Schema (ECS) and indexed into Elasticsearch for use in detection rules, indicator-match enrichment, and threat hunting.

Speculus is a curated IP threat intelligence feed. Each indicator carries a risk score, observed activity, named attribution where known, and rich network context (geo, ISP/ASN, cloud provider, residential proxy, scanner, and Tor classifications).

### Compatibility

This integration is compatible with the Speculus TAXII 2.1 server and has been tested against Elastic Stack 8.18.0 and later.

### How it works

The Elastic Agent uses the CEL input to poll the single Speculus TAXII collection. On each interval tick the agent sends `added_after` for incremental sync (and the TAXII `next` cursor for pagination), then forwards each STIX object to the ingest pipeline. The pipeline parses the STIX `pattern` and maps fields to ECS `threat.indicator.*`. Non-ECS STIX fields, including the Speculus `x_speculus_*` extension properties, are namespaced under `ti_speculus_taxii.stix.*`.

## What data does this integration collect?

This integration collects a single data stream:

- **indicator**: STIX 2.1 indicator objects from the Speculus TAXII server. Each indicator is emitted with `event.kind: enrichment` and mapped to ECS `threat.indicator.*` fields. The feed consists of IPv4 indicators (with IPv6 planned).

### Supported use cases

- Enriching alerts in Elastic Security with STIX-based threat indicators.
- Driving indicator-match detection rules.
- Building dashboards and reports over current threat landscape activity.

## What do I need to use this integration?

- A self-managed or Cloud Elastic deployment with Elastic Stack 8.18.0 or later.
- An Elastic Agent enrolled in Fleet (Fleet-managed deployment is recommended; agentless deployment is also supported).
- A Speculus account with TAXII access and an API key.

## How do I deploy this integration?

This integration is deployed using the Elastic Agent. See the general [Observability getting started guide](https://www.elastic.co/guide/en/observability/current/observability-get-started.html) for an end-to-end overview of installing the Agent and adding integrations.

### Onboard and configure

1. In Kibana, navigate to **Management > Integrations** and search for "Speculus Threat Intelligence".
2. Click **Add Speculus Threat Intelligence**.
3. Configure the following settings:
   - **Speculus TAXII Base URL**: Default `https://feed.speculus.co`. Change only if Speculus provides a different host.
   - **Collection ID**: Default is the `speculus-ioc-feed` collection. Change only if Speculus provides a different collection.
   - **API Key**: Your Speculus API key, sent as a Bearer token. Stored as a policy secret and masked in the UI.
   - **Interval**: Time between polling cycles (default `15m`, matching the Speculus feed refresh cadence).
   - **Initial Interval**: How far back to look on first start (default `720h`, i.e. 30 days).
   - **IOC Expiration Duration**: How long indicators remain valid after their last seen timestamp (default `90d`).
   - **Limit**: Max STIX objects per TAXII request (default `1000`). The agent paginates using the TAXII `next` cursor.
   - **Proxy URL** (optional): If you need to connect through a proxy.
   - **SSL Configuration** (optional): Custom SSL settings if needed.
4. Both Fleet-managed and agentless deployment modes are supported.
5. Click **Save and continue** to deploy the integration.

### Validation

After deployment, verify that data is flowing:

1. In Kibana, open **Discover** and select the `logs-ti_speculus_taxii.indicator-*` data view. Documents should start appearing within one `Interval`.
2. Confirm `threat.indicator.ip` and `threat.indicator.confidence` are populated on the documents.

## Troubleshooting

### No data appearing

1. Verify the API key is correct and active.
2. Check that the base URL and collection ID are reachable.
3. Inspect Elastic Agent logs for connection errors. `401`/`403` indicates an invalid or expired API key; `timeout` indicates network or proxy issues.

### Mapping failures

Check the failure store: `GET .fs-logs-ti_speculus_taxii.indicator-*/_count`. The expected value is `0`. If non-zero, query the failure store for `error.message` to identify the offending field or document.

### STIX parsing errors

1. Check the `event.original` field for the raw STIX document.
2. Verify the STIX `spec_version` is `2.1` (other versions are dropped).
3. Inspect `error.message` for the specific parser error.

## Performance and scaling

The CEL input paginates the collection using the TAXII `next` cursor with the configured `Limit` (default `1000` objects per request). On steady-state runs only indicators modified since the last sweep are returned, keeping each tick lightweight.

## Reference

### Logs reference

#### Indicator

{{fields "indicator"}}

{{event "indicator"}}

### Inputs used in this integration

- [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html): Polls the Speculus TAXII 2.1 server with `added_after` filtering and TAXII `next` cursor pagination.

### APIs used to collect data

- `GET /{api_root}/collections/{collection_id}/objects/?added_after={ts}&limit={n}` — Returns a STIX 2.1 envelope of indicator objects.
- `GET /{api_root}/collections/{collection_id}/objects/?next={cursor}&limit={n}` — Returns the next page of the collection.

### STIX to ECS field mapping

| STIX Field | ECS Field |
|------------|-----------|
| `id` | `event.id` |
| `type` | `threat.indicator.type` |
| `modified` | `threat.indicator.last_seen`, `threat.indicator.modified_at` |
| `valid_from` | `threat.indicator.first_seen` |
| `valid_until` | `ti_speculus_taxii.stix.ioc_expiration_date` |
| `confidence` | `threat.indicator.confidence` |
| `description` | `threat.indicator.description` |
| `name` | `threat.indicator.name` |
| `labels` | `tags` |
| `x_speculus_location.lat/lon` | `threat.indicator.geo.location` |
| `x_speculus_location.country_code` | `threat.indicator.geo.country_iso_code` |
| `x_speculus_identity.asn` | `threat.indicator.as.number` |
| `x_speculus_identity.org/isp` | `threat.indicator.as.organization.name` |

### Confidence mapping

STIX `confidence` (0-100, the Speculus risk score) is mapped to ECS `threat.indicator.confidence`:

| STIX Confidence | ECS Confidence |
|-----------------|----------------|
| 0 | None |
| 1-25 | Low |
| 26-49 | Medium |
| 50-100 | High |
| absent | Low |

### IOC expiration

By default, indicators expire 90 days after their last seen timestamp. The behavior is controlled by **IOC Expiration Duration**:

- If `valid_until` is present in the STIX object, it is used as the expiration date.
- Otherwise the expiration is calculated as `modified + ioc_expiration_duration`.
- The reason is recorded in `ti_speculus_taxii.stix.ioc_expiration_reason`.

### External references

- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [Elastic Threat Intelligence Integration Guide](https://www.elastic.co/guide/en/security/current/threat-intelligence.html)
