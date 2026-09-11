# SOCRadar Threat Intelligence (TAXII)

## Overview

The SOCRadar Threat Intelligence (TAXII) integration connects to SOCRadar's TAXII 2.1 server and collects threat intelligence indicators in [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) format. The indicators are mapped to the Elastic Common Schema (ECS) and indexed into Elasticsearch for use in detection rules, indicator-match enrichment, and threat hunting.

### Compatibility

This integration is compatible with the SOCRadar TAXII 2.1 server and has been tested against Elastic Stack 8.18.0 and later.

### How it works

The Elastic Agent uses the CEL input to poll SOCRadar TAXII collections in round-robin fashion. On each interval tick, one collection is fetched: the agent sends `added_after` and (where applicable) the TAXII `next` cursor for pagination, then forwards each STIX object to the ingest pipeline. The pipeline parses the STIX `pattern` per indicator type (IP, domain, URL, file hash, email, ASN, Windows registry key, x509 certificate) and maps the fields to ECS `threat.indicator.*`. Non-ECS STIX fields are namespaced under `ti_socradar_taxii.stix.*`.

## What data does this integration collect?

This integration collects a single data stream:

- **indicator**: STIX 2.1 indicator objects from SOCRadar's TAXII server. Each indicator is emitted with `event.kind: enrichment` and mapped to ECS `threat.indicator.*` fields. Supported indicator types: IPv4/IPv6 addresses, domain names, URLs, file hashes (MD5, SHA-1, SHA-256, SHA-384, SHA-512), email addresses, autonomous-system numbers, Windows registry keys, and x509 certificates.

The integration also installs a `latest_ioc` transform that deduplicates the source stream into `logs-ti_socradar_taxii_latest.indicator`, keeping the most recent state per STIX object ID for use in indicator-match detection rules.

### Supported use cases

- Enriching alerts in Elastic Security with STIX-based threat indicators.
- Driving indicator-match detection rules from the deduplicated latest-state index.
- Building dashboards and reports over current threat landscape activity.

## What do I need to use this integration?

- A self-managed or Cloud Elastic deployment with Elastic Stack 8.18.0 or later.
- An Elastic Agent enrolled in Fleet (Fleet-managed deployment is recommended; agentless deployment is also supported).
- A SOCRadar Platform account with TAXII 2.1 access (contact SOCRadar support to enable it).
- TAXII credentials (username and password) issued by SOCRadar.
- The API root(s) and collection ID(s) you want to ingest from. SOCRadar provides three API roots: `radar_alpha`, `radar_gamma`, and `radar_premium`. Collection IDs can be discovered via the SOCRadar Platform UI under **Threat Intelligence → TAXII Collections**.

## How do I deploy this integration?

This integration is deployed using the Elastic Agent. See the general [Observability getting started guide](https://www.elastic.co/guide/en/observability/current/observability-get-started.html) for an end-to-end overview of installing the Agent and adding integrations.

### Onboard and configure

1. In Kibana, navigate to **Management > Integrations** and search for "SOCRadar TAXII".
2. Click **Add SOCRadar TAXII**.
3. Configure the following settings:
   - **SOCRadar TAXII Base URL**: Default `https://taxii2.socradar.com`. Change only if SOCRadar provides a different host.
   - **Collections Configuration**: YAML list of `{api_root, collection_id}` pairs. The agent polls one collection per `Interval` tick in round-robin fashion. Collections from different API roots can be mixed in a single integration policy. Example:
     ```yaml
     - api_root: "radar_alpha"
       collection_id: "fd3fec42-efee-4353-85b2-cb87f9acc4ef"
     - api_root: "radar_gamma"
       collection_id: "00000000-0000-0000-0000-000000000010"
     - api_root: "radar_premium"
       collection_id: "00000000-0000-0000-0000-000000000050"
     ```
     If an entry is invalid the tick is skipped (the input does not stall) and polling continues with the next collection on the next tick. The error is recorded as an event with `error.code` and `error.message`.
   - **Username**: SOCRadar TAXII username (HTTP Basic authentication).
   - **Password**: SOCRadar TAXII password. Stored as a policy secret and masked in the UI.
   - **Interval**: Time between polling cycles (default `5m`). With N collections, each individual collection is refreshed roughly every `N × Interval`.
   - **Initial Interval**: How far back to look on first start (default `10h`).
   - **IOC Expiration Duration**: How long indicators remain valid after their last seen timestamp (default `90d`).
   - **Limit**: Max STIX objects per TAXII request (default `1000`). The agent paginates a single collection using the TAXII `next` cursor before round-robin advances to the next collection.
   - **Proxy URL** (optional): If you need to connect through a proxy.
   - **SSL Configuration** (optional): Custom SSL settings if needed.
4. Both Fleet-managed and agentless deployment modes are supported.
5. Click **Save and continue** to deploy the integration.

### Validation

After deployment, verify that data is flowing:

1. In Kibana, open **Discover** and select the `logs-ti_socradar_taxii.indicator-*` data view. Documents should start appearing within one `Interval`.
2. Check the `latest_ioc` transform under **Stack Management → Transforms**: the state should be `started` and `documents_processed` should grow over time.
3. Open the **[SOCRadar TAXII] IOC Overview** dashboard to see indicator counts, types, and feed sources.

## Troubleshooting

### No data appearing

1. Verify TAXII credentials are correct (username and password URL-encoded if they contain special characters).
2. Check that the collection is reachable and contains indicators.
3. Inspect Elastic Agent logs for connection errors. `401`/`403` indicates invalid or expired credentials; `timeout` indicates network or proxy issues.

### Mapping failures

Check the failure store: `GET .fs-logs-ti_socradar_taxii.indicator-*/_count`. The expected value is `0`. If non-zero, query the failure store for `error.message` to identify the offending field or document.

### STIX parsing errors

1. Check the `event.original` field for the raw STIX document.
2. Verify the STIX `spec_version` is `2.1` (other versions are dropped).
3. Inspect `error.message` for the specific parser error.

### Transform shows zero documents

The `logs-ti_socradar_taxii.latest_ioc-default-0.1.0` transform deduplicates indicators into the `logs-ti_socradar_taxii_latest.indicator-*` index. If `documents_processed` stays at `0` for more than `Interval × 2`, restart the transform from **Stack Management → Transforms**.

For SOCRadar-side issues (collection availability, TAXII credential permissions), consult the [SOCRadar Platform documentation](https://platform.socradar.com).

## Performance and scaling

The CEL input fetches one collection per `Interval` tick; the polling cost scales linearly with the number of configured collections. For environments with many collections, increase `Interval` rather than running many tightly-packed ticks, and split very large collection sets across multiple integration policies on separate agents.

A single collection is paginated using the TAXII `next` cursor with the configured `Limit` (default `1000` objects per request). Pagination of a single collection completes before the next collection is polled.

The `latest_ioc` transform runs every 60 seconds and indexes one document per unique STIX object ID; cluster sizing should account for the deduplicated indicator count rather than the raw event volume.

## Reference

### Logs reference

#### Indicator

{{fields "indicator"}}

{{event "indicator"}}

### Inputs used in this integration

- [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html): Polls the SOCRadar TAXII 2.1 server with `added_after` filtering, multi-collection round-robin selection, and TAXII `next` cursor pagination.

### APIs used to collect data

- `GET /{api_root}/collections/{collection_id}/objects/?added_after={ts}&limit={n}` — Returns a STIX 2.1 envelope of indicator objects.
- `GET /{api_root}/collections/{collection_id}/objects/?next={cursor}&limit={n}` — Returns the next page of a collection.

### SOCRadar API roots

| API Root | Collections | Description |
|----------|-------------|-------------|
| `radar_alpha` | ~15 | Curated alpha threat intelligence feed |
| `radar_gamma` | ~150 | Broader gamma threat intelligence feed |
| `radar_premium` | ~600 | Full premium threat intelligence feed |

### Supported STIX indicator types

| STIX Type | Example Pattern | ECS Fields |
|-----------|-----------------|------------|
| `ipv4-addr` | `[ipv4-addr:value = '192.0.2.1']` | `threat.indicator.ip`, `related.ip` |
| `ipv6-addr` | `[ipv6-addr:value = '2001:db8::1']` | `threat.indicator.ip`, `related.ip` |
| `domain-name` | `[domain-name:value = 'evil.example']` | `threat.indicator.url.domain`, `related.hosts` |
| `url` | `[url:value = 'http://malicious.example']` | `threat.indicator.url.full`, `threat.indicator.url.original` |
| `file` (MD5) | `[file:hashes.MD5 = '...']` | `threat.indicator.file.hash.md5`, `related.hash` |
| `file` (SHA-1) | `[file:hashes.'SHA-1' = '...']` | `threat.indicator.file.hash.sha1`, `related.hash` |
| `file` (SHA-256) | `[file:hashes.'SHA-256' = '...']` | `threat.indicator.file.hash.sha256`, `related.hash` |
| `file` (SHA-384) | `[file:hashes.'SHA-384' = '...']` | `threat.indicator.file.hash.sha384`, `related.hash` |
| `file` (SHA-512) | `[file:hashes.'SHA-512' = '...']` | `threat.indicator.file.hash.sha512`, `related.hash` |
| `email-addr` | `[email-addr:value = 'bad@actor.example']` | `threat.indicator.email.address` |
| `email-message` | `[email-message:from_ref.value = '...']` | `threat.indicator.email.address` |
| `autonomous-system` | `[autonomous-system:number = 12345]` | `threat.indicator.as.number` |
| `windows-registry-key` | `[windows-registry-key:key = 'HKLM\\...']` | `threat.indicator.registry.key` |
| `x509-certificate` | `[x509-certificate:hashes.'SHA-256' = '...']` | `threat.indicator.x509.serial_number`, `threat.indicator.x509.subject.common_name` |

### STIX to ECS field mapping

| STIX Field | ECS Field |
|------------|-----------|
| `id` | `event.id` |
| `type` | `threat.indicator.type` |
| `created` | `threat.indicator.first_seen` |
| `modified` | `threat.indicator.modified_at` |
| `valid_from` | `threat.indicator.first_seen` |
| `valid_until` | `ti_socradar_taxii.stix.ioc_expiration_date` |
| `confidence` | `threat.indicator.confidence` |
| `description` | `threat.indicator.description` |
| `labels` | `tags` |
| `pattern` | `ti_socradar_taxii.stix.pattern` |
| `spec_version` | `ti_socradar_taxii.stix.spec_version` |

### Confidence mapping

STIX `confidence` (0-100) is mapped to ECS `threat.indicator.confidence`:

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
- Expired indicators are marked in `ti_socradar_taxii.stix.ioc_expiration_reason`.

### Dashboards

- **[SOCRadar TAXII] IOC Overview** — KPI metrics (Total Indicators, Unique STIX IDs, IOC Types, Feed Sources) and visualizations (Indicators by Type, Indicators by Feed Source, Indicators by Confidence, Indicators Over Time, Feed Source Breakdown, Recent Indicators).

### External references

- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [Elastic Threat Intelligence Integration Guide](https://www.elastic.co/guide/en/security/current/threat-intelligence.html)
