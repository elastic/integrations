# SOCRadar Threat Intelligence (TAXII) integration

The SOCRadar TAXII integration connects to SOCRadar's TAXII 2.1 server to collect threat intelligence indicators in [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) format. It converts the indicators into the Elastic Common Schema (ECS) for ingestion into Elasticsearch.

## Data streams

This integration collects threat intelligence indicators via a single data stream:

- **indicator**: Collects STIX 2.1 indicator objects from SOCRadar's TAXII 2.1 server, including IP addresses, domain names, file hashes, URLs, and email addresses.

## Requirements

- Elastic Agent 8.18.0 or later
- SOCRadar Platform account with TAXII 2.1 access
- TAXII credentials (username and password)

## Setup

### Prerequisites

1. Contact SOCRadar support to enable TAXII 2.1 access for your account.
2. Obtain your TAXII credentials (username and password).
3. Identify the API root(s) and collection ID(s) you want to ingest from. SOCRadar provides three API roots: `radar_alpha`, `radar_gamma`, `radar_premium` — see the [SOCRadar API roots](#socradar-api-roots) table below.

### Configuration

1. In Kibana, navigate to **Management > Integrations** and search for "SOCRadar TAXII".
2. Click **Add SOCRadar TAXII**.
3. Configure the following settings:
   - **SOCRadar TAXII Base URL**: Default `https://taxii2.socradar.com`. Change only if SOCRadar provides a different host.
   - **Collections Configuration**: YAML list of `{api_root, collection_id}` pairs. The agent polls one collection per `Interval` tick in round-robin fashion. You can mix collections from different API roots in a single integration policy. Example:
     ```yaml
     - api_root: "radar_alpha"
       collection_id: "fd3fec42-efee-4353-85b2-cb87f9acc4ef"
     - api_root: "radar_gamma"
       collection_id: "00000000-0000-0000-0000-000000000010"
     - api_root: "radar_premium"
       collection_id: "00000000-0000-0000-0000-000000000050"
     ```
     If a `collection_id` or `api_root` is invalid, that tick is skipped (the input does not stall) and polling continues with the next collection on the next tick. The error is recorded as an event with `error.code` and `error.message`.
   - **Username**: Your SOCRadar TAXII username (Basic HTTP authentication).
   - **Password**: Your SOCRadar TAXII password (stored as a policy secret, masked in the UI).
   - **Interval**: Time between polling cycles (default `5m`). With N collections, each individual collection is refreshed roughly every `N × Interval`.
   - **Initial Interval**: How far back to look on first start (default `10h`).
   - **IOC Expiration Duration**: How long indicators remain valid after their last seen timestamp (default `90d`).
   - **Limit**: Max STIX objects per TAXII request (default `1000`). The agent paginates automatically using the TAXII `next` cursor; pagination of a single collection completes before round-robin advances to the next collection.
   - **Proxy URL** (optional): If you need to connect through a proxy.
   - **SSL Configuration** (optional): Custom SSL settings if needed.
4. Click **Save and continue** to deploy the integration.

### SOCRadar API roots

SOCRadar provides the following TAXII API roots. Collection IDs can be discovered via the SOCRadar Platform UI under **Threat Intelligence → TAXII Collections**.

| API Root | Collections | Description |
|----------|-------------|-------------|
| `radar_alpha` | ~15 | Alpha threat intelligence feed (curated indicators) |
| `radar_gamma` | ~150 | Gamma threat intelligence feed (broader coverage) |
| `radar_premium` | ~600 | Premium threat intelligence feed (full SOCRadar feeds catalog) |

Endpoint format (constructed automatically from base URL + api_root + collection_id):
```
https://taxii2.socradar.com/{api_root}/collections/{collection_id}/objects/
```

## STIX to ECS Mapping

### Indicator Types

The following STIX indicator types are supported and mapped to ECS fields:

| STIX Type | STIX Pattern Example | ECS Fields |
|-----------|---------------------|------------|
| `ipv4-addr` | `[ipv4-addr:value = '192.168.1.1']` | `threat.indicator.ip`, `related.ip` |
| `ipv6-addr` | `[ipv6-addr:value = '::1']` | `threat.indicator.ip`, `related.ip` |
| `domain-name` | `[domain-name:value = 'evil.com']` | `threat.indicator.url.domain`, `related.hosts` |
| `url` | `[url:value = 'http://malicious.com']` | `threat.indicator.url.full`, `threat.indicator.url.original` |
| `file` (MD5) | `[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']` | `threat.indicator.file.hash.md5`, `related.hash` |
| `file` (SHA-1) | `[file:hashes.'SHA-1' = '...']` | `threat.indicator.file.hash.sha1`, `related.hash` |
| `file` (SHA-256) | `[file:hashes.'SHA-256' = '...']` | `threat.indicator.file.hash.sha256`, `related.hash` |
| `file` (SHA-384) | `[file:hashes.'SHA-384' = '...']` | `threat.indicator.file.hash.sha384`, `related.hash` |
| `file` (SHA-512) | `[file:hashes.'SHA-512' = '...']` | `threat.indicator.file.hash.sha512`, `related.hash` |
| `email-addr` | `[email-addr:value = 'bad@actor.com']` | `threat.indicator.email.address` |
| `email-message` | `[email-message:from_ref.value = '...']` | `threat.indicator.email.address` |
| `autonomous-system` | `[autonomous-system:number = 12345]` | `threat.indicator.as.number` |
| `windows-registry-key` | `[windows-registry-key:key = 'HKLM\\...']` | `threat.indicator.registry.key` |
| `x509-certificate` | `[x509-certificate:hashes.'SHA-256' = '...']` | `threat.indicator.x509.serial_number`, `threat.indicator.x509.subject.common_name` |

### Common Field Mappings

| STIX Field | ECS Field | Description |
|------------|-----------|-------------|
| `id` | `event.id` | STIX indicator unique identifier |
| `type` | `threat.indicator.type` | Indicator type (ipv4-addr, domain-name, etc.) |
| `created` | `threat.indicator.first_seen` | When the indicator was first created |
| `modified` | `threat.indicator.modified_at` | When the indicator was last modified |
| `valid_from` | `threat.indicator.first_seen` | Start of indicator validity |
| `valid_until` | `ti_socradar_taxii.stix.ioc_expiration_date` | End of indicator validity |
| `confidence` | `threat.indicator.confidence` | Confidence score (0-100) mapped to Low/Medium/High |
| `description` | `threat.indicator.description` | Human-readable description |
| `labels` | `tags` | STIX labels converted to tags |
| `pattern` | `ti_socradar_taxii.stix.pattern` | Original STIX pattern |
| `spec_version` | `ti_socradar_taxii.stix.spec_version` | STIX specification version |

### Confidence Mapping

STIX confidence scores (0-100) are mapped to ECS confidence levels:

| STIX Confidence | ECS Confidence |
|-----------------|----------------|
| 0 | None |
| 1-25 | Low |
| 26-49 | Medium |
| 50-100 | High |
| absent | Low |

## IOC Expiration

By default, indicators expire 90 days after their last seen timestamp. This behavior can be controlled via the **IOC Expiration Duration** setting:

- If `valid_until` is present in the STIX object, it is used as the expiration date.
- If `valid_until` is not present, the expiration is calculated as: `modified + ioc_expiration_duration`.
- Expired indicators are marked in the `ti_socradar_taxii.stix.ioc_expiration_reason` field.

## Transforms

This integration includes a `latest_ioc` transform that:

- Runs every 60 seconds
- Maintains the latest unique IOC per `event.dataset` and `ti_socradar_taxii.stix.id`
- Stores results in `logs-ti_socradar_taxii_latest.indicator`
- Removes indicators 1 minute after their `ti_socradar_taxii.stix.ioc_expiration_date`

Use the transform index for:
- Indicator match rules
- Threat intelligence lookups
- Current threat landscape analysis

## Dashboards

The integration includes the following dashboards:

### [SOCRadar TAXII] IOC Overview

Provides a comprehensive view of threat intelligence indicators (10 panels):

KPI metrics:
- **Total Indicators**: Total count of indicators in the selected time range
- **Unique STIX IDs**: Number of distinct STIX object IDs
- **IOC Types**: Number of distinct indicator types
- **Feed Sources**: Number of distinct upstream threat feeds

Visualizations:
- **Indicators by Type**: Donut chart breakdown (ipv4-addr, file, url, domain-name, etc.)
- **Indicators by Feed Source**: Donut chart breakdown by `ti_socradar_taxii.stix.threat_feed_source_name`
- **Indicators by Confidence**: Donut chart breakdown by ECS confidence (Low/Medium/High)
- **Indicators Over Time**: Area chart, time series of indicator ingestion split by type
- **Feed Source Breakdown**: Top 20 feed sources table with document counts
- **Recent Indicators**: Sortable table of latest indicators (timestamp, STIX ID, type, feed, confidence)

## Troubleshooting

### No data appearing

1. Verify TAXII credentials are correct
2. Check the collection URL is accessible
3. Ensure the collection contains indicators
4. Check Elastic Agent logs for connection errors

```bash
# Check agent logs
elastic-agent diagnostics collect
```

### Authentication errors

- Verify username and password are URL-encoded if they contain special characters
- Check proxy settings if connecting through a proxy

### Data parsing errors

1. Check `event.original` field for raw STIX data
2. Verify STIX spec_version is 2.1 (other versions are dropped)
3. Check `error.message` field for specific parsing errors

### Performance issues

- Adjust the `limit` parameter in CEL configuration (default: 1000)
- Consider using multiple integrations for different collections
- Monitor Elasticsearch cluster resources

### Common STIX Pattern Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Indicator not parsed | Unsupported STIX type | Check `ti_socradar_taxii.stix.type` field in logs |
| Pattern extraction failed | Complex pattern | Check `ti_socradar_taxii.stix.pattern` format |
| Missing ECS fields | Null values in STIX | Check STIX object completeness |

## Reference

- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [Elastic Threat Intelligence Integration Guide](https://www.elastic.co/guide/en/security/current/threat-intelligence.html)

## Logs reference


### Indicator

{{fields "indicator"}}

{{event "indicator"}}
