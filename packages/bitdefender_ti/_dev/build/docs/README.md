{{- generatedHeader }}
# Bitdefender IntelliZone Integration for Elastic

## Overview
The Bitdefender IntelliZone integration ingests threat intelligence indicators from Bitdefender reputation feeds into Elastic Security.

### Compatibility
This integration requires:
- Elastic Stack `8.13.0` or newer (including `9.x`), with a Basic subscription or above
- A valid Bitdefender IntelliZone API token
- Network access from Elastic Agent to `https://feeds.ti.bitdefender.com/reputation`

### How it works
Each data stream uses the CEL input to poll the Bitdefender API and ingest indicators:
- `ip_reputation`
- `web_reputation`
- `file_reputation`

The integration uses checkpoint-based polling with safety controls:
- Requests are capped at `now - 60s` by default (`safety_lag`) to avoid querying very fresh or future data
- The next run starts from the previous successful checkpoint (`last_success_at`)
- A small overlap (`overlap`, default `120s`) protects against scheduler drift
- API windows are chunked to `1h` by default (`max_window`) for safer retries and lower API load

## What data does this integration collect?
The integration collects threat indicators and normalizes them to ECS `threat.indicator.*` fields.

Collected data includes:
- Network indicators (IPv4/IPv6, confidence, severity, ASN, geo, TTL)
- Web indicators (domain/URL, confidence, countries, categories, popularity, TTL)
- File indicators (SHA256/SHA1/MD5, file metadata, confidence, threat family/name)

### Supported use cases
- Indicator match and enrichment in Elastic Security
- Threat hunting pivoting using `related.ip` and `related.hash`
- IOC lifecycle handling for network indicators via TTL-derived expiration fields

## What do I need to use this integration?
- Bitdefender IntelliZone API token with permission to read reputation feeds
- Elastic Agent policy with connectivity to the Bitdefender API endpoint
- Optional proxy/egress rules if outbound internet access is restricted

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Onboard / configure
1. In Kibana, open **Integrations** and install **Bitdefender Threat Intelligence**.
2. Add the integration to an Elastic Agent policy.
3. Provide the package-level `api_token`.
4. Enable one or more data streams: IP reputation, Web reputation, File reputation.
5. Review stream parameters:
- `interval`: poll frequency
- `initial_lookback`: fetch range used only on first run (default `1h`)
- `safety_lag`: delay from current time (default `60s`)
- `overlap`: checkpoint overlap between runs (default `120s`)
- `max_window`: maximum API interval per request (default `1h`)
- `from_param` / `to_param`: query parameter names for interval bounds (defaults `from` and `to`, sent as UNIX seconds)
6. Save and deploy the policy.

Recommended values:
- Keep `safety_lag` at `60s` or higher
- Keep `max_window` at `1h`
- Keep `overlap` at `120s` unless your scheduler jitter is higher

### Validation
After deployment, verify ingestion in Discover:
- `data_stream.dataset : "bitdefender_ti.ip_reputation"`
- `data_stream.dataset : "bitdefender_ti.file_reputation"`
- `data_stream.dataset : "bitdefender_ti.web_reputation"`

Check expected fields:
- `threat.indicator.type`
- `threat.indicator.confidence`
- `threat.feed.vendor : "Bitdefender"`
- `threat.indicator.id`

For network indicators, also verify:
- `threat.indicator.ttl`
- `threat.indicator.valid_until`

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

Common issues:
- `HTTP 400 BAD REQUEST`: time interval may include future timestamps; increase `safety_lag`
- Missing newest indicators: increase `safety_lag` and keep checkpoint overlap enabled
- Slow or heavy requests: reduce `max_window` or increase `interval`
- Duplicate-looking events: expected in overlap windows; stable `threat.indicator.id` supports dedup-friendly analysis

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

Operational guidance:
- Prefer shorter request windows (`1h`) instead of very large windows (`24h`)
- Spread polling intervals across agents to avoid synchronized API bursts
- Use ILM/data retention aligned with indicator lifetime and use case

## Reference
### IP reputation

The `ip_reputation` data stream provides network IOC reputation indicators.

#### IP reputation fields
{{ fields "ip_reputation" }}

### Web reputation

The `web_reputation` data stream provides domain and URL IOC reputation indicators.

#### Web reputation fields
{{ fields "web_reputation" }}

### File reputation

The `file_reputation` data stream provides malicious file hash reputation indicators.

#### File reputation fields
{{ fields "file_reputation" }}

### Inputs used
{{ inputDocs }}

### API usage
The integration queries:
- `GET https://feeds.ti.bitdefender.com/reputation`

Query parameters used:
- `feed_name` (`ip-feed`, `web-feed`, `file-feed`)
- Time window parameters (`from`, `to` by default, configurable; sent as UNIX seconds)
