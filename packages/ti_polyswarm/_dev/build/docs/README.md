# PolySwarm Threat Intelligence

## Overview

The PolySwarm Threat Intelligence integration collects malicious artifact (file) indicators from the [PolySwarm](https://polyswarm.network) CTI API and normalizes them into Elastic Common Schema (ECS) `threat.indicator.*` fields. PolySwarm is a crowdsourced malware-detection marketplace: each artifact submitted to the network is scanned by many independent engines, and the resulting assertions are condensed into a single malicious-likelihood score called the **PolyScore**.

Because the integration writes to `logs-ti_polyswarm.scans-*`, which matches Kibana's default threat intelligence index pattern (`logs-ti_*`), ingested indicators appear automatically under **Security → Explore → Intelligence** and are usable by indicator-match detection rules with no additional configuration.

### Compatibility

This integration has been tested against PolySwarm CTI API `v3` (`GET /v3/search/metadata/query`) and Elastic Stack 8.13.0 and later.

### How it works

The Elastic Agent uses the [CEL input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel) to poll the PolySwarm metadata search API on a configurable interval. Each poll submits a server-side metadata query — by default `artifact.created:>now-1d AND scan.detections.malicious:>0`, a rolling one-day window restricted to artifacts at least one engine flagged as malicious — and pages through the results using the cursor PolySwarm returns in `offset`, continuing while `has_more` is `true`.

Every returned artifact becomes one indicator document. The ingest pipeline maps the artifact hashes, file metadata, and scan timestamps to ECS, derives `threat.indicator.confidence` from the PolyScore, and records the raw vendor payload under the `polyswarm.*` field group. A non-200 response from the API is indexed as a single `event.kind: pipeline_error` document carrying `error.message`, `http.response.status_code`, and `url.full`, rather than as a false indicator.

## What data does this integration collect?

This integration collects a single data stream:

- **scans**: Malicious artifact indicators from PolySwarm metadata search. Each document is emitted with `event.kind: enrichment`, `event.category: [threat]`, `event.type: [indicator]`, and `threat.indicator.type: file`. Artifact hashes are mapped to `threat.indicator.file.hash.{md5,sha1,sha256}` and mirrored into `related.hash` so analysts can pivot on a hash without knowing which field holds it.

The integration also installs a `latest_scans` transform that deduplicates the source stream by SHA-256 into `logs-ti_polyswarm_latest.scans`, keeping one document per artifact. See [Deduplication and IOC expiration](#deduplication-and-ioc-expiration) below.

### Supported use cases

- Driving indicator-match detection rules from the deduplicated latest-state index, so file hashes observed by your endpoints are matched against artifacts PolySwarm recently scored as malicious.
- Enriching and triaging alerts in Elastic Security with PolyScore, malware family, and file metadata for a hash under investigation.
- Building dashboards over the recent malicious-artifact landscape (volume over time, malware families, file types).

## What do I need to use this integration?

- A self-managed or Elastic Cloud deployment running Elastic Stack 8.13.0 or later.
- An Elastic Agent enrolled in Fleet. If you do not have one, see the [Elastic Agent installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). Only one Elastic Agent can be installed per host.
- A PolySwarm account with CTI API access and an API key. Register at [polyswarm.network](https://polyswarm.network); the API key is available from your account settings. Metadata search is a paid capability — confirm your plan includes it before configuring the integration.

## How do I deploy this integration?

This integration is deployed using Elastic Agent. For an end-to-end overview of installing the agent and adding an integration, see the [Fleet and Elastic Agent guide](https://www.elastic.co/docs/reference/fleet).

### Onboard and configure

1. In Kibana, navigate to **Management → Integrations** and search for "PolySwarm".
2. Select **PolySwarm Threat Intelligence**, then click **Add PolySwarm Threat Intelligence**.
3. Configure the following settings:
   - **URL**: PolySwarm API base URL, without a trailing slash. Default `https://api.polyswarm.network`. Change only if PolySwarm provides a different host.
   - **API Key**: Your PolySwarm API key. Stored as a policy secret, masked in the UI, and redacted from CEL request-trace logs.
   - **Interval**: How often to poll the API. Default `5m`. Supported units are `h`, `m`, and `s`.
   - **Query**: The server-side metadata query. Default `artifact.created:>now-1d AND scan.detections.malicious:>0`. Keep the `scan.detections.malicious:>0` clause so only artifacts with at least one malicious detection are ingested as indicators — removing it ingests benign artifacts as threat indicators. See [Tuning the query](#tuning-the-query).
   - **Community**: The PolySwarm community to search. Default `default`.
   - **Batch Size**: Number of results requested per API request. Default `100`. Available under **Advanced options**.
4. Select the agent policy to deploy to, then click **Save and continue**.

### Validation

After deployment, verify that data is flowing:

1. In Kibana, open **Discover** and select the `logs-ti_polyswarm.scans-*` data view. Documents should appear within one **Interval**.
2. Check the `latest_scans` transform under **Stack Management → Transforms**: state should be `started` and `documents_processed` should grow over time. The transform runs every 30 seconds with a 120-second sync delay, so allow roughly three minutes after the first poll before the destination index populates.
3. Open **Security → Explore → Intelligence** and confirm indicators with `threat.feed.name: PolySwarm` are listed.

## Tuning the query

The **Query** setting is passed straight through to PolySwarm's metadata search, so the indicator set is defined server-side. Two clauses matter:

- `artifact.created:>now-1d` bounds the rolling window the integration re-reads on every poll. It must stay comfortably shorter than the transform's 48-hour retention window (see below) — widening it past 48 hours ingests artifacts that immediately fall outside the active view.
- `scan.detections.malicious:>0` is what makes each result an indicator. Keep it.

Useful refinements:

- `AND scan.latest_scan.polyscore:>0.7` — restrict ingestion to high-confidence artifacts only, cutting volume substantially.
- `AND scan.detections.malicious:>3` — require corroboration from multiple engines.
- `AND artifact.mimetype:"application/vnd.microsoft.portable-executable"` — narrow to a single file type.

## Deduplication and IOC expiration

Indicators are held in two tiers, following the same pattern as Elastic's other threat intelligence integrations:

- **Source data stream** `logs-ti_polyswarm.scans-*`: every poll re-ingests the artifacts still inside the rolling query window, duplicates included. This re-assertion acts as a heartbeat proving an indicator is still current. The ILM policy `logs-ti_polyswarm.scans-default_policy` rolls the stream over daily (or at 50 GB primary shard size) and deletes backing indices after 5 days, so the raw stream cannot grow unbounded.
- **Latest transform** `logs-ti_polyswarm_latest.scans`: keeps exactly one document per `threat.indicator.file.hash.sha256`, the most recent by `event.ingested`. Its retention policy deletes indicators whose last re-assertion is older than 48 hours — so once an artifact ages out of the query window, its IOC expires automatically.

For indicator-match rules and dashboards, always query the deduplicated index `logs-ti_polyswarm_latest.scans` rather than the raw source stream.

Each document records the configured polling interval in `labels.interval` for expiration diagnostics.

Both tiers match the default `logs-ti_*` threat index pattern, so the Intelligence page may show source-stream duplicates alongside the deduplicated view. For a strictly deduplicated view, set `securitySolution:defaultThreatIndex` in Kibana's **Advanced Settings** to `logs-ti_polyswarm_latest.scans` (plus any other feeds you use).

### Keep the interval well below the expiration window

Because expiration is driven by recency of re-assertion, a polling interval that approaches 48 hours can let still-current indicators drop out of the latest index between polls. The same window bounds your outage tolerance: if polling stops — agent down, network outage, revoked API key — the latest index drains and is empty within roughly 48 hours of the last successful poll, and indicator-match rules built on it silently stop matching. Alert on ingest freshness (for example, no new `event.ingested` on `logs-ti_polyswarm.scans-*` within a few hours) rather than relying on the active view to show the failure.

## Applying the intel with an indicator-match rule

Enable the prebuilt detection rule **"Threat Intel Hash Indicator Match"** (**Security → Rules → Detection rules → Add Elastic rules**), or create a custom indicator-match rule with:

- **Index patterns**: your endpoint and log indices (for example, `logs-*`).
- **Indicator index patterns**: `logs-ti_polyswarm_latest.scans`.
- **Indicator mapping**: `file.hash.sha256` MATCHES `threat.indicator.file.hash.sha256`. Add OR clauses for `sha1` and `md5` to widen coverage.

## Troubleshooting

### No indicators appear after install

The first poll happens after one **Interval** (default `5m`), and the transform adds up to ~2.5 minutes on top of that. If `logs-ti_polyswarm.scans-*` is still empty after 10 minutes:

1. **Verify the agent is healthy and on the current policy revision.** Fleet → Agents → your agent should report `Healthy` with the latest revision.
2. **Enable agent monitoring to see CEL polling logs.** Fleet → Agent policies → your policy → Settings → Agent monitoring → enable "Collect agent logs". Then Fleet → Agents → your agent → Logs and search for `cel` or `polyswarm`.
3. **Check for error documents.** A non-200 response is indexed rather than dropped: search `logs-ti_polyswarm.scans-*` for `event.kind: pipeline_error` and read `http.response.status_code`. `401`/`403` means the API key is invalid, expired, or lacks metadata-search entitlement; `429` means you are exceeding your plan's rate limit — increase **Interval**.
4. **Confirm the query returns results.** A narrow **Query** or a community with no recent malicious artifacts legitimately yields zero documents. Widen the `artifact.created` window temporarily to confirm connectivity.

### Mapping failures

Check the failure store: `GET .fs-logs-ti_polyswarm.scans-*/_count`. The expected value is `0`. If non-zero, query the failure store and read `error.message` to identify the offending field. PolySwarm's per-file analysis metadata (`polyswarm.exiftool`, `polyswarm.lief`, `polyswarm.pefile`, `polyswarm.scan`) is mapped as `flattened` precisely because its schema varies by file type.

### Transform shows zero documents

The `logs-ti_polyswarm.latest_scans-default-<version>` transform only processes documents that have `threat.indicator.file.hash.sha256` set. If source documents exist but `documents_processed` stays at `0`, confirm the source documents are indicators rather than `event.kind: pipeline_error` records, then restart the transform from **Stack Management → Transforms**.

For PolySwarm-side issues (API entitlements, rate limits, query syntax), consult the [PolySwarm API documentation](https://docs.polyswarm.io).

## Performance and scaling

Each poll pages through the entire result set for the configured query, so ingest volume is driven by the query window and the community's artifact rate, not by **Interval**. Shortening **Interval** refreshes indicators sooner but re-reads the same window more often, multiplying source-stream volume; the transform collapses the duplicates, so cluster sizing for the latest index should be based on the count of unique SHA-256 values in the window rather than raw event volume.

If you need broader coverage, prefer a wider **Query** on a moderate interval over a very short interval. Running several policies with disjoint queries (for example, split by mimetype) spreads load across agents without re-reading the same artifacts.

## Reference

### Logs reference

#### Scans

{{fields "scans"}}

{{event "scans"}}

### Inputs used in this integration

- [CEL input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel): Polls the PolySwarm metadata search API, paging with the cursor returned in `offset` while `has_more` is `true`, and redacts the API key from request-trace logs.

### APIs used to collect data

- `GET /v3/search/metadata/query?query={query}&community={community}&limit={batch_size}&offset={cursor}` — Returns artifacts matching a server-side metadata query, along with `has_more` and the next-page `offset`. Authenticated with the API key as a raw `Authorization` header token.
