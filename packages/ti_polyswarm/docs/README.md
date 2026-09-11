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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| http.response.status_code | HTTP response status code. | long |
| input.type | Type of Filebeat input. | keyword |
| labels.interval |  | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| polyswarm.artifact.created | Artifact creation time. | date |
| polyswarm.artifact.id | PolySwarm artifact identifier. | keyword |
| polyswarm.artifact.size |  | long |
| polyswarm.exiftool | Raw exiftool metadata (variable schema per file type). | flattened |
| polyswarm.extension |  | keyword |
| polyswarm.found |  | date |
| polyswarm.hash | All hash digests reported for the artifact. | flattened |
| polyswarm.lief |  | flattened |
| polyswarm.malware_family | Malware family from polyunite classification. | keyword |
| polyswarm.meta_community |  | keyword |
| polyswarm.modified |  | date |
| polyswarm.pefile |  | flattened |
| polyswarm.polyscore | PolySwarm malicious-likelihood score (0-1), copied from the latest scan. | double |
| polyswarm.polyunite |  | flattened |
| polyswarm.scan | Scan summary including assertions and detections. | flattened |
| polyswarm.updated |  | flattened |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.mime_type | MIME type should identify the format of the file or stream of bytes using IANA official types: https://www.iana.org/assignments/media-types/media-types.xhtml, where possible. When more than one type is applicable, the most specific type should be used. | keyword |
| threat.indicator.file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |


An example event for `scans` looks as following:

```json
{
    "@timestamp": "2026-07-06T22:29:41.618Z",
    "data_stream": {
        "dataset": "ti_polyswarm.scans",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "dataset": "ti_polyswarm.scans",
        "kind": "enrichment",
        "type": [
            "indicator"
        ]
    },
    "polyswarm": {
        "artifact": {
            "created": "2026-07-06T22:29:41.618Z",
            "id": "80984520749896316",
            "size": 806912
        },
        "extension": "exe",
        "malware_family": "GameOl",
        "meta_community": "_public",
        "polyscore": 0.999436205484525
    },
    "related": {
        "hash": [
            "52825f06485d504873ea97c323acd55dc74a0a1d5402ea11b61353e1e5906465",
            "2f533ea59bc330ffee07d970102577da7afafd98",
            "384e80bb62ba3a241c018880ff09b2d7"
        ]
    },
    "threat": {
        "feed": {
            "name": "PolySwarm"
        },
        "indicator": {
            "confidence": "High",
            "file": {
                "extension": "exe",
                "hash": {
                    "md5": "384e80bb62ba3a241c018880ff09b2d7",
                    "sha1": "2f533ea59bc330ffee07d970102577da7afafd98",
                    "sha256": "52825f06485d504873ea97c323acd55dc74a0a1d5402ea11b61353e1e5906465"
                },
                "mime_type": "application/vnd.microsoft.portable-executable",
                "size": 806912
            },
            "first_seen": "2026-07-06T22:29:41.618Z",
            "name": "52825f06485d504873ea97c323acd55dc74a0a1d5402ea11b61353e1e5906465",
            "provider": "PolySwarm",
            "type": "file"
        }
    }
}
```

### Inputs used in this integration

- [CEL input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel): Polls the PolySwarm metadata search API, paging with the cursor returned in `offset` while `has_more` is `true`, and redacts the API key from request-trace logs.

### APIs used to collect data

- `GET /v3/search/metadata/query?query={query}&community={community}&limit={batch_size}&offset={cursor}` — Returns artifacts matching a server-side metadata query, along with `has_more` and the next-page `offset`. Authenticated with the API key as a raw `Authorization` header token.
