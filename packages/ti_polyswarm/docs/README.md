# PolySwarm Threat Intelligence

## Overview

The PolySwarm Threat Intelligence integration collects malicious artifact (file) indicators from the [PolySwarm](https://polyswarm.network) CTI API and normalizes them into Elastic Common Schema (ECS) `threat.indicator.*` fields. PolySwarm is a crowdsourced malware-detection marketplace: each artifact submitted to the network is scanned by many independent engines, and the resulting assertions are condensed into a single malicious-likelihood score called the **PolyScore**.

Because the integration writes to `logs-ti_polyswarm.scans-*`, which matches Kibana's default threat intelligence index pattern (`logs-ti_*`), ingested indicators appear automatically under **Security → Explore → Intelligence** and are usable by indicator-match detection rules with no additional configuration.

### Compatibility

This integration has been tested against PolySwarm CTI API `v3` (`GET /v3/search/metadata/query`). For supported Elastic Stack versions, see the version constraints shown on the integration's page in Kibana.

### How it works

The Elastic Agent uses the [CEL input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel) to poll the PolySwarm metadata search API on a configurable interval. Each poll submits a server-side metadata query — by default `artifact.created:>now-1d AND scan.detections.malicious:>0`, a rolling one-day window restricted to artifacts at least one engine flagged as malicious — and pages through the results using the cursor PolySwarm returns in `offset`, continuing while `has_more` is `true`.

Every returned artifact becomes one indicator document. The ingest pipeline maps the artifact hashes, file metadata, and scan timestamps to ECS, derives `threat.indicator.confidence` from the PolyScore, and records the raw vendor payload under the `polyswarm.*` field group. A non-200 response from the API is indexed as a single `event.kind: pipeline_error` document carrying `error.code`, `error.message`, and `http.response.status_code`, rather than as a false indicator.

## What data does this integration collect?

This integration collects a single data stream:

- **scans**: Malicious artifact indicators from PolySwarm metadata search. Each document is emitted with `event.kind: enrichment`, `event.category: [threat]`, `event.type: [indicator]`, and `threat.indicator.type: file`. Artifact hashes are mapped to `threat.indicator.file.hash.{md5,sha1,sha256}` and mirrored into `related.hash` so analysts can pivot on a hash without knowing which field holds it.

The integration also installs a `latest_scans` transform that deduplicates the source stream by SHA-256 into `logs-ti_polyswarm_latest.scans`, keeping one document per artifact. See [Deduplication and IOC expiration](#deduplication-and-ioc-expiration) below.

### Supported use cases

- Driving indicator-match detection rules from the deduplicated latest-state index, so file hashes observed by your endpoints are matched against artifacts PolySwarm recently scored as malicious.
- Enriching and triaging alerts in Elastic Security with PolyScore, malware family, and file metadata for a hash under investigation.
- Building dashboards over the recent malicious-artifact landscape (volume over time, malware families, file types).

## What do I need to use this integration?

- A self-managed or Elastic Cloud deployment. The supported Elastic Stack versions are listed on the integration's page in Kibana.
- An Elastic Agent enrolled in Fleet. If you do not have one, see the [Elastic Agent installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). Only one Elastic Agent can be installed per host.
- A PolySwarm account with CTI API access and an API key. Register at [polyswarm.network](https://polyswarm.network). The API key is available from your account settings. Metadata search is a paid capability — confirm your plan includes it before configuring the integration.

## How do I deploy this integration?

This integration is deployed using Elastic Agent. For an end-to-end overview of installing the agent and adding an integration, see the [Fleet and Elastic Agent guide](https://www.elastic.co/docs/reference/fleet).

### Onboard and configure

1. In Kibana, navigate to **Management → Integrations** and search for "PolySwarm".
2. Select **PolySwarm Threat Intelligence**, then click **Add PolySwarm Threat Intelligence**.
3. Configure the following settings:
   - **URL**: PolySwarm API base URL, without a trailing slash. Default `https://api.polyswarm.network`. Change only if PolySwarm provides a different host.
   - **API Key**: Your PolySwarm API key. Stored as a policy secret, masked in the UI, and redacted from the CEL input's logged state.
   - **Interval**: How often to poll the API. Default `5m`. Supported units are `h`, `m`, and `s`.
   - **Query**: The server-side metadata query. Default `artifact.created:>now-1d AND scan.detections.malicious:>0`. Keep the `scan.detections.malicious:>0` clause so only artifacts with at least one malicious detection are ingested as indicators — removing it ingests benign artifacts as threat indicators. See [Tuning the query](#tuning-the-query).
   - **Community**: The PolySwarm community to search. Default `default`.
   - **Batch Size**: Number of results requested per API request. Default `100`. Available under **Advanced options**.
   - **Preserve original event**: Retains the raw PolySwarm JSON for each artifact in `event.original`. Default off. Enable it when you need an audit trail of exactly what the API returned.
   - **Proxy URL** (optional): Route the connection through an HTTP proxy, as `http[s]://<user>:<password>@<host>:<port>`. Available under **Advanced options**.
   - **SSL Configuration** (optional): Custom TLS settings, for example a corporate certificate authority. Available under **Advanced options**.
   - **HTTP Client Timeout**: How long to wait before declaring the HTTP connection timed out. Default `30s`. Available under **Advanced options**.
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

- **Source data stream** `logs-ti_polyswarm.scans-*`: every poll re-ingests the artifacts still inside the rolling query window, duplicates included. This re-assertion acts as a heartbeat proving an indicator is still current. Retention bounds its growth — see [Source data stream retention](#source-data-stream-retention) below.
- **Latest transform** `logs-ti_polyswarm_latest.scans`: keeps exactly one document per `threat.indicator.file.hash.sha256`, the most recent by `event.ingested`. Its retention policy deletes indicators whose last re-assertion is older than 48 hours — so once an artifact ages out of the query window, its IOC expires automatically.

For indicator-match rules and dashboards, always query the deduplicated index `logs-ti_polyswarm_latest.scans` rather than the raw source stream.

### Source data stream retention

The package bounds the growth of the source data stream with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_polyswarm.scans-*` | `logs-ti_polyswarm.scans-default_policy`: roll over after 1d or 50 GB primary shard size, delete 5d after rollover | delete 5d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies, and the data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. Neither mechanism affects the transform's destination index, whose expiration is governed by the transform retention policy described above.

Each document records the configured polling interval in `labels.interval` for expiration diagnostics.

Both tiers match the default `logs-ti_*` threat index pattern, so a query spanning that pattern reaches the raw stream as well as the deduplicated view. To tell them apart, every document carries `labels.is_ioc_transform_source` as a `constant_keyword`: `"true"` on the raw source stream, `"false"` on the transform's latest index. Filter on `labels.is_ioc_transform_source: "false"` to get only the deduplicated, currently-asserted set.

Elastic's prebuilt threat intelligence rules already use this label — their indicator query excludes `labels.is_ioc_transform_source: "true"` — so they read only the deduplicated tier with no configuration on your part.

### Keep the interval well below the expiration window

Because expiration is driven by recency of re-assertion, a polling interval that approaches 48 hours can let still-current indicators drop out of the latest index between polls.

### Expiration depends on continued ingestion

The transform's retention policy is applied as part of a completed checkpoint, not on an independent timer. A checkpoint only completes when new source documents arrive. If polling stops — agent down, network outage, revoked or expired API key — no further checkpoints complete and **the indicators already in `logs-ti_polyswarm_latest.scans` are not expired. They stay in the index, and in any indicator-match rule reading it, until ingestion resumes.**

This is the opposite of a quiet drain: the active view looks healthy while the intelligence behind it goes stale. Plan for it:

- **Alert on ingest freshness.** Watch for an absence of new `event.ingested` values on `logs-ti_polyswarm.scans-*` over a few hours, or monitor the agent and the `logs-ti_polyswarm.latest_scans-default-<version>` transform directly. This is your only reliable outage signal — the deduplicated index will not show one.
- **Add a freshness bound at query time** where staleness matters. Rules and dashboards reading the latest index can constrain `event.ingested` (for example, `event.ingested >= now-48h`) so an outage removes indicators from their scope regardless of whether the transform has run.

Once ingestion resumes, the next completed checkpoint applies the retention policy and the backlog of expired indicators is removed in one pass.

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

Documents that fail in the ingest pipeline are indexed with `event.kind: pipeline_error` and the processor error in `error.message`. Search `logs-ti_polyswarm.scans-*` for `event.kind: pipeline_error` and read `error.message` to identify the offending field. This works on every supported stack version.

On deployments where the data stream failure store is enabled you can additionally check `GET .fs-logs-ti_polyswarm.scans-*/_count`, which should be `0`.

PolySwarm's per-file analysis metadata (`polyswarm.exiftool`, `polyswarm.lief`, `polyswarm.pefile`, `polyswarm.scan`) is mapped as `flattened` precisely because its schema varies by file type.

### Transform shows zero documents

The `logs-ti_polyswarm.latest_scans-default-<version>` transform only processes documents that have `threat.indicator.file.hash.sha256` set. If source documents exist but `documents_processed` stays at `0`, confirm the source documents are indicators rather than `event.kind: pipeline_error` records, then restart the transform from **Stack Management → Transforms**.

For PolySwarm-side issues (API entitlements, rate limits, query syntax), consult the [PolySwarm API documentation](https://docs.polyswarm.io).

## Performance and scaling

Each poll pages through the entire result set for the configured query, so ingest volume is driven by the query window and the community's artifact rate, not by **Interval**. Shortening **Interval** refreshes indicators sooner but re-reads the same window more often, multiplying source-stream volume. The transform collapses the duplicates, so cluster sizing for the latest index should be based on the count of unique SHA-256 values in the window rather than raw event volume.

If you need broader coverage, prefer a wider **Query** on a moderate interval over a very short interval. Running several policies with disjoint queries (for example, split by mimetype) spreads load across agents without re-reading the same artifacts.

## Reference

### Logs reference

#### Scans

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| http.response.status_code | HTTP response status code. | long |
| input.type | Type of Filebeat input. | keyword |
| labels.interval | Configured polling interval, recorded for IOC expiration diagnostics. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or in the latest destination index. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| polyswarm.artifact.created | Artifact creation time. | date |
| polyswarm.artifact.id | PolySwarm artifact identifier. | keyword |
| polyswarm.artifact.size | Artifact size in bytes. | long |
| polyswarm.exiftool | Raw exiftool metadata (variable schema per file type). | flattened |
| polyswarm.extension | File extension reported for the artifact. | keyword |
| polyswarm.found | Time the artifact was first found by the network. | date |
| polyswarm.hash | All hash digests reported for the artifact. | flattened |
| polyswarm.lief | Raw LIEF binary-analysis metadata (variable schema per file type). | flattened |
| polyswarm.malware_family | Malware family from polyunite classification. | keyword |
| polyswarm.meta_community | PolySwarm community the artifact metadata belongs to. | keyword |
| polyswarm.modified | Time the artifact record was last modified. | date |
| polyswarm.pefile | Raw pefile PE-header metadata (variable schema per file type). | flattened |
| polyswarm.polyscore | PolySwarm malicious-likelihood score (0-1), copied from the latest scan. | double |
| polyswarm.polyunite | Raw polyunite malware-classification metadata. | flattened |
| polyswarm.scan | Scan summary including assertions and detections. | flattened |
| polyswarm.updated | Update metadata reported by PolySwarm (variable schema; kept as-is). | flattened |
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


An example event for `scans` looks as following:

```json
{
    "@timestamp": "2024-03-13T21:15:42.000Z",
    "agent": {
        "ephemeral_id": "c5895363-857b-4bd7-8b2f-84e64ab71a9e",
        "id": "71307fc9-1f95-4e8a-b863-df2f0de2df9e",
        "name": "elastic-agent-71661",
        "type": "filebeat",
        "version": "9.4.3"
    },
    "data_stream": {
        "dataset": "ti_polyswarm.scans",
        "namespace": "34907",
        "type": "logs"
    },
    "ecs": {
        "version": "9.5.0"
    },
    "elastic_agent": {
        "id": "71307fc9-1f95-4e8a-b863-df2f0de2df9e",
        "snapshot": false,
        "version": "9.4.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_polyswarm.scans",
        "ingested": "2026-10-21T20:21:47Z",
        "kind": "enrichment",
        "module": "ti_polyswarm",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "interval": "5m",
        "is_ioc_transform_source": "true"
    },
    "polyswarm": {
        "artifact": {
            "created": "2024-03-13T21:15:42.000Z",
            "id": "80984520749896318",
            "size": 262144
        },
        "extension": "dll",
        "hash": {
            "md5": "ffffffffffffffffffffffffffffffff",
            "sha1": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        },
        "malware_family": "Adware.Generic",
        "meta_community": "default",
        "polyscore": 0.21,
        "polyunite": {
            "malware_family": "Adware.Generic"
        },
        "scan": {
            "detections": {
                "malicious": "2",
                "total": "24"
            },
            "first_seen": "2024-03-12T11:05:00.000000",
            "last_seen": "2024-03-13T20:45:00.000000",
            "latest_scan": {
                "polyscore": "0.21"
            },
            "mimetype": {
                "mime": "application/vnd.microsoft.portable-executable"
            }
        }
    },
    "related": {
        "hash": [
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "ffffffffffffffffffffffffffffffff"
        ]
    },
    "tags": [
        "forwarded",
        "ti_polyswarm-scans"
    ],
    "threat": {
        "feed": {
            "name": "PolySwarm"
        },
        "indicator": {
            "confidence": "Low",
            "file": {
                "extension": "dll",
                "hash": {
                    "md5": "ffffffffffffffffffffffffffffffff",
                    "sha1": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                },
                "mime_type": "application/vnd.microsoft.portable-executable",
                "size": 262144
            },
            "first_seen": "2024-03-12T11:05:00.000Z",
            "last_seen": "2024-03-13T20:45:00.000Z",
            "name": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "provider": "PolySwarm",
            "type": "file"
        }
    }
}
```

### Inputs used in this integration

- [CEL input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel): Polls the PolySwarm metadata search API, paging with the cursor returned in `offset` while `has_more` is `true`, and redacts the API key from the CEL input's logged state. Note that redaction applies to the input's state, not to HTTP request traces: if request tracing is enabled for debugging, the trace files contain the API key in the `Authorization` header and must be handled as credentials.

### APIs used to collect data

- `GET /v3/search/metadata/query?query={query}&community={community}&limit={batch_size}&offset={cursor}` — Returns artifacts matching a server-side metadata query, along with `has_more` and the next-page `offset`. Authenticated with the API key as a raw `Authorization` header token.
