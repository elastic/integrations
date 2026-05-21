# SOCRadar Threat Feeds integration

The SOCRadar Threat Feeds integration collects threat intelligence indicators from SOCRadar's feed collections API. It supports IP addresses, domain names, file hashes, URLs, and email address indicators.

## Data streams

- **feed**: Collects indicators from SOCRadar feed collections.

## Logs reference

### Feed

{{fields "feed"}}

{{event "feed"}}

## Troubleshooting

### No indicators appear after install
The first poll happens after one `Interval` (default `5m`). With seven recommended collections processed in round-robin, every collection refreshes roughly every 35 minutes. If `logs-ti_socradar_feeds.feed-default` stays empty for more than 10 minutes:

1. **Verify the agent is online and on the correct policy revision.** Fleet → Agents → your agent should be `Healthy` with the latest `socradar-feeds-policy` revision.
2. **Enable agent monitoring to see CEL polling logs.** Fleet → Agent policies → your policy → Settings → Agent monitoring → enable "Collect agent logs". Then Fleet → Agents → your agent → Logs and search for `cel` or `socradar`. A successful poll logs `status: 200`. `401`/`403` indicates an invalid or expired API key; `timeout` indicates network/proxy issues.
3. **Verify the API key in policy secrets.** Integration policy → API Key → Replace api key, then paste the value from the SOCRadar Platform → Settings → API Keys.

### Mapping failures
Check the failure store: `GET .fs-logs-ti_socradar_feeds.feed-*/_count`. The expected value is `0`. If non-zero, query the failure store for `error.message` to see which field failed to map.

### Transform shows zero documents
The `logs-ti_socradar_feeds.latest_ioc-default-0.1.0` transform deduplicates indicators into the `logs-ti_socradar_feeds_latest.feed-*` index. It runs continuously and processes new source documents as they arrive. If `documents_processed` stays at `0` for more than `Interval × 2`, restart the transform from Stack Management → Transforms.
