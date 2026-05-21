# SOCRadar Threat Feeds integration

The SOCRadar Threat Feeds integration collects threat intelligence indicators from SOCRadar's feed collections API. It supports IP addresses, domain names, file hashes, URLs, and email address indicators.

## Data streams

- **feed**: Collects indicators from SOCRadar feed collections.

## Logs reference

### Feed

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.feed.reference | Reference information for the threat feed in a UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.full.text | Multi-field of `threat.indicator.url.full`. | match_only_text |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |
| ti_socradar_feeds.feed.collection_id | SOCRadar feed collection UUID. | keyword |
| ti_socradar_feeds.feed.collection_name | SOCRadar feed collection display name. | keyword |
| ti_socradar_feeds.feed.extra_info | Additional metadata from the feed. | flattened |
| ti_socradar_feeds.feed.first_seen_date | First seen date from SOCRadar feed. | date |
| ti_socradar_feeds.feed.ioc_expiration_date | Calculated indicator expiration date. | date |
| ti_socradar_feeds.feed.ioc_expiration_duration | Configured IOC expiration duration. | keyword |
| ti_socradar_feeds.feed.ioc_expiration_reason | Reason for IOC expiration setting. | keyword |
| ti_socradar_feeds.feed.latest_seen_date | Latest seen date from SOCRadar feed. | date |
| ti_socradar_feeds.feed.maintainer_name | Feed maintainer identifier. | keyword |
| ti_socradar_feeds.feed.type | Feed indicator type from SOCRadar (ip, hostname, hash, url, email). | keyword |
| ti_socradar_feeds.feed.value | The indicator value (IP, domain, hash, URL, email). | keyword |


An example event for `feed` looks as following:

```json
{
    "@timestamp": "2026-02-20T08:30:00.000Z",
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "created": "2026-02-20T08:30:00.000Z",
        "kind": "enrichment",
        "type": [
            "indicator"
        ]
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "related": {
        "ip": [
            "203.0.113.50"
        ]
    },
    "ti_socradar_feeds": {
        "feed": {
            "collection_id": "4d7a69ce6e7c49ff8c916da5d7343916",
            "collection_name": "SOCRadar-APT-Recommended-Block-IP",
            "extra_info": {
                "score": 72.5,
                "seen_count": 3
            },
            "first_seen_date": "2026-02-19T10:00:00.000Z",
            "ioc_expiration_date": "2026-05-21T08:30:00.000Z",
            "ioc_expiration_duration": "90d",
            "ioc_expiration_reason": "Expiration set by configuration",
            "latest_seen_date": "2026-02-20T08:30:00.000Z",
            "maintainer_name": "SOCRadar",
            "type": "ip",
            "value": "203.0.113.50"
        }
    },
    "tags": [
        "forwarded",
        "ti_socradar_feeds-feed"
    ],
    "threat": {
        "feed": {
            "name": "SOCRadar Threat Feeds",
            "reference": "https://platform.socradar.com"
        },
        "indicator": {
            "confidence": "High",
            "description": "SOCRadar feed: SOCRadar-APT-Recommended-Block-IP",
            "first_seen": "2026-02-19T10:00:00.000Z",
            "ip": "203.0.113.50",
            "last_seen": "2026-02-20T08:30:00.000Z",
            "modified_at": "2026-02-20T08:30:00.000Z",
            "provider": "SOCRadar",
            "type": "ipv4-addr"
        }
    }
}
```

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
