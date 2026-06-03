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
| threat.feed.name | The name of the threat feed in UI friendly format. | constant_keyword |
| threat.feed.reference | Reference information for the threat feed in a UI friendly format. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha384 | SHA384 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.file.name | Name of the file including the extension, without the directory. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.registry.key | Hive-relative path of keys. | keyword |
| threat.indicator.registry.path | Full path, including hive, key and value | keyword |
| threat.indicator.registry.value | Name of the value written. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.full.text | Multi-field of `threat.indicator.url.full`. | match_only_text |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |
| threat.indicator.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| threat.indicator.x509.issuer.country | List of country \(C) codes | keyword |
| threat.indicator.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | keyword |
| threat.indicator.x509.issuer.locality | List of locality names (L) | keyword |
| threat.indicator.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| threat.indicator.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| threat.indicator.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| threat.indicator.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| threat.indicator.x509.not_before | Time at which the certificate is first considered valid. | date |
| threat.indicator.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, this should be encoded in base 16 and formatted without colons and uppercase characters. | keyword |
| threat.indicator.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| threat.indicator.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| threat.indicator.x509.subject.country | List of country \(C) code | keyword |
| threat.indicator.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | keyword |
| threat.indicator.x509.subject.locality | List of locality names (L) | keyword |
| threat.indicator.x509.subject.organization | List of organizations (O) of subject. | keyword |
| threat.indicator.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| threat.indicator.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| threat.indicator.x509.version_number | Version of x509 format. | keyword |
| ti_socradar_taxii.stix.confidence | The confidence property identifies the confidence that the creator has in the correctness of their data. The confidence value MUST be a number in the range of 0-100. | integer |
| ti_socradar_taxii.stix.created | The time at which the STIX Indicator Object was originally created | date |
| ti_socradar_taxii.stix.created_by_ref | The created_by_ref property specifies the id property of the identity object that describes the entity that created this object. | keyword |
| ti_socradar_taxii.stix.date_added | Date when the indicator was added to the SOCRadar feed. | date |
| ti_socradar_taxii.stix.extensions | Specifies any extensions of the object, as a dictionary. | flattened |
| ti_socradar_taxii.stix.external_references | The external_references property specifies a list of external references which refers to non-STIX information. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems. | flattened |
| ti_socradar_taxii.stix.id | The ID of the indicator. | keyword |
| ti_socradar_taxii.stix.indicator_types | The STIX indicator types that categorize this indicator, for example malicious-activity. | keyword |
| ti_socradar_taxii.stix.ioc_expiration_date | The expiration date of the indicator. It can be defined from the source event, by the revoked or valid_until fields, or from the integration configuration by ioc_expiration_duration. | date |
| ti_socradar_taxii.stix.ioc_expiration_duration | The configured expiration duration for the indicator. | keyword |
| ti_socradar_taxii.stix.ioc_expiration_reason | Reason why the indicator is expired. Defined by the integration in the ingest pipeline. | keyword |
| ti_socradar_taxii.stix.kill_chain_phases | Describes the various phases of the kill chain that the attacker undertakes. | flattened |
| ti_socradar_taxii.stix.lang | Feed language. | keyword |
| ti_socradar_taxii.stix.modified | Date of the last modification. | date |
| ti_socradar_taxii.stix.object_marking_refs | The object_marking_refs property specifies a list of id properties of marking-definition objects that apply to this object. | keyword |
| ti_socradar_taxii.stix.pattern | The detection pattern for the indicator. | keyword |
| ti_socradar_taxii.stix.pattern_type | The pattern language used in this indicator, which is always "stix". | keyword |
| ti_socradar_taxii.stix.pattern_version | The version of the pattern language that is used in this indicator. | keyword |
| ti_socradar_taxii.stix.revoked | The revoked property is only used by STIX Objects that support versioning and indicates whether the object has been revoked. Revoked objects are no longer considered valid by the object creator. Revoking an object is permanent; future versions of the object with this id must not be created. | boolean |
| ti_socradar_taxii.stix.spec_version | The version of the STIX specification used to represent this object. The value of this property must be 2.1. | keyword |
| ti_socradar_taxii.stix.threat_feed_source_name | SOCRadar threat feed source name. | keyword |
| ti_socradar_taxii.stix.type | Type of the STIX Object. | keyword |
| ti_socradar_taxii.stix.valid_from | The time from which the indicator is considered a valid indicator. | date |
| ti_socradar_taxii.stix.valid_until | The time at which the indicator should no longer be considered a valid indicator. | date |
| ti_socradar_taxii.stix.version | SOCRadar indicator version timestamp. | keyword |


An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2026-02-17T12:00:00.000Z",
    "agent": {
        "ephemeral_id": "43af6da1-b18c-4817-8688-f525c200d434",
        "id": "8257fe94-2ac6-48cf-bd18-2ded67e2c463",
        "name": "elastic-agent-58386",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_socradar_taxii.indicator",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "8257fe94-2ac6-48cf-bd18-2ded67e2c463",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_socradar_taxii.indicator",
        "id": "indicator--c3d4e5f6-a7b8-9012-cdef-123456789012",
        "ingested": "2026-02-17T12:05:00Z",
        "kind": "enrichment",
        "original": "{\"confidence\":50,\"created\":\"2026-02-17T12:00:00.000Z\",\"created_by_ref\":\"identity--socradar-taxii-feed\",\"description\":\"Malicious file hash detected by SOCRadar\",\"id\":\"indicator--c3d4e5f6-a7b8-9012-cdef-123456789012\",\"labels\":[\"osint\"],\"lang\":\"en\",\"modified\":\"2026-02-17T12:15:00.000Z\",\"name\":\"d7a8fbb307d7809469ca5ce888b23a65f06e4563cc956e73e82f5c72c865aab6\",\"pattern\":\"[file:hashes.'SHA-256' = 'd7a8fbb307d7809469ca5ce888b23a65f06e4563cc956e73e82f5c72c865aab6']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2026-02-17T12:00:00.000Z\",\"valid_until\":\"2026-08-17T12:00:00.000Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "d7a8fbb307d7809469ca5ce888b23a65f06e4563cc956e73e82f5c72c865aab6"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_socradar_taxii-indicator",
        "osint"
    ],
    "threat": {
        "feed": {
            "name": "SOCRadar TAXII",
            "reference": "https://platform.socradar.com"
        },
        "indicator": {
            "confidence": "High",
            "description": "Malicious file hash detected by SOCRadar",
            "file": {
                "hash": {
                    "sha256": [
                        "d7a8fbb307d7809469ca5ce888b23a65f06e4563cc956e73e82f5c72c865aab6"
                    ]
                }
            },
            "first_seen": "2026-02-17T12:00:00.000Z",
            "last_seen": "2026-02-17T12:15:00.000Z",
            "modified_at": "2026-02-17T12:15:00.000Z",
            "name": "d7a8fbb307d7809469ca5ce888b23a65f06e4563cc956e73e82f5c72c865aab6",
            "provider": "SOCRadar",
            "type": "file"
        }
    },
    "ti_socradar_taxii": {
        "stix": {
            "confidence": 50,
            "created": "2026-02-17T12:00:00.000Z",
            "created_by_ref": "identity--socradar-taxii-feed",
            "id": "indicator--c3d4e5f6-a7b8-9012-cdef-123456789012",
            "ioc_expiration_date": "2026-08-17T12:00:00.000Z",
            "ioc_expiration_duration": "90d",
            "ioc_expiration_reason": "Expiration set from valid_until field",
            "lang": "en",
            "modified": "2026-02-17T12:15:00.000Z",
            "pattern": "[file:hashes.'SHA-256' = 'd7a8fbb307d7809469ca5ce888b23a65f06e4563cc956e73e82f5c72c865aab6']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2026-02-17T12:00:00.000Z",
            "valid_until": "2026-08-17T12:00:00.000Z"
        }
    }
}
```

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
