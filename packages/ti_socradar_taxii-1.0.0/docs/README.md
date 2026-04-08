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
3. Identify the collection URL you want to ingest from.

### Configuration

1. In Kibana, navigate to **Management > Integrations** and search for "SOCRadar TAXII".
2. Click **Add SOCRadar TAXII**.
3. Configure the following settings:
   - **TAXII 2.1 Collection URL**: The full URL of the SOCRadar TAXII collection objects endpoint, e.g., `https://taxii2.socradar.com/radar_alpha/collections/{collection_id}/objects/`
   - **Username**: Your SOCRadar TAXII username.
   - **Password**: Your SOCRadar TAXII password.
   - **Proxy URL** (optional): If you need to connect through a proxy.
   - **SSL Configuration** (optional): Custom SSL settings if needed.
4. Click **Save and continue** to deploy the integration.

### SOCRadar API roots

SOCRadar provides the following TAXII API roots:

| API Root | Collections | Description |
|----------|-------------|-------------|
| `radar_alpha` | 14 | Alpha threat intelligence feed (collection0000-0013) |
| `radar_gamma` | 100+ | Gamma threat intelligence feed |
| `radar_premium` | 300+ | Premium threat intelligence feed |

Example collection URL format:
```
https://taxii2.socradar.com/radar_alpha/collections/collection0001/objects/
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
| `email-addr` | `[email-addr:value = 'bad@actor.com']` | `threat.indicator.email.address` |

### Common Field Mappings

| STIX Field | ECS Field | Description |
|------------|-----------|-------------|
| `id` | `event.id` | STIX indicator unique identifier |
| `type` | `threat.indicator.type` | Indicator type (ipv4-addr, domain-name, etc.) |
| `created` | `threat.indicator.first_seen` | When the indicator was first created |
| `modified` | `threat.indicator.modified_at` | When the indicator was last modified |
| `valid_from` | `@timestamp` | Start of indicator validity |
| `valid_until` | `stix.ioc_expiration_date` | End of indicator validity |
| `confidence` | `threat.indicator.confidence` | Confidence score (0-100) mapped to Low/Medium/High |
| `description` | `threat.indicator.description` | Human-readable description |
| `labels` | `tags` | STIX labels converted to tags |
| `pattern` | `stix.pattern` | Original STIX pattern |
| `spec_version` | `stix.spec_version` | STIX specification version |

### Confidence Mapping

STIX confidence scores (0-100) are mapped to ECS confidence levels:

| STIX Confidence | ECS Confidence |
|-----------------|----------------|
| 0-33 | Low |
| 34-66 | Medium |
| 67-100 | High |

## IOC Expiration

By default, indicators expire 90 days after their last seen timestamp. This behavior can be controlled via the **IOC Expiration Duration** setting:

- If `valid_until` is present in the STIX object, it is used as the expiration date.
- If `valid_until` is not present, the expiration is calculated as: `modified + ioc_expiration_duration`.
- Expired indicators are marked in the `stix.ioc_expiration_reason` field.

## Transforms

This integration includes a `latest_ioc` transform that:

- Runs every 30 seconds
- Maintains the latest unique IOC per `event.dataset` and `stix.id`
- Stores results in `logs-ti_socradar_taxii_latest.indicator`
- Retains data for 24 hours

Use the transform index for:
- Indicator match rules
- Threat intelligence lookups
- Current threat landscape analysis

## Dashboards

The integration includes the following dashboards:

### [SOCRadar TAXII] IOC Overview

Provides a comprehensive view of threat intelligence indicators:
- **Total IOCs**: Total count of indicators
- **IOC Types**: Number of unique indicator types
- **High Confidence**: Count of high-confidence indicators
- **IOC Type Distribution**: Pie chart breakdown by type
- **IOCs Over Time**: Time series of indicator ingestion
- **Top Threats by Confidence**: Horizontal bar chart of confidence levels
- **Indicator Table**: Sortable table of recent indicators

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
| Indicator not parsed | Unsupported STIX type | Check `stix.type` field in logs |
| Pattern extraction failed | Complex pattern | Check `stix.pattern` format |
| Missing ECS fields | Null values in STIX | Check STIX object completeness |

## Reference

- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [Elastic Threat Intelligence Integration Guide](https://www.elastic.co/guide/en/security/current/threat-intelligence.html)

## Logs reference

### Indicator

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| stix.confidence | The confidence property identifies the confidence that the creator has in the correctness of their data. The confidence value MUST be a number in the range of 0-100. | integer |
| stix.created | The time at which the STIX Indicator Object was originally created | date |
| stix.created_by_ref | The created_by_ref property specifies the id property of the identity object that describes the entity that created this object. | keyword |
| stix.date_added | Date when the indicator was added to the SOCRadar feed. | date |
| stix.extensions | Specifies any extensions of the object, as a dictionary. | flattened |
| stix.external_references | The external_references property specifies a list of external references which refers to non-STIX information. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems. | flattened |
| stix.id | The ID of the indicator. | keyword |
| stix.indicator_types |  | keyword |
| stix.ioc_expiration_date | The expiration date of the indicator. It can be defined from the source event, by the revoked or valid_until fields, or from the integration configuration by ioc_expiration_duration. | date |
| stix.ioc_expiration_duration | The configured expiration duration for the indicator. | keyword |
| stix.ioc_expiration_reason | Reason why the indicator is expired. Defined by the integration in the ingest pipeline. | keyword |
| stix.kill_chain_phases | Describes the various phases of the kill chain that the attacker undertakes. | flattened |
| stix.lang | Feed language. | keyword |
| stix.modified | Date of the last modification. | date |
| stix.object_marking_refs | The object_marking_refs property specifies a list of id properties of marking-definition objects that apply to this object. | keyword |
| stix.pattern | The detection pattern for the indicator. | keyword |
| stix.pattern_type | The pattern language used in this indicator, which is always "stix". | keyword |
| stix.pattern_version | The version of the pattern language that is used in this indicator. | keyword |
| stix.revoked | The revoked property is only used by STIX Objects that support versioning and indicates whether the object has been revoked. Revoked objects are no longer considered valid by the object creator. Revoking an object is permanent; future versions of the object with this id must not be created. | boolean |
| stix.spec_version | The version of the STIX specification used to represent this object. The value of this property must be 2.1. | keyword |
| stix.threat_feed_source_name | SOCRadar threat feed source name. | keyword |
| stix.type | Type of the STIX Object. | keyword |
| stix.valid_from | The time from which the indicator is considered a valid indicator. | date |
| stix.valid_until | The time at which the indicator should no longer be considered a valid indicator. | date |
| stix.version | SOCRadar indicator version timestamp. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |
| threat.feed.reference | Feed reference URL. | keyword |
| threat.indicator.as.number | Autonomous System number. | integer |
| threat.indicator.confidence | Indicator confidence rating. | keyword |
| threat.indicator.description | Indicator description. | keyword |
| threat.indicator.email.address | Indicator email address. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.name | File name. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.ip | Indicator IP address. | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.marking.tlp | Traffic Light Protocol level. | keyword |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | Indicator display name. | keyword |
| threat.indicator.provider | Indicator provider. | keyword |
| threat.indicator.registry.key | Windows registry key. | keyword |
| threat.indicator.registry.path | Windows registry path. | keyword |
| threat.indicator.registry.value | Windows registry value. | keyword |
| threat.indicator.type | Type of indicator. | keyword |
| threat.indicator.url.full | Full URL. | keyword |
| threat.indicator.url.original | Original URL. | wildcard |
| threat.indicator.x509.issuer.common_name | X.509 issuer common name. | keyword |
| threat.indicator.x509.issuer.country | X.509 issuer country. | keyword |
| threat.indicator.x509.issuer.distinguished_name | X.509 issuer distinguished name. | keyword |
| threat.indicator.x509.issuer.locality | X.509 issuer locality. | keyword |
| threat.indicator.x509.issuer.organization | X.509 issuer organization. | keyword |
| threat.indicator.x509.issuer.organizational_unit | X.509 issuer organizational unit. | keyword |
| threat.indicator.x509.issuer.state_or_province | X.509 issuer state or province. | keyword |
| threat.indicator.x509.not_after | X.509 certificate expiration date. | date |
| threat.indicator.x509.not_before | X.509 certificate start date. | date |
| threat.indicator.x509.serial_number | X.509 certificate serial number. | keyword |
| threat.indicator.x509.signature_algorithm | X.509 signature algorithm. | keyword |
| threat.indicator.x509.subject.common_name | X.509 subject common name. | keyword |
| threat.indicator.x509.subject.country | X.509 subject country. | keyword |
| threat.indicator.x509.subject.distinguished_name | X.509 subject distinguished name. | keyword |
| threat.indicator.x509.subject.locality | X.509 subject locality. | keyword |
| threat.indicator.x509.subject.organization | X.509 subject organization. | keyword |
| threat.indicator.x509.subject.organizational_unit | X.509 subject organizational unit. | keyword |
| threat.indicator.x509.subject.state_or_province | X.509 subject state or province. | keyword |
| threat.indicator.x509.version_number | X.509 version number. | keyword |


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
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_socradar_taxii-indicator",
        "osint"
    ],
    "threat": {
        "feed": {
            "name": "SOCRadar TAXII"
        },
        "indicator": {
            "confidence": "Medium",
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
    }
}
```
