# ANY.RUN Threat Intelligence Feeds integration

The [ANY.RUN Threat Intelligence Feeds](https://any.run/threat-intelligence-feeds/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=elastic_feeds&utm_content=linktofeeds) integration provides users with continuously updated, high-fidelity IOCs (malicious IPs, domains, and URLs) extracted from live sandbox analyses across 15,000+ SOCs. This enables proactive defense against emerging threats with rich context including sandbox session links for faster triage and response.

With TI Feeds, you SOC can ensure: 
- **Early threat detection** using real-time IOCs from the latest emerging malware & phishing, catching attacks hours before they hit. 
- **More effective Tier 1** as analysts will be able to resolve more alerts without escalation thanks to clear indicator context. 
- **Lightning-fast MTTR** with TTPs and behavior insights from sandbox reports, enabling automated triage and response in minutes. 

To use this integration, you need an active [ANY.RUN TI Feeds subscription](https://any.run/demo/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=elastic_feeds&utm_content=linktodemo).

## Configuring the integration

### Prerequisites to configuring the integration

- Credentials are required to access the ANY.RUN Threat Intelligence Feeds API. Ensure you have an active ANY.RUN Threat Intelligence Feeds subscription.

### Generate API Key

- Follow [ANY.RUN](https://app.any.run/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=elastic_feeds&utm_content=linktoservice)
- Profile > [2] API and Limits > [3] Generate > [4] Copy

![anyrun_api_token.png](../img/anyrun_api_token.png) 


### Set up the integration:

| Parameter | Description | Required |
|--|--|--| 
| API Key | ANY.RUN API Key in format:`"NS9sY..FwvfR"`to access the ANY.RUN API  | Required |
| Feed fetch depth | How far back to look for indicators on first request. Supported units for this parameter are d/h/m (e.g,. 60d).  | Required |
| Interval | Interval between requests to the ANY.RUN TI Feeds API. Supported units for this parameter are h/m/s (e.g,. 2h).  | Required |
| IOC Expiration Duration | Enforces all indicators to expire after this duration. Using only days, hours, or minutes (e.g., 90d). | Required |
| ANY.RUN TI API URL | Base URL of the ANY.RUN Threat Intelligence API. Defaults to `https://api.any.run`  | Required |
| Proxy URL | URL to proxy connections in the form of `http[s]://<user>:<password>@<server name/ip>:<port>`.  | Optional |



Once the integration is running and pulling data, it automatically maps threat indicator fields from STIX to ECS. Verify that the imported indicators align with your detection rules.

## Expiration of Indicators of Compromise (IOCs)

The ANY.RUN Threat Intelligence Feeds integration supports IOC expiration by using [latest transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview):
1. All the indicators are retrieved into source indices named `logs-ti_anyrun.ioc-*` using CEL input and processed via ingest pipelines. These indicators have a property named expiration which is a timestamp such as "2026-01-01T00:00:00". If the timestamp value is less than current timestamp now(), the indicator is not expired, and hence is still active.
2. A latest transform is continuosly run on source indices. The purpose of this transform is to:
    - Move only the active indicators from source indices into destination indices named `logs-ti_anyrun_latest.dest_ioc-*`.
    - Delete expired indicators based on the expiration timestamp value.
3. All the active indicators can be retrieved using destination index alias `logs-ti_anyrun_latest.ioc` which points to the latest destination index version.

To configure IOC expiration and prevent false positives, use the `IOC Expiration Duration` parameter when setting up the integration. This parameter deletes any indicator ingested into destination indices `logs-ti_anyrun_latest.dest_ioc-*` after the specified duration is reached (defaults to 90d from the source's @timestamp field)

Note: Do not use the source indices `logs-ti_anyrun.ioc-*`, because when the indicators expire, the source indices will contain duplicates. Always use the destination index alias: `logs-ti_anyrun_latest.ioc` to query all active indicators.

## ILM Policy

To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_anyrun.ioc-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date.

## Logs reference

#### Example

```json
{
    "@timestamp": "2024-02-23T12:59:14.320Z",
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "kind": "enrichment",
        "original": "{\"id\":\"indicator--8b2de5a5-29a2-56a3-9089-94bef2464a7c\",\"created\":\"2024-02-23T12:59:14.320Z\",\"created_by_ref\":\"identity--96a9cd9c-2f73-5ad3-a2ab-c14b3eba65c7\",\"external_references\":[],\"labels\":[\"trickbot\"],\"modified\":\"2024-02-23T13:15:32.276Z\",\"pattern\":\"[ipv4-addr:value = '67.43.156.93']\",\"pattern_type\":\"stix\",\"revoked\":false,\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-02-23T12:59:14.320Z\",\"confidence\":90}",
        "type": [
            "indicator"
        ]
    },
    "related": {
        "ip": [
            "67.43.156.93"
        ]
    },
    "stix": {
        "confidence": 90,
        "created": "2024-02-23T12:59:14.320Z",
        "created_by_ref": "identity--96a9cd9c-2f73-5ad3-a2ab-c14b3eba65c7",
        "id": "indicator--8b2de5a5-29a2-56a3-9089-94bef2464a7c",
        "ioc_expiration_date": "2024-02-28T13:15:32.276Z",
        "ioc_expiration_duration": "5d",
        "ioc_expiration_reason": "Expiration set by Elastic from the integration's parameter `IOC Expiration Duration`",
        "modified": "2024-02-23T13:15:32.276Z",
        "pattern": "[ipv4-addr:value = '67.43.156.93']",
        "pattern_type": "stix",
        "revoked": false,
        "spec_version": "2.1",
        "type": "indicator",
        "valid_from": "2024-02-23T12:59:14.320Z"
    },
    "tags": [
        "trickbot"
    ],
    "threat": {
        "feed": {
            "name": "ANY.RUN",
            "description": "Indicator from the ANY.RUN TI Feeds",
            "reference": "https://intelligence.any.run/feeds"
        },
        "indicator": {
            "confidence": "High",
            "first_seen": "2024-02-23T12:59:14.320Z",
            "id": [
                "indicator--8b2de5a5-29a2-56a3-9089-94bef2464a7c"
            ],
            "ip": [
                "67.43.156.93"
            ],
            "last_seen": "2024-02-23T13:15:32.276Z",
            "modified_at": "2024-02-23T13:15:32.276Z",
            "provider": "ANY.RUN",
            "type": "ipv4-addr"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| stix.confidence | The confidence property identifies the confidence that the creator has in the correctness of their data. The confidence value MUST be a number in the range of 0-100. | integer |
| stix.created | The time at which the STIX Indicator Object was originally created | date |
| stix.created_by_ref | The created_by_ref property specifies the id property of the identity object that describes the entity that created this object. | keyword |
| stix.extensions | Specifies any extensions of the object, as a dictionary. | flattened |
| stix.external_references | The external_references property specifies a list of external references which refers to non-STIX information. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems. | flattened |
| stix.id | The ID of the indicator. | keyword |
| stix.indicator_types |  | keyword |
| stix.ioc_expiration_date | The expiration date of the indicator. It can be defined from the source event, by the revoked or valid_until fields, or from the integration configuration by ioc_expiration_duration. | date |
| stix.ioc_expiration_duration | The configured expiration duration for the indicator. | keyword |
| stix.ioc_expiration_reason | Reason why the indicator is expired. Defined by the integration in the ingest pipeline. | keyword |
| stix.modified | Date of the last modification. | date |
| stix.object_marking_refs | The object_marking_refs property specifies a list of id properties of marking-definition objects that apply to this object. | keyword |
| stix.pattern | The detection pattern for the indicator. | keyword |
| stix.pattern_type | The pattern language used in this indicator, which is always "stix". | keyword |
| stix.pattern_version | The version of the pattern language that is used in this indicator. | keyword |
| stix.revoked | The revoked property is only used by STIX Objects that support versioning and indicates whether the object has been revoked. Revoked objects are no longer considered valid by the object creator. Revoking an object is permanent; future versions of the object with this id must not be created. | boolean |
| stix.spec_version | The version of the STIX specification used to represent this object. The value of this property must be 2.1. | keyword |
| stix.type | Type of the STIX Object. | keyword |
| stix.valid_from | The time from which the indicator is considered a valid indicator. | date |
| stix.valid_until | The time at which the indicator should no longer be considered a valid indicator. | date |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |