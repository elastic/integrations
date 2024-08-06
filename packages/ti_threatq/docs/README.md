# ThreatQuotient Integration

The ThreatQuotient integration uses the available [ThreatQuotient](https://www.threatq.com/integrations/) REST API to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The ThreatQ integration requires you to set a valid URL, combination of Oauth2 credentials and the ID of the collection to retrieve
indicators from.
By default the indicators will be collected every 1 minute, and deduplication is handled by the API itself. This datastream supports expiration of indicators of compromise (IOC).

### Expiration of Indicators of Compromise (IOCs)
The ThreatQ's `Threat` datastream supports IOC expiration. The ingested IOCs expire after certain duration. In ThreatQ feed, this can happen in 3 ways: 
- When the value of `threatq.status` is `Expired`.
- When either of the fields `threatq.expires_at` or `threatq.expired_at` reaches current `now()` timestamp.
- When the indicator is not updated in a long time leading to default expiration set by `IOC Expiration Duration` configuration parameter. For more details, see [Handling Orphaned IOCs](#handling-orphaned-iocs).

The field `threatq.ioc_expiration_reason` indicates which among the 3 methods stated above is the reason for indicator expiration.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_threatq_latest.dest_threat-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_threatq_latest.threat`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards for the `Threat` datastream are also pointing to the latest destination indices containing active IoCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source datastream `.ds-logs-ti_threatq.threat-*` indices.

#### Handling Orphaned IOCs
Some IOCs may never expire and will continue to stay in the latest destination indices `logs-ti_threatq_latest.dest_threat-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes any indicator ingested into destination indices `logs-ti_threatq_latest.dest_threat-*` after this specified duration is reached, defaults to `90d` from source's `@timestamp` field. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_threatq.threat-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threatq.adversaries | Adversaries that are linked to the object | keyword |
| threatq.attributes | These provide additional context about an object | flattened |
| threatq.created_at | Object creation time | date |
| threatq.expired_at | Expiration time given by the API. Either `expires_at` or `expired_at` are present in the data. | date |
| threatq.expires_at | Expiration time given by the API. Either `expires_at` or `expired_at` are present in the data. | date |
| threatq.expires_calculated_at | Expiration calculation time | date |
| threatq.id | Indicator ID. `id`, `indicator_id` or both could be present in the dataset. | long |
| threatq.indicator_id | Indicator ID. `id`, `indicator_id` or both could be present in the dataset. | long |
| threatq.indicator_value | Original indicator value | keyword |
| threatq.ioc_expiration_reason | Reason why the indicator is expired. Set inside the ingest pipeline. | keyword |
| threatq.ioc_expired_at | Expiration time calculated by the integration needed for the transform. | date |
| threatq.published_at | Object publication time | date |
| threatq.status | Object status within the Threat Library | keyword |
| threatq.updated_at | Last modification time | date |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2019-11-15T00:00:02.000Z",
    "agent": {
        "ephemeral_id": "9f1b0b7f-5be0-463d-9551-3d66aab12b6f",
        "id": "8299ae35-ee0e-4107-9acb-1b6acfdda1fb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "ti_threatq.threat",
        "namespace": "94389",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8299ae35-ee0e-4107-9acb-1b6acfdda1fb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-08-02T06:46:26.556Z",
        "dataset": "ti_threatq.threat",
        "ingested": "2024-08-02T06:46:36Z",
        "kind": "enrichment",
        "original": "{\"adversaries\":[],\"attributes\":[{\"attribute_id\":3,\"created_at\":\"2020-09-11 14:35:53\",\"id\":1877,\"indicator_id\":336,\"name\":\"Description\",\"touched_at\":\"2020-10-15 14:36:00\",\"updated_at\":\"2020-10-15 14:36:00\",\"value\":\"Malicious Host\"},{\"attribute_id\":4,\"created_at\":\"2020-09-11 14:35:53\",\"id\":1878,\"indicator_id\":336,\"name\":\"Country\",\"touched_at\":\"2020-10-15 14:36:00\",\"updated_at\":\"2020-10-15 14:36:00\",\"value\":\"MP\"}],\"class\":\"network\",\"created_at\":\"2020-09-11 14:35:51\",\"expires_calculated_at\":\"2020-10-15 14:40:03\",\"hash\":\"1ece659dcec98b1e1141160b55655c96\",\"id\":336,\"published_at\":\"2020-09-11 14:35:51\",\"score\":4,\"sources\":[{\"created_at\":\"2020-09-11 14:35:53\",\"creator_source_id\":12,\"id\":336,\"indicator_id\":336,\"indicator_status_id\":2,\"indicator_type_id\":15,\"name\":\"AlienVault OTX\",\"published_at\":\"2020-09-11 14:35:53\",\"reference_id\":1,\"source_expire_days\":\"30\",\"source_id\":12,\"source_score\":1,\"source_type\":\"connectors\",\"updated_at\":\"2020-10-15 14:36:00\"}],\"status\":{\"description\":\"Poses a threat\",\"id\":2,\"name\":\"Active\"},\"status_id\":2,\"touched_at\":\"2021-06-07 19:47:27\",\"type\":{\"class\":\"network\",\"id\":15,\"name\":\"IP Address\"},\"type_id\":15,\"updated_at\":\"2019-11-15 00:00:02\",\"value\":\"89.160.20.156\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "threatq-threat"
    ],
    "threat": {
        "indicator": {
            "confidence": "Low",
            "ip": "89.160.20.156",
            "type": "ipv4-addr"
        }
    },
    "threatq": {
        "attributes": {
            "country": [
                "MP"
            ],
            "description": [
                "Malicious Host"
            ]
        },
        "created_at": "2020-09-11T14:35:51.000Z",
        "expires_calculated_at": "2020-10-15T14:40:03.000Z",
        "id": 336,
        "indicator_value": "89.160.20.156",
        "ioc_expiration_reason": "Expiration set by Elastic from the integration's parameter `IOC Expiration Duration`",
        "ioc_expired_at": "2019-11-20T00:00:02.000Z",
        "published_at": "2020-09-11T14:35:51.000Z",
        "status": "Active"
    }
}
```