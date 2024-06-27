# Alienvault OTX Integration

This integration is for [Alienvault OTX](https://otx.alienvault.com/api). It retrieves indicators for all pulses subscribed to a specific user account on OTX

## Configuration

To use this package, it is required to have an account on [Alienvault OTX](https://otx.alienvault.com/). Once an account has been created, and at least 1 pulse has been subscribed to, the API key can be retrieved from your [user profile dashboard](https://otx.alienvault.com/api). In the top right corner there should be an OTX KEY.

## Logs

### Threat

Retrieves all the related indicators over time, related to your pulse subscriptions on OTX.

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
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| otx.content | Extra text or descriptive content related to the indicator. | keyword |
| otx.description | A description of the indicator. | keyword |
| otx.id | The ID of the indicator. | keyword |
| otx.indicator | The value of the indicator, for example if the type is domain, this would be the value. | keyword |
| otx.title | Title describing the indicator. | keyword |
| otx.type | The indicator type, can for example be "domain, email, FileHash-SHA256". | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.file.hash.pehash | The file's pehash, if available. | keyword |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2024-03-08T02:55:33.690Z",
    "agent": {
        "ephemeral_id": "8edc1f21-05cd-4fa5-aadc-66e64f44856a",
        "id": "f29e7d89-991e-4f0a-838f-9c2eb93d876e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_otx.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f29e7d89-991e-4f0a-838f-9c2eb93d876e",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-08T02:55:33.690Z",
        "dataset": "ti_otx.threat",
        "ingested": "2024-03-08T02:55:45Z",
        "kind": "enrichment",
        "original": "{\"count\":40359,\"next\":\"https://otx.alienvault.com/api/v1/indicators/export?types=domain%2CIPv4%2Chostname%2Curl%2CFileHash-SHA256\\u0026modified_since=2020-11-29T01%3A10%3A00+00%3A00\\u0026page=2\",\"previous\":null,\"results\":{\"content\":\"\",\"description\":null,\"id\":1251,\"indicator\":\"info.3000uc.com\",\"title\":null,\"type\":\"hostname\"}}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "otx": {},
    "tags": [
        "preserve_original_event",
        "forwarded",
        "otx-threat"
    ],
    "threat": {
        "indicator": {
            "type": "domain-name",
            "url": {
                "domain": "info.3000uc.com"
            }
        }
    }
}
```

### Pulses Subscribed (Recommended)

Retrieves all indicators from subscribed pulses on OTX from API `/api/v1/pulses/subscribed` using Filebeat's [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html). 
The following subscriptions are included by this API:
 - All pulses by users you are subscribed to
 - All pulses you are directly subscribed to
 - All pulses you have created yourself
 - All pulses from groups you are a member of

#### Indicators of Comprosie (IoC) Expiration
`Pulses Subscribed` datastream also supports IoC expiration by using [latest transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-overview.html#latest-transform-overview). Below are the steps on how it is handled:
1. All the indicators are retrieved into source indices named `logs-ti_otx.pulses_subscribed-*` using CEL input and processed via ingest pipelines. These indicators have a property named `expiration` which is either a `null` value or a timestamp such as `"2023-09-07T00:00:00"`. When the value is `null` or if the timestamp value is less than current timestamp `now()`, the indicator is not expired, and hence is still active.
2. A latest transform is continuosly run on source indices. The purpose of this transform is to:
    - Move only the `active` indicators from source indices into destination indices named `logs-ti_otx_latest.pulses_subscribed-<NUMBER>` where `NUMBER` indicates index version. 
    - Delete expired indicators based on the `expiration` timestamp value.
3. All the active indicators can be retrieved using destination index alias `logs-ti_otx_latest.pulses_subscribed` which points to the latest destination index version.

-  **Note**: Do not use the source indices `logs-ti_otx.pulses_subscribed-*`, because when the indicators expire, the source indices will contain duplicates. Always use the destination index alias: `logs-ti_otx_latest.pulses_subscribed` to query all active indicators.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| otx.content |  | keyword |
| otx.count |  | integer |
| otx.created |  | date |
| otx.description |  | keyword |
| otx.expiration |  | date |
| otx.id | The ID of the indicator. | keyword |
| otx.indicator |  | keyword |
| otx.is_active |  | integer |
| otx.prefetch_pulse_ids |  | boolean |
| otx.pulse.adversary |  | keyword |
| otx.pulse.attack_ids |  | keyword |
| otx.pulse.author_name |  | keyword |
| otx.pulse.created |  | date |
| otx.pulse.description |  | keyword |
| otx.pulse.extract_source |  | keyword |
| otx.pulse.id |  | keyword |
| otx.pulse.industries |  | keyword |
| otx.pulse.malware_families |  | keyword |
| otx.pulse.modified |  | date |
| otx.pulse.more_indicators |  | boolean |
| otx.pulse.name |  | keyword |
| otx.pulse.public |  | integer |
| otx.pulse.references |  | keyword |
| otx.pulse.revision |  | integer |
| otx.pulse.targeted_countries |  | keyword |
| otx.pulse.tlp |  | keyword |
| otx.role |  | keyword |
| otx.t |  | double |
| otx.t2 |  | double |
| otx.t3 |  | double |
| otx.title |  | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.file.hash.pehash | The file's pehash, if available. | keyword |


An example event for `pulses_subscribed` looks as following:

```json
{
    "@timestamp": "2023-08-08T05:05:15.000Z",
    "agent": {
        "ephemeral_id": "98babf94-9cf4-45af-aef8-2d57d61d9876",
        "id": "f29e7d89-991e-4f0a-838f-9c2eb93d876e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_otx.pulses_subscribed",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f29e7d89-991e-4f0a-838f-9c2eb93d876e",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_otx.pulses_subscribed",
        "ingested": "2024-03-08T02:54:50Z",
        "kind": "enrichment",
        "original": "{\"content\":\"\",\"count\":2,\"created\":\"2023-08-08T05:05:15\",\"description\":\"\",\"expiration\":null,\"id\":3454375108,\"indicator\":\"pinup-casino-tr.site\",\"is_active\":1,\"prefetch_pulse_ids\":false,\"pulse_raw\":\"{\\\"adversary\\\":\\\"\\\",\\\"attack_ids\\\":[\\\"T1531\\\",\\\"T1059\\\",\\\"T1566\\\"],\\\"author_name\\\":\\\"SampleUser\\\",\\\"created\\\":\\\"2023-08-22T09:43:18.855000\\\",\\\"description\\\":\\\"\\\",\\\"extract_source\\\":[],\\\"id\\\":\\\"64e38336d783f91d6948a7b1\\\",\\\"industries\\\":[],\\\"malware_families\\\":[\\\"WHIRLPOOL\\\"],\\\"modified\\\":\\\"2023-08-22T09:43:18.855000\\\",\\\"more_indicators\\\":false,\\\"name\\\":\\\"Sample Pulse\\\",\\\"public\\\":1,\\\"references\\\":[\\\"https://www.cisa.gov/news-events/analysis-reports/ar23-230a\\\"],\\\"revision\\\":1,\\\"tags\\\":[\\\"cisa\\\",\\\"backdoor\\\",\\\"whirlpool\\\",\\\"malware\\\"],\\\"targeted_countries\\\":[],\\\"tlp\\\":\\\"white\\\"}\",\"role\":null,\"t\":0,\"t2\":0.0050694942474365234,\"t3\":2.7960586547851562,\"title\":\"\",\"type\":\"domain\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "otx": {
        "count": 2,
        "created": "2023-08-08T05:05:15.000Z",
        "expiration": "2023-08-13T05:05:15.000Z",
        "id": "3454375108",
        "is_active": 1,
        "prefetch_pulse_ids": false,
        "pulse": {
            "attack_ids": [
                "T1531",
                "T1059",
                "T1566"
            ],
            "author_name": "SampleUser",
            "created": "2023-08-22T09:43:18.855Z",
            "description": "",
            "extract_source": [],
            "id": "64e38336d783f91d6948a7b1",
            "industries": [],
            "malware_families": [
                "WHIRLPOOL"
            ],
            "modified": "2023-08-22T09:43:18.855Z",
            "more_indicators": false,
            "name": "Sample Pulse",
            "public": 1,
            "references": [
                "https://www.cisa.gov/news-events/analysis-reports/ar23-230a"
            ],
            "revision": 1,
            "targeted_countries": [],
            "tlp": "white"
        },
        "t": 0,
        "t2": 0.0050694942474365234,
        "t3": 2.7960586547851562
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "otx-pulses_subscribed",
        "cisa",
        "backdoor",
        "whirlpool",
        "malware"
    ],
    "threat": {
        "indicator": {
            "provider": "OTX",
            "type": "domain-name",
            "url": {
                "domain": "pinup-casino-tr.site"
            }
        }
    }
}
```