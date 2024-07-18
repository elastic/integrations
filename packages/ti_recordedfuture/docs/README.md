# Recorded Future Integration

The Recorded Future integration fetches _risklists_ from the [Recorded Future API](https://api.recordedfuture.com/index.html).
It supports `domain`, `hash`, `ip` and `url` entities.

In order to use it you need to define the `entity` and `list` to fetch. Check with
Recorded Future for the available lists for each entity. To fetch indicators
from multiple entities, it's necessary to define one integration for each.

Alternatively, it's also possible to use the integration to fetch custom Fusion files
by supplying the URL to the CSV file as the _Custom_ _URL_ configuration option.

### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates a destination index named `logs-ti_recordedfuture_latest.threat-1` which only contains active and unexpired IOCs. The destination index also has an alias `logs-ti_recordedfuture_latest.threat`. When setting up indicator match rules, use this latest destination index to avoid false positives from expired IOCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source `.ds-logs-ti_recordedfuture.threat-*` indices.

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_recordedfuture.threat-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 


**NOTE:** For large risklist downloads, adjust the timeout setting so that the Agent has enough time to download and process the risklist.

An example event for `threat` looks as following:

```json
{
    "@timestamp": "2024-05-09T12:24:05.286Z",
    "agent": {
        "ephemeral_id": "b0d47395-89bd-40e7-8018-57fdcc0cf1b8",
        "id": "013c7177-2e5d-40da-9e17-9ee5d2249880",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "data_stream": {
        "dataset": "ti_recordedfuture.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "013c7177-2e5d-40da-9e17-9ee5d2249880",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_recordedfuture.threat",
        "ingested": "2024-05-09T12:24:15Z",
        "kind": "enrichment",
        "risk_score": 75,
        "timezone": "+00:00",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/rf_file_default.csv"
        },
        "offset": 57
    },
    "recordedfuture": {
        "evidence_details": [
            {
                "criticality": 2,
                "criticality_label": "Suspicious",
                "evidence_string": "2 sightings on 1 source: PolySwarm. Most recent link (Mar 23, 2024): https://polyswarm.network/scan/results/file/63212aa8c94098a844945ed1611389b2e1c9dc3906a5ba9d7d0d320344213f4f",
                "mitigation_string": "",
                "name": "linkedToMalware",
                "rule": "Linked to Malware",
                "sightings_count": 2,
                "sources": [
                    "source:doLlw5"
                ],
                "sources_count": 1,
                "timestamp": "2024-03-23T17:10:20.642Z"
            },
            {
                "criticality": 3,
                "criticality_label": "Malicious",
                "evidence_string": "3 sightings on 3 sources: Polyswarm Sandbox Analysis, Recorded Future Triage Malware Analysis, PolySwarm. Most recent link (Mar 23, 2024): https://polyswarm.network/scan/results/file/63212aa8c94098a844945ed1611389b2e1c9dc3906a5ba9d7d0d320344213f4f",
                "mitigation_string": "",
                "name": "positiveMalwareVerdict",
                "rule": "Positive Malware Verdict",
                "sightings_count": 3,
                "sources": [
                    "source:hzRhwZ",
                    "source:ndy5_2",
                    "source:doLlw5"
                ],
                "sources_count": 3,
                "timestamp": "2024-03-23T16:36:02.000Z"
            }
        ],
        "name": "63212aa8c94098a844945ed1611389b2e1c9dc3906a5ba9d7d0d320344213f4f",
        "risk_string": "2/17"
    },
    "tags": [
        "forwarded",
        "recordedfuture"
    ],
    "threat": {
        "feed": {
            "name": "Recorded Future"
        },
        "indicator": {
            "file": {
                "hash": {
                    "sha256": "63212aa8c94098a844945ed1611389b2e1c9dc3906a5ba9d7d0d320344213f4f"
                }
            },
            "provider": [
                "PolySwarm",
                "Polyswarm Sandbox Analysis",
                "Recorded Future Triage Malware Analysis"
            ],
            "scanner_stats": 4,
            "sightings": 5,
            "type": "file"
        }
    }
}
```

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
| recordedfuture.evidence_details.criticality |  | double |
| recordedfuture.evidence_details.criticality_label |  | keyword |
| recordedfuture.evidence_details.evidence_string |  | keyword |
| recordedfuture.evidence_details.mitigation_string |  | keyword |
| recordedfuture.evidence_details.name |  | keyword |
| recordedfuture.evidence_details.rule |  | keyword |
| recordedfuture.evidence_details.sightings_count |  | integer |
| recordedfuture.evidence_details.sources |  | keyword |
| recordedfuture.evidence_details.sources_count |  | integer |
| recordedfuture.evidence_details.timestamp |  | date |
| recordedfuture.list | User-configured risklist. | keyword |
| recordedfuture.name | Indicator value. | keyword |
| recordedfuture.risk_string | Details of risk rules observed. | keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |

