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
    "@timestamp": "2024-08-02T06:24:04.201Z",
    "agent": {
        "ephemeral_id": "25d7a936-2b7c-4476-9181-82d1296ce9df",
        "id": "8299ae35-ee0e-4107-9acb-1b6acfdda1fb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "ti_recordedfuture.threat",
        "namespace": "67234",
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
        "created": "2024-08-02T06:24:04.201Z",
        "dataset": "ti_recordedfuture.threat",
        "ingested": "2024-08-02T06:24:16Z",
        "kind": "enrichment",
        "original": "{\"EvidenceDetails\":\"{\\\"EvidenceDetails\\\": [{\\\"Name\\\": \\\"suspectedCncDnsName\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: ThreatFox Infrastructure Analysis. ThreatFox identified ubykou33.top as possible TA0011 (Command and Control) for CryptBot on December 26, 2023. Most recent link (Dec 26, 2023): https://threatfox.abuse.ch/ioc/1223634\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Rule\\\": \\\"Historical Suspected C\\\\u0026C DNS Name\\\", \\\"SourcesCount\\\": 1.0, \\\"Sources\\\": [\\\"source:sIoEOQ\\\"], \\\"Timestamp\\\": \\\"2023-12-26T17:06:29.000Z\\\", \\\"SightingsCount\\\": 1.0, \\\"Criticality\\\": 1.0}, {\\\"Name\\\": \\\"malwareSiteDetected\\\", \\\"EvidenceString\\\": \\\"2 sightings on 2 sources: External Sensor Data Analysis, Bitdefender. ubykou33.top is observed to be a malware site domain that navigates to malicious content including executables, drive-by infection sites, malicious scripts, viruses, trojans, or code.\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Rule\\\": \\\"Historically Detected Malware Operation\\\", \\\"SourcesCount\\\": 2.0, \\\"Sources\\\": [\\\"source:kBB1fk\\\", \\\"source:d3Awkm\\\"], \\\"Timestamp\\\": \\\"2024-01-26T00:00:00.000Z\\\", \\\"SightingsCount\\\": 2.0, \\\"Criticality\\\": 1.0}, {\\\"Name\\\": \\\"malwareSiteSuspected\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: Bitdefender. Detected malicious behavior from an endpoint agent via global telemetry. Last observed on Jan 26, 2024.\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Rule\\\": \\\"Historically Suspected Malware Operation\\\", \\\"SourcesCount\\\": 1.0, \\\"Sources\\\": [\\\"source:d3Awkm\\\"], \\\"Timestamp\\\": \\\"2024-01-26T00:00:00.000Z\\\", \\\"SightingsCount\\\": 1.0, \\\"Criticality\\\": 1.0}, {\\\"Name\\\": \\\"recentMalwareSiteDetected\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: External Sensor Data Analysis. ubykou33.top is observed to be a malware site domain that navigates to malicious content including executables, drive-by infection sites, malicious scripts, viruses, trojans, or code.\\\", \\\"CriticalityLabel\\\": \\\"Malicious\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Rule\\\": \\\"Recently Detected Malware Operation\\\", \\\"SourcesCount\\\": 1.0, \\\"Sources\\\": [\\\"source:kBB1fk\\\"], \\\"Timestamp\\\": \\\"2024-05-08T23:11:43.601Z\\\", \\\"SightingsCount\\\": 1.0, \\\"Criticality\\\": 3.0}]}\",\"Name\":\"ubykou33.top\",\"Risk\":\"67\",\"RiskString\":\"4/52\"}",
        "risk_score": 67,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "recordedfuture": {
        "evidence_details": [
            {
                "criticality": 1,
                "criticality_label": "Unusual",
                "evidence_string": "1 sighting on 1 source: ThreatFox Infrastructure Analysis. ThreatFox identified ubykou33.top as possible TA0011 (Command and Control) for CryptBot on December 26, 2023. Most recent link (Dec 26, 2023): https://threatfox.abuse.ch/ioc/1223634",
                "mitigation_string": "",
                "name": "suspectedCncDnsName",
                "rule": "Historical Suspected C&C DNS Name",
                "sightings_count": 1,
                "sources": [
                    "source:sIoEOQ"
                ],
                "sources_count": 1,
                "timestamp": "2023-12-26T17:06:29.000Z"
            },
            {
                "criticality": 1,
                "criticality_label": "Unusual",
                "evidence_string": "2 sightings on 2 sources: External Sensor Data Analysis, Bitdefender. ubykou33.top is observed to be a malware site domain that navigates to malicious content including executables, drive-by infection sites, malicious scripts, viruses, trojans, or code.",
                "mitigation_string": "",
                "name": "malwareSiteDetected",
                "rule": "Historically Detected Malware Operation",
                "sightings_count": 2,
                "sources": [
                    "source:kBB1fk",
                    "source:d3Awkm"
                ],
                "sources_count": 2,
                "timestamp": "2024-01-26T00:00:00.000Z"
            },
            {
                "criticality": 1,
                "criticality_label": "Unusual",
                "evidence_string": "1 sighting on 1 source: Bitdefender. Detected malicious behavior from an endpoint agent via global telemetry. Last observed on Jan 26, 2024.",
                "mitigation_string": "",
                "name": "malwareSiteSuspected",
                "rule": "Historically Suspected Malware Operation",
                "sightings_count": 1,
                "sources": [
                    "source:d3Awkm"
                ],
                "sources_count": 1,
                "timestamp": "2024-01-26T00:00:00.000Z"
            },
            {
                "criticality": 3,
                "criticality_label": "Malicious",
                "evidence_string": "1 sighting on 1 source: External Sensor Data Analysis. ubykou33.top is observed to be a malware site domain that navigates to malicious content including executables, drive-by infection sites, malicious scripts, viruses, trojans, or code.",
                "mitigation_string": "",
                "name": "recentMalwareSiteDetected",
                "rule": "Recently Detected Malware Operation",
                "sightings_count": 1,
                "sources": [
                    "source:kBB1fk"
                ],
                "sources_count": 1,
                "timestamp": "2024-05-08T23:11:43.601Z"
            }
        ],
        "list": "test",
        "name": "ubykou33.top",
        "risk_string": "4/52"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "recordedfuture"
    ],
    "threat": {
        "feed": {
            "name": "Recorded Future"
        },
        "indicator": {
            "provider": [
                "ThreatFox Infrastructure Analysis",
                "External Sensor Data Analysis",
                "Bitdefender"
            ],
            "scanner_stats": 5,
            "sightings": 5,
            "type": "domain-name",
            "url": {
                "domain": "ubykou33.top"
            }
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
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |

