# Cybersixgill Darkfeed TAXII Integration

This integration connects with the commercial [Cybersixgill Darkfeed](https://www.cybersixgill.com/products/darkfeed/) TAXII server.

## Logs

### Threat

The Cybersixgill Darkfeed integration collects threat intelligence from the Darkfeed TAXII service available using the credentials provided from Cybersixgill.

#### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs are expired after the duration configured by `IOC Expiration Duration` integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_cybersixgill_latest.dest_threat-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_cybersixgill_latest.threat`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards are also pointing to the latest destination indices containing active IOC. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source datastream `.ds-logs-ti_cybersixgill.threat-*` indices.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_cybersixgill.threat-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_cybersixgill.threat-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cybersixgill.actor | The related actor for the indicator. | keyword |
| cybersixgill.deleted_at | The timestamp when indicator is (or will be) expired. | date |
| cybersixgill.expiration_duration | The configured expiration duration. | keyword |
| cybersixgill.feedname | Name of the Threat Intel feed. | keyword |
| cybersixgill.mitre.description | The mitre description of the indicator | keyword |
| cybersixgill.title | The title of the indicator. | keyword |
| cybersixgill.valid_from | At what date the indicator is valid from. | date |
| cybersixgill.virustotal.pr | The Virustotal positive rate. | keyword |
| cybersixgill.virustotal.url | The related Virustotal URL. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2021-12-07T13:58:01.596Z",
    "agent": {
        "ephemeral_id": "70f5e8ea-8e32-4560-8e0f-3f3438fe9958",
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "cybersixgill": {
        "actor": "vaedzy",
        "deleted_at": "2021-12-17T13:58:01.596Z",
        "expiration_duration": "10d",
        "feedname": "dark_web_hashes",
        "mitre": {
            "description": "Mitre attack tactics and technique reference"
        },
        "title": "[病毒样本] #Trickbot (2021-12-07)",
        "virustotal": {
            "pr": "medium",
            "url": "https://virustotal.com/#/file/7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d"
        }
    },
    "data_stream": {
        "dataset": "ti_cybersixgill.threat",
        "namespace": "39285",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-06-12T03:26:26.797Z",
        "dataset": "ti_cybersixgill.threat",
        "ingested": "2024-06-12T03:26:27Z",
        "kind": "enrichment",
        "original": "{\"confidence\":70,\"created\":\"2021-12-07T13:58:01.596Z\",\"description\":\"Hash attributed to malware that was discovered in the dark and deep web\",\"extensions\":{\"extension-definition--3de9ff00-174d-4d41-87c9-05a27a7e117c\":{\"extension_type\":\"toplevel-property-extension\"}},\"external_references\":[{\"positive_rate\":\"medium\",\"source_name\":\"VirusTotal\",\"url\":\"https://virustotal.com/#/file/7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d\"},{\"description\":\"Mitre attack tactics and technique reference\",\"mitre_attack_tactic\":\"Build Capabilities\",\"mitre_attack_tactic_id\":\"TA0024\",\"mitre_attack_tactic_url\":\"https://attack.mitre.org/tactics/TA0024/\",\"source_name\":\"mitre-attack\"}],\"id\":\"indicator--302dab0f-64dc-42f5-b99e-702b28c1aaa9\",\"indicator_types\":[\"malicious-activity\"],\"lang\":\"en\",\"modified\":\"2021-12-07T13:58:01.596Z\",\"name\":\"4d0f21919d623bd1631ee15ca7429f28;5ce39ef0700b64bd0c71b55caf64ae45d8400965;7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d\",\"pattern\":\"[file:hashes.MD5 = '4d0f21919d623bd1631ee15ca7429f28' OR file:hashes.'SHA-1' = '5ce39ef0700b64bd0c71b55caf64ae45d8400965' OR file:hashes.'SHA-256' = '7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d']\",\"pattern_type\":\"stix\",\"sixgill_actor\":\"vaedzy\",\"sixgill_confidence\":70,\"sixgill_feedid\":\"darkfeed_012\",\"sixgill_feedname\":\"dark_web_hashes\",\"sixgill_post_virustotallink\":\"https://virustotal.com/#/file/7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d\",\"sixgill_postid\":\"c0c9a0085fb5281cfb40a0ddb62e1d2c6a53eb7a\",\"sixgill_posttitle\":\"[病毒样本] #Trickbot (2021-12-07)\",\"sixgill_severity\":70,\"sixgill_source\":\"forum_kafan\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2021-12-07T02:55:17Z\"}",
        "severity": 70,
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
        "ti_cybersixgill"
    ],
    "threat": {
        "indicator": {
            "confidence": "High",
            "description": "Hash attributed to malware that was discovered in the dark and deep web",
            "file": {
                "hash": {
                    "md5": "4d0f21919d623bd1631ee15ca7429f28",
                    "sha1": "5ce39ef0700b64bd0c71b55caf64ae45d8400965",
                    "sha256": "7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d"
                }
            },
            "first_seen": "2021-12-07T02:55:17.000Z",
            "last_seen": "2021-12-07T13:58:01.596Z",
            "name": "7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d",
            "provider": "forum_kafan",
            "reference": "https://portal.cybersixgill.com/#/search?q=_id:c0c9a0085fb5281cfb40a0ddb62e1d2c6a53eb7a",
            "type": "file"
        },
        "tactic": {
            "id": [
                "TA0024"
            ],
            "name": [
                "Build Capabilities"
            ],
            "reference": [
                "https://attack.mitre.org/tactics/TA0024/"
            ]
        }
    }
}
```