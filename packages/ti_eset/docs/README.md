# ESET Threat Intelligence Integration

This integration connects with the [ESET Threat Intelligence](https://eti.eset.com/taxii2/) TAXII version 2 server.
It includes the following datasets for retrieving logs:

|            Dataset | TAXII2 Collection name      |
|-------------------:|:----------------------------|
| androidinfostealer | androidinfostealer stix 2.1 |
|     androidthreats | androidthreats stix 2.1     |
|                apt | apt stix 2.1                |
|             botnet | botnet stix 2.1             |
|                 cc | botnet.cc stix 2.1          |
|         cryptoscam | cryptoscam stix 2.1         |
|            domains | domain stix 2.1             |
|   emailattachments | emailattachments stix 2.1   |
|              files | file stix 2.1               |
|                 ip | ip stix 2.1                 |
|        phishingurl | phishingurl stix 2.1        |
|          puaadware | puaadware stix 2.1          |
|        puadualapps | puadualapps stix 2.1        |
|         ransomware | ransomware stix 2.1         |
|            scamurl | scamurl stix 2.1            |
|           smishing | smishing stix 2.1           |
|            smsscam | smsscam stix 2.1            |
|                url | url stix 2.1                |

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Expiration of Indicators of Compromise (IOCs)

The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_eset_latest.dest_*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_eset_latest.<feed name>`.

| Source Datastream                   | Destination Index Pattern                     | Destination Alias                      |
|:------------------------------------|:----------------------------------------------|----------------------------------------|
| `logs-ti_eset.androidinfostealer-*` | logs-ti_eset_latest.dest_androidinfostealer-* | logs-ti_eset_latest.androidinfostealer |
| `logs-ti_eset.androidthreats-*`     | logs-ti_eset_latest.dest_androidthreats-*     | logs-ti_eset_latest.androidthreats     |
| `logs-ti_eset.apt-*`                | logs-ti_eset_latest.dest_apt-*                | logs-ti_eset_latest.apt                |
| `logs-ti_eset.botnet-*`             | logs-ti_eset_latest.dest_botnet-*             | logs-ti_eset_latest.botnet             |
| `logs-ti_eset.cc-*`                 | logs-ti_eset_latest.dest_cc-*                 | logs-ti_eset_latest.cc                 |
| `logs-ti_eset.cryptoscam-*`         | logs-ti_eset_latest.dest_cryptoscam-*         | logs-ti_eset_latest.cryptoscam         |
| `logs-ti_eset.domains-*`            | logs-ti_eset_latest.dest_domains-*            | logs-ti_eset_latest.domains            |
| `logs-ti_eset.emailattachments-*`   | logs-ti_eset_latest.dest_emailattachments-*   | logs-ti_eset_latest.emailattachments   |
| `logs-ti_eset.files-*`              | logs-ti_eset_latest.dest_files-*              | logs-ti_eset_latest.files              |
| `logs-ti_eset.ip-*`                 | logs-ti_eset_latest.dest_ip-*                 | logs-ti_eset_latest.ip                 |
| `logs-ti_eset.phishingurl-*`        | logs-ti_eset_latest.dest_phishingurl-*        | logs-ti_eset_latest.phishingurl        |
| `logs-ti_eset.puaadware-*`          | logs-ti_eset_latest.dest_puaadware-*          | logs-ti_eset_latest.puaadware          |
| `logs-ti_eset.puadualapps-*`        | logs-ti_eset_latest.dest_puadualapps-*        | logs-ti_eset_latest.puadualapps        |
| `logs-ti_eset.ransomware-*`         | logs-ti_eset_latest.dest_ransomware-*         | logs-ti_eset_latest.ransomware         |
| `logs-ti_eset.scamurl-*`            | logs-ti_eset_latest.dest_scamurl-*            | logs-ti_eset_latest.scamurl            |
| `logs-ti_eset.smishing-*`           | logs-ti_eset_latest.dest_smishing-*           | logs-ti_eset_latest.smishing           |
| `logs-ti_eset.smsscam-*`            | logs-ti_eset_latest.dest_smsscam-*            | logs-ti_eset_latest.smsscam            |
| `logs-ti_eset.url-*`                | logs-ti_eset_latest.dest_url-*                | logs-ti_eset_latest.url                |

### ILM Policy

ILM policy is added to the source indices, so it doesn't lead to unbounded growth.
Data in these source indices will be deleted after a certain number of days from ingested days:

|                             Index | Deleted after | Expired after |
|----------------------------------:|:--------------|---------------|
| `logs-ti_eset.androidinfostealer` | 7d            | 48h           |
|     `logs-ti_eset.androidthreats` | 7d            | 48h           |
|                `logs-ti_eset.apt` | 365d          | 365d          |
|             `logs-ti_eset.botnet` | 7d            | 48h           |
|                 `logs-ti_eset.cc` | 7d            | 48h           |
|         `logs-ti_eset.cryptoscam` | 7d            | 48h           |
|            `logs-ti_eset.domains` | 7d            | 48h           |
|   `logs-ti_eset.emailattachments` | 7d            | 48h           |
|              `logs-ti_eset.files` | 7d            | 48h           |
|                 `logs-ti_eset.ip` | 7d            | 48h           |
|        `logs-ti_eset.phishingurl` | 7d            | 48h           |
|          `logs-ti_eset.puaadware` | 7d            | 48h           |
|        `logs-ti_eset.puadualapps` | 7d            | 48h           |
|         `logs-ti_eset.ransomware` | 7d            | 48h           |
|            `logs-ti_eset.scamurl` | 7d            | 48h           |
|           `logs-ti_eset.smishing` | 7d            | 48h           |
|            `logs-ti_eset.smsscam` | 7d            | 48h           |
|                `logs-ti_eset.url` | 7d            | 48h           |

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **ESET Threat Intelligence**.
3. Select the **ESET Threat Intelligence** integration and add it.
4. Configure all required integration parameters, including username and password that you have received from ESET during onboarding process. For more information, check the [ESET Threat Intelligence](https://www.eset.com/int/business/services/threat-intelligence/) documentation.
5. Enable data streams you are interested in and have access to.
6. Save the integration.

## Logs

### Android info stealer

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `androidinfostealer` looks as following:

```json
{
    "@timestamp": "2025-08-27T12:51:58.000Z",
    "agent": {
        "ephemeral_id": "4e649840-f137-4c31-91e8-d254c09d489c",
        "id": "9e771b91-5a6f-419b-9971-1da61c8c4252",
        "name": "elastic-agent-94452",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.androidinfostealer",
        "namespace": "50257",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9e771b91-5a6f-419b-9971-1da61c8c4252",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--3f28a31b-5c23-46e6-bbae-15c20b5cb27b",
        "labels": "malicious-activity",
        "valid_until": "2025-08-29T12:51:58.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.androidinfostealer",
        "ingested": "2026-08-01T20:38:33Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"confidence\":85,\"created\":\"2025-08-27T12:51:58.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Each of these file hashes indicates that a variant of a variant of Android/Spy.Banker.DSU trojan is present.\",\"id\":\"indicator--3f28a31b-5c23-46e6-bbae-15c20b5cb27b\",\"labels\":[\"malicious-activity\"],\"modified\":\"2025-08-27T12:51:58.000Z\",\"name\":\"Malware variant\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[file:hashes.'SHA-256' = 'd077a2851161c3363e806b50d7b4648203ecf20647cb03d6d9e593074028c728'] OR [file:hashes.'SHA-1' = '5b913f8dfb17533def5db50b63583076ff8a6e28'] OR [file:hashes.'MD5' = '5db237b11fe18f92a13b743c98fb8945']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-27T12:51:58Z\",\"valid_until\":\"2025-08-29T12:51:58Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-androidinfostealer"
    ],
    "threat": {
        "feed": {
            "name": "ESET Android info stealer stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of a variant of Android/Spy.Banker.DSU trojan is present.",
            "file": {
                "hash": {
                    "md5": "5db237b11fe18f92a13b743c98fb8945",
                    "sha1": "5b913f8dfb17533def5db50b63583076ff8a6e28",
                    "sha256": "d077a2851161c3363e806b50d7b4648203ecf20647cb03d6d9e593074028c728"
                }
            },
            "last_seen": "2025-08-27T12:51:58.000Z",
            "modified_at": "2025-08-27T12:51:58.000Z",
            "name": "Malware variant",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### Android Threats

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `androidthreats` looks as following:

```json
{
    "@timestamp": "2024-07-10T11:58:57.000Z",
    "agent": {
        "ephemeral_id": "90f2eb93-3dae-4281-8f1e-7f04770e69bc",
        "id": "c76ed909-0c3f-4f6d-9e2e-ca7c89903cb4",
        "name": "elastic-agent-77465",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.androidthreats",
        "namespace": "45853",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c76ed909-0c3f-4f6d-9e2e-ca7c89903cb4",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--a4d26a0d-4a54-414e-8426-7f71ce95d2c1",
        "labels": "malicious-activity",
        "valid_until": "2024-07-12T11:58:57.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.androidthreats",
        "ingested": "2026-08-01T20:45:01Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"created\":\"2024-07-10T11:58:57.000Z\",\"description\":\"Each of these file hashes indicates that a variant of a variant of Android/Spy.Agent.DER trojan is present.\",\"id\":\"indicator--a4d26a0d-4a54-414e-8426-7f71ce95d2c1\",\"labels\":[\"malicious-activity\"],\"modified\":\"2024-07-10T11:58:57.000Z\",\"name\":\"Malware variant\",\"pattern\":\"[file:hashes.'SHA-256' = '422985ed937201e230537c5c10bbd8c1fda783923372e4cbd0ecad99a640695d'] OR [file:hashes.'SHA-1' = '3a6c1999caf6d063b7739d6375d1249419595aa1'] OR [file:hashes.'MD5' = '9538fc50262945cd15e42715f32f5039']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-07-10T11:58:57Z\",\"valid_until\":\"2024-07-12T11:58:57Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-androidthreats"
    ],
    "threat": {
        "feed": {
            "name": "ESET Android threats stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of a variant of Android/Spy.Agent.DER trojan is present.",
            "file": {
                "hash": {
                    "md5": "9538fc50262945cd15e42715f32f5039",
                    "sha1": "3a6c1999caf6d063b7739d6375d1249419595aa1",
                    "sha256": "422985ed937201e230537c5c10bbd8c1fda783923372e4cbd0ecad99a640695d"
                }
            },
            "last_seen": "2024-07-10T11:58:57.000Z",
            "modified_at": "2024-07-10T11:58:57.000Z",
            "name": "Malware variant",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### APT

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eset.category | Event category as defined by MISP. | keyword |
| eset.id | The UID of the event object. | keyword |
| eset.meta_category | Event sub-category as defined by MISP. | keyword |
| eset.name | Human readable name describing the event. | keyword |
| eset.type | Type of the event. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `apt` looks as following:

```json
{
    "@timestamp": "2023-09-29T08:48:42.000Z",
    "agent": {
        "ephemeral_id": "8090e389-5500-4f50-8f07-91c07d36fa23",
        "id": "8bd00dbe-79ef-4915-8eec-7d2e14c655dc",
        "name": "elastic-agent-60741",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.apt",
        "namespace": "26937",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8bd00dbe-79ef-4915-8eec-7d2e14c655dc",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--a4cb9aa8-b12e-4141-ae33-509dfd9dd382",
        "meta_category": "file",
        "name": "file",
        "valid_until": "2024-09-28T08:48:42.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.apt",
        "ingested": "2026-05-26T17:57:59Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-09-29T08:48:42.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"id\":\"indicator--a4cb9aa8-b12e-4141-ae33-509dfd9dd382\",\"kill_chain_phases\":[{\"kill_chain_name\":\"misp-category\",\"phase_name\":\"file\"}],\"labels\":[\"misp:name=\\\"file\\\"\",\"misp:meta-category=\\\"file\\\"\",\"misp:to_ids=\\\"True\\\"\"],\"modified\":\"2023-09-29T08:48:42.000Z\",\"pattern\":\"[file:hashes.MD5 = '7196b26572d2c357a17599b9a0d71d33' AND file:hashes.SHA1 = 'a3ee3d4bc8057cfde073a7acf3232cfb3cbb10c0' AND file:hashes.SHA256 = '6c9eab41d2e06702313ee6513a8b98adc083ee7bcd2c85821a8a3136c20d687e' AND file:name = 'KihqQGHs7zYOxqqNE0b9zO4w6d7ysXUWrfDf6vLOAW4MU3Fs.mp3' AND file:parent_directory_ref.path = 'Comchit ltr no 4200 dt 23-09-2023' AND file:x_misp_fullpath = 'Comchit ltr no 4200 dt 23-09-2023/KihqQGHs7zYOxqqNE0b9zO4w6d7ysXUWrfDf6vLOAW4MU3Fs.mp3' AND file:extensions.'windows-pebinary-ext'.imphash = 'fcab131627362db5898b1bcc15d7fd72' AND file:extensions.'windows-pebinary-ext'.pe_type = 'dll' AND file:extensions.'windows-pebinary-ext'.x_misp_compilation_timestamp = '2023-09-25 07:03:56+00:00' AND file:extensions.'windows-pebinary-ext'.x_misp_authentihash = '6c744b262dbf76fb20346a93cbedbb0668c90b5bb5027485109e3cfb41f48d8c']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-09-26T07:00:04Z\"}",
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
        "eset-apt"
    ],
    "threat": {
        "feed": {
            "name": "ESET APT stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "file": {
                "hash": {
                    "md5": "7196b26572d2c357a17599b9a0d71d33",
                    "sha1": "a3ee3d4bc8057cfde073a7acf3232cfb3cbb10c0",
                    "sha256": "6c9eab41d2e06702313ee6513a8b98adc083ee7bcd2c85821a8a3136c20d687e"
                },
                "name": "KihqQGHs7zYOxqqNE0b9zO4w6d7ysXUWrfDf6vLOAW4MU3Fs.mp3"
            },
            "last_seen": "2023-09-29T08:48:42.000Z",
            "modified_at": "2023-09-29T08:48:42.000Z",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### Botnet

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `botnet` looks as following:

```json
{
    "@timestamp": "2023-10-18T02:05:09.000Z",
    "agent": {
        "ephemeral_id": "8ccef148-0cdf-4314-b38b-74fb79d33d1e",
        "id": "9d61d79f-13ae-4202-8690-39cef6ce50c2",
        "name": "elastic-agent-36408",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.botnet",
        "namespace": "78283",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9d61d79f-13ae-4202-8690-39cef6ce50c2",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--80dc09fa-563f-4a9c-ad1d-655d8dffa37f",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-20T02:05:09.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.botnet",
        "ingested": "2026-05-26T17:59:08Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-18T02:05:09.000Z\",\"description\":\"Each of these file hashes indicates that a variant of Win32/Rescoms.B backdoor is present.\",\"id\":\"indicator--80dc09fa-563f-4a9c-ad1d-655d8dffa37f\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-18T02:05:09.000Z\",\"name\":\"373d34874d7bc89fd4cefa6272ee80bf\",\"pattern\":\"[file:hashes.'SHA-256'='b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7'] OR [file:hashes.'SHA-1'='373d34874d7bc89fd4cefa6272ee80bf'] OR [file:hashes.'MD5'='373d34874d7bc89fd4cefa6272ee80bf']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-18T02:05:09Z\",\"valid_until\":\"2023-10-20T02:05:09Z\"}",
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
        "eset-botnet"
    ],
    "threat": {
        "feed": {
            "name": "ESET Botnet stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of Win32/Rescoms.B backdoor is present.",
            "file": {
                "hash": {
                    "md5": "373d34874d7bc89fd4cefa6272ee80bf",
                    "sha1": "373d34874d7bc89fd4cefa6272ee80bf",
                    "sha256": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7"
                }
            },
            "last_seen": "2023-10-18T02:05:09.000Z",
            "modified_at": "2023-10-18T02:05:09.000Z",
            "name": "373d34874d7bc89fd4cefa6272ee80bf",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### C&C

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `cc` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:00:09.000Z",
    "agent": {
        "ephemeral_id": "2a76dc03-c546-45c4-9600-49f5c1e9bee8",
        "id": "dfbb6a96-ed78-4c98-8de5-476888da030a",
        "name": "elastic-agent-59245",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.cc",
        "namespace": "92562",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dfbb6a96-ed78-4c98-8de5-476888da030a",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--34e0eaa0-d35d-4039-b801-8f05d4e16bea",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-21T02:00:09.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.cc",
        "ingested": "2026-05-26T18:00:18Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:00:09.000Z\",\"description\":\"C\\u0026C of Win32/Smokeloader.H trojan\",\"id\":\"indicator--34e0eaa0-d35d-4039-b801-8f05d4e16bea\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-19T02:00:09.000Z\",\"name\":\"https://example.com/some/path\",\"pattern\":\"[url:value='https://example.com/some/path']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:00:09Z\",\"valid_until\":\"2023-10-21T02:00:09Z\"}",
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
        "eset-cc"
    ],
    "threat": {
        "feed": {
            "name": "ESET Botnet C&C stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "C&C of Win32/Smokeloader.H trojan",
            "last_seen": "2023-10-19T02:00:09.000Z",
            "modified_at": "2023-10-19T02:00:09.000Z",
            "name": "https://example.com/some/path",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "https://example.com/some/path"
            }
        }
    }
}
```

### Crypto scam

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `cryptoscam` looks as following:

```json
{
    "@timestamp": "2024-03-18T13:25:08.000Z",
    "agent": {
        "ephemeral_id": "03779f2f-485c-4df3-8938-c039b0321c66",
        "id": "32d81282-8391-46bd-bc19-51b8a54a6e8f",
        "name": "elastic-agent-12824",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.cryptoscam",
        "namespace": "66693",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "32d81282-8391-46bd-bc19-51b8a54a6e8f",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--5d8275cd-993e-4ba1-87a3-251e8e072894",
        "labels": "unwanted-activity",
        "valid_until": "2024-03-20T13:25:08.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.cryptoscam",
        "ingested": "2026-08-01T20:50:02Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"created\":\"2024-03-18T13:25:08.000Z\",\"description\":\"Host is known source of active fraudulent content.\",\"id\":\"indicator--5d8275cd-993e-4ba1-87a3-251e8e072894\",\"labels\":[\"unwanted-activity\"],\"modified\":\"2024-03-18T13:25:08.000Z\",\"name\":\"Unwanted\",\"pattern\":\"[url:value='http://future-exchange.net']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-03-18T13:25:08Z\",\"valid_until\":\"2024-03-20T13:25:08Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-cryptoscam"
    ],
    "threat": {
        "feed": {
            "name": "ESET Crypto scam stix 2.1"
        },
        "indicator": {
            "confidence": "Medium",
            "description": "Host is known source of active fraudulent content.",
            "last_seen": "2024-03-18T13:25:08.000Z",
            "modified_at": "2024-03-18T13:25:08.000Z",
            "name": "Unwanted",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "http://future-exchange.net"
            }
        }
    }
}
```

### Domains

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `domains` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:00:28.000Z",
    "agent": {
        "ephemeral_id": "56770e93-16e4-4739-b52f-1f2f5b41ce0e",
        "id": "d31d9d94-4df3-4adb-a5ba-b683cc996ebf",
        "name": "elastic-agent-96525",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.domains",
        "namespace": "51129",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d31d9d94-4df3-4adb-a5ba-b683cc996ebf",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--dfb05726-f2be-43c8-a5b2-48e78cc05286",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-21T02:00:28.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.domains",
        "ingested": "2026-05-26T18:01:28Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:00:28.000Z\",\"description\":\"Host is known to be actively distributing adware or other medium-risk software.\",\"id\":\"indicator--dfb05726-f2be-43c8-a5b2-48e78cc05286\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-19T02:00:28.000Z\",\"name\":\"example.com\",\"pattern\":\"[domain-name:value='example.com']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:00:28Z\",\"valid_until\":\"2023-10-21T02:00:28Z\"}",
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
        "eset-domains"
    ],
    "threat": {
        "feed": {
            "name": "ESET Domain stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Host is known to be actively distributing adware or other medium-risk software.",
            "last_seen": "2023-10-19T02:00:28.000Z",
            "modified_at": "2023-10-19T02:00:28.000Z",
            "name": "example.com",
            "provider": "eset",
            "type": "url",
            "url": {
                "domain": "example.com",
                "original": "example.com"
            }
        }
    }
}
```

### Email attachments

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `emailattachments` looks as following:

```json
{
    "@timestamp": "2024-03-18T14:15:42.000Z",
    "agent": {
        "ephemeral_id": "10a5edac-8074-47ea-bd11-49a03002b6f5",
        "id": "da1377da-0b30-430d-860b-8f73e8b3568a",
        "name": "elastic-agent-26272",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.emailattachments",
        "namespace": "63694",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "da1377da-0b30-430d-860b-8f73e8b3568a",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--00c42f20-62d2-4cb6-be87-2c451aaec4a4",
        "labels": "malicious-activity",
        "valid_until": "2024-03-20T14:15:42.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.emailattachments",
        "ingested": "2026-08-01T19:34:01Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"created\":\"2024-03-18T14:15:42.000Z\",\"description\":\"Each of these file hashes indicates that a variant of a variant of MSIL/Kryptik.ALDO trojan is present.\",\"id\":\"indicator--00c42f20-62d2-4cb6-be87-2c451aaec4a4\",\"labels\":[\"malicious-activity\"],\"modified\":\"2024-03-18T14:15:42.000Z\",\"name\":\"Malware variant\",\"pattern\":\"[file:hashes.'SHA-256'='a11a40ee211021d421a6f735715f0bae168aadada0a051c76c5b7e9f83fc0abb'] OR [file:hashes.'SHA-1'='9e8303d999889e32328f9ebcd0e17fdc6ecd8b2d'] OR [file:hashes.'MD5'='13442e50b95944a3c6aba42da0c9b1ad']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-03-18T14:15:42Z\",\"valid_until\":\"2024-03-20T14:15:42Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-emailattachments"
    ],
    "threat": {
        "feed": {
            "name": "ESET Email attachments stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of a variant of MSIL/Kryptik.ALDO trojan is present.",
            "file": {
                "hash": {
                    "md5": "13442e50b95944a3c6aba42da0c9b1ad",
                    "sha1": "9e8303d999889e32328f9ebcd0e17fdc6ecd8b2d",
                    "sha256": "a11a40ee211021d421a6f735715f0bae168aadada0a051c76c5b7e9f83fc0abb"
                }
            },
            "last_seen": "2024-03-18T14:15:42.000Z",
            "modified_at": "2024-03-18T14:15:42.000Z",
            "name": "Malware variant",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### Malicious files

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `files` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:00:38.000Z",
    "agent": {
        "ephemeral_id": "0fb77f31-1be9-4905-b796-ede69232c83d",
        "id": "772a41d6-f939-4684-9447-e1dcf2967364",
        "name": "elastic-agent-57534",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.files",
        "namespace": "10685",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "772a41d6-f939-4684-9447-e1dcf2967364",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--5d7e9ad6-7b48-42fa-8598-d474e8da1b0f",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-21T02:00:38.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.files",
        "ingested": "2026-05-26T18:02:39Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:00:38.000Z\",\"description\":\"Each of these file hashes indicates that a variant of HTML/Phishing.Agent.EVU trojan is present.\",\"id\":\"indicator--5d7e9ad6-7b48-42fa-8598-d474e8da1b0f\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-19T02:00:38.000Z\",\"name\":\"b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7\",\"pattern\":\"[file:hashes.'SHA-256'='b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7'] OR [file:hashes.'SHA-1'='b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7'] OR [file:hashes.'MD5'='b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:00:38Z\",\"valid_until\":\"2023-10-21T02:00:38Z\"}",
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
        "eset-files"
    ],
    "threat": {
        "feed": {
            "name": "ESET Malicious Files stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of HTML/Phishing.Agent.EVU trojan is present.",
            "file": {
                "hash": {
                    "md5": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7",
                    "sha1": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7",
                    "sha256": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7"
                }
            },
            "last_seen": "2023-10-19T02:00:38.000Z",
            "modified_at": "2023-10-19T02:00:38.000Z",
            "name": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### IP

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `ip` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:20:06.000Z",
    "agent": {
        "ephemeral_id": "d737e309-44ce-4216-864d-9dcacc8a9e31",
        "id": "b1a2ecec-61c3-44ee-8d45-8ba9d70a080c",
        "name": "elastic-agent-47253",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.ip",
        "namespace": "47488",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "b1a2ecec-61c3-44ee-8d45-8ba9d70a080c",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--905fad40-d804-4b89-ac9d-b616e0b8f6d3",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-21T02:20:06.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.ip",
        "ingested": "2026-05-26T18:03:47Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:20:06.000Z\",\"description\":\"Web services scanning and attacks\",\"id\":\"indicator--905fad40-d804-4b89-ac9d-b616e0b8f6d3\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-19T02:20:06.000Z\",\"name\":\"5.2.75.227\",\"pattern\":\"[ipv4-addr:value='5.2.75.227']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:20:06Z\",\"valid_until\":\"2023-10-21T02:20:06Z\"}",
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
        "eset-ip"
    ],
    "threat": {
        "feed": {
            "name": "ESET IP stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Web services scanning and attacks",
            "ip": "5.2.75.227",
            "last_seen": "2023-10-19T02:20:06.000Z",
            "modified_at": "2023-10-19T02:20:06.000Z",
            "name": "5.2.75.227",
            "provider": "eset",
            "type": "ipv4-addr"
        }
    }
}
```

### Phishing URL

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `phishingurl` looks as following:

```json
{
    "@timestamp": "2025-08-20T11:52:31.000Z",
    "agent": {
        "ephemeral_id": "ca08afc6-a246-41d8-af59-b0e9bfc8934b",
        "id": "c1987157-0dd8-4177-b862-16be299726c8",
        "name": "elastic-agent-83116",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.phishingurl",
        "namespace": "20027",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c1987157-0dd8-4177-b862-16be299726c8",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--f8bac022-878c-4c24-ab77-e275e04470b8",
        "labels": "phishing-activity",
        "valid_until": "2025-08-22T11:52:31.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.phishingurl",
        "ingested": "2026-08-01T20:55:01Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"confidence\":85,\"created\":\"2025-08-20T11:52:31.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Host is known source of phishing or other fraudulent content.\",\"id\":\"indicator--f8bac022-878c-4c24-ab77-e275e04470b8\",\"labels\":[\"phishing-activity\"],\"modified\":\"2025-08-20T11:52:31.000Z\",\"name\":\"Phishing\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[url:value = 'http://track-supportdhl.com']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-20T11:52:31Z\",\"valid_until\":\"2025-08-22T11:52:31Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-phishingurl"
    ],
    "threat": {
        "feed": {
            "name": "ESET Phishing URLs stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Host is known source of phishing or other fraudulent content.",
            "last_seen": "2025-08-20T11:52:31.000Z",
            "modified_at": "2025-08-20T11:52:31.000Z",
            "name": "Phishing",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "http://track-supportdhl.com"
            }
        }
    }
}
```

### PUA adware

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `puaadware` looks as following:

```json
{
    "@timestamp": "2025-03-04T18:10:25.000Z",
    "agent": {
        "ephemeral_id": "500b3e73-e351-4200-a4e3-4c4a9d9788dc",
        "id": "24b7b419-d883-45ca-ab7c-54db800a6b86",
        "name": "elastic-agent-27609",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.puaadware",
        "namespace": "29529",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "24b7b419-d883-45ca-ab7c-54db800a6b86",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--f7c7d9f1-e31d-4c34-9d4b-c4d89b6b51ba",
        "labels": "malicious-activity",
        "valid_until": "2025-03-06T18:10:25.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.puaadware",
        "ingested": "2026-08-01T21:03:41Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"confidence\":85,\"created\":\"2025-03-04T18:10:25.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Each of these file hashes indicates that a variant of a variant of Win32/Adware.OpenSUpdater.LC.gen application is present.\",\"id\":\"indicator--f7c7d9f1-e31d-4c34-9d4b-c4d89b6b51ba\",\"labels\":[\"malicious-activity\"],\"modified\":\"2025-03-04T18:10:25.000Z\",\"name\":\"Malware variant\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[file:hashes.'SHA-256' = 'ece8562d64dad4a1aa24d06be50db38caffeac428d49be9cc6ef6eabf9120a0b'] OR [file:hashes.'SHA-1' = '74ecd87132c2ed11b7ef822692cb5d6d88280e7e'] OR [file:hashes.'MD5' = 'eb9c9d6eb5398d0d223140f866ad769c']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-03-04T18:10:25Z\",\"valid_until\":\"2025-03-06T18:10:25Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-puaadware"
    ],
    "threat": {
        "feed": {
            "name": "ESET PUA adware stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of a variant of Win32/Adware.OpenSUpdater.LC.gen application is present.",
            "file": {
                "hash": {
                    "md5": "eb9c9d6eb5398d0d223140f866ad769c",
                    "sha1": "74ecd87132c2ed11b7ef822692cb5d6d88280e7e",
                    "sha256": "ece8562d64dad4a1aa24d06be50db38caffeac428d49be9cc6ef6eabf9120a0b"
                }
            },
            "last_seen": "2025-03-04T18:10:25.000Z",
            "modified_at": "2025-03-04T18:10:25.000Z",
            "name": "Malware variant",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### PUA dual apps

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `puadualapps` looks as following:

```json
{
    "@timestamp": "2025-08-27T13:06:13.000Z",
    "agent": {
        "ephemeral_id": "d3425085-54b0-4fdf-aafb-b786a078201e",
        "id": "ccb14835-6779-4cb3-a050-7ca02c08ddb1",
        "name": "elastic-agent-69277",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.puadualapps",
        "namespace": "52034",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ccb14835-6779-4cb3-a050-7ca02c08ddb1",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--2d49ae92-fd09-4d78-a612-cab9cb2d3c95",
        "labels": "malicious-activity",
        "valid_until": "2025-08-29T13:06:13.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.puadualapps",
        "ingested": "2026-08-01T21:07:34Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"confidence\":85,\"created\":\"2025-08-27T13:06:13.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Each of these file hashes indicates that a variant of Python/Riskware.Impacket.C application is present.\",\"id\":\"indicator--2d49ae92-fd09-4d78-a612-cab9cb2d3c95\",\"labels\":[\"malicious-activity\"],\"modified\":\"2025-08-27T13:06:13.000Z\",\"name\":\"Malware variant\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[file:hashes.'SHA-256' = '9dffb771cdfafeefe68972be28e705179bb19b73c114e6ec2155e8670cf82e99'] OR [file:hashes.'SHA-1' = 'e22d9493be1c4dbe57fa28ba9a11ecbad02d11aa'] OR [file:hashes.'MD5' = 'ae405a845a510ba4a6a19aca8cdf8252']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-27T13:06:13Z\",\"valid_until\":\"2025-08-29T13:06:13Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-puadualapps"
    ],
    "threat": {
        "feed": {
            "name": "ESET PUA dual applications stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of Python/Riskware.Impacket.C application is present.",
            "file": {
                "hash": {
                    "md5": "ae405a845a510ba4a6a19aca8cdf8252",
                    "sha1": "e22d9493be1c4dbe57fa28ba9a11ecbad02d11aa",
                    "sha256": "9dffb771cdfafeefe68972be28e705179bb19b73c114e6ec2155e8670cf82e99"
                }
            },
            "last_seen": "2025-08-27T13:06:13.000Z",
            "modified_at": "2025-08-27T13:06:13.000Z",
            "name": "Malware variant",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### Ransomware

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `ransomware` looks as following:

```json
{
    "@timestamp": "2025-08-27T11:20:08.000Z",
    "agent": {
        "ephemeral_id": "a3510329-1058-4210-aa97-9587d1bceea7",
        "id": "19e754eb-ffee-48b0-9f75-e821c7020398",
        "name": "elastic-agent-21836",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.ransomware",
        "namespace": "76770",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "19e754eb-ffee-48b0-9f75-e821c7020398",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--2a142f4d-8895-40ce-8c2b-0cc6961b8c1b",
        "labels": "malicious-activity",
        "valid_until": "2025-08-29T11:20:08.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.ransomware",
        "ingested": "2026-08-01T20:59:41Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"confidence\":85,\"created\":\"2025-08-27T11:20:08.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Each of these file hashes indicates that a variant of a variant of Win32/Filecoder.DragonForce.A trojan is present.\",\"id\":\"indicator--2a142f4d-8895-40ce-8c2b-0cc6961b8c1b\",\"labels\":[\"malicious-activity\"],\"modified\":\"2025-08-27T11:20:08.000Z\",\"name\":\"Malware variant\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[file:hashes.'SHA-256' = 'df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403'] OR [file:hashes.'SHA-1' = '4a34bbad85312ef34b60818a47f7b5bb8e9a7e26'] OR [file:hashes.'MD5' = 'e84270afa3030b48dc9e0c53a35c65aa']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-27T11:20:08Z\",\"valid_until\":\"2025-08-29T11:20:08Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-ransomware"
    ],
    "threat": {
        "feed": {
            "name": "ESET Ransomware stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of a variant of Win32/Filecoder.DragonForce.A trojan is present.",
            "file": {
                "hash": {
                    "md5": "e84270afa3030b48dc9e0c53a35c65aa",
                    "sha1": "4a34bbad85312ef34b60818a47f7b5bb8e9a7e26",
                    "sha256": "df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403"
                }
            },
            "last_seen": "2025-08-27T11:20:08.000Z",
            "modified_at": "2025-08-27T11:20:08.000Z",
            "name": "Malware variant",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### SMS scam

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `smsscam` looks as following:

```json
{
    "@timestamp": "2024-03-19T15:20:09.000Z",
    "agent": {
        "ephemeral_id": "eed81fc2-90d6-4154-841f-28cb1949acf4",
        "id": "10a89fde-9ce2-4bd4-9b30-f5d025a02639",
        "name": "elastic-agent-79474",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.smsscam",
        "namespace": "45314",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "10a89fde-9ce2-4bd4-9b30-f5d025a02639",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--9da47616-6288-475e-99e2-6827e77a7c17",
        "labels": "unwanted-activity",
        "valid_until": "2024-03-21T15:20:09.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.smsscam",
        "ingested": "2026-08-01T21:15:23Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"created\":\"2024-03-19T15:20:09.000Z\",\"description\":\"Host is known source of active fraudulent content.\",\"id\":\"indicator--9da47616-6288-475e-99e2-6827e77a7c17\",\"labels\":[\"unwanted-activity\"],\"modified\":\"2024-03-19T15:20:09.000Z\",\"name\":\"Unwanted\",\"pattern\":\"[url:value='www.candycasino79.com']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-03-19T15:20:09Z\",\"valid_until\":\"2024-03-21T15:20:09Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-smsscam"
    ],
    "threat": {
        "feed": {
            "name": "ESET SMS scam stix 2.1"
        },
        "indicator": {
            "confidence": "Medium",
            "description": "Host is known source of active fraudulent content.",
            "last_seen": "2024-03-19T15:20:09.000Z",
            "modified_at": "2024-03-19T15:20:09.000Z",
            "name": "Unwanted",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "www.candycasino79.com"
            }
        }
    }
}
```

### SMS phishing

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `smishing` looks as following:

```json
{
    "@timestamp": "2024-03-18T22:35:07.000Z",
    "agent": {
        "ephemeral_id": "ada03985-c59a-4d35-911f-d3ad04d2b922",
        "id": "a6eac74c-4e94-41b5-8b48-70607491fbaa",
        "name": "elastic-agent-30736",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.smishing",
        "namespace": "14839",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a6eac74c-4e94-41b5-8b48-70607491fbaa",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--056018a4-f5b5-49f5-a2a2-9df6b8160d0b",
        "labels": "phishing-activity",
        "valid_until": "2024-03-20T22:35:07.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.smishing",
        "ingested": "2026-08-01T21:19:32Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"created\":\"2024-03-18T22:35:07.000Z\",\"description\":\"Host is known source of phishing or other fraudulent content.\",\"id\":\"indicator--056018a4-f5b5-49f5-a2a2-9df6b8160d0b\",\"labels\":[\"phishing-activity\"],\"modified\":\"2024-03-18T22:35:07.000Z\",\"name\":\"Phishing\",\"pattern\":\"[url:value='gb-nuhuty.top']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-03-18T22:35:07Z\",\"valid_until\":\"2024-03-20T22:35:07Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-smishing"
    ],
    "threat": {
        "feed": {
            "name": "ESET SMS phishing stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Host is known source of phishing or other fraudulent content.",
            "last_seen": "2024-03-18T22:35:07.000Z",
            "modified_at": "2024-03-18T22:35:07.000Z",
            "name": "Phishing",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "gb-nuhuty.top"
            }
        }
    }
}
```

### Scam URL

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_from | Event start of validity. | date |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `scamurl` looks as following:

```json
{
    "@timestamp": "2025-08-25T18:20:09.000Z",
    "agent": {
        "ephemeral_id": "d771016a-959d-48a0-8575-07641db4325e",
        "id": "44158276-b2ef-482d-a776-c18c12b5872e",
        "name": "elastic-agent-32628",
        "type": "filebeat",
        "version": "9.4.2"
    },
    "data_stream": {
        "dataset": "ti_eset.scamurl",
        "namespace": "92981",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "44158276-b2ef-482d-a776-c18c12b5872e",
        "snapshot": false,
        "version": "9.4.2"
    },
    "eset": {
        "id": "indicator--7f3d4281-daf8-4d28-bd4a-4124518adf48",
        "labels": "unwanted-activity",
        "valid_until": "2025-08-27T18:20:09.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.scamurl",
        "ingested": "2026-08-01T21:11:25Z",
        "kind": "enrichment",
        "module": "ti_eset",
        "original": "{\"confidence\":85,\"created\":\"2025-08-25T18:20:09.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Host is known source of active fraudulent content.\",\"id\":\"indicator--7f3d4281-daf8-4d28-bd4a-4124518adf48\",\"labels\":[\"unwanted-activity\"],\"modified\":\"2025-08-25T18:20:09.000Z\",\"name\":\"Unwanted\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[url:value = 'https://nautubone-gel.online/satin-al-tr/core-scripts/dr-dtime.js?v=12']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-25T18:20:09Z\",\"valid_until\":\"2025-08-27T18:20:09Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-scamurl"
    ],
    "threat": {
        "feed": {
            "name": "ESET Scam URLs stix 2.1"
        },
        "indicator": {
            "confidence": "Medium",
            "description": "Host is known source of active fraudulent content.",
            "last_seen": "2025-08-25T18:20:09.000Z",
            "modified_at": "2025-08-25T18:20:09.000Z",
            "name": "Unwanted",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "https://nautubone-gel.online/satin-al-tr/core-scripts/dr-dtime.js?v=12"
            }
        }
    }
}
```

### URL

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `url` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:00:13.000Z",
    "agent": {
        "ephemeral_id": "3a2e8408-1f1c-4287-bee7-3f632e4f0934",
        "id": "05c7c23e-3d31-4bb6-9bc8-acba66e26d94",
        "name": "elastic-agent-98055",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.url",
        "namespace": "52267",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "05c7c23e-3d31-4bb6-9bc8-acba66e26d94",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--8986619a-150b-453c-aaa8-bfe8694d05cc",
        "labels": [
            "benign"
        ],
        "valid_until": "2023-10-21T02:00:13.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_eset.url",
        "ingested": "2026-05-26T18:04:58Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:00:13.000Z\",\"description\":\"Host actively distributes high-severity threat in the form of executable code.\",\"id\":\"indicator--8986619a-150b-453c-aaa8-bfe8694d05cc\",\"labels\":[\"benign\"],\"modified\":\"2023-10-19T02:00:13.000Z\",\"name\":\"https://example.com/some/path\",\"pattern\":\"[url:value='https://example.com/some/path']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:00:13Z\",\"valid_until\":\"2023-10-21T02:00:13Z\"}",
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
        "eset-url"
    ],
    "threat": {
        "feed": {
            "name": "ESET URL stix 2.1"
        },
        "indicator": {
            "confidence": "Low",
            "description": "Host actively distributes high-severity threat in the form of executable code.",
            "last_seen": "2023-10-19T02:00:13.000Z",
            "modified_at": "2023-10-19T02:00:13.000Z",
            "name": "https://example.com/some/path",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "https://example.com/some/path"
            }
        }
    }
}
```