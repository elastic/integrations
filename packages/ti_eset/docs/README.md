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
|             domain | domain stix 2.1             |
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

## Expiration of Indicators of Compromise (IOCs)

The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_eset_latest.dest_*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_eset_latest.<feed name>`.

| Source Datastream                   | Destination Index Pattern                     | Destination Alias                      |
|:------------------------------------|:----------------------------------------------|:---------------------------------------|
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


An example event for `androidinfostealer` looks as following:

```json
{
    "@timestamp": "2025-08-27T12:51:58.000Z",
    "agent": {
        "ephemeral_id": "8040c219-fd7a-46f6-b817-249e13cc2f8b",
        "id": "ec8fb42e-452e-4405-9ae9-b815f7e09755",
        "name": "elastic-agent-96426",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.androidinfostealer",
        "namespace": "90853",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ec8fb42e-452e-4405-9ae9-b815f7e09755",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--3f28a31b-5c23-46e6-bbae-15c20b5cb27b",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2025-08-29T12:51:58.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:33:53.856Z",
        "dataset": "ti_eset.androidinfostealer",
        "ingested": "2025-10-27T18:33:56Z",
        "kind": "enrichment",
        "original": "{\"confidence\":85,\"created\":\"2025-08-27T12:51:58.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Each of these file hashes indicates that a variant of a variant of Android/Spy.Banker.DSU trojan is present.\",\"id\":\"indicator--3f28a31b-5c23-46e6-bbae-15c20b5cb27b\",\"labels\":[\"malicious-activity\"],\"modified\":\"2025-08-27T12:51:58.000Z\",\"name\":\"Malware variant\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[file:hashes.'SHA-256' = 'd077a2851161c3363e806b50d7b4648203ecf20647cb03d6d9e593074028c728'] OR [file:hashes.'SHA-1' = '5b913f8dfb17533def5db50b63583076ff8a6e28'] OR [file:hashes.'MD5' = '5db237b11fe18f92a13b743c98fb8945']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-27T12:51:58Z\",\"valid_until\":\"2025-08-29T12:51:58Z\"}",
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


An example event for `androidthreats` looks as following:

```json
{
    "@timestamp": "2024-07-10T11:58:57.000Z",
    "agent": {
        "ephemeral_id": "4dc7d53e-2d91-4bf1-aa43-286857a9318a",
        "id": "b8aad934-fe85-4c24-a396-838a295b203c",
        "name": "elastic-agent-84087",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.androidthreats",
        "namespace": "92376",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "b8aad934-fe85-4c24-a396-838a295b203c",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--a4d26a0d-4a54-414e-8426-7f71ce95d2c1",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2024-07-12T11:58:57.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:35:04.190Z",
        "dataset": "ti_eset.androidthreats",
        "ingested": "2025-10-27T18:35:07Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2024-07-10T11:58:57.000Z\",\"description\":\"Each of these file hashes indicates that a variant of a variant of Android/Spy.Agent.DER trojan is present.\",\"id\":\"indicator--a4d26a0d-4a54-414e-8426-7f71ce95d2c1\",\"labels\":[\"malicious-activity\"],\"modified\":\"2024-07-10T11:58:57.000Z\",\"name\":\"Malware variant\",\"pattern\":\"[file:hashes.'SHA-256' = '422985ed937201e230537c5c10bbd8c1fda783923372e4cbd0ecad99a640695d'] OR [file:hashes.'SHA-1' = '3a6c1999caf6d063b7739d6375d1249419595aa1'] OR [file:hashes.'MD5' = '9538fc50262945cd15e42715f32f5039']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-07-10T11:58:57Z\",\"valid_until\":\"2024-07-12T11:58:57Z\"}",
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
        "ephemeral_id": "a679c1a0-9912-432a-8b96-c086ca315b48",
        "id": "cf4d8f48-a3a0-4e2b-a1c8-227f0e6989dc",
        "name": "elastic-agent-89667",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.apt",
        "namespace": "24024",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cf4d8f48-a3a0-4e2b-a1c8-227f0e6989dc",
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
        "created": "2025-10-07T05:22:55.697Z",
        "dataset": "ti_eset.apt",
        "ingested": "2025-10-07T05:22:56Z",
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
        "ephemeral_id": "bea850c5-7b99-4fe0-b62a-70e8f816f892",
        "id": "75de7f03-46a5-4fc6-88cb-6ec688bc8813",
        "name": "elastic-agent-97208",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.botnet",
        "namespace": "21530",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "75de7f03-46a5-4fc6-88cb-6ec688bc8813",
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
        "created": "2025-10-07T05:23:54.209Z",
        "dataset": "ti_eset.botnet",
        "ingested": "2025-10-07T05:23:57Z",
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
        "ephemeral_id": "b3edd383-6fe5-42f1-98e5-e36a924959ba",
        "id": "c5567d77-e4ac-453b-b1d3-aa2ea2cf9dfb",
        "name": "elastic-agent-90683",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.cc",
        "namespace": "30355",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c5567d77-e4ac-453b-b1d3-aa2ea2cf9dfb",
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
        "created": "2025-10-07T05:24:54.170Z",
        "dataset": "ti_eset.cc",
        "ingested": "2025-10-07T05:24:57Z",
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


An example event for `cryptoscam` looks as following:

```json
{
    "@timestamp": "2024-03-18T13:25:08.000Z",
    "agent": {
        "ephemeral_id": "cd028512-63c3-4f2e-8fc6-4553ba42c3a4",
        "id": "a1bcbb93-9d50-407c-841c-63740140025d",
        "name": "elastic-agent-37717",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.cryptoscam",
        "namespace": "83435",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a1bcbb93-9d50-407c-841c-63740140025d",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--5d8275cd-993e-4ba1-87a3-251e8e072894",
        "labels": [
            "unwanted-activity"
        ],
        "valid_until": "2024-03-20T13:25:08.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:39:21.169Z",
        "dataset": "ti_eset.cryptoscam",
        "ingested": "2025-10-27T18:39:24Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2024-03-18T13:25:08.000Z\",\"description\":\"Host is known source of active fraudulent content.\",\"id\":\"indicator--5d8275cd-993e-4ba1-87a3-251e8e072894\",\"labels\":[\"unwanted-activity\"],\"modified\":\"2024-03-18T13:25:08.000Z\",\"name\":\"Unwanted\",\"pattern\":\"[url:value='http://future-exchange.net']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-03-18T13:25:08Z\",\"valid_until\":\"2024-03-20T13:25:08Z\"}",
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
        "ephemeral_id": "73444b7b-a480-4ea7-b838-e041791c2cd8",
        "id": "32093ab2-602b-4282-ab43-c353c6ca2de4",
        "name": "elastic-agent-56675",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.domains",
        "namespace": "76832",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "32093ab2-602b-4282-ab43-c353c6ca2de4",
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
        "created": "2025-10-07T05:25:53.540Z",
        "dataset": "ti_eset.domains",
        "ingested": "2025-10-07T05:25:56Z",
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


An example event for `emailattachments` looks as following:

```json
{
    "@timestamp": "2024-03-18T14:15:42.000Z",
    "agent": {
        "ephemeral_id": "2630f00d-0b54-4dfe-b824-855585af7d97",
        "id": "09dc059d-7bdb-4df3-8f5b-84e3dedeb9cb",
        "name": "elastic-agent-79464",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.emailattachments",
        "namespace": "28212",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "09dc059d-7bdb-4df3-8f5b-84e3dedeb9cb",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--00c42f20-62d2-4cb6-be87-2c451aaec4a4",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2024-03-20T14:15:42.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:41:36.488Z",
        "dataset": "ti_eset.emailattachments",
        "ingested": "2025-10-27T18:41:39Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2024-03-18T14:15:42.000Z\",\"description\":\"Each of these file hashes indicates that a variant of a variant of MSIL/Kryptik.ALDO trojan is present.\",\"id\":\"indicator--00c42f20-62d2-4cb6-be87-2c451aaec4a4\",\"labels\":[\"malicious-activity\"],\"modified\":\"2024-03-18T14:15:42.000Z\",\"name\":\"Malware variant\",\"pattern\":\"[file:hashes.'SHA-256'='a11a40ee211021d421a6f735715f0bae168aadada0a051c76c5b7e9f83fc0abb'] OR [file:hashes.'SHA-1'='9e8303d999889e32328f9ebcd0e17fdc6ecd8b2d'] OR [file:hashes.'MD5'='13442e50b95944a3c6aba42da0c9b1ad']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-03-18T14:15:42Z\",\"valid_until\":\"2024-03-20T14:15:42Z\"}",
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
        "ephemeral_id": "11ca0f0e-0d11-4dd3-b2d4-64f567328b32",
        "id": "d13f581e-ff6e-4b91-9ec0-41af4d9ec6dd",
        "name": "elastic-agent-44731",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.files",
        "namespace": "39976",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d13f581e-ff6e-4b91-9ec0-41af4d9ec6dd",
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
        "created": "2025-10-07T05:26:44.370Z",
        "dataset": "ti_eset.files",
        "ingested": "2025-10-07T05:26:47Z",
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
        "ephemeral_id": "3c72f0b8-ccdc-4db2-93bd-ace8c478a0a8",
        "id": "62646616-f5ca-4969-9058-a59df4d18be7",
        "name": "elastic-agent-58112",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.ip",
        "namespace": "34125",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "62646616-f5ca-4969-9058-a59df4d18be7",
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
        "created": "2025-10-07T05:27:33.661Z",
        "dataset": "ti_eset.ip",
        "ingested": "2025-10-07T05:27:36Z",
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


An example event for `phishingurl` looks as following:

```json
{
    "@timestamp": "2025-08-20T11:52:31.000Z",
    "agent": {
        "ephemeral_id": "b8516742-478a-4c42-93f8-c8c2ff71ffa1",
        "id": "9595bebb-459a-4ec8-9c38-2e502d11c9bf",
        "name": "elastic-agent-68565",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.phishingurl",
        "namespace": "33772",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9595bebb-459a-4ec8-9c38-2e502d11c9bf",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--f8bac022-878c-4c24-ab77-e275e04470b8",
        "labels": [
            "phishing-activity"
        ],
        "valid_until": "2025-08-22T11:52:31.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:45:03.852Z",
        "dataset": "ti_eset.phishingurl",
        "ingested": "2025-10-27T18:45:06Z",
        "kind": "enrichment",
        "original": "{\"confidence\":85,\"created\":\"2025-08-20T11:52:31.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Host is known source of phishing or other fraudulent content.\",\"id\":\"indicator--f8bac022-878c-4c24-ab77-e275e04470b8\",\"labels\":[\"phishing-activity\"],\"modified\":\"2025-08-20T11:52:31.000Z\",\"name\":\"Phishing\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[url:value = 'http://track-supportdhl.com']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-20T11:52:31Z\",\"valid_until\":\"2025-08-22T11:52:31Z\"}",
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


An example event for `puaadware` looks as following:

```json
{
    "@timestamp": "2025-03-04T18:10:25.000Z",
    "agent": {
        "ephemeral_id": "861cd1e3-a26e-4f91-8722-4eba390aef7a",
        "id": "78115c2b-726e-4158-88a3-2ba49ce42adb",
        "name": "elastic-agent-22374",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.puaadware",
        "namespace": "88418",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "78115c2b-726e-4158-88a3-2ba49ce42adb",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--f7c7d9f1-e31d-4c34-9d4b-c4d89b6b51ba",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2025-03-06T18:10:25.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:46:13.863Z",
        "dataset": "ti_eset.puaadware",
        "ingested": "2025-10-27T18:46:16Z",
        "kind": "enrichment",
        "original": "{\"confidence\":85,\"created\":\"2025-03-04T18:10:25.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Each of these file hashes indicates that a variant of a variant of Win32/Adware.OpenSUpdater.LC.gen application is present.\",\"id\":\"indicator--f7c7d9f1-e31d-4c34-9d4b-c4d89b6b51ba\",\"labels\":[\"malicious-activity\"],\"modified\":\"2025-03-04T18:10:25.000Z\",\"name\":\"Malware variant\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[file:hashes.'SHA-256' = 'ece8562d64dad4a1aa24d06be50db38caffeac428d49be9cc6ef6eabf9120a0b'] OR [file:hashes.'SHA-1' = '74ecd87132c2ed11b7ef822692cb5d6d88280e7e'] OR [file:hashes.'MD5' = 'eb9c9d6eb5398d0d223140f866ad769c']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-03-04T18:10:25Z\",\"valid_until\":\"2025-03-06T18:10:25Z\"}",
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


An example event for `puadualapps` looks as following:

```json
{
    "@timestamp": "2025-08-27T13:06:13.000Z",
    "agent": {
        "ephemeral_id": "c268e00a-43b2-46a3-a510-7994005dd74d",
        "id": "c0c56ad8-f025-4a6f-b5a3-f6c556f3abc9",
        "name": "elastic-agent-82114",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.puadualapps",
        "namespace": "78516",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c0c56ad8-f025-4a6f-b5a3-f6c556f3abc9",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--2d49ae92-fd09-4d78-a612-cab9cb2d3c95",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2025-08-29T13:06:13.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:47:12.871Z",
        "dataset": "ti_eset.puadualapps",
        "ingested": "2025-10-27T18:47:15Z",
        "kind": "enrichment",
        "original": "{\"confidence\":85,\"created\":\"2025-08-27T13:06:13.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Each of these file hashes indicates that a variant of Python/Riskware.Impacket.C application is present.\",\"id\":\"indicator--2d49ae92-fd09-4d78-a612-cab9cb2d3c95\",\"labels\":[\"malicious-activity\"],\"modified\":\"2025-08-27T13:06:13.000Z\",\"name\":\"Malware variant\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[file:hashes.'SHA-256' = '9dffb771cdfafeefe68972be28e705179bb19b73c114e6ec2155e8670cf82e99'] OR [file:hashes.'SHA-1' = 'e22d9493be1c4dbe57fa28ba9a11ecbad02d11aa'] OR [file:hashes.'MD5' = 'ae405a845a510ba4a6a19aca8cdf8252']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-27T13:06:13Z\",\"valid_until\":\"2025-08-29T13:06:13Z\"}",
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


An example event for `ransomware` looks as following:

```json
{
    "@timestamp": "2025-08-27T11:20:08.000Z",
    "agent": {
        "ephemeral_id": "0dcb045d-1c1a-4539-a191-024045538c5f",
        "id": "17966994-763f-4e87-b93c-36ff0b6f5b70",
        "name": "elastic-agent-14804",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.ransomware",
        "namespace": "35967",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "17966994-763f-4e87-b93c-36ff0b6f5b70",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--2a142f4d-8895-40ce-8c2b-0cc6961b8c1b",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2025-08-29T11:20:08.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:48:12.995Z",
        "dataset": "ti_eset.ransomware",
        "ingested": "2025-10-27T18:48:15Z",
        "kind": "enrichment",
        "original": "{\"confidence\":85,\"created\":\"2025-08-27T11:20:08.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"description\":\"Each of these file hashes indicates that a variant of a variant of Win32/Filecoder.DragonForce.A trojan is present.\",\"id\":\"indicator--2a142f4d-8895-40ce-8c2b-0cc6961b8c1b\",\"labels\":[\"malicious-activity\"],\"modified\":\"2025-08-27T11:20:08.000Z\",\"name\":\"Malware variant\",\"object_marking_refs\":[\"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82\"],\"pattern\":\"[file:hashes.'SHA-256' = 'df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403'] OR [file:hashes.'SHA-1' = '4a34bbad85312ef34b60818a47f7b5bb8e9a7e26'] OR [file:hashes.'MD5' = 'e84270afa3030b48dc9e0c53a35c65aa']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2025-08-27T11:20:08Z\",\"valid_until\":\"2025-08-29T11:20:08Z\"}",
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

### Scam URL

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
        "ephemeral_id": "3c72f0b8-ccdc-4db2-93bd-ace8c478a0a8",
        "id": "62646616-f5ca-4969-9058-a59df4d18be7",
        "name": "elastic-agent-58112",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.ip",
        "namespace": "34125",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "62646616-f5ca-4969-9058-a59df4d18be7",
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
        "created": "2025-10-07T05:27:33.661Z",
        "dataset": "ti_eset.ip",
        "ingested": "2025-10-07T05:27:36Z",
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

### SMS phishing

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


An example event for `smishing` looks as following:

```json
{
    "@timestamp": "2024-03-18T22:35:07.000Z",
    "agent": {
        "ephemeral_id": "df9eee6c-7ea9-40de-948f-66176bb6e235",
        "id": "a328abbb-99b1-4e8d-bc96-2af05380b79a",
        "name": "elastic-agent-42825",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.smishing",
        "namespace": "40685",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a328abbb-99b1-4e8d-bc96-2af05380b79a",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--056018a4-f5b5-49f5-a2a2-9df6b8160d0b",
        "labels": [
            "phishing-activity"
        ],
        "valid_until": "2024-03-20T22:35:07.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:50:24.174Z",
        "dataset": "ti_eset.smishing",
        "ingested": "2025-10-27T18:50:27Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2024-03-18T22:35:07.000Z\",\"description\":\"Host is known source of phishing or other fraudulent content.\",\"id\":\"indicator--056018a4-f5b5-49f5-a2a2-9df6b8160d0b\",\"labels\":[\"phishing-activity\"],\"modified\":\"2024-03-18T22:35:07.000Z\",\"name\":\"Phishing\",\"pattern\":\"[url:value='gb-nuhuty.top']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-03-18T22:35:07Z\",\"valid_until\":\"2024-03-20T22:35:07Z\"}",
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

### SMS scam

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


An example event for `smsscam` looks as following:

```json
{
    "@timestamp": "2024-03-19T15:20:09.000Z",
    "agent": {
        "ephemeral_id": "57b93b19-4feb-4427-9f3f-bb9c0021f763",
        "id": "53fb8d30-f2d3-4395-940d-3d1fc7583b42",
        "name": "elastic-agent-84010",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.smsscam",
        "namespace": "79943",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "53fb8d30-f2d3-4395-940d-3d1fc7583b42",
        "snapshot": false,
        "version": "8.19.4"
    },
    "eset": {
        "id": "indicator--9da47616-6288-475e-99e2-6827e77a7c17",
        "labels": [
            "unwanted-activity"
        ],
        "valid_until": "2024-03-21T15:20:09.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-27T18:51:33.150Z",
        "dataset": "ti_eset.smsscam",
        "ingested": "2025-10-27T18:51:36Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2024-03-19T15:20:09.000Z\",\"description\":\"Host is known source of active fraudulent content.\",\"id\":\"indicator--9da47616-6288-475e-99e2-6827e77a7c17\",\"labels\":[\"unwanted-activity\"],\"modified\":\"2024-03-19T15:20:09.000Z\",\"name\":\"Unwanted\",\"pattern\":\"[url:value='www.candycasino79.com']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2024-03-19T15:20:09Z\",\"valid_until\":\"2024-03-21T15:20:09Z\"}",
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
        "ephemeral_id": "5c8679f1-6925-42cb-8688-444f99a1bba1",
        "id": "73974f2f-fe42-40a5-a461-3d277a6d1dcf",
        "name": "elastic-agent-87584",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_eset.url",
        "namespace": "85559",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "73974f2f-fe42-40a5-a461-3d277a6d1dcf",
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
        "created": "2025-10-07T05:28:22.084Z",
        "dataset": "ti_eset.url",
        "ingested": "2025-10-07T05:28:25Z",
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
