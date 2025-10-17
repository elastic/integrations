# ESET Threat Intelligence Integration

This integration connects with the [ESET Threat Intelligence](https://eti.eset.com/taxii2/) TAXII version 2 server.
It includes the following datasets for retrieving logs:

| Dataset | TAXII2 Collection name |
|--------:|:-----------------------|
|     apt | apt stix 2.1           |
|  botnet | botnet stix 2.1        |
|      cc | botnet.cc stix 2.1     |
| domains | domain stix 2.1        |
|   files | file stix 2.1          |
|      ip | ip stix 2.1            |
|     url | url stix 2.1           |

## Expiration of Indicators of Compromise (IOCs)

The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_eset_latest.dest_*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_eset_latest.<feed name>`.

| Source Datastream        | Destination Index Pattern          | Destination Alias           |
|:-------------------------|:-----------------------------------|-----------------------------|
| `logs-ti_eset.apt-*`     | logs-ti_eset_latest.dest_apt-*     | logs-ti_eset_latest.apt     |
| `logs-ti_eset.botnet-*`  | logs-ti_eset_latest.dest_botnet-*  | logs-ti_eset_latest.botnet  |
| `logs-ti_eset.cc-*`      | logs-ti_eset_latest.dest_cc-*      | logs-ti_eset_latest.cc      |
| `logs-ti_eset.domains-*` | logs-ti_eset_latest.dest_domains-* | logs-ti_eset_latest.domains |
| `logs-ti_eset.files-*`   | logs-ti_eset_latest.dest_files-*   | logs-ti_eset_latest.files   |
| `logs-ti_eset.ip-*`      | logs-ti_eset_latest.dest_ip-*      | logs-ti_eset_latest.ip      |
| `logs-ti_eset.url-*`     | logs-ti_eset_latest.dest_url-*     | logs-ti_eset_latest.url     |

### ILM Policy

ILM policy is added to the source indices, so it doesn't lead to unbounded growth.
Data in these source indices will be deleted after a certain number of days from ingested days:

|                  Index | Deleted after | Expired after |
|-----------------------:|:--------------|---------------|
|     `logs-ti_eset.apt` | 365d          | 365d          |
|  `logs-ti_eset.botnet` | 7d            | 48h           |
|      `logs-ti_eset.cc` | 7d            | 48h           |
| `logs-ti_eset.domains` | 7d            | 48h           |
|   `logs-ti_eset.files` | 7d            | 48h           |
|      `logs-ti_eset.ip` | 7d            | 48h           |
|     `logs-ti_eset.url` | 7d            | 48h           |

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