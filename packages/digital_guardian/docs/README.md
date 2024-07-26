# Digital Guardian

This integration is for [Digital Guardian logs](https://www.digitalguardian.com/). 

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

This module has been tested against the **Digital Guardian API version v1**.


## To collect data from Digital Guardian ARC API, follow the below steps:

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Digital Guardian.
3. Click on the "Digital Guardian" integration from the search results.
4. Click on the "Add Digital Guardian" button to add the integration.
5. Configure all required integration parameters, including URL, Client ID, Client Secret, Scope, Token URL, Export Profile, to enable data collection for Digital Guardian ARC API.
6. Save the integration.

## Logs reference

### arc

This is the `arc` dataset.

#### Example

An example event for `arc` looks as following:

```json
{
    "@timestamp": "2024-07-04T12:08:18.143Z",
    "agent": {
        "ephemeral_id": "d12fe3a6-bd2e-4729-9303-bdbbc18f187e",
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "digital_guardian.arc",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7a8d18bc-b73c-424e-a30b-120ddeb66eeb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "completed",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "digital_guardian.arc",
        "duration": 454557000000,
        "ingested": "2024-07-04T12:08:30Z",
        "kind": "alert",
        "original": "{\"Classification\":{\"Category\":\"MALWARE_BOTNET\",\"DetectedMalware\":\"\",\"Max Score\":100,\"Score\":86,\"Type\":\"MALICIOUS\"},\"FileProperties\":{\"DigitalCerificate\":\"\",\"FileSize\":9810,\"FileType\":\"CMD\",\"Issuer\":\"\",\"MD5\":\"8350ded6d39df158e51d6cfbe36fb012\",\"RootCA\":\"\",\"SHA1\":\"f4dd1d176975c70ba8963ebc654a78a6e345cfb6\",\"SSDeep\":\"192:+cgNT7Zj4tvl2Drc+gEakjqBT1W431lXXH1TR8J:InZjevl2Drc+gEakmBT44rXVR8J\",\"Sha256\":\"aff2d40828597fbf482753bec73cc9fc2714484262258875cc23c7d5a7372cee\"},\"Summary\":{\"Analysis\":\"0\",\"Category\":\"SCRIPT\",\"Duration\":454557,\"FileType\":\"CMD\",\"StartTime\":1509567511,\"Status\":\"COMPLETED\",\"TimeUnit\":\"ms\",\"Url\":\"\"},\"SystemSummary\":{\"Risk\":\"LOW\",\"Signature\":\"Allocates memory within range which is reserved for system DLLs\",\"SignatureSources\":[\"\",\"76F90000 page execute and read and write\"]}}",
        "risk_score": 86,
        "start": "2017-11-01T20:18:31.000Z",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "md5": "8350ded6d39df158e51d6cfbe36fb012",
            "sha1": "f4dd1d176975c70ba8963ebc654a78a6e345cfb6",
            "sha256": "aff2d40828597fbf482753bec73cc9fc2714484262258875cc23c7d5a7372cee",
            "ssdeep": "192:+cgNT7Zj4tvl2Drc+gEakjqBT1W431lXXH1TR8J:InZjevl2Drc+gEakmBT44rXVR8J"
        },
        "size": 9810
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "8350ded6d39df158e51d6cfbe36fb012",
            "f4dd1d176975c70ba8963ebc654a78a6e345cfb6",
            "aff2d40828597fbf482753bec73cc9fc2714484262258875cc23c7d5a7372cee",
            "192:+cgNT7Zj4tvl2Drc+gEakjqBT1W431lXXH1TR8J:InZjevl2Drc+gEakmBT44rXVR8J"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "digital_guardian-arc"
    ],
    "threat": {
        "indicator": {
            "type": "file"
        }
    },
    "digital_guardian": {
        "arc": {
            "classification": {
                "category": "MALWARE_BOTNET",
                "max_score": 100,
                "score": 86,
                "type": "MALICIOUS"
            },
            "file_properties": {
                "file_size": 9810,
                "file_type": "CMD",
                "md5": "8350ded6d39df158e51d6cfbe36fb012",
                "sha1": "f4dd1d176975c70ba8963ebc654a78a6e345cfb6",
                "sha256": "aff2d40828597fbf482753bec73cc9fc2714484262258875cc23c7d5a7372cee",
                "ssdeep": "192:+cgNT7Zj4tvl2Drc+gEakjqBT1W431lXXH1TR8J:InZjevl2Drc+gEakmBT44rXVR8J"
            },
            "summary": {
                "analysis": "0",
                "category": "SCRIPT",
                "duration": 454557,
                "file": {
                    "type": "CMD"
                },
                "start_time": "2017-11-01T20:18:31.000Z",
                "status": "COMPLETED",
                "time_unit": "ms"
            },
            "system_summary": {
                "risk": "LOW",
                "signature": "Allocates memory within range which is reserved for system DLLs",
                "signature_sources": [
                    "76F90000 page execute and read and write"
                ]
            }
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
| digital_guardian.arc.dg_comment |  | keyword |
| digital_guardian.arc.dg_description |  | keyword |
| digital_guardian.arc.dg_guid |  | keyword |
| digital_guardian.arc.dg_name |  | keyword |
| digital_guardian.arc.dg_tenant |  | keyword |
| digital_guardian.arc.dg_utype |  | keyword |
| digital_guardian.arc.inc_assign |  | keyword |
| digital_guardian.arc.inc_creator |  | keyword |
| digital_guardian.arc.inc_id |  | keyword |
| digital_guardian.arc.inc_mtime |  | date |
| digital_guardian.arc.inc_sev |  | keyword |
| digital_guardian.arc.inc_state |  | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |

