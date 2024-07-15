# Sophos Central Integration

The [Sophos Central](https://www.sophos.com/en-us/products/sophos-central) integration allows you to monitor Alerts and Events logs. Sophos Central is a cloud-native application with high availability. It is a cybersecurity management platform hosted on public cloud platforms. Each Sophos Central account is hosted in a named region. Sophos Central uses well-known, widely used, and industry-standard software libraries to mitigate common vulnerabilities.

Use the Sophos Central integration to collect logs across Sophos Central managed by your Sophos account.
Visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

## Data streams

The Sophos Central integration collects logs for two types of events: alerts and events.

**Alerts**: See Example Schema [here](https://developer.sophos.com/docs/siem-v1/1/routes/alerts/get) for more information.

**Events**: See Example Schema [here](https://developer.sophos.com/docs/siem-v1/1/routes/events/get) for more information.

## Compatibility

The Sophos Central Application does not feature version numbers. This integration has been configured and tested against **Sophos Central SIEM Integration API version v1**.

## Requirements

You need Elasticsearch for storing and searching your data, and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Elastic Integration for Sophos Central Settings

Follow this [link](https://developer.sophos.com/getting-started-tenant) to guide you through the process of generating authentication credentials for Sophos Central.

The Elastic Integration for Sophos Central requires the following Authentication Settings in order to connect to the Target service:
  - Client ID
  - Client Secret
  - Grant Type
  - Scope
  - Tenant ID
  - Token URL

**NOTE**: Sophos central supports logs only upto last 24 hrs.

## Logs reference

### Alerts

This is the `alerts` dataset.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2022-11-24T07:07:48.000Z",
    "agent": {
        "ephemeral_id": "f0294025-e37d-4210-bda4-eaf14642e17e",
        "id": "cf659b85-d5b7-4b0d-8b9a-4ea2e187d862",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "data_stream": {
        "dataset": "sophos_central.alert",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "192.168.0.2",
        "port": 789
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cf659b85-d5b7-4b0d-8b9a-4ea2e187d862",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "code": "Event::Endpoint::Threat::PuaCleanupFailed",
        "created": "2022-11-24T07:07:52.094Z",
        "dataset": "sophos_central.alert",
        "id": "8bbd989a-6cab-407f-a586-c5064b94f76a",
        "ingested": "2023-05-24T14:37:54Z",
        "kind": [
            "alert"
        ],
        "original": "{\"created_at\":\"2022-11-24T07:07:52.094Z\",\"customer_id\":\"d1271b33-4e24-4cc3-951a-badc38976ca3\",\"data\":{\"certificates\":[],\"core_remedy_items\":{\"items\":[{\"descriptor\":\"C:\\\\foo.dll\",\"processPath\":\"\",\"result\":\"SUCCESS\",\"sophosPid\":\"\",\"suspendResult\":\"NOT_APPLICABLE\",\"type\":\"file\"}],\"totalItems\":1},\"created_at\":1669273672085,\"endpoint_id\":\"0320820b-84b4-41ea-95fd-5893fb17e420\",\"endpoint_java_id\":\"0320820b-84b4-41ea-95fd-5893fb17e420\",\"endpoint_platform\":\"windows\",\"endpoint_type\":\"computer\",\"event_service_id\":{\"data\":\"ASctdeo4TVyAZU0SyIzlJg==\",\"type\":3},\"hmpa_exploit\":{\"family_id\":\"aecab125-0118-4828-a2bb-c0815aa5864d\",\"process_name\":\"Lightning:Notepad++\",\"process_path\":\"C:\\\\Windows\\\\Virus\",\"process_pid\":\"135510845\",\"process_version\":\"21.13.87\",\"thumbprint\":\"d99d375c1e190e6ccc77d22d51e8f9ed881bbb4af1342f618adf9f78358c6488\",\"type\":\"CryptoGuard\",\"uid\":\"344b9a0b-2271-0e14-0c61-0fa89122c6ad\",\"version\":\"2.13.7\"},\"inserted_at\":1669273672085,\"ips_threat\":{\"detection_type\":1,\"executable_name\":\"Bad Program\",\"executable_path\":\"C:\\\\Program Files\\\\Bad Vendor\\\\Bad Program.exe\",\"executable_pid\":\"2468\",\"executable_version\":\"7.6.5\",\"local_port\":\"123\",\"raw_data\":\"Message       OS-WINDOWS Microsoft Windows SMB remote code execution attempt\\nReference     CVE-2017-0146\\nPacket type   TCP\\nLocal IP:     192.168.0.3\\nLocal Port:   123\\nLocal MAC:    00:50:b6:90:9e:e3\\nRemote IP:    192.168.0.2\\nRemote Port:  789\\nRemote MAC:   00:1C:B3:09:85:15\\nPID:          2468\\nExecutable:   C:\\\\Program Files\\\\Bad Vendor\\\\Bad Program.exe\\nVersion:      7.6.5\\nSigner:       PositiveSSL CA 2\\nSHA-256:      19648CE85F07F4DEC80C4B37266C31A1025DAB5318DFF5C1AB1F65A7E7886B3C\",\"remote_ip\":\"192.168.0.2\",\"remote_port\":\"789\",\"tech_support_id\":\"2019052901.77863414.5\"},\"make_actionable_at\":1674533519751,\"policy_type\":30,\"source_app_id\":\"CORE\",\"source_info\":{\"ip\":\"10.1.39.32\"},\"threat_id\":{\"counter\":5044432,\"date\":1669273672000,\"machineIdentifier\":13006844,\"processIdentifier\":3865,\"time\":1669273672000,\"timeSecond\":1669273672,\"timestamp\":1669273672},\"threat_status\":\"NONE\",\"user_match_id\":{\"counter\":5199272,\"date\":1667463333000,\"machineIdentifier\":14271215,\"processIdentifier\":3997,\"time\":1667463333000,\"timeSecond\":1667463333,\"timestamp\":1667463333},\"user_match_uuid\":{\"data\":\"SltcnDmTSoSky+G00P5iTQ==\",\"type\":3}},\"description\":\"Manual PUA cleanup required: 'PUAqsw3kby31j' at 'C:\\\\Program Files (x86)\\\\Trojan Horse\\\\bin\\\\eicar.com'\",\"event_service_event_id\":\"8bbd989a-6cab-407f-a586-c5064b94f76a\",\"id\":\"8bbd989a-6cab-407f-a586-c5064b94f76a\",\"location\":\"Lightning-rvda5c291x\",\"severity\":\"medium\",\"source\":\"Domain\\\\User\",\"threat\":\"PUAqsw3kby31j\",\"threat_cleanable\":false,\"type\":\"Event::Endpoint::Threat::PuaCleanupFailed\",\"when\":\"2022-11-24T07:07:48.000Z\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "message": "Manual PUA cleanup required: 'PUAqsw3kby31j' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'",
    "organization": {
        "id": "d1271b33-4e24-4cc3-951a-badc38976ca3"
    },
    "process": {
        "executable": "Bad Program",
        "name": "Lightning:Notepad++",
        "pid": 135510845
    },
    "related": {
        "hash": [
            "19648CE85F07F4DEC80C4B37266C31A1025DAB5318DFF5C1AB1F65A7E7886B3C"
        ],
        "ip": [
            "10.1.39.32",
            "192.168.0.2"
        ]
    },
    "sophos_central": {
        "alert": {
            "created_at": "2022-11-24T07:07:52.094Z",
            "customer_id": "d1271b33-4e24-4cc3-951a-badc38976ca3",
            "data": {
                "core_remedy": {
                    "items": [
                        {
                            "descriptor": "C:\\foo.dll",
                            "result": "SUCCESS",
                            "suspend_result": "NOT_APPLICABLE",
                            "type": "file"
                        }
                    ],
                    "total_items": 1
                },
                "created_at": "2022-11-24T07:07:52.085Z",
                "endpoint": {
                    "id": "0320820b-84b4-41ea-95fd-5893fb17e420",
                    "java_id": "0320820b-84b4-41ea-95fd-5893fb17e420",
                    "platform": "windows",
                    "type": "computer"
                },
                "event_service_id": {
                    "data": "ASctdeo4TVyAZU0SyIzlJg==",
                    "type": 3
                },
                "hmpa_exploit": {
                    "family_id": "aecab125-0118-4828-a2bb-c0815aa5864d",
                    "process_name": "Lightning:Notepad++",
                    "process_path": "C:\\Windows\\Virus",
                    "process_pid": 135510845,
                    "process_version": "21.13.87",
                    "thumbprint": "d99d375c1e190e6ccc77d22d51e8f9ed881bbb4af1342f618adf9f78358c6488",
                    "type": "CryptoGuard",
                    "uid": "344b9a0b-2271-0e14-0c61-0fa89122c6ad",
                    "version": "2.13.7"
                },
                "inserted_at": "2022-11-24T07:07:52.085Z",
                "ips_threat": {
                    "detection_type": 1,
                    "executable": {
                        "name": "Bad Program",
                        "path": "C:\\Program Files\\Bad Vendor\\Bad Program.exe",
                        "pid": "2468",
                        "version": "7.6.5"
                    },
                    "local_port": 123,
                    "raw_data": {
                        "executable": "C:\\Program Files\\Bad Vendor\\Bad Program.exe",
                        "local": {
                            "ip": "192.168.0.3",
                            "mac": "00-50-B6-90-9E-E3",
                            "port": 123
                        },
                        "message": "OS-WINDOWS Microsoft Windows SMB remote code execution attempt",
                        "original": "Message       OS-WINDOWS Microsoft Windows SMB remote code execution attempt\nReference     CVE-2017-0146\nPacket type   TCP\nLocal IP:     192.168.0.3\nLocal Port:   123\nLocal MAC:    00:50:b6:90:9e:e3\nRemote IP:    192.168.0.2\nRemote Port:  789\nRemote MAC:   00:1C:B3:09:85:15\nPID:          2468\nExecutable:   C:\\Program Files\\Bad Vendor\\Bad Program.exe\nVersion:      7.6.5\nSigner:       PositiveSSL CA 2\nSHA-256:      19648CE85F07F4DEC80C4B37266C31A1025DAB5318DFF5C1AB1F65A7E7886B3C",
                        "packet_type": "TCP",
                        "pid": "2468",
                        "reference": "CVE-2017-0146",
                        "remote": {
                            "ip": "192.168.0.2",
                            "mac": "00-1C-B3-09-85-15",
                            "port": 789
                        },
                        "sha_256": "19648CE85F07F4DEC80C4B37266C31A1025DAB5318DFF5C1AB1F65A7E7886B3C",
                        "signer": "PositiveSSL CA 2",
                        "version": "7.6.5"
                    },
                    "remote": {
                        "ip": "192.168.0.2",
                        "port": 789
                    },
                    "tech_support_id": "2019052901.77863414.5"
                },
                "make_actionable_at": "2023-01-24T04:11:59.751Z",
                "policy_type": 30,
                "source_app_id": "CORE",
                "source_info_ip": "10.1.39.32",
                "threat_id": {
                    "counter": 5044432,
                    "date": "2022-11-24T07:07:52.000Z",
                    "machine_identifier": 13006844,
                    "process_identifier": 3865,
                    "time": "2022-11-24T07:07:52.000Z",
                    "time_sec": "2022-11-24T07:07:52.000Z",
                    "timestamp": "2022-11-24T07:07:52.000Z"
                },
                "threat_status": "NONE",
                "user_match_id": {
                    "counter": 5199272,
                    "date": "2022-11-03T08:15:33.000Z",
                    "machine_identifier": 14271215,
                    "process_identifier": 3997,
                    "time": "2022-11-03T08:15:33.000Z",
                    "time_sec": "2022-11-03T08:15:33.000Z",
                    "timestamp": "2022-11-03T08:15:33.000Z"
                },
                "user_match_uuid": {
                    "data": "SltcnDmTSoSky+G00P5iTQ==",
                    "type": 3
                }
            },
            "description": "Manual PUA cleanup required: 'PUAqsw3kby31j' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'",
            "event_service_event_id": "8bbd989a-6cab-407f-a586-c5064b94f76a",
            "id": "8bbd989a-6cab-407f-a586-c5064b94f76a",
            "location": "Lightning-rvda5c291x",
            "severity": "medium",
            "source": {
                "domain": {
                    "name": "Domain"
                },
                "original": "Domain\\User",
                "user": {
                    "name": "User"
                }
            },
            "threat": {
                "cleanable": false,
                "value": "PUAqsw3kby31j"
            },
            "type": "Event::Endpoint::Threat::PuaCleanupFailed",
            "when": "2022-11-24T07:07:48.000Z"
        }
    },
    "source": {
        "ip": "10.1.39.32"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "sophos_central-alert"
    ],
    "user": {
        "domain": "Domain",
        "name": "User"
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
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| sophos_central.alert.created_at | The date at which the alert was created. | date |
| sophos_central.alert.customer_id | The unique identifier of the customer linked with this record. | keyword |
| sophos_central.alert.data.app_id | App identifier. | keyword |
| sophos_central.alert.data.certificates | Certificates of alert. | keyword |
| sophos_central.alert.data.core_remedy.items.descriptor | Descriptor of items. | keyword |
| sophos_central.alert.data.core_remedy.items.process_path | Process path of sophos items. | keyword |
| sophos_central.alert.data.core_remedy.items.result | The following values are allowed: NOT_APPLICABLE, SUCCESS, NOT_FOUND, DELETED, FAILED_TO_DELETE, WHITELISTED, OTHER_ERROR, FAILED_TO_DELETE_SYSTEM_PROTECTED. | keyword |
| sophos_central.alert.data.core_remedy.items.sophos_pid | Process id of sophos items. | keyword |
| sophos_central.alert.data.core_remedy.items.suspend_result | Suspend result of sophos items. | keyword |
| sophos_central.alert.data.core_remedy.items.type | Type of core remedy items. | keyword |
| sophos_central.alert.data.core_remedy.total_items | Total core remedy items of alert. | long |
| sophos_central.alert.data.created_at | The timestamp at which the event/alert was received and inserted into the Central datastore. | date |
| sophos_central.alert.data.endpoint.id | Object_id of the device (endpoint); also used for correlation. | keyword |
| sophos_central.alert.data.endpoint.java_id | Identifier for endpoint. | keyword |
| sophos_central.alert.data.endpoint.platform | Endpoint platform of alert. | keyword |
| sophos_central.alert.data.endpoint.type | The type of endpoint - currently only computer or server. | keyword |
| sophos_central.alert.data.event_service_id.data | Service id of event data. | keyword |
| sophos_central.alert.data.event_service_id.type | Service id of event type. | long |
| sophos_central.alert.data.hmpa_exploit.family_id | Family id of hmpa exploit. | keyword |
| sophos_central.alert.data.hmpa_exploit.process_name | Process name of hmpa exploit. | keyword |
| sophos_central.alert.data.hmpa_exploit.process_path | Process path of hmpa exploit. | keyword |
| sophos_central.alert.data.hmpa_exploit.process_pid | Process Parent ID of hmpa exploit. | long |
| sophos_central.alert.data.hmpa_exploit.process_version | Process version of hmpa exploit. | keyword |
| sophos_central.alert.data.hmpa_exploit.thumbprint | Thumbprint of hmpa exploit. | keyword |
| sophos_central.alert.data.hmpa_exploit.type | Type of hmpa exploit. | keyword |
| sophos_central.alert.data.hmpa_exploit.uid | Uid of hmpa exploit. | keyword |
| sophos_central.alert.data.hmpa_exploit.version | Version of hmpa exploits. | keyword |
| sophos_central.alert.data.inserted_at | When the event was inserted into the Central datastore. | date |
| sophos_central.alert.data.ips_threat.detection_type | Detection type of ips threat. | long |
| sophos_central.alert.data.ips_threat.executable.name | Executable name of ips threat. | keyword |
| sophos_central.alert.data.ips_threat.executable.path | Executable path of ips threat. | keyword |
| sophos_central.alert.data.ips_threat.executable.pid | Executable process id of ips threat. | keyword |
| sophos_central.alert.data.ips_threat.executable.version | Executable version of ips threat. | keyword |
| sophos_central.alert.data.ips_threat.local_port | Local port of ips threat. | long |
| sophos_central.alert.data.ips_threat.raw_data.executable | Executable raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.local.ip | local ip in raw data of IPS threat. | ip |
| sophos_central.alert.data.ips_threat.raw_data.local.mac | local mac in raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.local.port | local port in raw data of IPS threat. | long |
| sophos_central.alert.data.ips_threat.raw_data.message | Original raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.original | Original raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.packet_type | Packet type in raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.pid | PID raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.reference | Original raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.remote.ip | Remote IP in raw data of IPS threat. | ip |
| sophos_central.alert.data.ips_threat.raw_data.remote.mac | remote mac in raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.remote.port | remote port in raw data of IPS threat. | long |
| sophos_central.alert.data.ips_threat.raw_data.sha_256 | sha 256 code of raw data. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.signer | signer raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.raw_data.version | Version raw data of IPS threat. | keyword |
| sophos_central.alert.data.ips_threat.remote.ip | Remote ip from which ips threat occured. | ip |
| sophos_central.alert.data.ips_threat.remote.port | Remote port of ips threat. | long |
| sophos_central.alert.data.ips_threat.tech_support_id | IPS tech support id. | keyword |
| sophos_central.alert.data.make_actionable_at | Action make date. | date |
| sophos_central.alert.data.policy_type | Alert policy type. | long |
| sophos_central.alert.data.source_app_id | Source App id. | keyword |
| sophos_central.alert.data.source_info_ip | This shows the IPv4 address of an endpoint. If there are multiple IP addresses, this will show the first ip reported. | ip |
| sophos_central.alert.data.threat_id.counter | Counter of threat. | long |
| sophos_central.alert.data.threat_id.date | Date of threat. | date |
| sophos_central.alert.data.threat_id.machine_identifier | Machine identifier of threat. | long |
| sophos_central.alert.data.threat_id.process_identifier | Process identifier of threat. | long |
| sophos_central.alert.data.threat_id.time | Time of threat. | date |
| sophos_central.alert.data.threat_id.time_sec | Second at which threat occured. | date |
| sophos_central.alert.data.threat_id.timestamp | Time at which threat id of data was created. | date |
| sophos_central.alert.data.threat_status | Status of threat. | keyword |
| sophos_central.alert.data.user_match_id.counter | Counter of user. | long |
| sophos_central.alert.data.user_match_id.date | Date of user match. | date |
| sophos_central.alert.data.user_match_id.machine_identifier | Machine identifier of user. | long |
| sophos_central.alert.data.user_match_id.process_identifier | Process identifier of user. | long |
| sophos_central.alert.data.user_match_id.time | Time of user match. | date |
| sophos_central.alert.data.user_match_id.time_sec | Second at which user matched. | date |
| sophos_central.alert.data.user_match_id.timestamp | Time at which user match id of data was created. | date |
| sophos_central.alert.data.user_match_uuid.data | UUID of user matched data. | keyword |
| sophos_central.alert.data.user_match_uuid.type | UUID of user matched type. | long |
| sophos_central.alert.description | The description of the alert that was generated. | keyword |
| sophos_central.alert.event_service_event_id | Unique identifier of the event. | keyword |
| sophos_central.alert.id | Unique identifier of the event. | keyword |
| sophos_central.alert.location | Location of alert. | keyword |
| sophos_central.alert.severity | The severity of the threat reported by the event; possible values are: None, Low, Medium, High, Critical. | keyword |
| sophos_central.alert.source.domain.name | Domain name of source. | keyword |
| sophos_central.alert.source.original | Describes the source from alert was generated. | keyword |
| sophos_central.alert.source.user.name | Username of source. | keyword |
| sophos_central.alert.threat.cleanable | Indicate if the threat can be cleaned automatically: True or False. | boolean |
| sophos_central.alert.threat.value | Name of the threat (as identified by threat_id). | keyword |
| sophos_central.alert.type | Event type. | keyword |
| sophos_central.alert.when | The date at which the alert was created. | date |


### Events

This is the `events` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2022-12-06T12:27:28.094Z",
    "agent": {
        "ephemeral_id": "5347e925-6d9e-4a32-bda5-1785fd44709f",
        "id": "cf659b85-d5b7-4b0d-8b9a-4ea2e187d862",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "data_stream": {
        "dataset": "sophos_central.event",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "81.2.69.192",
        "port": 789
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cf659b85-d5b7-4b0d-8b9a-4ea2e187d862",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "action": "Malicious inbound network traffic blocked from remote computer at 192.168.0.2 (Technical Support reference: 2019052901.77863414.5)",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2022-12-06T12:27:31.310Z",
        "dataset": "sophos_central.event",
        "id": "3dab71db-32c9-426a-8616-1e0fd5c9aab9",
        "ingested": "2023-05-24T14:38:29Z",
        "kind": [
            "event"
        ],
        "original": "{\"created_at\":\"2022-12-06T12:27:31.310Z\",\"customer_id\":\"d1271b33-4e24-4cc3-951a-badc38976ca3\",\"endpoint_id\":\"fb11564b-2882-44ea-ac64-d1bfb041ab49\",\"endpoint_type\":\"computer\",\"group\":\"RUNTIME_DETECTIONS\",\"id\":\"3dab71db-32c9-426a-8616-1e0fd5c9aab9\",\"ips_threat_data\":{\"detectionType\":0,\"executableName\":\"\",\"localPort\":\"123\",\"rawData\":\"Message       OS-WINDOWS Microsoft Windows SMB remote code execution attempt\\nReference     CVE-2017-0146\\nPacket type   TCP\\nLocal IP:     81.2.69.192\\nLocal Port:   123\\nLocal MAC:    00:50:56:81:62:41\\nRemote IP:    81.2.69.192\\nRemote Port:  789\\nRemote MAC:   00:1C:B3:09:85:15\",\"remoteIp\":\"81.2.69.192\",\"remotePort\":\"789\",\"techSupportId\":\"2019052901.77863414.5\"},\"location\":\"Lightning-4naq56bx4j\",\"name\":\"Malicious inbound network traffic blocked from remote computer at 192.168.0.2 (Technical Support reference: 2019052901.77863414.5)\",\"severity\":\"low\",\"source\":\"Lightning-a3i691l7cv\\\\Lightning\",\"source_info\":{\"ip\":\"81.2.69.192\"},\"threat\":\"IPS/Inbound/7777001\",\"type\":\"Event::Endpoint::Threat::IpsInboundDetection\",\"user_id\":\"638f34e1e5d0a20f3d40cf93\",\"when\":\"2022-12-06T12:27:28.094Z\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "d1271b33-4e24-4cc3-951a-badc38976ca3"
    },
    "related": {
        "ip": [
            "81.2.69.192"
        ]
    },
    "sophos_central": {
        "event": {
            "created_at": "2022-12-06T12:27:31.310Z",
            "customer_id": "d1271b33-4e24-4cc3-951a-badc38976ca3",
            "endpoint": {
                "id": "fb11564b-2882-44ea-ac64-d1bfb041ab49",
                "type": "computer"
            },
            "group": "RUNTIME_DETECTIONS",
            "id": "3dab71db-32c9-426a-8616-1e0fd5c9aab9",
            "ips_threat_data": {
                "detection_type": 0,
                "local_port": 123,
                "raw_data": {
                    "local": {
                        "ip": "81.2.69.192",
                        "mac": "00-50-56-81-62-41",
                        "port": 123
                    },
                    "message": "OS-WINDOWS Microsoft Windows SMB remote code execution attempt",
                    "original": "Message       OS-WINDOWS Microsoft Windows SMB remote code execution attempt\nReference     CVE-2017-0146\nPacket type   TCP\nLocal IP:     81.2.69.192\nLocal Port:   123\nLocal MAC:    00:50:56:81:62:41\nRemote IP:    81.2.69.192\nRemote Port:  789\nRemote MAC:   00:1C:B3:09:85:15",
                    "packet_type": "TCP",
                    "reference": "CVE-2017-0146",
                    "remote": {
                        "ip": "81.2.69.192",
                        "mac": "00-1C-B3-09-85-15",
                        "port": 789
                    }
                },
                "remote": {
                    "ip": "81.2.69.192",
                    "port": 789
                },
                "tech_support_id": "2019052901.77863414.5"
            },
            "location": "Lightning-4naq56bx4j",
            "name": "Malicious inbound network traffic blocked from remote computer at 192.168.0.2 (Technical Support reference: 2019052901.77863414.5)",
            "severity": "low",
            "source": {
                "domain": {
                    "name": "Lightning-a3i691l7cv"
                },
                "original": "Lightning-a3i691l7cv\\Lightning",
                "user": {
                    "name": "Lightning"
                }
            },
            "source_info": {
                "ip": "81.2.69.192"
            },
            "threat": "IPS/Inbound/7777001",
            "type": "Event::Endpoint::Threat::IpsInboundDetection",
            "user_id": "638f34e1e5d0a20f3d40cf93",
            "when": "2022-12-06T12:27:28.094Z"
        }
    },
    "source": {
        "ip": "81.2.69.192",
        "port": 123
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "sophos_central-event"
    ],
    "threat": {
        "feed": {
            "name": "IPS/Inbound/7777001"
        }
    },
    "user": {
        "domain": "Lightning-a3i691l7cv",
        "id": "638f34e1e5d0a20f3d40cf93",
        "name": "Lightning"
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
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| sophos_central.event.amsi_threat_data.parent_process.id | Parent process id of amsi_threat_data. | keyword |
| sophos_central.event.amsi_threat_data.parent_process.path | Parent process path of amsi_threat_data. | keyword |
| sophos_central.event.amsi_threat_data.process.id | Process ID of amsi_threat_data. | keyword |
| sophos_central.event.amsi_threat_data.process.name | Process name of amsi_threat_data. | keyword |
| sophos_central.event.amsi_threat_data.process.path | Process path of amsi_threat_data. | keyword |
| sophos_central.event.app_certs.signer | Certificate info of the singer with the threat, if available. | keyword |
| sophos_central.event.app_certs.thumbprint | Certificate info of the thumbprint with the threat, if available. | keyword |
| sophos_central.event.app_sha256 | SHA 256 hash of the application associated with the threat, if available. | keyword |
| sophos_central.event.core_remedy.items.descriptor | Descriptor of Core remedy items. | keyword |
| sophos_central.event.core_remedy.items.process_path | Process path of core remedy items. | keyword |
| sophos_central.event.core_remedy.items.result | The following values are allowed NOT_APPLICABLE, SUCCESS, NOT_FOUND, DELETED, FAILED_TO_DELETE, WHITELISTED, OTHER_ERROR, FAILED_TO_DELETE_SYSTEM_PROTECTED. | keyword |
| sophos_central.event.core_remedy.items.sophos_pid | Sophos process ID. | keyword |
| sophos_central.event.core_remedy.items.suspend_result | Suspend result of core remedy items. | keyword |
| sophos_central.event.core_remedy.items.type | Type of Core remedy items. | keyword |
| sophos_central.event.core_remedy.total_items | Total items of core remedy. | long |
| sophos_central.event.created_at | The date at which the event was created. | date |
| sophos_central.event.customer_id | The identifier of the customer for which record is created. | keyword |
| sophos_central.event.endpoint.id | The corresponding endpoint id associated with the record. | keyword |
| sophos_central.event.endpoint.type | The corresponding endpoint type associated with the record. | keyword |
| sophos_central.event.group | The group associated with the group. | keyword |
| sophos_central.event.id | The Identifier for the event. | keyword |
| sophos_central.event.ips_threat_data.detection_type | Detection type of IPS threat. | long |
| sophos_central.event.ips_threat_data.executable.name | Name of executable ips threat. | keyword |
| sophos_central.event.ips_threat_data.executable.path | Path of executable ips threat. | keyword |
| sophos_central.event.ips_threat_data.executable.pid | Process id of executable ips threat. | long |
| sophos_central.event.ips_threat_data.executable.version | Version of executable ips threat. | keyword |
| sophos_central.event.ips_threat_data.local_port | Local port of IPS threat. | long |
| sophos_central.event.ips_threat_data.raw_data.executable | Executable raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.local.ip | Local ip in raw data of IPS threat. | ip |
| sophos_central.event.ips_threat_data.raw_data.local.mac | Local mac in raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.local.port | Local port in raw data of IPS threat. | long |
| sophos_central.event.ips_threat_data.raw_data.message | Original raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.original | Original raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.packet_type | Packet type in raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.pid | PID raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.reference | Original raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.remote.ip | Remote IP in raw data of IPS threat. | ip |
| sophos_central.event.ips_threat_data.raw_data.remote.mac | Remote mac in raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.remote.port | Remote port in raw data of IPS threat. | long |
| sophos_central.event.ips_threat_data.raw_data.sha_256 | SHA 256 code of raw data. | keyword |
| sophos_central.event.ips_threat_data.raw_data.signer | Signer raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.raw_data.version | Version raw data of IPS threat. | keyword |
| sophos_central.event.ips_threat_data.remote.ip | Remote IP of IPS threat. | ip |
| sophos_central.event.ips_threat_data.remote.port | Remote Port of IPS threat. | long |
| sophos_central.event.ips_threat_data.tech_support_id | Tech support ID of IPS threat. | keyword |
| sophos_central.event.location | The location captured for this record. | keyword |
| sophos_central.event.name | The name of the record created. | keyword |
| sophos_central.event.origin | Originating component of a detection. | keyword |
| sophos_central.event.severity | The severity of the threat reported by the event; possible values are None (0), Low (1), Medium (2), High (3), Critical (4). | keyword |
| sophos_central.event.source.domain.name | Domain name of source. | keyword |
| sophos_central.event.source.original | Describes the source from alert was generated. | keyword |
| sophos_central.event.source.user.name | Username of source. | keyword |
| sophos_central.event.source_info.ip | Detailed source information for IP. | ip |
| sophos_central.event.threat | The threat associated with the record. | keyword |
| sophos_central.event.type | The type of this record. | keyword |
| sophos_central.event.user_id | The identifier of the user for which record is created. | keyword |
| sophos_central.event.when | The date at which the event was created. | date |
