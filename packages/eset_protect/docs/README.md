# ESET PROTECT

ESET PROTECT enables you to manage ESET products on workstations and servers in a networked environment with up to 50,000 devices from one central location. Using the ESET PROTECT Web Console, you can deploy ESET solutions, manage tasks, enforce security policies, monitor system status, and quickly respond to problems or threats on remote computers.

## Data streams

The ESET PROTECT integration collects three types of logs: Detection, Device Task and Event.

**[Detection](https://help.eset.com/protect_cloud/en-US/admin_ct.html?threats.html)** is used to retrieve detections via the [ESET Connect - Incident Management](https://eu.business-account.iam.eset.systems/swagger/?urls.primaryName=Incident%20Management).

**[Device Task](https://help.eset.com/protect_cloud/en-US/admin_ct.html?admin_ct.html)** is used to retrieve device tasks via the [ESET Connect - Automation](https://eu.business-account.iam.eset.systems/swagger/?urls.primaryName=Automation).

**Event** is used to retrieve Detection, Firewall, HIPS, Audit, and ESET Inspect logs using the [Syslog Server](https://help.eset.com/protect_cloud/en-US/events-exported-to-json-format.html?admin_server_settings_export_to_syslog.html).

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

The minimum **Kibana version** required is **8.12.0**.
This module has been tested against the **ESET PROTECT (version: 5.0.9.1)**.

## Setup

### To collect data from ESET Connect, follow the below steps:

1. [Create API User Account](https://help.eset.com/eset_connect/en-US/use_api_with_swagger.html?create_api_user_account.html)
2. Retrieve the username and password generated during the creation of an API user account.
3. Retrieve the region from the ESET Web Console URL.

### To collect data from ESET PROTECT via Syslog, follow the below steps:

1. Follow the steps to [configure syslog server](https://help.eset.com/protect_cloud/en-US/admin_server_settings_export_to_syslog.html?admin_server_settings_syslog.html).
   - Set the format of the payload to **JSON**.
   - Set the format of the envelope to **Syslog**.
   - Set the minimal log level to **Information** to collect all data.
   - Select all checkboxes to collect logs for all event types.
   - Enter the **IP Address** or **FQDN** of the Elastic Agent that is running the integration in the Destination IP field.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type ESET PROTECT
3. Click on the "ESET PROTECT" integration from the search results.
4. Click on the "Add ESET PROTECT" button to add the integration.
5. Configure all required integration parameters, including username, password, and region, to enable data collection from the ESET Connect REST API. For syslog data collection, provide parameters such as listen address, listen port, and SSL settings.
6. Save the integration.

## Logs Reference

### Detection

This is the `Detection` dataset.

#### Example

An example event for `detection` looks as following:

```json
{
    "@timestamp": "2023-10-26T13:36:53.000Z",
    "agent": {
        "ephemeral_id": "a2da59f5-382d-41e2-be5e-0b06df998911",
        "id": "930b36c5-0fd6-41c4-83bc-d8547e3fa880",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "eset_protect.detection",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.112",
        "port": 443
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "930b36c5-0fd6-41c4-83bc-d8547e3fa880",
        "snapshot": false,
        "version": "8.12.0"
    },
    "eset_protect": {
        "detection": {
            "category": "DETECTION_CATEGORY_NETWORK_INTRUSION",
            "context": {
                "circumstances": "Eicar",
                "device_uuid": "xxx-xxxx-1234-5678-xxxxxxxxxxxx",
                "process": {
                    "path": "C:\\Windows\\chrome.exe"
                },
                "user_name": "testingpc\\example"
            },
            "network_communication": {
                "protocol_name": "0",
                "remote": {
                    "ip_address": "89.160.20.112",
                    "port": 443
                }
            },
            "object_hash_sha1": "AAF4C61DDCC5E8A2DABEDE0F3B4820123456789D",
            "object_type_name": "File",
            "object_url": "C:\\Temp\\06516f11-xxxx-xxxx-xxxx-37da66b5de99_ccf7464ba6e2e12e984514f694bfb10d03de77358d8a3afd7a2ffed150ec1df8.zip.e99\\ccf7464ba6e2e12e984514f694bfb10d03de77358d8a3afd7a2ffed150ec1df8",
            "occur_time": "2023-10-26T13:36:53.000Z",
            "severity_level": "SEVERITY_LEVEL_MEDIUM",
            "type_name": "TCP Port scanning attack",
            "uuid": "xxx-xxxx-xxxx-1234-xxxxxxxxxxxx"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection"
        ],
        "dataset": "eset_protect.detection",
        "ingested": "2024-04-16T05:41:07Z",
        "kind": "alert",
        "original": "{\"category\":\"DETECTION_CATEGORY_NETWORK_INTRUSION\",\"context\":{\"circumstances\":\"Eicar\",\"deviceUuid\":\"xxx-xxxx-1234-5678-xxxxxxxxxxxx\",\"process\":{\"path\":\"C:\\\\Windows\\\\chrome.exe\"},\"userName\":\"testingpc\\\\example\"},\"networkCommunication\":{\"protocolName\":\"0\",\"remoteIpAddress\":\"89.160.20.112\",\"remotePort\":443},\"objectHashSha1\":\"AAF4C61DDCC5E8A2DABEDE0F3B4820123456789D\",\"objectTypeName\":\"File\",\"objectUrl\":\"C:\\\\Temp\\\\06516f11-xxxx-xxxx-xxxx-37da66b5de99_ccf7464ba6e2e12e984514f694bfb10d03de77358d8a3afd7a2ffed150ec1df8.zip.e99\\\\ccf7464ba6e2e12e984514f694bfb10d03de77358d8a3afd7a2ffed150ec1df8\",\"occurTime\":\"2023-10-26T13:36:53Z\",\"responses\":[{}],\"severityLevel\":\"SEVERITY_LEVEL_MEDIUM\",\"typeName\":\"TCP Port scanning attack\",\"uuid\":\"xxx-xxxx-xxxx-1234-xxxxxxxxxxxx\"}",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "sha1": "aaf4c61ddcc5e8a2dabede0f3b4820123456789d"
        }
    },
    "host": {
        "id": "xxx-xxxx-1234-5678-xxxxxxxxxxxx"
    },
    "input": {
        "type": "cel"
    },
    "message": "Eicar",
    "observer": {
        "product": "ESET PROTECT",
        "type": "ids",
        "vendor": "ESET"
    },
    "process": {
        "executable": "C:\\Windows\\chrome.exe",
        "name": "chrome.exe"
    },
    "related": {
        "hash": [
            "aaf4c61ddcc5e8a2dabede0f3b4820123456789d"
        ],
        "hosts": [
            "xxx-xxxx-1234-5678-xxxxxxxxxxxx"
        ],
        "ip": [
            "89.160.20.112"
        ],
        "user": [
            "example"
        ]
    },
    "rule": {
        "category": "DETECTION_CATEGORY_NETWORK_INTRUSION"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "eset_protect-detection"
    ],
    "threat": {
        "technique": {
            "name": [
                "TCP Port scanning attack"
            ]
        }
    },
    "user": {
        "domain": "testingpc",
        "name": "example"
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
| eset_protect.detection.category | Category of detection. | keyword |
| eset_protect.detection.context.circumstances | Human-friendly description of [detection]'s circumstances. | keyword |
| eset_protect.detection.context.device_uuid | Reference to [device]. | keyword |
| eset_protect.detection.context.process.path | Disk path to the executable. | keyword |
| eset_protect.detection.context.user_name | User name in whose context detection occurred. | keyword |
| eset_protect.detection.display_name | Human-friendly name of the detection. This value can be used to look up details at http://www.virusradar.com/en/threat_encyclopedia. | keyword |
| eset_protect.detection.network_communication.direction | Direction of network communication. | keyword |
| eset_protect.detection.network_communication.local.ip_address | IPv4 or IPv6 address of the device (i.e. the device where detection occurred). | ip |
| eset_protect.detection.network_communication.local.port | TCP or UDP port on the device (i.e. the device where detection occurred). | long |
| eset_protect.detection.network_communication.protocol_name | Human readable name of the protocol used to communicate between local and remote hosts. | keyword |
| eset_protect.detection.network_communication.remote.ip_address | IPv4 or IPv6 address of the remote host (i.e. not the device where detection occurred). | ip |
| eset_protect.detection.network_communication.remote.port | TCP or UDP port on the remote host (i.e. not the device where detection occurred). | long |
| eset_protect.detection.object_hash_sha1 | SHA1 hash of content of scanned object. | keyword |
| eset_protect.detection.object_name | Name/path of scanned object. | keyword |
| eset_protect.detection.object_type_name | Human-friendly type name of scanned object. | keyword |
| eset_protect.detection.object_url | URL (uniform resource locator) of scanned object. | keyword |
| eset_protect.detection.occur_time | Timestamp of detection occurrence. | date |
| eset_protect.detection.responses.description | Human-readable description of the response. | keyword |
| eset_protect.detection.responses.device_restart_required | Response needs restart of the device to be completed. | boolean |
| eset_protect.detection.responses.display_name | Human-friendly name of the response. | keyword |
| eset_protect.detection.responses.protection_name | Human-readable name of the protection that performed the response. | keyword |
| eset_protect.detection.severity_level | Severity levels abstracted to cover all the possible GUIs. Vocabulary is leaving interpretation of severity level completely to API client. | keyword |
| eset_protect.detection.type_name | Human-friendly type of detection. | keyword |
| eset_protect.detection.uuid | Universally Unique Identifier of detection. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |


### Device Task

This is the `Device Task` dataset.

#### Example

An example event for `device_task` looks as following:

```json
{
    "@timestamp": "2024-04-16T05:41:49.641Z",
    "agent": {
        "ephemeral_id": "a2da59f5-382d-41e2-be5e-0b06df998911",
        "id": "930b36c5-0fd6-41c4-83bc-d8547e3fa880",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "eset_protect.device_task",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "930b36c5-0fd6-41c4-83bc-d8547e3fa880",
        "snapshot": false,
        "version": "8.12.0"
    },
    "eset_protect": {
        "device_task": {
            "action": {
                "name": "Shutdown computer",
                "params": {
                    "@type": "type.googleapis.com/Era.Common.DataDefinition.Task.ESS.OnDemandScan",
                    "cleaning_enabled": true,
                    "custom_profile_name": "DefaultProfile",
                    "scan_profile": "InDepth",
                    "scan_targets": [
                        "eset://AllTargets"
                    ]
                }
            },
            "description": "Automatically created via context menu",
            "display_name": "Reboot Computer - via context menu",
            "targets": {
                "devices_uuids": [
                    "0205321e-XXXX-XXXX-1234-feeb35010ea7",
                    "0205321e-XXXX-XXXX-5678-feeb35010ea7",
                    "0205321e-XXXX-1234-5678-feeb35010ea7"
                ]
            },
            "triggers": [
                {
                    "manual": {
                        "expire_time": "2023-12-01T01:30:00.000Z"
                    }
                }
            ],
            "uuid": "c93070e0-XXXX-1234-5678-c48f0e5e0b7e",
            "version_id": "1511"
        }
    },
    "event": {
        "action": "Shutdown computer",
        "agent_id_status": "verified",
        "dataset": "eset_protect.device_task",
        "ingested": "2024-04-16T05:41:59Z",
        "kind": "event",
        "original": "{\"action\":{\"name\":\"Shutdown computer\",\"params\":{\"@type\":\"type.googleapis.com/Era.Common.DataDefinition.Task.ESS.OnDemandScan\",\"cleaningEnabled\":true,\"customProfileName\":\"DefaultProfile\",\"scanProfile\":\"InDepth\",\"scanTargets\":[\"eset://AllTargets\"]}},\"description\":\"Automatically created via context menu\",\"displayName\":\"Reboot Computer - via context menu\",\"targets\":{\"devicesUuids\":[\"0205321e-XXXX-XXXX-1234-feeb35010ea7\",\"0205321e-XXXX-XXXX-5678-feeb35010ea7\",\"0205321e-XXXX-1234-5678-feeb35010ea7\"]},\"triggers\":[{\"manual\":{\"expireTime\":\"2023-12-01T01:30:00Z\"}}],\"uuid\":\"c93070e0-XXXX-1234-5678-c48f0e5e0b7e\",\"versionId\":\"1511\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": [
            "0205321e-XXXX-XXXX-1234-feeb35010ea7",
            "0205321e-XXXX-XXXX-5678-feeb35010ea7",
            "0205321e-XXXX-1234-5678-feeb35010ea7"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "0205321e-XXXX-XXXX-1234-feeb35010ea7",
            "0205321e-XXXX-XXXX-5678-feeb35010ea7",
            "0205321e-XXXX-1234-5678-feeb35010ea7"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "eset_protect-device_task"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eset_protect.device_task.action.name | Name of the function to execute. | keyword |
| eset_protect.device_task.action.params.@type | A URL/resource name that uniquely identifies the type of the serialized protocol buffer message. | keyword |
| eset_protect.device_task.action.params.actions.cancel_action |  | boolean |
| eset_protect.device_task.action.params.actions.postpone |  | keyword |
| eset_protect.device_task.action.params.cleaning_enabled |  | boolean |
| eset_protect.device_task.action.params.custom_profile_name |  | keyword |
| eset_protect.device_task.action.params.restart |  | boolean |
| eset_protect.device_task.action.params.scan_profile |  | keyword |
| eset_protect.device_task.action.params.scan_targets |  | keyword |
| eset_protect.device_task.description | User's description. | keyword |
| eset_protect.device_task.display_name | User friendly name of the task. | keyword |
| eset_protect.device_task.targets.device_groups_uuids | Task can be assigned to groups of devices. | keyword |
| eset_protect.device_task.targets.devices_uuids | Task can be assigned to individual devices, for example if task run failed on these devices. | keyword |
| eset_protect.device_task.triggers.manual.create_time | When the manual trigger has been created. Task can only be triggered after this time. | date |
| eset_protect.device_task.triggers.manual.expire_time | Task is not triggered after this time. | date |
| eset_protect.device_task.uuid | Universally Unique Identifier for device task. | keyword |
| eset_protect.device_task.version_id | Identifier of entity version. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |


### Event

This is the `Event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2021-06-21T03:56:20.000Z",
    "agent": {
        "ephemeral_id": "fe2f9827-1823-4a86-8826-b6789530f104",
        "id": "930b36c5-0fd6-41c4-83bc-d8547e3fa880",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "eset_protect.event",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.128"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "930b36c5-0fd6-41c4-83bc-d8547e3fa880",
        "snapshot": false,
        "version": "8.12.0"
    },
    "eset_protect": {
        "event": {
            "action_taken": "blocked",
            "group_description": "Lost & found static group",
            "group_name": "All/Lost & found",
            "hash": "ABCDAA625E6961037B8904E113FD0C232A7D0EDC",
            "hostname": "win-test",
            "ipv4": "192.168.30.30",
            "is_handled": false,
            "name": "An attempt to connect to URL",
            "object_uri": "https://test.com",
            "occured": "2021-06-21T03:56:20.000Z",
            "os_name": "Microsoft Windows 11 Pro",
            "processname": "C:\\Program Files\\Web browser\\brwser.exe",
            "rule_id": "Blocked by PUA blacklist",
            "scanner_id": "HTTP filter",
            "severity": "Warning",
            "source_uuid": "d9477661-8fa4-4144-b8d4-e37b983bcd69",
            "target_address": "89.160.20.128",
            "target_address_type": "IPv4",
            "type": "FilteredWebsites_Event",
            "username": "WIN-TEST\\Administrator"
        }
    },
    "event": {
        "action": "blocked",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "eset_protect.event",
        "ingested": "2024-04-16T05:42:56Z",
        "kind": "alert",
        "original": "{\"event_type\":\"FilteredWebsites_Event\",\"ipv4\":\"192.168.30.30\",\"hostname\":\"win-test\",\"group_name\":\"All/Lost & found\",\"os_name\":\"Microsoft Windows 11 Pro\",\"group_description\":\"Lost & found static group\",\"source_uuid\":\"d9477661-8fa4-4144-b8d4-e37b983bcd69\",\"occured\":\"21-Jun-2021 03:56:20\",\"severity\":\"Warning\",\"event\":\"An attempt to connect to URL\",\"target_address\":\"89.160.20.128\",\"target_address_type\":\"IPv4\",\"scanner_id\":\"HTTP filter\",\"action_taken\":\"blocked\",\"object_uri\":\"https://test.com\",\"hash\":\"ABCDAA625E6961037B8904E113FD0C232A7D0EDC\",\"username\":\"WIN-TEST\\\\Administrator\",\"processname\":\"C:\\\\Program Files\\\\Web browser\\\\brwser.exe\",\"rule_id\":\"Blocked by PUA blacklist\"}",
        "type": [
            "info"
        ]
    },
    "group": {
        "name": "All/Lost & found"
    },
    "host": {
        "hostname": "win-test",
        "id": "d9477661-8fa4-4144-b8d4-e37b983bcd69",
        "ip": [
            "192.168.30.30"
        ],
        "name": "win-test",
        "os": {
            "name": "Microsoft Windows 11 Pro"
        }
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.247.8:59824"
        },
        "syslog": {
            "appname": "ERAServer",
            "facility": {
                "code": 1,
                "name": "user-level"
            },
            "hostname": "co7",
            "priority": 15,
            "procid": "75",
            "severity": {
                "code": 7,
                "name": "Debug"
            }
        }
    },
    "message": "An attempt to connect to URL",
    "process": {
        "executable": "C:\\Program Files\\Web browser\\brwser.exe",
        "name": "brwser.exe"
    },
    "related": {
        "hash": [
            "abcdaa625e6961037b8904e113fd0c232a7d0edc"
        ],
        "hosts": [
            "win-test",
            "d9477661-8fa4-4144-b8d4-e37b983bcd69"
        ],
        "ip": [
            "192.168.30.30",
            "89.160.20.128"
        ],
        "user": [
            "Administrator"
        ]
    },
    "rule": {
        "name": "Blocked by PUA blacklist"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "eset_protect-event"
    ],
    "threat": {
        "indicator": {
            "provider": "ESET PROTECT"
        }
    },
    "user": {
        "domain": "WIN-TEST",
        "name": "Administrator"
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
| eset_protect.event.account | Name of the user account associated with the event. | keyword |
| eset_protect.event.action | Action taken. | keyword |
| eset_protect.event.action_error | Error message if the "action" was not successful. | keyword |
| eset_protect.event.action_taken | Action taken by the Endpoint. | keyword |
| eset_protect.event.aggregate_count | How many exact same messages were generated by the endpoint between two consecutive replications between ESET PROTECT Server and managing ESET Management Agent. | long |
| eset_protect.event.application | Application name associated with the event. | keyword |
| eset_protect.event.cause |  | keyword |
| eset_protect.event.circumstances | Short description of what caused the event. | keyword |
| eset_protect.event.computer_severity_score | Computer severity score associated with the event. | long |
| eset_protect.event.count | Number of alerts of this type generated since last alarm. | long |
| eset_protect.event.description | Description of the blocked file. | keyword |
| eset_protect.event.detail | Detailed description of the action. | keyword |
| eset_protect.event.domain | Audit log domain. | keyword |
| eset_protect.event.eialarmid | ID sub-part of the alarm link ($1 in ^http.\*/alarm/([0-9]+)$). | keyword |
| eset_protect.event.eiconsolelink | Link to the alarm in ESET Inspect console. | keyword |
| eset_protect.event.engine_version | Version of the scanning engine. | keyword |
| eset_protect.event.firstseen | Time and date when the detection was found for the first time at that machine. | date |
| eset_protect.event.group_description | Description of the static group. | keyword |
| eset_protect.event.group_name | The full path to the static group of the computer generating the event. If the path is longer than 255 characters, group_name only contains the static group name. | keyword |
| eset_protect.event.handled | Indicates whether or not the detection was handled. | keyword |
| eset_protect.event.hash | SHA1 hash associated with the event. | keyword |
| eset_protect.event.hostname | Hostname of the computer generating the event. | keyword |
| eset_protect.event.inbound | Whether or not the connection was inbound. | boolean |
| eset_protect.event.ipv4 | IPv4 address of the computer generating the event. | ip |
| eset_protect.event.ipv6 | IPv6 address of the computer generating the event. | ip |
| eset_protect.event.is_handled | Indicates whether or not the detection was handled. | boolean |
| eset_protect.event.name | Event name. | keyword |
| eset_protect.event.need_restart | Whether or not the restart is needed. | boolean |
| eset_protect.event.object_type | Type of object related to this event. | keyword |
| eset_protect.event.object_uri | Object URI associated with the event. | keyword |
| eset_protect.event.occured | UTC time of occurrence of the event. Format is %d-%b-%Y %H:%M:%S. | date |
| eset_protect.event.operation | Operation associated with the event. | keyword |
| eset_protect.event.os_name | Information about the computer´s operating system. | keyword |
| eset_protect.event.processname | Name of the process associated with the event. | keyword |
| eset_protect.event.protocol | Protocol associated with the event. | keyword |
| eset_protect.event.result | Result of the action. | keyword |
| eset_protect.event.rule_id | Rule ID associated with the event. | keyword |
| eset_protect.event.rulename | Rule name associated with the event. | keyword |
| eset_protect.event.scan_id | Scan ID associated with the event. | keyword |
| eset_protect.event.scanner_id | Scanner ID associated with the event. | keyword |
| eset_protect.event.severity | Severity of the event. Possible values (from least severe to most severe) are: Information, Notice, Warning, Error, Critical, Fatal. | keyword |
| eset_protect.event.severity_score | Rule severity score associated with the event. | long |
| eset_protect.event.source_address | Address of the event source. | ip |
| eset_protect.event.source_address_type | Type of address of the event source. | keyword |
| eset_protect.event.source_port | Port of the event source. | long |
| eset_protect.event.source_uuid | UUID of the computer generating the event. | keyword |
| eset_protect.event.target | Target action is operating on. | keyword |
| eset_protect.event.target_address | Address of the event destination. | ip |
| eset_protect.event.target_address_type | Type of address of the event destination. | keyword |
| eset_protect.event.target_port | Port of the event destination. | long |
| eset_protect.event.threat_flags | Detection related flags. | keyword |
| eset_protect.event.threat_handled | Indicates whether or not the detection was handled. | boolean |
| eset_protect.event.threat_name | Name of the detection. | keyword |
| eset_protect.event.threat_type | Type of detection. | keyword |
| eset_protect.event.type | Type of exported events. | keyword |
| eset_protect.event.username | Name of the user account associated with the event. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| tags | User defined tags. | keyword |

