# ESET PROTECT

ESET PROTECT enables you to manage ESET products on workstations and servers in a networked environment with up to 50,000 devices from one central location. Using the ESET PROTECT Web Console, you can deploy ESET solutions, manage tasks, enforce security policies, monitor system status, and quickly respond to problems or threats on remote computers.

## Data streams

The ESET PROTECT integration collects three types of logs: Detection, Device Task and Event.

**[Detection](https://help.eset.com/protect_cloud/en-US/admin_ct.html?threats.html)** is used to retrieve detections via the **Incident Management - List detections** ([v1](https://help.eset.com/eset_connect/en-US/incident_management_v1_detections_get.html) & [v2](https://help.eset.com/eset_connect/en-US/incident_management_v2_detections_get.html) endpoints).

**[Device Task](https://help.eset.com/protect_cloud/en-US/admin_ct.html?admin_ct.html)** is used to retrieve device tasks via the [Automation - List tasks](https://help.eset.com/eset_connect/en-US/automation_v1_device_tasks_get.html) endpoint.

**Event** is used to retrieve Detection, Firewall, HIPS, Audit, and ESET Inspect logs using the [Syslog Server](https://help.eset.com/protect_cloud/en-US/admin_server_settings_export_to_syslog.html). ESET notifications are also retrieved but in plain text.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect data from ESET Connect

1. [Create API User Account](https://help.eset.com/eset_connect/en-US/create_api_user_account.html)
2. Retrieve the username and password generated during the creation of an API user account.
3. Retrieve the region from the ESET Web Console URL.

**NOTE**: Detection logs can be collected using the v2 endpoint only after your API user has signed in to your ESET Cloud Office Security instance at least once; this ensures the account is recognized. Note that the v2 endpoint is not supported in the Japanese region.

### Collect data from ESET PROTECT via Syslog

Follow these steps to [configure syslog server](https://help.eset.com/protect_cloud/en-US/admin_server_settings_syslog.html):

1. Set the format of the payload to **JSON** (Hint: ESET Notifications are sent as plain text, regardless of the selection made https://help.eset.com/protect_admin/12.0/en-US/events-exported-to-json-format.html).
2. Set the format of the envelope to **Syslog**.
3. Set the minimal log level to **Information** to collect all data.
4. Select all checkboxes to collect logs for all event types.
5. Enter the **IP Address** or **FQDN** of the Elastic Agent that is running the integration in the Destination IP field.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **ESET PROTECT**.
3. Select the **ESET PROTECT** integration and add it.
4. Configure all required integration parameters, including username, password, and region, to enable data collection from the ESET Connect REST API. For syslog data collection, provide parameters such as listen address, listen port, and SSL settings.
5. Save the integration.

## Logs Reference

### Detection

This is the `Detection` dataset.

#### Example

An example event for `detection` looks as following:

```json
{
    "@timestamp": "2023-10-26T13:36:53.000Z",
    "agent": {
        "ephemeral_id": "9fed99a0-45df-42ef-afb4-d96ed33cfe85",
        "id": "d0b8ac83-9cce-4df1-aa84-794fb6ff89df",
        "name": "elastic-agent-39862",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "eset_protect.detection",
        "namespace": "77988",
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
        "id": "d0b8ac83-9cce-4df1-aa84-794fb6ff89df",
        "snapshot": false,
        "version": "8.16.0"
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
        "id": "xxx-xxxx-xxxx-1234-xxxxxxxxxxxx",
        "ingested": "2026-02-18T06:46:50Z",
        "kind": "alert",
        "original": "{\"category\":\"DETECTION_CATEGORY_NETWORK_INTRUSION\",\"context\":{\"circumstances\":\"Eicar\",\"deviceUuid\":\"xxx-xxxx-1234-5678-xxxxxxxxxxxx\",\"process\":{\"path\":\"C:\\\\Windows\\\\chrome.exe\"},\"userName\":\"testingpc\\\\example\"},\"networkCommunication\":{\"protocolName\":\"0\",\"remoteIpAddress\":\"89.160.20.112\",\"remotePort\":443},\"objectHashSha1\":\"AAF4C61DDCC5E8A2DABEDE0F3B4820123456789D\",\"objectTypeName\":\"File\",\"objectUrl\":\"C:\\\\Temp\\\\06516f11-xxxx-xxxx-xxxx-37da66b5de99_ccf7464ba6e2e12e984514f694bfb10d03de77358d8a3afd7a2ffed150ec1df8.zip.e99\\\\ccf7464ba6e2e12e984514f694bfb10d03de77358d8a3afd7a2ffed150ec1df8\",\"occurTime\":\"2023-10-26T13:36:53Z\",\"responses\":[{}],\"severityLevel\":\"SEVERITY_LEVEL_MEDIUM\",\"typeName\":\"TCP Port scanning attack\",\"uuid\":\"xxx-xxxx-xxxx-1234-xxxxxxxxxxxx\"}",
        "reason": "Eicar",
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
| eset_protect.detection.cloud_office_tenant_uuid | Reference to cloud office tenant. | keyword |
| eset_protect.detection.context.circumstances | Human-friendly description of [detection]'s circumstances. | keyword |
| eset_protect.detection.context.device_display_name | Human-friendly name of the device with detection. | keyword |
| eset_protect.detection.context.device_uuid | Reference to [device]. | keyword |
| eset_protect.detection.context.process.command_line | Argument used with the command. | keyword |
| eset_protect.detection.context.process.path | Disk path to the executable. | keyword |
| eset_protect.detection.context.process.uuid | Universally Unique Identifier References use this identifier, so it must be filled in all the cases except the resource creation. | keyword |
| eset_protect.detection.context.user_name | User name in whose context detection occurred. | keyword |
| eset_protect.detection.display_name | Human-friendly name of the detection. This value can be used to look up details at http://www.virusradar.com/en/threat_encyclopedia. | keyword |
| eset_protect.detection.edr_rule_uuid | Reference to the EDR rule which triggered the detection. | keyword |
| eset_protect.detection.email.attachments.contained_files | List of files contained within this file, in case this file has internal structure. | keyword |
| eset_protect.detection.email.attachments.hash_sha1 | SHA-1 digest of file's content. | keyword |
| eset_protect.detection.email.attachments.hash_sha2256 | SHA-2 256 digest of file's content. | keyword |
| eset_protect.detection.email.attachments.is_read_only | True if the scanned object was read-only and cannot be modified/cleaned/deleted. | boolean |
| eset_protect.detection.email.attachments.last_editor.email | Email of the user. | keyword |
| eset_protect.detection.email.attachments.last_editor.user_name | Name of the user. | keyword |
| eset_protect.detection.email.attachments.last_editor.user_uuid | Reference to user. | keyword |
| eset_protect.detection.email.attachments.origin | Object origin denotes a system managing object's life-cycle. | keyword |
| eset_protect.detection.email.attachments.path | File path. | keyword |
| eset_protect.detection.email.attachments.reference | How the file is referred to. | keyword |
| eset_protect.detection.email.attachments.size_bytes | File size in bytes. | long |
| eset_protect.detection.email.attachments.storages.archive_reference | Reference to the archive containing the file. Can be an URL or path to the parent archive. | keyword |
| eset_protect.detection.email.attachments.storages.cloud_drive_user_uuid | If the file resides in the cloud on a cloud drive (for example, Google Drive or Microsoft OneDrive), this attribute references the user who owns that drive. | keyword |
| eset_protect.detection.email.attachments.storages.display_name | Human readable name of the storage. | keyword |
| eset_protect.detection.email.attachments.storages.email_reference | Reference to the email containing the file. | keyword |
| eset_protect.detection.email.attachments.storages.ms_sharepoint_root_site_uuid | Reference to Microsoft Sharepoint root site. | keyword |
| eset_protect.detection.email.attachments.storages.ms_sharepoint_site_uuid | Reference to Microsoft Sharepoint site. | keyword |
| eset_protect.detection.email.attachments.storages.ms_teams_team_uuid | Reference to Microsoft Teams team. | keyword |
| eset_protect.detection.email.attachments.storages.uuid | Unique identifier of the file storage instance where the file resides. | keyword |
| eset_protect.detection.email.body_parts.contained_files | List of files contained within this file, in case this file has internal structure. | keyword |
| eset_protect.detection.email.body_parts.hash_sha1 | SHA-1 digest of file's content. | keyword |
| eset_protect.detection.email.body_parts.hash_sha2256 | SHA-2 256 digest of file's content. | keyword |
| eset_protect.detection.email.body_parts.is_read_only | True if the scanned object was read-only and cannot be modified/cleaned/deleted. | boolean |
| eset_protect.detection.email.body_parts.last_editor.email | Email of the user. | keyword |
| eset_protect.detection.email.body_parts.last_editor.user_name | Name of the user. | keyword |
| eset_protect.detection.email.body_parts.last_editor.user_uuid | Reference to user. | keyword |
| eset_protect.detection.email.body_parts.origin | Object origin denotes a system managing object's life-cycle. | keyword |
| eset_protect.detection.email.body_parts.path | File path. | keyword |
| eset_protect.detection.email.body_parts.reference | How the file is referred to. | keyword |
| eset_protect.detection.email.body_parts.size_bytes | File size in bytes. | long |
| eset_protect.detection.email.body_parts.storages.archive_reference | Reference to the archive containing the file. Can be an URL or path to the parent archive. | keyword |
| eset_protect.detection.email.body_parts.storages.cloud_drive_user_uuid | If the file resides in the cloud on a cloud drive (for example, Google Drive or Microsoft OneDrive), this attribute references the user who owns that drive. | keyword |
| eset_protect.detection.email.body_parts.storages.display_name | Human readable name of the storage. | keyword |
| eset_protect.detection.email.body_parts.storages.email_reference | Reference to the email containing the file. | keyword |
| eset_protect.detection.email.body_parts.storages.ms_sharepoint_root_site_uuid | Reference to Microsoft Sharepoint root site. | keyword |
| eset_protect.detection.email.body_parts.storages.ms_sharepoint_site_uuid | Reference to Microsoft Sharepoint site. | keyword |
| eset_protect.detection.email.body_parts.storages.ms_teams_team_uuid | Reference to Microsoft Teams team. | keyword |
| eset_protect.detection.email.body_parts.storages.uuid | Unique identifier of the file storage instance where the file resides. | keyword |
| eset_protect.detection.email.cc | Carbon copy recipient(s) of the email. | keyword |
| eset_protect.detection.email.contained_urls | URLs contained in the email. | keyword |
| eset_protect.detection.email.from | Sender(s) of the email. | keyword |
| eset_protect.detection.email.headers | Header of the email. | keyword |
| eset_protect.detection.email.internet_message_id | Unique identifier of the message. | keyword |
| eset_protect.detection.email.is_read_only | True if the scanned object was read-only and cannot be modified/cleaned/deleted. | boolean |
| eset_protect.detection.email.mailbox_user_uuid | Reference to the user who owns the mailbox, if the email can be associated with a mailbox. | keyword |
| eset_protect.detection.email.mailbox_uuid | Reference to mailbox. | keyword |
| eset_protect.detection.email.mta_smtp_details.hello | Parameter of extended HELLO (EHLO) or HELLO (HELO) command. | keyword |
| eset_protect.detection.email.mta_smtp_details.recipients | Parameter of RECIPIENT (RCPT) command or multiple commands for multiple recipients. | keyword |
| eset_protect.detection.email.mta_smtp_details.sender | Parameter (reverse-path) of MAIL (MAIL FROM) command. A sender of the email. | keyword |
| eset_protect.detection.email.mta_smtp_details.sender_ip_address | IP address of the sender. Might be IPv4 or IPv6. | ip |
| eset_protect.detection.email.origin | Object origin denotes a system managing object's life-cycle. | keyword |
| eset_protect.detection.email.reference | How the email is referred to. | keyword |
| eset_protect.detection.email.sender_ip_address | IP address of the sender. Might be IPv4 or IPv6. | ip |
| eset_protect.detection.email.subject | Subject of the email. | keyword |
| eset_protect.detection.email.to | Recipient(s) of the email. | keyword |
| eset_protect.detection.file.contained_files | List of files contained within this file, in case this file has internal structure. | keyword |
| eset_protect.detection.file.hash_sha1 | SHA-1 digest of file's content. | keyword |
| eset_protect.detection.file.hash_sha2256 | SHA-2 256 digest of file's content. | keyword |
| eset_protect.detection.file.is_read_only | True if the scanned object was read-only and cannot be modified/cleaned/deleted. | boolean |
| eset_protect.detection.file.last_editor.email | Email of the user. | keyword |
| eset_protect.detection.file.last_editor.user_name | Name of the user. | keyword |
| eset_protect.detection.file.last_editor.user_uuid | Reference to user. | keyword |
| eset_protect.detection.file.origin | Object origin denotes a system managing object's life-cycle. | keyword |
| eset_protect.detection.file.path | File path. | keyword |
| eset_protect.detection.file.reference | How the file is referred to. | keyword |
| eset_protect.detection.file.size_bytes | File size in bytes. | long |
| eset_protect.detection.file.storages.archive_reference | Reference to the archive containing the file. Can be an URL or path to the parent archive. | keyword |
| eset_protect.detection.file.storages.cloud_drive_user_uuid | If the file resides in the cloud on a cloud drive (for example, Google Drive or Microsoft OneDrive), this attribute references the user who owns that drive. | keyword |
| eset_protect.detection.file.storages.display_name | Human readable name of the storage. | keyword |
| eset_protect.detection.file.storages.email_reference | Reference to the email containing the file. | keyword |
| eset_protect.detection.file.storages.ms_sharepoint_root_site_uuid | Reference to Microsoft Sharepoint root site. | keyword |
| eset_protect.detection.file.storages.ms_sharepoint_site_uuid | Reference to Microsoft Sharepoint site. | keyword |
| eset_protect.detection.file.storages.ms_teams_team_uuid | Reference to Microsoft Teams team. | keyword |
| eset_protect.detection.file.storages.uuid | Unique identifier of the file storage instance where the file resides. | keyword |
| eset_protect.detection.network_communication.direction | Direction of network communication. | keyword |
| eset_protect.detection.network_communication.local.ip_address | IPv4 or IPv6 address of the device (i.e. the device where detection occurred). | ip |
| eset_protect.detection.network_communication.local.mac_address | The MAC (L2) address of endpoint-local network interface. | keyword |
| eset_protect.detection.network_communication.local.port | TCP or UDP port on the device (i.e. the device where detection occurred). | long |
| eset_protect.detection.network_communication.protocol_name | Human readable name of the protocol used to communicate between local and remote hosts. | keyword |
| eset_protect.detection.network_communication.remote.ip_address | IPv4 or IPv6 address of the remote host (i.e. not the device where detection occurred). | ip |
| eset_protect.detection.network_communication.remote.mac_address | The MAC (L2) address of the remote network interface (possibly the MAC address of the gateway). | keyword |
| eset_protect.detection.network_communication.remote.port | TCP or UDP port on the remote host (i.e. not the device where detection occurred). | long |
| eset_protect.detection.note | Arbitrary text. | keyword |
| eset_protect.detection.object_hash_sha1 | SHA1 hash of content of scanned object. | keyword |
| eset_protect.detection.object_name | Name/path of scanned object. | keyword |
| eset_protect.detection.object_size_bytes | Object's size in bytes. | long |
| eset_protect.detection.object_type_name | Human-friendly type name of scanned object. | keyword |
| eset_protect.detection.object_url | URL (uniform resource locator) of scanned object. | keyword |
| eset_protect.detection.occur_time | Timestamp of detection occurrence. | date |
| eset_protect.detection.resolved | If true, the detection is resolved and poses a threat no more. | boolean |
| eset_protect.detection.responses.action_type | Categories of operations that can be performed on objects. | keyword |
| eset_protect.detection.responses.description | Human-readable description of the response. | keyword |
| eset_protect.detection.responses.device_restart_required | Response needs restart of the device to be completed. | boolean |
| eset_protect.detection.responses.display_name | Human-friendly name of the response. | keyword |
| eset_protect.detection.responses.email_reference | Reference to the affected email. | keyword |
| eset_protect.detection.responses.file_reference | Reference to the file affected by the response. | keyword |
| eset_protect.detection.responses.protection_name | Human-readable name of the protection that performed the response. | keyword |
| eset_protect.detection.scan_uuid | Reference to the on-demand scan during which the detection occurred. | keyword |
| eset_protect.detection.severity_level | Severity levels abstracted to cover all the possible GUIs. Vocabulary is leaving interpretation of severity level completely to API client. | keyword |
| eset_protect.detection.severity_score | The integer representation of the severity level to be comparable in queries. | long |
| eset_protect.detection.triggering_event.data | Data of the event described as generic structure. | flattened |
| eset_protect.detection.triggering_event.type | Event that triggered the detection. | keyword |
| eset_protect.detection.type_name | Human-friendly type of detection. | keyword |
| eset_protect.detection.uuid | Universally Unique Identifier of detection. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Device Task

This is the `Device Task` dataset.

#### Example

An example event for `device_task` looks as following:

```json
{
    "@timestamp": "2025-11-10T06:07:33.442Z",
    "agent": {
        "ephemeral_id": "2de42df7-1a70-45c2-bdb4-f36db2841c08",
        "id": "3d09e751-a7b0-418a-ba1c-07154b8f5558",
        "name": "elastic-agent-81384",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "eset_protect.device_task",
        "namespace": "78597",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3d09e751-a7b0-418a-ba1c-07154b8f5558",
        "snapshot": false,
        "version": "8.16.0"
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
        "ingested": "2025-11-10T06:07:36Z",
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


### Event

This is the `Event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2021-06-21T03:56:20.000Z",
    "agent": {
        "ephemeral_id": "15db6629-f3a1-4a0f-94ea-1bf6ec62aaba",
        "id": "adf2804e-ca6b-4c6b-90af-e9060e7ee1b2",
        "name": "elastic-agent-28441",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "eset_protect.event",
        "namespace": "71776",
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
        "id": "adf2804e-ca6b-4c6b-90af-e9060e7ee1b2",
        "snapshot": false,
        "version": "8.16.0"
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
        "ingested": "2025-10-30T10:35:48Z",
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
            "address": "192.168.241.3:58054"
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
| eset_protect.event.command_line | Command line of process which triggered detection. | keyword |
| eset_protect.event.computer_severity_score | Computer severity score associated with the event. | long |
| eset_protect.event.count | Number of alerts of this type generated since last alarm. | long |
| eset_protect.event.description | Description of the blocked file. | keyword |
| eset_protect.event.detail | Detailed description of the action. | keyword |
| eset_protect.event.detection_uuid | A detection's unique identifier can be used to query details via ESET CONNECT API. | keyword |
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
| eset_protect.event.trigger_event | Description of event which triggered detection. | keyword |
| eset_protect.event.type | Type of exported events. | keyword |
| eset_protect.event.username | Name of the user account associated with the event. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |

