# ESET PROTECT

## Overview

ESET PROTECT enables you to manage ESET products on workstations and servers in a networked environment with up to 50,000 devices from one central location. Using the ESET PROTECT Web Console, you can deploy ESET solutions, manage tasks, enforce security policies, monitor system status, and quickly respond to problems or threats on remote computers.

### Compatibility

This integration supports ESET PROTECT Cloud services that expose the ESET Connect APIs in the `eu`, `de`, `us`, `ca`, and `jpn` regions. The Event data stream supports JSON payloads from ESET PROTECT Syslog Forwarder.

### How it works

The Detection, Device, Device Task, and Device Vulnerability data streams periodically query the regional ESET Connect APIs. The Event data stream listens for JSON security and audit events that ESET PROTECT sends over TCP with optional TLS.

## What data does this integration collect?

The ESET PROTECT integration collects five data streams:

**[Detection](https://help.eset.com/eset_connect/en-US/incident_management_v1_detections_get.html)** retrieves detections from the ESET Connect Incident Management API.

**[Device](https://help.eset.com/eset_connect/en-US/device_management_v1_devices_get.html)** retrieves managed-device inventory from the ESET Connect Device Management API.

**[Device Task](https://help.eset.com/eset_connect/en-US/automation_v1_device_tasks_get.html)** retrieves task definitions from the ESET Connect Automation API.

**[Device Vulnerability](https://help.eset.com/eset_connect/en-US/vulnerability_management_v1_device-vulnerabilities_get.html)** retrieves current per-device vulnerability findings from the ESET Connect Vulnerability Management API.

**Event** receives JSON security and audit events from the [ESET PROTECT Syslog Forwarder](https://help.eset.com/protect_cloud/en-US/syslog_forwarder.html). ESET notifications are also received, but their message content is administrator-defined plain text.

### Supported use cases

Use this integration to monitor endpoint detections, investigate security events, track managed-device inventory and task definitions, and assess current device vulnerabilities in Elastic.

## What do I need to use this integration?

### From ESET PROTECT

The ESET Connect API data streams require:

- A dedicated API user with **Integrations** access.
- Read permissions for the intended products and static groups.
- Outbound HTTPS access from the collector to the regional ESET authentication and API endpoints.

The Event data stream requires ESET PROTECT Syslog Forwarder and network access from ESET PROTECT to the TCP/TLS listener.

### From Elastic

The four ESET Connect API data streams support Elastic Managed and Agent-based deployments. Elastic Managed integrations are available on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. Elastic runs the collector, so you do not need to manage the collection infrastructure. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

The Event data stream requires an Agent-based deployment on a host that can accept connections from ESET PROTECT.

## How do I deploy this integration?

### Onboard and configure

#### Collect data from ESET Connect

1. [Create a dedicated API user account](https://help.eset.com/eset_connect/en-US/create_api_user_account.html). Enable **Integrations** access and assign the required read permissions.
2. Complete the API user invitation. An ESET PROTECT Hub API user must sign in to the Hub at least once before using the API.
3. Record the API user's username and password.
4. Identify the service region used by the ESET tenant: `eu`, `de`, `us`, `ca`, or `jpn`.

#### Collect data from ESET PROTECT via Syslog

Use an Agent-based deployment for this data stream. In ESET PROTECT, open **Marketplace** → **Integrations**, add [Syslog Forwarder](https://help.eset.com/protect_cloud/en-US/syslog_forwarder.html), and configure the following settings:

1. Set **Payload** to **JSON**. Notifications remain administrator-defined plain text.
2. Set **Envelope** to **Syslog**.
3. Set the minimum log level to **Information** to collect all severities.
4. Select the required Antivirus, HIPS, Firewall, Web protection, Audit Log, Blocked files, ESET Inspect, and Incident event types.
5. Enter the public IPv4 address or FQDN and port that route to the Elastic Agent. The integration's default port is `6514`.
6. Enable TLS and configure certificate validation as required. The server certificate presented by Elastic Agent must match the destination name and include the complete trusted certificate chain.

ESET enables RFC 6587 octet-counted framing by default. When octet counting is enabled in ESET, add the following under **Custom TCP Options**:

```yaml
framing: rfc6587
max_message_size: 50KiB
```

Alternatively, turn off octet-counted framing in ESET and use the integration's default delimiter framing.

ESET truncates exported messages larger than 8 KB, sends a `HEARTBEAT` message every one to three minutes, and does not buffer events while the destination is unavailable. Events generated during an outage are not replayed after connectivity is restored. For more information, refer to [Syslog restrictions and limits](https://help.eset.com/protect_cloud/en-US/syslogexportsettingsconstraints.html) and [Events exported as JSON](https://help.eset.com/protect_cloud/en-US/events-exported-to-json-format.html).

### Agent-based deployment

Install Elastic Agent on a host that can reach the ESET Connect APIs or receive connections from ESET PROTECT Syslog Forwarder. For installation guidance, refer to [Install Elastic Agents](docs-content://reference/fleet/install-elastic-agents.md).

### Configure the integration in Elastic

1. In Kibana navigate to **Management** → **Integrations**.
2. In the search bar, type **ESET PROTECT**.
3. Select the **ESET PROTECT** integration and add it.
4. To collect from ESET Connect, enable the required API data streams and configure the API username, password, and region.
5. To collect events from Syslog Forwarder, enable the Event data stream and configure:
   - **Listen Address** as `0.0.0.0` or a specific interface reachable through the destination configured in ESET.
   - **Listen Port** to match the ESET destination port.
   - **SSL Configuration** with the server certificate and matching private key.
   - **Custom TCP Options** with `framing: rfc6587` when ESET octet-counted framing is enabled.
6. Save the integration.

### Validation

1. Confirm that the integration policy is healthy in Fleet.
2. Wait for the configured collection interval, then search for `data_stream.dataset: eset_protect.<data_stream>` in Discover.
3. For the Event data stream, generate a supported event in ESET PROTECT and verify that it appears in the `eset_protect.event` dataset.

## Troubleshooting

- **Authentication fails:** Verify the API username and password, confirm that the user completed the ESET PROTECT Hub sign-in, and check that **Integrations** access is enabled.
- **API data is missing:** Verify the selected region, product permissions, static-group scope, and outbound HTTPS connectivity to ESET.
- **Syslog events are missing:** Confirm that ESET PROTECT can reach the configured listener, that the certificate identity and trust chain are valid, and that the ESET and Elastic framing settings match.
- **Syslog messages are incomplete:** ESET truncates messages larger than 8 KB. This limit cannot be increased in the Elastic integration.
- **Events are missing after an outage:** ESET does not buffer Syslog Forwarder events while the destination is unavailable.

For help with Elastic Agent and Fleet, refer to [Common problems with Fleet and Elastic Agent](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

Shorter API polling intervals increase request volume. Choose intervals based on tenant size, enabled data streams, and the time required to complete each paginated collection cycle.

For the Event data stream, size the Agent host and network path for the expected Syslog Forwarder event rate. ESET truncates messages larger than 8 KB and does not buffer events during an outage, so maintain listener availability when event continuity is required.

For scaling architecture guidance, refer to [Ingest architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures).

## Reference

### Vendor documentation

- [ESET Connect API documentation](https://help.eset.com/eset_connect/en-US/)
- [ESET PROTECT Syslog Forwarder](https://help.eset.com/protect_cloud/en-US/syslog_forwarder.html)
- [Syslog restrictions and limits](https://help.eset.com/protect_cloud/en-US/syslogexportsettingsconstraints.html)
- [Events exported as JSON](https://help.eset.com/protect_cloud/en-US/events-exported-to-json-format.html)

### Logs reference

#### Detection

This is the `Detection` dataset.

##### Example

An example event for `detection` looks as following:

```json
{
    "@timestamp": "2023-10-26T13:36:53.000Z",
    "agent": {
        "ephemeral_id": "3166280a-d109-4e1a-a949-eae156770c1e",
        "id": "fbb34d12-6a92-4b08-8435-1076804a69a2",
        "name": "elastic-agent-11274",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "eset_protect.detection",
        "namespace": "36613",
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
        "id": "fbb34d12-6a92-4b08-8435-1076804a69a2",
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
        "ingested": "2026-04-01T06:55:33Z",
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
| host.ip | Host ip addresses. | ip |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.ip | All of the IPs seen on your event. | ip |


#### Device

This is the `Device` dataset.

##### Example

An example event for `device` looks as following:

```json
{
    "@timestamp": "2024-01-22T10:30:00.000Z",
    "ecs": {
        "version": "8.11.0"
    },
    "eset_protect": {
        "device": {
            "deployed_components": [
                {
                    "display_name": "ESET Management Agent",
                    "version": {
                        "name": "13.1.1110.0"
                    }
                },
                {
                    "display_name": "ESET Endpoint Security",
                    "version": {
                        "name": "13.0.2044.0"
                    }
                }
            ],
            "enrollment_status": "DEVICE_ENROLLMENT_STATUS_UNSPECIFIED",
            "functionality_problem_count": 0,
            "functionality_status": "DEVICE_FUNCTIONALITY_STATUS_OK",
            "hardware_profiles": [
                {
                    "bios": {
                        "serial_number": "VMware-XX XX XX XX XX XX XX XX-XX XX XX XX XX XX XX XX"
                    },
                    "hard_drives": [
                        {
                            "capacity_bytes": 0,
                            "display_name": "NECVMWar VMware SATA CD01",
                            "drive_type": "DRIVE_TYPE_OPTICAL",
                            "hardware_encryption_supported": false,
                            "manufacturer_name": "(Standard CD-ROM drives)"
                        },
                        {
                            "capacity_bytes": 134214656,
                            "display_name": "VMware Virtual NVMe Disk",
                            "drive_type": "DRIVE_TYPE_HDD",
                            "hardware_encryption_supported": false,
                            "manufacturer_name": "(Standard disk drives)",
                            "serial_number": "XXXX_XXXX_XXXX_XXXX_XXXX_XXXX_XXXX_XXXX."
                        }
                    ],
                    "network_adapters": [
                        {
                            "mac_address": "AA-BB-CC-DD-EE-FF"
                        }
                    ],
                    "processors": [
                        {
                            "architecture": "CPU_ARCHITECTURE_X64",
                            "caption": "Intel(R) Core(TM) i9-14900K",
                            "id": "CPU0",
                            "manufacturer": "GenuineIntel"
                        },
                        {
                            "architecture": "CPU_ARCHITECTURE_X64",
                            "caption": "Intel(R) Core(TM) i9-14900K",
                            "id": "CPU1",
                            "manufacturer": "GenuineIntel"
                        }
                    ]
                }
            ],
            "is_master": false,
            "is_mobile": false,
            "is_muted": false,
            "last_sync_time": "2024-01-22T10:30:00.000Z",
            "parent_group_uuid": "group-uuid-XXXX-1234",
            "primary_local_ip_address": "192.168.1.100",
            "public_ip_address": "203.0.113.10",
            "type": "DEVICE_TYPE_UNSPECIFIED"
        }
    },
    "event": {
        "category": [
            "host"
        ],
        "dataset": "eset_protect.device",
        "kind": "event",
        "module": "eset_protect",
        "original": "{\"activeProducts\":[],\"deployedComponents\":[{\"displayName\":\"ESET Management Agent\",\"id\":0,\"name\":\"\",\"version\":{\"id\":\"0\",\"major\":0,\"minor\":0,\"name\":\"13.1.1110.0\",\"patch\":0}},{\"displayName\":\"ESET Endpoint Security\",\"id\":0,\"name\":\"\",\"version\":{\"id\":\"0\",\"major\":0,\"minor\":0,\"name\":\"13.0.2044.0\",\"patch\":0}}],\"description\":\"\",\"deviceToken\":\"\",\"deviceType\":\"DEVICE_TYPE_UNSPECIFIED\",\"displayName\":\"WORKSTATION01\",\"enrollmentStatus\":\"DEVICE_ENROLLMENT_STATUS_UNSPECIFIED\",\"etag\":\"\",\"functionalityProblemCount\":0,\"functionalityStatus\":\"DEVICE_FUNCTIONALITY_STATUS_OK\",\"hardwareProfiles\":[{\"bios\":{\"manufacturer\":\"VMware, Inc.\",\"serialNumber\":\"VMware-XX XX XX XX XX XX XX XX-XX XX XX XX XX XX XX XX\",\"uuid\":\"\"},\"hardDrives\":[{\"capacityBytes\":\"0\",\"displayName\":\"NECVMWar VMware SATA CD01\",\"driveType\":\"DRIVE_TYPE_OPTICAL\",\"hardwareEncryptionSupported\":false,\"manufacturerName\":\"(Standard CD-ROM drives)\",\"serialNumber\":\"\"},{\"capacityBytes\":\"134214656\",\"displayName\":\"VMware Virtual NVMe Disk\",\"driveType\":\"DRIVE_TYPE_HDD\",\"hardwareEncryptionSupported\":false,\"manufacturerName\":\"(Standard disk drives)\",\"serialNumber\":\"XXXX_XXXX_XXXX_XXXX_XXXX_XXXX_XXXX_XXXX.\"}],\"manufacturer\":\"No Enclosure\",\"model\":\"System Enclosure\",\"networkAdapters\":[{\"caption\":\"Intel(R) 82574L Gigabit Network Connection\",\"macAddress\":\"AA-BB-CC-DD-EE-FF\"}],\"processors\":[{\"architecture\":\"CPU_ARCHITECTURE_X64\",\"caption\":\"Intel(R) Core(TM) i9-14900K\",\"id\":\"CPU0\",\"manufacturer\":\"GenuineIntel\"},{\"architecture\":\"CPU_ARCHITECTURE_X64\",\"caption\":\"Intel(R) Core(TM) i9-14900K\",\"id\":\"CPU1\",\"manufacturer\":\"GenuineIntel\"}],\"resettableIdentifier\":\"\",\"salt\":\"\"}],\"isMaster\":false,\"isMobile\":false,\"isMuted\":false,\"lastSyncTime\":\"2024-01-22T10:30:00Z\",\"managementDomain\":\"\",\"operatingSystem\":{\"bitness\":0,\"displayName\":\"Microsoft Windows 11 Pro\",\"editionId\":0,\"familyId\":0,\"version\":{\"id\":\"0\",\"major\":0,\"minor\":0,\"name\":\"10.0.26200.8457\",\"patch\":0}},\"originalDisplayName\":\"\",\"ownerUuid\":\"\",\"parentGroupUuid\":\"group-uuid-XXXX-1234\",\"primaryLocalIpAddress\":\"192.168.1.100\",\"publicIpAddress\":\"203.0.113.10\",\"tags\":[\"\"],\"uuid\":\"device-uuid-XXXX-1234\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "device-uuid-XXXX-1234",
        "ip": [
            "192.168.1.100",
            "203.0.113.10"
        ],
        "mac": [
            "AA-BB-CC-DD-EE-FF"
        ],
        "name": "WORKSTATION01",
        "os": {
            "family": "windows",
            "full": "Microsoft Windows 11 Pro",
            "name": "Microsoft Windows 11 Pro",
            "platform": "windows",
            "type": "windows",
            "version": "10.0.26200.8457"
        }
    },
    "related": {
        "hosts": [
            "device-uuid-XXXX-1234",
            "WORKSTATION01"
        ],
        "ip": [
            "192.168.1.100",
            "203.0.113.10"
        ]
    },
    "tags": [
        "forwarded",
        "eset_protect-device"
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
| eset_protect.device.active_products | List of active ESET product identifiers installed on the device. | keyword |
| eset_protect.device.deployed_components.display_name | Human-friendly name of the deployed ESET component. | keyword |
| eset_protect.device.deployed_components.version.name | Human-readable version string of the deployed component. | keyword |
| eset_protect.device.description | Optional description of the device. | keyword |
| eset_protect.device.display_name | Human-friendly name of the device. | keyword |
| eset_protect.device.enrollment_status | Enrollment status of the device. Possible values: DEVICE_ENROLLMENT_STATUS_ENROLLED, DEVICE_ENROLLMENT_STATUS_UNENROLLED. | keyword |
| eset_protect.device.etag | Opaque entity tag used for cache validation and change detection. | keyword |
| eset_protect.device.functionality_problem_count | Number of active functionality problems on the device. | long |
| eset_protect.device.functionality_status | Functionality status of the device. Possible values: DEVICE_FUNCTIONALITY_STATUS_OK, DEVICE_FUNCTIONALITY_STATUS_ATTENTION_RECOMMENDED, DEVICE_FUNCTIONALITY_STATUS_ATTENTION_REQUIRED. | keyword |
| eset_protect.device.hardware_profiles.bios.serial_number | BIOS serial number. | keyword |
| eset_protect.device.hardware_profiles.hard_drives.capacity_bytes | Total capacity of the drive in bytes. | long |
| eset_protect.device.hardware_profiles.hard_drives.display_name | Human-friendly name of the hard drive. | keyword |
| eset_protect.device.hardware_profiles.hard_drives.drive_type | Type of the drive (e.g. DRIVE_TYPE_SSD, DRIVE_TYPE_HDD). | keyword |
| eset_protect.device.hardware_profiles.hard_drives.hardware_encryption_supported | Whether the drive supports hardware-level encryption. | boolean |
| eset_protect.device.hardware_profiles.hard_drives.manufacturer_name | Name of the drive manufacturer. | keyword |
| eset_protect.device.hardware_profiles.hard_drives.serial_number | Serial number of the hard drive. | keyword |
| eset_protect.device.hardware_profiles.network_adapters.mac_address | MAC address of the network adapter. | keyword |
| eset_protect.device.hardware_profiles.processors.architecture | Processor architecture (e.g. x86_64, ARM). | keyword |
| eset_protect.device.hardware_profiles.processors.caption | Human-readable description of the processor. | keyword |
| eset_protect.device.hardware_profiles.processors.id | Processor identifier as reported by the OS. | keyword |
| eset_protect.device.hardware_profiles.processors.manufacturer | Name of the processor manufacturer. | keyword |
| eset_protect.device.is_master | If true, this device acts as an ESET management master agent. | boolean |
| eset_protect.device.is_mobile | If true, the device is a mobile device. | boolean |
| eset_protect.device.is_muted | If true, the device is muted and alerts are suppressed. | boolean |
| eset_protect.device.labels.name | Label tag applied to the device. | keyword |
| eset_protect.device.last_sync_time | Timestamp of the last successful synchronisation with the ESET PROTECT server. | date |
| eset_protect.device.management_domain | Management domain the device belongs to. | keyword |
| eset_protect.device.original_display_name | Original display name of the device before any rename. | keyword |
| eset_protect.device.owner_uuid | UUID of the user who owns the device. | keyword |
| eset_protect.device.parent_group_uuid | UUID of the parent device group. | keyword |
| eset_protect.device.primary_local_ip_address | Primary local (LAN) IP address of the device. | ip |
| eset_protect.device.public_ip_address | Public (WAN) IP address of the device. | ip |
| eset_protect.device.type | Device type identifier. Possible values: DEVICE_TYPE_DESKTOP, DEVICE_TYPE_SERVER, DEVICE_TYPE_LAPTOP, DEVICE_TYPE_MOBILE, DEVICE_TYPE_VIRTUAL. | keyword |
| eset_protect.device.uuid | Unique identifier of the device. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


#### Device Task

This is the `Device Task` dataset.

##### Example

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


#### Device Vulnerability

This is the `Device Vulnerability` dataset.

##### Example

An example event for `device_vulnerability` looks as following:

```json
{
    "@timestamp": "2024-01-22T10:30:00.000Z",
    "ecs": {
        "version": "8.11.0"
    },
    "eset_protect": {
        "device_vulnerability": {
            "application": {
                "developer_display_name": "Mozilla Corporation",
                "display_name": "Mozilla Firefox ESR",
                "uuid": "202410458",
                "version": {
                    "id": "0",
                    "major": 0,
                    "minor": 0,
                    "name": "128.3.0",
                    "patch": 0
                }
            },
            "cve_number": "CVE-2024-10458",
            "first_detect_time": "2024-01-15T08:30:00Z",
            "last_detect_time": "2024-01-22T10:30:00Z",
            "patch_available": false,
            "risk_score": 60,
            "severity": "SEVERITY_LEVEL_MEDIUM",
            "type": "application",
            "vulnerability_id": 202410458
        }
    },
    "event": {
        "category": [
            "vulnerability"
        ],
        "dataset": "eset_protect.device_vulnerability",
        "kind": "event",
        "module": "eset_protect",
        "original": "{\"applicationVulnerability\":{\"application\":{\"developerDisplayName\":\"Mozilla Corporation\",\"displayName\":\"Mozilla Firefox ESR\",\"uuid\":\"202410458\",\"version\":{\"id\":\"0\",\"major\":0,\"minor\":0,\"name\":\"128.3.0\",\"patch\":0}},\"cveNumber\":\"CVE-2024-10458\",\"firstDetectTime\":\"2024-01-15T08:30:00Z\",\"lastDetectTime\":\"2024-01-22T10:30:00Z\",\"patchAvailable\":false,\"riskScore\":60,\"severity\":\"SEVERITY_LEVEL_MEDIUM\",\"vulnerabilityId\":202410458},\"availablePatchUuids\":[],\"deviceDisplayName\":\"WORKSTATION01\",\"deviceGroupUuid\":\"\",\"deviceUuid\":\"device-uuid-XXXX-1234\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "device-uuid-XXXX-1234",
        "name": "WORKSTATION01"
    },
    "observer": {
        "product": "ESET PROTECT",
        "vendor": "ESET"
    },
    "package": {
        "name": "Mozilla Firefox ESR",
        "vendor": "Mozilla Corporation",
        "version": "128.3.0"
    },
    "related": {
        "hosts": [
            "WORKSTATION01",
            "device-uuid-XXXX-1234"
        ]
    },
    "resource": {
        "id": "device-uuid-XXXX-1234",
        "name": "WORKSTATION01"
    },
    "tags": [
        "forwarded",
        "eset_protect-device_vulnerability"
    ],
    "vulnerability": {
        "enumeration": "CVE",
        "id": "CVE-2024-10458",
        "scanner": {
            "vendor": "ESET"
        },
        "severity": "medium",
        "title": "Vulnerability found in Mozilla Firefox ESR 128.3.0 - CVE-2024-10458"
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
| eset_protect.device_vulnerability.application.developer_display_name | A human-readable name of the application developer. | keyword |
| eset_protect.device_vulnerability.application.display_name | A human-friendly name of the application. | keyword |
| eset_protect.device_vulnerability.application.uuid | Unique identifier of the application. | keyword |
| eset_protect.device_vulnerability.application.version.id | Internal version identifier. | keyword |
| eset_protect.device_vulnerability.application.version.major | Major version number component. | long |
| eset_protect.device_vulnerability.application.version.minor | Minor version number component. | long |
| eset_protect.device_vulnerability.application.version.name | Human-readable version string. | keyword |
| eset_protect.device_vulnerability.application.version.patch | Patch version number component. | long |
| eset_protect.device_vulnerability.available_patch_uuids | UUIDs of patches available to remediate this vulnerability. | keyword |
| eset_protect.device_vulnerability.cve_number | A CVE identifier string. | keyword |
| eset_protect.device_vulnerability.device_group_uuid | UUID of the device group the vulnerable device belongs to. | keyword |
| eset_protect.device_vulnerability.device_uuid | Unique identifier of the vulnerable device. Duplicate of host.id. | keyword |
| eset_protect.device_vulnerability.first_detect_time | When the vulnerability was detected for the first time. | date |
| eset_protect.device_vulnerability.last_detect_time | When the vulnerability was last observed. | date |
| eset_protect.device_vulnerability.os_family_id | Operating system family identifier (OS vulnerability only). Known values: 1 (Windows), 2 (Linux), 3 (Mac OS), 7 (Unix). | long |
| eset_protect.device_vulnerability.package.display_name | A human-friendly name of the package. | keyword |
| eset_protect.device_vulnerability.package.name | Package name as indexed within the package manager. | keyword |
| eset_protect.device_vulnerability.package.package_manager_type | Type of package manager (e.g. PACKAGE_MANAGER_TYPE_APT). | keyword |
| eset_protect.device_vulnerability.package.version_name | Human-readable name of the package version. | keyword |
| eset_protect.device_vulnerability.patch_available | If true, a patch fixing this vulnerability is available. | boolean |
| eset_protect.device_vulnerability.risk_score | How risky the vulnerability is, ranging from 0 (no threat) to 100 (threat). | long |
| eset_protect.device_vulnerability.severity | Severity level of the vulnerability. | keyword |
| eset_protect.device_vulnerability.type | Vulnerability type: application, os, or package. | keyword |
| eset_protect.device_vulnerability.vulnerability_id | Vulnerability catalog ID. | long |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| package.name | Name of the affected software package or application. | keyword |
| package.vendor | Developer or vendor of the affected software (from application vulnerabilities). | keyword |
| package.version | Version of the affected software package or application. | keyword |
| resource.id | Unique identifier of the affected device. Equal to host.id. | keyword |
| resource.name | Display name of the affected device. | keyword |
| vulnerability.enumeration | The type of identifier used for this vulnerability. For example (https://cve.mitre.org/about/) | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | keyword |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
| vulnerability.title | Human-readable title for this vulnerability finding. | keyword |


#### Event

This is the `Event` dataset.

##### Example

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
            "occurred": "2021-06-21T03:56:20.000Z",
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
| email.attachments | A list of objects describing the attachment files sent along with an email message. | nested |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
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
| eset_protect.event.occurred | UTC time of occurrence of the event. Format is %d-%b-%Y %H:%M:%S. | date |
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

