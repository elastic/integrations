# Cisco Secure Endpoint Integration

This integration is for [Cisco Secure Endpoint](https://developer.cisco.com/amp-for-endpoints/) logs. It includes the following datasets for receiving logs over syslog or read from a file:

- `event` dataset: supports Cisco Secure Endpoint Event logs.

## Logs

### Secure Endpoint

The `event` dataset collects Cisco Secure Endpoint logs.

An example event for `event` looks as following:

```json
{
    "@timestamp": "2021-01-13T10:13:08.000Z",
    "agent": {
        "ephemeral_id": "5402117c-8965-4c2d-9404-2a1fb6c47431",
        "id": "49007565-f0ac-4df0-9672-50a3e25920e8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "cisco": {
        "secure_endpoint": {
            "cloud_ioc": {
                "description": "Microsoft Word launched PowerShell. This is indicative of multiple dropper variants that make use of Visual Basic Application macros to perform nefarious activities, such as downloading and executing malicious executables.",
                "short_description": "W32.WinWord.Powershell"
            },
            "computer": {
                "active": true,
                "connector_guid": "test_connector_guid",
                "external_ip": "8.8.8.8",
                "network_addresses": [
                    {
                        "ip": "10.10.10.10",
                        "mac": "38:1e:eb:ba:2c:15"
                    }
                ]
            },
            "connector_guid": "test_connector_guid",
            "event_type_id": 1107296274,
            "file": {
                "disposition": "Clean",
                "parent": {
                    "disposition": "Clean"
                }
            },
            "group_guids": [
                "test_group_guid"
            ],
            "related": {
                "mac": [
                    "38-1E-EB-BA-2C-15"
                ]
            }
        }
    },
    "data_stream": {
        "dataset": "cisco_secure_endpoint.event",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "49007565-f0ac-4df0-9672-50a3e25920e8",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "Cloud IOC",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "code": "1107296274",
        "created": "2023-06-01T09:45:22.836Z",
        "dataset": "cisco_secure_endpoint.event",
        "id": "1515298355162029000",
        "ingested": "2023-06-01T09:45:23Z",
        "kind": "alert",
        "original": "{\"data\":{\"cloud_ioc\":{\"description\":\"Microsoft Word launched PowerShell. This is indicative of multiple dropper variants that make use of Visual Basic Application macros to perform nefarious activities, such as downloading and executing malicious executables.\",\"short_description\":\"W32.WinWord.Powershell\"},\"computer\":{\"active\":true,\"connector_guid\":\"test_connector_guid\",\"external_ip\":\"8.8.8.8\",\"hostname\":\"Demo_AMP\",\"links\":{\"computer\":\"https://api.eu.amp.cisco.com/v1/computers/test_computer\",\"group\":\"https://api.eu.amp.cisco.com/v1/groups/test_group\",\"trajectory\":\"https://api.eu.amp.cisco.com/v1/computers/test_computer/trajectory\"},\"network_addresses\":[{\"ip\":\"10.10.10.10\",\"mac\":\"38:1e:eb:ba:2c:15\"}]},\"connector_guid\":\"test_connector_guid\",\"date\":\"2021-01-13T10:13:08+00:00\",\"event_type\":\"Cloud IOC\",\"event_type_id\":1107296274,\"file\":{\"disposition\":\"Clean\",\"file_name\":\"PowerShell.exe\",\"file_path\":\"/C:/Windows/SysWOW64/WindowsPowerShell/v1.0/PowerShell.exe\",\"identity\":{\"sha256\":\"6c05e11399b7e3c8ed31bae72014cf249c144a8f4a2c54a758eb2e6fad47aec7\"},\"parent\":{\"disposition\":\"Clean\",\"identity\":{\"sha256\":\"3d46e95284f93bbb76b3b7e1bf0e1b2d51e8a9411c2b6e649112f22f92de63c2\"}}},\"group_guids\":[\"test_group_guid\"],\"id\":1515298355162029000,\"severity\":\"Medium\",\"start_date\":\"2021-01-13T10:13:08+00:00\",\"start_timestamp\":1610532788,\"timestamp\":1610532788,\"timestamp_nanoseconds\":162019000},\"metadata\":{\"links\":{\"next\":\"http://47c9519daa08:8080/v1/events?start_date=2023-05-31T09:45:22+00:00\\u0026limit=1\\u0026offset=1\",\"self\":\"http://47c9519daa08:8080/v1/events?start_date=2023-05-31T09:45:22+00:00\\u0026limit=1\"},\"results\":{\"current_item_count\":1,\"index\":0,\"items_per_page\":1,\"total\":2}},\"version\":\"v1.2.0\"}",
        "severity": 2,
        "start": "2021-01-13T10:13:08.000Z"
    },
    "file": {
        "hash": {
            "sha256": "6c05e11399b7e3c8ed31bae72014cf249c144a8f4a2c54a758eb2e6fad47aec7"
        },
        "name": "PowerShell.exe",
        "path": "/C:/Windows/SysWOW64/WindowsPowerShell/v1.0/PowerShell.exe"
    },
    "host": {
        "hostname": "Demo_AMP",
        "name": "demo_amp"
    },
    "input": {
        "type": "httpjson"
    },
    "process": {
        "hash": {
            "sha256": "3d46e95284f93bbb76b3b7e1bf0e1b2d51e8a9411c2b6e649112f22f92de63c2"
        }
    },
    "related": {
        "hash": [
            "6c05e11399b7e3c8ed31bae72014cf249c144a8f4a2c54a758eb2e6fad47aec7"
        ],
        "hosts": [
            "demo_amp"
        ],
        "ip": [
            "8.8.8.8",
            "10.10.10.10"
        ]
    },
    "tags": [
        "cisco-secure_endpoint",
        "forwarded",
        "preserve_original_event"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco.secure_endpoint.bp_data | Endpoint isolation information | flattened |
| cisco.secure_endpoint.cloud_ioc.description | Description of the related IOC for specific IOC events from AMP. | keyword |
| cisco.secure_endpoint.cloud_ioc.short_description | Short description of the related IOC for specific IOC events from AMP. | keyword |
| cisco.secure_endpoint.command_line.arguments | The CLI arguments related to the Cloud Threat IOC reported by Cisco. | keyword |
| cisco.secure_endpoint.computer.active | If the current endpoint is active or not. | boolean |
| cisco.secure_endpoint.computer.connector_guid | The GUID of the connector, similar to top level connector_guid, but unique if multiple connectors are involved. | keyword |
| cisco.secure_endpoint.computer.external_ip | The external IP of the related host. | ip |
| cisco.secure_endpoint.computer.network_addresses | All network interface information on the related host. | flattened |
| cisco.secure_endpoint.connector_guid | The GUID of the connector sending information to AMP. | keyword |
| cisco.secure_endpoint.detection | The name of the malware detected. | keyword |
| cisco.secure_endpoint.detection_id | The ID of the detection. | keyword |
| cisco.secure_endpoint.error.description | Description of an endpoint error event. | keyword |
| cisco.secure_endpoint.error.error_code | The error code describing the related error event. | long |
| cisco.secure_endpoint.event_type_id | A sub ID of the event, depending on event type. | long |
| cisco.secure_endpoint.file.archived_file.disposition | Categorization of a file archive related to a file, for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.file.archived_file.identity.md5 | MD5 hash of the archived file related to the malicious event. | keyword |
| cisco.secure_endpoint.file.archived_file.identity.sha1 | SHA1 hash of the archived file related to the malicious event. | keyword |
| cisco.secure_endpoint.file.archived_file.identity.sha256 | SHA256 hash of the archived file related to the malicious event. | keyword |
| cisco.secure_endpoint.file.attack_details.application | The application name related to Exploit Prevention events. | keyword |
| cisco.secure_endpoint.file.attack_details.attacked_module | Path to the executable or dll that was attacked and detected by Exploit Prevention. | keyword |
| cisco.secure_endpoint.file.attack_details.base_address | The base memory address related to the exploit detected. | keyword |
| cisco.secure_endpoint.file.attack_details.indicators | Different indicator types that matches the exploit detected, for example different MITRE tactics. | flattened |
| cisco.secure_endpoint.file.attack_details.suspicious_files | An array of related files when an attack is detected by Exploit Prevention. | keyword |
| cisco.secure_endpoint.file.disposition | Categorization of file, for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.file.parent.disposition | Categorization of parrent, for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.group_guids | An array of group GUIDS related to the connector sending information to AMP. | keyword |
| cisco.secure_endpoint.network_info.disposition | Categorization of a network event related to a file, for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.network_info.nfm.direction | The current direction based on source and destination IP. | keyword |
| cisco.secure_endpoint.network_info.parent.disposition | Categorization of a IOC for example "Malicious" or "Clean". | keyword |
| cisco.secure_endpoint.network_info.parent.identify.sha256 | SHA256 hash of the related IOC. | keyword |
| cisco.secure_endpoint.network_info.parent.identity.md5 | MD5 hash of the related IOC. | keyword |
| cisco.secure_endpoint.network_info.parent.identity.sha1 | SHA1 hash of the related IOC. | keyword |
| cisco.secure_endpoint.related.cve | An array of all related CVEs | keyword |
| cisco.secure_endpoint.related.mac | An array of all related MAC addresses. | keyword |
| cisco.secure_endpoint.scan.clean | Boolean value if a scanned file was clean or not. | boolean |
| cisco.secure_endpoint.scan.description | Description of an event related to a scan being initiated, for example the specific directory name. | keyword |
| cisco.secure_endpoint.scan.malicious_detections | Count of malicious files or documents detected related to a single scan event. | long |
| cisco.secure_endpoint.scan.scanned_files | Count of files scanned in a directory. | long |
| cisco.secure_endpoint.scan.scanned_paths | Count of different directories scanned related to a single scan event. | long |
| cisco.secure_endpoint.scan.scanned_processes | Count of processes scanned related to a single scan event. | long |
| cisco.secure_endpoint.tactics | List of all MITRE tactics related to the incident found. | flattened |
| cisco.secure_endpoint.techniques | List of all MITRE techniques related to the incident found. | flattened |
| cisco.secure_endpoint.threat_hunting.incident_end_time | When the threat hunt finalized or closed. | date |
| cisco.secure_endpoint.threat_hunting.incident_hunt_guid | The GUID of the related investigation tracking issue. | keyword |
| cisco.secure_endpoint.threat_hunting.incident_id | The id of the related incident for the threat hunting activity. | long |
| cisco.secure_endpoint.threat_hunting.incident_remediation | Recommendations to resolve the vulnerability or exploited host. | keyword |
| cisco.secure_endpoint.threat_hunting.incident_report_guid | The GUID of the related threat hunting report. | keyword |
| cisco.secure_endpoint.threat_hunting.incident_start_time | When the threat hunt was initiated. | date |
| cisco.secure_endpoint.threat_hunting.incident_summary | Summary of the outcome on the threat hunting activity. | keyword |
| cisco.secure_endpoint.threat_hunting.incident_title | Title of the incident related to the threat hunting activity. | keyword |
| cisco.secure_endpoint.threat_hunting.severity | Severity result of the threat hunt registered to the malicious event. Can be Low-Critical. | keyword |
| cisco.secure_endpoint.threat_hunting.tactics | List of all MITRE tactics related to the incident found. | flattened |
| cisco.secure_endpoint.threat_hunting.techniques | List of all MITRE techniques related to the incident found. | flattened |
| cisco.secure_endpoint.timestamp_nanoseconds | The timestamp in Epoch nanoseconds. | date |
| cisco.secure_endpoint.vulnerabilities | An array of related vulnerabilities to the malicious event. | flattened |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |

