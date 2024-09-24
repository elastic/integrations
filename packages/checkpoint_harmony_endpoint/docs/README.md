# Check Point Harmony Endpoint

Harmony Endpoint EPMaaS (Endpoint Management as a Service) is the cloud service to manage policies and deployments for Endpoint Security. It provides advanced threat prevention and detection capabilities to safeguard endpoints from malware, ransomware, and other sophisticated attacks. The solution offers real-time protection through behavioral analysis, machine learning, and threat intelligence.

For details please refer to the [Harmony Endpoint Admin guide](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Harmony-Endpoint-Admin-Guide/Topics-HEP/Introduction.htm)

## Setup

### To collect data from Check Point Harmony Endpoint, the following parameters from your Harmony Endpoint instance are required:

1. Server URL
2. Client ID
3. Secret key

To use this integration generate an API Key. API key consists of Client ID and Secret Key. Users can create API Keys by browsing to Infinity Portal at GLOBAL SETTINGS > API Keys. When creating an API Key, make sure that Service is set to Logs as a Service.

To create an API key please refer to Check Point's [Infinity API Guide](https://app.swaggerhub.com/apis-docs/Check-Point/infinity-events-api/1.0.0#/Authentication/getAuthToken)

### Following are optional parameters which are used for fine-tuning:

1. Initial Interval: Initial interval for which existing logs will be pulled.
2. Interval: Interval at which new logs will be pulled.
3. Limit: Sets the number of results to return per API search query.
4. Page Limit: Sets the number of results to return per page, in API search query.

### Enabling Integration in Elastic

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Check Point Harmony Endpoint
3. Click on the "Check Point Harmony Endpoint" integration from the search results.
4. Click on the "Add Check Point Harmony Endpoint" button to add the integration.
5. Add all the required integration configuration parameters, such as Server URL, Client ID, Secret Key. For all data streams, these parameters must be provided in order to retrieve logs.
6. Save the integration.

## Data Streams:

1. **Anti-bot:** This is behavioral protection against bots. A single bot can create multiple threats. Cybercriminals often use bots in Advanced Persistent Threat (APT) attacks to target specific individuals or organizations.
2. **Anti-Malware:** Protects computers from viruses, spyware, and other malicious software. It uses real-time and scheduled scans to detect and neutralize threats before they can harm your computer.
3. **Forensics:** This component monitors file operations, processes, and network activity for suspicious behavior. It analyzes attacks detected by other client components or the Check Point Security Gateway and applies remediation to malicious files.
4. **Threat Emulation:** Detects zero-day and unknown attacks. Files on the endpoint computer are sent to a sandbox for emulation to uncover evasive zero-day attacks.
5. **Threat Extraction:** Proactively protects users from downloaded malicious files. It quickly delivers safe files while inspecting the originals for potential threats.
6. **URL Filtering:** Defines which websites are accessible within your organization. The URL Filtering policy consists of selected sites and the mode of operation applied to them.
7. **Zero-phishing:** Examines various website characteristics to ensure a site isn't impersonating another to maliciously collect personal information. It generates alerts for potential phishing sites.

## Logs Reference

### Anti-bot

This is `Anti-bot` dataset.

An example event for `antibot` looks as following:

```json
{
    "@timestamp": "2024-09-02T08:53:44.000Z",
    "agent": {
        "ephemeral_id": "aeee3c31-1817-417d-8faa-620891b9d47b",
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "checkpoint_harmony_endpoint": {
        "antibot": {
            "client": {
                "name": "Check Point Endpoint Security Client",
                "version": "88.50.0213"
            },
            "confidence_level": "Medium",
            "description": "Detected bot activity [Anti-Bot test.TC.e]. To exclude: On the Harmony Endpoint Management add an exclusion of type \"URL\" with value: \"http://www.threat-cloud.com/test/files/MediumConfidenceBot.html\"",
            "malware": {
                "action": "Communication with C&C"
            },
            "packet_capture_unique_id": "6c239c74-89a9-4797-ab6b-75a2b2a6afd7",
            "policy": {
                "date": "2024-08-29T13:12:51.0000000Z",
                "name": "Default Anti-Bot settings",
                "number": 2
            },
            "protection_type": "URL Reputation",
            "proxy_src_ip": "89.160.20.128",
            "severity": "Critical",
            "tenant_id": "3e15ed24-89ff-4986-a204-c425cee4ba48"
        }
    },
    "data_stream": {
        "dataset": "checkpoint_harmony_endpoint.antibot",
        "namespace": "61759",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "country_name": "UnitedStates"
        },
        "ip": "89.160.20.128"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "action": "Detect",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "checkpoint_harmony_endpoint.antibot",
        "id": "a4640108-91b1-0f19-66d5-7d9d00000000",
        "ingested": "2024-09-16T08:21:03Z",
        "kind": "alert",
        "module": "checkpoint_harmony_endpoint",
        "original": "{\"action\":\"Detect\",\"advanced_info\":\"\\\"exclusions\\\":[{\\\"exclusion_engine_type\\\":\\\"Anti Bot exclusions\\\",\\\"exclusion_type\\\":\\\"URL\\\",\\\"exclusion_value\\\":{\\\"default_value\\\":\\\"http://www.threat-cloud.com/test/files/MediumConfidenceBot.html\\\",\\\"md5\\\":\\\"\\\",\\\"original_name\\\":\\\"\\\",\\\"signer\\\":\\\"\\\",\\\"process\\\":\\\"\\\",\\\"protection\\\":\\\"\\\",\\\"comment\\\":\\\"\\\"}}]\",\"client_name\":\"Check Point Endpoint Security Client\",\"client_version\":[\"88.50.0213\"],\"confidence_level\":\"Medium\",\"description\":\"Detected bot activity [Anti-Bot test.TC.e]. To exclude: On the Harmony Endpoint Management add an exclusion of type \\\"URL\\\" with value: \\\"http://www.threat-cloud.com/test/files/MediumConfidenceBot.html\\\"\",\"domain\":\"SMC User\",\"dst\":\"89.160.20.128\",\"dst_country\":[\"UnitedStates\"],\"event_type\":\"Anti Bot Event\",\"file_md5\":\"bd075be9d011daaa82c3f9ff2572076e\",\"file_name\":[\"chrome.exe\"],\"file_size\":2742376,\"file_type\":\"exe\",\"host_type\":[\"Desktop\"],\"id\":\"a4640108-91b1-0f19-66d5-7d9d00000000\",\"installed_products\":\"Full Disk Encryption; Media Encryption \\u0026 Port Protection; Firewall; Compliance; Application Control; Anti-Malware; VPN; Anti-Bot; Forensics; Threat Emulation\",\"malware_action\":[\"Communication with C\\u0026C\"],\"orig\":\"164.100.1.8\",\"os_name\":[\"Microsoft Windows 10 Pro\"],\"os_version\":[\"10.0-19045-SP0.0-SMP\"],\"packet_capture\":\"Packet Capture\",\"packet_capture_unique_id\":\"6c239c74-89a9-4797-ab6b-75a2b2a6afd7\",\"policy_date\":\"2024-08-29T13:12:51.0000000Z\",\"policy_name\":\"Default Anti-Bot settings\",\"policy_number\":2,\"process_username\":\"admin\",\"product\":\"Anti-Bot\",\"product_family\":\"Endpoint\",\"protection_name\":\"Anti-Bot test.TC.e\",\"protection_type\":\"URL Reputation\",\"proxy_src_ip\":\"89.160.20.128\",\"resource\":[\"www.threat-cloud.com\"],\"sequencenum\":16777215,\"severity\":\"Critical\",\"src\":\"10.35.38.102\",\"src_machine_name\":\"DESKTOP-E2P4OL0\",\"src_user_name\":[\"admin\"],\"tenant_id\":\"3e15ed24-89ff-4986-a204-c425cee4ba48\",\"time\":\"2024-09-02T08:53:44Z\",\"type\":\"Log\",\"user_sid\":\"S-1-5-21-3766288932-3295778425-2939962592-1001\"}",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "md5": "bd075be9d011daaa82c3f9ff2572076e"
        },
        "size": 2742376,
        "type": "exe"
    },
    "host": {
        "hostname": "DESKTOP-E2P4OL0",
        "ip": [
            "10.35.38.102"
        ],
        "name": "DESKTOP-E2P4OL0",
        "os": {
            "name": "Microsoft Windows 10 Pro",
            "version": "10.0-19045-SP0.0-SMP"
        },
        "type": [
            "Desktop"
        ]
    },
    "input": {
        "type": "cel"
    },
    "process": {
        "user": {
            "name": "admin"
        }
    },
    "rule": {
        "name": "Anti-Bot test.TC.e"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "url": {
        "original": "www.threat-cloud.com"
    },
    "user": {
        "domain": "SMC User",
        "id": "S-1-5-21-3766288932-3295778425-2939962592-1001",
        "name": [
            "admin"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint_harmony_endpoint.antibot.attack_status | Status of attack | keyword |
| checkpoint_harmony_endpoint.antibot.client.name | Can be either Check Point Endpoint Security Client or Check Point Capsule Docs Client | keyword |
| checkpoint_harmony_endpoint.antibot.client.version | Build version of Harmony Endpoint client installed on the computer | version |
| checkpoint_harmony_endpoint.antibot.confidence_level | Confidence level | keyword |
| checkpoint_harmony_endpoint.antibot.description | Details of the event | text |
| checkpoint_harmony_endpoint.antibot.detected_by | Component which detected Event | keyword |
| checkpoint_harmony_endpoint.antibot.malware.action | Description of detected malware activity | keyword |
| checkpoint_harmony_endpoint.antibot.packet_capture_unique_id | Unique Packet Capture ID | keyword |
| checkpoint_harmony_endpoint.antibot.policy.date | Date of policy | date |
| checkpoint_harmony_endpoint.antibot.policy.name | Name of policy | keyword |
| checkpoint_harmony_endpoint.antibot.policy.number | Version number of policy | integer |
| checkpoint_harmony_endpoint.antibot.protection_type | Source of detection - can be IOC when manually configured, or URL/IP/CMI Reputation | keyword |
| checkpoint_harmony_endpoint.antibot.proxy_src_ip | Address where traffic was sent | ip |
| checkpoint_harmony_endpoint.antibot.service_domain | Service Domain Name | keyword |
| checkpoint_harmony_endpoint.antibot.severity | Event severity | keyword |
| checkpoint_harmony_endpoint.antibot.suspicious_events | ID of EFR report, if relevant/exists | text |
| checkpoint_harmony_endpoint.antibot.tenant_id | Tenant ID | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |


### Anti-Malware

This is `Anti-Malware` dataset.

An example event for `antimalware` looks as following:

```json
{
    "@timestamp": "2024-09-02T09:09:07.000Z",
    "agent": {
        "ephemeral_id": "46a5bde6-7c5a-4e1c-b397-13ce60845776",
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "checkpoint_harmony_endpoint": {
        "antimalware": {
            "action_details": "Infected",
            "client": {
                "name": "Check Point Endpoint Security Client",
                "version": "88.50.0213"
            },
            "confidence_level": "High",
            "connectivity_state": "Connected",
            "malware": {
                "category": "Malware"
            },
            "packet_capture_unique_id": "31dc576b-7192-49bf-b2fc-b40c93f84b7c",
            "policy": {
                "date": "2024-08-29T13:12:46.0000000Z",
                "name": "Default Anti-Malware settings for the entire organization",
                "number": 3
            },
            "protection_type": "Protection",
            "severity": "High",
            "tenant_id": "3e15ed24-89ff-4986-a204-c425cee4ba48"
        }
    },
    "data_stream": {
        "dataset": "checkpoint_harmony_endpoint.antimalware",
        "namespace": "59852",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "action": "Detect",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "checkpoint_harmony_endpoint.antimalware",
        "id": "a4640108-91b1-0f19-66d5-815d0000000f",
        "ingested": "2024-09-16T08:22:15Z",
        "module": "checkpoint_harmony_endpoint",
        "original": "{\"action\":\"Detect\",\"action_details\":\"Infected\",\"advanced_info\":\"\\\"exclusions\\\":[{\\\"exclusion_engine_type\\\":\\\"File \\u0026 Folder exclusions (system, scheduled and on-demand)\\\",\\\"exclusion_type\\\":\\\"Path\\\",\\\"exclusion_value\\\":{\\\"default_value\\\":\\\"md5:\\\",\\\"md5\\\":\\\"\\\",\\\"original_name\\\":\\\"\\\",\\\"signer\\\":\\\"\\\",\\\"process\\\":\\\"\\\",\\\"protection\\\":\\\"\\\",\\\"comment\\\":\\\"md5 taken from file C:\\\\\\\\Users\\\\\\\\admin\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\\\\\9e68140d-22bb-4e96-8aaa-70ec80eb2dc4.tmp\\\"}}]\",\"client_name\":\"Check Point Endpoint Security Client\",\"client_version\":[\"88.50.0213\"],\"confidence_level\":\"High\",\"connectivity_state\":\"Connected\",\"domain\":\"SMC User\",\"engine_ver\":\"3.90\",\"event_type\":\"Infection\",\"file_name\":[\"9e68140d-22bb-4e96-8aaa-70ec80eb2dc4.tmp\"],\"host_type\":[\"Desktop\"],\"id\":\"a4640108-91b1-0f19-66d5-815d0000000f\",\"infection_category\":\"Malware\",\"installed_products\":\"Full Disk Encryption; Media Encryption \\u0026 Port Protection; Firewall; Compliance; Application Control; Anti-Malware; VPN; Anti-Bot; Forensics; Threat Emulation\",\"orig\":\"164.100.1.8\",\"os_name\":[\"Microsoft Windows 10 Pro\"],\"os_version\":[\"10.0-19045-SP0.0-SMP\"],\"packet_capture\":\"Packet Capture\",\"packet_capture_unique_id\":\"31dc576b-7192-49bf-b2fc-b40c93f84b7c\",\"policy_date\":\"2024-08-29T13:12:46.0000000Z\",\"policy_name\":\"Default Anti-Malware settings for the entire organization\",\"policy_number\":3,\"product\":\"Anti-Malware\",\"product_family\":\"Endpoint\",\"protection_name\":\"Mal/ShellDl-A\",\"protection_type\":\"Protection\",\"sequencenum\":16777215,\"severity\":\"High\",\"sig_ver\":\"202409011444\",\"src\":\"10.35.38.102\",\"src_machine_name\":\"DESKTOP-E2P4OL0\",\"src_user_name\":[\"admin\"],\"tenant_id\":\"3e15ed24-89ff-4986-a204-c425cee4ba48\",\"time\":\"2024-09-02T09:09:07Z\",\"type\":\"Log\",\"user_sid\":\"S-1-5-21-3766288932-3295778425-2939962592-1001\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "DESKTOP-E2P4OL0",
        "ip": [
            "10.35.38.102"
        ],
        "name": "DESKTOP-E2P4OL0",
        "os": {
            "name": "Microsoft Windows 10 Pro",
            "version": "10.0-19045-SP0.0-SMP"
        },
        "type": [
            "Desktop"
        ]
    },
    "input": {
        "type": "cel"
    },
    "rule": {
        "name": "Mal/ShellDl-A"
    },
    "source": {
        "ip": [
            "10.35.38.102"
        ]
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "domain": "SMC User",
        "id": "S-1-5-21-3766288932-3295778425-2939962592-1001",
        "name": [
            "admin"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint_harmony_endpoint.antimalware.action_details | Malware action details | keyword |
| checkpoint_harmony_endpoint.antimalware.attack_status | Status of attack | keyword |
| checkpoint_harmony_endpoint.antimalware.client.name | Can be either Check Point Endpoint Security Client or Check Point Capsule Docs Client | keyword |
| checkpoint_harmony_endpoint.antimalware.client.version | Build version of Harmony Endpoint client installed on the computer | version |
| checkpoint_harmony_endpoint.antimalware.confidence_level | Confidence level | keyword |
| checkpoint_harmony_endpoint.antimalware.connectivity_state | Type of currently applied AM policy (Connected/Disconnected/Restricted) | keyword |
| checkpoint_harmony_endpoint.antimalware.description | Details of the event | text |
| checkpoint_harmony_endpoint.antimalware.detected_by | Component which detected Event | keyword |
| checkpoint_harmony_endpoint.antimalware.malware.category | Malware category | keyword |
| checkpoint_harmony_endpoint.antimalware.packet_capture_unique_id | Unique Packet Capture ID | keyword |
| checkpoint_harmony_endpoint.antimalware.policy.date | Date of policy | date |
| checkpoint_harmony_endpoint.antimalware.policy.name | Name of policy | keyword |
| checkpoint_harmony_endpoint.antimalware.policy.number | Version number of policy | integer |
| checkpoint_harmony_endpoint.antimalware.protection_type | Source of detection - can be IOC when manually configured, or URL/IP/CMI Reputation | keyword |
| checkpoint_harmony_endpoint.antimalware.proxy_src_ip | Address where traffic was sent | ip |
| checkpoint_harmony_endpoint.antimalware.service_domain | Service Domain Name | keyword |
| checkpoint_harmony_endpoint.antimalware.severity | Event severity | keyword |
| checkpoint_harmony_endpoint.antimalware.suspicious_events | Identified suspicious events | text |
| checkpoint_harmony_endpoint.antimalware.tenant_id | Tenant ID | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |


### Forensics
This is `Forensics` dataset.

An example event for `forensics` looks as following:

```json
{
    "@timestamp": "2024-09-03T08:53:12.000Z",
    "agent": {
        "ephemeral_id": "f8766356-0f75-4477-9d7f-97bdb33e142f",
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "checkpoint_harmony_endpoint": {
        "forensics": {
            "attack_status": "Dormant",
            "client": {
                "name": "Check Point Endpoint Security Client",
                "version": "88.50.0213"
            },
            "confidence_level": "High",
            "description": "To exclude the file: On the Harmony Endpoint Management add this sha1 exclusion: 62f0bd56-b0e1235b-99940b34-916c19ec-fac8e80c Attack status: Dormant.",
            "detected_by": "Endpoint File Reputation",
            "malware": {},
            "packet_capture_unique_id": "0acd55a9-f241-4097-a699-6b7e41cd26af",
            "policy": {
                "date": "2024-09-02T06:23:25.0000000Z",
                "name": "Default Forensics settings",
                "number": 3
            },
            "protection_type": "File Reputation",
            "service_domain": "ep-demo",
            "severity": "Critical",
            "suspicious_events": "System Shutdown / Reboot: ; ",
            "tenant_id": "3e15ed24-89ff-4986-a204-c425cee4ba48"
        }
    },
    "data_stream": {
        "dataset": "checkpoint_harmony_endpoint.forensics",
        "namespace": "19896",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "action": "Detect",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "checkpoint_harmony_endpoint.forensics",
        "id": "a4640108-91b1-0f19-66d6-ceb500000000",
        "ingested": "2024-09-16T08:23:26Z",
        "kind": "alert",
        "module": "checkpoint_harmony_endpoint",
        "original": "{\"action\":\"Detect\",\"attack_status\":\"Dormant\",\"client_name\":\"Check Point Endpoint Security Client\",\"client_version\":[\"88.50.0213\"],\"confidence_level\":\"High\",\"description\":\"To exclude the file: On the Harmony Endpoint Management add this sha1 exclusion: 62f0bd56-b0e1235b-99940b34-916c19ec-fac8e80c Attack status: Dormant.\",\"detected_by\":\"Endpoint File Reputation\",\"domain\":\"SMC User\",\"event_type\":\"Forensics Case Analysis\",\"file_md5\":\"1468c1908845ef238f7f196809946288\",\"file_name\":[\"malz5.zip\"],\"file_sha1\":\"62f0bd56b0e1235b99940b34916c19ecfac8e80c\",\"file_size\":12707198,\"file_type\":\"zip\",\"host_type\":[\"Desktop\"],\"id\":\"a4640108-91b1-0f19-66d6-ceb500000000\",\"installed_products\":\"Full Disk Encryption; Media Encryption \\u0026 Port Protection; Firewall; Compliance; Application Control; Anti-Malware; VPN; Anti-Bot; Forensics; Threat Emulation\",\"malware_action\":[\" \"],\"orig\":\"164.100.1.8\",\"os_name\":[\"Microsoft Windows 10 Pro\"],\"os_version\":[\"10.0-19045-SP0.0-SMP\"],\"packet_capture\":\"Packet Capture\",\"packet_capture_unique_id\":\"0acd55a9-f241-4097-a699-6b7e41cd26af\",\"policy_date\":\"2024-09-02T06:23:25.0000000Z\",\"policy_name\":\"Default Forensics settings\",\"policy_number\":3,\"product\":\"Forensics\",\"product_family\":\"Endpoint\",\"protection_name\":\"Gen.Rep.zip\",\"protection_type\":\"File Reputation\",\"remediated_files\":\"malz5.zip(Remediation disabled in policy)\",\"resource\":[\"c:\\\\users\\\\admin\\\\downloads\\\\malz5.zip\"],\"sequencenum\":1,\"service_domain\":\"ep-demo\",\"severity\":\"Critical\",\"src\":\"10.35.38.102\",\"src_machine_name\":\"DESKTOP-E2P4OL0\",\"src_user_name\":[\"admin\"],\"suspicious_events\":\"System Shutdown / Reboot: ; \",\"tenant_id\":\"3e15ed24-89ff-4986-a204-c425cee4ba48\",\"time\":\"2024-09-03T08:53:12.000001Z\",\"type\":\"Log\",\"user_sid\":\"S-1-5-21-3766288932-3295778425-2939962592-1001\"}",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "md5": "1468c1908845ef238f7f196809946288",
            "sha1": "62f0bd56b0e1235b99940b34916c19ecfac8e80c"
        },
        "path": "c:\\users\\admin\\downloads\\malz5.zip",
        "size": 12707198,
        "type": "zip"
    },
    "host": {
        "hostname": "DESKTOP-E2P4OL0",
        "ip": [
            "10.35.38.102"
        ],
        "name": "DESKTOP-E2P4OL0",
        "os": {
            "name": "Microsoft Windows 10 Pro",
            "version": "10.0-19045-SP0.0-SMP"
        },
        "type": [
            "Desktop"
        ]
    },
    "input": {
        "type": "cel"
    },
    "rule": {
        "name": "Gen.Rep.zip"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "domain": "SMC User",
        "id": "S-1-5-21-3766288932-3295778425-2939962592-1001",
        "name": [
            "admin"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint_harmony_endpoint.forensics.attack_status | Status of attack | keyword |
| checkpoint_harmony_endpoint.forensics.client.name | Can be either Check Point Endpoint Security Client or Check Point Capsule Docs Client | keyword |
| checkpoint_harmony_endpoint.forensics.client.version | Build version of Harmony Endpoint client installed on the computer | version |
| checkpoint_harmony_endpoint.forensics.confidence_level | Confidence level | keyword |
| checkpoint_harmony_endpoint.forensics.description | Details of the event | text |
| checkpoint_harmony_endpoint.forensics.detected_by | Component which detected Event | keyword |
| checkpoint_harmony_endpoint.forensics.malware.action | Malware action | keyword |
| checkpoint_harmony_endpoint.forensics.packet_capture_unique_id | ID of EFR report | keyword |
| checkpoint_harmony_endpoint.forensics.policy.date | Date of policy | date |
| checkpoint_harmony_endpoint.forensics.policy.name | Name of policy | keyword |
| checkpoint_harmony_endpoint.forensics.policy.number | Version number of policy | integer |
| checkpoint_harmony_endpoint.forensics.protection_type | Source of detection - can be IOC when manually configured, or URL/IP/CMI Reputation | keyword |
| checkpoint_harmony_endpoint.forensics.service_domain | Service Domain Name | keyword |
| checkpoint_harmony_endpoint.forensics.severity | Event severity | keyword |
| checkpoint_harmony_endpoint.forensics.suspicious_events | Events that lead to the trigger | text |
| checkpoint_harmony_endpoint.forensics.tenant_id | Tenant ID | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |


### Threat Emulation
This is `Threat Emulation` dataset.

An example event for `threatemulation` looks as following:

```json
{
    "@timestamp": "2024-09-02T09:04:54.000Z",
    "agent": {
        "ephemeral_id": "6f327f74-1823-4730-8a42-a12ecff65ae2",
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "checkpoint_harmony_endpoint": {
        "threatemulation": {
            "advanced_info": "\"exclusions\":[{\"exclusion_engine_type\":\"Threat Emulation, Extraction and Zero Phishing Exclusions\",\"exclusion_type\":\"SHA1\",\"exclusion_value\":{\"default_value\":\"9d3395d94c6bbba52abf0e6afcbf4ca312597c21\",\"md5\":\"\",\"original_name\":\"\",\"signer\":\"\",\"process\":\"\",\"protection\":\"\",\"comment\":\"\"}}]",
            "analyzed_on": "Check Point Threat Emulation Cloud",
            "client": {
                "name": "Check Point Endpoint Security Client",
                "version": "88.50.0213"
            },
            "confidence_level": "High",
            "description": "Endpoint TE detected malicious file (681573a2-414a-4f7d-9683-177df4f8ca7f.tmp) . To exclude the file: On the Harmony Endpoint Management add this sha1 exclusion: 9d3395d9-4c6bbba5-2abf0e6a-fcbf4ca3-12597c21",
            "incident_uid": "74a33ecb-1b91-4c25-a136-1989eb175638",
            "malware": {
                "action": "Adware\",\"Solimba\",\"Trojan\",\"behavior"
            },
            "packet_capture_unique_id": "5e3302e5-3f73-4b77-beec-2849003e9d47",
            "policy": {
                "date": "2024-08-29T13:12:50.0000000Z",
                "name": "Default Threat Extraction, Emulation and Anti-Exploit settings for the entire organization",
                "number": 3
            },
            "protection_type": "File System Emulation",
            "severity": "Critical",
            "tenant_id": "3e15ed24-89ff-4986-a204-c425cee4ba48",
            "verdict": "Malicious"
        }
    },
    "data_stream": {
        "dataset": "checkpoint_harmony_endpoint.threatemulation",
        "namespace": "27154",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "action": "Detect",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "checkpoint_harmony_endpoint.threatemulation",
        "id": "a4640108-91b1-0f19-66d5-803100000012",
        "ingested": "2024-09-16T08:24:37Z",
        "kind": "alert",
        "module": "checkpoint_harmony_endpoint",
        "original": "{\"action\":\"Detect\",\"advanced_info\":\"\\\"exclusions\\\":[{\\\"exclusion_engine_type\\\":\\\"Threat Emulation, Extraction and Zero Phishing Exclusions\\\",\\\"exclusion_type\\\":\\\"SHA1\\\",\\\"exclusion_value\\\":{\\\"default_value\\\":\\\"9d3395d94c6bbba52abf0e6afcbf4ca312597c21\\\",\\\"md5\\\":\\\"\\\",\\\"original_name\\\":\\\"\\\",\\\"signer\\\":\\\"\\\",\\\"process\\\":\\\"\\\",\\\"protection\\\":\\\"\\\",\\\"comment\\\":\\\"\\\"}}]\",\"analyzed_on\":\"Check Point Threat Emulation Cloud\",\"client_name\":\"Check Point Endpoint Security Client\",\"client_version\":[\"88.50.0213\"],\"confidence_level\":\"High\",\"description\":\"Endpoint TE detected malicious file (681573a2-414a-4f7d-9683-177df4f8ca7f.tmp) . To exclude the file: On the Harmony Endpoint Management add this sha1 exclusion: 9d3395d9-4c6bbba5-2abf0e6a-fcbf4ca3-12597c21\",\"domain\":\"SMC User\",\"event_type\":\"TE Event\",\"file_md5\":\"ebe8b633d231bbfee9543d744a2ab59d\",\"file_name\":[\"681573a2-414a-4f7d-9683-177df4f8ca7f.tmp\"],\"file_sha1\":\"9d3395d94c6bbba52abf0e6afcbf4ca312597c21\",\"file_size\":139648,\"file_type\":\"zip\",\"host_type\":[\"Desktop\"],\"id\":\"a4640108-91b1-0f19-66d5-803100000012\",\"incident_uid\":\"74a33ecb-1b91-4c25-a136-1989eb175638\",\"installed_products\":\"Full Disk Encryption; Media Encryption \\u0026 Port Protection; Firewall; Compliance; Application Control; Anti-Malware; VPN; Anti-Bot; Forensics; Threat Emulation\",\"malware_action\":[\"Adware\\\",\\\"Solimba\\\",\\\"Trojan\\\",\\\"behavior\"],\"orig\":\"164.100.1.8\",\"os_name\":[\"Microsoft Windows 10 Pro\"],\"os_version\":[\"10.0-19045-SP0.0-SMP\"],\"packet_capture\":\"Packet Capture\",\"packet_capture_unique_id\":\"5e3302e5-3f73-4b77-beec-2849003e9d47\",\"policy_date\":\"2024-08-29T13:12:50.0000000Z\",\"policy_name\":\"Default Threat Extraction, Emulation and Anti-Exploit settings for the entire organization\",\"policy_number\":3,\"product\":\"Threat Emulation\",\"product_family\":\"Endpoint\",\"protection_name\":\"Gen.SB.zip\",\"protection_type\":\"File System Emulation\",\"resource\":[\"C:\\\\Users\\\\admin\\\\Downloads\\\\681573a2-414a-4f7d-9683-177df4f8ca7f.tmp\"],\"sequencenum\":16777215,\"severity\":\"Critical\",\"src\":\"10.35.38.102\",\"src_machine_name\":\"DESKTOP-E2P4OL0\",\"src_user_name\":[\"admin\"],\"tenant_id\":\"3e15ed24-89ff-4986-a204-c425cee4ba48\",\"time\":\"2024-09-02T09:04:54Z\",\"type\":\"Log\",\"user_sid\":\"S-1-5-21-3766288932-3295778425-2939962592-1001\",\"verdict\":\"Malicious\",\"web_client_type\":[\" \"]}",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "md5": "ebe8b633d231bbfee9543d744a2ab59d",
            "sha1": "9d3395d94c6bbba52abf0e6afcbf4ca312597c21"
        },
        "path": "C:\\Users\\admin\\Downloads\\681573a2-414a-4f7d-9683-177df4f8ca7f.tmp",
        "size": 139648,
        "type": "zip"
    },
    "host": {
        "hostname": "DESKTOP-E2P4OL0",
        "ip": [
            "10.35.38.102"
        ],
        "name": "DESKTOP-E2P4OL0",
        "os": {
            "name": "Microsoft Windows 10 Pro",
            "version": "10.0-19045-SP0.0-SMP"
        },
        "type": [
            "Desktop"
        ]
    },
    "input": {
        "type": "cel"
    },
    "rule": {
        "name": "Gen.SB.zip"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "domain": "SMC User",
        "id": "S-1-5-21-3766288932-3295778425-2939962592-1001",
        "name": [
            "admin"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint_harmony_endpoint.threatemulation.advanced_info | Internal field used for configuring exclusions | text |
| checkpoint_harmony_endpoint.threatemulation.analyzed_on | Asset used for emulation - can be "Check Point Threat Emulation Cloud", "Check Point Appliance", or "Harmony Local Cache" | keyword |
| checkpoint_harmony_endpoint.threatemulation.client.name | Can be either Check Point Endpoint Security Client or Check Point Capsule Docs Client | keyword |
| checkpoint_harmony_endpoint.threatemulation.client.version | Build version of Harmony Endpoint client installed on the computer | version |
| checkpoint_harmony_endpoint.threatemulation.confidence_level | Can be Low/Medium/High/N-A | keyword |
| checkpoint_harmony_endpoint.threatemulation.description | Details of the event | text |
| checkpoint_harmony_endpoint.threatemulation.incident_uid | ID of EFR report, if relevant/exists | keyword |
| checkpoint_harmony_endpoint.threatemulation.malware.action | Additional info about malware category or actions that led to detection | keyword |
| checkpoint_harmony_endpoint.threatemulation.packet_capture_unique_id | ID of EFR report, if relevant/exists | keyword |
| checkpoint_harmony_endpoint.threatemulation.policy.date | Date of policy | date |
| checkpoint_harmony_endpoint.threatemulation.policy.name | Name of policy | keyword |
| checkpoint_harmony_endpoint.threatemulation.policy.number | Version number of policy | integer |
| checkpoint_harmony_endpoint.threatemulation.protection_type | Type of detection | keyword |
| checkpoint_harmony_endpoint.threatemulation.severity | Event severity | keyword |
| checkpoint_harmony_endpoint.threatemulation.tenant_id | Tenant ID | keyword |
| checkpoint_harmony_endpoint.threatemulation.verdict | Can be Malicious/Benign | keyword |
| checkpoint_harmony_endpoint.threatemulation.web_client_type | When relevant, name of the browser (Chrome, Edge, …) | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |


### Threat Extraction
This is `Threat Extraction` dataset.

An example event for `threatextraction` looks as following:

```json
{
    "@timestamp": "2024-09-02T09:21:42.000Z",
    "agent": {
        "ephemeral_id": "ea319773-7ec0-4067-9c87-1753b46a2d59",
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "checkpoint_harmony_endpoint": {
        "threatextraction": {
            "advanced_info": " \"disable_exclusion\": true ",
            "client": {
                "name": "Check Point Endpoint Security Client",
                "version": "88.50.0213"
            },
            "confidence_level": "High",
            "description": "File is not supported for extraction",
            "malware": {
                "action": "Not Supported"
            },
            "policy": {
                "date": "2024-08-29T13:12:50.0000000Z",
                "name": "Default Threat Extraction, Emulation and Anti-Exploit settings for the entire organization",
                "number": 3
            },
            "protection_type": "Content Removal",
            "severity": "Informational",
            "tenant_id": "3e15ed24-89ff-4986-a204-c425cee4ba48",
            "web_client_type": "Chrome"
        }
    },
    "data_stream": {
        "dataset": "checkpoint_harmony_endpoint.threatextraction",
        "namespace": "30748",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "action": "Extract",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "checkpoint_harmony_endpoint.threatextraction",
        "id": "a4640108-91b1-0f19-66d5-83f100000019",
        "ingested": "2024-09-16T08:25:48Z",
        "kind": "alert",
        "module": "checkpoint_harmony_endpoint",
        "original": "{\"action\":\"Extract\",\"advanced_info\":\" \\\"disable_exclusion\\\": true \",\"client_name\":\"Check Point Endpoint Security Client\",\"client_version\":[\"88.50.0213\"],\"confidence_level\":\"High\",\"description\":\"File is not supported for extraction\",\"domain\":\"SMC User\",\"event_type\":\"TEX Event\",\"extension_version\":\" 990.97.911 \",\"file_name\":[\"mirai.sh4\"],\"file_sha1\":\"no-sha1\",\"file_size\":0,\"file_type\":\"sh4\",\"host_type\":[\"Desktop\"],\"id\":\"a4640108-91b1-0f19-66d5-83f100000019\",\"installed_products\":\"Full Disk Encryption; Media Encryption \\u0026 Port Protection; Firewall; Compliance; Application Control; Anti-Malware; VPN; Anti-Bot; Forensics; Threat Emulation\",\"malware_action\":[\"Not Supported\"],\"orig\":\"164.100.1.8\",\"os_name\":[\"Microsoft Windows 10 Pro\"],\"os_version\":[\"10.0-19045-SP0.0-SMP\"],\"policy_date\":\"2024-08-29T13:12:50.0000000Z\",\"policy_name\":\"Default Threat Extraction, Emulation and Anti-Exploit settings for the entire organization\",\"policy_number\":3,\"product\":\"Threat Extraction\",\"product_family\":\"Endpoint\",\"protection_name\":\"Extract potentially malicious content\",\"protection_type\":\"Content Removal\",\"resource\":[\"blob:https://github.com/6bd30ea7-29a8-4dd2-9056-f5077632e110\"],\"sequencenum\":1,\"severity\":\"Informational\",\"src\":\"10.35.38.102\",\"src_machine_name\":\"DESKTOP-E2P4OL0\",\"src_user_name\":[\"admin\"],\"tenant_id\":\"3e15ed24-89ff-4986-a204-c425cee4ba48\",\"time\":\"2024-09-02T09:21:42.000001Z\",\"type\":\"Log\",\"user_sid\":\"S-1-5-21-3766288932-3295778425-2939962592-1001\",\"web_client_type\":[\"Chrome\"]}",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {
            "sha1": "no-sha1"
        },
        "path": "blob:https://github.com/6bd30ea7-29a8-4dd2-9056-f5077632e110",
        "size": 0,
        "type": "sh4"
    },
    "host": {
        "hostname": "DESKTOP-E2P4OL0",
        "ip": [
            "10.35.38.102"
        ],
        "name": "DESKTOP-E2P4OL0",
        "os": {
            "name": "Microsoft Windows 10 Pro",
            "version": "10.0-19045-SP0.0-SMP"
        },
        "type": [
            "Desktop"
        ]
    },
    "input": {
        "type": "cel"
    },
    "rule": {
        "name": "Extract potentially malicious content"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "domain": "SMC User",
        "id": "S-1-5-21-3766288932-3295778425-2939962592-1001",
        "name": [
            "admin"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint_harmony_endpoint.threatextraction.advanced_info | Internal field used for configuring exclusions | text |
| checkpoint_harmony_endpoint.threatextraction.analyzed_on | Describes location where threat is analyzed. | keyword |
| checkpoint_harmony_endpoint.threatextraction.client.name | Can be either Check Point Endpoint Security Client or Check Point Capsule Docs Client | keyword |
| checkpoint_harmony_endpoint.threatextraction.client.version | Build version of Harmony Endpoint client installed on the computer | version |
| checkpoint_harmony_endpoint.threatextraction.confidence_level | Can be Low/Medim/High/N-A | keyword |
| checkpoint_harmony_endpoint.threatextraction.description | Details of the event | text |
| checkpoint_harmony_endpoint.threatextraction.incident_uid | ID of EFR report, if relevant/exists | keyword |
| checkpoint_harmony_endpoint.threatextraction.malware.action | Additional info about the extraction - can be Extracted, Verified, Oversized, Not Supported, Corrupted file | keyword |
| checkpoint_harmony_endpoint.threatextraction.policy.date | Date of policy | date |
| checkpoint_harmony_endpoint.threatextraction.policy.name | Name of policy | keyword |
| checkpoint_harmony_endpoint.threatextraction.policy.number | Version number of policy | integer |
| checkpoint_harmony_endpoint.threatextraction.protection_type | Type of detection | keyword |
| checkpoint_harmony_endpoint.threatextraction.severity | Event severity | keyword |
| checkpoint_harmony_endpoint.threatextraction.tenant_id | Tenant ID | keyword |
| checkpoint_harmony_endpoint.threatextraction.web_client_type | When relevant, name of the browser (Chrome, Edge, …) | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |


### URL Filtering
This is `URL Filtering` dataset.

An example event for `urlfiltering` looks as following:

```json
{
    "@timestamp": "2024-09-06T10:07:43.000Z",
    "agent": {
        "ephemeral_id": "13d1fa6c-064b-49ec-832a-957964c868ac",
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "checkpoint_harmony_endpoint": {
        "urlfiltering": {
            "advanced_info": "\"exclusions\":[{\"exclusion_engine_type\":\"URL Filtering exclusions\",\"exclusion_type\":\"Domain\",\"exclusion_value\":{\"default_value\":\"secure.indeed.com\",\"md5\":\"\",\"original_name\":\"\",\"signer\":\"\",\"process\":\"\",\"protection\":\"\",\"comment\":\"\"}}]",
            "app": {
                "id": "0",
                "properties": "Job Search / Careers, Business / Economy"
            },
            "appi_name": "secure.indeed.com",
            "client": {
                "name": "Check Point Endpoint Security Client",
                "version": "88.50.0213"
            },
            "description": "URLF Info Event",
            "event_type": "URLF Info Event",
            "matched_category": "Job Search / Careers",
            "policy": {
                "date": "2024-09-06T09:57:28.0000000Z",
                "name": "Default Anti-Bot settings",
                "number": 4
            },
            "process_exe_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "protection_type": "URL Filtering",
            "severity": "Informational",
            "tenant_id": "3e15ed24-89ff-4986-a204-c425cee4ba48",
            "usercheck_incident_uid": "b04d8940",
            "web_client_type": "Chrome"
        }
    },
    "data_stream": {
        "dataset": "checkpoint_harmony_endpoint.urlfiltering",
        "namespace": "83352",
        "type": "logs"
    },
    "destination": {
        "ip": "0.0.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "action": "Detect",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "checkpoint_harmony_endpoint.urlfiltering",
        "id": "a4640108-91b1-0f19-66da-d62100000013",
        "ingested": "2024-09-16T08:26:57Z",
        "kind": "alert",
        "module": "checkpoint_harmony_endpoint",
        "original": "{\"action\":\"Detect\",\"advanced_info\":\"\\\"exclusions\\\":[{\\\"exclusion_engine_type\\\":\\\"URL Filtering exclusions\\\",\\\"exclusion_type\\\":\\\"Domain\\\",\\\"exclusion_value\\\":{\\\"default_value\\\":\\\"secure.indeed.com\\\",\\\"md5\\\":\\\"\\\",\\\"original_name\\\":\\\"\\\",\\\"signer\\\":\\\"\\\",\\\"process\\\":\\\"\\\",\\\"protection\\\":\\\"\\\",\\\"comment\\\":\\\"\\\"}}]\",\"app_id\":\"0\",\"app_properties\":[\"Job Search / Careers, Business / Economy\"],\"appi_name\":\"secure.indeed.com\",\"client_name\":\"Check Point Endpoint Security Client\",\"client_version\":[\"88.50.0213\"],\"description\":\"URLF Info Event\",\"domain\":\"SMC User\",\"dst\":\"0.0.0.0\",\"event_type\":\"URLF Info Event\",\"host_type\":[\"Desktop\"],\"id\":\"a4640108-91b1-0f19-66da-d62100000013\",\"installed_products\":\"Full Disk Encryption; Media Encryption \\u0026 Port Protection; Firewall; Compliance; Application Control; Anti-Malware; VPN; Anti-Bot; Forensics; Threat Emulation\",\"matched_category\":\"Job Search / Careers\",\"orig\":\"164.100.1.8\",\"os_name\":[\"Microsoft Windows 10 Pro\"],\"os_version\":[\"10.0-19045-SP0.0-SMP\"],\"policy_date\":\"2024-09-06T09:57:28.0000000Z\",\"policy_name\":\"Default Anti-Bot settings\",\"policy_number\":4,\"process_exe_path\":\"C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe\",\"product\":\"URL Filtering\",\"product_family\":\"Endpoint\",\"protection_name\":\"gen.urlf\",\"protection_type\":\"URL Filtering\",\"resource\":[\"https://secure.indeed.com/auth?branding=save-profile-modal\\u0026tmpl=inline\\u0026from=act_zeroauth_profile_tst\\u0026iframe_tk=9a019527-a6f1-4b3d-b803-2b25bb46b1db\\u0026hl=en_IN\\u0026co=IN\"],\"sequencenum\":16777215,\"severity\":\"Informational\",\"src\":\"10.35.38.102\",\"src_machine_name\":\"DESKTOP-E2P4OL0\",\"src_user_name\":[\"admin\"],\"tenant_id\":\"3e15ed24-89ff-4986-a204-c425cee4ba48\",\"time\":\"2024-09-06T10:07:43Z\",\"type\":\"Log\",\"user_sid\":\"S-1-5-21-3766288932-3295778425-2939962592-1001\",\"usercheck_incident_uid\":\"b04d8940\",\"web_client_type\":[\"Chrome\"]}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "DESKTOP-E2P4OL0",
        "ip": [
            "10.35.38.102"
        ],
        "name": "DESKTOP-E2P4OL0",
        "os": {
            "name": "Microsoft Windows 10 Pro",
            "version": "10.0-19045-SP0.0-SMP"
        },
        "type": [
            "Desktop"
        ]
    },
    "input": {
        "type": "cel"
    },
    "rule": {
        "name": "gen.urlf"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "url": {
        "domain": "secure.indeed.com",
        "original": "https://secure.indeed.com/auth?branding=save-profile-modal&tmpl=inline&from=act_zeroauth_profile_tst&iframe_tk=9a019527-a6f1-4b3d-b803-2b25bb46b1db&hl=en_IN&co=IN",
        "path": "/auth",
        "query": "branding=save-profile-modal&tmpl=inline&from=act_zeroauth_profile_tst&iframe_tk=9a019527-a6f1-4b3d-b803-2b25bb46b1db&hl=en_IN&co=IN",
        "scheme": "https"
    },
    "user": {
        "domain": "SMC User",
        "id": "S-1-5-21-3766288932-3295778425-2939962592-1001",
        "name": [
            "admin"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint_harmony_endpoint.urlfiltering.advanced_info | Internal field used for configuring exclusions | text |
| checkpoint_harmony_endpoint.urlfiltering.analyzed_on | Describes location where threat is analyzed. | keyword |
| checkpoint_harmony_endpoint.urlfiltering.app.id | Application ID | keyword |
| checkpoint_harmony_endpoint.urlfiltering.app.properties | All categories application belongs to | text |
| checkpoint_harmony_endpoint.urlfiltering.appi_name | Requested website (domain only, without path) | text |
| checkpoint_harmony_endpoint.urlfiltering.client.name | Can be either Check Point Endpoint Security Client or Check Point Capsule Docs Client | keyword |
| checkpoint_harmony_endpoint.urlfiltering.client.version | Build version of Harmony Endpoint client installed on the computer | version |
| checkpoint_harmony_endpoint.urlfiltering.confidence_level | Can be Low/Medim/High/N-A | keyword |
| checkpoint_harmony_endpoint.urlfiltering.description | Details of the event | text |
| checkpoint_harmony_endpoint.urlfiltering.event_type | Name of the event | keyword |
| checkpoint_harmony_endpoint.urlfiltering.matched_category | Matched category | keyword |
| checkpoint_harmony_endpoint.urlfiltering.policy.date | Date of policy | date |
| checkpoint_harmony_endpoint.urlfiltering.policy.name | Name of policy | keyword |
| checkpoint_harmony_endpoint.urlfiltering.policy.number | Version number of policy | integer |
| checkpoint_harmony_endpoint.urlfiltering.process_exe_path | Path to Process's executable | keyword |
| checkpoint_harmony_endpoint.urlfiltering.protection_type | Type of detection | keyword |
| checkpoint_harmony_endpoint.urlfiltering.severity | Event severity | keyword |
| checkpoint_harmony_endpoint.urlfiltering.tenant_id | Tenant ID | keyword |
| checkpoint_harmony_endpoint.urlfiltering.usercheck_incident_uid | Internal ID of user confirmation | keyword |
| checkpoint_harmony_endpoint.urlfiltering.web_client_type | When relevant, name of the browser (Chrome, Edge, …) | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |


### Zero-phishing
This is `Zero-Phishing` dataset.

An example event for `zerophishing` looks as following:

```json
{
    "@timestamp": "2024-09-02T08:51:08.000Z",
    "agent": {
        "ephemeral_id": "c49eeccf-dc55-48c4-b0ba-45b5cf8fe9f3",
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "checkpoint_harmony_endpoint": {
        "zerophishing": {
            "advanced_info": "\"exclusions\":[{\"exclusion_engine_type\":\"Threat Emulation, Extraction and Zero Phishing Exclusions\",\"exclusion_type\":\"Domain\",\"exclusion_value\":{\"default_value\":\"main.sbm-demo.xyz\",\"md5\":\"\",\"original_name\":\"\",\"signer\":\"\",\"process\":\"\",\"protection\":\"\",\"comment\":\"\"}}]",
            "client": {
                "name": "Check Point Endpoint Security Client",
                "version": "88.50.0213"
            },
            "confidence_level": "High",
            "description": "Deceptive site (https://main.sbm-demo.xyz/zero-phishing) was detected.",
            "event_type": "Phishing Event",
            "extension_version": "Check Point Endpoint Security Client",
            "malware": {},
            "policy": {
                "date": "2024-08-29T13:12:50.0000000Z",
                "name": "Default Threat Extraction, Emulation and Anti-Exploit settings for the entire organization",
                "number": 3
            },
            "protection_type": "Phishing",
            "severity": "High",
            "tenant_id": "3e15ed24-89ff-4986-a204-c425cee4ba48",
            "web_client_type": "Chrome"
        }
    },
    "data_stream": {
        "dataset": "checkpoint_harmony_endpoint.zerophishing",
        "namespace": "80023",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "831f83c6-e906-440e-a2cc-828138a24217",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "action": "Detect",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "dataset": "checkpoint_harmony_endpoint.zerophishing",
        "id": "a4640108-91b1-0f19-66d5-7d6100000004",
        "ingested": "2024-09-16T08:28:07Z",
        "kind": "alert",
        "module": "checkpoint_harmony_endpoint",
        "original": "{\"action\":\"Detect\",\"advanced_info\":\"\\\"exclusions\\\":[{\\\"exclusion_engine_type\\\":\\\"Threat Emulation, Extraction and Zero Phishing Exclusions\\\",\\\"exclusion_type\\\":\\\"Domain\\\",\\\"exclusion_value\\\":{\\\"default_value\\\":\\\"main.sbm-demo.xyz\\\",\\\"md5\\\":\\\"\\\",\\\"original_name\\\":\\\"\\\",\\\"signer\\\":\\\"\\\",\\\"process\\\":\\\"\\\",\\\"protection\\\":\\\"\\\",\\\"comment\\\":\\\"\\\"}}]\",\"client_name\":\"Check Point Endpoint Security Client\",\"client_version\":[\"88.50.0213\"],\"confidence_level\":\"High\",\"description\":\"Deceptive site (https://main.sbm-demo.xyz/zero-phishing) was detected.\",\"domain\":\"SMC User\",\"event_type\":\"Phishing Event\",\"extension_version\":\"Check Point Endpoint Security Client\",\"host_type\":[\"Desktop\"],\"id\":\"a4640108-91b1-0f19-66d5-7d6100000004\",\"installed_products\":\"Full Disk Encryption; Media Encryption \\u0026 Port Protection; Firewall; Compliance; Application Control; Anti-Malware; VPN; Anti-Bot; Forensics; Threat Emulation\",\"malware_action\":[\" \"],\"orig\":\"164.100.1.8\",\"os_name\":[\"Microsoft Windows 10 Pro\"],\"os_version\":[\"10.0-19045-SP0.0-SMP\"],\"policy_date\":\"2024-08-29T13:12:50.0000000Z\",\"policy_name\":\"Default Threat Extraction, Emulation and Anti-Exploit settings for the entire organization\",\"policy_number\":3,\"product\":\"Zero Phishing\",\"product_family\":\"Endpoint\",\"protection_name\":\"gen.ba.phishing\",\"protection_type\":\"Phishing\",\"resource\":[\"https://main.sbm-demo.xyz/zero-phishing\"],\"sequencenum\":16777215,\"severity\":\"High\",\"src\":\"10.35.38.102\",\"src_machine_name\":\"DESKTOP-E2P4OL0\",\"src_user_name\":[\"admin\"],\"tenant_id\":\"3e15ed24-89ff-4986-a204-c425cee4ba48\",\"time\":\"2024-09-02T08:51:08Z\",\"type\":\"Log\",\"user_sid\":\"S-1-5-21-3766288932-3295778425-2939962592-1001\",\"web_client_type\":[\"Chrome\"]}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "DESKTOP-E2P4OL0",
        "ip": [
            "10.35.38.102"
        ],
        "name": "DESKTOP-E2P4OL0",
        "os": {
            "name": "Microsoft Windows 10 Pro",
            "version": "10.0-19045-SP0.0-SMP"
        },
        "type": [
            "Desktop"
        ]
    },
    "input": {
        "type": "cel"
    },
    "rule": {
        "name": "gen.ba.phishing"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "url": {
        "domain": "main.sbm-demo.xyz",
        "original": "https://main.sbm-demo.xyz/zero-phishing",
        "path": "/zero-phishing",
        "scheme": "https"
    },
    "user": {
        "domain": "SMC User",
        "id": "S-1-5-21-3766288932-3295778425-2939962592-1001",
        "name": [
            "admin"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint_harmony_endpoint.zerophishing.advanced_info | Internal field used for configuring exclusions | text |
| checkpoint_harmony_endpoint.zerophishing.client.name | Can be either Check Point Endpoint Security Client or Check Point Capsule Docs Client | keyword |
| checkpoint_harmony_endpoint.zerophishing.client.version | Build version of Harmony Endpoint client installed on the computer | version |
| checkpoint_harmony_endpoint.zerophishing.confidence_level | Can be Low/Medim/High/N-A | keyword |
| checkpoint_harmony_endpoint.zerophishing.description | Details of the event | text |
| checkpoint_harmony_endpoint.zerophishing.event_type | Name of the event | keyword |
| checkpoint_harmony_endpoint.zerophishing.extension_version | Browser Extention version | keyword |
| checkpoint_harmony_endpoint.zerophishing.malware.action | Additional information about detection, for example "User reused corporate credentials" | keyword |
| checkpoint_harmony_endpoint.zerophishing.policy.date | Date of policy | date |
| checkpoint_harmony_endpoint.zerophishing.policy.name | Name of policy | keyword |
| checkpoint_harmony_endpoint.zerophishing.policy.number | Version number of policy | integer |
| checkpoint_harmony_endpoint.zerophishing.protection_type | Type of detection | keyword |
| checkpoint_harmony_endpoint.zerophishing.severity | Event severity | keyword |
| checkpoint_harmony_endpoint.zerophishing.tenant_id | Tenant ID | keyword |
| checkpoint_harmony_endpoint.zerophishing.web_client_type | When relevant, name of the browser (Chrome, Edge, …) | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |

