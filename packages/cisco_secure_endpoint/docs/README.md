# Cisco Secure Endpoint Integration

This integration is for Cisco Secure Endpoint logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `event` dataset: supports Cisco Secure Endpoint Event logs.

## Logs

### Secure Endpoint

The `event` dataset collects Cisco Secure Endpoint logs.

An example event for `event` looks as following:

```json
{
    "@timestamp": "2021-01-15T11:59:52.000Z",
    "ecs": {
        "version": "1.12.0"
    },
    "related": {
        "hosts": [
            "Demo_Threat_Hunting"
        ],
        "ip": [
            "8.8.8.8",
            "10.10.10.10"
        ]
    },
    "host": {
        "name": "Demo_Threat_Hunting",
        "hostname": "Demo_Threat_Hunting"
    },
    "threat": {
        "technique": {
            "reference": [
                "https://attack.mitre.org/techniques/T1005",
                "https://attack.mitre.org/techniques/T1053",
                "https://attack.mitre.org/techniques/T1064"
            ],
            "name": [
                "Data from Local System",
                "Scheduled Task/Job",
                "Scripting"
            ],
            "id": [
                "T1005",
                "T1053",
                "T1064"
            ]
        },
        "tactic": {
            "reference": [
                "https://attack.mitre.org/tactics/TA0005"
            ],
            "name": [
                "Defense Evasion"
            ],
            "id": [
                "TA0005"
            ]
        }
    },
    "event": {
        "severity": 4,
        "action": "SecureX Threat Hunting Incident",
        "ingested": "2021-09-27T00:41:08.619280442Z",
        "original": "{\"version\":\"v1.2.0\",\"metadata\":{\"links\":{\"self\":\"https://api.eu.amp.cisco.com/v1/events?limit=500\",\"next\":\"https://api.eu.amp.cisco.com/v1/events?limit=500\u0026offset=500\"},\"results\":{\"total\":972,\"current_item_count\":500,\"index\":0,\"items_per_page\":500}},\"data\":{\"timestamp\":1610711992,\"timestamp_nanoseconds\":155518026,\"date\":\"2021-01-15T11:59:52+00:00\",\"event_type\":\"SecureX Threat Hunting Incident\",\"event_type_id\":1107296344,\"connector_guid\":\"test_connector_guid\",\"severity\":\"Critical\",\"computer\":{\"connector_guid\":\"test_connector_guid\",\"hostname\":\"Demo_Threat_Hunting\",\"external_ip\":\"8.8.8.8\",\"active\":true,\"network_addresses\":[{\"ip\":\"10.10.10.10\",\"mac\":\"87:c2:d9:a2:8c:74\"}],\"links\":{\"computer\":\"https://api.eu.amp.cisco.com/v1/computers/test_computer\",\"trajectory\":\"https://api.eu.amp.cisco.com/v1/computers/test_computer/trajectory\",\"group\":\"https://api.eu.amp.cisco.com/v1/groups/test_group\"}},\"threat_hunting\":{\"incident_report_guid\":\"6e5292d5-248c-49dc-839d-201bcba64562\",\"incident_hunt_guid\":\"4bdbaf20-020f-4bb5-9da9-585da0e07817\",\"incident_title\":\"Valak Variant\",\"incident_summary\":\"The host Demo_Threat_Hunting is compromised by a Valak malware variant.  Valak is a multi-stage malware attack that uses screen capture, reconnaissance, geolocation, and fileless execution techniques to infiltrate and exfiltrate sensitive information.  Based on the event details listed and the techniques used, we recommend the host in question be investigated further.\",\"incident_remediation\":\"We recommend the following:\\r\\n\\r\\n- Isolation of the affected hosts from the network\\r\\n- Perform forensic investigation\\r\\n    - Review all activity performed by the user\\r\\n    - Upload any suspicious files to ThreatGrid for analysis\\r\\n    - Search the registry for data \\\"var config = ( COMMAND_C2\\\" and remove the key\\r\\n    - Review scheduled tasks and cancel any involving the execution of WSCRIPT.EXE //E:jscript C:\\\\Users\\\\Public\\\\PowerManagerSpm.jar:LocalZone lqjsxokgowhbxjaetyrifnbigtcxmuj eimljujnv\\r\\n    - Remove the Alternate Data Stream file located C:\\\\Users\\\\Public\\\\PowerManagerSpm.jar:LocalZone.\\r\\n- If possible, reimage the affected system to prevent potential unknown persistence methods.\",\"incident_id\":416,\"tactics\":[{\"name\":\"Defense Evasion\",\"description\":\"\u003cp\u003eThe adversary is trying to avoid being detected.\u003c/p\u003e\\n\\n\u003cp\u003eDefense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses.\u003c/p\u003e\\n\",\"external_id\":\"TA0005\",\"mitre_name\":\"tactic\",\"mitre_url\":\"https://attack.mitre.org/tactics/TA0005\"}],\"techniques\":[{\"name\":\"Data from Local System\",\"description\":\"\u003cp\u003eAdversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to Exfiltration.\u003c/p\u003e\\n\\n\u003cp\u003eAdversaries may do this using a \u003ca href=\\\"https://attack.mitre.org/techniques/T1059\\\"\u003eCommand and Scripting Interpreter\u003c/a\u003e, such as \u003ca href=\\\"https://attack.mitre.org/software/S0106\\\"\u003ecmd\u003c/a\u003e, which has functionality to interact with the file system to gather information. Some adversaries may also use \u003ca href=\\\"https://attack.mitre.org/techniques/T1119\\\"\u003eAutomated Collection\u003c/a\u003e on the local system.\u003c/p\u003e\\n\",\"external_id\":\"T1005\",\"mitre_name\":\"technique\",\"mitre_url\":\"https://attack.mitre.org/techniques/T1005\",\"tactics_names\":\"Collection\",\"platforms\":\"Linux, macOS, Windows\",\"system_requirements\":\"Privileges to access certain files and directories\",\"permissions\":\"\",\"data_sources\":\"File monitoring, Process monitoring, Process command-line parameters\"},{\"name\":\"Scheduled Task/Job\",\"description\":\"\u003cp\u003eAdversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)\u003c/p\u003e\\n\\n\u003cp\u003eAdversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).\u003c/p\u003e\\n\",\"external_id\":\"T1053\",\"mitre_name\":\"technique\",\"mitre_url\":\"https://attack.mitre.org/techniques/T1053\",\"tactics_names\":\"Execution, Persistence, Privilege Escalation\",\"platforms\":\"Windows, Linux, macOS\",\"system_requirements\":null,\"permissions\":\"Administrator, SYSTEM, User\",\"data_sources\":\"File monitoring, Process monitoring, Process command-line parameters, Windows event logs\"},{\"name\":\"Scripting\",\"description\":\"\u003cp\u003e\u003cstrong\u003eThis technique has been deprecated. Please use \u003ca href=\\\"https://attack.mitre.org/techniques/T1059\\\"\u003eCommand and Scripting Interpreter\u003c/a\u003e where appropriate.\u003c/strong\u003e\u003c/p\u003e\\n\\n\u003cp\u003eAdversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and \u003ca href=\\\"https://attack.mitre.org/techniques/T1086\\\"\u003ePowerShell\u003c/a\u003e but could also be in the form of command-line batch scripts.\u003c/p\u003e\\n\\n\u003cp\u003eScripts can be embedded inside Office documents as macros that can be set to execute when files used in \u003ca href=\\\"https://attack.mitre.org/techniques/T1193\\\"\u003eSpearphishing Attachment\u003c/a\u003e and other types of spearphishing are opened. Malicious embedded macros are an alternative means of execution than software exploitation through \u003ca href=\\\"https://attack.mitre.org/techniques/T1203\\\"\u003eExploitation for Client Execution\u003c/a\u003e, where adversaries will rely on macros being allowed or that the user will accept to activate them.\u003c/p\u003e\\n\\n\u003cp\u003eMany popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and PowerSploit (Citation: Powersploit) are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch 2014)\u003c/p\u003e\\n\",\"external_id\":\"T1064\",\"mitre_name\":\"technique\",\"mitre_url\":\"https://attack.mitre.org/techniques/T1064\",\"tactics_names\":\"Defense Evasion, Execution\",\"platforms\":\"Linux, macOS, Windows\",\"system_requirements\":null,\"permissions\":\"User\",\"data_sources\":\"Process monitoring, File monitoring, Process command-line parameters\"}],\"severity\":\"critical\",\"incident_start_time\":1610707688,\"incident_end_time\":1592478770},\"tactics\":[{\"name\":\"Defense Evasion\",\"description\":\"\u003cp\u003eThe adversary is trying to avoid being detected.\u003c/p\u003e\\n\\n\u003cp\u003eDefense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses.\u003c/p\u003e\\n\",\"external_id\":\"TA0005\",\"mitre_name\":\"tactic\",\"mitre_url\":\"https://attack.mitre.org/tactics/TA0005\"}],\"techniques\":[{\"name\":\"Data from Local System\",\"description\":\"\u003cp\u003eAdversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to Exfiltration.\u003c/p\u003e\\n\\n\u003cp\u003eAdversaries may do this using a \u003ca href=\\\"https://attack.mitre.org/techniques/T1059\\\"\u003eCommand and Scripting Interpreter\u003c/a\u003e, such as \u003ca href=\\\"https://attack.mitre.org/software/S0106\\\"\u003ecmd\u003c/a\u003e, which has functionality to interact with the file system to gather information. Some adversaries may also use \u003ca href=\\\"https://attack.mitre.org/techniques/T1119\\\"\u003eAutomated Collection\u003c/a\u003e on the local system.\u003c/p\u003e\\n\",\"external_id\":\"T1005\",\"mitre_name\":\"technique\",\"mitre_url\":\"https://attack.mitre.org/techniques/T1005\",\"tactics_names\":\"Collection\",\"platforms\":\"Linux, macOS, Windows\",\"system_requirements\":\"Privileges to access certain files and directories\",\"permissions\":\"\",\"data_sources\":\"File monitoring, Process monitoring, Process command-line parameters\"},{\"name\":\"Scheduled Task/Job\",\"description\":\"\u003cp\u003eAdversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)\u003c/p\u003e\\n\\n\u003cp\u003eAdversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).\u003c/p\u003e\\n\",\"external_id\":\"T1053\",\"mitre_name\":\"technique\",\"mitre_url\":\"https://attack.mitre.org/techniques/T1053\",\"tactics_names\":\"Execution, Persistence, Privilege Escalation\",\"platforms\":\"Windows, Linux, macOS\",\"system_requirements\":null,\"permissions\":\"Administrator, SYSTEM, User\",\"data_sources\":\"File monitoring, Process monitoring, Process command-line parameters, Windows event logs\"},{\"name\":\"Scripting\",\"description\":\"\u003cp\u003e\u003cstrong\u003eThis technique has been deprecated. Please use \u003ca href=\\\"https://attack.mitre.org/techniques/T1059\\\"\u003eCommand and Scripting Interpreter\u003c/a\u003e where appropriate.\u003c/strong\u003e\u003c/p\u003e\\n\\n\u003cp\u003eAdversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and \u003ca href=\\\"https://attack.mitre.org/techniques/T1086\\\"\u003ePowerShell\u003c/a\u003e but could also be in the form of command-line batch scripts.\u003c/p\u003e\\n\\n\u003cp\u003eScripts can be embedded inside Office documents as macros that can be set to execute when files used in \u003ca href=\\\"https://attack.mitre.org/techniques/T1193\\\"\u003eSpearphishing Attachment\u003c/a\u003e and other types of spearphishing are opened. Malicious embedded macros are an alternative means of execution than software exploitation through \u003ca href=\\\"https://attack.mitre.org/techniques/T1203\\\"\u003eExploitation for Client Execution\u003c/a\u003e, where adversaries will rely on macros being allowed or that the user will accept to activate them.\u003c/p\u003e\\n\\n\u003cp\u003eMany popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and PowerSploit (Citation: Powersploit) are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch 2014)\u003c/p\u003e\\n\",\"external_id\":\"T1064\",\"mitre_name\":\"technique\",\"mitre_url\":\"https://attack.mitre.org/techniques/T1064\",\"tactics_names\":\"Defense Evasion, Execution\",\"platforms\":\"Linux, macOS, Windows\",\"system_requirements\":null,\"permissions\":\"User\",\"data_sources\":\"Process monitoring, File monitoring, Process command-line parameters\"}]}}",
        "kind": "alert"
    },
    "cisco": {
        "secure_endpoint": {
            "computer": {
                "active": true,
                "network_addresses": [
                    {
                        "mac": "87:c2:d9:a2:8c:74",
                        "ip": "10.10.10.10"
                    }
                ],
                "connector_guid": "test_connector_guid",
                "external_ip": "8.8.8.8"
            },
            "threat_hunting": {
                "severity": "critical",
                "incident_title": "Valak Variant",
                "incident_id": 416,
                "incident_end_time": "2020-06-18T11:12:50.000Z",
                "incident_start_time": "2021-01-15T10:48:08.000Z",
                "incident_summary": "The host Demo_Threat_Hunting is compromised by a Valak malware variant.  Valak is a multi-stage malware attack that uses screen capture, reconnaissance, geolocation, and fileless execution techniques to infiltrate and exfiltrate sensitive information.  Based on the event details listed and the techniques used, we recommend the host in question be investigated further.",
                "incident_remediation": "We recommend the following:\r\n\r\n- Isolation of the affected hosts from the network\r\n- Perform forensic investigation\r\n    - Review all activity performed by the user\r\n    - Upload any suspicious files to ThreatGrid for analysis\r\n    - Search the registry for data \"var config = ( COMMAND_C2\" and remove the key\r\n    - Review scheduled tasks and cancel any involving the execution of WSCRIPT.EXE //E:jscript C:\\Users\\Public\\PowerManagerSpm.jar:LocalZone lqjsxokgowhbxjaetyrifnbigtcxmuj eimljujnv\r\n    - Remove the Alternate Data Stream file located C:\\Users\\Public\\PowerManagerSpm.jar:LocalZone.\r\n- If possible, reimage the affected system to prevent potential unknown persistence methods.",
                "incident_report_guid": "6e5292d5-248c-49dc-839d-201bcba64562",
                "incident_hunt_guid": "4bdbaf20-020f-4bb5-9da9-585da0e07817"
            },
            "connector_guid": "test_connector_guid",
            "related": {
                "mac": [
                    "87:c2:d9:a2:8c:74"
                ]
            },
            "techniques": [
                {
                    "mitre_name": "technique",
                    "tactics_names": "Collection",
                    "system_requirements": "Privileges to access certain files and directories",
                    "permissions": "",
                    "name": "Data from Local System",
                    "description": "\u003cp\u003eAdversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to Exfiltration.\u003c/p\u003e\n\n\u003cp\u003eAdversaries may do this using a \u003ca href=\"https://attack.mitre.org/techniques/T1059\"\u003eCommand and Scripting Interpreter\u003c/a\u003e, such as \u003ca href=\"https://attack.mitre.org/software/S0106\"\u003ecmd\u003c/a\u003e, which has functionality to interact with the file system to gather information. Some adversaries may also use \u003ca href=\"https://attack.mitre.org/techniques/T1119\"\u003eAutomated Collection\u003c/a\u003e on the local system.\u003c/p\u003e\n",
                    "external_id": "T1005",
                    "mitre_url": "https://attack.mitre.org/techniques/T1005",
                    "data_sources": "File monitoring, Process monitoring, Process command-line parameters",
                    "platforms": "Linux, macOS, Windows"
                },
                {
                    "mitre_name": "technique",
                    "tactics_names": "Execution, Persistence, Privilege Escalation",
                    "permissions": "Administrator, SYSTEM, User",
                    "name": "Scheduled Task/Job",
                    "description": "\u003cp\u003eAdversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)\u003c/p\u003e\n\n\u003cp\u003eAdversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).\u003c/p\u003e\n",
                    "external_id": "T1053",
                    "mitre_url": "https://attack.mitre.org/techniques/T1053",
                    "data_sources": "File monitoring, Process monitoring, Process command-line parameters, Windows event logs",
                    "platforms": "Windows, Linux, macOS"
                },
                {
                    "mitre_name": "technique",
                    "tactics_names": "Defense Evasion, Execution",
                    "permissions": "User",
                    "name": "Scripting",
                    "description": "\u003cp\u003e\u003cstrong\u003eThis technique has been deprecated. Please use \u003ca href=\"https://attack.mitre.org/techniques/T1059\"\u003eCommand and Scripting Interpreter\u003c/a\u003e where appropriate.\u003c/strong\u003e\u003c/p\u003e\n\n\u003cp\u003eAdversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and \u003ca href=\"https://attack.mitre.org/techniques/T1086\"\u003ePowerShell\u003c/a\u003e but could also be in the form of command-line batch scripts.\u003c/p\u003e\n\n\u003cp\u003eScripts can be embedded inside Office documents as macros that can be set to execute when files used in \u003ca href=\"https://attack.mitre.org/techniques/T1193\"\u003eSpearphishing Attachment\u003c/a\u003e and other types of spearphishing are opened. Malicious embedded macros are an alternative means of execution than software exploitation through \u003ca href=\"https://attack.mitre.org/techniques/T1203\"\u003eExploitation for Client Execution\u003c/a\u003e, where adversaries will rely on macros being allowed or that the user will accept to activate them.\u003c/p\u003e\n\n\u003cp\u003eMany popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), and PowerSploit (Citation: Powersploit) are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch 2014)\u003c/p\u003e\n",
                    "external_id": "T1064",
                    "mitre_url": "https://attack.mitre.org/techniques/T1064",
                    "data_sources": "Process monitoring, File monitoring, Process command-line parameters",
                    "platforms": "Linux, macOS, Windows"
                }
            ],
            "tactics": [
                {
                    "name": "Defense Evasion",
                    "description": "\u003cp\u003eThe adversary is trying to avoid being detected.\u003c/p\u003e\n\n\u003cp\u003eDefense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses.\u003c/p\u003e\n",
                    "mitre_name": "tactic",
                    "external_id": "TA0005",
                    "mitre_url": "https://attack.mitre.org/tactics/TA0005"
                }
            ],
            "event_type_id": 1107296344
        }
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
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
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.tactic.reference | The reference url of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.reference | The reference url of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |

