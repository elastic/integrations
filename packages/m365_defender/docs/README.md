# Microsoft Defender XDR integration

## Overview

The [Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/) integration allows you to monitor Alert, Incident (Microsoft Graph Security API), Event (Streaming API) Logs, and Vulnerability (Microsoft Defender for Endpoint API) Logs. Microsoft Defender XDR is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

Use the Microsoft Defender XDR integration to collect and parse data from the Microsoft Azure Event Hub, Microsoft Graph Security v1.0 REST API, and the Microsoft Defender Endpoint API. Then visualise that data in Kibana.

For example, you could use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert, incident, and vulnerability a user can take an appropriate action in the Microsoft Defender XDR Portal.

## Data streams

The Microsoft Defender XDR integration collects logs for four types of events: Alert, Event, Incident, and Vulnerability.

**Alert:** This data streams leverages the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0) to collect alerts including suspicious activities in a customer's tenant that Microsoft or partner security providers have identified and flagged for action.

**Event (Recommended):** This data stream leverages the [M365 Defender Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide) to collect Alert, Device, Email, App and Identity Events. Events are streamed to an Azure Event Hub. For a list of Supported Events exposed by the Streaming API and supported by Elastic's integration, please see Microsoft's documentation [here](https://learn.microsoft.com/en-us/defender-xdr/supported-event-types?view=o365-worldwide).

**Incidents and Alerts (Recommended):** This data streams leverages the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0) to ingest a collection of correlated alert instances and associated metadata that reflects the story of an attack in Microsoft Defender XDR. Incidents stemming from Microsoft Defender XDR, Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Identity, Microsoft Defender for Cloud Apps, and Microsoft Purview Data Loss Prevention are supported by this integration.

**Vulnerability:** This data stream uses the [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list) to gather vulnerability details by fetching data from three different endpoints — [vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities), [machines](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines), and [software/products](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines). The collected data is then correlated and mapped to generate a single, enriched log per vulnerability, providing a clear view of risks across machines and installed software in your environment.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has used **Microsoft Azure Event Hub** for Streaming Event, **Microsoft Graph Security v1.0 REST API** for Incident data stream and **Microsoft Defender for Endpoint API** for Vulnerability data stream.

For **Event**, using filebeat's [Azure Event Hub](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) input, state such as leases on partitions and checkpoints in the event stream are shared between receivers using an Azure Storage container. For this reason, as a prerequisite to using this input, users will have to create or use an existing storage account.

### Agentless enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility
###  This integration supports below API versions to collect data.
  - [Microsoft Graph Security v1.0 REST API](https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0)
  - [M365 Defender Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide)
    Supported Microsoft Defender XDR streaming event types:
      | Resource types            | Description               |
    |---------------------------|---------------------------|
    | AlertEvidence             | Files, IP addresses, URLs, users, or devices associated with alerts. |
    | AlertInfo                 | Alerts from M365 Defender XDR services, including severity and threat categorization. |
    | DeviceEvents              | Event types, including events triggered by security controls. |
    | DeviceFileCertificateInfo | Certificate information of signed files obtained from certificate verification events on endpoints. |
    | DeviceFileEvents          | File creation, modification, and other file system events. |
    | DeviceImageLoadEvents     | DLL loading events. |
    | DeviceInfo                | Machine information, including OS information. |
    | DeviceLogonEvents         | Sign-ins and other authentication events on devices. |
    | DeviceNetworkEvents       | Network connection and related events. |
    | DeviceNetworkInfo         | Network properties of devices, as well as connected networks and domains. |
    | DeviceProcessEvents       | Process creation and related events. |
    | DeviceRegistryEvents      | Creation and modification of registry entries. |
    | EmailAttachmentInfo       | Information about files attached to emails. |
    | EmailEvents               | Microsoft 365 email events, including email delivery and blocking events. |
    | EmailPostDeliveryEvents   | Security events that occur post-delivery, after Microsoft 365 delivers the emails to the recipient mailbox. |
    | EmailUrlInfo              | Information about URLs in emails. |
    | IdentityInfo              | Account information from various sources, including Microsoft Entra ID. |
    | IdentityLogonEvents       | Authentication events on Active Directory and Microsoft online services. |
    | IdentityQueryEvents       | Queries for Active Directory objects, such as users, groups, devices, and domains. |
    | IdentityDirectoryEvents   | Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller. |
    | CloudAppEvents            | Events involving accounts and objects in Office 365 and other cloud apps and services. |
    | UrlClickEvent             | Safe Links clicks from email messages, Teams, and Office 365 apps. |
  - [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list)
    - [Vulnerabilities API](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities) (Last updated On 04/25/2024)
    - [Machines API](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines) (Last updated On 03/01/2025)
    - [software/products API](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines) (Last updated On 04/25/2024)

## Setup

### Follow the steps below to configure data collection from Microsoft sources:

### 1. Collecting Data from Microsoft Azure Event Hub
- [Configure Microsoft Defender XDR to stream Advanced Hunting events to your Azure Event Hub](https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub?view=o365-worldwide).

### 2. Collecting Data from Microsoft Graph Security v1.0 REST API (for Incidents & Alerts)
- [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
- Assign the required permission: **SecurityIncident.Read.All**. See more details [here](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0).
- Once the application is registered, note the following values for use during configuration:
  - Client ID
  - Client Secret
  - Tenant ID

### 3. Collecting Data from Microsoft Defender for Endpoint API (for Vulnerabilities)
- [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
- Assign the required permissions: 
  - **Vulnerability.Read.All** See more details [here](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities#permissions).
  - **Machine.Read.All** See more details [here](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines#permissions).
- After registration, retrieve the following credentials needed for configuration:
  - Client ID
  - Client Secret
  - Tenant ID

### Data Retention and ILM Configuration
A full sync pulls in a large volume of data, which can lead to storage issues or index overflow over time. To avoid this, we’ve set up an Index Lifecycle Management (ILM) policy that automatically deletes data older than 7 days. This helps keep storage usage under control.

> **Note:** The user or service account associated with the integration must have the following **index privileges** on the relevant index have the following permissions `delete`, `delete_index`

## Alert severity mapping

The values used in `event.severity` are consistent with Elastic Detection Rules.

| Severity Name          | `event.severity` |
|------------------------|:----------------:|
| Low (or Informational) | 21               |
| Medium                 | 47               |
| High                   | 73               |
| Critical               | 99               |

## Logs reference

### alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2023-10-20T09:54:07.503Z",
    "agent": {
        "ephemeral_id": "5e4d1adc-4724-42e2-8bce-1bd3e7e7f7de",
        "id": "0565bad7-c286-4eed-ba44-49dde64f4313",
        "name": "elastic-agent-28236",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "cloud": {
        "account": {
            "id": "3adb963c-8e61-48e8-a06d-6dbb0dacea39"
        }
    },
    "data_stream": {
        "dataset": "m365_defender.alert",
        "namespace": "95822",
        "type": "logs"
    },
    "device": {
        "id": [
            "f18bd540-d5e4-46e0-8ddd-3d03a59e4e14"
        ]
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0565bad7-c286-4eed-ba44-49dde64f4313",
        "snapshot": false,
        "version": "8.18.0"
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
        "ingested": "2025-05-27T10:26:31Z",
        "kind": "alert",
        "original": "{\"actorDisplayName\":null,\"additionalData\":null,\"alertPolicyId\":null,\"alertWebUrl\":\"https://security.microsoft.com/alerts/daefa1828b-dd4e-405c-8a3b-aa28596830dd_1?tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39\",\"assignedTo\":null,\"category\":\"Execution\",\"classification\":null,\"comments\":[],\"createdDateTime\":\"2023-10-20T09:53:09.8839373Z\",\"description\":\"A suspicious PowerShell activity was observed on the machine. \\nThis behavior may indicate that PowerShell was used during installation, exploration, or in some cases in lateral movement activities which are used by attackers to invoke modules, download external payloads, or get more information about the system. Attackers usually use PowerShell to bypass security protection mechanisms by executing their payload in memory without touching the disk and leaving any trace.\",\"detectionSource\":\"microsoftDefenderForEndpoint\",\"detectorId\":\"7f1c3609-a3ff-40e2-995b-c01770161d68\",\"determination\":null,\"evidence\":[{\"@odata.type\":\"#microsoft.graph.security.deviceEvidence\",\"azureAdDeviceId\":\"f18bd540-d5e4-46e0-8ddd-3d03a59e4e14\",\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"defenderAvStatus\":\"notSupported\",\"detailedRoles\":[\"PrimaryDevice\"],\"deviceDnsName\":\"clw555test\",\"firstSeenDateTime\":\"2023-10-20T09:50:17.7383987Z\",\"healthStatus\":\"inactive\",\"ipInterfaces\":[\"192.168.5.65\",\"fe80::cfe4:80b:615c:38fb\",\"127.0.0.1\",\"::1\"],\"loggedOnUsers\":[{\"accountName\":\"CDPUserIS-38411\",\"domainName\":\"AzureAD\"}],\"mdeDeviceId\":\"505d70d89cfa3428f7aac7d2eb3a64c60fd3d843\",\"onboardingStatus\":\"onboarded\",\"osBuild\":22621,\"osPlatform\":\"Windows11\",\"rbacGroupId\":0,\"rbacGroupName\":null,\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"riskScore\":\"high\",\"roles\":[],\"tags\":[],\"verdict\":\"unknown\",\"version\":\"22H2\",\"vmMetadata\":null},{\"@odata.type\":\"#microsoft.graph.security.userEvidence\",\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"detailedRoles\":[],\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"userAccount\":{\"accountName\":\"CDPUserIS-38411\",\"azureAdUserId\":null,\"displayName\":null,\"domainName\":\"AzureAD\",\"userPrincipalName\":null,\"userSid\":\"S-1-12-1-1485667349-1150190949-4065799612-2328216759\"},\"verdict\":\"unknown\"},{\"@odata.type\":\"#microsoft.graph.security.urlEvidence\",\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"detailedRoles\":[],\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"url\":\"http://127.0.0.1/1.exe\",\"verdict\":\"suspicious\"},{\"@odata.type\":\"#microsoft.graph.security.ipEvidence\",\"countryLetterCode\":null,\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"detailedRoles\":[],\"ipAddress\":\"127.0.0.1\",\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"verdict\":\"suspicious\"},{\"@odata.type\":\"#microsoft.graph.security.processEvidence\",\"createdDateTime\":\"2023-10-20T09:53:10.1933333Z\",\"detailedRoles\":[],\"detectionStatus\":\"detected\",\"imageFile\":{\"fileName\":\"powershell.exe\",\"filePath\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":491520,\"issuer\":null,\"sha1\":\"a72c41316307889e43fe8605a0dca4a72e72a011\",\"sha256\":\"d783ba6567faf10fdff2d0ea3864f6756862d6c733c7f4467283da81aedc3a80\",\"signer\":null},\"mdeDeviceId\":\"505d70d89cfa3428f7aac7d2eb3a64c60fd3d843\",\"parentProcessCreationDateTime\":\"2023-10-20T09:51:19.5064237Z\",\"parentProcessId\":5772,\"parentProcessImageFile\":{\"fileName\":\"cmd.exe\",\"filePath\":\"C:\\\\Windows\\\\System32\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":323584,\"issuer\":null,\"sha1\":null,\"sha256\":null,\"signer\":null},\"processCommandLine\":\"powershell.exe  -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference= 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\\\\\\\test-WDATP-test\\\\\\\\invoice.exe');Start-Process 'C:\\\\\\\\test-WDATP-test\\\\\\\\invoice.exe'\",\"processCreationDateTime\":\"2023-10-20T09:51:39.4997961Z\",\"processId\":8224,\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"userAccount\":{\"accountName\":\"CDPUserIS-38411\",\"azureAdUserId\":null,\"displayName\":null,\"domainName\":\"AzureAD\",\"userPrincipalName\":null,\"userSid\":\"S-1-12-1-1485667349-1150190949-4065799612-2328216759\"},\"verdict\":\"unknown\"}],\"firstActivityDateTime\":\"2023-10-20T09:51:39.5154802Z\",\"id\":\"daefa1828b-dd4e-405c-8a3b-aa28596830dd_1\",\"incidentId\":\"23\",\"incidentWebUrl\":\"https://security.microsoft.com/incidents/23?tid=3adb963c-8e61-48e8-a06d-6dbb0dacea39\",\"lastActivityDateTime\":\"2023-10-20T09:51:41.9939003Z\",\"lastUpdateDateTime\":\"2023-10-20T09:54:07.5033333Z\",\"mitreTechniques\":[\"T1059.001\"],\"productName\":\"Microsoft Defender for Endpoint\",\"providerAlertId\":\"efa1828b-dd4e-405c-8a3b-aa28596830dd_1\",\"recommendedActions\":\"1. Examine the PowerShell command line to understand what commands were executed. Note: the content may need to be decoded if it is Base64-encoded.\\n2. Search the script for more indicators to investigate - for example IP addresses (potential C\\u0026C servers), target computers etc.\\n3. Explore the timeline of this and other related machines for additional suspect activities around the time of the alert.\\n4. Look for the process that invoked this PowerShell run and their origin. Consider submitting any suspect files in the chain for deep analysis for detailed behavior information.\",\"resolvedDateTime\":null,\"serviceSource\":\"microsoftDefenderForEndpoint\",\"severity\":\"medium\",\"status\":\"new\",\"tenantId\":\"3adb963c-8e61-48e8-a06d-6dbb0dacea39\",\"threatDisplayName\":null,\"threatFamilyName\":null,\"title\":\"Suspicious PowerShell command line\"}",
        "provider": "microsoftDefenderForEndpoint",
        "severity": 47,
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
        "entity_id": [
            "8224"
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
            "entity_id": [
                "5772"
            ],
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
| application.name | Name of the application. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dll.Ext.size | Size of the dll executable. | long |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| m365_defender.event.aad_device_id | Unique identifier for the device in Azure AD. | keyword |
| m365_defender.event.account.address | The address of the account user. | keyword |
| m365_defender.event.account.assigned_roles | The Microsoft Entra roles assigned to the account. | keyword |
| m365_defender.event.account.blast_radius | The potential impact of the user account in the org. | keyword |
| m365_defender.event.account.city | City where the account user is located. | keyword |
| m365_defender.event.account.cloud_sid | The Microsoft Entra security identifer for the account. | keyword |
| m365_defender.event.account.company_name | The company to which the account belongs. | keyword |
| m365_defender.event.account.country | Country/Region where the account user is located. | keyword |
| m365_defender.event.account.created | Date and time when the account user was created. | date |
| m365_defender.event.account.criticality_level | The criticality level assigned to an asset in M365 Defender XDR Exposure Management. Accepted values are Low (3) to Very High (0). | keyword |
| m365_defender.event.account.deleted_date_time | The date and time the user was deleted. | date |
| m365_defender.event.account.department | Name of the department that the account user belongs to. | keyword |
| m365_defender.event.account.display_name | Name of the account user displayed in the address book. Typically a combination of a given or first name, a middle initiation, and a last name or surname. | keyword |
| m365_defender.event.account.distinguished_name | The user's distinguished name. | keyword |
| m365_defender.event.account.domain | Domain of the account. | keyword |
| m365_defender.event.account.email_address | SMTP address of the account. | keyword |
| m365_defender.event.account.employee_id | Employee ID number of the account user. | keyword |
| m365_defender.event.account.given_name | Given name or first name of the account user. | keyword |
| m365_defender.event.account.id | An identifier for the account as found by Microsoft Defender for Cloud Apps. Could be Azure Active Directory ID, user principal name, or other identifiers. | keyword |
| m365_defender.event.account.is_enabled | Indicates whether the account is enabled or not. | boolean |
| m365_defender.event.account.job_title | Job title of the account user. | keyword |
| m365_defender.event.account.manager | The listed manager of the account user. | keyword |
| m365_defender.event.account.name | User name of the account. | keyword |
| m365_defender.event.account.object_id | Unique identifier for the account in Azure Active Directory. | keyword |
| m365_defender.event.account.on_prem_sid | On-premises security identifier (SID) of the account. | keyword |
| m365_defender.event.account.other_mail_addresses | The additional email addresses of the user. | keyword |
| m365_defender.event.account.phone | The listed phone number of the account user. | keyword |
| m365_defender.event.account.risk_level | Level of the detected risk. Possible values are low, medium, high, hidden, none, and unknownFutureValue. | keyword |
| m365_defender.event.account.risk_level_details | Details of the detected risk. | keyword |
| m365_defender.event.account.sid | Security Identifier (SID) of the account. | keyword |
| m365_defender.event.account.sip_proxy_address | Voice over IP (VOIP) session initiation protocol (SIP) address of the account. | keyword |
| m365_defender.event.account.state | The geographical state of the user account. | keyword |
| m365_defender.event.account.surname | Surname, family name, or last name of the account user. | keyword |
| m365_defender.event.account.tags | Tags assigned to the account user by Defender for Identity. | keyword |
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
| m365_defender.event.change_source | Identifies which identity provider or process triggered the addition of the new row. For example, the System-UserPersistence value is used for any rows added by an automated process. | keyword |
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
| m365_defender.event.dns.ttls | The time interval in seconds that this resource record may be cached before it should be discarded. | double |
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
| m365_defender.event.source_provider | The identity's source, such as Microsoft Entra ID, Active Directory, or a hybrid identity synchronized from Active Directory to Azure Active Directory. | keyword |
| m365_defender.event.source_system | The source system for the record. | keyword |
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
| m365_defender.event.type | The type of record. | keyword |
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
| process.Ext.api.name |  | keyword |
| process.Ext.api.parameters.address | The target memory address. | long |
| process.Ext.api.parameters.desired_access_numeric | This parameter indicates the numeric value of the `DesiredAccess` field passed to `OpenProcess` or `OpenThread`. | long |
| process.Ext.api.parameters.protection | The memory protection for the region of pages. Corresponds to `MEMORY_BASIC_INFORMATION.Protect`. | keyword |
| process.Ext.api.parameters.size | The size of parameter values passed to the API call. | long |
| process.Ext.token.integrity_level_name | Integrity level that determine the levels of protection or access for a principal used by Mandatory Integrity Control (MIC). | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.caseless | Multi-field of `process.executable`. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.caseless | Multi-field of `process.name`. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.group_leader.name |  | keyword |
| url.user_info |  | keyword |


### incident

This is the `incident` dataset.

#### Example

An example event for `incident` looks as following:

```json
{
    "@timestamp": "2021-09-30T09:35:45.113Z",
    "agent": {
        "ephemeral_id": "5aa5e360-7f01-44c9-9f9e-e937ce979f07",
        "id": "a7b00d49-6bd4-4763-8f95-51625034832b",
        "name": "elastic-agent-67823",
        "type": "filebeat",
        "version": "8.18.1"
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
        "namespace": "38577",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a7b00d49-6bd4-4763-8f95-51625034832b",
        "snapshot": false,
        "version": "8.18.1"
    },
    "event": {
        "action": [
            "detected"
        ],
        "agent_id_status": "verified",
        "created": "2021-08-13T08:43:35.553Z",
        "dataset": "m365_defender.incident",
        "id": "2972395",
        "ingested": "2025-06-03T13:18:39Z",
        "kind": "alert",
        "original": "{\"@odata.type\":\"#microsoft.graph.security.incident\",\"alerts\":{\"@odata.type\":\"#microsoft.graph.security.alert\",\"actorDisplayName\":null,\"alertWebUrl\":\"https://security.microsoft.com/alerts/da637551227677560813_-961444813?tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c\",\"assignedTo\":null,\"category\":\"DefenseEvasion\",\"classification\":\"unknown\",\"comments\":[],\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"description\":\"A hidden file has been launched. This activity could indicate a compromised host. Attackers often hide files associated with malicious tools to evade file system inspection and defenses.\",\"detectionSource\":\"antivirus\",\"detectorId\":\"e0da400f-affd-43ef-b1d5-afc2eb6f2756\",\"determination\":\"unknown\",\"evidence\":[{\"@odata.type\":\"#microsoft.graph.security.deviceEvidence\",\"azureAdDeviceId\":null,\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"defenderAvStatus\":\"unknown\",\"deviceDnsName\":\"tempDns\",\"firstSeenDateTime\":\"2020-09-12T07:28:32.4321753Z\",\"healthStatus\":\"active\",\"loggedOnUsers\":[],\"mdeDeviceId\":\"73e7e2de709dff64ef64b1d0c30e67fab63279db\",\"onboardingStatus\":\"onboarded\",\"osBuild\":22424,\"osPlatform\":\"Windows10\",\"rbacGroupId\":75,\"rbacGroupName\":\"UnassignedGroup\",\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"riskScore\":\"medium\",\"roles\":[\"compromised\"],\"tags\":[\"Test Machine\"],\"verdict\":\"unknown\",\"version\":\"Other\",\"vmMetadata\":{\"cloudProvider\":\"azure\",\"resourceId\":\"/subscriptions/8700d3a3-3bb7-4fbe-a090-488a1ad04161/resourceGroups/WdatpApi-EUS-STG/providers/Microsoft.Compute/virtualMachines/NirLaviTests\",\"subscriptionId\":\"8700d3a3-3bb7-4fbe-a090-488a1ad04161\",\"vmId\":\"ca1b0d41-5a3b-4d95-b48b-f220aed11d78\"}},{\"@odata.type\":\"#microsoft.graph.security.fileEvidence\",\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"detectionStatus\":\"detected\",\"fileDetails\":{\"fileName\":\"MsSense.exe\",\"filePath\":\"C:\\\\Program Files\\\\temp\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":6136392,\"issuer\":null,\"sha1\":\"5f1e8acedc065031aad553b710838eb366cfee9a\",\"sha256\":\"8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec\",\"signer\":null},\"mdeDeviceId\":\"73e7e2de709dff64ef64b1d0c30e67fab63279db\",\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"verdict\":\"unknown\"},{\"@odata.type\":\"#microsoft.graph.security.processEvidence\",\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"detectionStatus\":\"detected\",\"imageFile\":{\"fileName\":\"MsSense.exe\",\"filePath\":\"C:\\\\Program Files\\\\temp\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":6136392,\"issuer\":null,\"sha1\":\"5f1e8acedc065031aad553b710838eb366cfee9a\",\"sha256\":\"8963a19fb992ad9a76576c5638fd68292cffb9aaac29eb8285f9abf6196a7dec\",\"signer\":null},\"mdeDeviceId\":\"73e7e2de709dff64ef64b1d0c30e67fab63279db\",\"parentProcessCreationDateTime\":\"2021-08-12T07:39:09.0909239Z\",\"parentProcessId\":668,\"parentProcessImageFile\":{\"fileName\":\"services.exe\",\"filePath\":\"C:\\\\Windows\\\\System32\",\"filePublisher\":\"Microsoft Corporation\",\"fileSize\":731744,\"issuer\":null,\"sha1\":null,\"sha256\":null,\"signer\":null},\"processCommandLine\":\"\\\"MsSense.exe\\\"\",\"processCreationDateTime\":\"2021-08-12T12:43:19.0772577Z\",\"processId\":4780,\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"userAccount\":{\"accountName\":\"SYSTEM\",\"azureAdUserId\":null,\"domainName\":\"NT AUTHORITY\",\"userPrincipalName\":null,\"userSid\":\"S-1-5-18\"},\"verdict\":\"unknown\"},{\"@odata.type\":\"#microsoft.graph.security.registryKeyEvidence\",\"createdDateTime\":\"2021-04-27T12:19:27.7211305Z\",\"registryHive\":\"HKEY_LOCAL_MACHINE\",\"registryKey\":\"SYSTEM\\\\CONTROLSET001\\\\CONTROL\\\\WMI\\\\AUTOLOGGER\\\\SENSEAUDITLOGGER\",\"remediationStatus\":\"none\",\"remediationStatusDetails\":null,\"roles\":[],\"tags\":[],\"verdict\":\"unknown\"}],\"firstActivityDateTime\":\"2021-04-26T07:45:50.116Z\",\"id\":\"da637551227677560813_-961444813\",\"incidentId\":\"28282\",\"incidentWebUrl\":\"https://security.microsoft.com/incidents/28282?tid=b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c\",\"lastActivityDateTime\":\"2021-05-02T07:56:58.222Z\",\"lastUpdateDateTime\":\"2021-05-02T14:19:01.3266667Z\",\"mitreTechniques\":[\"T1564.001\"],\"providerAlertId\":\"da637551227677560813_-961444813\",\"recommendedActions\":\"Collect artifacts and determine scope\\n�\\tReview the machine timeline for suspicious activities that may have occurred before and after the time of the alert, and record additional related artifacts (files, IPs/URLs) \\n�\\tLook for the presence of relevant artifacts on other systems. Identify commonalities and differences between potentially compromised systems.\\n�\\tSubmit relevant files for deep analysis and review resulting detailed behavioral information.\\n�\\tSubmit undetected files to the MMPC malware portal\\n\\nInitiate containment \\u0026 mitigation \\n�\\tContact the user to verify intent and initiate local remediation actions as needed.\\n�\\tUpdate AV signatures and run a full scan. The scan might reveal and remove previously-undetected malware components.\\n�\\tEnsure that the machine has the latest security updates. In particular, ensure that you have installed the latest software, web browser, and Operating System versions.\\n�\\tIf credential theft is suspected, reset all relevant users passwords.\\n�\\tBlock communication with relevant URLs or IPs at the organization�s perimeter.\",\"resolvedDateTime\":null,\"serviceSource\":\"microsoftDefenderForEndpoint\",\"severity\":\"low\",\"status\":\"new\",\"tenantId\":\"b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c\",\"threatDisplayName\":null,\"threatFamilyName\":null,\"title\":\"Suspicious execution of hidden file\"},\"assignedTo\":\"KaiC@contoso.onmicrosoft.com\",\"classification\":\"truePositive\",\"comments\":[{\"comment\":\"Demo incident\",\"createdBy\":\"DavidS@contoso.onmicrosoft.com\",\"createdTime\":\"2021-09-30T12:07:37.2756993Z\"}],\"createdDateTime\":\"2021-08-13T08:43:35.5533333Z\",\"determination\":\"multiStagedAttack\",\"displayName\":\"Multi-stage incident involving Initial access \\u0026 Command and control on multiple endpoints reported by multiple sources\",\"id\":\"2972395\",\"incidentWebUrl\":\"https://security.microsoft.com/incidents/2972395?tid=12f988bf-16f1-11af-11ab-1d7cd011db47\",\"lastUpdateDateTime\":\"2021-09-30T09:35:45.1133333Z\",\"redirectIncidentId\":null,\"severity\":\"medium\",\"status\":\"active\",\"tags\":[\"Demo\"],\"tenantId\":\"b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c\"}",
        "provider": "microsoftDefenderForEndpoint",
        "severity": 47,
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
        "entity_id": [
            "4780"
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
            "entity_id": [
                "668"
            ],
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
            "KaiC",
            "KaiC@contoso.onmicrosoft.com",
            "DavidS@contoso.onmicrosoft.com",
            "SYSTEM",
            "S-1-5-18"
        ]
    },
    "source": {
        "user": {
            "domain": "contoso.onmicrosoft.com",
            "email": "KaiC@contoso.onmicrosoft.com",
            "name": "KaiC"
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
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


### vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-05-27T10:44:59.658Z",
    "agent": {
        "ephemeral_id": "5f1f16e8-9234-4c2f-8497-bcbf282d23f5",
        "id": "f145b2f6-c9f6-40bb-ba86-40ed3894824a",
        "name": "elastic-agent-85182",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "m365_defender.vulnerability",
        "namespace": "42235",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "f145b2f6-c9f6-40bb-ba86-40ed3894824a",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "m365_defender.vulnerability",
        "id": "94819846155826828d1603b913c67fe336d81295-_-CVE-2025-3074-_-microsoft-_-edge_chromium-based-_-134.0.3124.72-_--2025-05-27T10:45:00.675702254Z",
        "ingested": "2025-05-27T10:45:00Z",
        "kind": "event",
        "original": "{\"affectedMachine\":{\"aadDeviceId\":null,\"agentVersion\":\"30.124092.2.0\",\"computerDnsName\":\"bdp3449-ub20-2-4a4f31e2-46ea-4c26-ad89-f09ad1d5fe01\",\"cveId\":\"CVE-2025-3074\",\"deviceValue\":\"Normal\",\"exclusionReason\":null,\"exposureLevel\":\"Low\",\"firstSeen\":\"2025-01-08T13:05:05.3483549Z\",\"fixingKbId\":null,\"healthStatus\":\"Inactive\",\"id\":\"94819846155826828d1603b913c67fe336d81295-_-CVE-2025-3074-_-microsoft-_-edge_chromium-based-_-134.0.3124.72-_-\",\"ipAddresses\":[{\"ipAddress\":\"216.160.83.56\",\"macAddress\":\"000C2910F1DA\",\"operationalStatus\":\"Up\",\"type\":\"Other\"}],\"isAadJoined\":false,\"isExcluded\":false,\"isPotentialDuplication\":false,\"lastExternalIpAddress\":\"1.128.0.0\",\"lastIpAddress\":\"175.16.199.0\",\"lastSeen\":\"2025-01-08T13:15:03.694371Z\",\"machineId\":\"94819846155826828d1603b913c67fe336d81295\",\"machineTags\":[\"test tag\"],\"managedBy\":\"MicrosoftDefenderForEndpoint\",\"managedByStatus\":\"Success\",\"mergedIntoMachineId\":null,\"onboardingStatus\":\"Onboarded\",\"osArchitecture\":\"64-bit\",\"osBuild\":6,\"osPlatform\":\"Ubuntu\",\"osProcessor\":\"x64\",\"osVersion\":null,\"productName\":\"edge_chromium-based\",\"productVendor\":\"microsoft\",\"productVersion\":\"134.0.3124.72\",\"rbacGroupId\":0,\"rbacGroupName\":null,\"riskScore\":\"None\",\"severity\":\"Medium\",\"version\":\"20.4\",\"vmMetadata\":null},\"cveSupportability\":\"Supported\",\"cvssV3\":6.5,\"cvssVector\":\"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:U/RL:O/RC:C\",\"description\":\"Summary: An inappropriate implementation in the Downloads feature of Google Chrome versions prior to 135.0.7049.52 could allow a remote attacker to perform UI spoofing via a crafted HTML page. This vulnerability, classified with a low severity by Chromium, may also enable bypassing security restrictions when a victim visits a specially crafted website. Impact: Exploitation of this vulnerability could lead to UI spoofing or bypassing security restrictions, potentially compromising user trust and security. AdditionalInformation: This vulnerability is associated with Google Chrome and has implications for Microsoft Edge (Chromium-based) due to shared code ingestion. Refer to Google Chrome Releases for further details. Remediation: Apply the latest patches and updates provided by the respective vendors. [Generated by AI]\",\"epss\":0.00111,\"exploitInKit\":false,\"exploitTypes\":[],\"exploitUris\":[],\"exploitVerified\":false,\"exposedMachines\":2,\"firstDetected\":\"2025-04-01T19:52:39Z\",\"id\":\"CVE-2025-3074\",\"name\":\"CVE-2025-3074\",\"patchFirstAvailable\":null,\"publicExploit\":false,\"publishedOn\":\"2025-04-01T00:00:00Z\",\"severity\":\"Medium\",\"tags\":[\"test\"],\"updatedOn\":\"2025-04-08T00:00:00Z\"}",
        "type": [
            "info"
        ]
    },
    "group": {
        "id": "0"
    },
    "host": {
        "architecture": "x64",
        "hostname": "bdp3449-ub20-2-4a4f31e2-46ea-4c26-ad89-f09ad1d5fe01",
        "id": "94819846155826828d1603b913c67fe336d81295",
        "ip": [
            "1.128.0.0"
        ],
        "name": "bdp3449-ub20-2-4a4f31e2-46ea-4c26-ad89-f09ad1d5fe01",
        "os": {
            "name": "Ubuntu 20.4",
            "platform": "Ubuntu",
            "type": "linux",
            "version": "20.4"
        },
        "risk": {
            "calculated_level": "None"
        }
    },
    "input": {
        "type": "cel"
    },
    "m365_defender": {
        "vulnerability": {
            "affected_machine": {
                "agent_version": "30.124092.2.0",
                "computer_dns_name": "bdp3449-ub20-2-4a4f31e2-46ea-4c26-ad89-f09ad1d5fe01",
                "device_value": "Normal",
                "exposure_level": "Low",
                "first_seen": "2025-01-08T13:05:05.348Z",
                "health_status": "Inactive",
                "id": "94819846155826828d1603b913c67fe336d81295-_-CVE-2025-3074-_-microsoft-_-edge_chromium-based-_-134.0.3124.72-_-",
                "ip_addresses": [
                    {
                        "ip_address": "216.160.83.56",
                        "mac_address": "00-0C-29-10-F1-DA",
                        "operational_status": "Up",
                        "type": "Other"
                    }
                ],
                "is_aad_joined": false,
                "is_excluded": false,
                "is_potential_duplication": false,
                "last_external_ip_address": "1.128.0.0",
                "last_ip_address": "175.16.199.0",
                "last_seen": "2025-01-08T13:15:03.694Z",
                "machine_id": "94819846155826828d1603b913c67fe336d81295",
                "machine_tags": [
                    "test tag"
                ],
                "managed_by": "MicrosoftDefenderForEndpoint",
                "managed_by_status": "Success",
                "onboarding_status": "Onboarded",
                "os_architecture": "64-bit",
                "os_build": 6,
                "os_platform": "Ubuntu",
                "os_processor": "x64",
                "product_name": "edge_chromium-based",
                "product_vendor": "microsoft",
                "product_version": "134.0.3124.72",
                "rbac_group_id": "0",
                "risk_score": "None",
                "severity": "Medium",
                "version": "20.4"
            },
            "cve_supportability": "Supported",
            "cvss_v3": 6.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:U/RL:O/RC:C",
            "description": "Summary: An inappropriate implementation in the Downloads feature of Google Chrome versions prior to 135.0.7049.52 could allow a remote attacker to perform UI spoofing via a crafted HTML page. This vulnerability, classified with a low severity by Chromium, may also enable bypassing security restrictions when a victim visits a specially crafted website. Impact: Exploitation of this vulnerability could lead to UI spoofing or bypassing security restrictions, potentially compromising user trust and security. AdditionalInformation: This vulnerability is associated with Google Chrome and has implications for Microsoft Edge (Chromium-based) due to shared code ingestion. Refer to Google Chrome Releases for further details. Remediation: Apply the latest patches and updates provided by the respective vendors. [Generated by AI]",
            "epss": 0.00111,
            "exploit_in_kit": false,
            "exploit_verified": false,
            "exposed_machines": 2,
            "first_detected": "2025-04-01T19:52:39.000Z",
            "id": "CVE-2025-3074",
            "impact": "Exploitation of this vulnerability could lead to UI spoofing or bypassing security restrictions, potentially compromising user trust and security.",
            "name": "CVE-2025-3074",
            "public_exploit": false,
            "published_on": "2025-04-01T00:00:00.000Z",
            "remediation": "Apply the latest patches and updates provided by the respective vendors.",
            "severity": "Medium",
            "tags": [
                "test"
            ],
            "updated_on": "2025-04-08T00:00:00.000Z"
        }
    },
    "message": "Summary: An inappropriate implementation in the Downloads feature of Google Chrome versions prior to 135.0.7049.52 could allow a remote attacker to perform UI spoofing via a crafted HTML page. This vulnerability, classified with a low severity by Chromium, may also enable bypassing security restrictions when a victim visits a specially crafted website. Impact: Exploitation of this vulnerability could lead to UI spoofing or bypassing security restrictions, potentially compromising user trust and security. AdditionalInformation: This vulnerability is associated with Google Chrome and has implications for Microsoft Edge (Chromium-based) due to shared code ingestion. Refer to Google Chrome Releases for further details. Remediation: Apply the latest patches and updates provided by the respective vendors. [Generated by AI]",
    "observer": {
        "product": "Microsoft 365 Defender",
        "vendor": "Microsoft"
    },
    "package": {
        "name": "edge_chromium-based",
        "version": "134.0.3124.72"
    },
    "related": {
        "hosts": [
            "bdp3449-ub20-2-4a4f31e2-46ea-4c26-ad89-f09ad1d5fe01",
            "94819846155826828d1603b913c67fe336d81295"
        ],
        "ip": [
            "216.160.83.56",
            "1.128.0.0",
            "175.16.199.0"
        ]
    },
    "resource": {
        "id": "94819846155826828d1603b913c67fe336d81295",
        "name": "bdp3449-ub20-2-4a4f31e2-46ea-4c26-ad89-f09ad1d5fe01"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "m365_defender-vulnerability"
    ],
    "vulnerability": {
        "classification": "CVSS",
        "description": "Summary: An inappropriate implementation in the Downloads feature of Google Chrome versions prior to 135.0.7049.52 could allow a remote attacker to perform UI spoofing via a crafted HTML page. This vulnerability, classified with a low severity by Chromium, may also enable bypassing security restrictions when a victim visits a specially crafted website. Impact: Exploitation of this vulnerability could lead to UI spoofing or bypassing security restrictions, potentially compromising user trust and security. AdditionalInformation: This vulnerability is associated with Google Chrome and has implications for Microsoft Edge (Chromium-based) due to shared code ingestion. Refer to Google Chrome Releases for further details. Remediation: Apply the latest patches and updates provided by the respective vendors. [Generated by AI]",
        "enumeration": "CVE",
        "id": "CVE-2025-3074",
        "published_date": "2025-04-01T00:00:00.000Z",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2025-3074",
        "scanner": {
            "vendor": "Microsoft"
        },
        "score": {
            "base": 6.5
        },
        "severity": "Medium",
        "title": "An inappropriate implementation in the Downloads feature of Google Chrome versions prior to 135.0.7049.52 could allow a remote attacker to perform UI spoofing via a crafted HTML page. This vulnerability, classified with a low severity by Chromium, may also enable bypassing security restrictions when a victim visits a specially crafted website."
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
| m365_defender.vulnerability.affected_machine.aad_device_id | Microsoft Entra Device ID (when machine is Microsoft Entra joined). | keyword |
| m365_defender.vulnerability.affected_machine.agent_version |  | keyword |
| m365_defender.vulnerability.affected_machine.computer_dns_name | Machine fully qualified name. | keyword |
| m365_defender.vulnerability.affected_machine.device_value | The value of the device. Possible values are: Normal, Low, and High. | keyword |
| m365_defender.vulnerability.affected_machine.exclusion_reason |  | keyword |
| m365_defender.vulnerability.affected_machine.exposure_level | Exposure level as evaluated by Microsoft Defender for Endpoint. Possible values are: None, Low, Medium, and High. | keyword |
| m365_defender.vulnerability.affected_machine.first_seen | First date and time where the machine was observed by Microsoft Defender for Endpoint. | date |
| m365_defender.vulnerability.affected_machine.fixing_kb_id |  | keyword |
| m365_defender.vulnerability.affected_machine.health_status | machine health status. Possible values are: Active, Inactive, ImpairedCommunication, NoSensorData, NoSensorDataImpairedCommunication, and Unknown. | keyword |
| m365_defender.vulnerability.affected_machine.id |  | keyword |
| m365_defender.vulnerability.affected_machine.ip_addresses.ip_address |  | ip |
| m365_defender.vulnerability.affected_machine.ip_addresses.mac_address |  | keyword |
| m365_defender.vulnerability.affected_machine.ip_addresses.operational_status |  | keyword |
| m365_defender.vulnerability.affected_machine.ip_addresses.type |  | keyword |
| m365_defender.vulnerability.affected_machine.is_aad_joined |  | boolean |
| m365_defender.vulnerability.affected_machine.is_excluded |  | boolean |
| m365_defender.vulnerability.affected_machine.is_potential_duplication |  | boolean |
| m365_defender.vulnerability.affected_machine.last_external_ip_address | Last IP through which the machine accessed the internet. | ip |
| m365_defender.vulnerability.affected_machine.last_ip_address | Last IP on local NIC on the machine. | ip |
| m365_defender.vulnerability.affected_machine.last_seen | Time and date of the last received full device report. A device typically sends a full report every 24 hours. NOTE: This property doesn't correspond to the last seen value in the UI. It pertains to the last device update. | date |
| m365_defender.vulnerability.affected_machine.machine_id | Machine identity. | keyword |
| m365_defender.vulnerability.affected_machine.machine_tags | Set of machine tags. | keyword |
| m365_defender.vulnerability.affected_machine.managed_by |  | keyword |
| m365_defender.vulnerability.affected_machine.managed_by_status |  | keyword |
| m365_defender.vulnerability.affected_machine.merged_into_machine_id |  | keyword |
| m365_defender.vulnerability.affected_machine.onboarding_status | Status of machine onboarding. Possible values are: onboarded, CanBeOnboarded, Unsupported, and InsufficientInfo. | keyword |
| m365_defender.vulnerability.affected_machine.os_architecture | Operating system architecture. Possible values are: 32-bit, 64-bit. Use this property instead of osProcessor. | keyword |
| m365_defender.vulnerability.affected_machine.os_build | Operating system build number. | long |
| m365_defender.vulnerability.affected_machine.os_platform | Operating system platform. | keyword |
| m365_defender.vulnerability.affected_machine.os_processor | Operating system processor. Use osArchitecture property instead. | keyword |
| m365_defender.vulnerability.affected_machine.os_version |  | keyword |
| m365_defender.vulnerability.affected_machine.product_name |  | keyword |
| m365_defender.vulnerability.affected_machine.product_vendor |  | keyword |
| m365_defender.vulnerability.affected_machine.product_version |  | keyword |
| m365_defender.vulnerability.affected_machine.rbac_group_id | Machine group ID. | keyword |
| m365_defender.vulnerability.affected_machine.rbac_group_name | Machine group Name. | keyword |
| m365_defender.vulnerability.affected_machine.risk_score | Risk score as evaluated by Microsoft Defender for Endpoint. Possible values are: None, Informational, Low, Medium, and High. | keyword |
| m365_defender.vulnerability.affected_machine.severity |  | keyword |
| m365_defender.vulnerability.affected_machine.version | Operating system version. | keyword |
| m365_defender.vulnerability.affected_machine.vmMetadata.cloud_provider |  | keyword |
| m365_defender.vulnerability.affected_machine.vmMetadata.resource_id |  | keyword |
| m365_defender.vulnerability.affected_machine.vmMetadata.subscription_id |  | keyword |
| m365_defender.vulnerability.affected_machine.vmMetadata.vm_id |  | keyword |
| m365_defender.vulnerability.cve_supportability | Possible values are: Supported, Not Supported, or SupportedInPremium. | keyword |
| m365_defender.vulnerability.cvss_v3 | CVSS v3 score. | double |
| m365_defender.vulnerability.cvss_vector | A compressed textual representation that reflects the values used to derive the score. | keyword |
| m365_defender.vulnerability.description | Vulnerability description. | keyword |
| m365_defender.vulnerability.epss | Represents the probability that a vulnerability will be exploited. This probability is expressed as a number between 0 and 1 (0%-100%) according to the EPSS model. | double |
| m365_defender.vulnerability.exploit_in_kit | Exploit is part of an exploit kit. | boolean |
| m365_defender.vulnerability.exploit_types | Exploit affect. Possible values are: Local privilege escalation, Denial of service, or Local. | keyword |
| m365_defender.vulnerability.exploit_uris | Exploit source URLs. | keyword |
| m365_defender.vulnerability.exploit_verified | Exploit is verified to work. | boolean |
| m365_defender.vulnerability.exposed_machines | Number of exposed devices. | long |
| m365_defender.vulnerability.first_detected |  | date |
| m365_defender.vulnerability.id | Vulnerability ID. | keyword |
| m365_defender.vulnerability.impact |  | keyword |
| m365_defender.vulnerability.name | Vulnerability title. | keyword |
| m365_defender.vulnerability.patch_first_available |  | date |
| m365_defender.vulnerability.public_exploit | Public exploit exists. | boolean |
| m365_defender.vulnerability.published_on | Date when vulnerability was published. | date |
| m365_defender.vulnerability.remediation |  | keyword |
| m365_defender.vulnerability.severity | Vulnerability Severity. Possible values are: Low, Medium, High, or Critical. | keyword |
| m365_defender.vulnerability.tags |  | keyword |
| m365_defender.vulnerability.updated_on | Date when vulnerability was updated. | date |
| package.fixed_version |  | keyword |
| package.name | Package name | keyword |
| package.version | Package version | keyword |
| resource.id |  | keyword |
| resource.name |  | keyword |
| vulnerability.published_date |  | date |
| vulnerability.title |  | keyword |

