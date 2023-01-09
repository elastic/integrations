# M365 Defender integration

## Overview

The [Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender) integration allows you to monitor Incident Logs. Microsoft 365 Defender is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

Use the Microsoft 365 Defender integration to collect and parse data from the Microsoft Graph Security v1.0 REST API and Microsoft 365 Defender API. Then visualise that data in Kibana.

For example, you could use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert and incident, a user can take an appropriate action in the Microsoft 365 Defender Portal.

## Data streams

The Microsoft 365 Defender integration collects logs for two types of events: Incident and Log.

**Incident** in Microsoft 365 Defender is a collection of correlated alert instances and associated metadata that reflects the story of an attack in a tenant. It uses the Microsoft Graph Security v1.0 REST API to collect data. See Example Schema [here](https://learn.microsoft.com/en-us/graph/api/resources/security-incident?view=graph-rest-1.0#properties).

**Log (Deprecated)** incidents API allows you to sort through incidents to create an informed cybersecurity response. It exposes a collection of incidents that were flagged in your network, within the time range you specified in your environmental retention policy. The most recent incidents are displayed at the top of the list. Each incident contains an array of related alerts and their related entities. It uses the Microsoft 365 Defender API to collect data. See Example Schema [here](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-list-incidents?view=o365-worldwide#schema-mapping).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has used **Microsoft Graph Security v1.0 REST API** and **Microsoft 365 Defender API**.

## Setup

### To collect data from Microsoft Graph Security v1.0 REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
2. Permission required for accessing Incident API would be **SecurityIncident.Read.All**. See more details [here](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0)
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for alert and incident data collection.

### To collect data from Microsoft 365 Defender REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app).
2. Permission required for accessing Log API would be **Incident.Read.All**.
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for log data collection.

## Logs reference

### incident

This is the `incident` dataset.

#### Example

An example event for `incident` looks as following:

```json
{
    "@timestamp": "2021-09-30T09:35:45.113Z",
    "agent": {
        "ephemeral_id": "d68cb804-9591-40e3-99c5-d7795d9cc6db",
        "hostname": "docker-fleet-agent",
        "id": "7d671689-2ad3-4d46-978e-feb42f33ba61",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
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
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "7d671689-2ad3-4d46-978e-feb42f33ba61",
        "snapshot": false,
        "version": "7.16.0"
    },
    "event": {
        "action": [
            "detected"
        ],
        "agent_id_status": "verified",
        "created": "2021-08-13T08:43:35.553Z",
        "dataset": "m365_defender.incident",
        "id": "2972395",
        "ingested": "2022-12-21T10:27:40Z",
        "kind": "event",
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
                "recommended_actions": "Collect artifacts and determine scope\n�\tReview the machine timeline for suspicious activities that may have occurred before and after the time of the alert, and record additional related artifacts (files, IPs/URLs) \n�\tLook for the presence of relevant artifacts on other systems. Identify commonalities and differences between potentially compromised systems.\n�\tSubmit relevant files for deep analysis and review resulting detailed behavioral information.\n�\tSubmit undetected files to the MMPC malware portal\n\nInitiate containment \u0026 mitigation \n�\tContact the user to verify intent and initiate local remediation actions as needed.\n�\tUpdate AV signatures and run a full scan. The scan might reveal and remove previously-undetected malware components.\n�\tEnsure that the machine has the latest security updates. In particular, ensure that you have installed the latest software, web browser, and Operating System versions.\n�\tIf credential theft is suspected, reset all relevant users passwords.\n�\tBlock communication with relevant URLs or IPs at the organization�s perimeter.",
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
            "display_name": "Multi-stage incident involving Initial access \u0026 Command and control on multiple endpoints reported by multiple sources",
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
    "message": "Multi-stage incident involving Initial access \u0026 Command and control on multiple endpoints reported by multiple sources",
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
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
| m365_defender.incident.alert.recommended_actions | Recommended response and remediation actions to take in the event this alert was generated. | keyword |
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
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.group.name | The name of the group for a set of related intrusion activity that are tracked by a common name in the security community. While not required, you can use a MITRE ATT&CK® group name. | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.technique.subtechnique.id | The full id of subtechnique used by this threat. You can use a MITRE ATT&CK® subtechnique, for example. (ex. https://attack.mitre.org/techniques/T1059/001/) | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
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
        "ephemeral_id": "59a61472-ed6a-45e4-aa4b-28da27acaafc",
        "hostname": "docker-fleet-agent",
        "id": "bfb1194b-23e1-4172-9477-2756dbcd4373",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
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
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "bfb1194b-23e1-4172-9477-2756dbcd4373",
        "snapshot": false,
        "version": "7.16.0"
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
        "ingested": "2022-12-15T09:17:21Z",
        "kind": "alert",
        "original": "{\"alerts\":{\"actorName\":null,\"alertId\":\"faf8edc936-85f8-a603-b800-08d8525cf099\",\"assignedTo\":\"Automation\",\"category\":\"InitialAccess\",\"classification\":null,\"creationTime\":\"2020-09-06T12:07:54.3716642Z\",\"description\":\"This alert is triggered when any email message is reported as malware or phish by users -V1.0.0.2\",\"detectionSource\":\"OfficeATP\",\"determination\":null,\"devices\":[],\"entities\":{\"aadUserId\":null,\"accountName\":null,\"clusterBy\":null,\"deliveryAction\":null,\"deviceId\":null,\"domainName\":null,\"entityType\":\"MailBox\",\"fileName\":null,\"filePath\":null,\"ipAddress\":null,\"mailboxAddress\":\"testUser3@contoso.com\",\"mailboxDisplayName\":\"test User3\",\"parentProcessCreationTime\":null,\"parentProcessId\":null,\"processCommandLine\":null,\"processCreationTime\":null,\"processId\":null,\"recipient\":null,\"registryHive\":null,\"registryKey\":null,\"registryValue\":null,\"registryValueType\":null,\"securityGroupId\":null,\"securityGroupName\":null,\"sender\":null,\"sha1\":null,\"sha256\":null,\"subject\":null,\"url\":null,\"userPrincipalName\":\"testUser3@contoso.com\",\"userSid\":null},\"firstActivity\":\"2020-09-06T12:04:00Z\",\"incidentId\":924518,\"investigationId\":null,\"investigationState\":\"Queued\",\"lastActivity\":\"2020-09-06T12:04:00Z\",\"lastUpdatedTime\":\"2020-09-06T12:37:40.88Z\",\"mitreTechniques\":[],\"resolvedTime\":null,\"serviceSource\":\"OfficeATP\",\"severity\":\"Informational\",\"status\":\"InProgress\",\"threatFamilyName\":null,\"title\":\"Email reported by user as malware or phish\"},\"assignedTo\":null,\"classification\":\"Unknown\",\"comments\":[],\"createdTime\":\"2020-09-06T12:07:55.1366667Z\",\"determination\":\"NotAvailable\",\"incidentId\":924518,\"incidentName\":\"Email reported by user as malware or phish\",\"lastUpdateTime\":\"2020-09-06T12:07:55.32Z\",\"redirectIncidentId\":null,\"severity\":\"Informational\",\"status\":\"Active\",\"tags\":[]}",
        "provider": "OfficeATP",
        "severity": 1,
        "start": "2020-09-06T12:04:00Z",
        "timezone": "UTC"
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
        "framework": "MITRE ATT\u0026CK",
        "technique": {
            "name": "InitialAccess"
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
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
| m365_defender.alerts.actorName | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.assignedTo | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.classification | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.creationTime | Deprecated key defined only in table map. | date |
| m365_defender.alerts.detectionSource | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.detectorId | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.determination | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.devices | Deprecated key defined only in table map. | flattened |
| m365_defender.alerts.entities.accountName | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.clusterBy | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.deliveryAction | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.deviceId | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.entityType | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.evidenceCreationTime | Deprecated key defined only in table map. | date |
| m365_defender.alerts.entities.ipAddress | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.mailboxAddress | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.mailboxDisplayName | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.recipient | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.registryHive | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.registryKey | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.registryValueType | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.remediationStatus | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.securityGroupId | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.securityGroupName | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.sender | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.subject | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.userSid | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.entities.verdict | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.incidentId | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.investigationId | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.investigationState | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.lastUpdatedTime | Deprecated key defined only in table map. | date |
| m365_defender.alerts.mitreTechniques | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.providerAlertId | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.resolvedTime | Deprecated key defined only in table map. | date |
| m365_defender.alerts.severity | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.status | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.threatFamilyName | Deprecated key defined only in table map. | keyword |
| m365_defender.alerts.userSid | Deprecated key defined only in table map. | keyword |
| m365_defender.assignedTo | Deprecated key defined only in table map. | keyword |
| m365_defender.classification | Deprecated key defined only in table map. | keyword |
| m365_defender.comments | Deprecated key defined only in table map. | flattened |
| m365_defender.determination | Deprecated key defined only in table map. | keyword |
| m365_defender.incidentId | Deprecated key defined only in table map. | keyword |
| m365_defender.incidentName | Deprecated key defined only in table map. | keyword |
| m365_defender.incidentUri | Deprecated key defined only in table map. | keyword |
| m365_defender.investigationState | Deprecated key defined only in table map. | keyword |
| m365_defender.redirectIncidentId | Deprecated key defined only in table map. | keyword |
| m365_defender.status | Deprecated key defined only in table map. | keyword |
| m365_defender.tags | Deprecated key defined only in table map. | keyword |
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

