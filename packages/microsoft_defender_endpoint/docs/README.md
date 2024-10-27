# Microsoft Defender for Endpoint integration

This integration is for [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide) logs.

## Setting up

To allow the integration to ingest data from the Microsoft Defender API, you need to create a new application on your Azure domain. The procedure to create an application is found on the [Create a new Azure Application](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-webapp) documentation page.

> Note: When giving the application the API permissions described in the documentation (`Windows Defender ATP Alert.Read.All`), it will only grant access to read alerts from ATP and nothing else in the Azure Domain

After the application has been created, it should contain 3 values that you need to apply to the module configuration.

These values are:

- Client ID
- Client Secret
- Tenant ID

## ECS mappings

| Defender for Endpoint fields       | ECS Fields            |
| ---------------------------------- | --------------------- |
| alertCreationTime                  | @timestamp            |
| aadTenantId                        | cloud.account.id      |
| category                           | threat.technique.name |
| computerDnsName                    | host.hostname         |
| description                        | rule.description      |
| detectionSource                    | observer.name         |
| evidence.fileName                  | file.name             |
| evidence.filePath                  | file.path             |
| evidence.processId                 | process.pid           |
| evidence.processCommandLine        | process.command_line  |
| evidence.processCreationTime       | process.start         |
| evidence.parentProcessId           | process.parent.pid    |
| evidence.parentProcessCreationTime | process.parent.start  |
| evidence.sha1                      | file.hash.sha1        |
| evidence.sha256                    | file.hash.sha256      |
| evidence.url                       | url.full              |
| firstEventTime                     | event.start           |
| id                                 | event.id              |
| lastEventTime                      | event.end             |
| machineId                          | cloud.instance.id     |
| title                              | message               |
| severity                           | event.severity        |

An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-09-22T03:31:55.887Z",
    "agent": {
        "ephemeral_id": "20bd2ad7-6c7e-4d34-9d55-57edc09ba1a6",
        "id": "a4d1a8b2-b45c-4d97-a37a-bd371f13111b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "cloud": {
        "account": {
            "id": "a839b112-1253-6432-9bf6-94542403f21c"
        },
        "instance": {
            "id": "111e6dd8c833c8a052ea231ec1b19adaf497b625"
        },
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "microsoft_defender_endpoint.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a4d1a8b2-b45c-4d97-a37a-bd371f13111b",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "action": "Execution",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2021-01-26T20:33:57.7220239Z",
        "dataset": "microsoft_defender_endpoint.log",
        "duration": 101466100,
        "end": "2021-01-26T20:31:33.0577322Z",
        "id": "da637472900382838869_1364969609",
        "ingested": "2023-09-22T03:31:58Z",
        "kind": "alert",
        "provider": "defender_endpoint",
        "severity": 2,
        "start": "2021-01-26T20:31:32.9562661Z",
        "timezone": "UTC",
        "type": [
            "access",
            "start"
        ]
    },
    "host": {
        "hostname": "temp123.middleeast.corp.microsoft.com",
        "name": "temp123.middleeast.corp.microsoft.com"
    },
    "input": {
        "type": "httpjson"
    },
    "message": "Low-reputation arbitrary code executed by signed executable",
    "microsoft": {
        "defender_endpoint": {
            "evidence": {
                "aadUserId": "11118379-2a59-1111-ac3c-a51eb4a3c627",
                "accountName": "name",
                "domainName": "DOMAIN",
                "entityType": "User",
                "userPrincipalName": "temp123@microsoft.com"
            },
            "incidentId": "1126093",
            "investigationState": "Queued",
            "lastUpdateTime": "2021-01-26T20:33:59.2Z",
            "rbacGroupName": "A",
            "status": "New"
        }
    },
    "observer": {
        "name": "WindowsDefenderAtp",
        "product": "Defender for Endpoint",
        "vendor": "Microsoft"
    },
    "related": {
        "hosts": [
            "temp123.middleeast.corp.microsoft.com"
        ],
        "user": [
            "temp123"
        ]
    },
    "rule": {
        "description": "Binaries signed by Microsoft can be used to run low-reputation arbitrary code. This technique hides the execution of malicious code within a trusted process. As a result, the trusted process might exhibit suspicious behaviors, such as opening a listening port or connecting to a command-and-control (C&C) server."
    },
    "tags": [
        "microsoft-defender-endpoint",
        "forwarded"
    ],
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {
            "name": [
                "Execution"
            ]
        }
    },
    "user": {
        "domain": "DOMAIN",
        "id": "S-1-5-21-11111607-1111760036-109187956-75141",
        "name": "temp123"
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| microsoft.defender_endpoint.assignedTo | Owner of the alert. | keyword |
| microsoft.defender_endpoint.classification | Specification of the alert. Possible values are: 'Unknown', 'FalsePositive', 'TruePositive'. | keyword |
| microsoft.defender_endpoint.determination | Specifies the determination of the alert. Possible values are: 'NotAvailable', 'Apt', 'Malware', 'SecurityPersonnel', 'SecurityTesting', 'UnwantedSoftware', 'Other'. | keyword |
| microsoft.defender_endpoint.evidence.aadUserId | ID of the user involved in the alert | keyword |
| microsoft.defender_endpoint.evidence.accountName | Username of the user involved in the alert | keyword |
| microsoft.defender_endpoint.evidence.domainName | Domain name related to the alert | keyword |
| microsoft.defender_endpoint.evidence.entityType | The type of evidence | keyword |
| microsoft.defender_endpoint.evidence.ipAddress | IP address involved in the alert | ip |
| microsoft.defender_endpoint.evidence.userPrincipalName | Principal name of the user involved in the alert | keyword |
| microsoft.defender_endpoint.incidentId | The Incident ID of the Alert. | keyword |
| microsoft.defender_endpoint.investigationId | The Investigation ID related to the Alert. | keyword |
| microsoft.defender_endpoint.investigationState | The current state of the Investigation. | keyword |
| microsoft.defender_endpoint.lastUpdateTime | The date and time (in UTC) the alert was last updated. | date |
| microsoft.defender_endpoint.rbacGroupName | User group related to the alert | keyword |
| microsoft.defender_endpoint.resolvedTime | The date and time in which the status of the alert was changed to 'Resolved'. | date |
| microsoft.defender_endpoint.status | Specifies the current status of the alert. Possible values are: 'Unknown', 'New', 'InProgress' and 'Resolved'. | keyword |
| microsoft.defender_endpoint.threatFamilyName | Threat family. | keyword |

