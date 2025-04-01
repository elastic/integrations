# Microsoft Defender for Endpoint integration

This integration is for [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide) logs.

## Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

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
    "@timestamp": "2025-04-01T09:20:53.806Z",
    "agent": {
        "ephemeral_id": "57c2955e-3022-4c82-813b-eff4e3d6a79b",
        "id": "570010d2-ab7e-4d5b-882e-ed58b15778da",
        "name": "elastic-agent-88683",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "cloud": {
        "account": {
            "id": "123543-d66c-4c7e-9e30-40034eb7c6f3"
        },
        "instance": {
            "id": "c5a964f417c11f6277d5bf9489f0d"
        },
        "provider": "azure"
    },
    "data_stream": {
        "dataset": "microsoft_defender_endpoint.log",
        "namespace": "65879",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "570010d2-ab7e-4d5b-882e-ed58b15778da",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "Malware",
        "agent_id_status": "verified",
        "category": [
            "host",
            "malware"
        ],
        "created": "2020-06-30T10:09:01.1569718Z",
        "dataset": "microsoft_defender_endpoint.log",
        "duration": 0,
        "end": "2020-06-30T10:07:44.333733Z",
        "id": "da637291085411733957_-1043898914",
        "ingested": "2025-04-01T09:20:56Z",
        "kind": "alert",
        "provider": "defender_endpoint",
        "severity": 2,
        "start": "2020-06-30T10:07:44.333733Z",
        "timezone": "UTC",
        "type": [
            "end"
        ]
    },
    "file": {
        "name": "SB.xsl",
        "path": "C:\\Windows\\Temp\\sb-sim-temp-ikyxqi\\sb_10554_bs_h4qpk5"
    },
    "host": {
        "hostname": "testserver4",
        "id": "c5a964f417c11f6277d5bf9489f0d",
        "name": "testserver4"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/defender_atp-test.json.log"
        },
        "offset": 0
    },
    "message": "An active 'Exeselrun' malware was detected",
    "microsoft": {
        "defender_endpoint": {
            "assignedTo": "elastic@elasticuser.com",
            "evidence": {
                "entityType": "File"
            },
            "incidentId": "12",
            "investigationId": "9",
            "investigationState": "Benign",
            "lastUpdateTime": "2020-07-03T15:15:39.13Z",
            "resolvedTime": "2020-06-30T11:13:12.2680434Z",
            "status": "Resolved"
        }
    },
    "observer": {
        "name": "WindowsDefenderAv",
        "product": "Defender for Endpoint",
        "vendor": "Microsoft"
    },
    "related": {
        "hosts": [
            "testserver4"
        ]
    },
    "rule": {
        "description": "Malware and unwanted software are undesirable applications that perform annoying, disruptive, or harmful actions on affected machines. Some of these undesirable applications can replicate and spread from one machine to another. Others are able to receive commands from remote attackers and perform activities associated with cyber attacks.\n\nA malware is considered active if it is found running on the machine or it already has persistence mechanisms in place. Active malware detections are assigned higher severity ratings.\n\nBecause this malware was active, take precautionary measures and check for residual signs of infection."
    },
    "tags": [
        "microsoft-defender-endpoint",
        "forwarded"
    ],
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {
            "name": [
                "Malware"
            ]
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

