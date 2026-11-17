# Zero Networks Integration

[Zero Networks](https://www.zeronetworks.com) is used by numerous orgazations to microsegment the network and apply MFA anywhere.

The **Zero Networks** integration uses Zero Networks' API to retrieve audit events and ingest them into Elasticsearch. This allows you to search, observe, and visualize the **Zero Networks** audit events through Elasticsearch.

The Elastic agent running this integration interacts with Zero Networks' infrastructure using their APIs to retrieve audit logs for an environment.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Data streams

The **Zero Networks** integration collects one type of data streams: logs.

**Logs** help you keep a record of events happening in **Zero Networks**.
Log data streams collected by the **Zero Networks** integration include Audit events. 

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Other requirements including:
 - Zero Networks API Token with Read access

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.


### Get an API Token

1. Log into the [Zero Networks portal](https://portal.zeronetworks.com).
2. Click **Setting**.
3. Click **API** under **Integrations**.
4. Click **Add new token**.
5. Enter a **Token Name** such as *Elastic Integration*. Set the **Expiry** to ** 36 Months**.  Click **Add**.
6. Copy the generated token for later use.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In the **"Search for integrations"** search bar type **Zero Networks**.
3. Click on **"Zero Networks"** integration from the search results.
4. Click on **Add Zero Networks** button to add the Zero Networks integration.

### Configure Zero Networks Audit logs data stream

Enter values **"API Token"**.

1. **API Token** copied from earlier steps.

***NOTE:*** Some operating systems may not have the root CA installed.  You can download the **[USERTrust RSA Certification Authority](https://ssl-tools.net/subjects/cd30d24c343a82ab1f0570158ad7a107762992e9)** and install it. As a work around, not recommended, you can set **verification_mode: none** in the **SSL** box under **Settings** by clicking **Advanced Options**.

## Logs reference

### Audit

The `audit` data stream provides audit events from Zero Networks, such as asset segmentation changes, rule and policy changes, and portal logons.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2024-04-01T08:30:36.440Z",
    "agent": {
        "ephemeral_id": "9f5e16d9-5d3b-4d3a-b858-bcca443fd381",
        "id": "adc346aa-b9e4-4a15-bca4-f4165156bd64",
        "name": "elastic-agent-31641",
        "type": "filebeat",
        "version": "9.5.5"
    },
    "data_stream": {
        "dataset": "zeronetworks.audit",
        "namespace": "15730",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "adc346aa-b9e4-4a15-bca4-f4165156bd64",
        "snapshot": false,
        "version": "9.5.5"
    },
    "event": {
        "action": "Inbound JIT rule created",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "code": "20",
        "created": "2026-11-17T13:09:57.999Z",
        "dataset": "zeronetworks.audit",
        "id": "5kpgk0bTgw+kPo5LHuGDTRF1or0=",
        "ingested": "2026-11-17T13:10:02Z",
        "kind": "event",
        "module": "zeronetworks",
        "original": "{\"auditType\":20,\"destinationEntitiesList\":[{\"id\":\"a:a:9ebab20f\",\"name\":\"SHARE\"}],\"details\":\"{\\\"rule\\\":{\\\"localEntityNames\\\":{\\\"id\\\":\\\"a:a:9ebab20f\\\",\\\"name\\\":\\\"SHARE\\\"},\\\"remoteEntityNames\\\":[{\\\"id\\\":\\\"a:a:Y5UYoaWk\\\",\\\"name\\\":\\\"SURFACE\\\"}],\\\"ports\\\":[{\\\"protocol_type\\\":6,\\\"ports\\\":\\\"3389\\\"}],\\\"expiration\\\":1711974636423,\\\"description\\\":\\\"RDP/WinRM MFA\\\",\\\"localProcesses\\\":[\\\"*\\\"],\\\"created_by\\\":{\\\"id\\\":\\\"u:a:OOdYqjWI\\\",\\\"name\\\":\\\"Benny Lakunishok\\\"},\\\"enforcementSource\\\":1,\\\"createdAt\\\":1711960236426,\\\"usedMfaMethod\\\":3,\\\"excludedLocalEntityNames\\\":[],\\\"state\\\":1,\\\"updatedAt\\\":1711960236426,\\\"updatedBy\\\":{},\\\"approvedAt\\\":0,\\\"approvedBy\\\":null,\\\"ruleClass\\\":3}}\",\"enforcementSource\":1,\"isoTimestamp\":\"2024-04-01T08:30:36.440Z\",\"parentObjectId\":\"75bde6e6-83d6-401b-b63b-c2ed062e80fb\",\"performedBy\":{\"id\":\"u:a:OOdYqjWI\",\"name\":\"Benny Lakunishok\"},\"reportedObjectGeneration\":15201363,\"reportedObjectId\":\"21cbb13b-848a-49f0-8fe1-1dc369987403\",\"timestamp\":1711960236440,\"userRole\":6}",
        "outcome": "success",
        "type": [
            "info",
            "change"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "user": [
            "u:a:OOdYqjWI",
            "Benny Lakunishok"
        ]
    },
    "tags": [
        "forwarded",
        "zeronetworks-audit",
        "preserve_original_event"
    ],
    "user": {
        "full_name": "Benny Lakunishok",
        "id": "u:a:OOdYqjWI"
    },
    "zeronetworks": {
        "audit": {
            "destinationEntitiesList": {
                "id": "a:a:9ebab20f",
                "name": "SHARE"
            },
            "details": {
                "rule": {
                    "approvedAt": "1970-01-01T00:00:00.000Z",
                    "createdAt": "2024-04-01T08:30:36.426Z",
                    "created_by": {
                        "id": "u:a:OOdYqjWI",
                        "name": "Benny Lakunishok"
                    },
                    "description": "RDP/WinRM MFA",
                    "enforcementSource": 1,
                    "expiration": "2024-04-01T12:30:36.423Z",
                    "localEntityNames": {
                        "id": "a:a:9ebab20f",
                        "name": "SHARE"
                    },
                    "localProcesses": "*",
                    "ports": {
                        "ports": "3389",
                        "protocol_type": 6
                    },
                    "remoteEntityNames": {
                        "id": "a:a:Y5UYoaWk",
                        "name": "SURFACE"
                    },
                    "ruleClass": 3,
                    "state": 1,
                    "updatedAt": "2024-04-01T08:30:36.426Z",
                    "usedMfaMethod": 3
                }
            },
            "enforcementSource": 1,
            "parentObjectId": "75bde6e6-83d6-401b-b63b-c2ed062e80fb",
            "reportedObjectGeneration": 15201363,
            "reportedObjectId": "21cbb13b-848a-49f0-8fe1-1dc369987403",
            "userRole": 6
        }
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| zeronetworks.audit.destinationEntitiesList.id | The id of the affected entity. | keyword |
| zeronetworks.audit.destinationEntitiesList.name | The name of the affected entity. | keyword |
| zeronetworks.audit.details.assetManager.entity.id | The id of the entity. | keyword |
| zeronetworks.audit.details.assetManager.entity.name | The name of the entity. | keyword |
| zeronetworks.audit.details.assetManager.manager.id | The id of the manager. | keyword |
| zeronetworks.audit.details.assetManager.manager.name | The name of the manager. | keyword |
| zeronetworks.audit.details.audience | The audience of the JWT token | keyword |
| zeronetworks.audit.details.clientId | Id of the token. | keyword |
| zeronetworks.audit.details.connectServer | The server the user connected to. | keyword |
| zeronetworks.audit.details.connectedSince | The time the user connected. | date |
| zeronetworks.audit.details.currInactiveReason | The current inactive reason. | integer |
| zeronetworks.audit.details.detection.dstAsset.Name | The name of the destination asset. | keyword |
| zeronetworks.audit.details.detection.dstAsset.id | The id of the destination asset. | keyword |
| zeronetworks.audit.details.detection.dstProcess | The destination process. | keyword |
| zeronetworks.audit.details.detection.loggedOnUser | The user that was logged on. | keyword |
| zeronetworks.audit.details.detection.port.ports | The ports of the audit. | keyword |
| zeronetworks.audit.details.detection.port.protocol_type | The protocol of the audit. | integer |
| zeronetworks.audit.details.detection.rejectedBy.id | The id who rejected. | keyword |
| zeronetworks.audit.details.detection.rejectedBy.name | The name who rejected. | keyword |
| zeronetworks.audit.details.detection.srcAsset.id | The id of the source asset. | keyword |
| zeronetworks.audit.details.detection.srcAsset.name | The name of the source asset. | keyword |
| zeronetworks.audit.details.detection.srcProcess | The source process. | keyword |
| zeronetworks.audit.details.detection.srcUser.id | The id of the source user. | keyword |
| zeronetworks.audit.details.detection.srcUser.name | The name of the source user. | keyword |
| zeronetworks.audit.details.detection.usedMfaMethod | The MFA method that was used. | integer |
| zeronetworks.audit.details.expiresAt | When the token expires. | date |
| zeronetworks.audit.details.expiry | When the token expires | date |
| zeronetworks.audit.details.externalIP | The external IP of the user. | ip |
| zeronetworks.audit.details.idp | The IDP used. | integer |
| zeronetworks.audit.details.issuedAt | When the token was issued. | date |
| zeronetworks.audit.details.issuer | The issuer of the token | keyword |
| zeronetworks.audit.details.learningDuration | The duration of learning set. | integer |
| zeronetworks.audit.details.name | The name of the token | keyword |
| zeronetworks.audit.details.newAsset.id | The new id of the asset. | keyword |
| zeronetworks.audit.details.newAsset.name | The new name of the asset. | keyword |
| zeronetworks.audit.details.otAsset.displayName | The display name of the OT asset. | keyword |
| zeronetworks.audit.details.otAsset.ipv4 | The IPv4 address of the OT asset. | ip |
| zeronetworks.audit.details.otAsset.ipv6 | The IPv6 address of the OT asset. | ip |
| zeronetworks.audit.details.otAsset.type | The type for the OT asset. | integer |
| zeronetworks.audit.details.prevInactiveReason | The previous inactive reason. | integer |
| zeronetworks.audit.details.prevOTAsset.displayName | The display name of the OT asset. | keyword |
| zeronetworks.audit.details.prevOTAsset.ipv4 | The IPv4 address of the OT asset. | ip |
| zeronetworks.audit.details.prevOTAsset.ipv6 | The IPv6 address of the OT asset. | ip |
| zeronetworks.audit.details.prevOTAsset.type | The type for the OT asset. | integer |
| zeronetworks.audit.details.prevProtectionPolicy.createdBy.id | The id of the created by. | keyword |
| zeronetworks.audit.details.prevProtectionPolicy.createdBy.name | The name of the created by. | keyword |
| zeronetworks.audit.details.prevProtectionPolicy.description | The description of the protection policy. | keyword |
| zeronetworks.audit.details.prevProtectionPolicy.group.id | The id of the group. | keyword |
| zeronetworks.audit.details.prevProtectionPolicy.group.name | The name of the group. | keyword |
| zeronetworks.audit.details.prevProtectionPolicy.initialProtectAt | The date the protection policy. | date |
| zeronetworks.audit.details.prevProtectionPolicy.minQueueDays | The integer of days in learning for the protection policy. | integer |
| zeronetworks.audit.details.prevRp.additionalPorts.ports | The ports. | keyword |
| zeronetworks.audit.details.prevRp.additionalPorts.protocol_type | The protocol type. | integer |
| zeronetworks.audit.details.prevRp.createdBy.id | The id of created by. | keyword |
| zeronetworks.audit.details.prevRp.createdBy.name | The name of created by. | keyword |
| zeronetworks.audit.details.prevRp.description | The description of the reactive policy. | keyword |
| zeronetworks.audit.details.prevRp.dstEntities.id | The id of the destination entity. | keyword |
| zeronetworks.audit.details.prevRp.dstEntities.name | The name of the destination entity. | keyword |
| zeronetworks.audit.details.prevRp.dstProcessNames | The destination process names. | keyword |
| zeronetworks.audit.details.prevRp.duration | The duration of the rule. | integer |
| zeronetworks.audit.details.prevRp.enforcementSource | The enforcement source. | integer |
| zeronetworks.audit.details.prevRp.excludedSrcEntities.id | The id of excluded entity. | keyword |
| zeronetworks.audit.details.prevRp.excludedSrcEntities.name | The name of excluded entity. | keyword |
| zeronetworks.audit.details.prevRp.excludedSrcProcessNames | The excluded source processes. | keyword |
| zeronetworks.audit.details.prevRp.mfaMethods | The approved MFA methods. | integer |
| zeronetworks.audit.details.prevRp.overrideBuiltins | Override global policies. | boolean |
| zeronetworks.audit.details.prevRp.ports | The ports for the policy. | keyword |
| zeronetworks.audit.details.prevRp.protocol | The protocol for the policy. | integer |
| zeronetworks.audit.details.prevRp.srcEntities.id | The id of the source entity. | keyword |
| zeronetworks.audit.details.prevRp.srcEntities.name | The name of the source entity. | keyword |
| zeronetworks.audit.details.prevRp.srcProcessNames | The source process names. | keyword |
| zeronetworks.audit.details.prevRp.srcUsers.id | The id of the source users. | keyword |
| zeronetworks.audit.details.prevRp.srcUsers.name | The name of the source users. | keyword |
| zeronetworks.audit.details.prevRp.state | The state of the policy. | integer |
| zeronetworks.audit.details.prevRp.userSource | The user source of the policy. | integer |
| zeronetworks.audit.details.prevRule.approvedAt | When the previous rule was approved. | date |
| zeronetworks.audit.details.prevRule.approvedBy.id | The id of the approver. | keyword |
| zeronetworks.audit.details.prevRule.approvedBy.name | The name of the approver. | keyword |
| zeronetworks.audit.details.prevRule.createdAt | The time the previous rule was created. | date |
| zeronetworks.audit.details.prevRule.created_by.id | The id of created by. | keyword |
| zeronetworks.audit.details.prevRule.created_by.name | The name of created by. | keyword |
| zeronetworks.audit.details.prevRule.description | The description of the previous rule. | keyword |
| zeronetworks.audit.details.prevRule.enforcementSource | The enforcement source of the previous rule. | integer |
| zeronetworks.audit.details.prevRule.excludedLocalEntityNames.id | The id of the excluded local entity. | keyword |
| zeronetworks.audit.details.prevRule.excludedLocalEntityNames.name | The name of the excluded local entity. | keyword |
| zeronetworks.audit.details.prevRule.expiration | The time the previous rule will expire. | date |
| zeronetworks.audit.details.prevRule.localEntityNames.id | The id of the local entity. | keyword |
| zeronetworks.audit.details.prevRule.localEntityNames.name | The name of the local entity. | keyword |
| zeronetworks.audit.details.prevRule.localProcesses | The local processes for the previous rule. | keyword |
| zeronetworks.audit.details.prevRule.ports.ports | The ports of the previous rule. | keyword |
| zeronetworks.audit.details.prevRule.ports.protocol_type | The protocol type for the ports of the previous rule. | integer |
| zeronetworks.audit.details.prevRule.remoteEntityNames.id | The id of the remote entity. | keyword |
| zeronetworks.audit.details.prevRule.remoteEntityNames.name | The name of the remote entity. | keyword |
| zeronetworks.audit.details.prevRule.ruleClass | The rule class of the previous rule. | integer |
| zeronetworks.audit.details.prevRule.state | The rule state of the previous rule. | integer |
| zeronetworks.audit.details.prevRule.updatedAt | The time the previous rule was updated. | date |
| zeronetworks.audit.details.prevRule.updatedBy.id | The id of the updated by. | keyword |
| zeronetworks.audit.details.prevRule.updatedBy.name | The name of the updated by. | keyword |
| zeronetworks.audit.details.prevRule.usedMfaMethod | The MFA method used for rule creation. | integer |
| zeronetworks.audit.details.protectionDate | The date the asset was protected. | date |
| zeronetworks.audit.details.protectionPolicy.createdBy.id | The id of the created by. | keyword |
| zeronetworks.audit.details.protectionPolicy.createdBy.name | The name of the created by. | keyword |
| zeronetworks.audit.details.protectionPolicy.description | The description of the protection policy. | keyword |
| zeronetworks.audit.details.protectionPolicy.group.id | The id of the group. | keyword |
| zeronetworks.audit.details.protectionPolicy.group.name | The name of the group. | keyword |
| zeronetworks.audit.details.protectionPolicy.initialProtectAt | The date the protection policy. | date |
| zeronetworks.audit.details.protectionPolicy.minQueueDays | The integer of days in learning for the protection policy. | integer |
| zeronetworks.audit.details.publicIp | The IP the user logged into the portal with. | ip |
| zeronetworks.audit.details.role | The role of the user. | integer |
| zeronetworks.audit.details.rp.additionalPorts.ports | The ports. | keyword |
| zeronetworks.audit.details.rp.additionalPorts.protocol_type | The protocol type. | integer |
| zeronetworks.audit.details.rp.createdBy.id | The id of created by. | keyword |
| zeronetworks.audit.details.rp.createdBy.name | The name of created by. | keyword |
| zeronetworks.audit.details.rp.description | The description of the reactive policy. | keyword |
| zeronetworks.audit.details.rp.dstEntities.id | The id of the destination entity. | keyword |
| zeronetworks.audit.details.rp.dstEntities.name | The name of the destination entity. | keyword |
| zeronetworks.audit.details.rp.dstProcessNames | The destination process names. | keyword |
| zeronetworks.audit.details.rp.duration | The duration of the rule. | integer |
| zeronetworks.audit.details.rp.enforcementSource | The enforcement source. | integer |
| zeronetworks.audit.details.rp.excludedSrcEntities.id | The id of excluded entity. | keyword |
| zeronetworks.audit.details.rp.excludedSrcEntities.name | The name of excluded entity. | keyword |
| zeronetworks.audit.details.rp.excludedSrcProcessNames | The excluded source processes. | keyword |
| zeronetworks.audit.details.rp.mfaMethods | The approved MFA methods. | integer |
| zeronetworks.audit.details.rp.overrideBuiltins | Override global policies. | boolean |
| zeronetworks.audit.details.rp.ports | The ports for the policy. | keyword |
| zeronetworks.audit.details.rp.protocol | The protocol for the policy. | integer |
| zeronetworks.audit.details.rp.srcEntities.id | The id of the source entity. | keyword |
| zeronetworks.audit.details.rp.srcEntities.name | The name of the source entity. | keyword |
| zeronetworks.audit.details.rp.srcProcessNames | The source process names. | keyword |
| zeronetworks.audit.details.rp.srcUsers.id | The id of the source users. | keyword |
| zeronetworks.audit.details.rp.srcUsers.name | The name of the source users. | keyword |
| zeronetworks.audit.details.rp.state | The state of the policy. | integer |
| zeronetworks.audit.details.rp.userSource | The user source of the policy. | integer |
| zeronetworks.audit.details.rule.approvedAt | When the rule was approved. | date |
| zeronetworks.audit.details.rule.approvedBy.id | The id of the approver. | keyword |
| zeronetworks.audit.details.rule.approvedBy.name | The name of the approver. | keyword |
| zeronetworks.audit.details.rule.createdAt | The time the rule was created. | date |
| zeronetworks.audit.details.rule.created_by.id | The id of created by. | keyword |
| zeronetworks.audit.details.rule.created_by.name | The name of created by. | keyword |
| zeronetworks.audit.details.rule.description | The description of the rule. | keyword |
| zeronetworks.audit.details.rule.enforcementSource | The enforcement source of the rule. | integer |
| zeronetworks.audit.details.rule.excludedLocalEntityNames.id | The id of the excluded local entity. | keyword |
| zeronetworks.audit.details.rule.excludedLocalEntityNames.name | The name of the excluded local entity. | keyword |
| zeronetworks.audit.details.rule.expiration | The time the rule will expire. | date |
| zeronetworks.audit.details.rule.localEntityNames.id | The id of the local entity. | keyword |
| zeronetworks.audit.details.rule.localEntityNames.name | The name of the local entity. | keyword |
| zeronetworks.audit.details.rule.localProcesses | The local processes for the rule. | keyword |
| zeronetworks.audit.details.rule.ports.ports | The ports of the rule. | keyword |
| zeronetworks.audit.details.rule.ports.protocol_type | The protocol type for the ports of the rule. | integer |
| zeronetworks.audit.details.rule.remoteEntityNames.id | The id of the remote entity. | keyword |
| zeronetworks.audit.details.rule.remoteEntityNames.name | The name of the remote entity. | keyword |
| zeronetworks.audit.details.rule.ruleClass | The rule class of the rule. | integer |
| zeronetworks.audit.details.rule.state | The rule state of the rule. | integer |
| zeronetworks.audit.details.rule.updatedAt | The time the rule was updated. | date |
| zeronetworks.audit.details.rule.updatedBy.id | The id of the updated by. | keyword |
| zeronetworks.audit.details.rule.updatedBy.name | The name of the updated by. | keyword |
| zeronetworks.audit.details.rule.usedMfaMethod | The MFA method used for rule creation. | integer |
| zeronetworks.audit.details.scope | The scope of the token. | integer |
| zeronetworks.audit.details.sourceAsset | The source asset of the audit. | keyword |
| zeronetworks.audit.details.tokenTtl | The lifetime of the portal token. | date |
| zeronetworks.audit.details.type | The type of token that was created. | keyword |
| zeronetworks.audit.details.uacId | The UAC id. | keyword |
| zeronetworks.audit.details.uacName | The UAC name. | keyword |
| zeronetworks.audit.details.user | The user that performed the action. | keyword |
| zeronetworks.audit.enforcementSource | The platform of the audit. | integer |
| zeronetworks.audit.parentObjectId | The Id of the previous version object modified such as Rule Id. | keyword |
| zeronetworks.audit.prevProtectAt | When the asset was previously set to be protected. | date |
| zeronetworks.audit.protectAt | When the asset will be protected. | date |
| zeronetworks.audit.publicIp | The IP the user logged into the portal with. | ip |
| zeronetworks.audit.reason | The reason for the audit. | keyword |
| zeronetworks.audit.reportedObjectGeneration | The version of the reported object. | integer |
| zeronetworks.audit.reportedObjectId | The Id of the object modified such as Rule Id. | keyword |
| zeronetworks.audit.userRole | The role of the user performaing the action | integer |

