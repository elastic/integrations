# Bitwarden

## Overview

The [Bitwarden](https://bitwarden.com) integration allows users to monitor collections, groups, events and policies. Bitwarden is a free and open-source password management service that stores sensitive information such as website credentials in an encrypted vault. The Bitwarden platform offers a variety of client applications including a web interface, desktop applications, browser extensions, mobile apps and a command-line interface. Bitwarden offers a cloud-hosted service as well as the ability to deploy the solution on-premises.

Use the Bitwarden integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Bitwarden integration collects four types of data: collections, events, groups and policies.

**Collections** returns a list of an organization's collections.

**Events** returns a list of an organization's event logs.

**Groups** returns a list of an organization's groups.

**Policies** returns a list of an organization's policies.

Reference for [Rest APIs](https://bitwarden.com/help/api/) of Bitwarden.

## Requirements

Elasticsearch is needed to store and search data and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

This module has been tested against **Bitwarden Version 2023.2.0**.

## Setup

### To collect data from Bitwarden REST APIs, follow the below steps:

1. Go to the [Bitwarden console](https://vault.bitwarden.com/#/vault), enter an email address and master password.
2. Click **Organizations**.
3. Go to **Settings → Organization info**.
4. Click **View API Key** from API key Section.
5. Enter master password.
6. Click **View API Key**.
7. Copy **client_id** and **client_secret**.

## Logs Reference

### Collection

This is the `Collection` dataset.

#### Example

An example event for `collection` looks as following:

```json
{
    "@timestamp": "2023-04-18T11:44:01.141Z",
    "agent": {
        "ephemeral_id": "0601b1ca-3a76-4d9a-9ed7-3da5b4333d2d",
        "id": "ff2a1bfe-20b0-4bab-ad84-8609f33b69f8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "bitwarden": {
        "collection": {
            "external": {
                "id": "external_id_123456"
            },
            "id": "539a36c5-e0d2-4cf9-979e-51ecf5cf6593"
        },
        "object": "collection"
    },
    "data_stream": {
        "dataset": "bitwarden.collection",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "ff2a1bfe-20b0-4bab-ad84-8609f33b69f8",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-04-18T11:44:01.141Z",
        "dataset": "bitwarden.collection",
        "ingested": "2023-04-18T11:44:04Z",
        "kind": "event",
        "original": "{\"externalId\":\"external_id_123456\",\"groups\":null,\"id\":\"539a36c5-e0d2-4cf9-979e-51ecf5cf6593\",\"object\":\"collection\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "bitwarden-collection"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bitwarden.collection.external.id | External identifier for reference or linking this collection to another system. | keyword |
| bitwarden.collection.groups | The associated groups that this collection is assigned to. | nested |
| bitwarden.collection.id | The collection's unique identifier. | keyword |
| bitwarden.object | String representing the object's type. Objects of the same type share the same properties. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |


### Event

This is the `Event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2023-02-22T09:00:21.728Z",
    "agent": {
        "ephemeral_id": "03059a2a-a7ad-4677-a95d-00b24272a9af",
        "id": "ff2a1bfe-20b0-4bab-ad84-8609f33b69f8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "bitwarden": {
        "event": {
            "acting_user": {
                "id": "a2549f79-a71f-4eb9-9234-eb7247333f94"
            },
            "collection": {
                "id": "bce212a4-25f3-4888-8a0a-4c5736d851e0"
            },
            "date": "2023-02-22T09:00:21.728Z",
            "device": {
                "name": "Android",
                "value": "0"
            },
            "group": {
                "id": "f29a2515-91d2-4452-b49b-5e8040e6b0f4"
            },
            "ip_address": "172.16.254.1",
            "item": {
                "id": "3767a302-8208-4dc6-b842-030428a1cfad"
            },
            "member": {
                "id": "e68b8629-85eb-4929-92c0-b84464976ba4"
            },
            "policy": {
                "id": "f29a2515-91d2-4452-b49b-5e8040e6b0f4"
            },
            "type": {
                "name": "User_LoggedIn",
                "value": "1000"
            }
        },
        "object": "event"
    },
    "data_stream": {
        "dataset": "bitwarden.event",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "ff2a1bfe-20b0-4bab-ad84-8609f33b69f8",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam",
            "authentication"
        ],
        "created": "2023-04-18T11:45:04.623Z",
        "dataset": "bitwarden.event",
        "ingested": "2023-04-18T11:45:08Z",
        "kind": "event",
        "original": "{\"actingUserId\":\"a2549f79-a71f-4eb9-9234-eb7247333f94\",\"collectionId\":\"bce212a4-25f3-4888-8a0a-4c5736d851e0\",\"date\":\"2023-02-22T09:00:21.728Z\",\"device\":0,\"groupId\":\"f29a2515-91d2-4452-b49b-5e8040e6b0f4\",\"ipAddress\":\"172.16.254.1\",\"itemId\":\"3767a302-8208-4dc6-b842-030428a1cfad\",\"memberId\":\"e68b8629-85eb-4929-92c0-b84464976ba4\",\"object\":\"event\",\"policyId\":\"f29a2515-91d2-4452-b49b-5e8040e6b0f4\",\"type\":1000}",
        "outcome": "success",
        "type": [
            "user",
            "start"
        ]
    },
    "group": {
        "id": "f29a2515-91d2-4452-b49b-5e8040e6b0f4"
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "172.16.254.1"
        ],
        "user": [
            "e68b8629-85eb-4929-92c0-b84464976ba4",
            "a2549f79-a71f-4eb9-9234-eb7247333f94"
        ]
    },
    "source": {
        "ip": "172.16.254.1",
        "user": {
            "id": "a2549f79-a71f-4eb9-9234-eb7247333f94"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "bitwarden-event"
    ],
    "user": {
        "id": "e68b8629-85eb-4929-92c0-b84464976ba4"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bitwarden.event.acting_user.id | The unique identifier of the user that performed the event. | keyword |
| bitwarden.event.collection.id | The unique identifier of the related collection that the event describes. | keyword |
| bitwarden.event.date | The date/timestamp when the event occurred. | date |
| bitwarden.event.device.name | Device type name. | keyword |
| bitwarden.event.device.value | Device type value. | keyword |
| bitwarden.event.group.id | The unique identifier of the related group that the event describes. | keyword |
| bitwarden.event.installation.id | The unique identifier of the Installation that performed the event. | keyword |
| bitwarden.event.ip_address | The IP address of the acting user. | ip |
| bitwarden.event.item.id | The unique identifier of the related item that the event describes. | keyword |
| bitwarden.event.member.id | The unique identifier of the related member that the event describes. | keyword |
| bitwarden.event.policy.id | The unique identifier of the related policy that the event describes. | keyword |
| bitwarden.event.type.name | Event type name. | keyword |
| bitwarden.event.type.value | Event type value. | keyword |
| bitwarden.object | String representing the object's type. Objects of the same type share the same properties. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |


### Group

This is the `Group` dataset.

#### Example

An example event for `group` looks as following:

```json
{
    "@timestamp": "2023-04-18T11:46:13.418Z",
    "agent": {
        "ephemeral_id": "88e47b12-e16a-4b3e-8170-e610d78e0566",
        "id": "ff2a1bfe-20b0-4bab-ad84-8609f33b69f8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "bitwarden": {
        "group": {
            "access_all": true,
            "collection": [
                {
                    "id": "bfbc8338-e329-4dc0-b0c9-317c2ebf1a09",
                    "read_only": true
                }
            ],
            "external": {
                "id": "external_id_123456"
            },
            "id": "539a36c5-e0d2-4cf9-979e-51ecf5cf6593",
            "name": "Development Team"
        },
        "object": "group"
    },
    "data_stream": {
        "dataset": "bitwarden.group",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "ff2a1bfe-20b0-4bab-ad84-8609f33b69f8",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2023-04-18T11:46:13.418Z",
        "dataset": "bitwarden.group",
        "ingested": "2023-04-18T11:46:16Z",
        "kind": "event",
        "original": "{\"accessAll\":true,\"collections\":[{\"id\":\"bfbc8338-e329-4dc0-b0c9-317c2ebf1a09\",\"readOnly\":true}],\"externalId\":\"external_id_123456\",\"id\":\"539a36c5-e0d2-4cf9-979e-51ecf5cf6593\",\"name\":\"Development Team\",\"object\":\"group\"}",
        "type": [
            "group"
        ]
    },
    "group": {
        "id": "539a36c5-e0d2-4cf9-979e-51ecf5cf6593",
        "name": "Development Team"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "bitwarden-group"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bitwarden.group.access_all | Determines if this group can access all collections within the organization, or only the associated collections. If set to \{true\}, this option overrides any collection assignments. | boolean |
| bitwarden.group.collection.id | The associated object's unique identifier. | keyword |
| bitwarden.group.collection.read_only | When true, the read only permission will not allow the user or group to make changes to items. | boolean |
| bitwarden.group.external.id | External identifier for reference or linking this group to another system, such as a user directory. | keyword |
| bitwarden.group.id | The group's unique identifier. | keyword |
| bitwarden.group.name | The name of the group. | keyword |
| bitwarden.object | String representing the object's type. Objects of the same type share the same properties. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |


### Policy

This is the `Policy` dataset.

#### Example

An example event for `policy` looks as following:

```json
{
    "@timestamp": "2023-04-18T11:47:30.746Z",
    "agent": {
        "ephemeral_id": "a91254b2-feca-467c-969c-f0d919205f96",
        "id": "ff2a1bfe-20b0-4bab-ad84-8609f33b69f8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "bitwarden": {
        "object": "policy",
        "policy": {
            "data": {
                "capitalize": "true",
                "default_type": "password",
                "include_number": "true",
                "min": {
                    "length": "5",
                    "number_words": "3",
                    "numbers": "1",
                    "special": "1"
                },
                "use": {
                    "lower": "true",
                    "numbers": "true",
                    "special": "true",
                    "upper": "true"
                }
            },
            "enabled": true,
            "id": "539a36c5-e0d2-4cf9-979e-51ecf5cf6593",
            "type": {
                "name": "TwoFactorAuthentication",
                "value": "0"
            }
        }
    },
    "data_stream": {
        "dataset": "bitwarden.policy",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "ff2a1bfe-20b0-4bab-ad84-8609f33b69f8",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-04-18T11:47:30.746Z",
        "dataset": "bitwarden.policy",
        "ingested": "2023-04-18T11:47:34Z",
        "kind": "event",
        "original": "{\"data\":{\"capitalize\":true,\"defaultType\":\"password\",\"includeNumber\":true,\"minLength\":5,\"minNumberWords\":3,\"minNumbers\":1,\"minSpecial\":1,\"useLower\":true,\"useNumbers\":true,\"useSpecial\":true,\"useUpper\":true},\"enabled\":true,\"id\":\"539a36c5-e0d2-4cf9-979e-51ecf5cf6593\",\"object\":\"policy\",\"type\":0}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "bitwarden-policy"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bitwarden.object | String representing the object's type. Objects of the same type share the same properties. | keyword |
| bitwarden.policy.data.auto_enroll_enabled |  | keyword |
| bitwarden.policy.data.capitalize |  | keyword |
| bitwarden.policy.data.default_type |  | keyword |
| bitwarden.policy.data.disable_hide_email |  | keyword |
| bitwarden.policy.data.include_number |  | keyword |
| bitwarden.policy.data.min.complexity |  | keyword |
| bitwarden.policy.data.min.length |  | keyword |
| bitwarden.policy.data.min.number_words |  | keyword |
| bitwarden.policy.data.min.numbers |  | keyword |
| bitwarden.policy.data.min.special |  | keyword |
| bitwarden.policy.data.minutes |  | keyword |
| bitwarden.policy.data.require.lower |  | keyword |
| bitwarden.policy.data.require.numbers |  | keyword |
| bitwarden.policy.data.require.special |  | keyword |
| bitwarden.policy.data.require.upper |  | keyword |
| bitwarden.policy.data.use.lower |  | keyword |
| bitwarden.policy.data.use.numbers |  | keyword |
| bitwarden.policy.data.use.special |  | keyword |
| bitwarden.policy.data.use.upper |  | keyword |
| bitwarden.policy.enabled | Determines if this policy is enabled and enforced. | boolean |
| bitwarden.policy.id | The policy's unique identifier. | keyword |
| bitwarden.policy.type.name | Policy type name. | keyword |
| bitwarden.policy.type.value | Policy type value. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |
