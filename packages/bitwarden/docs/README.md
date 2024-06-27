# Bitwarden

## Overview

The [Bitwarden](https://bitwarden.com) integration allows users to monitor collections, events, groups, members and policies. Bitwarden is a free and open-source password management service that stores sensitive information such as website credentials in an encrypted vault. The Bitwarden platform offers a variety of client applications including a web interface, desktop applications, browser extensions, mobile apps and a command-line interface. Bitwarden offers a cloud-hosted service as well as the ability to deploy the solution on-premises.

Use the Bitwarden integration to collect and parse data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Bitwarden integration collects five types of data: Collections, Events, Groups, Members and Policies.

**Collections** returns a list of an organization's collections.

**Events** returns a list of an organization's event logs.

**Groups** returns a list of an organization's groups.

**Members** returns the details of an organization's members.

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
    "@timestamp": "2023-10-31T07:31:24.050Z",
    "agent": {
        "ephemeral_id": "bf237146-2d4b-427b-b731-6dadb1dfdd90",
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
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
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-10-31T07:31:24.050Z",
        "dataset": "bitwarden.collection",
        "ingested": "2023-10-31T07:31:27Z",
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


### Event

This is the `Event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2023-02-22T09:00:21.728Z",
    "agent": {
        "ephemeral_id": "23334f92-55ed-4a8f-b7c3-9e36ff9d73a2",
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
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
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam",
            "authentication"
        ],
        "created": "2023-10-31T07:32:17.783Z",
        "dataset": "bitwarden.event",
        "ingested": "2023-10-31T07:32:21Z",
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


### Group

This is the `Group` dataset.

#### Example

An example event for `group` looks as following:

```json
{
    "@timestamp": "2023-10-31T07:33:12.430Z",
    "agent": {
        "ephemeral_id": "2531708a-f7fa-48b6-913e-7d5d7d08b29b",
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
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
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2023-10-31T07:33:12.430Z",
        "dataset": "bitwarden.group",
        "ingested": "2023-10-31T07:33:15Z",
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
| bitwarden.group.access_all | Determines if this group can access all collections within the organization, or only the associated collections. If set to true, this option overrides any collection assignments. | boolean |
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


### Member

This is the `Member` dataset.

#### Example

An example event for `member` looks as following:

```json
{
    "@timestamp": "2023-10-31T07:34:06.988Z",
    "agent": {
        "ephemeral_id": "ecbc5fc6-80f7-4b74-a759-47e029f39507",
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.1"
    },
    "bitwarden": {
        "member": {
            "access_all": true,
            "email": "jsmith@example.com",
            "external": {
                "id": "external_id_123456"
            },
            "id": "1234",
            "name": "John Smith",
            "reset_password_enrolled": true,
            "status": {
                "name": "Invited",
                "value": "0"
            },
            "two_factor_enabled": true,
            "type": {
                "name": "Owner",
                "value": "0"
            },
            "user": {
                "id": "48b47ee1-493e-4c67-aef7-014996c40eca"
            }
        },
        "object": "member"
    },
    "data_stream": {
        "dataset": "bitwarden.member",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2023-10-31T07:34:06.988Z",
        "dataset": "bitwarden.member",
        "ingested": "2023-10-31T07:34:10Z",
        "kind": "event",
        "original": "{\"accessAll\":true,\"collections\":null,\"email\":\"jsmith@example.com\",\"externalId\":\"external_id_123456\",\"id\":\"1234\",\"name\":\"John Smith\",\"object\":\"member\",\"resetPasswordEnrolled\":true,\"status\":0,\"twoFactorEnabled\":true,\"type\":0,\"userId\":\"48b47ee1-493e-4c67-aef7-014996c40eca\"}",
        "type": [
            "user"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "user": [
            "1234",
            "48b47ee1-493e-4c67-aef7-014996c40eca",
            "John Smith",
            "jsmith@example.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "bitwarden-member"
    ],
    "user": {
        "email": "jsmith@example.com",
        "id": "1234",
        "name": "John Smith"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bitwarden.member.access_all | Determines if this member can access all collections within the organization, or only the associated collections. If set to true, this option overrides any collection assignments. | boolean |
| bitwarden.member.collection.id | The associated object's unique identifier. | keyword |
| bitwarden.member.collection.read_only | When true, the read only permission will not allow the user or group to make changes to items. | boolean |
| bitwarden.member.email | The member's email address. | keyword |
| bitwarden.member.external.id | External identifier for reference or linking this member to another system, such as a user directory. | keyword |
| bitwarden.member.id | The member's unique identifier within the organization. | keyword |
| bitwarden.member.name | The member's name, set from their user account profile. | keyword |
| bitwarden.member.reset_password_enrolled | Returns true if the member has enrolled in Password Reset assistance within the organization. | boolean |
| bitwarden.member.status.name | Organization user status type name. | keyword |
| bitwarden.member.status.value | Organization user status type value. | keyword |
| bitwarden.member.two_factor_enabled | Returns true if the member has a two-step login method enabled on their user account. | boolean |
| bitwarden.member.type.name | Organization user type name. | keyword |
| bitwarden.member.type.value | Organization user type value. | keyword |
| bitwarden.member.user.id | The member's unique identifier across Bitwarden. | keyword |
| bitwarden.object | String representing the object's type. Objects of the same type share the same properties. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Policy

This is the `Policy` dataset.

#### Example

An example event for `policy` looks as following:

```json
{
    "@timestamp": "2023-10-31T07:35:03.192Z",
    "agent": {
        "ephemeral_id": "eedf4c11-ed1e-4b64-b210-2c8120abdbbf",
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
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
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fa60f5ca-bf95-4706-9195-907dd5f9b537",
        "snapshot": false,
        "version": "8.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-10-31T07:35:03.192Z",
        "dataset": "bitwarden.policy",
        "ingested": "2023-10-31T07:35:06Z",
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
