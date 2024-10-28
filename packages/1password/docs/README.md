# 1Password Events Reporting

With [1Password Business](https://support.1password.com/explore/business/), you can send your account activity to your security information and event management (SIEM) system, using the 1Password Events API. 

Get reports about 1Password activity, such as sign-in attempts and item usage, while you manage all your company’s applications and services from a central location.

With 1Password Events Reporting and Elastic SIEM, you can:

-	Control your 1Password data retention
-	Build custom graphs and dashboards
-	Set up custom alerts that trigger specific actions
-	Cross-reference 1Password events with the data from other services

You can set up Events Reporting if you’re an owner or administrator.  
Ready to get started? [Learn how to set up the Elastic Events Reporting integration](https://support.1password.com/events-reporting).

Events
------

### Sign-in Attempts

Use the 1Password Events API to retrieve information about sign-in attempts. Events include the name and IP address of the user who attempted to sign in to the account, when the attempt was made, and – for failed attempts – the cause of the failure.

*Exported fields*

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type | keyword |
| onepassword.client.app_name | The name of the 1Password app that attempted to sign in to the account | keyword |
| onepassword.client.app_version | The version number of the 1Password app | keyword |
| onepassword.client.platform_name | The name of the platform running the 1Password app | keyword |
| onepassword.client.platform_version | The version of the browser or computer where the 1Password app is installed, or the CPU of the machine where the 1Password command-line tool is installed | keyword |
| onepassword.country | The country code of the event. Uses the ISO 3166 standard | keyword |
| onepassword.details.value |  | keyword |
| onepassword.session_uuid | The UUID of the session that created the event | keyword |
| onepassword.type | Details about the sign-in attempt | keyword |
| onepassword.uuid | The UUID of the event | keyword |


An example event for `signin_attempts` looks as following:

```json
{
    "@timestamp": "2021-08-11T14:28:03.000Z",
    "agent": {
        "ephemeral_id": "53b71bee-2cfb-44b2-91e8-56858cf7948a",
        "id": "830aad64-eb94-4e27-830a-be5a339967b4",
        "name": "elastic-agent-21199",
        "type": "filebeat",
        "version": "8.15.2"
    },
    "data_stream": {
        "dataset": "1password.signin_attempts",
        "namespace": "71969",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "830aad64-eb94-4e27-830a-be5a339967b4",
        "snapshot": false,
        "version": "8.15.2"
    },
    "event": {
        "action": "success",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2024-10-23T03:10:13.522Z",
        "dataset": "1password.signin_attempts",
        "ingested": "2024-10-23T03:10:16Z",
        "kind": "event",
        "original": "{\"category\":\"success\",\"client\":{\"app_name\":\"1Password Browser Extension\",\"app_version\":\"1109\",\"ip_address\":\"1.1.1.1\",\"os_name\":\"Android\",\"os_version\":\"10\",\"platform_name\":\"Chrome\",\"platform_version\":\"93.0.4577.62\"},\"country\":\"AR\",\"details\":null,\"session_uuid\":\"UED4KFZ5BH37IQWTJ7LG4VPWK7\",\"target_user\":{\"email\":\"email@1password.com\",\"name\":\"Name\",\"uuid\":\"OJQGU46KAPROEJLCK674RHSAY5\"},\"timestamp\":\"2021-08-11T14:28:03Z\",\"type\":\"credentials_ok\",\"uuid\":\"HGIF4OEWXDTVWKEQDIWTKV26HU\"}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "host": {
        "os": {
            "name": "Android",
            "version": "10"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "onepassword": {
        "client": {
            "app_name": "1Password Browser Extension",
            "app_version": "1109",
            "platform_name": "Chrome",
            "platform_version": "93.0.4577.62"
        },
        "country": "AR",
        "session_uuid": "UED4KFZ5BH37IQWTJ7LG4VPWK7",
        "type": "credentials_ok",
        "uuid": "HGIF4OEWXDTVWKEQDIWTKV26HU"
    },
    "related": {
        "ip": [
            "1.1.1.1"
        ],
        "user": [
            "OJQGU46KAPROEJLCK674RHSAY5",
            "email@1password.com",
            "Name"
        ]
    },
    "source": {
        "ip": "1.1.1.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "1password-signin_attempts"
    ],
    "user": {
        "email": "email@1password.com",
        "full_name": "Name",
        "id": "OJQGU46KAPROEJLCK674RHSAY5"
    }
}
```

### Item Usages

This uses the 1Password Events API to retrieve information about items in shared vaults that have been modified, accessed, or used. Events include the name and IP address of the user who accessed the item, when it was accessed, and the vault where the item is stored.

*Exported fields*

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type | keyword |
| onepassword.client.app_name | The name of the 1Password app the item was accessed from | keyword |
| onepassword.client.app_version | The version number of the 1Password app | keyword |
| onepassword.client.platform_name | The name of the platform the item was accessed from | keyword |
| onepassword.client.platform_version | The version of the browser or computer where the 1Password app is installed, or the CPU of the machine where the 1Password command-line tool is installed | keyword |
| onepassword.item_uuid | The UUID of the item that was accessed | keyword |
| onepassword.used_version | The version of the item that was accessed | integer |
| onepassword.uuid | The UUID of the event | keyword |
| onepassword.vault_uuid | The UUID of the vault the item is in | keyword |


An example event for `item_usages` looks as following:

```json
{
    "@timestamp": "2021-08-30T18:57:42.484Z",
    "agent": {
        "ephemeral_id": "a0a48829-3614-4525-8def-4814cdab271d",
        "id": "c987e484-ccdb-465d-aec3-6b7d68b73337",
        "name": "elastic-agent-80484",
        "type": "filebeat",
        "version": "8.15.2"
    },
    "data_stream": {
        "dataset": "1password.item_usages",
        "namespace": "61510",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c987e484-ccdb-465d-aec3-6b7d68b73337",
        "snapshot": false,
        "version": "8.15.2"
    },
    "event": {
        "action": "reveal",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "created": "2024-10-23T03:07:44.001Z",
        "dataset": "1password.item_usages",
        "ingested": "2024-10-23T03:07:47Z",
        "kind": "event",
        "original": "{\"action\":\"reveal\",\"client\":{\"app_name\":\"1Password Browser Extension\",\"app_version\":\"1109\",\"ip_address\":\"1.1.1.1\",\"os_name\":\"Android\",\"os_version\":\"10\",\"platform_name\":\"Chrome\",\"platform_version\":\"93.0.4577.62\"},\"item_uuid\":\"bvwmmwxisuca7wbehrbyqhag54\",\"location\":{\"city\":\"Toronto\",\"country\":\"Canada\",\"latitude\":43.64,\"longitude\":-79.433,\"region\":\"Ontario\"},\"timestamp\":\"2021-08-30T18:57:42.484Z\",\"used_version\":1,\"user\":{\"email\":\"email@1password.com\",\"name\":\"Name\",\"uuid\":\"OJQGU46KAPROEJLCK674RHSAY5\"},\"uuid\":\"MCQODBBWJD5HISKYNP3HJPV2DV\",\"vault_uuid\":\"jaqxqf5qylslqiitnduawrndc5\"}",
        "type": [
            "access"
        ]
    },
    "host": {
        "os": {
            "name": "Android",
            "version": "10"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "onepassword": {
        "client": {
            "app_name": "1Password Browser Extension",
            "app_version": "1109",
            "platform_name": "Chrome",
            "platform_version": "93.0.4577.62"
        },
        "item_uuid": "bvwmmwxisuca7wbehrbyqhag54",
        "used_version": 1,
        "uuid": "MCQODBBWJD5HISKYNP3HJPV2DV",
        "vault_uuid": "jaqxqf5qylslqiitnduawrndc5"
    },
    "related": {
        "ip": [
            "1.1.1.1"
        ],
        "user": [
            "OJQGU46KAPROEJLCK674RHSAY5",
            "email@1password.com",
            "Name"
        ]
    },
    "source": {
        "ip": "1.1.1.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "1password-item_usages"
    ],
    "user": {
        "email": "email@1password.com",
        "full_name": "Name",
        "id": "OJQGU46KAPROEJLCK674RHSAY5"
    }
}
```


### Audit Events

This uses the 1Password Events API to retrieve information about audit events. Events includes information about actions performed by team members such as account updates, access and invitations, device authorization, changes to vault permissions, and more. 

*Exported fields*

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type | keyword |
| onepassword.actor_details.email | The email of the actor. | keyword |
| onepassword.actor_details.name | The name of the actor. | keyword |
| onepassword.actor_details.uuid | The UUID of the actor. | keyword |
| onepassword.actor_uuid | The UUID of the actor. | keyword |
| onepassword.aux_details.email | The email of the aux resource. | keyword |
| onepassword.aux_details.name | The name of the aux resource. | keyword |
| onepassword.aux_details.uuid | The UUID of the aux resource. | keyword |
| onepassword.aux_id | Any auxilary id related to the event. | long |
| onepassword.aux_info | Any auxilary info related to the event. | text |
| onepassword.aux_uuid | Any auxilary uuid related to the event. | keyword |
| onepassword.object_details.email | The email of the object. | keyword |
| onepassword.object_details.name | The name of the object. | keyword |
| onepassword.object_details.uuid | The UUID of the object. | keyword |
| onepassword.object_type | The type of object changed by the event. | keyword |
| onepassword.object_uuid | The UUID of the object changed by the event. | keyword |
| onepassword.session.device_uuid | The device uuid of the session used to create the event. | keyword |
| onepassword.session.login_time | The login time of the session used to create the event. | date |
| onepassword.session.uuid | The session uuid of the session used to create the event. | keyword |
| onepassword.uuid | The UUID of the event. | keyword |


An example event for `audit_events` looks as following:

```json
{
    "@timestamp": "2022-10-24T21:16:52.827Z",
    "agent": {
        "ephemeral_id": "707e9afa-28e0-4f96-a888-3e83853dba31",
        "id": "1befb18f-d4ea-4c2c-95f5-308d7df0439e",
        "name": "elastic-agent-11710",
        "type": "filebeat",
        "version": "8.15.2"
    },
    "data_stream": {
        "dataset": "1password.audit_events",
        "namespace": "30141",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "1befb18f-d4ea-4c2c-95f5-308d7df0439e",
        "snapshot": false,
        "version": "8.15.2"
    },
    "event": {
        "action": "suspend",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "created": "2024-10-23T03:06:30.812Z",
        "dataset": "1password.audit_events",
        "ingested": "2024-10-23T03:06:33Z",
        "kind": "event",
        "original": "{\"action\":\"suspend\",\"actor_uuid\":\"GLF6WUEKS5CSNDJ2OG6TCZD3M4\",\"location\":{\"city\":\"Toronto\",\"country\":\"Canada\",\"latitude\":43.64,\"longitude\":-79.433,\"region\":\"Ontario\"},\"object_type\":\"user\",\"object_uuid\":\"ZRQCUD6A65AKHFETOUFO7NL4OM\",\"session\":{\"device_uuid\":\"rqtd557fn2husnstp5nc66w2xa\",\"ip\":\"89.160.20.156\",\"login_time\":\"2022-10-24T21:07:34.703106271Z\",\"uuid\":\"ODOHXUYQCJBUJKRGZNNPBJURPE\"},\"timestamp\":\"2022-10-24T21:16:52.827288935Z\",\"uuid\":\"3UQOGUC7DVOCN4OZP2MDKHFLSG\"}",
        "type": [
            "access"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "onepassword": {
        "object_type": "user",
        "object_uuid": "ZRQCUD6A65AKHFETOUFO7NL4OM",
        "session": {
            "device_uuid": "rqtd557fn2husnstp5nc66w2xa",
            "login_time": "2022-10-24T21:07:34.703106271Z",
            "uuid": "ODOHXUYQCJBUJKRGZNNPBJURPE"
        },
        "uuid": "3UQOGUC7DVOCN4OZP2MDKHFLSG"
    },
    "related": {
        "ip": [
            "89.160.20.156"
        ],
        "user": [
            "GLF6WUEKS5CSNDJ2OG6TCZD3M4",
            "ZRQCUD6A65AKHFETOUFO7NL4OM"
        ]
    },
    "source": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "1password-audit_events"
    ],
    "user": {
        "id": "GLF6WUEKS5CSNDJ2OG6TCZD3M4"
    }
}
```