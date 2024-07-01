# Cisco Duo

The Cisco Duo integration collects and parses data from the [Cisco Duo Admin APIs](https://duo.com/docs/adminapi).

## Compatibility

This module has been tested against Cisco Duo `Core Authentication Service: D224.13` and `Admin Panel: D224.18`

## Requirements

In order to ingest data from the Cisco Duo Admin API you must:
- Have a the Cisco Duo administrator account with **Owner** role [Sign up](https://signup.duo.com/)
- Sign in to [Duo Admin Panel](https://admin.duosecurity.com/)
- Go through following tabs **Application > Protect an Application > Admin API > Protect**
- Now you will find your **Hostname**, **Integration key** and **Secret key** which will be required while configuring the integration package.
- For this integration you will require **Grant read information** and **Grant read log** permissions.
- Make sure you have whitelisted your IP Address.

## Note

While setting up the interval take care of following.
- `Interval has to be greater than 1m.`
- `Larger values of interval might cause delay in data ingestion.`

## Logs

### Administrator

This is the `admin` dataset.

An example event for `admin` looks as following:

```json
{
    "@timestamp": "2021-07-20T11:41:31.000Z",
    "agent": {
        "ephemeral_id": "2785cbfe-5f49-4cf2-b1c4-7dbc52b0f1fa",
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
    },
    "cisco_duo": {
        "admin": {
            "action": "activation_begin",
            "user": {
                "name": "narroway"
            }
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.admin",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "action": "activation_begin",
        "agent_id_status": "verified",
        "created": "2023-05-10T14:54:46.085Z",
        "dataset": "cisco_duo.admin",
        "ingested": "2023-05-10T14:54:47Z",
        "kind": "event",
        "original": "{\"action\":\"activation_begin\",\"description\":\"Starting activation process\",\"isotimestamp\":\"2021-07-20T11: 41: 31+00: 00\",\"object\":null,\"timestamp\":1626781291,\"username\":\"narroway\"}",
        "outcome": "success",
        "reason": "Starting activation process"
    },
    "input": {
        "type": "httpjson"
    },
    "message": "Starting activation process",
    "related": {
        "user": [
            "narroway"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-admin"
    ],
    "user": {
        "name": "narroway"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.admin.action | The type of change that was performed | keyword |
| cisco_duo.admin.action_performed_on | The object that was acted on. | keyword |
| cisco_duo.admin.errors | The set of error reported for the event. | keyword |
| cisco_duo.admin.flattened | ES flattened datatype for objects where the subfields aren't known in advance. | flattened |
| cisco_duo.admin.status | The status of the event. | keyword |
| cisco_duo.admin.user.name | The full name of the administrator who performed the action in the Duo Admin Panel. | keyword |
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


### Authentication

This is the `auth` dataset.

An example event for `auth` looks as following:

```json
{
    "@timestamp": "2020-02-13T18:56:20.000Z",
    "agent": {
        "ephemeral_id": "d12366d8-e76c-4b7a-a521-cf8f709b7fd3",
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
    },
    "cisco_duo": {
        "auth": {
            "access_device": {
                "flash_version": "uninstalled",
                "ip": "89.160.20.156",
                "is_encryption_enabled": "true",
                "is_firewall_enabled": "true",
                "is_password_set": "true",
                "java_version": "uninstalled",
                "location": {
                    "city": "Ann Arbor",
                    "country": "United States",
                    "state": "Michigan"
                }
            },
            "application": {
                "key": "DIY231J8BR23QK4UKBY8",
                "name": "Microsoft Azure Active Directory"
            },
            "auth_device": {
                "ip": "192.168.225.254",
                "location": {
                    "city": "Ann Arbor",
                    "country": "United States",
                    "state": "Michigan"
                },
                "name": "My iPhone X (734-555-2342)"
            },
            "email": "narroway@example.com",
            "event_type": "authentication",
            "factor": "duo_push",
            "reason": "user_approved",
            "result": "success",
            "trusted_endpoint_status": "not trusted",
            "txid": "340a23e3-23f3-23c1-87dc-1491a23dfdbb"
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.auth",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "created": "2023-05-10T14:55:22.717Z",
        "dataset": "cisco_duo.auth",
        "ingested": "2023-05-10T14:55:23Z",
        "kind": "event",
        "original": "{\"access_device\":{\"browser\":\"Chrome\",\"browser_version\":\"67.0.3396.99\",\"flash_version\":\"uninstalled\",\"hostname\":null,\"ip\":\"89.160.20.156\",\"is_encryption_enabled\":true,\"is_firewall_enabled\":true,\"is_password_set\":true,\"java_version\":\"uninstalled\",\"location\":{\"city\":\"Ann Arbor\",\"country\":\"United States\",\"state\":\"Michigan\"},\"os\":\"Mac OS X\",\"os_version\":\"10.14.1\",\"security_agents\":null},\"alias\":\"\",\"application\":{\"key\":\"DIY231J8BR23QK4UKBY8\",\"name\":\"Microsoft Azure Active Directory\"},\"auth_device\":{\"ip\":\"192.168.225.254\",\"location\":{\"city\":\"Ann Arbor\",\"country\":\"United States\",\"state\":\"Michigan\"},\"name\":\"My iPhone X (734-555-2342)\"},\"email\":\"narroway@example.com\",\"event_type\":\"authentication\",\"factor\":\"duo_push\",\"isotimestamp\":\"2020-02-13T18:56:20.351346+00:00\",\"ood_software\":null,\"reason\":\"user_approved\",\"result\":\"success\",\"timestamp\":1581620180,\"trusted_endpoint_status\":\"not trusted\",\"txid\":\"340a23e3-23f3-23c1-87dc-1491a23dfdbb\",\"user\":{\"groups\":[\"Duo Users\",\"CorpHQ Users\"],\"key\":\"DU3KC77WJ06Y5HIV7XKQ\",\"name\":\"narroway@example.com\"}}",
        "outcome": "success",
        "reason": "user_approved",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "hosts": [
            "89.160.20.156"
        ],
        "ip": [
            "89.160.20.156",
            "192.168.225.254"
        ],
        "user": [
            "narroway@example.com"
        ]
    },
    "source": {
        "address": "89.160.20.156",
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
        "ip": "89.160.20.156",
        "user": {
            "email": "narroway@example.com",
            "group": {
                "name": [
                    "Duo Users",
                    "CorpHQ Users"
                ]
            },
            "id": "DU3KC77WJ06Y5HIV7XKQ",
            "name": "narroway@example.com"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-auth"
    ],
    "user": {
        "email": "narroway@example.com",
        "id": "DU3KC77WJ06Y5HIV7XKQ",
        "name": "narroway@example.com"
    },
    "user_agent": {
        "name": "Chrome",
        "os": {
            "name": "Mac OS X",
            "version": "10.14.1"
        },
        "version": "67.0.3396.99"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.auth.access_device.flash_version | The Flash plugin version used, if present. | keyword |
| cisco_duo.auth.access_device.hostname | The hostname, if present. | keyword |
| cisco_duo.auth.access_device.ip | The access device's IP address. | ip |
| cisco_duo.auth.access_device.is_encryption_enabled | Reports the disk encryption state as detected by the Duo Device Health app. | keyword |
| cisco_duo.auth.access_device.is_firewall_enabled | Reports the firewall state as detected by the Duo Device Health app. | keyword |
| cisco_duo.auth.access_device.is_password_set | Reports the system password state as detected by the Duo Device Health app | keyword |
| cisco_duo.auth.access_device.java_version | The Java plugin version used. | keyword |
| cisco_duo.auth.access_device.location.city | The city name of the access device using geoip location. | keyword |
| cisco_duo.auth.access_device.location.country | The country of the access device using geoip location. | keyword |
| cisco_duo.auth.access_device.location.state | The state name of the access device using geoip location. | keyword |
| cisco_duo.auth.access_device.port | The access device's port number. | long |
| cisco_duo.auth.access_device.security_agents | Reports the security agents present on the endpoint as detected by the Duo Device Health app. | flattened |
| cisco_duo.auth.alias | The username alias used to log in. | keyword |
| cisco_duo.auth.application.key | The application's integration_key. | keyword |
| cisco_duo.auth.application.name | The application's name. | keyword |
| cisco_duo.auth.auth_device.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| cisco_duo.auth.auth_device.as.organization.name | Organization name. | keyword |
| cisco_duo.auth.auth_device.geo.city_name | City name. | keyword |
| cisco_duo.auth.auth_device.geo.continent_name | Name of the continent. | keyword |
| cisco_duo.auth.auth_device.geo.country_iso_code | Country ISO code. | keyword |
| cisco_duo.auth.auth_device.geo.country_name | Country name. | keyword |
| cisco_duo.auth.auth_device.geo.location | Longitude and latitude. | geo_point |
| cisco_duo.auth.auth_device.geo.region_iso_code | Region ISO code. | keyword |
| cisco_duo.auth.auth_device.geo.region_name | Region name. | keyword |
| cisco_duo.auth.auth_device.ip | The IP address of the authentication device. | ip |
| cisco_duo.auth.auth_device.location.city | The city name of the authentication device using geoip location. | keyword |
| cisco_duo.auth.auth_device.location.country | The country of the authentication device using geoip location. | keyword |
| cisco_duo.auth.auth_device.location.state | The state name of the authentication device using geoip location. | keyword |
| cisco_duo.auth.auth_device.name | The name of the authentication device. | keyword |
| cisco_duo.auth.auth_device.port | The network port of the authentication device. | long |
| cisco_duo.auth.email | The email address of the user, if known to Duo, otherwise none. | keyword |
| cisco_duo.auth.event_type | The type of activity logged. | keyword |
| cisco_duo.auth.factor | The authentication factor. | keyword |
| cisco_duo.auth.ood_software | If authentication was denied due to out-of-date software, shows the name of the software. | keyword |
| cisco_duo.auth.reason | Provide the reason for the authentication attempt result. | keyword |
| cisco_duo.auth.result | The result of the authentication attempt. | keyword |
| cisco_duo.auth.trusted_endpoint_status | Status of Trusted Endpoint. | keyword |
| cisco_duo.auth.txid | The transaction ID of the event. | keyword |
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


### Offline Enrollment

This is the `offline_enrollment` dataset.

An example event for `offline_enrollment` looks as following:

```json
{
    "@timestamp": "2019-08-30T16:10:05.000Z",
    "agent": {
        "ephemeral_id": "24599b3c-1dd1-45c6-802a-ec30f6e720cc",
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
    },
    "cisco_duo": {
        "offline_enrollment": {
            "action": "o2fa_user_provisioned",
            "description": {
                "factor": "duo_otp",
                "hostname": "WKSW10x64",
                "user_agent": "DuoCredProv/4.0.6.413 (Windows NT 6.3.9600; x64; Server)"
            },
            "object": "Acme Laptop Windows Logon",
            "user": {
                "name": "narroway"
            }
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.offline_enrollment",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-05-10T14:56:00.686Z",
        "dataset": "cisco_duo.offline_enrollment",
        "ingested": "2023-05-10T14:56:04Z",
        "original": "{\"action\":\"o2fa_user_provisioned\",\"description\":\"{\\\"user_agent\\\": \\\"DuoCredProv/4.0.6.413 (Windows NT 6.3.9600; x64; Server)\\\", \\\"hostname\\\": \\\"WKSW10x64\\\", \\\"factor\\\": \\\"duo_otp\\\"}\",\"isotimestamp\":\"2019-08-30T16:10:05+00:00\",\"object\":\"Acme Laptop Windows Logon\",\"timestamp\":1567181405,\"username\":\"narroway\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "hosts": [
            "WKSW10x64"
        ],
        "user": [
            "narroway"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-offline_enrollment"
    ],
    "user": {
        "name": "narroway"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.offline_enrollment.action | The offline enrollment operation | keyword |
| cisco_duo.offline_enrollment.description.factor | The type of authenticator used for offline access. | keyword |
| cisco_duo.offline_enrollment.description.hostname | The host name of the system where Duo Windows Logon is installed. | keyword |
| cisco_duo.offline_enrollment.description.user_agent | The Duo Windows Logon application version information and the Windows OS version and platform information. | keyword |
| cisco_duo.offline_enrollment.object | The Duo Windows Logon integration's name. | keyword |
| cisco_duo.offline_enrollment.user.name | The Duo username | keyword |
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


### Summary

This is the `summary` dataset.

An example event for `summary` looks as following:

```json
{
    "@timestamp": "2023-05-10T14:56:41.873942700Z",
    "agent": {
        "ephemeral_id": "e03bb3c3-0d99-45e9-bd9d-a30e435ed069",
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
    },
    "cisco_duo": {
        "summary": {
            "admin_count": 3,
            "integration_count": 9,
            "telephony_credits_remaining": 960,
            "user_count": 8
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.summary",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-05-10T14:56:40.862Z",
        "dataset": "cisco_duo.summary",
        "ingested": "2023-05-10T14:56:41Z",
        "original": "{\"response\":{\"admin_count\":3,\"integration_count\":9,\"telephony_credits_remaining\":960,\"user_count\":8},\"stat\":\"OK\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-summary"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.summary.admin_count | Current number of admins in the account. | integer |
| cisco_duo.summary.integration_count | Current number of integrations in the account. | integer |
| cisco_duo.summary.telephony_credits_remaining | Current total number of telephony credits available in the account. This is the sum of all types of telephony credits. | integer |
| cisco_duo.summary.user_count | Current number of users in the account. | integer |
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


### Telephony

This is the `telephony` dataset.

An example event for `telephony` looks as following:

```json
{
    "@timestamp": "2020-03-20T15:38:12.000Z",
    "agent": {
        "ephemeral_id": "fc6cd027-e67d-45f2-81f3-547c668998c6",
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.0"
    },
    "cisco_duo": {
        "telephony": {
            "credits": 1,
            "event_type": "authentication",
            "phone_number": "+121234512345",
            "type": "sms"
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.telephony",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cdda426a-7e47-48c4-b2f5-b9f1ad5bf08a",
        "snapshot": true,
        "version": "8.8.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-05-10T14:57:17.933Z",
        "dataset": "cisco_duo.telephony",
        "ingested": "2023-05-10T14:57:18Z",
        "kind": "event",
        "original": "{\"context\":\"authentication\",\"credits\":1,\"isotimestamp\":\"2020-03-20T15:38:12+00:00\",\"phone\":\"+121234512345\",\"timestamp\":1584718692,\"type\":\"sms\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-telephony"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.telephony.credits | How many telephony credits this event cost. | integer |
| cisco_duo.telephony.event_type | How this telephony event was initiated. | keyword |
| cisco_duo.telephony.phone_number | The phone number that initiated this event. | keyword |
| cisco_duo.telephony.type | This type of telephony Event. | keyword |
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
