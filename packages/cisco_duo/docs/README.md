# Cisco Duo

The Cisco Duo integration collects and parses data from the [Cisco Duo Admin APIs](https://duo.com/docs/adminapi). The Duo Admin API provides programmatic access to the administrative functionality of Duo Security's two-factor authentication platform.

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

More details for each step can be found at [First steps](https://duo.com/docs/adminapi#first-steps).

## Data streams

The Cisco Duo integration collects logs for the following types of events.

- [**Activity Logs**](https://duo.com/docs/adminapi#activity-logs)
- [**Administrator Logs**](https://duo.com/docs/adminapi#administrator-logs)
- [**Authentication Logs**](https://duo.com/docs/adminapi#authentication-logs)
- [**Offline Enrollment Logs**](https://duo.com/docs/adminapi#offline-enrollment-logs)
- [**Summary**](https://duo.com/docs/adminapi#retrieve-summary)
- [**Telephony Logs**](https://duo.com/docs/adminapi#telephony-logs)
- [**Telephony Logs (legacy)**](https://duo.com/docs/adminapi#telephony-logs-(legacy-v1))
- [**Trust Monitor**](https://duo.com/docs/adminapi#trust-monitor)

## V2 Handlers

Cisco Duo has implemented v2 handlers for some endpoints. In these cases, the API v1 handler remains supported, but will be limited or deprecated in the future.

From data streams listed above, v2 handlers are supported for Activity, Authentication and Telephony Logs at the moment. It is recommended to migrate data streams to the v2 endpoints when they become available.

## Configuration

The following considerations should be taken into account when configuring the integration.

- Interval has to be greater or equal than `1m`.
- The Duo Admin API retrieves records from the last 180 days up to as recently as two minutes before the API request. Consider this when configuring the `Initial interval` parameter for the v2 API endpoints, as it doesn't support `d` as a suffix, its maximum value is `4320h` which corresponds to that 180 days.
- For v2 API endpoints, a new parameter `limit` has been added to control the number of records per response. Default value is 100 and can be incresead until 1000.
- Larger values of interval might cause delay in data ingestion.

## Logs

### Activity

This is the `activity` dataset.

An example event for `activity` looks as following:

```json
{
    "@timestamp": "2023-03-21T15:51:22.591Z",
    "agent": {
        "ephemeral_id": "a04443dc-0f75-4c19-87b0-c1c2b6325eae",
        "id": "87f5b0df-c981-4785-8d74-44932a323935",
        "name": "elastic-agent-22181",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "cisco_duo": {
        "activity": {
            "access_device": {
                "browser": "Chrome",
                "browser_version": "111.0.0.0",
                "epkey": "EP123456789012345678",
                "ip": {
                    "address": "172.34.40.116"
                },
                "location": {
                    "city": "Ann Arbor",
                    "country": "United States",
                    "state": "Michigan"
                },
                "os": "Mac OS X",
                "os_version": "10.15.7"
            },
            "action": {
                "name": "webauthncredential_create"
            },
            "actor": {
                "details": {
                    "created": "2015-09-25T23:17:40.000000+00:00",
                    "groups": [
                        {
                            "key": "DGAZ172QBWDM26AK8ITK",
                            "name": "CorpHQ_Users"
                        },
                        {
                            "key": "DGK3B7XTSIP00LKHK1RD",
                            "name": "ITAdmins"
                        },
                        {
                            "key": "DGKZWSBCDADEVFGFK5NR",
                            "name": "yee"
                        }
                    ],
                    "last_login": "2023-03-21T19:51:09.000000+00:00",
                    "status": "Active"
                },
                "key": "DU64TKJPJ0SHFWKO2LNBC",
                "name": "sogilby",
                "type": "user"
            },
            "akey": "DAAR5FO0OZ4VYZA0WOB2",
            "application": {
                "key": "DILSVDEYH66TBHKIXGR9",
                "name": "Acme Corp",
                "type": "websdk"
            },
            "id": "720b8360-078b-47c4-adc7-7968df1caef0",
            "outcome": "FAILURE",
            "target": {
                "details": {
                    "authenticator_type": "Security key",
                    "browser": "Chrome",
                    "browser_version": "111.0.0.0",
                    "credential_name": "Security key",
                    "os": "Mac OS X",
                    "os_version": "10.15.7",
                    "passwordless_authorized": false,
                    "transport_types": "usb",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
                },
                "key": "WAUKH0IMTGP00L90LT4KM",
                "name": "WAUKH0IMTG3EDD4DT4KM",
                "type": "webauthn_credential"
            }
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.activity",
        "namespace": "62263",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "87f5b0df-c981-4785-8d74-44932a323935",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "webauthncredential_create",
        "agent_id_status": "verified",
        "dataset": "cisco_duo.activity",
        "id": "720b8360-078b-47c4-adc7-7968df1caef0",
        "ingested": "2024-11-14T15:12:27Z",
        "kind": "event",
        "original": "{\"access_device\":{\"browser\":\"Chrome\",\"browser_version\":\"111.0.0.0\",\"epkey\":\"EP123456789012345678\",\"ip\":{\"address\":\"172.34.40.116\"},\"location\":{\"city\":\"Ann Arbor\",\"country\":\"United States\",\"state\":\"Michigan\"},\"os\":\"Mac OS X\",\"os_version\":\"10.15.7\"},\"action\":{\"details\":null,\"name\":\"webauthncredential_create\"},\"activity_id\":\"720b8360-078b-47c4-adc7-7968df1caef0\",\"actor\":{\"details\":\"{\\\"created\\\": \\\"2015-09-25T23:17:40.000000+00:00\\\",\\\"last_login\\\": \\\"2023-03-21T19:51:09.000000+00:00\\\",\\\"status\\\": \\\"Active\\\",\\\"groups\\\": [{\\\"name\\\": \\\"CorpHQ_Users\\\",\\\"key\\\": \\\"DGAZ172QBWDM26AK8ITK\\\"},{\\\"name\\\": \\\"ITAdmins\\\",\\\"key\\\": \\\"DGK3B7XTSIP00LKHK1RD\\\"},{\\\"name\\\": \\\"yee\\\",\\\"key\\\": \\\"DGKZWSBCDADEVFGFK5NR\\\"}]}\",\"key\":\"DU64TKJPJ0SHFWKO2LNBC\",\"name\":\"sogilby\",\"type\":\"user\"},\"akey\":\"DAAR5FO0OZ4VYZA0WOB2\",\"application\":{\"key\":\"DILSVDEYH66TBHKIXGR9\",\"name\":\"Acme Corp\",\"type\":\"websdk\"},\"old_target\":null,\"outcome\":{\"result\":\"FAILURE\"},\"target\":{\"details\":\"{\\\"authenticator_type\\\": \\\"Security key\\\",\\\"transport_types\\\": \\\"usb\\\",\\\"passwordless_authorized\\\": false,\\\"browser\\\": \\\"Chrome\\\",\\\"browser_version\\\": \\\"111.0.0.0\\\",\\\"os\\\": \\\"Mac OS X\\\",\\\"os_version\\\": \\\"10.15.7\\\",\\\"user_agent\\\": \\\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36\\\",\\\"credential_name\\\": \\\"Security key\\\"}\",\"key\":\"WAUKH0IMTGP00L90LT4KM\",\"name\":\"WAUKH0IMTG3EDD4DT4KM\",\"type\":\"webauthn_credential\"},\"ts\":\"2023-03-21T15:51:22.591015+00:00\"}",
        "outcome": "failure"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "ip": [
            "172.34.40.116"
        ],
        "user": [
            "sogilby"
        ]
    },
    "source": {
        "ip": "172.34.40.116"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-activity"
    ],
    "user": {
        "name": "sogilby"
    },
    "user_agent": {
        "name": "Chrome",
        "os": {
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "111.0.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.activity.access_device.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| cisco_duo.activity.access_device.as.organization.name | Organization name. | keyword |
| cisco_duo.activity.access_device.browser | The web browser used for access. | keyword |
| cisco_duo.activity.access_device.browser_version | The web browser version. | keyword |
| cisco_duo.activity.access_device.epkey | The device's unique identifier or epkey. | keyword |
| cisco_duo.activity.access_device.geo.city_name | City name (geo enrichment based on the IP address). | keyword |
| cisco_duo.activity.access_device.geo.continent_name | Name of the continent (geo enrichment based on the IP address). | keyword |
| cisco_duo.activity.access_device.geo.country_iso_code | Country ISO code (geo enrichment based on the IP address). | keyword |
| cisco_duo.activity.access_device.geo.country_name | Country name (geo enrichment based on the IP address). | keyword |
| cisco_duo.activity.access_device.geo.location | Longitude and latitude (geo enrichment based on the IP address). | geo_point |
| cisco_duo.activity.access_device.geo.region_iso_code | Region ISO code (geo enrichment based on the IP address). | keyword |
| cisco_duo.activity.access_device.geo.region_name | Region name (geo enrichment based on the IP address). | keyword |
| cisco_duo.activity.access_device.ip.address | IP address of access device. | ip |
| cisco_duo.activity.access_device.location.city | The city name provided by Cisco Duo. | keyword |
| cisco_duo.activity.access_device.location.country | The country code provided by Cisco Duo. Refer to ISO 3166 for a list of possible countries. | keyword |
| cisco_duo.activity.access_device.location.state | The state, county, province, or prefecture provided by Cisco Duo. | keyword |
| cisco_duo.activity.access_device.os | The device operating system name. | keyword |
| cisco_duo.activity.access_device.os_version | The device operating system version. | keyword |
| cisco_duo.activity.action.details | Provides additional information about the action. Details is optional. | keyword |
| cisco_duo.activity.action.name | The name is a string representing the action the actor performed. If a target is present, the action was performed on that target. | keyword |
| cisco_duo.activity.actor.details | Details about the actor. | flattened |
| cisco_duo.activity.actor.key | Identifier of the actor. | keyword |
| cisco_duo.activity.actor.name | Name of the actor. | keyword |
| cisco_duo.activity.actor.type | Type of actor. One of: admin, adminapi, admin_sync, azure_sync, deviceapi, ldapsync, system, or user. | keyword |
| cisco_duo.activity.akey | Unique identifier of entity associated with the activity log. | keyword |
| cisco_duo.activity.application.key | The application's integration key. | keyword |
| cisco_duo.activity.application.name | The application's name. | keyword |
| cisco_duo.activity.application.type | The application's type. | keyword |
| cisco_duo.activity.id | Transaction ID of the event. | keyword |
| cisco_duo.activity.old_target.details | Key-value pair of properties about the target. The properties for a given target may vary by target type, but should be consistent for the same type. | flattened |
| cisco_duo.activity.old_target.key | Key of the target that corresponds to the target type. | keyword |
| cisco_duo.activity.old_target.name | Name of the target. | keyword |
| cisco_duo.activity.old_target.type | The target type. One of: admin, adminap_integrations, authproxy, computer_registration, device_registration, enroll_code, group, log_export, login_settings, hardtoken, integration, phone, policy, trusted_endpoints_integration, u2f_token, user, user_bypass, or webauthn_credentials. | keyword |
| cisco_duo.activity.outcome | Result of the ADMIN_ACTION_ADMIN_LOGIN action. By default, the outcome field is "SUCCESS". On failure, the outcome field is "FAILURE". | keyword |
| cisco_duo.activity.target.details | Key-value pair of properties about the target. The properties for a given target may vary by target type, but should be consistent for the same type. | flattened |
| cisco_duo.activity.target.key | Key of the target that corresponds to the target type. | keyword |
| cisco_duo.activity.target.name | Name of the target. | keyword |
| cisco_duo.activity.target.type | The target type. One of: admin, adminap_integrations, authproxy, computer_registration, device_registration, enroll_code, group, log_export, login_settings, hardtoken, integration, phone, policy, trusted_endpoints_integration, u2f_token, user, user_bypass, or webauthn_credentials. | keyword |
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
| cisco_duo.admin.errors | The set of error reported for the event. | match_only_text |
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
        "ephemeral_id": "59577463-d70a-4e8d-b98a-f19259ea5754",
        "id": "58df2bd8-08b5-427c-9e9f-5bd330eaff86",
        "name": "elastic-agent-17284",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "cisco_duo": {
        "auth": {
            "access_device": {
                "as": {
                    "number": 29518,
                    "organization": {
                        "name": "Bredband2 AB"
                    }
                },
                "flash_version": "uninstalled",
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
        "namespace": "35756",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "58df2bd8-08b5-427c-9e9f-5bd330eaff86",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "cisco_duo.auth",
        "ingested": "2024-10-10T16:29:11Z",
        "kind": "event",
        "original": "{\"access_device\":{\"browser\":\"Chrome\",\"browser_version\":\"67.0.3396.99\",\"flash_version\":\"uninstalled\",\"hostname\":null,\"ip\":\"89.160.20.156\",\"is_encryption_enabled\":true,\"is_firewall_enabled\":true,\"is_password_set\":true,\"java_version\":\"uninstalled\",\"location\":{\"city\":\"Ann Arbor\",\"country\":\"United States\",\"state\":\"Michigan\"},\"os\":\"Mac OS X\",\"os_version\":\"10.14.1\",\"security_agents\":null},\"alias\":\"\",\"application\":{\"key\":\"DIY231J8BR23QK4UKBY8\",\"name\":\"Microsoft Azure Active Directory\"},\"auth_device\":{\"ip\":\"192.168.225.254\",\"location\":{\"city\":\"Ann Arbor\",\"country\":\"United States\",\"state\":\"Michigan\"},\"name\":\"My iPhone X (734-555-2342)\"},\"email\":\"narroway@example.com\",\"event_type\":\"authentication\",\"factor\":\"duo_push\",\"isotimestamp\":\"2020-02-13T18:56:20.351346+00:00\",\"ood_software\":null,\"reason\":\"user_approved\",\"result\":\"success\",\"timestamp\":1581620180,\"trusted_endpoint_status\":\"not trusted\",\"txid\":\"340a23e3-23f3-23c1-87dc-1491a23dfdbb\",\"user\":{\"groups\":[\"Duo Users\",\"CorpHQ Users\"],\"key\":\"DU3KC77WJ06Y5HIV7XKQ\",\"name\":\"narroway@example.com\"}}",
        "outcome": "success",
        "reason": "user_approved",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "ip": [
            "89.160.20.156",
            "192.168.225.254"
        ],
        "user": [
            "narroway@example.com"
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
| cisco_duo.auth.access_device.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| cisco_duo.auth.access_device.as.organization.name | Organization name. | keyword |
| cisco_duo.auth.access_device.flash_version | The Flash plugin version used, if present. | keyword |
| cisco_duo.auth.access_device.geo.city_name | City name (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.access_device.geo.continent_name | Name of the continent (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.access_device.geo.country_iso_code | Country ISO code (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.access_device.geo.country_name | Country name (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.access_device.geo.location | Longitude and latitude (geo enrichment based on the IP address). | geo_point |
| cisco_duo.auth.access_device.geo.region_iso_code | Region ISO code (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.access_device.geo.region_name | Region name (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.access_device.hostname | The hostname, if present. | keyword |
| cisco_duo.auth.access_device.ip | The access device's IP address. | ip |
| cisco_duo.auth.access_device.is_encryption_enabled | Reports the disk encryption state as detected by the Duo Device Health app. | keyword |
| cisco_duo.auth.access_device.is_firewall_enabled | Reports the firewall state as detected by the Duo Device Health app. | keyword |
| cisco_duo.auth.access_device.is_password_set | Reports the system password state as detected by the Duo Device Health app | keyword |
| cisco_duo.auth.access_device.java_version | The Java plugin version used. | keyword |
| cisco_duo.auth.access_device.location.city | The city name of the access device provided by Cisco Duo. | keyword |
| cisco_duo.auth.access_device.location.country | The country of the access device provided by Cisco Duo. | keyword |
| cisco_duo.auth.access_device.location.state | The state name of the access device provided by Cisco Duo. | keyword |
| cisco_duo.auth.access_device.port | The access device's port number. | long |
| cisco_duo.auth.access_device.security_agents | Reports the security agents present on the endpoint as detected by the Duo Device Health app. | flattened |
| cisco_duo.auth.alias | The username alias used to log in. | keyword |
| cisco_duo.auth.application.key | The application's integration_key. | keyword |
| cisco_duo.auth.application.name | The application's name. | keyword |
| cisco_duo.auth.auth_device.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| cisco_duo.auth.auth_device.as.organization.name | Organization name. | keyword |
| cisco_duo.auth.auth_device.geo.city_name | City name (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.auth_device.geo.continent_name | Name of the continent (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.auth_device.geo.country_iso_code | Country ISO code (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.auth_device.geo.country_name | Country name (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.auth_device.geo.location | Longitude and latitude (geo enrichment based on the IP address). | geo_point |
| cisco_duo.auth.auth_device.geo.region_iso_code | Region ISO code (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.auth_device.geo.region_name | Region name (geo enrichment based on the IP address). | keyword |
| cisco_duo.auth.auth_device.ip | The IP address of the authentication device. | ip |
| cisco_duo.auth.auth_device.location.city | The city name of the authentication device provided by Cisco Duo. | keyword |
| cisco_duo.auth.auth_device.location.country | The country of the authentication device provided by Cisco Duo. | keyword |
| cisco_duo.auth.auth_device.location.state | The state name of the authentication device provided by Cisco Duo. | keyword |
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
        "ephemeral_id": "e8ad4b18-fbaa-4216-91a3-4607968d61f3",
        "id": "0e034435-4ea5-4a95-9f07-151a1467f7d9",
        "name": "elastic-agent-20659",
        "type": "filebeat",
        "version": "8.13.0"
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
        "namespace": "52653",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0e034435-4ea5-4a95-9f07-151a1467f7d9",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2024-09-30T16:13:10.700Z",
        "dataset": "cisco_duo.telephony",
        "ingested": "2024-09-30T16:13:11Z",
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


### Telephony v2

This is the `telephony_v2` dataset.

An example event for `telephony_v2` looks as following:

```json
{
    "@timestamp": "2022-10-25T16:07:45.304Z",
    "agent": {
        "ephemeral_id": "cfc63710-9c78-4d83-acc6-cc1f17ea61ae",
        "id": "04bc48e2-1bc2-4745-baec-658738d836f3",
        "name": "elastic-agent-56970",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "cisco_duo": {
        "telephony_v2": {
            "credits": 0,
            "event_type": "administrator login",
            "id": "5bf1a860-fe39-49e3-be29-217659663a74",
            "phone_number": "+13135559542",
            "txid": "fb0c129b-f994-4d3d-953b-c3e764272eb7",
            "type": "sms"
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.telephony_v2",
        "namespace": "98588",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "04bc48e2-1bc2-4745-baec-658738d836f3",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cisco_duo.telephony_v2",
        "id": "5bf1a860-fe39-49e3-be29-217659663a74",
        "ingested": "2024-09-30T16:14:08Z",
        "kind": "event",
        "original": "{\"context\":\"administrator login\",\"credits\":0,\"phone\":\"+13135559542\",\"telephony_id\":\"5bf1a860-fe39-49e3-be29-217659663a74\",\"ts\":\"2022-10-25T16:07:45.304526+00:00\",\"txid\":\"fb0c129b-f994-4d3d-953b-c3e764272eb7\",\"type\":\"sms\"}"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-telephony_v2"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.telephony_v2.credits | How many telephony credits this event used. | integer |
| cisco_duo.telephony_v2.event_type | The context under which this telephony event was used (e.g. Administrator Login). | keyword |
| cisco_duo.telephony_v2.id | A unique identifier for the telephony event. | keyword |
| cisco_duo.telephony_v2.phone_number | The phone number that initiated this event. | keyword |
| cisco_duo.telephony_v2.txid | A unique identifier that relates to the successful authentication attempt using this telephony event. | keyword |
| cisco_duo.telephony_v2.type | The event type. Either "sms" or "phone". | keyword |
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


### Trust Monitor

This is the `trust_monitor` dataset.

An example event for `trust_monitor` looks as following:

```json
{
    "@timestamp": "2020-11-17T08:48:31.680Z",
    "agent": {
        "ephemeral_id": "6425e1a1-6171-4b20-ba87-65bf63231ef4",
        "id": "a2c45cbf-69cf-4bf5-93e2-df91aa0f8eae",
        "name": "elastic-agent-51366",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "cisco_duo": {
        "trust_monitor": {
            "explanations": [
                {
                    "summary": "amanda_tucker has not logged in from this location recently.",
                    "type": "NEW_COUNTRY_CODE"
                },
                {
                    "summary": "amanda_tucker has not logged in from this IP recently.",
                    "type": "NEW_NETBLOCK"
                },
                {
                    "summary": "amanda_tucker has not accessed this application recently.",
                    "type": "NEW_IKEY"
                }
            ],
            "from_common_netblock": true,
            "from_new_user": false,
            "low_risk_ip": false,
            "priority_event": true,
            "priority_reasons": [
                {
                    "label": "CN",
                    "type": "country"
                }
            ],
            "sekey": "SEDOR9BP00L23C6YUH5",
            "state": "new",
            "surfaced_auth": {
                "access_device": {
                    "browser": "Chrome",
                    "browser_version": "86.0.4240.198",
                    "epkey": "EP18JX1A10AB102M2T2X",
                    "ip": "17.88.232.83",
                    "is_encryption_enabled": "unknown",
                    "is_firewall_enabled": "unknown",
                    "is_password_set": "unknown",
                    "location": {
                        "city": "Shanghai",
                        "country": "China",
                        "state": "Shanghai"
                    },
                    "os": "Windows",
                    "os_version": "10",
                    "security_agents": "unknown"
                },
                "alias": "unknown",
                "application": {
                    "key": "DIUD2X62LHMPDP00LXS3",
                    "name": "Microsoft Azure Active Directory"
                },
                "factor": "not_available",
                "isotimestamp": "2020-11-17T03:19:13.092+00:00",
                "reason": "location_restricted",
                "result": "denied",
                "timestamp": 1605583153,
                "txid": "436694ad-467c-4aed-b048-8ad--f58e04c",
                "user": {
                    "groups": [
                        "crazy"
                    ],
                    "key": "DUN73JE5M92DP00L4ZYS",
                    "name": "amanda_tucker"
                }
            },
            "triage_event_uri": "https://admin-xxxxxxxx.duosecurity.com/trust-monitor?sekey=SEDOR9BP00L23C6YUH5",
            "triaged_as_interesting": false,
            "type": "auth"
        }
    },
    "data_stream": {
        "dataset": "cisco_duo.trust_monitor",
        "namespace": "54506",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a2c45cbf-69cf-4bf5-93e2-df91aa0f8eae",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cisco_duo.trust_monitor",
        "id": "SEDOR9BP00L23C6YUH5",
        "ingested": "2024-10-04T07:55:31Z",
        "kind": "event",
        "original": "{\"explanations\":[{\"summary\":\"amanda_tucker has not logged in from this location recently.\",\"type\":\"NEW_COUNTRY_CODE\"},{\"summary\":\"amanda_tucker has not logged in from this IP recently.\",\"type\":\"NEW_NETBLOCK\"},{\"summary\":\"amanda_tucker has not accessed this application recently.\",\"type\":\"NEW_IKEY\"}],\"from_common_netblock\":true,\"from_new_user\":false,\"low_risk_ip\":false,\"priority_event\":true,\"priority_reasons\":[{\"label\":\"CN\",\"type\":\"country\"}],\"sekey\":\"SEDOR9BP00L23C6YUH5\",\"state\":\"new\",\"state_updated_timestamp\":null,\"surfaced_auth\":{\"access_device\":{\"browser\":\"Chrome\",\"browser_version\":\"86.0.4240.198\",\"epkey\":\"EP18JX1A10AB102M2T2X\",\"flash_version\":null,\"hostname\":null,\"ip\":\"17.88.232.83\",\"is_encryption_enabled\":\"unknown\",\"is_firewall_enabled\":\"unknown\",\"is_password_set\":\"unknown\",\"java_version\":null,\"location\":{\"city\":\"Shanghai\",\"country\":\"China\",\"state\":\"Shanghai\"},\"os\":\"Windows\",\"os_version\":\"10\",\"security_agents\":\"unknown\"},\"alias\":\"unknown\",\"application\":{\"key\":\"DIUD2X62LHMPDP00LXS3\",\"name\":\"Microsoft Azure Active Directory\"},\"auth_device\":{\"ip\":null,\"key\":null,\"location\":{\"city\":null,\"country\":null,\"state\":null},\"name\":null},\"email\":\"\",\"event_type\":null,\"factor\":\"not_available\",\"isotimestamp\":\"2020-11-17T03:19:13.092+00:00\",\"ood_software\":\"\",\"reason\":\"location_restricted\",\"result\":\"denied\",\"timestamp\":1605583153,\"trusted_endpoint_status\":null,\"txid\":\"436694ad-467c-4aed-b048-8ad--f58e04c\",\"user\":{\"groups\":[\"crazy\"],\"key\":\"DUN73JE5M92DP00L4ZYS\",\"name\":\"amanda_tucker\"}},\"surfaced_timestamp\":1605602911680,\"triage_event_uri\":\"https://admin-xxxxxxxx.duosecurity.com/trust-monitor?sekey=SEDOR9BP00L23C6YUH5\",\"triaged_as_interesting\":false,\"type\":\"auth\"}"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_duo-trust_monitor"
    ],
    "url": {
        "domain": "admin-xxxxxxxx.duosecurity.com",
        "original": "https://admin-xxxxxxxx.duosecurity.com/trust-monitor?sekey=SEDOR9BP00L23C6YUH5",
        "path": "/trust-monitor",
        "query": "sekey=SEDOR9BP00L23C6YUH5",
        "scheme": "https"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_duo.trust_monitor.bypass_status_enabled | The Unix timestamp in milliseconds when bypass status was enabled for the user or group. Returned for events with type=bypass_status. | long |
| cisco_duo.trust_monitor.enabled_by.key | Key of the application or the administrator that enabled bypass status. Returned for events with type=bypass_status. | keyword |
| cisco_duo.trust_monitor.enabled_by.name | Name of the application or the administrator that enabled bypass status. Returned for events with type=bypass_status. | keyword |
| cisco_duo.trust_monitor.enabled_for.key | Key of the user or group with bypass status. Returned for events with type=bypass_status. | keyword |
| cisco_duo.trust_monitor.enabled_for.name | Name of the user or group with bypass status. Returned for events with type=bypass_status. | keyword |
| cisco_duo.trust_monitor.explanations.summary | Description of why Trust Monitor surfaced the event. | keyword |
| cisco_duo.trust_monitor.explanations.type | Type of reason why Trust Monitor surfaced the event. | keyword |
| cisco_duo.trust_monitor.from_common_netblock | A boolean describing if this event was created from a common IP netblock. Returned for events with type=auth. | boolean |
| cisco_duo.trust_monitor.from_new_user | A boolean describing if this event was created for a new user. Returned for events with type=auth or type=device_registration. | boolean |
| cisco_duo.trust_monitor.low_risk_ip | A boolean describing if this event was created from an IP address identified in the Risk Profile configuration as a low risk IP address. Returned for events with type=auth. | boolean |
| cisco_duo.trust_monitor.priority_event | A boolean describing if the event matches the Risk Profile configuration. | boolean |
| cisco_duo.trust_monitor.priority_reasons.label | The label of the priority reason describing how the event matches the Trust Monitor Risk Profile configuration for the event's match. Returned for events with type=auth or type=device_registration. | keyword |
| cisco_duo.trust_monitor.priority_reasons.type | The type of priority reason describing how the event matches the Trust Monitor Risk Profile configuration for the event's match. Returned for events with type=auth or type=device_registration. | keyword |
| cisco_duo.trust_monitor.sekey | The unique identifier for this event as a 20 character string. This is unique across all different event types. | keyword |
| cisco_duo.trust_monitor.state | A string describing the state of the event. One of statenew or stateprocessed. | keyword |
| cisco_duo.trust_monitor.state_updated_timestamp | The Unix timestamp in milliseconds of the last change to the state of the event. | long |
| cisco_duo.trust_monitor.surfaced_auth | An object which represents the actual authentication. Returned for events with type=auth. | flattened |
| cisco_duo.trust_monitor.triage_event_uri | A string representing the URI of the security event, which a Duo administrator can use to view and process the surfaced event in the Duo Admin Panel. Returned for events with type=auth. | keyword |
| cisco_duo.trust_monitor.triaged_as_interesting | A boolean describing if this event was triaged as being interesting or not interesting. | boolean |
| cisco_duo.trust_monitor.type | The type of event, as a string. One of auth, bypass_status, or device_registration. | keyword |
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

