# Google Workspace Integration

The Google Workspace integration collects and parses data from the different [Google Workspace audit reports APIs](https://developers.google.com/admin-sdk/reports).

If you want to know more about how you can fully leverage the Google Workspace integration, there is a multipart blog from our Security Labs that will help you:

1. To understand what Google Workspace is in [Part One - Surveying the Land](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one)
2. To set it up, step by step, in [Part Two - Setup Threat Detection with Elastic](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two)
3. And to use the collected information to your advantage in [Part Three - Detecting Common Threats](https://www.elastic.co/security-labs/google-workspace-attack-surface-part-three)

## Compatibility

It is compatible with a subset of applications under the [Google Reports API v1](https://developers.google.com/admin-sdk/reports/v1/get-start/getting-started). As of today it supports:

| Google Workspace Service | Description |
|---|---|
| [SAML](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/saml) [help](https://support.google.com/a/answer/7007375?hl=en&ref_topic=9027054) | View users’ successful and failed sign-ins to SAML applications. |
| [User Accounts](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts) [help](https://support.google.com/a/answer/9022875?hl=en&ref_topic=9027054) | Audit actions carried out by users on their own accounts including password changes, account recovery details and 2-Step Verification enrollment. |
| [Login](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login) [help](https://support.google.com/a/answer/4580120?hl=en&ref_topic=9027054) | Track user sign-in activity to your domain. |
| [Rules](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules) [help](https://support.google.com/a/answer/9656783?hl=en&ref_topic=9027054) | View a record of actions to review your user’s attempts to share sensitive data. |
| [Admin](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-application-settings) [help](https://support.google.com/a/answer/4579579?hl=en&ref_topic=9027054) | View administrator activity performed within the Google Admin console. |
| [Drive](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive) [help](https://support.google.com/a/answer/4579696?hl=en&ref_topic=9027054) | Record user activity within Google Drive including content creation in such as Google Docs, as well as content created elsewhere that your users upload to Drive such as PDFs and Microsoft Word files. |
| [Groups](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups) [help](https://support.google.com/a/answer/6270454?hl=en&ref_topic=9027054) | Track changes to groups, group memberships and group messages. |
| [Group Enterprise](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups-enterprise) [help](https://support.google.com/a/answer/9667889?hl=en&ref_topic=9027054) | The Group Enterprise activity report returns information about various types of Enterprise Groups Audit activity events. |
| [Device](https://developers.google.com/admin-sdk/reports/v1/reference/appendix/mobile) [help](https://support.google.com/a/answer/6350074?hl=en&ref_topic=9027054) | The Mobile activity report returns information about various types of Device Audit activity events. |
| [Token](https://developers.google.com/admin-sdk/reports/v1/reference/activity-ref-appendix-a/token-event-names) [help](https://support.google.com/a/answer/6124308?hl=en&ref_topic=9027054) | The Token activity report returns information about various types of OAuth Token Audit activity events. |
| [Access Transparency](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/access-transparency) [help](https://support.google.com/a/answer/9230474?hl=en) | The Access Transparency activity report returns information about various types of Access Transparency activity events. |
| [Context Aware Access](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/context-aware-access) [help](https://support.google.com/a/answer/9394107?hl=en#zippy=) | The Context Aware Access activity report returns information about various types of Context-Aware Access Audit activity events. |
| [GCP](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/gcp) | The GCP activity report returns information about various types of Google Cloud Platform activity events. |

## Requirements

In order to ingest data from the Google Reports API you must:

- Have an *administrator account*.
- [Set up a ServiceAccount](https://support.google.com/workspacemigrate/answer/9222993?hl=en) using the administrator account.
- [Set up access to the Admin SDK API](https://support.google.com/workspacemigrate/answer/9222865?hl=en) for the ServiceAccount.
- [Enable Domain-Wide Delegation](https://developers.google.com/admin-sdk/reports/v1/guides/delegation) for your ServiceAccount.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly`

Once you have downloaded your service account credentials as a JSON file, you are ready to set up your integration.

Click the Advanced option of Google Workspace Audit Reports. The default value of "API Host" is `https://www.googleapis.com`. The API Host will be used for collecting `access_transparency`, `admin`, `device`, `context_aware_access`, `drive`, `gcp`, `groups`, `group_enterprise`, `login`, `rules`, `saml`, `token` and `user accounts` logs.

>  NOTE: The `Delegated Account` value in the configuration, is expected to be the email of the administrator account, and not the email of the ServiceAccount.

# Google Workspace Alert

The [Google Workspace](https://developers.google.com/admin-sdk/alertcenter) Integration collects and parses data received from the Google Workspace Alert Center API using HTTP JSON Input.

## Compatibility

- Alert Data Stream has been tested against `Google Workspace Alert Center API (v1)`.

- Following Alert types have been supported in the current integration version:
    1. Customer takeout initiated
    2. Malware reclassification
    3. Misconfigured whitelist
    4. Phishing reclassification
    5. Suspicious message reported
    6. User reported phishing
    7. User reported spam spike
    8. Leaked password
    9. Suspicious login
    10. Suspicious login (less secure app)
    11. Suspicious programmatic login
    12. User suspended
    13. User suspended (spam)
    14. User suspended (spam through relay)
    15. User suspended (suspicious activity)
    16. Google Operations
    17. Configuration problem
    18. Government attack warning
    19. Device compromised
    20. Suspicious activity
    21. AppMaker Default Cloud SQL setup
    22. Activity Rule
    23. Data Loss Prevention
    24. Apps outage
    25. Primary admin changed
    26. SSO profile added
    27. SSO profile updated
    28. SSO profile deleted
    29. Super admin password reset
    30. Account suspension warning
    31. Calendar settings changed
    32. Chrome devices auto-update expiration warning
    33. Customer takeout initiated
    34. Drive settings changed
    35. Email settings changed
    36. Gmail potential employee spoofing
    37. Mobile settings changed
    38. New user added
    39. Reporting Rule
    40. Suspended user made active
    41. User deleted
    42. User granted Admin privilege
    43. User suspended (spam)
    44. User's Admin privileges revoked
    45. Users password changed
    46. Google Voice configuration problem detected


## Requirements

In order to ingest data from the Google Alert Center API, you must:

- Have an *administrator account*.
- [Set up a ServiceAccount](https://support.google.com/workspacemigrate/answer/9222993?hl=en) using the Administrator Account.
- [Set up access to the Admin SDK API](https://support.google.com/workspacemigrate/answer/9222865?hl=en) for the ServiceAccount.
- [Enable Domain-Wide Delegation](https://developers.google.com/admin-sdk/reports/v1/guides/delegation) for the ServiceAccount.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/apps.alerts`

Once Service Account credentials are downloaded as a JSON file, then the integration can be setup to collect data.

>  NOTE: The `Delegated Account` value in the configuration, is expected to be the email of the administrator account, and not the email of the ServiceAccount.

>  NOTE: The default value of the "Page Size" is set to 1000. This option is available under 'Alert' Advance options. Set the parameter "Page Size" according to the requirement. For Alert Data Stream, The default value of "Alert Center API Host" is `https://alertcenter.googleapis.com`. The Alert Center API Host will be used for collecting alert logs only.

## Logs

### Google Workspace Reports ECS fields

This is a list of Google Workspace Reports fields that are mapped to ECS that are common to al data sets.

| Google Workspace Reports     | ECS Fields                                                    |
|------------------------------|---------------------------------------------------------------|
| `items[].id.time`            | `@timestamp`                                                  |
| `items[].id.uniqueQualifier` | `event.id`                                                    |
| `items[].id.applicationName` | `event.provider`                                              |
| `items[].events[].name`      | `event.action`                                                |
| `items[].customerId`         | `organization.id`                                             |
| `items[].ipAddress`          | `source.ip`, `related.ip`, `source.as.*`, `source.geo.*`      |
| `items[].actor.email`        | `source.user.email`, `source.user.name`, `source.user.domain` |
| `items[].actor.profileId`    | `source.user.id`                                              |

### SAML

This is the `saml` dataset.

An example event for `saml` looks as following:

```json
{
    "@timestamp": "2021-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "21bc9c22-c07c-4d9e-be7d-d847757ace52",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.saml",
        "namespace": "42924",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "login_failure",
        "agent_id_status": "verified",
        "category": [
            "authentication",
            "session"
        ],
        "created": "2024-08-01T22:01:50.429Z",
        "dataset": "google_workspace.saml",
        "id": "1",
        "ingested": "2024-08-01T22:02:02Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"login_failure\",\"parameters\":[{\"name\":\"application_name\",\"value\":\"app\"},{\"name\":\"failure_type\",\"value\":\"failure_app_not_configured_for_user\"},{\"name\":\"initiated_by\",\"value\":\"idp\"},{\"name\":\"orgunit_path\",\"value\":\"ounit\"},{\"name\":\"saml_second_level_status_code\",\"value\":\"SUCCESS_URI\"},{\"name\":\"saml_status_code\",\"value\":\"SUCCESS_URI\"}],\"type\":\"login\"},\"id\":{\"applicationName\":\"saml\",\"customerId\":\"1\",\"time\":\"2021-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"98.235.162.24\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"elastic.com\"}",
        "outcome": "failure",
        "provider": "saml",
        "type": [
            "start"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "event": {
            "type": "login"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "saml": {
            "application_name": "app",
            "failure_type": "failure_app_not_configured_for_user",
            "initiated_by": "idp",
            "orgunit_path": "ounit",
            "second_level_status_code": "SUCCESS_URI",
            "status_code": "SUCCESS_URI"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-saml"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| google_workspace.saml.application_name | Saml SP application name. | keyword |
| google_workspace.saml.failure_type | Login failure type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/saml. | keyword |
| google_workspace.saml.initiated_by | Requester of SAML authentication. | keyword |
| google_workspace.saml.orgunit_path | User orgunit. | keyword |
| google_workspace.saml.second_level_status_code | SAML second level status code. | keyword |
| google_workspace.saml.status_code | SAML status code. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### User Accounts

This is the `user_accounts` dataset.

An example event for `user_accounts` looks as following:

```json
{
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "65179230-7468-4b71-9b2b-a2cd4f778866",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.user_accounts",
        "namespace": "10103",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "2sv_disable",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2024-08-01T22:03:58.977Z",
        "dataset": "google_workspace.user_accounts",
        "id": "1",
        "ingested": "2024-08-01T22:04:10Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"2sv_disable\",\"type\":\"2sv_change\"},\"id\":{\"applicationName\":\"user_accounts\",\"customerId\":\"1\",\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"98.235.162.24\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"elastic.com\"}",
        "provider": "user_accounts",
        "type": [
            "change",
            "user"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "event": {
            "type": "2sv_change"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-user_accounts"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| google_workspace.user_accounts.email_forwarding_destination_address | Out of domain email the actor has forwarded to. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Login Accounts

This is the `login` dataset.

An example event for `login` looks as following:

```json
{
    "@timestamp": "2022-05-04T15:04:05.000Z",
    "agent": {
        "ephemeral_id": "8d5b6a07-b1e1-4397-982f-9223504ae534",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.login",
        "namespace": "61171",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "account_disabled_password_leak",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2024-08-01T21:59:36.067Z",
        "dataset": "google_workspace.login",
        "id": "1",
        "ingested": "2024-08-01T21:59:48Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"account_disabled_password_leak\",\"parameters\":[{\"name\":\"affected_email_address\",\"value\":\"foo@elastic.co\"}],\"type\":\"account_warning\"},\"id\":{\"applicationName\":\"login\",\"customerId\":\"1\",\"time\":\"2022-05-04T15:04:05Z\",\"uniqueQualifier\":1},\"ipAddress\":\"98.235.162.24\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"elastic.com\"}",
        "provider": "login",
        "type": [
            "user",
            "info"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "event": {
            "type": "account_warning"
        },
        "kind": "admin#reports#activity",
        "login": {
            "affected_email_address": "foo@elastic.co"
        },
        "organization": {
            "domain": "elastic.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo",
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-login"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo",
        "target": {
            "domain": "elastic.co",
            "name": "foo"
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
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.login.affected_email_address |  | keyword |
| google_workspace.login.challenge_method | Login challenge method. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.login.challenge_status | Login challenge status. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.login.failure_type | Login failure type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.login.is_second_factor |  | boolean |
| google_workspace.login.is_suspicious |  | boolean |
| google_workspace.login.timestamp | UNIX timestmap of login in microseconds. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | long |
| google_workspace.login.type | Login credentials type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login. | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Rules

This is the `rules` dataset.

An example event for `rules` looks as following:

```json
{
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "5c6a871e-fa71-4f56-b30d-46922ca4e836",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.rules",
        "namespace": "88921",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "rule_match",
        "agent_id_status": "verified",
        "created": "2024-08-01T22:00:43.194Z",
        "dataset": "google_workspace.rules",
        "id": "1",
        "ingested": "2024-08-01T22:00:55Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"rule_match\",\"parameters\":[{\"boolValue\":\"true\",\"name\":\"has_alert\"},{\"name\":\"actor_ip_address\",\"value\":\"127.0.0.0\"},{\"intValue\":\"1234\",\"name\":\"resource_recipients_omitted_count\"},{\"multiValue\":[\"managers\"],\"name\":\"rule_name\"},{\"multiIntValue\":[\"12\"],\"name\":\"rule_id\"}],\"type\":\"rule_match_type\"},\"id\":{\"applicationName\":\"rules\",\"customerId\":\"1\",\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"elastic.com\"}",
        "provider": "rules"
    },
    "google_workspace": {
        "actor": {
            "email": "foo@bar.com",
            "profile": {
                "id": "1"
            },
            "type": "USER"
        },
        "event": {
            "name": "rule_match",
            "type": "rule_match_type"
        },
        "id": {
            "application_name": "rules",
            "customer": {
                "id": "1"
            },
            "time": "2020-10-02T15:00:00.000Z",
            "unique_qualifier": "1"
        },
        "ip_address": "67.43.156.13",
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        },
        "rules": {
            "actor_ip_address": "127.0.0.0",
            "has_alert": true,
            "id": [
                "12"
            ],
            "name": [
                "managers"
            ],
            "resource": {
                "recipients_omitted_count": 1234
            }
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "hosts": [
            "bar.com",
            "elastic.com"
        ],
        "ip": [
            "67.43.156.13",
            "127.0.0.0"
        ],
        "user": [
            "foo"
        ]
    },
    "rule": {
        "id": [
            "12"
        ],
        "name": [
            "managers"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-rules"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile.id | The unique Google Workspace profile ID of the actor. This value might be absent if the actor is not a Google Workspace user, or may be the number 105250506097979753968 which acts as a placeholder ID. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.event.name | Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific Google Workspace service or feature which the API organizes into types of events. For eventName request parameters in general:   If no eventName is given, the report returns all possible instances of an eventName.   When you request an eventName, the API's response returns all activities which contain that eventName. It is possible that the returned activities will have other eventName properties in addition to the one requested. For more information about eventName properties, see the list of event names for various applications above in applicationName. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer.id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| google_workspace.rules.actions | List of actions taken. For a list of possible values refer to `actions` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#rule_match). | keyword |
| google_workspace.rules.actor_ip_address | IP of the entity who was responsible for the original event which triggered the rule. | ip |
| google_workspace.rules.application | Name of the application to which the flagged item belongs. For a list of possible values refer to `application` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#rule_match). | keyword |
| google_workspace.rules.conference_id | The unique identifier of a Google Meet conference. | keyword |
| google_workspace.rules.data_source | Source of the data. For a list of possible values refer to `data_source` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#rule_trigger). | keyword |
| google_workspace.rules.device.id | ID of the device on which the action was triggered. | keyword |
| google_workspace.rules.device.type | Type of device referred to by device ID. For a list of possible values refer to `device_type` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#action_complete). | keyword |
| google_workspace.rules.drive_shared_drive_id | Shared drive Id to which the drive item belongs, if applicable. | keyword |
| google_workspace.rules.evaluation_context | Evaluation metadata, such as contextual messages used in a rule evaluation. | flattened |
| google_workspace.rules.has_alert | Whether or not the triggered rule has alert enabled. | boolean |
| google_workspace.rules.has_content_match | Whether the resource has content which matches the criteria in the rule. For a list of possible values refer to `has_content_match` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#rule_match). | boolean |
| google_workspace.rules.id | Unique identifier for a rule. Rules are created by admins in Google Workspace. | keyword |
| google_workspace.rules.matched.detectors | A list of detectors that matched against the resource. | flattened |
| google_workspace.rules.matched.templates | List of content detector templates that matched. | keyword |
| google_workspace.rules.matched.threshold | Threshold that matched in the rule. | keyword |
| google_workspace.rules.matched.trigger | Trigger of the rule evaluation: email sent or received, document shared. For a list of possible values refer to `matched_trigger` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#rule_trigger). | keyword |
| google_workspace.rules.mobile_device_type | Type of device on which rule was applied. | keyword |
| google_workspace.rules.mobile_ios_vendor_id | iOS Vendor Id of device on which rule was applied, if applicable. | keyword |
| google_workspace.rules.name | Name of the rule. | keyword |
| google_workspace.rules.resource.id | Identifier of the resource which matched the rule. | keyword |
| google_workspace.rules.resource.name | Resource name that uniquely identifies a rule. | keyword |
| google_workspace.rules.resource.owner_email | Email address of the owner of the resource. | keyword |
| google_workspace.rules.resource.recipients | A list of users that a Drive document or an email message was shared with when the rule was triggered. | keyword |
| google_workspace.rules.resource.recipients_omitted_count | The number of resource recipients omitted due to exceeding the size limit. | long |
| google_workspace.rules.resource.title | Title of the resource which matched the rule: email subject, or document title. | keyword |
| google_workspace.rules.resource.type | Type of the rule. For a list of possible values refer to `resource_type` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#action_complete). | keyword |
| google_workspace.rules.resource_name | Name of the resource which matched the rule. | keyword |
| google_workspace.rules.scan_type | Scan mode for the rule evaluation. For a list of possible values refer to `scan_type` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#action_complete). | keyword |
| google_workspace.rules.severity | Severity of violating a rule. For a list of possible values refer to to `severity` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#action_complete). | keyword |
| google_workspace.rules.space.id | ID of the space where the rule was triggered. | keyword |
| google_workspace.rules.space.type | Type of space referred to by the space ID. For a list of possible values refer to `space_type` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#action_complete). | keyword |
| google_workspace.rules.suppressed_actions | A list of actions that were not taken due to other actions with higher priority. | flattened |
| google_workspace.rules.triggered_actions | A list of actions that were taken as a consequence of the rule being triggered. | flattened |
| google_workspace.rules.type | Type of the rule. For a list of possible values refer to `rule_type` in the [event details table](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/rules#action_complete). | keyword |
| google_workspace.rules.update_time_usec | Update time (microseconds since epoch) indicating the version of rule which is used. | date |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Admin

This is the `admin` dataset.

An example event for `admin` looks as following:

```json
{
    "@timestamp": "2022-04-04T15:04:05.000Z",
    "agent": {
        "ephemeral_id": "e64e710c-e02b-4997-bb7e-83b936dd6aa5",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.admin",
        "namespace": "62273",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "CHANGE_APPLICATION_SETTING",
        "agent_id_status": "verified",
        "category": [
            "iam",
            "configuration"
        ],
        "created": "2024-08-01T21:51:15.529Z",
        "dataset": "google_workspace.admin",
        "id": "1",
        "ingested": "2024-08-01T21:51:27Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"CHANGE_APPLICATION_SETTING\",\"parameters\":[{\"name\":\"APPLICATION_EDITION\",\"value\":\"basic\"},{\"name\":\"APPLICATION_NAME\",\"value\":\"drive\"},{\"name\":\"GROUP_EMAIL\",\"value\":\"group@example.com\"},{\"name\":\"NEW_VALUE\",\"value\":\"new\"},{\"name\":\"OLD_VALUE\",\"value\":\"old\"},{\"name\":\"ORG_UNIT_NAME\",\"value\":\"org\"},{\"name\":\"SETTING_NAME\",\"value\":\"setting\"}],\"type\":\"APPLICATION_SETTINGS\"},\"id\":{\"applicationName\":\"admin\",\"customerId\":\"1\",\"time\":\"2022-04-04T15:04:05Z\",\"uniqueQualifier\":1},\"ipAddress\":\"98.235.162.24\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"elastic.com\"}",
        "provider": "admin",
        "type": [
            "change"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "admin": {
            "application": {
                "edition": "basic",
                "name": "drive"
            },
            "group": {
                "email": "group@example.com"
            },
            "new_value": "new",
            "old_value": "old",
            "org_unit": {
                "name": "org"
            },
            "setting": {
                "name": "setting"
            }
        },
        "event": {
            "type": "APPLICATION_SETTINGS"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "group": {
        "domain": "example.com",
        "name": "group"
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-admin"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo",
        "target": {
            "group": {
                "domain": "example.com",
                "name": "group"
            }
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
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.admin.alert.name | The alert name. | keyword |
| google_workspace.admin.api.client.name | The API client name. | keyword |
| google_workspace.admin.api.scopes | The API scopes. | keyword |
| google_workspace.admin.application.asp_id | The application specific password ID. | keyword |
| google_workspace.admin.application.edition | The Google Workspace edition. | keyword |
| google_workspace.admin.application.enabled | The enabled application. | keyword |
| google_workspace.admin.application.id | The application ID. | keyword |
| google_workspace.admin.application.licences_order_number | Order number used to redeem licenses. | keyword |
| google_workspace.admin.application.licences_purchased | Number of licences purchased. | long |
| google_workspace.admin.application.name | The application's name. | keyword |
| google_workspace.admin.application.package_id | The mobile application package ID. | keyword |
| google_workspace.admin.bulk_upload.failed | Number of failed records in bulk upload operation. | long |
| google_workspace.admin.bulk_upload.total | Number of total records in bulk upload operation. | long |
| google_workspace.admin.chrome_licenses.allowed | Licences enabled. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-org-settings | keyword |
| google_workspace.admin.chrome_licenses.enabled | Licences enabled. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-org-settings | keyword |
| google_workspace.admin.chrome_os.session_type | Chrome OS session type. | keyword |
| google_workspace.admin.device.command_details | Command details. | keyword |
| google_workspace.admin.device.id |  | keyword |
| google_workspace.admin.device.serial_number | Device serial number. | keyword |
| google_workspace.admin.device.type | Device type. | keyword |
| google_workspace.admin.distribution.entity.name | The distribution entity value, which can be a group name or an org-unit name. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-mobile-settings | keyword |
| google_workspace.admin.distribution.entity.type | The distribution entity type, which can be a group or an org-unit. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-mobile-settings | keyword |
| google_workspace.admin.domain.alias | The domain alias. | keyword |
| google_workspace.admin.domain.name | The primary domain name. | keyword |
| google_workspace.admin.domain.secondary_name | The secondary domain name. | keyword |
| google_workspace.admin.email.log_search_filter.end_date | The log search filter's ending date. | date |
| google_workspace.admin.email.log_search_filter.message_id | The log search filter's email message ID. | keyword |
| google_workspace.admin.email.log_search_filter.recipient.ip | The log search filter's email recipient's IP address. | ip |
| google_workspace.admin.email.log_search_filter.recipient.value | The log search filter's email recipient. | keyword |
| google_workspace.admin.email.log_search_filter.sender.ip | The log search filter's email sender's IP address. | ip |
| google_workspace.admin.email.log_search_filter.sender.value | The log search filter's email sender. | keyword |
| google_workspace.admin.email.log_search_filter.start_date | The log search filter's start date. | date |
| google_workspace.admin.email.quarantine_name | The name of the quarantine. | keyword |
| google_workspace.admin.email_dump.include_deleted | Indicates if deleted emails are included in the export. | boolean |
| google_workspace.admin.email_dump.package_content | The contents of the mailbox package. | keyword |
| google_workspace.admin.email_dump.query | The search query used for the dump. | keyword |
| google_workspace.admin.email_monitor.dest_email | The destination address of the email monitor. | keyword |
| google_workspace.admin.email_monitor.level.chat | The chat email monitor level. | keyword |
| google_workspace.admin.email_monitor.level.draft | The draft email monitor level. | keyword |
| google_workspace.admin.email_monitor.level.incoming | The incoming email monitor level. | keyword |
| google_workspace.admin.email_monitor.level.outgoing | The outgoing email monitor level. | keyword |
| google_workspace.admin.field | The name of the field. | keyword |
| google_workspace.admin.gateway.name | Gateway name. Present on some chat settings. | keyword |
| google_workspace.admin.group.allowed_list | Names of allow-listed groups. | keyword |
| google_workspace.admin.group.email | The group's primary email address. | keyword |
| google_workspace.admin.group.priorities | Group priorities. | keyword |
| google_workspace.admin.info_type | This will be used to state what kind of information was changed. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings | keyword |
| google_workspace.admin.managed_configuration | The name of the managed configuration. | keyword |
| google_workspace.admin.mdm.token | The MDM vendor enrollment token. | keyword |
| google_workspace.admin.mdm.vendor | The MDM vendor's name. | keyword |
| google_workspace.admin.mobile.action.id | The mobile device action's ID. | keyword |
| google_workspace.admin.mobile.action.type | The mobile device action's type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-mobile-settings | keyword |
| google_workspace.admin.mobile.certificate.name | The mobile certificate common name. | keyword |
| google_workspace.admin.mobile.company_owned_devices | The number of devices a company owns. | long |
| google_workspace.admin.new_value | The new value for the setting. | keyword |
| google_workspace.admin.non_featured_services_selection | Non-featured services selection. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-application-settings#FLASHLIGHT_EDU_NON_FEATURED_SERVICES_SELECTED | keyword |
| google_workspace.admin.oauth2.application.id | OAuth2 application ID. | keyword |
| google_workspace.admin.oauth2.application.name | OAuth2 application name. | keyword |
| google_workspace.admin.oauth2.application.type | OAuth2 application type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings | keyword |
| google_workspace.admin.oauth2.service.name | OAuth2 service name. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings | keyword |
| google_workspace.admin.old_value | The old value for the setting. | keyword |
| google_workspace.admin.org_unit.full | The org unit full path including the root org unit name. | keyword |
| google_workspace.admin.org_unit.name | The organizational unit name. | keyword |
| google_workspace.admin.print_server.name | The name of the print server. | keyword |
| google_workspace.admin.printer.name | The name of the printer. | keyword |
| google_workspace.admin.privilege.name | Privilege name. | keyword |
| google_workspace.admin.product.name | The product name. | keyword |
| google_workspace.admin.product.sku | The product SKU. | keyword |
| google_workspace.admin.request.id | The request ID. | keyword |
| google_workspace.admin.resource.id | The name of the resource identifier. | keyword |
| google_workspace.admin.role.id | Unique identifier for this role privilege. | keyword |
| google_workspace.admin.role.name | The role name. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings | keyword |
| google_workspace.admin.rule.name | The rule name. | keyword |
| google_workspace.admin.service.name | The service name. | keyword |
| google_workspace.admin.setting.description | The setting name. | keyword |
| google_workspace.admin.setting.name | The setting name. | keyword |
| google_workspace.admin.url.name | The website name. | keyword |
| google_workspace.admin.user.birthdate | The user's birth date. | date |
| google_workspace.admin.user.email | The user's primary email address. | keyword |
| google_workspace.admin.user.nickname | The user's nickname. | keyword |
| google_workspace.admin.user_defined_setting.name | The name of the user-defined setting. | keyword |
| google_workspace.admin.verification_method | Related verification method. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings and https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Drive

This is the `drive` dataset.

An example event for `drive` looks as following:

```json
{
    "@timestamp": "2022-05-04T15:04:05.000Z",
    "agent": {
        "ephemeral_id": "afd0c297-d853-427a-96bc-20af38e5b145",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.drive",
        "namespace": "99832",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "add_to_folder",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "created": "2024-08-01T21:55:29.295Z",
        "dataset": "google_workspace.drive",
        "id": "1",
        "ingested": "2024-08-01T21:55:41Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"add_to_folder\",\"parameters\":[{\"boolValue\":false,\"name\":\"billable\"},{\"name\":\"destination_folder_id\",\"value\":\"1234\"},{\"name\":\"destination_folder_title\",\"value\":\"folder title\"},{\"name\":\"doc_id\",\"value\":\"1234\"},{\"name\":\"doc_title\",\"value\":\"document title\"},{\"name\":\"doc_type\",\"value\":\"document\"},{\"name\":\"originating_app_id\",\"value\":\"1234\"},{\"name\":\"owner\",\"value\":\"owner@example.com\"},{\"boolValue\":false,\"name\":\"owner_is_shared_drive\"},{\"boolValue\":true,\"name\":\"primary_event\"},{\"name\":\"visibility\",\"value\":\"people_with_link\"}],\"type\":\"access\"},\"id\":{\"applicationName\":\"drive\",\"customerId\":\"1\",\"time\":\"2022-05-04T15:04:05Z\",\"uniqueQualifier\":1},\"ipAddress\":\"98.235.162.24\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"elastic.com\"}",
        "provider": "drive",
        "type": [
            "change"
        ]
    },
    "file": {
        "name": "document title",
        "owner": "owner",
        "type": "file"
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "drive": {
            "billable": false,
            "destination_folder_id": "1234",
            "destination_folder_title": "folder title",
            "file": {
                "id": "1234",
                "owner": {
                    "email": "owner@example.com",
                    "is_shared_drive": false
                },
                "type": "document"
            },
            "originating_app_id": "1234",
            "primary_event": true,
            "visibility": "people_with_link"
        },
        "event": {
            "type": "access"
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "owner",
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-drive"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.drive.actor_is_collaborator_account | Whether the actor is a collaborator account. | boolean |
| google_workspace.drive.added_role | Added membership role of a user/group in a Team Drive. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.billable | Whether this activity is billable. | boolean |
| google_workspace.drive.destination_folder_id |  | keyword |
| google_workspace.drive.destination_folder_title |  | keyword |
| google_workspace.drive.file.id |  | keyword |
| google_workspace.drive.file.owner.email |  | keyword |
| google_workspace.drive.file.owner.is_shared_drive | Boolean flag denoting whether owner is a shared drive. | boolean |
| google_workspace.drive.file.type | Document Drive type. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.is_encrypted | Whether the file is client-side encrypted. | boolean |
| google_workspace.drive.membership_change_type | Type of change in Team Drive membership of a user/group. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.new_value | When a setting or property of the file changes, the new value for it will appear here. | keyword |
| google_workspace.drive.old_value | When a setting or property of the file changes, the old value for it will appear here. | keyword |
| google_workspace.drive.old_visibility | When visibility changes, this holds the old value. | keyword |
| google_workspace.drive.originating_app_id | The Google Cloud Project ID of the application that performed the action. | keyword |
| google_workspace.drive.owner_is_team_drive | Whether the owner is a Team Drive. | boolean |
| google_workspace.drive.primary_event | Whether this is a primary event. A single user action in Drive may generate several events. | boolean |
| google_workspace.drive.removed_role | Removed membership role of a user/group in a Team Drive. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.shared_drive_id | The unique identifier of the Team Drive. Only populated for for events relating to a Team Drive or item contained inside a Team Drive. | keyword |
| google_workspace.drive.shared_drive_settings_change_type | Type of change in Team Drive settings. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.sheets_import_range_recipient_doc | Doc ID of the recipient of a sheets import range. | keyword |
| google_workspace.drive.source_folder_id |  | keyword |
| google_workspace.drive.source_folder_title |  | keyword |
| google_workspace.drive.target | Target user or group. | keyword |
| google_workspace.drive.target_domain | The domain for which the acccess scope was changed. This can also be the alias all to indicate the access scope was changed for all domains that have visibility for this document. | keyword |
| google_workspace.drive.target_user | The email address of the user or group whose access permissions were changed, or the name of the domain for which access permissions were changed. | keyword |
| google_workspace.drive.visibility | Visibility of target file. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive | keyword |
| google_workspace.drive.visibility_change | When visibility changes, this holds the new overall visibility of the file. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Groups

This is the `groups` dataset.

An example event for `groups` looks as following:

```json
{
    "@timestamp": "2022-05-04T15:04:05.000Z",
    "agent": {
        "ephemeral_id": "786aaf54-461f-4190-adaf-05ab3174ad01",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.groups",
        "namespace": "35359",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "change_acl_permission",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2024-08-01T21:58:26.973Z",
        "dataset": "google_workspace.groups",
        "id": "1",
        "ingested": "2024-08-01T21:58:38Z",
        "kind": "event",
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"change_acl_permission\",\"parameters\":[{\"name\":\"acl_permission\",\"value\":\"can_add_members\"},{\"name\":\"group_email\",\"value\":\"group@example.com\"},{\"multiValue\":[\"managers\",\"members\"],\"name\":\"new_value_repeated\"},{\"multiValue\":[\"managers\"],\"name\":\"old_value_repeated\"}],\"type\":\"acl_change\"},\"id\":{\"applicationName\":\"groups\",\"customerId\":\"1\",\"time\":\"2022-05-04T15:04:05Z\",\"uniqueQualifier\":1},\"ipAddress\":\"98.235.162.24\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"elastic.com\"}",
        "provider": "groups",
        "type": [
            "group",
            "change"
        ]
    },
    "google_workspace": {
        "actor": {
            "type": "USER"
        },
        "event": {
            "type": "acl_change"
        },
        "groups": {
            "acl_permission": "can_add_members",
            "email": "group@example.com",
            "new_value": [
                "managers",
                "members"
            ],
            "old_value": [
                "managers"
            ]
        },
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "elastic.com"
        }
    },
    "group": {
        "domain": "example.com",
        "name": "group"
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "ip": [
            "98.235.162.24"
        ],
        "user": [
            "foo"
        ]
    },
    "source": {
        "as": {
            "number": 7922,
            "organization": {
                "name": "Comcast Cable Communications, Inc."
            }
        },
        "ip": "98.235.162.24",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_workspace-groups"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo",
        "target": {
            "group": {
                "domain": "example.com",
                "name": "group"
            }
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
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.groups.acl_permission | Group permission setting updated. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.email | Group email. | keyword |
| google_workspace.groups.member.email | Member email. | keyword |
| google_workspace.groups.member.role | Member role. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.message.id | SMTP message Id of an email message. Present for moderation events. | keyword |
| google_workspace.groups.message.moderation_action | Message moderation action. Possible values are `approved` and `rejected`. | keyword |
| google_workspace.groups.new_value | New value(s) of the group setting. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.old_value | Old value(s) of the group setting. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.setting | Group setting updated. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.groups.status | A status describing the output of an operation. Possible values are `failed` and `succeeded`. | keyword |
| google_workspace.groups.value | Value of the group setting. For a list of possible values refer to https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups | keyword |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload. More details can be found at https://developers.google.com/admin-sdk/reports/v1/reference/activities/list | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Alert

This is the `alert` dataset.

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2022-07-01T10:49:29.436Z",
    "agent": {
        "ephemeral_id": "245194a8-7787-44f7-ac57-201f8c49a9a0",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.alert",
        "namespace": "62301",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "attachments": {
            "file": {
                "hash": {
                    "sha256": [
                        "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
                        "228b48a56dbc2ecf10393227ac9c9dc943881fd7a55452e12a09107476bef2b2",
                        "5fb1679e08674059b72e271d8902c11a127bb5301b055dc77fa03932ada56a56"
                    ]
                }
            }
        },
        "delivery_timestamp": [
            "2022-07-01T10:38:13.194Z"
        ],
        "message_id": [
            "decedih843@example.com",
            "decedih@example.com"
        ],
        "subject": [
            "Sales",
            "RE: Example salesorderspca JSON request"
        ],
        "to": {
            "address": [
                "example@example.com"
            ]
        }
    },
    "event": {
        "action": "Gmail phishing",
        "agent_id_status": "verified",
        "category": [
            "email",
            "threat",
            "malware"
        ],
        "created": "2024-08-01T21:52:26.588Z",
        "dataset": "google_workspace.alert",
        "end": "2022-07-01T10:47:04.530Z",
        "id": "91840a82-3af0-46d7-95ec-625c1cf0c3f7",
        "ingested": "2024-08-01T21:52:38Z",
        "kind": "alert",
        "original": "{\"alertId\":\"91840a82-3af0-46d7-95ec-625c1cf0c3f7\",\"createTime\":\"2022-07-01T10:49:29.436394Z\",\"customerId\":\"02umwv6u\",\"data\":{\"@type\":\"type.googleapis.com/google.apps.alertcenter.type.MailPhishing\",\"domainId\":{\"customerPrimaryDomain\":\"example.com\"},\"isInternal\":true,\"maliciousEntity\":{\"displayName\":\"string\",\"entity\":{\"displayName\":\"example\",\"emailAddress\":\"example@example.com\"},\"fromHeader\":\"header@example.com\"},\"messages\":[{\"attachmentsSha256Hash\":[\"50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c\",\"228b48a56dbc2ecf10393227ac9c9dc943881fd7a55452e12a09107476bef2b2\"],\"date\":\"2022-07-01T10:38:13.194711Z\",\"md5HashMessageBody\":\"d29343907090dff4cec4a9a0efb80d20\",\"md5HashSubject\":\"a3708f8228384d932237f85980ff8283\",\"messageBodySnippet\":\" hi greetings from sales \",\"messageId\":\"decedih843@example.com\",\"recipient\":\"example@example.com\",\"subjectText\":\"Sales\"},{\"attachmentsSha256Hash\":[\"5fb1679e08674059b72e271d8902c11a127bb5301b055dc77fa03932ada56a56\"],\"md5HashMessageBody\":\"d29343907090dff4cec4a9a0efb80d20\",\"md5HashSubject\":\"a3708f8228384d932237f85980ff8283\",\"messageBodySnippet\":\" hi greetings \",\"messageId\":\"decedih@example.com\",\"recipient\":\"example@example.com\",\"subjectText\":\"RE: Example salesorderspca JSON request\"}],\"systemActionType\":\"NO_OPERATION\"},\"deleted\":false,\"endTime\":\"2022-07-01T10:47:04.530834Z\",\"etag\":\"wF2Ix2DWDv8=\",\"metadata\":{\"alertId\":\"91840a82-3af0-46d7-95ec-625c1cf0c3f7\",\"assignee\":\"example@example.com\",\"customerId\":\"02umwv6u\",\"etag\":\"wF2Ix2DWDv8=\",\"severity\":\"HIGH\",\"status\":\"NOT_STARTED\",\"updateTime\":\"2022-07-01T10:49:29.436394Z\"},\"securityInvestigationToolLink\":\"string\",\"source\":\"Gmail phishing\",\"startTime\":\"2022-07-01T10:38:13.194711Z\",\"type\":\"User reported phishing\",\"updateTime\":\"2022-07-01T10:49:29.436394Z\"}",
        "start": "2022-07-01T10:38:13.194Z",
        "type": [
            "info"
        ]
    },
    "google_workspace": {
        "alert": {
            "create_time": "2022-07-01T10:49:29.436Z",
            "customer": {
                "id": "02umwv6u"
            },
            "data": {
                "domain_id": {
                    "customer_primary_domain": "example.com"
                },
                "is_internal": true,
                "malicious_entity": {
                    "display_name": "string",
                    "entity": {
                        "display_name": "example",
                        "email_address": "example@example.com"
                    },
                    "from_header": "header@example.com"
                },
                "messages": [
                    {
                        "attachments_sha256_hash": [
                            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
                            "228b48a56dbc2ecf10393227ac9c9dc943881fd7a55452e12a09107476bef2b2"
                        ],
                        "date": "2022-07-01T10:38:13.194Z",
                        "id": "decedih843@example.com",
                        "md5": {
                            "hash": {
                                "message_body": "d29343907090dff4cec4a9a0efb80d20",
                                "subject": "a3708f8228384d932237f85980ff8283"
                            }
                        },
                        "message_body_snippet": " hi greetings from sales ",
                        "recipient_email": "example@example.com",
                        "subject_text": "Sales"
                    },
                    {
                        "attachments_sha256_hash": [
                            "5fb1679e08674059b72e271d8902c11a127bb5301b055dc77fa03932ada56a56"
                        ],
                        "id": "decedih@example.com",
                        "md5": {
                            "hash": {
                                "message_body": "d29343907090dff4cec4a9a0efb80d20",
                                "subject": "a3708f8228384d932237f85980ff8283"
                            }
                        },
                        "message_body_snippet": " hi greetings ",
                        "recipient_email": "example@example.com",
                        "subject_text": "RE: Example salesorderspca JSON request"
                    }
                ],
                "system_action_type": "NO_OPERATION",
                "type": "type.googleapis.com/google.apps.alertcenter.type.MailPhishing"
            },
            "deleted": false,
            "end_time": "2022-07-01T10:47:04.530Z",
            "etag": "wF2Ix2DWDv8=",
            "id": "91840a82-3af0-46d7-95ec-625c1cf0c3f7",
            "metadata": {
                "alert": {
                    "id": "91840a82-3af0-46d7-95ec-625c1cf0c3f7"
                },
                "assignee": "example@example.com",
                "customer": {
                    "id": "02umwv6u"
                },
                "etag": "wF2Ix2DWDv8=",
                "severity": "HIGH",
                "status": "NOT_STARTED",
                "update_time": "2022-07-01T10:49:29.436Z"
            },
            "security_investigation_tool_link": "string",
            "source": "Gmail phishing",
            "start_time": "2022-07-01T10:38:13.194Z",
            "type": "User reported phishing",
            "update_time": "2022-07-01T10:49:29.436Z"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "02umwv6u"
    },
    "related": {
        "hash": [
            "a3708f8228384d932237f85980ff8283",
            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
            "228b48a56dbc2ecf10393227ac9c9dc943881fd7a55452e12a09107476bef2b2",
            "5fb1679e08674059b72e271d8902c11a127bb5301b055dc77fa03932ada56a56"
        ],
        "user": [
            "example"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-alert"
    ],
    "user": {
        "domain": "example.com",
        "email": [
            "example@example.com"
        ],
        "name": "example"
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
| google_workspace.alert.create_time | The time this alert was created. | date |
| google_workspace.alert.customer.id | The unique identifier of the Google account of the customer. | keyword |
| google_workspace.alert.data.action.name | List of action names associated with the rule threshold. | keyword |
| google_workspace.alert.data.actor.email | Email of person who performed the action. | keyword |
| google_workspace.alert.data.affected.user_emails | The list of emails which correspond to the users directly affected by the incident. | keyword |
| google_workspace.alert.data.alert_details | alert details of google workspace alert. | keyword |
| google_workspace.alert.data.appeal_window | appeal window of alert. | keyword |
| google_workspace.alert.data.attachment.data.csv.data_rows.entries | The data entries in a CSV file row, as a string array rather than a single comma-separated string. | keyword |
| google_workspace.alert.data.attachment.data.csv.headers | The list of headers for data columns in a CSV file. | keyword |
| google_workspace.alert.data.create_time | Rule create timestamp. | date |
| google_workspace.alert.data.dashboard.uri | Link to the outage event in Google Workspace Status Dashboard. | keyword |
| google_workspace.alert.data.description | A detailed, freeform incident description. | text |
| google_workspace.alert.data.display.name | Alert display name. | keyword |
| google_workspace.alert.data.domain | Customer domain for email template personalization. | keyword |
| google_workspace.alert.data.domain_id.customer_primary_domain | The primary domain for the customer. | keyword |
| google_workspace.alert.data.email | The email of the user that this event belongs to. | keyword |
| google_workspace.alert.data.event_time | The time at which event occurred. | date |
| google_workspace.alert.data.events.device.id | The device ID. | keyword |
| google_workspace.alert.data.events.device.model | The model of the device. | keyword |
| google_workspace.alert.data.events.device.property | The device property which was changed. | keyword |
| google_workspace.alert.data.events.device.type | The type of the device. | keyword |
| google_workspace.alert.data.events.device_compromised_state | The device compromised state. Possible values are "Compromised" or "Not Compromised". | keyword |
| google_workspace.alert.data.events.ios_vendor.id | Required for iOS, empty for others. | keyword |
| google_workspace.alert.data.events.new_value | The new value of the device property after the change. | keyword |
| google_workspace.alert.data.events.old_value | The old value of the device property before the change. | keyword |
| google_workspace.alert.data.events.resource.id | The device resource ID. | keyword |
| google_workspace.alert.data.events.serial.number | The serial number of the device. | keyword |
| google_workspace.alert.data.header | A header to display above the incident message. Typically used to attach a localized notice on the timeline for followup comms translations. | keyword |
| google_workspace.alert.data.incident_tracking.id | Incident tracking ID. | keyword |
| google_workspace.alert.data.is_internal | If true, the email originated from within the organization. | boolean |
| google_workspace.alert.data.login_details.ip_address | The human-readable IP address that is associated with the warning event. | ip |
| google_workspace.alert.data.login_details.login_time | The successful login time that is associated with the warning event. This isn't present for blocked login attempts. | date |
| google_workspace.alert.data.malicious_entity.display_name | The header from display name. | keyword |
| google_workspace.alert.data.malicious_entity.entity.display_name | Display name of the user. | keyword |
| google_workspace.alert.data.malicious_entity.entity.email_address | Email address of the user. | keyword |
| google_workspace.alert.data.malicious_entity.from_header | The sender email address. | keyword |
| google_workspace.alert.data.merge_info.new_alert.id | New alert ID. Reference the `google.apps.alertcenter.Alert` with this ID for the current state. | keyword |
| google_workspace.alert.data.merge_info.new_incident_tracking.id | The new tracking ID from the parent incident. | keyword |
| google_workspace.alert.data.messages.attachments_sha256_hash | The SHA256 hash of email's attachment and all MIME parts. | keyword |
| google_workspace.alert.data.messages.date | The date of the event related to this email. | date |
| google_workspace.alert.data.messages.id | The message ID. | keyword |
| google_workspace.alert.data.messages.md5.hash.message_body | The hash of the message body text. | keyword |
| google_workspace.alert.data.messages.md5.hash.subject | The MD5 Hash of email's subject (only available for reported emails). | keyword |
| google_workspace.alert.data.messages.message_body_snippet | The snippet of the message body text (only available for reported emails). | keyword |
| google_workspace.alert.data.messages.recipient | The recipient of this email. | keyword |
| google_workspace.alert.data.messages.recipient_email |  | keyword |
| google_workspace.alert.data.messages.subject_text | The email subject text (only available for reported emails). | keyword |
| google_workspace.alert.data.name | Rule name. | keyword |
| google_workspace.alert.data.next_update_time | Timestamp by which the next update is expected to arrive. | date |
| google_workspace.alert.data.primary.admin.changed_event.domain | domain in which actioned occurred. | keyword |
| google_workspace.alert.data.primary.admin.changed_event.previous_admin_email | Email of person who was the primary admin before the action. | keyword |
| google_workspace.alert.data.primary.admin.changed_event.updated_admin_email | Email of person who is the primary admin after the action. | keyword |
| google_workspace.alert.data.products | List of products impacted by the outage. | keyword |
| google_workspace.alert.data.query | Query that is used to get the data from the associated source. | keyword |
| google_workspace.alert.data.request.info.app.developer_email | List of app developers who triggered notifications for above application. | keyword |
| google_workspace.alert.data.request.info.app.key | The application that requires the SQL setup. | keyword |
| google_workspace.alert.data.request.info.number_of_requests | Number of requests sent for this application to set up default SQL instance. | keyword |
| google_workspace.alert.data.resolution_time | Timestamp when the outage is expected to be resolved, or has confirmed resolution. Provided only when known. | date |
| google_workspace.alert.data.rule.violation_info.data.source | Source of the data. | keyword |
| google_workspace.alert.data.rule.violation_info.match_info.predefined_detector.name | Name that uniquely identifies the detector. | keyword |
| google_workspace.alert.data.rule.violation_info.match_info.user_defined_detector.display.name | Display name of the detector. | keyword |
| google_workspace.alert.data.rule.violation_info.match_info.user_defined_detector.resource.name | Resource name that uniquely identifies the detector. | keyword |
| google_workspace.alert.data.rule.violation_info.recipients | For Drive, they are grantees that the Drive file was shared with at the time of rule triggering. Valid values include user emails, group emails, domains, or 'anyone' if the file was publicly accessible. If the file was private the recipients list will be empty. For Gmail, they are emails of the users or groups that the Gmail message was sent to. | keyword |
| google_workspace.alert.data.rule.violation_info.resource_info.document.id | Drive file ID. | keyword |
| google_workspace.alert.data.rule.violation_info.resource_info.resource.title | Title of the resource, for example email subject, or document title. | keyword |
| google_workspace.alert.data.rule.violation_info.rule_info.display.name | User provided name of the rule. | keyword |
| google_workspace.alert.data.rule.violation_info.rule_info.resource.name | Resource name that uniquely identifies the rule. | keyword |
| google_workspace.alert.data.rule.violation_info.suppressed.action.types | Actions suppressed due to other actions with higher priority. | keyword |
| google_workspace.alert.data.rule.violation_info.trigger.user.email | Email of the user who caused the violation. Value could be empty if not applicable, for example, a violation found by drive continuous scan. | keyword |
| google_workspace.alert.data.rule.violation_info.trigger.value | Trigger of the rule. | keyword |
| google_workspace.alert.data.rule.violation_info.triggered.action.info.object |  | keyword |
| google_workspace.alert.data.rule.violation_info.triggered.action.types | Actions applied as a consequence of the rule being triggered. | keyword |
| google_workspace.alert.data.rule_description | Description of the rule. | text |
| google_workspace.alert.data.source.ip | The source IP address of the malicious email. | ip |
| google_workspace.alert.data.sso_profile.created_event.inbound_sso.profile_name | sso profile name which got created. | keyword |
| google_workspace.alert.data.sso_profile.deleted_event.inbound_sso.profile_name | sso profile name which got deleted. | keyword |
| google_workspace.alert.data.sso_profile.updated_event.inbound_sso.profile_changes | changes made to sso profile. | keyword |
| google_workspace.alert.data.sso_profile.updated_event.inbound_sso.profile_name | sso profile name which got updated. | keyword |
| google_workspace.alert.data.state | state of alert. | keyword |
| google_workspace.alert.data.status | Current outage status. | keyword |
| google_workspace.alert.data.super_admin_password_reset_event.user.email | email of person whose password was reset. | keyword |
| google_workspace.alert.data.superseded_alerts | List of alert IDs superseded by this alert. It is used to indicate that this alert is essentially extension of superseded alerts and we found the relationship after creating these alerts. | keyword |
| google_workspace.alert.data.superseding_alert | Alert ID superseding this alert. It is used to indicate that superseding alert is essentially extension of this alert and we found the relationship after creating both alerts. | keyword |
| google_workspace.alert.data.suspension_details.abuse_reason | abuse reason for suspension details. | keyword |
| google_workspace.alert.data.suspension_details.product_name | product name for suspension details. | keyword |
| google_workspace.alert.data.system_action_type | System actions on the messages. | keyword |
| google_workspace.alert.data.takeout.request.id | The takeout request ID. | keyword |
| google_workspace.alert.data.threshold | Alert threshold is for example “COUNT \> 5”. | keyword |
| google_workspace.alert.data.title | A one-line incident description. | keyword |
| google_workspace.alert.data.trigger.source | The trigger sources for this rule. | keyword |
| google_workspace.alert.data.type | The type of the alert with alert data. | keyword |
| google_workspace.alert.data.update_time | The timestamp of the last update to the rule. | date |
| google_workspace.alert.data.window_size | Rule window size. Possible values are 1 hour or 24 hours. | keyword |
| google_workspace.alert.deleted | True if this alert is marked for deletion. | boolean |
| google_workspace.alert.end_time | The time the event that caused this alert ceased being active. If provided, the end time must not be earlier than the start time. If not provided, it indicates an ongoing alert. | date |
| google_workspace.alert.etag | etag is used for optimistic concurrency control as a way to help prevent simultaneous updates of an alert from overwriting each other. | keyword |
| google_workspace.alert.id | The unique identifier for the alert. | keyword |
| google_workspace.alert.metadata.alert.id | The alert identifier. | keyword |
| google_workspace.alert.metadata.assignee | The email address of the user assigned to the alert. | keyword |
| google_workspace.alert.metadata.customer.id | The unique identifier of the Google account of the customer. | keyword |
| google_workspace.alert.metadata.etag | etag is used for optimistic concurrency control as a way to help prevent simultaneous updates of an alert metadata from overwriting each other. | keyword |
| google_workspace.alert.metadata.severity | The severity value of the alert. Alert Center will set this field at alert creation time, default's to an empty string when it could not be determined. | keyword |
| google_workspace.alert.metadata.status | The current status of the alert. | keyword |
| google_workspace.alert.metadata.update_time | The time this metadata was last updated. | date |
| google_workspace.alert.security_investigation_tool_link | An optional Security Investigation Tool query for this alert. | keyword |
| google_workspace.alert.source | A unique identifier for the system that reported the alert. This is output only after alert is created. | keyword |
| google_workspace.alert.start_time | The time the event that caused this alert was started or detected. | date |
| google_workspace.alert.type | The type of the alert. This is output only after alert is created. | keyword |
| google_workspace.alert.update_time | The time this alert was last updated. | date |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### Device

This is the `device` dataset.

An example event for `device` looks as following:

```json
{
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "9875ab07-088d-4ff3-8cfe-daa3a497cf78",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.device",
        "namespace": "89096",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "APPLICATION_EVENT",
        "agent_id_status": "verified",
        "created": "2024-08-01T21:54:32.984Z",
        "dataset": "google_workspace.device",
        "id": "1",
        "ingested": "2024-08-01T21:54:44Z",
        "kind": [
            "event"
        ],
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"APPLICATION_EVENT\",\"parameters\":[{\"name\":\"ACCOUNT_STATE\",\"value\":\"REGISTERED\"},{\"name\":\"ACTION_EXECUTION_STATUS\",\"value\":\"ACTION_REJECTED_BY_USER\"},{\"name\":\"ACTION_ID\",\"value\":\"asd1234\"},{\"name\":\"ACTION_TYPE\",\"value\":\"ACCOUNT_WIPE\"},{\"name\":\"APK_SHA256_HASH\",\"value\":\"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf\"},{\"name\":\"APPLICATION_ID\",\"value\":\"af2bdbe1aa9f\"},{\"name\":\"APPLICATION_MESSAGE\",\"value\":\"message\"},{\"name\":\"APPLICATION_REPORT_KEY\",\"value\":\"sda21\"},{\"name\":\"APPLICATION_REPORT_SEVERITY\",\"value\":\"ERROR\"},{\"name\":\"APPLICATION_REPORT_TIMESTAMP\",\"value\":\"2020-10-03T15:00:00Z\"},{\"name\":\"APPLICATION_STATE\",\"value\":\"INSTALLED\"},{\"name\":\"BASIC_INTEGRITY\",\"value\":\"integrity\"},{\"name\":\"CTS_PROFILE_MATCH\",\"value\":\"profile\"},{\"name\":\"DEVICE_COMPLIANCE\",\"value\":\"COMPLIANT\"},{\"name\":\"DEVICE_COMPROMISED_STATE\",\"value\":\"COMPROMISED\"},{\"name\":\"DEVICE_DEACTIVATION_REASON\",\"value\":\"CAMERA_NOT_DISABLED\"},{\"name\":\"DEVICE_ID\",\"value\":\"asdqwe12e\"},{\"name\":\"DEVICE_MODEL\",\"value\":\"model\"},{\"name\":\"DEVICE_OWNERSHIP\",\"value\":\"COMPANY_OWNED\"},{\"name\":\"DEVICE_PROPERTY\",\"value\":\"BASIC_INTEGRITY\"},{\"name\":\"DEVICE_SETTING\",\"value\":\"DEVELOPER_OPTIONS\"},{\"name\":\"DEVICE_STATUS_ON_APPLE_PORTAL\",\"value\":\"ADDED\"},{\"name\":\"DEVICE_TYPE\",\"value\":\"ANDROID\"},{\"name\":\"FAILED_PASSWD_ATTEMPTS\",\"value\":20},{\"name\":\"IOS_VENDOR_ID\",\"value\":\"asfdwer23\"},{\"name\":\"NEW_DEVICE_ID\",\"value\":\"asfwr5tg\"},{\"name\":\"NEW_VALUE\",\"value\":\"DEVICE_ADMINISTRATOR\"},{\"name\":\"OLD_VALUE\",\"value\":\"DEVICE_OWNER\"},{\"name\":\"OS_EDITION\",\"value\":\"edition\"},{\"name\":\"OS_PROPERTY\",\"value\":\"property\"},{\"name\":\"OS_VERSION\",\"value\":\"os11\"},{\"name\":\"PHA_CATEGORY\",\"value\":\"BACKDOOR\"},{\"name\":\"POLICY_NAME\",\"value\":\"policy name\"},{\"name\":\"POLICY_SYNC_RESULT\",\"value\":\"POLICY_SYNC_ABORTED\"},{\"name\":\"POLICY_SYNC_TYPE\",\"value\":\"POLICY_APPLIED_TYPE\"},{\"name\":\"REGISTER_PRIVILEGE\",\"value\":\"DEVICE_OWNER\"},{\"name\":\"RESOURCE_ID\",\"value\":\"sads324\"},{\"name\":\"RISK_SIGNAL\",\"value\":\"BASIC_INTEGRITY\"},{\"name\":\"SECURITY_EVENT_ID\",\"value\":2323523},{\"name\":\"SECURITY_PATCH_LEVEL\",\"value\":\"patch level\"},{\"name\":\"SERIAL_NUMBER\",\"value\":\"asdsad1234\"},{\"name\":\"USER_EMAIL\",\"value\":\"user@foo.com\"},{\"name\":\"VALUE\",\"value\":\"value\"},{\"name\":\"WINDOWS_SYNCML_POLICY_STATUS_CODE\",\"value\":\"200\"}],\"type\":\"device_applications\"},\"id\":{\"applicationName\":\"device\",\"customerId\":\"1\",\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"example.com\"}",
        "provider": "device"
    },
    "google_workspace": {
        "actor": {
            "email": "foo@bar.com",
            "profile": {
                "id": "1"
            },
            "type": "USER"
        },
        "device": {
            "account_state": "REGISTERED",
            "action": {
                "execution_status": "ACTION_REJECTED_BY_USER",
                "id": "asd1234",
                "type": "ACCOUNT_WIPE"
            },
            "apk_sha256_hash": "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
            "application": {
                "id": "af2bdbe1aa9f",
                "message": "message",
                "report": {
                    "key": "sda21",
                    "severity": "ERROR",
                    "timestamp": "2020-10-03T15:00:00.000Z"
                },
                "state": "INSTALLED"
            },
            "basic_integrity": "integrity",
            "compliance": "COMPLIANT",
            "compromised_state": "COMPROMISED",
            "cts_profile_match": "profile",
            "deactivation_reason": "CAMERA_NOT_DISABLED",
            "failed_passwd_attempts": 20,
            "id": "asdqwe12e",
            "ios_vendor_id": "asfdwer23",
            "model": "model",
            "new_device_id": "asfwr5tg",
            "new_value": "DEVICE_ADMINISTRATOR",
            "old_value": "DEVICE_OWNER",
            "os": {
                "edition": "edition",
                "property": "property",
                "version": "os11"
            },
            "ownership": "COMPANY_OWNED",
            "pha_category": "BACKDOOR",
            "policy": {
                "name": "policy name",
                "sync": {
                    "result": "POLICY_SYNC_ABORTED",
                    "type": "POLICY_APPLIED_TYPE"
                }
            },
            "property": "BASIC_INTEGRITY",
            "register_privilege": "DEVICE_OWNER",
            "resource": {
                "id": "sads324"
            },
            "risk_signal": "BASIC_INTEGRITY",
            "security": {
                "event_id": 2323523,
                "patch_level": "patch level"
            },
            "serial_number": "asdsad1234",
            "setting": "DEVELOPER_OPTIONS",
            "status_on_apple_portal": "ADDED",
            "type": "ANDROID",
            "user_email": "user@foo.com",
            "value": "value",
            "windows_syncml_policy_status_code": "200"
        },
        "event": {
            "name": "APPLICATION_EVENT",
            "type": "device_applications"
        },
        "id": {
            "application_name": "device",
            "customer": {
                "id": "1"
            },
            "time": "2020-10-02T15:00:00.000Z",
            "unique_qualifier": "1"
        },
        "ip_address": "67.43.156.13",
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "example.com"
        }
    },
    "host": {
        "os": {
            "version": "os11"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "hash": [
            "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
        ],
        "hosts": [
            "bar.com",
            "example.com"
        ],
        "ip": [
            "67.43.156.13"
        ],
        "user": [
            "1",
            "foo",
            "foo@bar.com",
            "user@foo.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-device"
    ],
    "user": {
        "domain": "bar.com",
        "email": [
            "foo@bar.com",
            "user@foo.com"
        ],
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile.id | The unique Google Workspace profile ID of the actor. This value might be absent if the actor is not a Google Workspace user, or may be the number 105250506097979753968 which acts as a placeholder ID. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.device.account_state | Parameter to indicate the account state on the device. | keyword |
| google_workspace.device.action.execution_status | The execution status of an action. | keyword |
| google_workspace.device.action.id | Unique identifier for an action. | keyword |
| google_workspace.device.action.type | The type of an action. | keyword |
| google_workspace.device.apk_sha256_hash | Parameter to indicate the SHA-256 hash of an application. | keyword |
| google_workspace.device.application.id | Parameter to indicate the Application Id. | keyword |
| google_workspace.device.application.message | Parameter to indicate the message sent by an application report. | keyword |
| google_workspace.device.application.report.key | Parameter to indicate the key of an application message. | keyword |
| google_workspace.device.application.report.severity | Parameter to indicate the severity of a report. | keyword |
| google_workspace.device.application.report.timestamp | Parameter to indicate the timestamp of a report. | date |
| google_workspace.device.application.state | Parameter to indicate the application install/uninstall/update done on device. | keyword |
| google_workspace.device.basic_integrity | Parameter to indicate whether the device passes the basic integrity check. | keyword |
| google_workspace.device.compliance | Parameter to indicate the device compliance state with set policies. | keyword |
| google_workspace.device.compromised_state | Parameter to indicate the compromised state of device. | keyword |
| google_workspace.device.cts_profile_match | Parameter to indicate whether the device passes the CTS profile match. | keyword |
| google_workspace.device.deactivation_reason | Parameter to indicate the reason for the deactivation of the mobile device | keyword |
| google_workspace.device.failed_passwd_attempts | Parameter to indicate the number of failed screen unlock attempts. | long |
| google_workspace.device.id | Parameter to indicate the Device Id. | keyword |
| google_workspace.device.ios_vendor_id | Parameter to indicate the iOS Vendor Id. | keyword |
| google_workspace.device.model | Parameter to indicate the device model. | keyword |
| google_workspace.device.new_device_id | Parameter to indicate the new Device Id. | keyword |
| google_workspace.device.new_value | Parameter to indicate the new value. | keyword |
| google_workspace.device.old_value | Parameter to indicate the old value. | keyword |
| google_workspace.device.os.edition | Parameter to indicate the Windows OS edition. | keyword |
| google_workspace.device.os.property | Parameter to indicate OS Property. | keyword |
| google_workspace.device.os.version | Parameter to indicate the OS version. | keyword |
| google_workspace.device.ownership | Parameter to indicate the ownership of mobile device. | keyword |
| google_workspace.device.pha_category | Potentially harmful app category reported by SafetyNet. | keyword |
| google_workspace.device.policy.name | Parameter to indicate the policy name. | keyword |
| google_workspace.device.policy.sync.result | Parameter to indicate the policy status. | keyword |
| google_workspace.device.policy.sync.type | Parameter to indicate the policy sync type. | keyword |
| google_workspace.device.property | Parameter to indicate the changed device property. | keyword |
| google_workspace.device.register_privilege | Parameter to indicate Device Policy app's privilege on the user's device. | keyword |
| google_workspace.device.resource.id | Parameter to indicate the unique resource id of a device. | keyword |
| google_workspace.device.risk_signal | Parameter to indicate the risk signal, e.g. CTS profile match. | keyword |
| google_workspace.device.security.event_id | Security event id. | long |
| google_workspace.device.security.patch_level | Parameter to indicate the security patch Level. | keyword |
| google_workspace.device.serial_number | Parameter to indicate the Serial number. | keyword |
| google_workspace.device.setting | Parameter to indicate device settings. | keyword |
| google_workspace.device.status_on_apple_portal | Parameter to indicate the device status on Apple portal. | keyword |
| google_workspace.device.type | Parameter to indicate the device type. | keyword |
| google_workspace.device.user_email | Parameter to indicate the User email. | keyword |
| google_workspace.device.value | Parameter to indicate the value of a field. | keyword |
| google_workspace.device.windows_syncml_policy_status_code | Parameter to indicate the policy status code. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.event.name | Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific Google Workspace service or feature which the API organizes into types of events. For eventName request parameters in general:   If no eventName is given, the report returns all possible instances of an eventName.   When you request an eventName, the API's response returns all activities which contain that eventName. It is possible that the returned activities will have other eventName properties in addition to the one requested. For more information about eventName properties, see the list of event names for various applications above in applicationName. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer.id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Group Enterprise

This is the `group_enterprise` dataset.

An example event for `group_enterprise` looks as following:

```json
{
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "9405bd92-9ad6-4271-9f8f-10d1dc3bae86",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.group_enterprise",
        "namespace": "26916",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "add_info_setting",
        "agent_id_status": "verified",
        "created": "2024-08-01T21:57:32.529Z",
        "dataset": "google_workspace.group_enterprise",
        "id": "1",
        "ingested": "2024-08-01T21:57:44Z",
        "kind": [
            "event"
        ],
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"add_info_setting\",\"parameters\":[{\"name\":\"dynamic_group_query\",\"value\":\"query\"},{\"name\":\"group_id\",\"value\":\"asd123d\"},{\"name\":\"info_setting\",\"value\":\"setting\"},{\"name\":\"member_id\",\"value\":\"mem12w3\"},{\"name\":\"member_role\",\"value\":\"owner\"},{\"name\":\"member_type\",\"value\":\"user\"},{\"name\":\"membership_expiry\",\"value\":\"2020-10-02T15:00:00Z\"},{\"name\":\"namespace\",\"value\":\"namespace\"},{\"name\":\"new_value\",\"value\":\"new\"},{\"name\":\"old_value\",\"value\":\"old\"},{\"name\":\"security_setting\",\"value\":\"group setting\"},{\"name\":\"security_setting_state\",\"value\":\"group setting state\"},{\"name\":\"value\",\"value\":\"group setting value\"}],\"type\":\"moderator_action\"},\"id\":{\"applicationName\":\"group_enterprise\",\"customerId\":\"1\",\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"example.com\"}",
        "provider": "group_enterprise"
    },
    "google_workspace": {
        "actor": {
            "email": "foo@bar.com",
            "profile": {
                "id": "1"
            },
            "type": "USER"
        },
        "event": {
            "name": "add_info_setting",
            "type": "moderator_action"
        },
        "group_enterprise": {
            "dynamic_group_query": "query",
            "group": {
                "id": "asd123d"
            },
            "info_setting": "setting",
            "member": {
                "id": "mem12w3",
                "role": "owner",
                "type": "user"
            },
            "membership_expiry": "2020-10-02T15:00:00.000Z",
            "namespace": "namespace",
            "new_value": "new",
            "old_value": "old",
            "security_setting": {
                "state": "group setting state",
                "value": "group setting"
            },
            "value": "group setting value"
        },
        "id": {
            "application_name": "group_enterprise",
            "customer": {
                "id": "1"
            },
            "time": "2020-10-02T15:00:00.000Z",
            "unique_qualifier": "1"
        },
        "ip_address": "67.43.156.13",
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "example.com"
        }
    },
    "group": {
        "id": "asd123d"
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "hosts": [
            "bar.com",
            "example.com"
        ],
        "ip": [
            "67.43.156.13"
        ],
        "user": [
            "1",
            "foo",
            "foo@bar.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-group_enterprise"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile.id | The unique Google Workspace profile ID of the actor. This value might be absent if the actor is not a Google Workspace user, or may be the number 105250506097979753968 which acts as a placeholder ID. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.event.name | Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific Google Workspace service or feature which the API organizes into types of events. For eventName request parameters in general:   If no eventName is given, the report returns all possible instances of an eventName.   When you request an eventName, the API's response returns all activities which contain that eventName. It is possible that the returned activities will have other eventName properties in addition to the one requested. For more information about eventName properties, see the list of event names for various applications above in applicationName. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.group_enterprise.dynamic_group_query | Dynamic group query. | keyword |
| google_workspace.group_enterprise.group.id | Identifier of the target group. | keyword |
| google_workspace.group_enterprise.info_setting | Group info setting. | keyword |
| google_workspace.group_enterprise.member.id | Identifier of the member. | keyword |
| google_workspace.group_enterprise.member.role | The role assigned to the member in the context of the group, such as owner, manager, or member. | keyword |
| google_workspace.group_enterprise.member.type | A member's type, such as user, group, or service account. In rare cases, a value of "other" appears when the member type is unknown. | keyword |
| google_workspace.group_enterprise.membership_expiry | Membership expiration time. | date |
| google_workspace.group_enterprise.namespace | Namespace of the target group. | keyword |
| google_workspace.group_enterprise.new_value | New value of a group setting. | keyword |
| google_workspace.group_enterprise.old_value | Old value of a group setting. | keyword |
| google_workspace.group_enterprise.security_setting.state | Group security setting. | keyword |
| google_workspace.group_enterprise.security_setting.value | Group security setting state. | keyword |
| google_workspace.group_enterprise.value | Value of a group setting. | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer.id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Token

This is the `token` dataset.

An example event for `token` looks as following:

```json
{
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "22e6154c-9c10-4cb9-b17b-41f429c22724",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.token",
        "namespace": "16418",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "authorize",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2024-08-01T22:03:00.693Z",
        "dataset": "google_workspace.token",
        "id": "1",
        "ingested": "2024-08-01T22:03:12Z",
        "kind": [
            "event"
        ],
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"authorize\",\"parameters\":[{\"name\":\"client_id\",\"value\":\"923474483785-sqf6uk8vq1rqe853il0g2h4m98ji2fq6.apps.googleusercontent.com\"},{\"name\":\"app_name\",\"value\":\"Gmail Add-on\"},{\"name\":\"api_name\",\"value\":\"token\"},{\"name\":\"method_name\",\"value\":\"oauth\"},{\"name\":\"num_response_bytes\",\"value\":1223},{\"name\":\"client_type\",\"value\":\"WEB\"},{\"multiMessageValue\":[{\"parameter\":[{\"name\":\"scope_name\",\"value\":\"https://www.googleapis.com/auth/gmail.addons.current.message.readonly\"},{\"multiValue\":[\"GMAIL\"],\"name\":\"product_bucket\"}]},{\"parameter\":[{\"name\":\"scope_name\",\"value\":\"https://www.googleapis.com/auth/gmail.addons.execute\"},{\"multiValue\":[\"GMAIL\"],\"name\":\"product_bucket\"}]},{\"parameter\":[{\"name\":\"scope_name\",\"value\":\"https://www.googleapis.com/auth/script.external_request\"},{\"multiValue\":[\"APPS_SCRIPT_RUNTIME\"],\"name\":\"product_bucket\"}]},{\"parameter\":[{\"name\":\"scope_name\",\"value\":\"https://www.googleapis.com/auth/script.storage\"},{\"multiValue\":[\"APPS_SCRIPT_RUNTIME\"],\"name\":\"product_bucket\"}]},{\"parameter\":[{\"name\":\"scope_name\",\"value\":\"https://www.googleapis.com/auth/userinfo.email\"},{\"multiValue\":[\"IDENTITY\",\"OTHER\"],\"name\":\"product_bucket\"}]}],\"name\":\"scope_data\"},{\"multiValue\":[\"https://www.googleapis.com/auth/gmail.addons.current.message.readonly\",\"https://www.googleapis.com/auth/gmail.addons.execute\",\"https://www.googleapis.com/auth/script.external_request\",\"https://www.googleapis.com/auth/script.storage\",\"https://www.googleapis.com/auth/userinfo.email\"],\"name\":\"scope\"}]},\"id\":{\"applicationName\":\"token\",\"customerId\":\"1\",\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"example.com\"}",
        "provider": "token",
        "type": [
            "info",
            "user"
        ]
    },
    "google_workspace": {
        "actor": {
            "email": "foo@bar.com",
            "profile": {
                "id": "1"
            },
            "type": "USER"
        },
        "event": {
            "name": "authorize"
        },
        "id": {
            "application_name": "token",
            "customer": {
                "id": "1"
            },
            "time": "2020-10-02T15:00:00.000Z",
            "unique_qualifier": "1"
        },
        "ip_address": "67.43.156.13",
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "example.com"
        },
        "token": {
            "api_name": "token",
            "app_name": "Gmail Add-on",
            "client": {
                "id": "923474483785-sqf6uk8vq1rqe853il0g2h4m98ji2fq6.apps.googleusercontent.com",
                "type": "WEB"
            },
            "method_name": "oauth",
            "num_response_bytes": 1223,
            "scope": {
                "data": [
                    {
                        "product_bucket": [
                            "GMAIL"
                        ],
                        "scope_name": "https://www.googleapis.com/auth/gmail.addons.current.message.readonly"
                    },
                    {
                        "product_bucket": [
                            "GMAIL"
                        ],
                        "scope_name": "https://www.googleapis.com/auth/gmail.addons.execute"
                    },
                    {
                        "product_bucket": [
                            "APPS_SCRIPT_RUNTIME"
                        ],
                        "scope_name": "https://www.googleapis.com/auth/script.external_request"
                    },
                    {
                        "product_bucket": [
                            "APPS_SCRIPT_RUNTIME"
                        ],
                        "scope_name": "https://www.googleapis.com/auth/script.storage"
                    },
                    {
                        "product_bucket": [
                            "IDENTITY",
                            "OTHER"
                        ],
                        "scope_name": "https://www.googleapis.com/auth/userinfo.email"
                    }
                ],
                "value": [
                    "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
                    "https://www.googleapis.com/auth/gmail.addons.execute",
                    "https://www.googleapis.com/auth/script.external_request",
                    "https://www.googleapis.com/auth/script.storage",
                    "https://www.googleapis.com/auth/userinfo.email"
                ]
            }
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "hosts": [
            "bar.com",
            "example.com"
        ],
        "ip": [
            "67.43.156.13"
        ],
        "user": [
            "1",
            "foo",
            "foo@bar.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-token"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile.id | The unique Google Workspace profile ID of the actor. This value might be absent if the actor is not a Google Workspace user, or may be the number 105250506097979753968 which acts as a placeholder ID. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.event.name | Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific Google Workspace service or feature which the API organizes into types of events. For eventName request parameters in general:   If no eventName is given, the report returns all possible instances of an eventName.   When you request an eventName, the API's response returns all activities which contain that eventName. It is possible that the returned activities will have other eventName properties in addition to the one requested. For more information about eventName properties, see the list of event names for various applications above in applicationName. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer.id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| google_workspace.token.api_name | The API name which was used in the OAuth Activity. | keyword |
| google_workspace.token.app_name | The application for which access was granted or revoked. | keyword |
| google_workspace.token.client.id | Client ID to which access has been granted / revoked. | keyword |
| google_workspace.token.client.type | The client type. | keyword |
| google_workspace.token.method_name | The method name which was used in the OAuth Activity. | keyword |
| google_workspace.token.num_response_bytes | The number of response bytes in the OAuth Activity. | long |
| google_workspace.token.scope.data | Scope Data. | flattened |
| google_workspace.token.scope.value | Scopes under which access was granted / revoked. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Access Transparency

This is the `access_transparency` dataset.

An example event for `access_transparency` looks as following:

```json
{
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "e3f2296a-a4a2-4d03-9105-cee5b37c1408",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.access_transparency",
        "namespace": "83912",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "APPLICATION_EVENT",
        "agent_id_status": "verified",
        "created": "2024-08-01T21:50:19.274Z",
        "dataset": "google_workspace.access_transparency",
        "id": "1",
        "ingested": "2024-08-01T21:50:31Z",
        "kind": [
            "event"
        ],
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"APPLICATION_EVENT\",\"parameters\":[{\"name\":\"ACCESS_APPROVAL_ALERT_CENTER_IDS\",\"value\":\"alert123\"},{\"name\":\"ACCESS_APPROVAL_REQUEST_IDS\",\"value\":\"req12341\"},{\"name\":\"ACCESS_MANAGEMENT_POLICY\",\"value\":\"policy\"},{\"name\":\"ACTOR_HOME_OFFICE\",\"value\":\"actoroffice\"},{\"name\":\"GSUITE_PRODUCT_NAME\",\"value\":\"CALENDAR\"},{\"name\":\"JUSTIFICATIONS\",\"value\":\"justfy\"},{\"name\":\"LOG_ID\",\"value\":\"lg651667\"},{\"name\":\"ON_BEHALF_OF\",\"value\":\"example@example.com\"},{\"name\":\"OWNER_EMAIL\",\"value\":\"foo@example.com\"},{\"name\":\"RESOURCE_NAME\",\"value\":\"foo\"},{\"name\":\"TICKETS\",\"value\":\"ticket\"}],\"type\":\"device_applications\"},\"id\":{\"applicationName\":\"device\",\"customerId\":\"1\",\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"example.com\"}",
        "provider": "device"
    },
    "google_workspace": {
        "access_transparency": {
            "access_approval": {
                "alert_center_ids": "alert123",
                "request_ids": "req12341"
            },
            "access_management": {
                "policy": "policy"
            },
            "actor_home_office": "actoroffice",
            "gsuite_product_name": "CALENDAR",
            "justifications": "justfy",
            "log_id": "lg651667",
            "on_behalf_of": "example@example.com",
            "owner_email": "foo@example.com",
            "resource_name": "foo",
            "tickets": "ticket"
        },
        "actor": {
            "email": "foo@bar.com",
            "profile": {
                "id": "1"
            },
            "type": "USER"
        },
        "event": {
            "name": "APPLICATION_EVENT",
            "type": "device_applications"
        },
        "id": {
            "application_name": "device",
            "customer": {
                "id": "1"
            },
            "time": "2020-10-02T15:00:00.000Z",
            "unique_qualifier": "1"
        },
        "ip_address": "67.43.156.13",
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "example.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "hosts": [
            "bar.com",
            "example.com"
        ],
        "ip": [
            "67.43.156.13"
        ],
        "user": [
            "1",
            "foo",
            "foo@bar.com",
            "foo@example.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-access_transparency"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.access_transparency.access_approval.alert_center_ids | Parameter for the Access Approval Alert Center IDs. | keyword |
| google_workspace.access_transparency.access_approval.request_ids | Parameter for the Access Approval ticket IDs. | keyword |
| google_workspace.access_transparency.access_management.policy | Parameter for the Access Management Policy. | keyword |
| google_workspace.access_transparency.actor_home_office | The home office of the actor who performed the data access. | keyword |
| google_workspace.access_transparency.gsuite_product_name | Google Workspace product name. | keyword |
| google_workspace.access_transparency.justifications | Access justifications, such as "Customer Initiated Support - Case Number: 12345678". | keyword |
| google_workspace.access_transparency.log_id | Unique log ID. | keyword |
| google_workspace.access_transparency.on_behalf_of | Parameter for the resource sharee email(s). | keyword |
| google_workspace.access_transparency.owner_email | The email ID or team identifier of the customer who owns the resource. | keyword |
| google_workspace.access_transparency.resource_name | Name of the resource that was accessed. | keyword |
| google_workspace.access_transparency.tickets | Parameter for tickets. | keyword |
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile.id | The unique Google Workspace profile ID of the actor. This value might be absent if the actor is not a Google Workspace user, or may be the number 105250506097979753968 which acts as a placeholder ID. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.event.name | Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific Google Workspace service or feature which the API organizes into types of events. For eventName request parameters in general:   If no eventName is given, the report returns all possible instances of an eventName.   When you request an eventName, the API's response returns all activities which contain that eventName. It is possible that the returned activities will have other eventName properties in addition to the one requested. For more information about eventName properties, see the list of event names for various applications above in applicationName. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer.id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Context Aware Access

This is the `context_aware_access` dataset.

An example event for `context_aware_access` looks as following:

```json
{
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "6fde0a21-1448-4531-a5c9-42751772e3a7",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.context_aware_access",
        "namespace": "14973",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "APPLICATION_EVENT",
        "agent_id_status": "verified",
        "created": "2024-08-01T21:53:36.823Z",
        "dataset": "google_workspace.context_aware_access",
        "id": "1",
        "ingested": "2024-08-01T21:53:48Z",
        "kind": [
            "event"
        ],
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"APPLICATION_EVENT\",\"parameters\":[{\"name\":\"CAA_ACCESS_LEVEL_APPLIED\",\"value\":\"applied\"},{\"name\":\"CAA_ACCESS_LEVEL_SATISFIED\",\"value\":\"satisfied\"},{\"name\":\"CAA_ACCESS_LEVEL_UNSATISFIED\",\"value\":\"unsatisfied\"},{\"name\":\"CAA_APPLICATION\",\"value\":\"app\"},{\"name\":\"CAA_DEVICE_ID\",\"value\":\"devic423\"},{\"name\":\"CAA_DEVICE_STATE\",\"value\":\"devstate\"}],\"type\":\"device_applications\"},\"id\":{\"applicationName\":\"device\",\"customerId\":\"1\",\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"example.com\"}",
        "provider": "device"
    },
    "google_workspace": {
        "actor": {
            "email": "foo@bar.com",
            "profile": {
                "id": "1"
            },
            "type": "USER"
        },
        "context_aware_access": {
            "access_level": {
                "applied": "applied",
                "satisfied": "satisfied",
                "unsatisfied": "unsatisfied"
            },
            "application": "app",
            "device": {
                "id": "devic423",
                "state": "devstate"
            }
        },
        "event": {
            "name": "APPLICATION_EVENT",
            "type": "device_applications"
        },
        "id": {
            "application_name": "device",
            "customer": {
                "id": "1"
            },
            "time": "2020-10-02T15:00:00.000Z",
            "unique_qualifier": "1"
        },
        "ip_address": "67.43.156.13",
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "example.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "hosts": [
            "bar.com",
            "example.com"
        ],
        "ip": [
            "67.43.156.13"
        ],
        "user": [
            "1",
            "foo",
            "foo@bar.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-context_aware_access"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile.id | The unique Google Workspace profile ID of the actor. This value might be absent if the actor is not a Google Workspace user, or may be the number 105250506097979753968 which acts as a placeholder ID. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.context_aware_access.access_level.applied | Display name of Access level applied. | keyword |
| google_workspace.context_aware_access.access_level.satisfied | Display name of Access level satisfied. | keyword |
| google_workspace.context_aware_access.access_level.unsatisfied | Display name of Access level unsatisfied. | keyword |
| google_workspace.context_aware_access.application | Display name of Application. | keyword |
| google_workspace.context_aware_access.device.id | Display name of Device Id. | keyword |
| google_workspace.context_aware_access.device.state | Display name of Device State. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.event.name | Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific Google Workspace service or feature which the API organizes into types of events. For eventName request parameters in general:   If no eventName is given, the report returns all possible instances of an eventName.   When you request an eventName, the API's response returns all activities which contain that eventName. It is possible that the returned activities will have other eventName properties in addition to the one requested. For more information about eventName properties, see the list of event names for various applications above in applicationName. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer.id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### GCP

This is the `gcp` dataset.

An example event for `gcp` looks as following:

```json
{
    "@timestamp": "2020-10-02T15:00:00.000Z",
    "agent": {
        "ephemeral_id": "73bd4e11-03bc-40dc-a0bc-1d9ca1aaa853",
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "google_workspace.gcp",
        "namespace": "65228",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43b6bca-79fe-44a7-b837-da9db4bf7be4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "IMPORT_SSH_PUBLIC_KEY",
        "agent_id_status": "verified",
        "created": "2024-08-01T21:56:37.313Z",
        "dataset": "google_workspace.gcp",
        "id": "1",
        "ingested": "2024-08-01T21:56:49Z",
        "kind": [
            "event"
        ],
        "original": "{\"actor\":{\"callerType\":\"USER\",\"email\":\"foo@bar.com\",\"profileId\":1},\"events\":{\"name\":\"IMPORT_SSH_PUBLIC_KEY\",\"parameters\":[{\"name\":\"USER_EMAIL\",\"value\":\"foo@bar.com\"}],\"type\":\"CLOUD_OSLOGIN\"},\"id\":{\"applicationName\":\"device\",\"customerId\":\"1\",\"time\":\"2020-10-02T15:00:00Z\",\"uniqueQualifier\":1},\"ipAddress\":\"67.43.156.13\",\"kind\":\"admin#reports#activity\",\"ownerDomain\":\"example.com\"}",
        "provider": "device"
    },
    "google_workspace": {
        "actor": {
            "email": "foo@bar.com",
            "profile": {
                "id": "1"
            },
            "type": "USER"
        },
        "event": {
            "name": "IMPORT_SSH_PUBLIC_KEY",
            "type": "CLOUD_OSLOGIN"
        },
        "gcp": {
            "user_email": "foo@bar.com"
        },
        "id": {
            "application_name": "device",
            "customer": {
                "id": "1"
            },
            "time": "2020-10-02T15:00:00.000Z",
            "unique_qualifier": "1"
        },
        "ip_address": "67.43.156.13",
        "kind": "admin#reports#activity",
        "organization": {
            "domain": "example.com"
        }
    },
    "input": {
        "type": "httpjson"
    },
    "organization": {
        "id": "1"
    },
    "related": {
        "hosts": [
            "bar.com",
            "example.com"
        ],
        "ip": [
            "67.43.156.13"
        ],
        "user": [
            "1",
            "foo",
            "foo@bar.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "user": {
            "domain": "bar.com",
            "email": "foo@bar.com",
            "id": "1",
            "name": "foo"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_workspace-gcp"
    ],
    "user": {
        "domain": "bar.com",
        "email": "foo@bar.com",
        "id": "1",
        "name": "foo"
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
| google_workspace.actor.email | The primary email address of the actor. May be absent if there is no email address associated with the actor. | keyword |
| google_workspace.actor.key | Only present when `actor.type` is `KEY`. Can be the `consumer_key` of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | keyword |
| google_workspace.actor.profile.id | The unique Google Workspace profile ID of the actor. This value might be absent if the actor is not a Google Workspace user, or may be the number 105250506097979753968 which acts as a placeholder ID. | keyword |
| google_workspace.actor.type | The type of actor. Values can be:   \*USER\*: Another user in the same domain.   \*EXTERNAL_USER\*: A user outside the domain.   \*KEY\*: A non-human actor. | keyword |
| google_workspace.etag | ETag of the entry. | keyword |
| google_workspace.event.name | Name of the event. This is the specific name of the activity reported by the API. And each eventName is related to a specific Google Workspace service or feature which the API organizes into types of events. For eventName request parameters in general:   If no eventName is given, the report returns all possible instances of an eventName.   When you request an eventName, the API's response returns all activities which contain that eventName. It is possible that the returned activities will have other eventName properties in addition to the one requested. For more information about eventName properties, see the list of event names for various applications above in applicationName. | keyword |
| google_workspace.event.type | The type of Google Workspace event, mapped from `items[].events[].type` in the original payload. Each fileset can have a different set of values for it, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.gcp.user_email | The email address of the acting user. | keyword |
| google_workspace.id.application_name | Application name to which the event belongs. For possible values see the list of applications above in applicationName. | keyword |
| google_workspace.id.customer.id | The unique identifier for a Google Workspace account. | keyword |
| google_workspace.id.time | Time of occurrence of the activity. This is in UNIX epoch time in seconds. | date |
| google_workspace.id.unique_qualifier | Unique qualifier if multiple events have the same time. | keyword |
| google_workspace.ip_address | IP address of the user doing the action. This is the Internet Protocol (IP) address of the user when logging into Google Workspace, which may or may not reflect the user's physical location. For example, the IP address can be the user's proxy server's address or a virtual private network (VPN) address. The API supports IPv4 and IPv6. | ip |
| google_workspace.kind | The type of API resource, mapped from `kind` in the original payload, more details can be found [here](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#activity). | keyword |
| google_workspace.organization.domain | The domain that is affected by the report's event. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |

